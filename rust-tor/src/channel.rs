// Copyright 2021 37 Miners, LLC
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

use crate::num_enum::IntoPrimitive;
use crate::x509_signature;
use nioruntime_deps::rustls::client::{
	HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier, ServerName,
};
use nioruntime_deps::rustls::internal::msgs::enums::SignatureScheme;
use nioruntime_deps::rustls::internal::msgs::handshake::DigitallySignedStruct;
use nioruntime_deps::rustls::{
	Certificate, ClientConfig, ClientConnection, IoState, Reader, RootCertStore, Writer,
};
use nioruntime_deps::rustls_pemfile;
use nioruntime_deps::x509_signature::X509Certificate;
use nioruntime_err::{Error, ErrorKind};
use nioruntime_log::*;
use std::convert::TryInto;
use std::fs::File;
use std::io::{BufReader, Read, Write};
use std::sync::Arc;
use std::time::SystemTime;

debug!();

#[derive(Clone, Debug)]
struct Verifier {}

impl ServerCertVerifier for Verifier {
	fn verify_server_cert(
		&self,
		end_entity: &Certificate,
		_intermediates: &[Certificate],
		_server_name: &ServerName,
		_scts: &mut dyn Iterator<Item = &[u8]>,
		_ocsp_response: &[u8],
		_now: SystemTime,
	) -> Result<ServerCertVerified, nioruntime_deps::rustls::Error> {
		let _ = get_cert(end_entity).map_err(|e| {
			nioruntime_deps::rustls::Error::InvalidCertificateData(format!(
				"InvalidCertificateData: {}",
				e
			))
		})?;
		Ok(ServerCertVerified::assertion())
	}

	fn verify_tls12_signature(
		&self,
		message: &[u8],
		cert: &Certificate,
		dss: &DigitallySignedStruct,
	) -> Result<HandshakeSignatureValid, nioruntime_deps::rustls::Error> {
		let cert = get_cert(cert)
			.map_err(|_e| nioruntime_deps::rustls::Error::InvalidCertificateSignature)?;
		let scheme = convert_scheme(dss.scheme)?;
		let signature = dss.sig.0.as_ref();

		cert.check_signature(scheme, message, signature)
			.map(|_| HandshakeSignatureValid::assertion())
			.map_err(|_| nioruntime_deps::rustls::Error::InvalidCertificateSignature)
	}
	fn verify_tls13_signature(
		&self,
		message: &[u8],
		cert: &Certificate,
		dss: &DigitallySignedStruct,
	) -> Result<HandshakeSignatureValid, nioruntime_deps::rustls::Error> {
		let cert = get_cert(cert)
			.map_err(|_e| nioruntime_deps::rustls::Error::InvalidCertificateSignature)?;
		let scheme = convert_scheme(dss.scheme)?;
		let signature = dss.sig.0.as_ref();

		cert.check_tls13_signature(scheme, message, signature)
			.map(|_| HandshakeSignatureValid::assertion())
			.map_err(|_| nioruntime_deps::rustls::Error::InvalidCertificateSignature)
	}
}

fn get_cert(c: &Certificate) -> Result<X509Certificate, Error> {
	x509_signature::parse_certificate(c.as_ref())
		.map_err(|e| ErrorKind::TLSError(format!("Cert error: {:?}", e)).into())
}

/// Convert from the signature scheme type used in `rustls` to the one used in
/// `x509_signature`.
///
/// (We can't just use the x509_signature crate's "rustls" feature to have it
/// use the same enum from `rustls`, because it seems to be on a different
/// version from the rustls we want.)
fn convert_scheme(
	scheme: SignatureScheme,
) -> Result<x509_signature::SignatureScheme, nioruntime_deps::rustls::Error> {
	use nioruntime_deps::rustls::internal::msgs::enums::SignatureScheme as R;
	use x509_signature::SignatureScheme as X;

	// Yes, we do allow PKCS1 here.  That's fine in practice when PKCS1 is only
	// used (as in TLS 1.2) for signatures; the attacks against correctly
	// implemented PKCS1 make sense only when it's used for encryption.
	Ok(match scheme {
		R::RSA_PKCS1_SHA256 => X::RSA_PKCS1_SHA256,
		R::ECDSA_NISTP256_SHA256 => X::ECDSA_NISTP256_SHA256,
		R::RSA_PKCS1_SHA384 => X::RSA_PKCS1_SHA384,
		R::ECDSA_NISTP384_SHA384 => X::ECDSA_NISTP384_SHA384,
		R::RSA_PKCS1_SHA512 => X::RSA_PKCS1_SHA512,
		R::RSA_PSS_SHA256 => X::RSA_PSS_SHA256,
		R::RSA_PSS_SHA384 => X::RSA_PSS_SHA384,
		R::RSA_PSS_SHA512 => X::RSA_PSS_SHA512,
		R::ED25519 => X::ED25519,
		R::ED448 => X::ED448,
		R::RSA_PKCS1_SHA1 | R::ECDSA_SHA1_Legacy | R::ECDSA_NISTP521_SHA512 => {
			// The `x509-signature` crate doesn't support these, nor should it really.
			return Err(nioruntime_deps::rustls::Error::PeerIncompatibleError(
				format!("Unsupported signature scheme {:?}", scheme),
			));
		}
		R::Unknown(_) => {
			return Err(nioruntime_deps::rustls::Error::PeerIncompatibleError(
				format!("Unrecognized signature scheme {:?}", scheme),
			))
		}
	})
}

#[derive(IntoPrimitive)]
#[repr(u8)]
/// We don't support everything for now. Just what we need to use
enum ChanCmd {
	/// Variable-length cell, despite its number: negotiate versions
	Versions = 7,
}

pub struct Channel {
	tls_conn: ClientConnection,
}

impl Channel {
	pub fn new(trusted_cert_full_chain_file: Option<String>) -> Result<Self, Error> {
		let config = Self::make_config(trusted_cert_full_chain_file)?;
		// note that any server name can be used here since tor doesn't recognize them.
		let tls_conn = ClientConnection::new(config, "localhost".try_into()?)?;

		Ok(Self { tls_conn })
	}

	pub fn start(&mut self, wbuf: &mut Vec<u8>) -> Result<(), Error> {
		let versions_msg: &[u8] = &[0, 0, ChanCmd::Versions.into(), 0, 2, 0, 4];
		self.tls_conn.writer().write_all(&versions_msg)?;
		self.tls_conn.write_tls(wbuf)?;
		Ok(())
	}

	pub fn reader(&mut self) -> Reader {
		self.tls_conn.reader()
	}

	pub fn writer(&mut self) -> Writer {
		self.tls_conn.writer()
	}

	pub fn read_tor(&mut self, rd: &mut dyn Read) -> Result<usize, Error> {
		self.tls_conn.read_tls(rd).map_err(|e| {
			let error: Error =
				ErrorKind::ApplicationError(format!("tls_conn.read_tls generated error: {}", e))
					.into();
			error
		})
	}

	pub fn write_tor(&mut self, wr: &mut dyn Write) -> Result<usize, Error> {
		self.tls_conn.write_tls(wr).map_err(|e| {
			let error: Error =
				ErrorKind::ApplicationError(format!("tls_conn.read_tls generated error: {}", e))
					.into();
			error
		})
	}

	pub fn process_new_packets(&mut self) -> Result<IoState, Error> {
		self.tls_conn.process_new_packets().map_err(|e| {
			let error: Error =
				ErrorKind::ApplicationError(format!("process_new_packets generated error: {}", e))
					.into();
			error
		})
	}

	pub fn connect(&self, rd: &mut dyn Read, wr: &mut dyn Write) -> Result<(), Error> {
		// advertise version 4.
		let versions_msg: &[u8] = &[0, 0, ChanCmd::Versions.into(), 0, 2, 0, 4];
		wr.write(versions_msg)?;
		wr.flush()?;

		let mut hdr = [0_u8; 5];
		let len = rd.read(&mut hdr)?;
		warn!("hdr={:?}, read len = {}", hdr, len)?;
		Ok(())
	}

	fn make_config(
		trusted_cert_full_chain_file: Option<String>,
	) -> Result<Arc<ClientConfig>, Error> {
		let mut root_store = RootCertStore::empty();
		match trusted_cert_full_chain_file {
			Some(trusted_cert_full_chain_file) => {
				let full_chain_certs = Self::load_certs(&trusted_cert_full_chain_file)?;
				for i in 0..full_chain_certs.len() {
					root_store.add(&full_chain_certs[i]).map_err(|e| {
						let error: Error = ErrorKind::SetupError(format!(
							"adding certificate to root store generated error: {}",
							e.to_string()
						))
						.into();
						error
					})?;
				}
			}
			None => {}
		}

		let mut config = ClientConfig::builder()
			.with_safe_default_cipher_suites()
			.with_safe_default_kx_groups()
			.with_safe_default_protocol_versions()
			.unwrap()
			.with_root_certificates(root_store)
			.with_no_client_auth();

		config
			.dangerous()
			.set_certificate_verifier(std::sync::Arc::new(Verifier {}));

		Ok(Arc::new(config))
	}

	fn load_certs(filename: &str) -> Result<Vec<Certificate>, Error> {
		let certfile = File::open(filename)?;
		let mut reader = BufReader::new(certfile);
		let certs = rustls_pemfile::certs(&mut reader)?;
		Ok(certs.iter().map(|v| Certificate(v.clone())).collect())
	}
}

#[cfg(test)]
mod test {
	use crate::channel::Channel;
	use nioruntime_err::Error;
	use nioruntime_log::*;
	use std::io::{Read, Write};
	use std::net::TcpStream;

	debug!();

	#[test]
	fn test_channel() -> Result<(), Error> {
		let addr = "45.66.33.45:443";
		//let addr = "127.0.0.1:8092";

		// note creating the channel will automatically initiate
		// the handshake, version exchange, and authentication.
		// it will also call a CREATE_FAST with the server which is the first hop.
		// beyond that is the responsibility of the caller to initiate.
		let mut channel = Channel::new(Some("../eventhandler/src/resources/cert.pem".to_string()))?;
		let mut wbuf = vec![];
		channel.start(&mut wbuf)?;
		debug!("wbuf.len={}", wbuf.len())?;

		let mut stream = TcpStream::connect(addr)?;

		stream.write(&wbuf)?;

		debug!("spawning read thread")?;
		std::thread::spawn(move || -> Result<(), Error> {
			// read thread
			let mut buffer: Vec<u8> = vec![];
			buffer.resize(1024 * 1024, 0u8);

			debug!("about to start reading")?;
			loop {
				let mut wbuf = vec![];
				buffer.resize(1024 * 1024, 0u8);
				let pt_len;
				let len = stream.read(&mut buffer[..])?;
				debug!("read len = {} bytes", len)?;
				if len == 0 {
					break;
				}
				channel.read_tor(&mut &buffer[0..len])?;

				match channel.process_new_packets() {
					Ok(io_state) => {
						pt_len = io_state.plaintext_bytes_to_read();
						buffer.resize(pt_len, 0u8);
						let buf = &mut buffer[0..pt_len];
						channel.reader().read_exact(&mut buf[..])?;
					}
					Err(e) => {
						error!("Error processing packets: {}", e)?;
						pt_len = 0;
					}
				}

				channel.write_tor(&mut wbuf)?;

				if wbuf.len() > 0 {
					debug!("writing {} bytes to the channel", wbuf.len())?;
					stream.write(&wbuf)?;
				}

				if pt_len > 0 {
					info!("read pt_len bytes = {} '{:?}'", pt_len, &buffer[0..pt_len])?;
				} else {
					info!("pt_len = {}", pt_len)?;
				}
			}

			Ok(())
		});

		//		std::thread::park();

		Ok(())
	}
}
