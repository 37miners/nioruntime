// Copyright (c) 2022, 37 Miners, LLC
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

use crate::cell::{next_cell, CellBody, Certs, NetInfo};
use crate::common::IoState;
use crate::crypto::handshake::fast::{CreateFastClient, CreateFastClientState, CreateFastServer};
use crate::crypto::handshake::{ClientHandshake, KeyGenerator, ServerHandshake};
use crate::x509_signature;
use crate::{ChanCmd, CELL_LEN};
use nioruntime_deps::arrayref::array_ref;
use nioruntime_deps::digest::Digest;
use nioruntime_deps::rustls::client::{
	HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier, ServerName,
};
use nioruntime_deps::rustls::internal::msgs::enums::SignatureScheme;
use nioruntime_deps::rustls::internal::msgs::handshake::DigitallySignedStruct;
use nioruntime_deps::rustls::{
	Certificate, ClientConfig, ClientConnection, Reader, RootCertStore, Writer,
};
use nioruntime_deps::rustls_pemfile;
use nioruntime_deps::x509_signature::X509Certificate;
use nioruntime_err::{Error, ErrorKind};
use nioruntime_log::*;
use std::convert::TryInto;
use std::fs::File;
use std::io::{BufReader, Read, Write};
use std::net::IpAddr;
use std::sync::Arc;
use std::time::SystemTime;
use tor_checkable::{ExternallySigned, Timebound};
use tor_llcrypto as ll;
use tor_llcrypto::pk::ed25519::Ed25519Identity;

info!();

//pub const FAST_C_HANDSHAKE_LEN: usize = 20;
//pub struct CreateFastClientState(pub [u8; FAST_C_HANDSHAKE_LEN]);

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

pub struct Channel {
	tls_conn: ClientConnection,
	in_buf: Vec<u8>,
	verified: bool,
	has_versions: bool,
	netinfo: Option<NetInfo>,
	certs: Option<Certs>,
	ip_addr: IpAddr,
	create_fast_state: Option<CreateFastClientState>,
}

impl Channel {
	pub fn new(ip_addr: IpAddr) -> Result<Self, Error> {
		let config = Self::make_config(None)?;
		// localhost used. Tor doesn't use DNS.
		let tls_conn = ClientConnection::new(config, "localhost".try_into()?)?;
		let in_buf = vec![];

		Ok(Self {
			tls_conn,
			verified: false,
			has_versions: false,
			netinfo: None,
			certs: None,
			in_buf,
			ip_addr,
			create_fast_state: None,
		})
	}

	pub fn get_create_fast_state(&self) -> Option<&CreateFastClientState> {
		self.create_fast_state.as_ref()
	}

	pub fn start(&mut self) -> Result<(), Error> {
		let versions_msg: &[u8] = &[0, 0, ChanCmd::VERSIONS.into(), 0, 2, 0, 4];
		self.tls_conn.writer().write_all(&versions_msg)?;
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
				ErrorKind::Tor(format!("tls_conn.read_tls generated error: {}", e)).into();
			error
		})
	}

	pub fn write_tor(&mut self, wr: &mut dyn Write) -> Result<usize, Error> {
		self.tls_conn.write_tls(wr).map_err(|e| {
			let error: Error =
				ErrorKind::Tor(format!("tls_conn.write_tls generated error: {}", e)).into();
			error
		})
	}

	pub fn process_new_packets(&mut self) -> Result<IoState, Error> {
		let io_state = self.tls_conn.process_new_packets().map_err(|e| {
			let error: Error =
				ErrorKind::Tor(format!("process_new_packets generated error: {}", e)).into();
			error
		});

		match io_state {
			Ok(io_state) => {
				if self.verified || io_state.peer_has_closed() {
					Ok(io_state.into())
				} else {
					let wlen = io_state.tls_bytes_to_write();
					self.process_unverified(io_state.into())?;

					Ok(IoState::new(wlen, 0, false))
				}
			}

			Err(e) => Err(e),
		}
	}

	fn process_unverified(&mut self, io_state: IoState) -> Result<(), Error> {
		let len = io_state.plaintext_bytes_to_read();

		if len > 0 {
			{
				let mut reader = self.reader();
				let mut buf = vec![];
				buf.resize(len, 0u8);
				reader.read_exact(&mut buf)?;
				self.in_buf.append(&mut buf);

				debug!(
					"Internal process (len={}): '{:?}'",
					self.in_buf.len(),
					self.in_buf
				)?;
			}

			if !self.has_versions {
				self.confirm_versions()?;
				if self.has_versions {
					debug!("versions match confirmed!")?;
				}
			}

			loop {
				match next_cell(&mut self.in_buf)? {
					Some(cell) => {
						debug!("next cell = {:?}", cell)?;
						match cell.cell_body {
							CellBody::NetInfo(netinfo) => {
								self.netinfo = Some(netinfo);
								if self.certs.is_some() && self.netinfo.is_some() {
									// we have everything we need
									break;
								}
							}
							CellBody::Certs(certs) => {
								self.certs = Some(certs);
								if self.certs.is_some() && self.netinfo.is_some() {
									// we have everything we need
									break;
								}
							}
							_ => {}
						}
					}
					None => break,
				}
			}

			if self.certs.is_some() && self.netinfo.is_some() {
				// we are ready to verify them.
				self.verify_channel()?;
				self.verified = true;
				debug!("Verified the channel!")?;
				self.send_net_info()?;
				self.send_create_fast()?
			}
		}

		Ok(())
	}

	fn send_create_fast(&mut self) -> Result<(), Error> {
		let mut create_fast = vec![255, 255, 255, 255, ChanCmd::CREATE_FAST.into()];

		let mut rng = nioruntime_deps::rand::thread_rng();
		let (state, mut cmsg) = CreateFastClient::client1(&mut rng, &()).unwrap();
		let (s_kg, smsg) = CreateFastServer::server(&mut rng, &[()], cmsg.clone()).unwrap();
		let c_kg = CreateFastClient::client2(state.clone(), smsg).unwrap();
		let s_key = s_kg.expand(100).unwrap();
		let c_key = c_kg.expand(100).unwrap();
		assert_eq!(c_key, s_key);

		self.create_fast_state = Some(state);
		create_fast.append(&mut cmsg);
		create_fast.resize(CELL_LEN, 0u8);

		debug!("sending create_fast = {:?}", create_fast)?;

		self.tls_conn.writer().write(&create_fast)?;

		Ok(())
	}

	fn send_net_info(&mut self) -> Result<(), Error> {
		let netinfo = match &self.netinfo {
			Some(netinfo) => netinfo,
			None => {
				return Err(
					ErrorKind::Tor("unexpected error: netinfo not found".to_string()).into(),
				);
			}
		};

		let mut local = vec![];
		// we return us as they see us since we don't necesserily know the external ip.
		local.push(netinfo.remote);
		let remote = self.ip_addr;
		// TODO: we should construct our own timestamp
		let timestamp = netinfo.timestamp;
		let netinfo = NetInfo {
			timestamp,
			local,
			remote,
		};
		let mut netinfo = NetInfo::serialize(netinfo)?;
		debug!("Sending netinfo to peer: {:?}", netinfo)?;
		self.tls_conn.writer().write(&mut netinfo)?;
		Ok(())
	}

	// Verify the channel
	fn verify_channel(&self) -> Result<(), Error> {
		let certs = match &self.certs {
			Some(certs) => certs,
			None => return Err(ErrorKind::Tor(format!("no certs")).into()),
		};

		let mut type2_cert = None;
		let mut type4_cert = None;
		let mut type5_cert = None;
		let mut type7_cert = None;
		for cert in &certs.certs {
			debug!("parsing type = {}", cert.cert_type)?;

			if cert.cert_type == 2 {
				if type2_cert.is_some() {
					return Err(ErrorKind::Tor(
						"certs must have exactly 1 type 2 cert".to_string(),
					)
					.into());
				}
				type2_cert = Some(cert.cert.clone());
			} else if cert.cert_type == 4 {
				if type4_cert.is_some() {
					return Err(ErrorKind::Tor(
						"certs must have exactly 1 type 4 cert".to_string(),
					)
					.into());
				}
				type4_cert = Some(crate::ed25519::Ed25519Cert::decode(&cert.cert)?);
			} else if cert.cert_type == 5 {
				if type5_cert.is_some() {
					return Err(ErrorKind::Tor(
						"certs must have exactly 1 type 5 cert".to_string(),
					)
					.into());
				}
				type5_cert = Some(crate::ed25519::Ed25519Cert::decode(&cert.cert)?);
			} else if cert.cert_type == 7 {
				if type7_cert.is_some() {
					return Err(ErrorKind::Tor(
						"certs must have exactly 1 type 7 cert".to_string(),
					)
					.into());
				}
				type7_cert = Some(cert.cert.clone());
			}
		}

		let type2_cert = match type2_cert {
			Some(type2_cert) => type2_cert,
			None => {
				return Err(
					ErrorKind::Tor("certs must have exactly 1 type 2 cert".to_string()).into(),
				)
			}
		};

		let type7_cert = match type7_cert {
			Some(type7_cert) => type7_cert,
			None => {
				return Err(
					ErrorKind::Tor("certs must have exactly 1 type 7 cert".to_string()).into(),
				)
			}
		};

		let id_sk = match type4_cert {
			Some(type4_cert) => type4_cert,
			None => {
				return Err(
					ErrorKind::Tor("certs must have exactly 1 type 4 cert".to_string()).into(),
				)
			}
		};
		let sk_tls = match type5_cert {
			Some(type5_cert) => type5_cert,
			None => {
				return Err(
					ErrorKind::Tor("certs must have exactly 1 type 5 cert".to_string()).into(),
				)
			}
		};

		let mut sigs = Vec::new();
		let now = std::time::SystemTime::now();

		// Part 1: validate ed25519 stuff.
		// Check the identity->signing cert
		let (id_sk, id_sk_sig) = id_sk.check_key(&None)?.dangerously_split()?;
		sigs.push(&id_sk_sig);
		let id_sk = id_sk.check_valid_at_opt(Some(now)).map_err(|_| {
			let error: Error = ErrorKind::Tor("Certificate expired or not yet valid".into()).into();
			error
		})?;

		// Take the identity key from the identity->signing cert
		let identity_key = id_sk.signing_key().ok_or_else(|| {
			let error: Error =
				ErrorKind::Tor("Missing identity key in identity->signing cert".into()).into();
			error
		})?;

		// Take the signing key from the identity->signing cert
		let signing_key = id_sk.subject_key().as_ed25519().ok_or_else(|| {
			let error: Error =
				ErrorKind::Tor("Bad key type in identity->signing cert".into()).into();
			error
		})?;

		// Now look at the signing->TLS cert and check it against the
		// peer certificate.
		let (sk_tls, sk_tls_sig) = sk_tls
			.check_key(&Some(*signing_key))? // TODO(nickm): this is a bad interface
			.dangerously_split()?;
		sigs.push(&sk_tls_sig);
		let sk_tls = sk_tls.check_valid_at_opt(Some(now)).map_err(|_| {
			let error: Error = ErrorKind::Tor("Certificate expired or not yet valid".into()).into();
			error
		})?;

		let peer_certs = self.tls_conn.peer_certificates();
		let peer_certs = match peer_certs {
			Some(peer_certs) => peer_certs,
			None => {
				return Err(ErrorKind::Tor("Peer does not have a TLS cert".into()).into());
			}
		};
		if peer_certs.len() == 0 {
			return Err(ErrorKind::Tor("Peer does not have a cert".into()).into());
		}

		// get the peer certificate which is first per rustls docs.
		let peer_cert = &peer_certs[0].0;
		let peer_cert_sha256 = ll::d::Sha256::digest(peer_cert);
		let peer_cert_sha256 = &peer_cert_sha256[..];

		if peer_cert_sha256 != sk_tls.subject_key().as_bytes() {
			return Err(ErrorKind::Tor("Peer cert did not authenticate TLS cert".into()).into());
		}

		// Batch-verify the ed25519 certificates in this handshake.
		//
		// In theory we could build a list of _all_ the certificates here
		// and call pk::validate_all_sigs() instead, but that doesn't gain
		// any performance.
		if !ll::pk::ed25519::validate_batch(&sigs[..]) {
			return Err(ErrorKind::Tor("Invalid ed25519 signature in handshake".into()).into());
		}

		let ed25519_id: Ed25519Identity = identity_key.into();

		// Part 2: validate rsa stuff.

		// What is the RSA identity key, according to the X.509 certificate
		// in which it is self-signed?
		//
		// (We don't actually check this self-signed certificate, and we use
		// a kludge to extract the RSA key)
		let pkrsa = ll::util::x509_extract_rsa_subject_kludge(&type2_cert).ok_or({
			let error: Error = ErrorKind::Tor("could not extract RSA Identity key".into()).into();
			error
		})?;

		// Now verify the RSA identity -> Ed Identity crosscert.
		//
		// This proves that the RSA key vouches for the Ed key.  Note that
		// the Ed key does not vouch for the RSA key: The RSA key is too
		// weak.
		let rsa_cert = crate::rsa::RsaCrosscert::decode(&type7_cert)?
			.check_signature(&pkrsa)
			.map_err(|_| {
				let error: Error = ErrorKind::Tor("Bad RSA->Ed crosscert signature".into()).into();
				error
			})?
			.check_valid_at_opt(Some(now))
			.map_err(|_| {
				let error: Error =
					ErrorKind::Tor("RSA->Ed crosscert expired or invalid".into()).into();
				error
			})?;

		if !rsa_cert.subject_key_matches(identity_key) {
			return Err(ErrorKind::Tor("RSA->Ed crosscert certifies incorrect key".into()).into());
		}

		let rsa_id = pkrsa.to_rsa_identity();

		debug!(
			"Validated identity as {:?} [{}]",
			nioruntime_deps::base64::encode(ll::d::Sha256::digest(ed25519_id.as_bytes())),
			rsa_id
		)?;

		// all checks passed. We're ok which will mark the channel as verified
		Ok(())
	}

	fn confirm_versions(&mut self) -> Result<(), Error> {
		let inbuf_len = self.in_buf.len();
		if inbuf_len < 5 {
			// not enough data yet. Return ok and process again when more.
			return Ok(());
		}
		if self.in_buf[0] != 0 || self.in_buf[1] != 0 || self.in_buf[2] != 7 {
			return Err(ErrorKind::Tor("TOR must start with 007".to_string()).into());
		}
		let len = u16::from_be_bytes(*array_ref![self.in_buf, 3, 2]);
		if inbuf_len < (len + 5).into() {
			// not enough data yet. Return ok and process again when more.
			return Ok(());
		}

		// currently we just care about matching our version '4' which is 1 byte
		let mut found = false;
		for i in 0..(len / 2) {
			match self.in_buf[(6 + i * 2) as usize] {
				4 => found = true,
				_ => {}
			}
		}
		if !found {
			return Err(ErrorKind::Tor("Protocol version 4 not supported".to_string()).into());
		}

		self.has_versions = true;
		let dr_len: usize = (len + 5).into();
		trace!("draining len = {}", dr_len)?;
		self.in_buf.drain(..dr_len);

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
			.with_safe_default_protocol_versions()?
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
	use nioruntime_err::{Error, ErrorKind};
	use nioruntime_log::*;
	use std::io::{Read, Write};
	use std::net::TcpStream;
	use std::time::Instant;

	info!();

	#[test]
	fn test_channel() -> Result<(), Error> {
		/*
				let now = Instant::now();
				//let ip = "45.66.33.45";
				//let addr = format!("{}:{}", ip, 443);
				//let ip = "66.111.2.131";
				//let addr = format!("{}:{}", ip, 9001);
				//let ip = "148.251.81.16";
				//let addr = format!("{}:{}", ip, 110);
				let ip = "127.0.0.1";
				let addr = format!("{}:{}", ip, 9001);

				// note creating the channel will automatically initiate
				// the handshake, version exchange, netinfo,
				// and call create_fast to initiate circuit creation.
				// beyond that is the responsibility of the caller to initiate.
				let mut channel = Channel::new(ip.parse()?)?;

				let mut wbuf = vec![];
				channel.start()?;
				channel.write_tor(&mut wbuf)?;
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
						if buffer.len() != 1024 * 1024 {
							buffer.resize(1024 * 1024, 0u8);
						}
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
								return Err(ErrorKind::ApplicationError(format!(
									"Error processing packets: {}",
									e
								))
								.into());
							}
						}

						channel.write_tor(&mut wbuf)?;

						if pt_len > 0 {
							info!(
								"read pt_len bytes = {} [elapsed={}] '{:?}'",
								pt_len,
								now.elapsed().as_millis(),
								&buffer[0..pt_len]
							)?;
						} else {
							debug!("pt_len = {}", pt_len)?;
						}

						if wbuf.len() > 0 {
							debug!(
								"writing {} bytes to the channel [elapsed={}]",
								wbuf.len(),
								now.elapsed().as_millis()
							)?;
							stream.write(&wbuf)?;
						}
					}

					Ok(())
				});

				// TODO: test with an actual relay
				std::thread::park();
		*/

		Ok(())
	}
}
