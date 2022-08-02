// Copyright (c) 2022, 37 Miners, LLC
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
// http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

use crate::cell::Cell;
use crate::circuit::Circuit;
use crate::ed25519::Ed25519Identity;
use crate::ed25519::XDalekPublicKey as PublicKey;
use crate::handshake::ntor::NtorHandshakeState;
use crate::handshake::ntor::NtorPublicKey;
use crate::rsa::RsaIdentity;
use crate::util::InboundClientCrypt;
use crate::util::OutboundClientCrypt;
use nioruntime_deps::rustls::client::{
	HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier, ServerName,
};
use nioruntime_deps::rustls::internal::msgs::handshake::DigitallySignedStruct;
use nioruntime_deps::rustls::{Certificate, SignatureScheme};
use nioruntime_deps::x509_signature;
use nioruntime_deps::x509_signature::X509Certificate;
use nioruntime_err::{Error, ErrorKind};
use nioruntime_log::*;
use nioruntime_util::lockr;
use std::net::SocketAddr;
use std::sync::{Arc, RwLock};
use std::time::SystemTime;

info!();

pub trait Stream {
	fn event_type(&self) -> StreamEventType;
	fn write(&mut self, circuit: &mut Circuit, _: &[u8]) -> Result<(), Error>;
	fn get_data(&self) -> Result<&Vec<u8>, Error>;
	fn available(&self) -> Result<usize, Error>;
	fn close(&mut self, circuit: &mut Circuit, reason: u8) -> Result<(), Error>;
	fn id(&self) -> u16;
}

#[derive(Clone, Copy, Debug)]
pub enum StreamEventType {
	Created,
	Readable,
	Connected,
	Close(u8),
}

pub struct CircuitPlan {
	hops: Vec<Node>,
}

impl CircuitPlan {
	pub fn new(hops: Vec<Node>) -> Self {
		Self { hops }
	}

	pub fn hops(&self) -> &Vec<Node> {
		&self.hops
	}
}

#[derive(Debug)]
pub struct ChannelCryptState {
	pub cc_in: InboundClientCrypt,
	pub cc_out: OutboundClientCrypt,
	pub hs_state: Option<NtorHandshakeState>,
}

impl ChannelCryptState {
	pub fn new() -> Self {
		Self {
			cc_in: InboundClientCrypt::new(),
			cc_out: OutboundClientCrypt::new(),
			hs_state: None,
		}
	}

	pub fn layers(&self) -> usize {
		// we use cc_out (assumption cc_in and cc_out should be equal).
		self.cc_out.n_layers()
	}
}

#[derive(Debug, Clone)]
pub struct TorCert {
	pub cert_type: u8,
	pub cert: Vec<u8>,
}

pub struct ChannelContext {
	pub in_buf: Vec<u8>,
	pub offset: usize,
	pub crypt_state: Arc<RwLock<ChannelCryptState>>,
}

impl ChannelContext {
	pub fn new() -> Self {
		Self {
			in_buf: vec![],
			offset: 0,
			crypt_state: Arc::new(RwLock::new(ChannelCryptState::new())),
		}
	}

	pub fn layers(&self) -> usize {
		match lockr!(self.crypt_state) {
			Ok(crypt_state) => crypt_state.layers(),
			_ => {
				let _ = warn!("crypt state lock was not obtained! We can only return 0");
				// not expected
				0
			}
		}
	}
}

#[derive(Debug, Clone)]
pub struct TorState {
	tls_bytes_to_write: usize,
	cells: Vec<Cell>,
	peer_has_closed: bool,
}

impl TorState {
	pub fn new(tls_bytes_to_write: usize, cells: Vec<Cell>, peer_has_closed: bool) -> Self {
		Self {
			tls_bytes_to_write,
			cells,
			peer_has_closed,
		}
	}

	pub fn tls_bytes_to_write(&self) -> usize {
		self.tls_bytes_to_write
	}

	pub fn cells(&self) -> &Vec<Cell> {
		&self.cells
	}

	pub fn clear(&mut self) {
		self.cells.clear();
	}

	pub fn peer_has_closed(&self) -> bool {
		self.peer_has_closed
	}
}

impl From<nioruntime_deps::rustls::IoState> for TorState {
	fn from(io_state: nioruntime_deps::rustls::IoState) -> TorState {
		TorState::new(
			io_state.tls_bytes_to_write(),
			vec![],
			io_state.peer_has_closed(),
		)
	}
}

#[derive(Debug, Clone)]
pub struct Node {
	pub sockaddr: SocketAddr,
	pub ed_identity: Ed25519Identity,
	pub rsa_identity: RsaIdentity,
	pub ntor_onion_pubkey: PublicKey,
}

impl Node {
	pub fn new(
		sockaddr: &str,
		ed_identity_b64: &str,
		ntor_onion_pubkey_b64: &str,
		rsa_identity_b64: &str,
	) -> Result<Self, Error> {
		let sockaddr: SocketAddr = sockaddr.parse()?;
		let ed_identity = match Ed25519Identity::from_base64(ed_identity_b64) {
			Some(id) => id,
			None => {
				return Err(ErrorKind::Tor("invalid ed25519 identity base64".to_string()).into())
			}
		};
		let ntor_onion_pubkey = match NtorPublicKey::from_base64(ntor_onion_pubkey_b64) {
			Some(id) => id,
			None => return Err(ErrorKind::Tor("invalid ntor pubkey base64".to_string()).into()),
		};

		let rsa_identity = match RsaIdentity::from_base64(rsa_identity_b64) {
			Some(id) => id,
			None => return Err(ErrorKind::Tor("invalid rsa identity base64".to_string()).into()),
		};
		Ok(Self {
			sockaddr,
			ed_identity,
			ntor_onion_pubkey,
			rsa_identity,
		})
	}
}

pub struct Verifier {}

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
	// implemented PKCS1 make sense only when it's used for
	// encryption.
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
