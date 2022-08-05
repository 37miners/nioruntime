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
use nioruntime_err::{Error, ErrorKind};
use nioruntime_log::*;
use nioruntime_util::lockr;
use std::net::SocketAddr;
use std::sync::{Arc, RwLock};

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

	pub fn layers(&self) -> Result<usize, Error> {
		match lockr!(self.crypt_state) {
			Ok(crypt_state) => Ok(crypt_state.layers()),
			_ => Err(ErrorKind::Tor("crypt state lock was not obtained!".to_string()).into()),
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
