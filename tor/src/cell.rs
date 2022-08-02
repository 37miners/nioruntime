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

use crate::constants::*;
use crate::handshake::ntor::NtorClient;
use crate::handshake::ntor::NtorPublicKey;
use crate::handshake::ClientHandshake;
use crate::types::ChannelContext;
use crate::types::ChannelCryptState;
use crate::types::Node;
use crate::types::TorCert;
use crate::util::tor1::RelayCellBody;
use crate::util::RngCompatExt;
use nioruntime_deps::arrayref::array_mut_ref;
use nioruntime_deps::arrayref::array_ref;
use nioruntime_deps::byteorder::WriteBytesExt;
use nioruntime_err::{Error, ErrorKind};
use nioruntime_log::*;
use std::convert::TryInto;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::sync::{Arc, RwLock};
use std::time::{SystemTime, UNIX_EPOCH};

info!();

#[derive(Debug, Clone)]
pub struct Relay {
	relay_data: Vec<u8>,
	relay_cmd: u8,
	crypt_state: Option<Arc<RwLock<ChannelCryptState>>>,
	stream_id: u16,
}

impl Relay {
	pub fn new_end(
		reason: u8,
		crypt_state: Arc<RwLock<ChannelCryptState>>,
		stream_id: u16,
	) -> Result<Self, Error> {
		Ok(Self {
			relay_data: vec![reason],
			relay_cmd: RELAY_CMD_END,
			crypt_state: Some(crypt_state),
			stream_id,
		})
	}
	pub fn new_data(
		relay_data: Vec<u8>,
		crypt_state: Arc<RwLock<ChannelCryptState>>,
		stream_id: u16,
	) -> Result<Self, Error> {
		if relay_data.len() > 498 {
			return Err(ErrorKind::Tor("Max relay_data size exceeded".to_string()).into());
		}
		Ok(Self {
			relay_data,
			relay_cmd: RELAY_CMD_DATA,
			crypt_state: Some(crypt_state),
			stream_id,
		})
	}

	pub fn new_begin_dir(
		crypt_state: Arc<RwLock<ChannelCryptState>>,
		stream_id: u16,
	) -> Result<Self, Error> {
		Ok(Self {
			relay_cmd: RELAY_CMD_BEGIN_DIR,
			relay_data: vec![],
			crypt_state: Some(crypt_state),
			stream_id,
		})
	}

	pub fn new_sendme(
		crypt_state: Arc<RwLock<ChannelCryptState>>,
		stream_id: u16,
	) -> Result<Self, Error> {
		Ok(Self {
			relay_cmd: RELAY_CMD_SENDME,
			relay_data: vec![],
			crypt_state: Some(crypt_state),
			stream_id,
		})
	}

	pub fn new_begin(
		address_port: &str,
		crypt_state: Arc<RwLock<ChannelCryptState>>,
		stream_id: u16,
	) -> Result<Self, Error> {
		// limit length to 400.
		if address_port.len() > 400 {
			return Err(ErrorKind::Tor(format!(
				"address_port.len()={}. Maximum is 400.",
				address_port.len()
			))
			.into());
		}

		let mut relay_data = address_port.as_bytes().to_vec();
		relay_data.push(0); // null terminated string
					//relay_data.push(0); // 4 byte flags (none for now)
					//relay_data.push(0); // 4 byte flags (none for now)
					//relay_data.push(0); // 4 byte flags (none for now)
					//relay_data.push(0); // 4 byte flags (none for now)
		debug!("relay_data={:?}", relay_data)?;
		Ok(Self {
			relay_cmd: RELAY_CMD_BEGIN,
			relay_data,
			crypt_state: Some(crypt_state),
			stream_id,
		})
	}

	pub fn stream_id(&self) -> u16 {
		self.stream_id
	}

	fn serialize(&self, circ_id: u32) -> Result<Vec<u8>, Error> {
		debug!("relay serialize for circ_id={}", circ_id)?;
		let crypt_state = match &self.crypt_state {
			Some(c) => c,
			None => {
				return Err(ErrorKind::InternalError(
					"crypt state not found for a relay command and it is needed to serialize"
						.to_string(),
				)
				.into())
			}
		};
		let mut ret = vec![];
		ret.append(&mut circ_id.to_be_bytes().to_vec());
		ret.push(CHAN_CMD_RELAY);
		ret.push(self.relay_cmd);
		ret.push(0); // recognized
		ret.push(0); // recognized
			 // push the two byte streamid
		ret.append(&mut self.stream_id.to_be_bytes().to_vec());
		ret.push(0); // digest
		ret.push(0); // digest
		ret.push(0); // digest
		ret.push(0); // digest
		ret.append(&mut (self.relay_data.len() as u16).to_be_bytes().to_vec()); // length 2 bytes
		ret.append(&mut self.relay_data.clone());

		let mut padding = vec![];
		padding.resize(CELL_LEN - ret.len(), 0u8);
		ret.append(&mut padding);

		debug!("relay serialize pre encrypted cell={:?}", ret)?;
		let mut relay_cell_body = RelayCellBody(*array_mut_ref![ret, 5, 509]);
		{
			let mut crypt_state = lockw!(crypt_state)?;
			let hop = crypt_state.layers().saturating_sub(1) as u8;
			crypt_state
				.cc_out
				.encrypt(&mut relay_cell_body, hop.into())?;
			(&mut ret[5..514]).clone_from_slice(relay_cell_body.as_ref());
		}
		debug!("relay serialize encrypted cell={:?}", ret)?;

		Ok(ret)
	}

	fn deserialize(ctx: &mut ChannelContext) -> Result<Option<Cell>, Error> {
		debug!("in relay")?;
		// we need at least 514 bytes to decode
		if ctx.offset < 514 {
			return Ok(None);
		}

		let circ_id = u32::from_be_bytes(ctx.in_buf[0..4].try_into()?);
		let mut relay_cell_body = RelayCellBody(*array_ref![ctx.in_buf, 5, 509]);
		debug!("relay_cell_body[predecrypt]={:?}", relay_cell_body.as_ref())?;

		{
			let mut crypt_state = lockw!(ctx.crypt_state)?;
			crypt_state.cc_in.decrypt(&mut relay_cell_body)?;
			debug!("relay_cell_body={:?}", relay_cell_body.as_ref())?;
		}

		// get length
		let relay_cell_body = relay_cell_body.as_ref();
		let stream_id = u16::from_be_bytes(relay_cell_body[3..5].try_into()?) as u16;
		let relay_data_len = u16::from_be_bytes(relay_cell_body[9..11].try_into()?) as usize;
		debug!("relay cell len = {}", relay_data_len)?;
		for i in 0..20 {
			debug!("buf[{}]={}", i, relay_cell_body[i])?;
		}
		if relay_data_len > ctx.offset {
			// not enough data, wait for more
			return Ok(None);
		}

		let mut relay_data = Vec::with_capacity(relay_data_len);
		relay_data.resize(relay_data_len, 0u8);
		relay_data.clone_from_slice(&relay_cell_body[11..11 + relay_data_len]);

		debug!("circ[{}] relay data = {:?}", circ_id, relay_data)?;

		let end = 514;
		ctx.in_buf.drain(..end);
		ctx.offset = ctx.offset.saturating_sub(end);

		Ok(Some(Cell {
			body: CellBody::Relay(Relay {
				relay_cmd: relay_cell_body[0],
				relay_data: relay_data,
				crypt_state: None,
				stream_id,
			}),
			circ_id,
		}))
	}

	pub fn get_relay_data(&self) -> &Vec<u8> {
		&self.relay_data
	}

	pub fn get_relay_cmd(&self) -> u8 {
		self.relay_cmd
	}
}

#[derive(Debug, Clone)]
pub struct Extend2 {
	destination: Node,
	crypt_state: Arc<RwLock<ChannelCryptState>>,
}

impl Extend2 {
	pub fn new(destination: &Node, ctx: &ChannelContext) -> Self {
		let crypt_state = ctx.crypt_state.clone();
		Self {
			destination: destination.clone(),
			crypt_state,
		}
	}

	pub fn serialize(&self, circ_id: u32) -> Result<Vec<u8>, Error> {
		// try to build our message
		let mut rng = nioruntime_deps::rand::thread_rng().rng_compat();
		let relay_ntpk = NtorPublicKey {
			id: self.destination.rsa_identity,
			pk: self.destination.ntor_onion_pubkey,
		};
		let (state, cmsg) = NtorClient::client1(&mut rng, &relay_ntpk)?;
		debug!("cmsg.len={}", cmsg.len())?;

		debug!("ser of an extend2 circ_id: {}", circ_id)?;
		let mut ret = vec![];

		ret.append(&mut circ_id.to_be_bytes().to_vec());
		ret.push(CHAN_CMD_RELAY_EARLY);
		ret.push(RELAY_CMD_EXTEND2);
		ret.push(0); // recognized
		ret.push(0); // recognized
		ret.push(0); // stream id = 0 (control)
		ret.push(0); // stream id = 0 (control)
		ret.push(0); // digest
		ret.push(0); // digest
		ret.push(0); // digest
		ret.push(0); // digest
		ret.append(&mut (119 as u16).to_be_bytes().to_vec()); // length of the extend2 cell is always 119.
		ret.push(2); // we use 2 link specifiers (ipv4 and rsaid)
		ret.push(0); // type 0 = tls over ipv4
		ret.push(6); // len = 6 bytes

		let port: u16 = self.destination.sockaddr.port();
		let addr = self.destination.sockaddr.ip();

		let addr = match addr {
			IpAddr::V4(addr) => addr,
			_ => {
				return Err(ErrorKind::Tor("Currently only ipv4 is supported".to_string()).into());
			}
		};
		ret.append(&mut addr.octets().to_vec());
		ret.append(&mut port.to_be_bytes().to_vec());
		ret.push(2); // rsa link specifier type
		ret.push(20); // len = 20
		ret.append(&mut self.destination.rsa_identity.as_bytes().to_vec());
		ret.append(&mut (2 as u16).to_be_bytes().to_vec()); // ntor handshake type = 0x0002
		ret.append(&mut (84 as u16).to_be_bytes().to_vec()); // ntor handshake len = 0x0084
		ret.append(&mut cmsg.to_vec()); // append ntor handshake

		let mut padding = vec![];
		padding.resize(CELL_LEN - ret.len(), 0u8);
		ret.append(&mut padding);

		{
			let mut crypt_state = lockw!(self.crypt_state)?;
			crypt_state.hs_state = Some(state);
		}

		debug!("pre encrypted cell={:?}", ret)?;
		let mut relay_cell_body = RelayCellBody(*array_mut_ref![ret, 5, 509]);
		{
			let mut crypt_state = lockw!(self.crypt_state)?;
			let hop = crypt_state.layers().saturating_sub(1) as u8;
			debug!("encrypting for hop = {}", hop)?;
			crypt_state
				.cc_out
				.encrypt(&mut relay_cell_body, hop.into())?;
			(&mut ret[5..514]).clone_from_slice(relay_cell_body.as_ref());
			debug!("encrypted cell={:?}", ret)?;
		}

		Ok(ret)
	}
}

// We don't fully support AuthChallenge because we are only a client
#[derive(Debug, Clone)]
pub struct AuthChallenge {}

impl AuthChallenge {
	fn deserialize(ctx: &mut ChannelContext) -> Result<Option<Cell>, Error> {
		let in_buf = &mut ctx.in_buf;
		if in_buf.len() < 7 {
			return Ok(None);
		}
		let circ_id = u32::from_be_bytes(*array_ref![in_buf, 0, 4]);
		let cell_len = u16::from_be_bytes(*array_ref![in_buf, 5, 2]);
		debug!("cell_len={}", cell_len)?;
		if in_buf.len() <= (cell_len + 6).into() {
			return Ok(None);
		}
		let _challenge = &in_buf[7..39];
		let n_methods = u16::from_be_bytes(*array_ref![in_buf, 39, 2]);
		let end: usize = (n_methods * 2 + 41).into();
		if in_buf.len() <= end {
			return Ok(None);
		}

		in_buf.drain(..end);
		ctx.offset = ctx.offset.saturating_sub(end);

		Ok(Some(Cell {
			body: CellBody::AuthChallenge(AuthChallenge {}),
			circ_id,
		}))
	}
}

#[derive(Debug, Clone)]
pub struct Certs {
	pub certs: Vec<TorCert>,
}

impl Certs {
	fn deserialize(ctx: &mut ChannelContext) -> Result<Option<Cell>, Error> {
		let in_buf = &mut ctx.in_buf;
		trace!("deser certs")?;
		let buf_len = in_buf.len();
		let circ_id = u32::from_be_bytes(*array_ref![in_buf, 0, 4]);
		if buf_len <= 7 {
			return Ok(None);
		}
		let cell_len = u16::from_be_bytes(*array_ref![in_buf, 5, 2]);
		let cert_count = in_buf[7];
		let end: usize = (cell_len + 7).into();

		if buf_len <= end {
			return Ok(None);
		}
		debug!("end={}", end)?;

		let mut certs = vec![];
		let mut itt = 8;
		trace!("cert_count={}", cert_count)?;
		for _i in 0..cert_count {
			if end <= itt {
				return Ok(None);
			}
			let cert_type = in_buf[itt];
			trace!("cert type = {}", cert_type)?;
			itt += 1;
			if end <= itt + 1 {
				return Ok(None);
			}
			let cert_len: usize = u16::from_be_bytes(*array_ref![in_buf, itt, 2]).into();
			trace!("cert_len = {}", cert_len)?;

			itt += 2;
			if end < itt + cert_len {
				return Ok(None);
			}
			let tor_cert = TorCert {
				cert_type,
				cert: (&in_buf[itt..(itt + cert_len)]).to_vec(),
			};
			certs.push(tor_cert);
			itt += cert_len;
		}

		in_buf.drain(..end);
		ctx.offset = ctx.offset.saturating_sub(end);
		Ok(Some(Cell {
			body: CellBody::Certs(Certs { certs }),
			circ_id,
		}))
	}
}

#[derive(Debug, Clone)]
pub struct Created2 {
	hsdata: Vec<u8>,
}

impl Created2 {
	pub fn get_hsdata(&self) -> &Vec<u8> {
		&self.hsdata
	}
	fn deserialize(ctx: &mut ChannelContext) -> Result<Option<Cell>, Error> {
		let in_buf_len = ctx.in_buf.len();
		if in_buf_len < 7 {
			return Ok(None);
		}
		let circ_id = u32::from_be_bytes(ctx.in_buf[0..4].try_into()?);
		let hslen: usize = u16::from_be_bytes(ctx.in_buf[5..7].try_into()?).into();
		if in_buf_len < hslen + 7 {
			return Ok(None);
		}
		debug!("created cell with hslen={}", hslen)?;
		let mut hsdata = Vec::with_capacity(hslen);
		hsdata.resize(hslen, 0u8);
		(&mut hsdata[..]).clone_from_slice(&ctx.in_buf[7..hslen + 7]);

		let end = hslen + 7;
		ctx.in_buf.drain(..end);
		ctx.offset = ctx.offset.saturating_sub(end);

		Ok(Some(Cell {
			body: CellBody::Created2(Created2 { hsdata }),
			circ_id,
		}))
	}
}

#[derive(Debug, Clone)]
pub struct Create2 {
	destination: Node,
	crypt_state: Arc<RwLock<ChannelCryptState>>,
}

impl Create2 {
	pub fn new(destination: &Node, ctx: &ChannelContext) -> Self {
		let crypt_state = ctx.crypt_state.clone();
		Self {
			destination: destination.clone(),
			crypt_state,
		}
	}

	pub fn serialize(&self, circ_id: u32) -> Result<Vec<u8>, Error> {
		let mut rng = nioruntime_deps::rand::thread_rng().rng_compat();
		let relay_ntpk = NtorPublicKey {
			id: self.destination.rsa_identity,
			pk: self.destination.ntor_onion_pubkey,
		};
		let (state, cmsg) = NtorClient::client1(&mut rng, &relay_ntpk)?;
		debug!("cmsg.len={}", cmsg.len())?;
		let cmsg_len: u16 = cmsg.len().try_into()?;

		let mut ret = vec![];
		ret.append(&mut circ_id.to_be_bytes().to_vec());
		ret.push(CHAN_CMD_CREATE2);

		// only ntor supported for now
		ret.append(&mut HANDSHAKE_TYPE_NTOR.to_vec());
		ret.append(&mut cmsg_len.to_be_bytes().to_vec());
		ret.append(&mut cmsg.clone());

		let mut padding = vec![];
		padding.resize(CELL_LEN - ret.len(), 0u8);
		ret.append(&mut padding);

		{
			let mut crypt_state = lockw!(self.crypt_state)?;
			crypt_state.hs_state = Some(state);
		}
		Ok(ret)
	}
}

#[derive(Debug, Clone)]
pub struct NetInfo {
	pub timestamp: u32,
	pub remote: IpAddr,
	pub local: Vec<IpAddr>,
}

impl NetInfo {
	pub fn new(remote: IpAddr, local: Vec<IpAddr>) -> Result<Self, Error> {
		let timestamp: u32 = SystemTime::now()
			.duration_since(UNIX_EPOCH)?
			.as_secs()
			.try_into()?;
		Ok(Self {
			timestamp,
			remote,
			local,
		})
	}
	pub fn serialize(&self, circ_id: u32) -> Result<Vec<u8>, Error> {
		let mut ret = vec![];
		ret.append(&mut circ_id.to_be_bytes().to_vec());
		ret.push(CHAN_CMD_NETINFO);
		ret.write_u32::<nioruntime_deps::byteorder::BigEndian>(self.timestamp)?;
		let (atype, alen) = Self::get_values(self.remote);

		ret.append(&mut vec![atype, alen]);
		ret.append(&mut Self::ser_addr(self.remote));

		let len = self.local.len();
		ret.push(len.try_into()?);

		for i in 0..len {
			let (atype, alen) = Self::get_values(self.local[i]);
			ret.append(&mut vec![atype, alen]);
			ret.append(&mut Self::ser_addr(self.local[i]));
		}

		let mut padding = vec![];
		padding.resize(CELL_LEN - ret.len(), 0u8);

		ret.append(&mut padding);

		Ok(ret)
	}

	fn ser_addr(addr: IpAddr) -> Vec<u8> {
		let mut ret = vec![];
		match addr {
			IpAddr::V4(addr) => ret.append(&mut addr.octets().to_vec()),
			IpAddr::V6(addr) => {
				let mut octets = vec![];
				for segment in addr.segments() {
					let be_bytes = segment.to_be_bytes();
					octets.push(be_bytes[0]);
					octets.push(be_bytes[1]);
				}
				ret.append(&mut octets);
			}
		}
		ret
	}

	fn get_values(addr: IpAddr) -> (u8, u8) {
		match addr {
			IpAddr::V4(_) => (4, 4),
			IpAddr::V6(_) => (6, 16),
		}
	}

	fn deserialize(ctx: &mut ChannelContext) -> Result<Option<Cell>, Error> {
		debug!("deser netinfo")?;
		let in_buf = &mut ctx.in_buf;
		let in_buf_len = in_buf.len();

		if in_buf_len < 10 {
			return Ok(None);
		}

		let circ_id = u32::from_be_bytes(*array_ref![in_buf, 0, 4]);

		let timestamp = u32::from_be_bytes(*array_ref![in_buf, 5, 4]);
		let (remote, mut ptr) = match Self::parse_address(in_buf, 9)? {
			Some(remote) => remote,
			None => return Ok(None),
		};
		let mut local = vec![];
		if in_buf_len <= ptr {
			return Ok(None);
		}
		let count = in_buf[ptr];
		ptr += 1;
		for _i in 0..count {
			match Self::parse_address(in_buf, ptr)? {
				Some((next, offset)) => {
					ptr = offset;
					local.push(next);
				}
				None => return Ok(None),
			};
		}

		in_buf.drain(..ptr);
		ctx.offset = ctx.offset.saturating_sub(ptr);
		Ok(Some(Cell {
			body: CellBody::NetInfo(NetInfo {
				timestamp,
				remote,
				local,
			}),
			circ_id,
		}))
	}

	fn parse_address(buf: &mut Vec<u8>, offset: usize) -> Result<Option<(IpAddr, usize)>, Error> {
		let len = buf.len();
		if len <= offset {
			Ok(None)
		} else {
			match buf[offset] {
				4 => {
					if len <= offset + 6 {
						Ok(None)
					} else if buf[offset + 1] != 4 {
						Err(
							ErrorKind::Tor("length must be 4 for address type 4".to_string())
								.into(),
						)
					} else {
						Ok(Some((
							IpAddr::V4(Ipv4Addr::new(
								buf[offset + 2],
								buf[offset + 3],
								buf[offset + 4],
								buf[offset + 5],
							)),
							offset + 6,
						)))
					}
				}
				6 => {
					if len <= offset + 18 {
						Ok(None)
					} else if buf[offset + 1] != 16 {
						Err(
							ErrorKind::Tor("length must be 16 for address type 6".to_string())
								.into(),
						)
					} else {
						Ok(Some((
							IpAddr::V6(Ipv6Addr::new(
								u16::from_be_bytes(*array_ref![buf, offset + 2, 2]),
								u16::from_be_bytes(*array_ref![buf, offset + 4, 2]),
								u16::from_be_bytes(*array_ref![buf, offset + 6, 2]),
								u16::from_be_bytes(*array_ref![buf, offset + 8, 2]),
								u16::from_be_bytes(*array_ref![buf, offset + 10, 2]),
								u16::from_be_bytes(*array_ref![buf, offset + 12, 2]),
								u16::from_be_bytes(*array_ref![buf, offset + 14, 2]),
								u16::from_be_bytes(*array_ref![buf, offset + 16, 2]),
							)),
							offset + 18,
						)))
					}
				}
				_ => Err(ErrorKind::Tor("Invalid address type in netinfo".to_string()).into()),
			}
		}
	}
}

#[derive(Debug, Clone)]
pub struct Padding {}

impl Padding {
	fn deserialize(ctx: &mut ChannelContext) -> Result<Option<Cell>, Error> {
		if ctx.in_buf.len() == 0 {
			return Ok(None);
		}

		let circ_id = 0;
		let mut end_padding = 0;

		for _ in 0..ctx.in_buf.len() {
			if ctx.in_buf[end_padding] == 0 {
				end_padding += 1;
			} else {
				end_padding = end_padding.saturating_sub(1);
				break;
			}
		}

		ctx.in_buf.drain(..end_padding);
		ctx.offset = ctx.offset.saturating_sub(end_padding);
		Ok(Some(Cell {
			body: CellBody::Padding(Padding {}),
			circ_id,
		}))
	}
}

#[derive(Debug, Clone)]
pub enum CellBody {
	NetInfo(NetInfo),
	Certs(Certs),
	AuthChallenge(AuthChallenge),
	Padding(Padding),
	Create2(Create2),
	Created2(Created2),
	Extend2(Extend2),
	Relay(Relay),
}

#[derive(Debug, Clone)]
pub struct Cell {
	circ_id: u32,
	body: CellBody,
}

impl Cell {
	pub fn new(circ_id: u32, body: CellBody) -> Result<Self, Error> {
		Ok(Self { circ_id, body })
	}

	pub fn next(ctx: &mut ChannelContext) -> Result<Option<Cell>, Error> {
		if ctx.offset < 5 {
			Ok(None)
		} else {
			debug!("ctx.in_buf[4] = {}", ctx.in_buf[4])?;
			match ctx.in_buf[4] {
				CHAN_CMD_NETINFO => Ok(NetInfo::deserialize(ctx)?),
				CHAN_CMD_CERTS => Ok(Certs::deserialize(ctx)?),
				CHAN_CMD_AUTH_CHALLENGE => Ok(AuthChallenge::deserialize(ctx)?),
				CHAN_CMD_PADDING => Ok(Padding::deserialize(ctx)?),
				CHAN_CMD_CREATED2 => Ok(Created2::deserialize(ctx)?),
				CHAN_CMD_RELAY => Ok(Relay::deserialize(ctx)?),
				_ => {
					warn!("Got an unexpected cell: {:?}", &ctx.in_buf[0..ctx.offset])?;
					Ok(None)
				}
			}
		}
	}

	pub fn serialize(&self) -> Result<Vec<u8>, Error> {
		match &self.body {
			CellBody::NetInfo(netinfo) => Ok(netinfo.serialize(self.circ_id)?),
			CellBody::Create2(create2) => Ok(create2.serialize(self.circ_id)?),
			CellBody::Extend2(extend2) => Ok(extend2.serialize(self.circ_id)?),
			CellBody::Relay(relay) => Ok(relay.serialize(self.circ_id)?),
			_ => {
				todo!()
			}
		}
	}

	pub fn circ_id(&self) -> u32 {
		self.circ_id
	}

	pub fn body(&self) -> &CellBody {
		&self.body
	}
}
