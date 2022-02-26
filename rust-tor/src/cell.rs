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

use nioruntime_deps::arrayref::array_ref;
use nioruntime_deps::byteorder::WriteBytesExt;
use nioruntime_deps::caret::caret_int;
use nioruntime_err::{Error, ErrorKind};
use nioruntime_log::*;
use std::convert::TryInto;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

info!();

caret_int! {
		/// A ChanCmd is the type of a channel cell.  The value of the ChanCmd
		/// indicates the meaning of the cell, and (possibly) its length.
		pub struct ChanCmd(u8) {
				/// A fixed-length cell that will be dropped.
				PADDING = 0,
				/// Create a new circuit (obsolete format)
				CREATE = 1,
				/// Finish circuit-creation handshake (obsolete format)
				CREATED = 2,
				/// Relay cell, transmitted over a circuit.
				RELAY = 3,
				/// Destroy a circuit
				DESTROY = 4,
				/// Create a new circuit (no public-key)
				CREATE_FAST = 5,
				/// Finish a circuit-creation handshake (no public-key)
				CREATED_FAST = 6,
				// note gap in numbering: 7 is grouped with the variable-length cells
				/// Finish a channel handshake with time and address information
				NETINFO = 8,
				/// Relay cell, transmitted over a circuit.  Limited.
				RELAY_EARLY = 9,
				/// Create a new circuit (current format)
				CREATE2 = 10,
				/// Finish a circuit-creation handshake (current format)
				CREATED2 = 11,
				/// Adjust channel-padding settings
				PADDING_NEGOTIATE = 12,

				/// Variable-length cell, despite its number: negotiate versions
				VERSIONS = 7,
				/// Variable-length channel-padding cell
				VPADDING = 128,
				/// Provide additional certificates beyond those given in the TLS
				/// handshake
				CERTS = 129,
				/// Challenge material used in relay-to-relay handshake.
				AUTH_CHALLENGE = 130,
				/// Response material used in relay-to-relay handshake.
				AUTHENTICATE = 131,
				/// Indicates client permission to use relay.  Not currently used.
				AUTHORIZE = 132,
		}
}

#[derive(Debug)]
pub struct TorCert {
	pub cert_type: u8,
	pub cert: Vec<u8>,
}

#[derive(Debug)]
pub struct Certs {
	pub certs: Vec<TorCert>,
}

impl Certs {
	fn deserialize(in_buf: &mut Vec<u8>) -> Result<Option<Cell>, Error> {
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
		Ok(Some(Cell {
			cell_body: CellBody::Certs(Certs { certs }),
			circ_id,
		}))
	}
}

// We don't fully support AuthChallenge because we are only a client
#[derive(Debug)]
pub struct AuthChallenge {}

impl AuthChallenge {
	fn deserialize(in_buf: &mut Vec<u8>) -> Result<Option<Cell>, Error> {
		let circ_id = u32::from_be_bytes(*array_ref![in_buf, 0, 4]);
		if in_buf.len() < 38 {
			return Ok(None);
		}
		let _challenge = &in_buf[7..39];
		let n_methods = u16::from_be_bytes(*array_ref![in_buf, 39, 2]);
		let end: usize = (n_methods * 2 + 41).into();
		in_buf.drain(..end);
		Ok(Some(Cell {
			cell_body: CellBody::AuthChallenge(AuthChallenge {}),
			circ_id,
		}))
	}
}

#[derive(Debug)]
pub struct NetInfo {
	pub timestamp: u32,
	pub remote: IpAddr,
	pub local: Vec<IpAddr>,
}

impl NetInfo {
	pub fn serialize(ni: NetInfo) -> Result<Vec<u8>, Error> {
		let mut ret = vec![];
		ret.append(&mut vec![0, 0, 0, 0, 8]);
		ret.write_u32::<nioruntime_deps::byteorder::BigEndian>(ni.timestamp)?;
		let (atype, alen) = Self::get_values(ni.remote);

		ret.append(&mut vec![atype, alen]);
		ret.append(&mut Self::ser_addr(ni.remote));

		let len = ni.local.len();
		ret.push(len.try_into()?);

		for i in 0..len {
			let (atype, alen) = Self::get_values(ni.local[i]);
			ret.append(&mut vec![atype, alen]);
			ret.append(&mut Self::ser_addr(ni.local[i]));
		}

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

	fn deserialize(in_buf: &mut Vec<u8>) -> Result<Option<Cell>, Error> {
		debug!("deser net info")?;
		let circ_id = u32::from_be_bytes(*array_ref![in_buf, 0, 4]);
		let in_buf_len = in_buf.len();

		if in_buf_len < 10 {
			return Ok(None);
		}
		let timestamp = u32::from_be_bytes(*array_ref![in_buf, 5, 4]);
		let remote;
		let mut ptr;
		(remote, ptr) = match Self::parse_address(in_buf, 9)? {
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
		Ok(Some(Cell {
			cell_body: CellBody::NetInfo(NetInfo {
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

#[derive(Debug)]
pub enum CellBody {
	Certs(Certs),
	AuthChallenge(AuthChallenge),
	NetInfo(NetInfo),
}

#[derive(Debug)]
pub struct Cell {
	pub circ_id: u32,
	pub cell_body: CellBody,
}

pub fn next_cell(in_buf: &mut Vec<u8>) -> Result<Option<Cell>, Error> {
	if in_buf.len() < 5 {
		return Ok(None);
	}

	Ok(match ChanCmd(in_buf[4]) {
		ChanCmd::CERTS => Certs::deserialize(in_buf)?,
		ChanCmd::AUTH_CHALLENGE => AuthChallenge::deserialize(in_buf)?,
		ChanCmd::NETINFO => NetInfo::deserialize(in_buf)?,
		_ => None,
	})
}
