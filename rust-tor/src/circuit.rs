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

use crate::cell::{next_cell, CellBody};
use crate::channel::Channel;
use crate::common::IoState;
use crate::crypto::handshake::ntor::{NtorClient, NtorHandshakeState, NtorPublicKey};
use crate::crypto::handshake::{ClientHandshake, TapKeyGenerator};
use crate::crypto::ll::kdf::Kdf;
use crate::crypto::ll::kdf::LegacyKdf;
use crate::crypto::ClientLayer;
use crate::crypto::CryptInit;
use crate::crypto::RelayCellBody;
use crate::crypto::Tor1RelayCrypto;
use crate::crypto::{InboundClientCrypt, OutboundClientCrypt};
use crate::{ChanCmd, RelayCmd};
use nioruntime_deps::arrayref::array_ref;
use nioruntime_deps::base64;
use nioruntime_deps::hex;
use nioruntime_err::{Error, ErrorKind};
use nioruntime_log::*;
use nioruntime_util::lockw;
use std::convert::TryInto;
use std::io::{Read, Write};
use std::net::IpAddr;
use std::pin::Pin;
use std::sync::{Arc, RwLock};
use tor_llcrypto::pk::curve25519::PublicKey;
use tor_llcrypto::pk::rsa::RsaIdentity;
use tor_llcrypto::util::ct::bytes_eq;
use tor_llcrypto::util::rand_compat::RngCompatExt;

debug!();

pub struct Layers {
	cc_out: OutboundClientCrypt,
	cc_in: InboundClientCrypt,
	handshake_state: NtorHandshakeState,
	cur_hops: u8,
}

#[derive(Clone, Debug)]
pub struct Hop {
	pub ipaddr: IpAddr,
	pub port: u16,
	pub identity_bytes: [u8; 20],
	pub ntor_onion_bytes: [u8; 32],
}

#[derive(Clone)]
pub struct CircuitPlan {
	pub hops: Vec<Hop>,
}

#[derive(Clone)]
pub struct Circuit<OnComplete, OnError> {
	channel: Option<Arc<RwLock<Channel>>>,
	on_complete: Option<Pin<Box<OnComplete>>>,
	on_error: Option<Pin<Box<OnError>>>,
	is_complete: bool,
	circuit_plan: Option<CircuitPlan>,
	layers: Arc<RwLock<Option<Layers>>>,
}

impl<OnComplete, OnError> Circuit<OnComplete, OnError>
where
	OnComplete: Fn(u8) -> Result<(), Error> + Send + 'static + Clone + Sync + Unpin,
	OnError: Fn(Error) -> Result<(), Error> + Send + 'static + Clone + Sync + Unpin,
{
	pub fn new() -> Self {
		Self {
			channel: None,
			on_complete: None,
			on_error: None,
			is_complete: false,
			circuit_plan: None,
			layers: Arc::new(RwLock::new(None)),
		}
	}

	pub fn set_on_complete(&mut self, on_complete: OnComplete) -> Result<(), Error> {
		self.on_complete = Some(Box::pin(on_complete));
		Ok(())
	}

	pub fn set_on_error(&mut self, on_error: OnError) -> Result<(), Error> {
		self.on_error = Some(Box::pin(on_error));
		Ok(())
	}

	pub fn read_exact(&mut self, buf: &mut [u8]) -> Result<(), Error> {
		match &self.channel {
			Some(channel) => Ok(lockw!(channel)?.reader().read_exact(buf)?),
			None => Err(ErrorKind::Tor("must add first hop to use channel".into()).into()),
		}
	}

	pub fn _write_all(&mut self, buf: &[u8]) -> Result<(), Error> {
		match &self.channel {
			Some(channel) => Ok(lockw!(channel)?.writer().write_all(buf)?),
			None => Err(ErrorKind::Tor("must add first hop to use channel".into()).into()),
		}
	}

	pub fn read_tor(&mut self, rd: &mut dyn Read) -> Result<usize, Error> {
		match &self.channel {
			Some(channel) => Ok(lockw!(channel)?.read_tor(rd)?),
			None => Err(ErrorKind::Tor("must add first hop to use channel".into()).into()),
		}
	}

	pub fn write_tor(&mut self, wr: &mut dyn Write) -> Result<usize, Error> {
		match &self.channel {
			Some(channel) => Ok(lockw!(channel)?.write_tor(wr)?),
			None => Err(ErrorKind::Tor("must add first hop to use channel".into()).into()),
		}
	}

	pub fn process_new_packets(&mut self) -> Result<IoState, Error> {
		match &mut self.channel {
			Some(channel) => {
				let mut channel = lockw!(channel)?;
				if self.is_complete {
					Ok(channel.process_new_packets()?)
				} else {
					let io_state = channel.process_new_packets()?;
					let wlen = io_state.tls_bytes_to_write();
					self.is_complete = Self::process_incomplete(
						&mut *channel,
						io_state,
						self.on_complete.clone(),
						self.on_error.clone(),
						self.circuit_plan.as_ref(),
						self.layers.clone(),
					)?;

					if self.is_complete {
						debug!("circuit now complete. packets will go to user")?;
					}
					Ok(IoState::new(wlen, 0, false))
				}
			}
			None => Err(ErrorKind::Tor("must add first hop to use channel".into()).into()),
		}
	}

	pub fn build_circuit(&mut self, plan: CircuitPlan) -> Result<(), Error> {
		// first create channel to first hop and call create fast
		let mut channel = Channel::new(plan.hops[0].ipaddr)?;
		channel.start()?;
		self.channel = Some(Arc::new(RwLock::new(channel)));

		// next set our plan for when channel completes
		self.circuit_plan = Some(plan);
		Ok(())
	}

	fn process_incomplete(
		channel: &mut Channel,
		io_state: IoState,
		on_complete: Option<Pin<Box<OnComplete>>>,
		on_error: Option<Pin<Box<OnError>>>,
		plan: Option<&CircuitPlan>,
		layers: Arc<RwLock<Option<Layers>>>,
	) -> Result<bool, Error> {
		let mut ret = false;
		let pt_len = io_state.plaintext_bytes_to_read();
		let mut buffer = vec![];
		buffer.resize(pt_len, 0u8);
		channel.reader().read_exact(&mut buffer[..])?;

		debug!(
			"read incomplete on circuit = {} bytes. buf={:?}",
			pt_len, buffer,
		)?;

		let cell = next_cell(&mut buffer)?;

		match cell {
			Some(cell) => {
				match cell.cell_body {
					CellBody::CreatedFast(b) => {
						let mut inp = Vec::new();
						let state = channel.get_create_fast_state().unwrap();
						inp.extend(&state.0[..]);
						inp.extend(b.key_y);

						let kh_expect = LegacyKdf::new(0).derive(&inp[..], 20)?;

						if !bytes_eq(&kh_expect, &b.derivative_key_data) {
							return Err(ErrorKind::Tor(format!(
								"Bad Circ Handshake exp: {:?}, found: {:?}",
								kh_expect, b.derivative_key_data,
							))
							.into());
						}

						debug!("created fast complete: {:?}", b)?;

						let generator = TapKeyGenerator::new(inp.into());

						// first hop is done.
						match on_complete {
							Some(on_complete) => (on_complete)(1)?,
							None => error!("no on_complete handler!")?,
						}

						match &plan {
							Some(ref plan) => {
								if plan.hops.len() <= 1 {
									debug!("circuit complete!")?;
									ret = true;
								} else {
									debug!("connect to hop = {:?}", plan.hops[1])?;
									let (mut extend, handshake_state) =
										Self::build_extend(&plan.hops[1])?;
									let mut cc_out = OutboundClientCrypt::new();
									let mut cc_in = InboundClientCrypt::new();
									let pair = Tor1RelayCrypto::construct(generator).unwrap();
									let (outbound, inbound) = pair.split();
									cc_out.add_layer(Box::new(outbound));
									cc_in.add_layer(Box::new(inbound));

									Self::encode_extend(&mut extend, &mut cc_out, 0)?;

									channel.writer().write_all(&extend)?;

									{
										let mut layers = lockw!(layers)?;
										*layers = Some(Layers {
											cc_out,
											cc_in,
											handshake_state,
											cur_hops: 1,
										});
									}
								}
							}
							None => match on_error {
								Some(on_error) => {
									(on_error)(
										ErrorKind::Tor("no plan for the circuit!".into()).into(),
									)?;
								}
								None => error!("no plan for the circuit!")?,
							},
						}
					}
					CellBody::Relay(mut r) => {
						debug!("got a relay cell")?;
						{
							let mut layers = lockw!(layers)?;
							let layers = (*layers).as_mut();
							match layers {
								Some(layers) => {
									Self::decode_relay(&mut r.body, &mut layers.cc_in)?;
									debug!("decrypted cell: {:?}", r.body)?;
									ret = Self::process_relay_cell(
										channel,
										r.body,
										layers,
										on_complete,
										plan,
									)?;
								}
								None => match on_error {
									Some(on_error) => (on_error)(
										ErrorKind::Tor("got a relay cell too early".into()).into(),
									)?,
									None => error!("got a relay cell too early")?,
								},
							}
						}
					}
					CellBody::Destroy(d) => match on_error {
						Some(on_error) => (on_error)(
							ErrorKind::Tor(format!(
								"Got a destroy circuit cell. Reason = {}",
								d.reason
							))
							.into(),
						)?,
						None => error!("Got a destroy circuit cell. Reason = {}", d.reason)?,
					},
					_ => {
						// for now we ignore other cells
						debug!("other: {:?}", cell)?;
					}
				}
			}
			None => {
				// could mean that we don't have enough data to process the next cell
				debug!("none")?;
			}
		}

		Ok(ret)
	}

	fn process_relay_cell(
		channel: &mut Channel,
		cell: Vec<u8>,
		layers: &mut Layers,
		on_complete: Option<Pin<Box<OnComplete>>>,
		plan: Option<&CircuitPlan>,
	) -> Result<bool, Error> {
		let mut ret = false;
		match RelayCmd(cell[5]) {
			RelayCmd::EXTENDED2 => {
				debug!("processing extended2")?;
				ret = Self::process_extended2(channel, cell, layers, on_complete, plan)?;
			}
			_ => {
				error!("Unknown command: {}", cell[5])?;
			}
		}
		Ok(ret)
	}

	fn process_extended2(
		channel: &mut Channel,
		cell: Vec<u8>,
		layers: &mut Layers,
		on_complete: Option<Pin<Box<OnComplete>>>,
		plan: Option<&CircuitPlan>,
	) -> Result<bool, Error> {
		let mut ret = false;
		let len = u16::from_be_bytes(*array_ref![cell, 14, 2]);
		let inner_len = u16::from_be_bytes(*array_ref![cell, 16, 2]);
		let msg = *array_ref![cell, 18, 64];
		debug!("len={},inner_len={},msg={:?}", len, inner_len, msg)?;
		let generator = NtorClient::client2(layers.handshake_state.clone(), msg)?;
		let pair = Tor1RelayCrypto::construct(generator).unwrap();
		let (outbound, inbound) = pair.split();
		layers.cc_in.add_layer(Box::new(inbound));
		layers.cc_out.add_layer(Box::new(outbound));
		layers.cur_hops += 1;

		debug!("handshake complete!")?;

		match on_complete {
			Some(on_complete) => (on_complete)(layers.cur_hops)?,
			None => error!("no on_complete handler!")?,
		}

		// if there's more layers, add them
		let plan = plan.unwrap();
		if usize::from(layers.cur_hops) < plan.hops.len() {
			let (mut extend, handhsake_state) =
				Self::build_extend(&plan.hops[usize::from(layers.cur_hops)])?;
			layers.handshake_state = handhsake_state;
			Self::encode_extend(&mut extend, &mut layers.cc_out, layers.cur_hops - 1)?;
			channel.writer().write_all(&extend)?;
		} else {
			// circuit complete
			ret = true;
		}
		Ok(ret)
	}

	fn decode_relay(cell: &mut Vec<u8>, cc_in: &mut InboundClientCrypt) -> Result<(), Error> {
		let mut relay_cell_body = RelayCellBody(*array_ref![cell, 5, 509]);
		cc_in.decrypt(&mut relay_cell_body)?;
		(&mut cell[5..514]).clone_from_slice(relay_cell_body.as_ref());
		Ok(())
	}

	fn encode_extend(
		cell: &mut Vec<u8>,
		cc_out: &mut OutboundClientCrypt,
		hop_num: u8,
	) -> Result<(), Error> {
		let mut relay_cell_body = RelayCellBody(*array_ref![cell, 5, 509]);
		cc_out.encrypt(&mut relay_cell_body, hop_num.into())?;
		// TODO: remove this memcpy. Too expensive.
		(&mut cell[5..514]).clone_from_slice(relay_cell_body.as_ref());
		debug!("encrypted cell={:?}", cell)?;
		Ok(())
	}

	fn build_extend(hop: &Hop) -> Result<(Vec<u8>, NtorHandshakeState), Error> {
		let mut rng = nioruntime_deps::rand::thread_rng().rng_compat();
		let relay_public: PublicKey = hop.ntor_onion_bytes.into();
		let identity_bytes = hop.identity_bytes;

		let relay_identity = RsaIdentity::from_bytes(&(identity_bytes)[..]).unwrap();

		let relay_ntpk = NtorPublicKey {
			id: relay_identity,
			pk: relay_public,
		};
		let (state, cmsg) = NtorClient::client1(&mut rng, &relay_ntpk)?;

		let mut extend = vec![];
		extend.resize(514, 0u8);

		// for now hard code our 255 circuit
		extend[0] = 255;
		extend[1] = 255;
		extend[2] = 255;
		extend[3] = 255;
		extend[4] = ChanCmd::RELAY_EARLY.into();
		extend[5] = 14; // RELAY_EXTEND2
		extend[6] = 0; // recognized
		extend[7] = 0; // recognized
		extend[8] = 0; // stream_id
		extend[9] = 0; // stream_id
			   // extend 10 - 13 digest
		extend[14] = 0; // length
		extend[15] = 119; // length
		extend[16] = 2; // 2 link specifiers

		match hop.ipaddr {
			IpAddr::V4(addr) => {
				let octets = addr.octets();
				let port_bytes = hop.port.to_be_bytes();
				extend[17] = 0; // tls over ipv4
				extend[18] = 6; // 6 byte length
				// ipv4 address
				extend[19] = octets[0];
				extend[20] = octets[1];
				extend[21] = octets[2];
				extend[22] = octets[3];
				extend[23] = port_bytes[0];
				extend[24] = port_bytes[1];

				// rsa id
				extend[25] = 2; // rsa is type 2
				extend[26] = 20; // length = 20

				(&mut extend[27..47]).clone_from_slice(&identity_bytes);

				// ntor handshake type
				extend[47] = 0;
				extend[48] = 2;

				// handshake len is 84
				extend[49] = 0;
				extend[50] = 84;

				(&mut extend[51..135]).clone_from_slice(&cmsg);
			}
			IpAddr::V6(_addr) => {
				// TODO: implement ipv6
			}
		}

		debug!("relay early command = {:?}", extend)?;

		Ok((extend, state))
	}
}

#[cfg(test)]
mod test {
	use crate::circuit::*;
	use nioruntime_err::Error;
	use std::net::TcpStream;
	use std::net::{IpAddr, Ipv4Addr};
	use std::time::Instant;

	info!();

	#[test]
	fn test_circuit() -> Result<(), Error> {
		let now = Instant::now();
		let mut circuit = Circuit::new();

		circuit.set_on_complete(move |hop| {
			info!(
				"hop {} complete! time elapsed = {}ms.",
				hop,
				now.elapsed().as_millis()
			)?;
			Ok(())
		})?;

		circuit.set_on_error(move |e| {
			error!("Connecting to circuit resulted in error: {}", e)?;
			Ok(())
		})?;

		let plan = CircuitPlan {
			hops: vec![
				Hop {
					ipaddr: IpAddr::V4(Ipv4Addr::new(37, 200, 99, 251)),
					port: 9001,
					identity_bytes: hex::decode("F6EC46933CE8D4FAD5CCDAA8B1C5A377685FC521")?[..]
						.try_into()?,
					ntor_onion_bytes: base64::decode(
						"rS0cP7NMq/d/9SzjYkuAQ8uMA/WLhwUxy6/mng+2CXw",
					)?[..]
						.try_into()?,
				},
				Hop {
					ipaddr: IpAddr::V4(Ipv4Addr::new(45, 66, 33, 45)),
					port: 443,
					identity_bytes: hex::decode("7EA6EAD6FD83083C538F44038BBFA077587DD755")?[..]
						.try_into()?,
					ntor_onion_bytes: base64::decode(
						"OJktsaEmqNHWpEa6zxPIAc6T2MaNM8b/VEZPl58+em8",
					)?[..]
						.try_into()?,
				},
				Hop {
					ipaddr: IpAddr::V4(Ipv4Addr::new(199, 249, 230, 149)),
					port: 443,
					identity_bytes: hex::decode("7070199EF60B5B1AE4EA2EFB4881F9F90B6FA9EF")?[..]
						.try_into()?,
					ntor_onion_bytes: base64::decode(
						"JPkT/DoMZN20DR1efZ0UIOI56SjgLDUF069FwNzzCSY",
					)?[..]
						.try_into()?,
				},
			],
		};

		circuit.build_circuit(plan)?;

		let mut stream = TcpStream::connect("127.0.0.1:9001")?;

		let mut wbuf = vec![];
		circuit.write_tor(&mut wbuf)?;
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
				circuit.read_tor(&mut &buffer[0..len])?;

				match circuit.process_new_packets() {
					Ok(io_state) => {
						pt_len = io_state.plaintext_bytes_to_read();
						buffer.resize(pt_len, 0u8);
						let buf = &mut buffer[0..pt_len];
						circuit.read_exact(&mut buf[..])?;
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

				circuit.write_tor(&mut wbuf)?;

				if pt_len > 0 {
					info!(
						"circuit read bytes = {} [elapsed={}] '{:?}'",
						pt_len,
						now.elapsed().as_millis(),
						&buffer[0..pt_len]
					)?;
				} else {
					debug!("pt_len = {},now={}", pt_len, now.elapsed().as_millis())?;
				}

				if wbuf.len() > 0 {
					debug!(
						"writing {} bytes to the circuit [elapsed={}]",
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
		Ok(())
	}
}
