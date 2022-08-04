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
use crate::cell::CellBody;
use crate::cell::Create2;
use crate::cell::Extend2;
use crate::cell::NetInfo;
use crate::cell::Relay;
use crate::channel::Channel;
use crate::constants::*;
use crate::handshake::ntor::NtorClient;
use crate::handshake::ClientHandshake;
use crate::stream::StreamImpl;
use crate::types::ChannelContext;
use crate::types::CircuitPlan;
use crate::types::Stream;
use crate::types::StreamEventType;
use crate::util::tor1::ClientLayer;
use crate::util::tor1::CryptInit;
use crate::util::RngCompatExt;
use crate::util::Tor1RelayCrypto;
use crate::TorState;
use nioruntime_deps::rand::Rng;
use nioruntime_err::{Error, ErrorKind};
use nioruntime_log::*;
use std::collections::HashMap;
use std::io::{Read, Write};
use std::net::IpAddr;

info!();

pub struct CircuitState<'a> {
	built: bool,
	is_closed: bool,
	circuit: &'a mut Circuit,
}

impl<'a> CircuitState<'a> {
	pub fn ready(&mut self) -> Result<Vec<StreamImpl>, Error> {
		self.circuit.ready()
	}
	pub fn built(&self) -> bool {
		self.built
	}
	pub fn is_closed(&self) -> bool {
		self.is_closed
	}

	fn new(built: bool, is_closed: bool, circuit: &'a mut Circuit) -> Self {
		Self {
			built,
			is_closed,
			circuit,
		}
	}
}

pub struct Circuit {
	plan: CircuitPlan,
	channel: Channel,
	create2: bool,
	created2: bool,
	extension_count: usize,
	built: bool,
	circuit_id: u32,
	sendme_state: HashMap<u64, u64>,
	channel_context: ChannelContext,
	tor_state: Option<TorState>,
}

impl Circuit {
	pub fn new(plan: CircuitPlan) -> Result<Self, Error> {
		let mut rng = nioruntime_deps::rand::thread_rng().rng_compat();
		let mut circuit_id: u32 = rng.gen();
		circuit_id |= 0x80000000;
		let hops = plan.hops();
		if hops.len() < 1 {
			return Err(ErrorKind::Tor("Plan must have at least 1 hop".to_string()).into());
		}

		let channel = Channel::new(hops[0].clone())?;
		Ok(Self {
			plan,
			channel,
			built: false,
			circuit_id,
			create2: false,
			created2: false,
			extension_count: 0,
			sendme_state: HashMap::new(),
			channel_context: ChannelContext::new(),
			tor_state: None,
		})
	}

	pub fn close(&mut self, sid: u16, reason: u8) -> Result<(), Error> {
		let body = CellBody::Relay(Relay::new_end(
			reason,
			self.channel_context().crypt_state.clone(),
			sid,
		)?);

		self.send_cell(body)?;

		let circ_id = self.id();
		let id: u64 = (sid as u64) << 32 | (circ_id as u64);
		self.sendme_state.remove(&id);

		Ok(())
	}

	pub(crate) fn channel_context(&self) -> &ChannelContext {
		&self.channel_context
	}

	pub fn ready<'a>(&'a mut self) -> Result<Vec<StreamImpl>, Error> {
		let circ_id = self.id();
		if !self.built {
			return Ok(vec![]);
		}

		let mut map: HashMap<u16, StreamImpl> = HashMap::new();
		let mut end_map: HashMap<u16, StreamImpl> = HashMap::new();
		let mut connected_map: HashMap<u16, StreamImpl> = HashMap::new();

		match &self.tor_state {
			Some(tor_state) => {
				let mut ret = vec![];
				for cell in tor_state.cells() {
					match cell.body() {
						CellBody::Relay(relay) => {
							let cmd = relay.get_relay_cmd();
							if cmd == RELAY_CMD_DATA {
								let sid = relay.stream_id();
								let found = match map.get_mut(&sid) {
									Some(se) => {
										se.data().append(&mut relay.get_relay_data().to_vec());
										true
									}
									None => false,
								};
								if !found {
									let se = StreamImpl::new(
										relay.stream_id(),
										circ_id,
										StreamEventType::Readable,
										relay.get_relay_data().to_vec(),
									);
									map.insert(sid, se);
								}
							} else if cmd == RELAY_CMD_END {
								let sid = relay.stream_id();
								match end_map.get_mut(&sid) {
									Some(_) => {}
									None => {
										let data = relay.get_relay_data();
										let mut reason = 0;
										if data.len() >= 1 {
											reason = data[0];
										}
										let se = StreamImpl::new(
											relay.stream_id(),
											circ_id,
											StreamEventType::Close(reason),
											relay.get_relay_data().to_vec(),
										);
										end_map.insert(sid, se);
									}
								}
							} else if cmd == RELAY_CMD_CONNECTED {
								let sid = relay.stream_id();
								match connected_map.get_mut(&sid) {
									Some(_) => {}
									None => {
										let se = StreamImpl::new(
											relay.stream_id(),
											circ_id,
											StreamEventType::Connected,
											relay.get_relay_data().to_vec(),
										);
										connected_map.insert(sid, se);
									}
								}
							} else if cmd == RELAY_CMD_EXTENDED2 {
								// note: this is expected behaviour
								// because we set built after this cell
								// has been added to the struct
								// tor_state. We ignore it here.
							} else {
								warn!("Got another type of command. Cell = {:?}", cell)?;
							}
						}
						_ => {}
					}
				}
				for (_k, v) in connected_map {
					ret.push(v);
				}
				for (_k, v) in map {
					ret.push(v);
				}
				for (_k, v) in end_map {
					ret.push(v);
				}
				Ok(ret)
			}
			None => Ok(vec![]),
		}
	}

	pub fn open_stream_dir(&mut self) -> Result<Box<dyn Stream>, Error> {
		let mut rng = nioruntime_deps::rand::thread_rng().rng_compat();
		let stream_id: u16 = rng.gen();

		let circ_id = self.id();
		let id: u64 = (stream_id as u64) << 32 | (circ_id as u64);
		self.sendme_state.insert(id as u64, 0);

		let body = CellBody::Relay(Relay::new_begin_dir(
			self.channel_context.crypt_state.clone(),
			stream_id,
		)?);
		self.send_cell(body)?;

		let stream = StreamImpl::new(stream_id, self.id(), StreamEventType::Created, vec![]);

		Ok(Box::new(stream))
	}

	pub fn open_stream(&mut self, address_port: &str) -> Result<Box<dyn Stream>, Error> {
		let mut rng = nioruntime_deps::rand::thread_rng().rng_compat();
		let stream_id: u16 = rng.gen();

		let circ_id = self.id();
		let id: u64 = (stream_id as u64) << 32 | (circ_id as u64);
		self.sendme_state.insert(id as u64, 0);

		debug!("address port = {}", address_port)?;
		let body = CellBody::Relay(Relay::new_begin(
			address_port,
			self.channel_context.crypt_state.clone(),
			stream_id,
		)?);
		self.send_cell(body)?;

		let stream = StreamImpl::new(stream_id, self.id(), StreamEventType::Created, vec![]);

		Ok(Box::new(stream))
	}

	pub fn id(&self) -> u32 {
		self.circuit_id
	}

	pub fn is_built(&self) -> bool {
		self.built
	}

	pub fn start(&mut self) -> Result<(), Error> {
		self.channel.start()?;
		Ok(())
	}

	pub fn read_tor(&mut self, rd: &mut dyn Read) -> Result<usize, Error> {
		self.channel.read_tor(rd)
	}

	pub fn write_tor(&mut self, wr: &mut dyn Write) -> Result<usize, Error> {
		self.channel.write_tor(wr)
	}

	pub fn send_cell(&mut self, cell_body: CellBody) -> Result<(), Error> {
		let cell = Cell::new(self.circuit_id, cell_body)?;
		debug!("sending cell = {:?}", cell)?;
		self.channel.send_cell(cell)
	}

	pub fn process_new_packets<'a>(&'a mut self) -> Result<CircuitState<'a>, Error> {
		let tor_state = self
			.channel
			.process_new_packets(&mut self.channel_context)?;
		self.tor_state = Some(tor_state.clone());
		let verified = self.channel.is_verified();
		if !verified {
			// protect so we don't do anything unverified
			if tor_state.cells().len() > 0 {
				return Err(ErrorKind::Tor(
					"Channel sent cells before verification complete".to_string(),
				)
				.into());
			}
			return Ok(CircuitState::new(
				self.built,
				tor_state.peer_has_closed(),
				self,
			));
		} else if !self.create2 {
			// we haven't sent the create2 cell yet. Do so.
			let hop = &self.plan.hops()[0];
			let sockaddr = &hop.sockaddr;
			let ip = sockaddr.ip();
			let ip = match ip {
				IpAddr::V4(ip) => ip,
				_ => {
					return Err(ErrorKind::Tor("Ipv4 only supported".to_string()).into());
				}
			};
			self.channel.send_cell(Cell::new(
				0,
				CellBody::NetInfo(NetInfo::new(
					IpAddr::V4(ip),
					vec![IpAddr::V4("127.0.0.1".parse()?)],
				)?),
			)?)?;

			self.send_cell(CellBody::Create2(Create2::new(&hop, &self.channel_context)))?;
			self.create2 = true;
		} else if !self.created2 {
			// we should have a created cell here
			for cell in tor_state.cells() {
				match cell.body() {
					CellBody::Created2(created2) => {
						if self.created2 {
							return Err(ErrorKind::Tor(
								"unexpected multiple create2 cells on circuit.".to_string(),
							)
							.into());
						}
						// update our crypt_state
						let crypt_state_clone = self.channel_context.crypt_state.clone();
						let mut crypt_state = lockw!(crypt_state_clone)?;
						match &crypt_state.hs_state {
							Some(state) => {
								let hsdata = created2.get_hsdata();
								debug!("hsdata = {}", hsdata.len())?;
								let generator = NtorClient::client2(state.clone(), hsdata)?;
								let pair = Tor1RelayCrypto::construct(generator).unwrap();
								let (outbound, inbound) = pair.split();
								crypt_state.cc_out.add_layer(Box::new(outbound));
								crypt_state.cc_in.add_layer(Box::new(inbound));
								debug!("created2 on circ id = {}", cell.circ_id())?;
								self.created2 = true;
								self.extension_count = 1;
							}
							None => {
								error!("expected a build state")?;
								return Err(ErrorKind::InternalError(
									"build state not found".to_string(),
								)
								.into());
							}
						}
					}
					_ => {
						return Err(ErrorKind::Tor(format!(
							"Unepxected cell before circuit built: {:?}",
							cell
						))
						.into());
					}
				}
			}
		} else if !self.built {
			// the only thing we should get here are relay cells that have extended2's
			// in them.

			let cells = tor_state.cells();

			for cell in cells {
				match cell.body() {
					CellBody::Relay(relay) => {
						debug!("got a relay: {:?}", relay)?;
						let cmd = relay.get_relay_cmd();
						match cmd {
							RELAY_CMD_EXTENDED2 => {
								let crypt_state_clone = self.channel_context.crypt_state.clone();
								let mut crypt_state = lockw!(crypt_state_clone)?;
								match &crypt_state.hs_state {
									Some(state) => {
										let hsdata = &relay.get_relay_data()[2..];
										debug!("hsdata.len={}", hsdata.len())?;
										let generator = NtorClient::client2(state.clone(), hsdata)?;
										let pair = Tor1RelayCrypto::construct(generator).unwrap();
										let (outbound, inbound) = pair.split();
										crypt_state.cc_out.add_layer(Box::new(outbound));
										crypt_state.cc_in.add_layer(Box::new(inbound));
										debug!(
											"extended2 on circ id = {}, layers = {}",
											cell.circ_id(),
											crypt_state.layers(),
										)?;
										self.extension_count += 1;
									}
									None => {
										error!("expected a build state")?;
										return Err(ErrorKind::InternalError(
											"build state not found".to_string(),
										)
										.into());
									}
								}
							}
							_ => {
								warn!("Unexpected cell: {:?}", cell)?;
								// we shouldn't get anything else since the
								// circuit is not built yet. return error.
								return Err(ErrorKind::Tor(format!(
									"Unepxected cell before circuit built: {:?}",
									cell
								))
								.into());
							}
						}
					}
					_ => {
						warn!("Unexpected cell: {:?}", cell)?;
						return Err(ErrorKind::Tor(format!(
							"Unepxected cell before circuit built: {:?}",
							cell
						))
						.into());
					}
				}
			}

			if cells.len() > 1 {
				// we should only get a single extend2 here. return error.
				return Err(ErrorKind::Tor(
					"unexpected multiple extended2 cells on circuit.".to_string(),
				)
				.into());
			}
		}

		if self.created2 && !self.built {
			// if we have created we check where we are in extending process
			let hops = self.plan.hops();
			if self.extension_count >= hops.len() {
				self.built = true;
			} else {
				// we need to extend
				let hop = self.extension_count;
				debug!("impl extend2")?;
				self.send_cell(CellBody::Extend2(Extend2::new(
					&hops[hop],
					&self.channel_context,
				)))?;
			}
		}

		if self.built {
			self.check_sendme(&tor_state)?;
		}

		Ok(CircuitState::new(
			self.built,
			tor_state.peer_has_closed(),
			self,
		))
	}

	fn check_sendme(&mut self, state: &TorState) -> Result<(), Error> {
		for cell in state.cells() {
			match cell.body() {
				CellBody::Relay(relay) => {
					let circ_id = cell.circ_id();
					let stream_id = relay.stream_id();
					let id: u64 = (stream_id as u64) << 32 | (circ_id as u64);
					let cmd = relay.get_relay_cmd();
					match cmd {
						RELAY_CMD_END => {
							// this stream has ended. remove it from the
							// hashmap

							match self.sendme_state.remove(&id) {
								Some(_) => {
									debug!("Removing sid={}", stream_id)?;
								}
								None => {
									warn!(
										"Tried to remove a stream that we didn't know about {}",
										stream_id
									)?;
								}
							}
						}
						_ => {
							let v_stream = match self.sendme_state.get_mut(&id) {
								Some(cur) => {
									let ret = *cur;
									*cur += 1;
									ret
								}
								None => 0,
							};

							if v_stream == 0 {
								self.sendme_state.insert(id, 1);
							}

							let v_circ = match self.sendme_state.get_mut(&(circ_id as u64)) {
								Some(cur) => {
									let ret = *cur;
									*cur += 1;
									ret
								}
								None => 0,
							};

							if v_circ == 0 {
								self.sendme_state.insert(circ_id as u64, 1);
							}

							// flow control stream level at every 50
							if (1 + v_stream) % 50 == 0 {
								self.send_cell(CellBody::Relay(Relay::new_sendme(
									self.channel_context.crypt_state.clone(),
									stream_id,
								)?))?;
							}

							// flow control circuit level at every 100
							if (1 + v_circ) % 100 == 0 {
								self.send_cell(CellBody::Relay(Relay::new_sendme(
									self.channel_context.crypt_state.clone(),
									0,
								)?))?;
							}
						}
					}
				}
				_ => {}
			}
		}
		Ok(())
	}
}

#[cfg(test)]
mod test {
	use crate::circuit::Circuit;
	use crate::process::test::TorProcess;
	use crate::types::CircuitPlan;
	use crate::types::Node;
	use crate::types::Stream;
	use crate::types::StreamEventType;
	use nioruntime_err::{Error, ErrorKind};
	use nioruntime_log::*;
	use std::io::{Read, Write};
	use std::net::TcpStream;
	use std::time::Instant;

	info!();

	fn setup_test_dir(name: &str) -> Result<(), Error> {
		let _ = std::fs::remove_dir_all(name);
		std::fs::create_dir_all(name)?;
		std::fs::create_dir_all(format!("{}/router1/data/keys", name))?;
		std::fs::create_dir_all(format!("{}/router2/data/keys", name))?;
		std::fs::create_dir_all(format!("{}/router3/data/keys", name))?;

		std::fs::copy(
			"./test/router1/torrc.circuit",
			format!("{}/router1/torrc", name),
		)?;
		std::fs::copy(
			"./test/router2/torrc.circuit",
			format!("{}/router2/torrc", name),
		)?;
		std::fs::copy(
			"./test/router3/torrc.circuit",
			format!("{}/router3/torrc", name),
		)?;

		for file in std::fs::read_dir("./test/router1/data/keys").unwrap() {
			let file = file.unwrap();
			std::fs::copy(
				format!("{}", file.path().display()),
				format!(
					"{}/router1/data/keys/{}",
					name,
					file.file_name().into_string()?
				),
			)?;
		}

		for file in std::fs::read_dir("./test/router2/data/keys").unwrap() {
			let file = file.unwrap();
			std::fs::copy(
				format!("{}", file.path().display()),
				format!(
					"{}/router2/data/keys/{}",
					name,
					file.file_name().into_string()?
				),
			)?;
		}

		for file in std::fs::read_dir("./test/router3/data/keys").unwrap() {
			let file = file.unwrap();
			std::fs::copy(
				format!("{}", file.path().display()),
				format!(
					"{}/router3/data/keys/{}",
					name,
					file.file_name().into_string()?
				),
			)?;
		}
		Ok(())
	}

	fn tear_down_test_dir(name: &str) -> Result<(), Error> {
		std::fs::remove_dir_all(name)?;
		Ok(())
	}

	fn launch_tor(working_dir: &str, process: &mut TorProcess) {
		// note we use 0% because this configuration is a testnet which is never
		// bootstrapped.
		process
			.torrc_path(&"torrc")
			.working_dir(working_dir)
			.timeout(200)
			.completion_percent(0)
			.launch()
			.unwrap();
	}

	#[test]
	fn test_circuit() -> Result<(), Error> {
		let test_dir = ".test_circuit.nio";
		setup_test_dir(test_dir)?;

		let mut success = false;
		let mut read_data = false;
		let mut wbuf = vec![];
		let mut sent_begin = false;

		// first launch three tor instances

		let mut _p = TorProcess::new();
		launch_tor(&format!("{}/router1", test_dir)[..], &mut _p);
		let mut _p = TorProcess::new();
		launch_tor(&format!("{}/router2", test_dir)[..], &mut _p);
		let mut _p = TorProcess::new();
		launch_tor(&format!("{}/router3", test_dir)[..], &mut _p);

		/*
		let mut stream = TcpStream::connect("104.53.221.159:9001")?;
		let node1 = Node::new(
			"104.53.221.159:9001",                          // router1
			"ZtzhbIWHJpGQG+5N7hbRTtenyzq2RNJrx0QegtoY+bY=", // ed25519Identity
			"03dOCy/Dud/kPwIzD+cbpIR+K8BxJoHIKmGsrXvJiFY=", // ntor pubkey
			"AAoQ1DAR6kkoo19hBAX5K0QztNw=",                 // rsa identity
		)?;

		let node2 = Node::new(
			"154.35.175.225:443",                           // router2
			"r/mzLbFVinqX14PW091o3jM14ifPiEO4zdVxr8BQrsI=", // ed25519Identity
			"SVcLOUxfauyHtZ08gp1SbxKPlGyhbO6oUBZBv0bYpDw=", // ntor pubkey
			"z20Kr7OFvnG44RH8XP9LR5I3M7w=",                 // rsa identity
		)?;

		let node3 = Node::new(
			"5.255.101.131:9001",
			"fKy8py24dUeTinJgQ78OW0c7BV2Q3gX24OMIDZCZQ+4=",
			"MmMf88cx87yaT1/psofamaKdEmRg07x0NStFhbOr0yc=",
			"CLSIimVm9rxTY0I4YvSFKUIKufc=",
		)?;
				*/
		let mut stream = TcpStream::connect("127.0.0.1:39101")?;
		let node1 = Node::new(
			"127.0.0.1:39101",                              // router1
			"Z9aVaImseaOHcmqF8PYjPRvRtsoNRkgMfVunFQUDTag=", // ed25519Identity
			"PtfQsnnCPPA93X3BcbFeCxGMLDfVfIG4XbzVCIlOsgU=", // ntor pubkey
			"v29gfbDlrWStvBjWRnqwKNUhpv4=",                 // rsa identity
		)?;

		let node2 = Node::new(
			"127.0.0.1:39102",                              // router2
			"8nf9qPZ9gixbks0KrZEiLsKJYyVmmAgZUAW/iYvGnKI=", // ed25519Identity
			"l7BJm4Cq3c8YJlq/H+vaUtdaJ4K7lsDEmqv8ZI3HUjo=", // ntor pubkey
			"kJP6GBtWIPDGzQWJLpLA7qW2M9o",                  // rsa identity
		)?;

		let node3 = Node::new(
			"127.0.0.1:39103",                              // router3
			"Z9aVaImseaOHcmqF8PYjPRvRtsoNRkgMfVunFQUDTag=", // ed25519Identity
			"zoxann7++99ntL8gQThK4IJPiKU+XOOhTihl3pIDa04=", // ntor pubkey
			"x06BlN36ChTqd9Nqeb25o0byc0I=",                 // rsa identity
		)?;

		let now = Instant::now();
		let plan = CircuitPlan::new(vec![node1, node2, node3]);
		let mut circuit = Circuit::new(plan)?;

		circuit.start()?;

		circuit.write_tor(&mut wbuf)?;
		stream.write(&wbuf)?;

		info!("Begin tor loop")?;
		let mut buffer = vec![];
		const BUFFER_SIZE: usize = 8 * 1024;
		buffer.resize(BUFFER_SIZE, 0u8);

		let mut local_id = 0;

		loop {
			wbuf.clear();

			let len = stream.read(&mut buffer[0..BUFFER_SIZE])?;

			debug!("read len = {} bytes", len)?;
			// returning 0 means disconnect. Error occurred.
			assert!(len != 0);

			circuit.read_tor(&mut &buffer[0..len])?;
			{
				{
					match circuit.process_new_packets() {
						Ok(mut state) => {
							for stream in state.ready()? {
								match stream.event_type() {
									StreamEventType::Readable => {
										info!(
											"read data on stream id [elapsed={}] = {}: {}",
											now.elapsed().as_millis() as f64 / 1000 as f64,
											stream.sid(),
											std::str::from_utf8(stream.get_data()?)
												.unwrap_or("non-utf8")
										)?;
										assert!(local_id != 0);
										assert_eq!(local_id, stream.sid());
										read_data = true;
									}
									StreamEventType::Close(reason) => {
										info!(
											"stream {} closed for reason: {}",
											stream.sid(),
											reason
										)?;
										if read_data {
											info!(
												"Test was successful. Ran in {} seconds.",
												now.elapsed().as_millis() as f64 / 1000 as f64
											)?;
											success = true;
											break;
										}
									}
									StreamEventType::Connected => {
										info!("stream {} connected", stream.sid())?;
									}
									_ => {
										warn!("other type of event: {:?}", stream.event_type())?;
									}
								}
							}
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
				}

				if circuit.is_built() && !sent_begin {
					let mut stream = circuit.open_stream_dir()?;
					local_id = stream.id();
					stream.write(
						&mut circuit,
						b"GET / HTTP/1.1\r\nHost: example.com\r\nConnection: keep-alive\r\n\r\n",
					)?;
					sent_begin = true;
				}
			}

			circuit.write_tor(&mut wbuf)?;

			if wbuf.len() > 0 {
				debug!(
					"writing {} bytes to the channel [elapsed={}]",
					wbuf.len(),
					now.elapsed().as_millis()
				)?;
				stream.write(&wbuf)?;
			}

			if success {
				break;
			}
		}

		tear_down_test_dir(test_dir)?;
		Ok(())
	}
}
