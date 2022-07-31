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
use crate::channel::Channel;
use crate::constants::*;
use crate::handshake::ntor::NtorClient;
use crate::handshake::ClientHandshake;
use crate::types::CircuitContext;
use crate::types::CircuitPlan;
use crate::util::tor1::ClientLayer;
use crate::util::tor1::CryptInit;
use crate::util::RngCompatExt;
use crate::util::Tor1RelayCrypto;
use crate::TorState;
use nioruntime_deps::rand::Rng;
use nioruntime_err::{Error, ErrorKind};
use nioruntime_log::*;
use std::io::{Read, Write};
use std::net::IpAddr;

info!();

struct Circuit {
	plan: CircuitPlan,
	channel: Channel,
	create2: bool,
	created2: bool,
	extension_count: usize,
	built: bool,
	circuit_id: u32,
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
		})
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
		self.channel
			.send_cell(Cell::new(self.circuit_id, cell_body)?)
	}

	pub fn process_new_packets(&mut self, ctx: &mut CircuitContext) -> Result<TorState, Error> {
		let tor_state = self.channel.process_new_packets(&mut ctx.channel_context)?;
		let mut ret_state = tor_state.clone();
		let verified = self.channel.is_verified();
		debug!("channel verified = {}", self.channel.is_verified())?;

		if !verified {
			// protect so we don't do anything unverified
			if tor_state.cells().len() > 0 {
				return Err(ErrorKind::Tor(
					"Channel sent cells before verification complete".to_string(),
				)
				.into());
			}
			return Ok(ret_state);
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

			self.channel.send_cell(Cell::new(
				self.circuit_id,
				CellBody::Create2(Create2::new(&hop, &ctx.channel_context)),
			)?)?;
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
						let crypt_state_clone = ctx.channel_context.crypt_state.clone();
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

				// we handle the create2 cell so do not pass onto user
				ret_state.clear();
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
								let crypt_state_clone = ctx.channel_context.crypt_state.clone();
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

			// since we handle the extended2 we don't pass it along.
			ret_state.clear();
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
				self.channel.send_cell(Cell::new(
					self.circuit_id,
					CellBody::Extend2(Extend2::new(&hops[hop], &ctx.channel_context)),
				)?)?;
			}
		}

		Ok(ret_state)
	}
}

#[cfg(test)]
mod test {
	use crate::cell::CellBody;
	use crate::cell::Relay;
	use crate::circuit::Circuit;
	use crate::constants::*;
	use crate::process::test::TorProcess;
	use crate::types::CircuitContext;
	use crate::types::CircuitPlan;
	use crate::types::Node;
	use nioruntime_err::{Error, ErrorKind};
	use nioruntime_log::*;
	use std::io::{Read, Write};
	use std::net::TcpStream;
	use std::time::Instant;

	info!();

	fn launch_tor(working_dir: &str, process: &mut TorProcess) {
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
		let mut wbuf = vec![];
		let mut sent_begin = false;

		// first launch three tor instances
		// note we use 0% because this configuration is a testnet which is never
		// bootstrapped.
		let mut _p = TorProcess::new();
		launch_tor("./test/router1", &mut _p);
		let mut _p = TorProcess::new();
		launch_tor("./test/router2", &mut _p);
		let mut _p = TorProcess::new();
		launch_tor("./test/router3", &mut _p);

		let mut stream = TcpStream::connect("127.0.0.1:39001")?;
		let node1 = Node::new(
			"127.0.0.1:39001",                              // router1
			"Z9aVaImseaOHcmqF8PYjPRvRtsoNRkgMfVunFQUDTag=", // ed25519Identity
			"PtfQsnnCPPA93X3BcbFeCxGMLDfVfIG4XbzVCIlOsgU=", // ntor pubkey
			"v29gfbDlrWStvBjWRnqwKNUhpv4=",                 // rsa identity
		)?;

		let node2 = Node::new(
			"127.0.0.1:39002",                              // router2
			"8nf9qPZ9gixbks0KrZEiLsKJYyVmmAgZUAW/iYvGnKI=", // ed25519Identity
			"l7BJm4Cq3c8YJlq/H+vaUtdaJ4K7lsDEmqv8ZI3HUjo=", // ntor pubkey
			"kJP6GBtWIPDGzQWJLpLA7qW2M9o",                  // rsa identity
		)?;

		let node3 = Node::new(
			"127.0.0.1:39003",                              // router3
			"Z9aVaImseaOHcmqF8PYjPRvRtsoNRkgMfVunFQUDTag=", // ed25519Identity
			"zoxann7++99ntL8gQThK4IJPiKU+XOOhTihl3pIDa04=", // ntor pubkey
			"x06BlN36ChTqd9Nqeb25o0byc0I=",                 // rsa identity
		)?;

		let plan = CircuitPlan::new(vec![node1, node2, node3]);
		let mut circuit = Circuit::new(plan)?;

		circuit.start()?;

		circuit.write_tor(&mut wbuf)?;
		stream.write(&wbuf)?;

		let mut buffer: Vec<u8> = vec![];
		buffer.resize(1024 * 1024, 0u8);
		let mut ctx = CircuitContext::new();
		let now = Instant::now();

		info!("Begin tor loop")?;

		loop {
			wbuf.clear();
			if buffer.len() != 1024 * 1024 {
				buffer.resize(1024 * 1024, 0u8);
			}

			let len = stream.read(&mut buffer[..])?;

			debug!("read len = {} bytes", len)?;
			// returning 0 means disconnect. Error occurred.
			assert!(len != 0);

			circuit.read_tor(&mut &buffer[0..len])?;

			match circuit.process_new_packets(&mut ctx) {
				Ok(tor_state) => {
					info!(
						"[{}]: circuit.is_built = {} got tor state = {:?}",
						now.elapsed().as_millis(),
						circuit.is_built(),
						tor_state,
					)?;
					if circuit.is_built() && !sent_begin {
						// send cells
						circuit.send_cell(CellBody::Relay(Relay::new_begin(
							"example.com:80",
							ctx.channel_context.crypt_state.clone(),
							12,
						)?))?;
						circuit.send_cell(CellBody::Relay(Relay::new_data(
							b"GET / HTTP/1.0\r\n\r\n".to_vec(),
							ctx.channel_context.crypt_state.clone(),
							12,
						)?))?;

						sent_begin = true;
					}

					for cell in tor_state.cells() {
						if circuit.is_built() {
							match cell.body() {
								CellBody::Relay(relay) => {
									// relays have a policy not to allow exits if they don't
									// know the previous host.  Since our testnet is not
									// fully setup it follows this policy and closes the
									// connection. It's ok we just assert these values below.
									assert_eq!(relay.get_relay_cmd(), RELAY_CMD_END);
									assert_eq!(cell.circ_id(), circuit.id());
									assert_eq!(relay.stream_id(), 12);
									assert_eq!(relay.get_relay_data(), &vec![1]);
									// success return so test passes.
									return Ok(());
								}
								_ => {
									return Err(ErrorKind::ApplicationError(format!(
										"Unexpected cell: {:?}",
										cell
									))
									.into());
								}
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

			circuit.write_tor(&mut wbuf)?;

			if wbuf.len() > 0 {
				debug!(
					"writing {} bytes to the channel [elapsed={}]",
					wbuf.len(),
					now.elapsed().as_millis()
				)?;
				stream.write(&wbuf)?;
			}
		}
	}
}
