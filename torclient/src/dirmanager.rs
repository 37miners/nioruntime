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

use crate::data::TorData;
use nioruntime_deps::chrono::Utc;
use nioruntime_err::{Error, ErrorKind};
use nioruntime_log::*;
use nioruntime_tor::directory::TorRelay;
use nioruntime_tor::TorDirectory;
use nioruntime_util::bytes_find;
use std::io::{Read, Write};
use std::net::TcpStream;

debug!();

// for now just do direct download. We should use circuits.
const DIR_AUTHORITIES: [&str; 10] = [
	"204.13.164.118:80",
	"199.58.81.140:80",
	"193.23.244.244:80",
	"45.66.33.45:80",
	"86.59.21.38:80",
	"128.31.0.34:9193",
	"66.111.2.131:9030",
	"171.25.193.9:443",
	"154.35.175.225:80",
	"131.188.40.189:80",
];

pub struct DirManager {
	directory: TorDirectory,
}

impl DirManager {
	pub fn new(data_dir: String) -> Result<Self, Error> {
		let data = TorData::new(&data_dir)?;
		let directory = Self::load(data.clone())?;
		data.write_directory(&directory)?;
		Ok(Self { directory })
	}

	pub fn random_guard(&self) -> Option<&TorRelay> {
		self.directory.random_guard()
	}

	pub fn random_relay(&self) -> Option<&TorRelay> {
		self.directory.random_relay()
	}

	pub fn random_exit(&self) -> Option<&TorRelay> {
		self.directory.random_exit()
	}

	fn try_load_cache(data: &TorData) -> Result<Option<TorDirectory>, Error> {
		data.read_directory()
	}

	fn load(data: TorData) -> Result<TorDirectory, Error> {
		match Self::try_load_cache(&data)? {
			Some(tor_directory) => {
				let now = Utc::now().naive_utc().timestamp();
				if tor_directory.valid_until() > now {
					info!(
						"Returning a valid tor directory. It is valid for {} more seconds.",
						tor_directory.valid_until() - now
					)?;
					return Ok(tor_directory);
				}
			}
			None => {}
		}

		for authority in DIR_AUTHORITIES {
			match Self::load_http(authority, data.clone()) {
				Ok(dir) => {
					return Ok(dir);
				}
				Err(e) => {
					warn!("Error loading authority: {} -> {}", authority, e)?;
					continue;
				}
			}
		}
		return Err(ErrorKind::Tor("No directories could be loaded".to_string()).into());
	}

	pub fn load_http(authority: &str, tor_data: TorData) -> Result<TorDirectory, Error> {
		let mut strm = TcpStream::connect(authority)?;
		strm.write(
			format!(
			"GET /tor/status-vote/current/authority HTTP/1.1\r\nHost: {}\r\nConnection: close\r\n\r\n",
			authority
		)
			.as_bytes(),
		)?;

		let mut buf = vec![];
		const CHUNK_SIZE: usize = 1024;
		buf.resize(CHUNK_SIZE, 0u8);
		let mut offset = 0;

		loop {
			let len = strm.read(&mut buf[offset..])?;
			if len == 0 {
				break;
			}
			offset += len;
			buf.resize(offset + CHUNK_SIZE, 0u8);
		}

		match bytes_find(&buf[0usize..50usize], b"503 ") {
			Some(_) => {
				// server busy try the next one
				return Err(ErrorKind::Tor("503 server busy error".into()).into());
			}
			None => {}
		}

		let data = std::str::from_utf8(&buf)?;
		debug!("data='{}',len={}", data, data.len())?;

		let mut ret = TorDirectory::from_bytes(data.as_bytes())?;
		Self::load_known_micros(tor_data.clone(), &mut ret)?;
		let relays = ret.unknown_ntor_relays().clone();
		let relay_count = relays.len();

		debug!("found {} new tor relays", relay_count)?;
		let mut offset = 0;
		let batch_size = 85;

		if relay_count > 0 {
			loop {
				let end = if relay_count < (offset + batch_size) {
					relay_count
				} else {
					offset + batch_size
				};
				Self::load_micro(authority, &relays[offset..end], &mut ret, tor_data.clone())?;
				if offset + batch_size >= relay_count {
					break;
				}
				offset += batch_size;
			}
		}

		ret.repopulate_ntor()?;

		Ok(ret)
	}

	fn load_known_micros(data: TorData, directory: &mut TorDirectory) -> Result<(), Error> {
		let relays = directory.relays();

		let mut to_add = vec![];

		for relay in relays {
			match data.get_ntor(&relay.microdesc)? {
				Some(ntor_onion_pubkey) => {
					to_add.push((relay.microdesc.clone(), ntor_onion_pubkey.clone()));
				}
				None => {}
			}
		}

		debug!("adding {} ntor_onion_pubkeys from cache", to_add.len())?;
		for (microdesc, ntor_onion_pubkey) in to_add {
			directory.add_ntor(&microdesc, &ntor_onion_pubkey)?;
		}

		Ok(())
	}

	fn load_micro(
		authority: &str,
		relays: &[TorRelay],
		directory: &mut TorDirectory,
		tor_data: TorData,
	) -> Result<(), Error> {
		let lookup = directory.get_ed25519_id_map().clone();
		let mut request_string = "".to_string();
		let mut first = true;
		for relay in relays {
			if first {
				request_string = format!("GET /tor/micro/d/{}", relay.microdesc);
			} else {
				request_string = format!("{}-{}", request_string, relay.microdesc);
			}
			first = false;
		}
		let request_string = format!("{} HTTP/1.0\r\n\r\n", request_string);

		debug!("request_string = {}", request_string)?;

		let mut strm = TcpStream::connect(authority)?;
		strm.write(request_string.as_bytes())?;

		let mut buf = vec![];
		const CHUNK_SIZE: usize = 1024 * 10;
		buf.resize(CHUNK_SIZE, 0u8);
		let mut offset = 0;

		loop {
			let len = strm.read(&mut buf[offset..])?;
			if len == 0 {
				break;
			}
			offset += len;
			buf.resize(offset + CHUNK_SIZE, 0u8);
		}
		let data = std::str::from_utf8(&buf)?;
		debug!("microddata='{}',len={}", data, data.len())?;
		let lines = data.split('\n');
		let mut index = 0;

		let mut ed25519_ids = vec![];
		for line in lines.clone() {
			if line.starts_with("id ed25519 ") {
				let spl: Vec<&str> = line.split(' ').collect();
				ed25519_ids.push(spl[2]);
			}
		}

		for line in lines {
			if line.starts_with("ntor-onion-key ") {
				let spl: Vec<&str> = line.split(' ').collect();
				debug!(
					"adding ntor microdesc = {}: {}",
					relays[index].microdesc, spl[1]
				)?;

				let relay = match lookup.get(ed25519_ids[index]) {
					Some(relay) => relay,
					None => {
						let append_equals = format!("{}=", ed25519_ids[index]);
						match lookup.get(&append_equals) {
							Some(relay) => relay,
							None => {
								return Err(ErrorKind::Tor(format!(
									"ed25519 id '{}' not found",
									ed25519_ids[index]
								))
								.into());
							}
						}
					}
				};
				debug!("inserting {}", relay.microdesc)?;
				tor_data.insert_ntor(&relay.microdesc, spl[1])?;
				directory.add_ntor(&relay.microdesc, spl[1])?;
				index += 1;
			}
		}

		debug!("index={},ed25519_ids.len()={}", index, ed25519_ids.len())?;

		Ok(())
	}
}
