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

use nioruntime_err::Error;
use nioruntime_log::*;
use std::io::{BufRead, BufReader, Read, Write};
use std::net::TcpStream;

debug!();

#[derive(Debug, Clone)]
pub struct TorHost {
	addr: String,
}

pub struct TorDirectory {
	directory_servers: Vec<String>,
	guards: Vec<TorHost>,
	relays: Vec<TorHost>,
}

impl TorDirectory {
	pub fn new(directory_servers: Vec<String>) -> Self {
		Self {
			directory_servers,
			relays: vec![],
			guards: vec![],
		}
	}

	pub fn load(&mut self) -> Result<(), Error> {
		let mut i = 0;
		let (guards, relays) = loop {
			match self.load_from_server(&self.directory_servers[i]) {
				Ok(info) => break info,
				Err(e) => {
					// warn and try next
					warn!(
						"Error connecting to directory server [{}]: {}",
						self.directory_servers[i], e
					)?;
				}
			}

			i += 1;
		};

		info!("Returned guards:");
		let mut count = 0;
		for guard in guards {
			info!("guard[{}]={:?}", count, guard);
			count += 1;
		}

		info!("Returned relays:");
		let mut count = 0;
		for relay in relays {
			info!("relay[{}]={:?}", count, relay);
			count += 1;
		}

		Ok(())
	}

	fn load_from_server(
		&self,
		directory_server: &String,
	) -> Result<(Vec<TorHost>, Vec<TorHost>), Error> {
		let mut relays = vec![];
		let mut guards = vec![];
		let mut stream = TcpStream::connect(directory_server)?;
		stream.write(b"GET /tor/status-vote/current/consensus/ HTTP/1.0\r\n\r\n")?;
		let mut reader = BufReader::new(stream);
		let mut next_host: Option<TorHost> = None;
		loop {
			let mut line = String::new();
			let count = reader.read_line(&mut line)?;
			if count == 0 {
				break;
			}

			if &line[..2] == "r " {
				let split: Vec<&str> = line.split(" ").collect();
				let addr = format!("{}:{}", split[6], split[7]);
				next_host = Some(TorHost { addr });
				//relays.push(TorHost{ addr });
			}
			if &line[..2] == "s " {
				let last_host = next_host.clone().unwrap();
				match line.find(" Guard") {
					Some(_) => guards.push(last_host),
					None => relays.push(last_host),
				}
			}
		}

		Ok((guards, relays))
	}
}

mod test {
	use crate::directory::*;
	use nioruntime_err::Error;

	#[test]
	fn test_directory_load() -> Result<(), Error> {
		let directories = vec![
			"45.66.33.45:80".to_string(),
			"193.23.244.244:80".to_string(),
			"66.111.2.131:80".to_string(),
		];

		let mut tor_dir = TorDirectory::new(directories);

		tor_dir.load()?;

		Ok(())
	}
}
