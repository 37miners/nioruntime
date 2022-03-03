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

use nioruntime_err::{Error, ErrorKind};
use nioruntime_log::*;
use std::io::{BufRead, BufReader, Write};
use std::net::TcpStream;

debug!();

/// Tor Host. Holds information about a tor host.
#[derive(Debug, Clone)]
pub struct TorHost {
	pub addr: String,
}

/// Tor directory. Holds information about the tor directory.
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

	pub fn guards(&self) -> &Vec<TorHost> {
		&self.guards
	}

	pub fn relays(&self) -> &Vec<TorHost> {
		&self.relays
	}

	// load the guard/relay nodes from the tor directory servers. Try in order specified in [`TorDirectory::new`].
	pub fn load(&mut self) -> Result<(), Error> {
		let mut i = 0;
		let res = loop {
			match self.load_from_server(&self.directory_servers[i]) {
				Ok(info) => break info,
				Err(e) => warn!(
					"Error connecting to directory server [{}]: {}",
					self.directory_servers[i], e
				)?,
			}

			i += 1;

			if i >= self.directory_servers.len() {
				return Err(ErrorKind::ApplicationError(
					"Not able to contact any directory servers".to_string(),
				)
				.into());
			}
		};
		self.guards = res.0;
		self.relays = res.1;

		debug!("Returned guards:")?;
		let mut count = 0;
		for guard in &self.guards {
			debug!("guard[{}]={:?}", count, guard)?;
			count += 1;
		}

		debug!("Returned relays:")?;
		let mut count = 0;
		for relay in &self.relays {
			debug!("relay[{}]={:?}", count, relay)?;
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
		stream.write(b"GET /tor/status-vote/current/consensus-Microdesc HTTP/1.0\r\n\r\n")?;
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
			}
			if &line[..2] == "s " {
				match next_host.clone() {
					Some(last_host) => match line.find(" Guard") {
						Some(_) => guards.push(last_host),
						None => relays.push(last_host),
					},
					None => {
						return Err(ErrorKind::ApplicationError(
							"Invalid format for directory data. 'r' must be followed by 's'."
								.to_string(),
						)
						.into())
					}
				}
			}
		}

		Ok((guards, relays))
	}
}

#[cfg(test)]
mod test {
	use crate::directory::TorDirectory;
	use nioruntime_err::Error;
	use nioruntime_log::*;
	use std::io::{Read, Write};
	use std::net::TcpListener;

	debug!();

	#[test]
	fn test_directory_load() -> Result<(), Error> {
		let listener = TcpListener::bind("127.0.0.1:8093")?;

		info!("starting new thread to process requests")?;
		// make a mock directory server that returns two entries.
		std::thread::spawn(move || {
			for stream in listener.incoming() {
				let mut stream = stream.unwrap();
				let buf = &mut [0u8; 100];
				stream.read(&mut buf[..]).unwrap();
				stream.write(
b"r plithismos GRdTUVgUe1VLSfpLIkV1HB7yHS4 uf5xsxMQy/gJxTNnCtlBtnXOzCg 2022-02-22 14:02:49 45.61.184.239 9001 9030\r\n\
s Fast Guard Running Stable V2Dir Valid\r\n\
r emandeman44678gudno GTlGnR6Jj3Z0pV8Jvkbul0LDP6Q QUKIW/cbXHxGNhzA4BN2b0Shmss 2022-02-22 13:00:31 82.220.109.130 9001 0\r\n\
s Fast HSDir Running Stable V2Dir Valid\r\n\
r emandeman44678gudno2 GTlGnR6Jj3Z0pV8Jvkbul0LDP6Q QUKIW/cbXHxGNhzA4BN2b0Shmss 2022-02-22 13:00:31 83.220.109.130 9002 0\r\n\
p something\r\n\
s Fast HSDir V2Dir Valid\r\n\
").unwrap();
			}
		});

		let directories = vec![
			"127.0.0.1:8094".to_string(), // test failing
			"127.0.0.1:8093".to_string(),
		];

		let mut tor_dir = TorDirectory::new(directories);

		tor_dir.load()?;

		let relays = tor_dir.relays();
		assert_eq!(relays.len(), 2);
		let guards = tor_dir.guards();
		assert_eq!(guards.len(), 1);

		assert_eq!(relays[0].addr, "82.220.109.130:9001");
		assert_eq!(relays[1].addr, "83.220.109.130:9002");
		assert_eq!(guards[0].addr, "45.61.184.239:9001");

		Ok(())
	}

	#[test]
	fn test_all_dirs_fail() -> Result<(), Error> {
		let directories = vec![
			"127.0.0.1:8094".to_string(), // test failing
			"127.0.0.1:8095".to_string(),
		];

		let mut tor_dir = TorDirectory::new(directories);
		assert!(tor_dir.load().is_err());
		Ok(())
	}

	#[test]
	fn test_invalid_file() -> Result<(), Error> {
		let listener = TcpListener::bind("127.0.0.1:8099")?;

		info!("starting new thread to process requests")?;
		// make a mock directory server that returns two entries.
		std::thread::spawn(move || {
			for stream in listener.incoming() {
				let mut stream = stream.unwrap();
				let buf = &mut [0u8; 100];
				stream.read(&mut buf[..]).unwrap();
				stream.write(
b"x plithismos GRdTUVgUe1VLSfpLIkV1HB7yHS4 uf5xsxMQy/gJxTNnCtlBtnXOzCg 2022-02-22 14:02:49 45.61.184.239 9001 9030\r\n\
s Fast Guard Running Stable V2Dir Valid\r\n\
r emandeman44678gudno GTlGnR6Jj3Z0pV8Jvkbul0LDP6Q QUKIW/cbXHxGNhzA4BN2b0Shmss 2022-02-22 13:00:31 82.220.109.130 9001 0\r\n\
s Fast HSDir Running Stable V2Dir Valid\r\n\
r emandeman44678gudno2 GTlGnR6Jj3Z0pV8Jvkbul0LDP6Q QUKIW/cbXHxGNhzA4BN2b0Shmss 2022-02-22 13:00:31 83.220.109.130 9002 0\r\n\
s Fast HSDir V2Dir Valid\r\n\
").unwrap();
			}
		});

		let directories = vec![
			"127.0.0.1:8094".to_string(), // test failing
			"127.0.0.1:8099".to_string(),
		];

		let mut tor_dir = TorDirectory::new(directories);

		assert!(tor_dir.load().is_err());

		Ok(())
	}
}
