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

#[allow(deprecated)]
use clap::load_yaml;
use clap::Command;
use nioruntime_err::Error;
use nioruntime_evh::EventHandlerConfig;
use nioruntime_http::{HttpConfig, HttpServer};
use nioruntime_log::*;
use std::fs::File;
use std::io::{BufRead, BufReader};
use std::net::SocketAddr;
use std::str::FromStr;

info!();

// include build information
pub mod built_info {
	include!(concat!(env!("OUT_DIR"), "/built.rs"));
}

fn main() -> Result<(), Error> {
	log_config!(LogConfig {
		show_line_num: false,
		show_log_level: false,
		show_bt: false,
		..Default::default()
	})?;

	#[allow(deprecated)]
	let yml = load_yaml!("nio.yml");
	#[allow(deprecated)]
	let cmd = Command::from_yaml(yml).version(built_info::PKG_VERSION);
	let args = cmd.clone().get_matches();

	let file_args = match args.is_present("config") {
		true => {
			let mut lines = vec![];
			lines.push("fileargs".to_string());
			let file = File::open(args.value_of("config").unwrap())?;
			for line in BufReader::new(file).lines() {
				let line = line?;
				for line in line.split_ascii_whitespace() {
					lines.push(line.to_string());
				}
			}
			cmd.get_matches_from(lines)
		}
		false => {
			let lines: Vec<String> = vec![];
			#[allow(deprecated)]
			Command::from_yaml(yml)
				.version(built_info::PKG_VERSION)
				.get_matches_from(lines)
		}
	};

	let mut addrs = match args.is_present("addr") {
		true => {
			let mut addrs = vec![];
			for addr in args.values_of("addr").unwrap() {
				addrs.push(SocketAddr::from_str(addr)?);
			}
			addrs
		}
		false => vec![],
	};

	match file_args.is_present("addr") {
		true => {
			for addr in file_args.values_of("addr").unwrap() {
				addrs.push(SocketAddr::from_str(addr.trim())?);
			}
		}
		false => {}
	}

	if addrs.len() == 0 {
		addrs.push(SocketAddr::from_str("127.0.0.1:8080")?);
	}

	let threads = match args.is_present("threads") {
		true => args.value_of("threads").unwrap().parse()?,
		false => match file_args.is_present("threads") {
			true => file_args.value_of("threads").unwrap().parse()?,
			false => 8,
		},
	};

	let config = HttpConfig {
		addrs,
		evh_config: EventHandlerConfig {
			threads,
			..Default::default()
		},
		..Default::default()
	};

	let mut http = HttpServer::new(config);
	http.set_api_handler(move |_, _, _| Ok(()))?;
	http.start()?;
	std::thread::park();
	Ok(())
}
