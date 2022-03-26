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
use nioruntime_deps::dirs;
use nioruntime_deps::fsutils;
use nioruntime_deps::path_clean::clean as path_clean;
use nioruntime_err::{Error, ErrorKind};
use nioruntime_evh::EventHandlerConfig;
use nioruntime_http::{HttpConfig, HttpServer, ListenerType};
use nioruntime_log::*;
use std::collections::HashMap;
use std::fs::File;
use std::io::{BufRead, BufReader};
use std::net::SocketAddr;
use std::path::PathBuf;
use std::str::FromStr;

info!();

// include build information
pub mod built_info {
	include!(concat!(env!("OUT_DIR"), "/built.rs"));
}

fn main() -> Result<(), Error> {
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
				let line = line.trim();
				if line.find("#") == Some(0) {
					continue; // comments
				}
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

	let fullchain_map = {
		let mut ret: HashMap<u16, String> = HashMap::new();
		match args.is_present("fullchain") {
			true => {
				for fullchain in args.values_of("fullchain").unwrap() {
					let mut spl = fullchain.split(':');
					let port = match spl.next() {
						Some(port) => port.parse()?,
						None => {
							return Err(
								ErrorKind::Configuration("malformed fullchain".into()).into()
							);
						}
					};

					let file = match spl.next() {
						Some(file) => file.to_string(),
						None => {
							return Err(
								ErrorKind::Configuration("malformed fullchain".into()).into()
							);
						}
					};
					ret.insert(port, file);
				}
			}
			false => {}
		}
		match file_args.is_present("fullchain") {
			true => {
				for fullchain in file_args.values_of("fullchain").unwrap() {
					let mut spl = fullchain.split(':');
					let port = match spl.next() {
						Some(port) => port.parse()?,
						None => {
							return Err(
								ErrorKind::Configuration("malformed fullchain".into()).into()
							);
						}
					};

					let file = match spl.next() {
						Some(file) => file.to_string(),
						None => {
							return Err(
								ErrorKind::Configuration("malformed fullchain".into()).into()
							);
						}
					};
					ret.insert(port, file);
				}
			}
			false => {}
		}

		ret
	};

	let privkey_map = {
		let mut ret: HashMap<u16, String> = HashMap::new();
		match args.is_present("privkey") {
			true => {
				for privkey in args.values_of("privkey").unwrap() {
					let mut spl = privkey.split(':');
					let port = match spl.next() {
						Some(port) => port.parse()?,
						None => {
							return Err(ErrorKind::Configuration("malformed privkey".into()).into());
						}
					};

					let file = match spl.next() {
						Some(file) => file.to_string(),
						None => {
							return Err(ErrorKind::Configuration("malformed privkey".into()).into());
						}
					};
					ret.insert(port, file);
				}
			}
			false => {}
		}
		match file_args.is_present("privkey") {
			true => {
				for privkey in file_args.values_of("privkey").unwrap() {
					let mut spl = privkey.split(':');
					let port = match spl.next() {
						Some(port) => port.parse()?,
						None => {
							return Err(ErrorKind::Configuration("malformed privkey".into()).into());
						}
					};

					let file = match spl.next() {
						Some(file) => file.to_string(),
						None => {
							return Err(ErrorKind::Configuration("malformed privkey".into()).into());
						}
					};
					ret.insert(port, file);
				}
			}
			false => {}
		}

		ret
	};

	let mut listeners = match args.is_present("listener") {
		true => {
			let mut listeners = vec![];
			for listener in args.values_of("listener").unwrap() {
				let mut spl = listener.split(':');
				let proto = match spl.next() {
					Some(proto) => proto,
					None => {
						return Err(ErrorKind::Configuration("malformed listener".into()).into());
					}
				};

				let sock_addr = match spl.next() {
					Some(sock_addr) => &sock_addr[2..],
					None => {
						return Err(ErrorKind::Configuration("malformed listener".into()).into());
					}
				};

				let sock_addr = match spl.next() {
					Some(port) => format!("{}:{}", sock_addr, port),
					None => {
						return Err(ErrorKind::Configuration("malformed listener".into()).into());
					}
				};

				let listener_type = if proto == "http" {
					ListenerType::Plain
				} else if proto == "https" {
					ListenerType::Tls
				} else {
					return Err(ErrorKind::Configuration(
						"malformed listener (http or https only)".into(),
					)
					.into());
				};
				listeners.push((listener_type, SocketAddr::from_str(&sock_addr)?));
			}
			listeners
		}
		false => vec![],
	};

	match file_args.is_present("listener") {
		true => {
			for listener in file_args.values_of("listener").unwrap() {
				let mut spl = listener.split(':');
				let proto = match spl.next() {
					Some(proto) => proto,
					None => {
						return Err(ErrorKind::Configuration("malformed listener".into()).into());
					}
				};

				let sock_addr = match spl.next() {
					Some(sock_addr) => &sock_addr[2..],
					None => {
						return Err(ErrorKind::Configuration("malformed listener".into()).into());
					}
				};

				let sock_addr = match spl.next() {
					Some(port) => format!("{}:{}", sock_addr, port),
					None => {
						return Err(ErrorKind::Configuration("malformed listener".into()).into());
					}
				};

				let listener_type = if proto == "http" {
					ListenerType::Plain
				} else if proto == "https" {
					ListenerType::Tls
				} else {
					return Err(ErrorKind::Configuration(
						"malformed listener (http or https only)".into(),
					)
					.into());
				};
				listeners.push((listener_type, SocketAddr::from_str(&sock_addr)?));
			}
		}
		false => {}
	}

	if listeners.len() == 0 {
		listeners.push((ListenerType::Plain, SocketAddr::from_str("127.0.0.1:8080")?));
	}

	let threads = match args.is_present("threads") {
		true => args.value_of("threads").unwrap().parse()?,
		false => match file_args.is_present("threads") {
			true => file_args.value_of("threads").unwrap().parse()?,
			false => 8,
		},
	};

	let listen_queue_size = match args.is_present("listen_queue_size") {
		true => args.value_of("listen_queue_size").unwrap().parse()?,
		false => match file_args.is_present("listen_queue_size") {
			true => file_args.value_of("listen_queue_size").unwrap().parse()?,
			false => 1_000,
		},
	};

	let max_header_size = match args.is_present("max_header_size") {
		true => args.value_of("max_header_size").unwrap().parse()?,
		false => match file_args.is_present("max_header_size") {
			true => file_args.value_of("max_header_size").unwrap().parse()?,
			false => 16_384,
		},
	};

	let max_header_name_len = match args.is_present("max_header_name_len") {
		true => args.value_of("max_header_name_len").unwrap().parse()?,
		false => match file_args.is_present("max_header_name_len") {
			true => file_args.value_of("max_header_name_len").unwrap().parse()?,
			false => 128,
		},
	};

	let max_header_value_len = match args.is_present("max_header_value_len") {
		true => args.value_of("max_header_value_len").unwrap().parse()?,
		false => match file_args.is_present("max_header_value_len") {
			true => file_args
				.value_of("max_header_value_len")
				.unwrap()
				.parse()?,
			false => 1_024,
		},
	};

	let webroot = match args.is_present("webroot") {
		true => args.value_of("webroot").unwrap(),
		false => match file_args.is_present("webroot") {
			true => file_args.value_of("webroot").unwrap(),
			false => "~/.niohttpd/www",
		},
	};

	let mainlog = match args.is_present("mainlog") {
		true => args.value_of("mainlog").unwrap(),
		false => match file_args.is_present("mainlog") {
			true => file_args.value_of("mainlog").unwrap(),
			false => "~/.niohttpd/logs/mainlog.log",
		},
	}
	.to_string();

	let mainlog_max_age = match args.is_present("mainlog_max_age") {
		true => args.value_of("mainlog_max_age").unwrap().parse()?,
		false => match file_args.is_present("mainlog_max_age") {
			true => file_args.value_of("mainlog_max_age").unwrap().parse()?,
			false => 3_600_000,
		},
	};

	let mainlog_max_size = match args.is_present("mainlog_max_size") {
		true => args.value_of("mainlog_max_size").unwrap().parse()?,
		false => match file_args.is_present("mainlog_max_size") {
			true => file_args.value_of("mainlog_max_size").unwrap().parse()?,
			false => 1_000_000,
		},
	};

	let max_header_entries = match args.is_present("max_header_entries") {
		true => args.value_of("max_header_entries").unwrap().parse()?,
		false => match file_args.is_present("max_header_entries") {
			true => file_args.value_of("max_header_entries").unwrap().parse()?,
			false => 1_000,
		},
	};

	let max_cache_files = match args.is_present("max_cache_files") {
		true => args.value_of("max_cache_files").unwrap().parse()?,
		false => match file_args.is_present("max_cache_files") {
			true => file_args.value_of("max_cache_files").unwrap().parse()?,
			false => 1_000,
		},
	};

	let max_cache_chunks = match args.is_present("max_cache_chunks") {
		true => args.value_of("max_cache_chunks").unwrap().parse()?,
		false => match file_args.is_present("max_cache_chunks") {
			true => file_args.value_of("max_cache_chunks").unwrap().parse()?,
			false => 100,
		},
	};

	let cache_chunk_size = match args.is_present("cache_chunk_size") {
		true => args.value_of("cache_chunk_size").unwrap().parse()?,
		false => match file_args.is_present("cache_chunk_size") {
			true => file_args.value_of("cache_chunk_size").unwrap().parse()?,
			false => 1_048_576,
		},
	};

	let max_load_factor = match args.is_present("max_load_factor") {
		true => args.value_of("max_load_factor").unwrap().parse()?,
		false => match file_args.is_present("max_load_factor") {
			true => file_args.value_of("max_load_factor").unwrap().parse()?,
			false => 0.9,
		},
	};

	let max_bring_to_front = match args.is_present("max_bring_to_front") {
		true => args.value_of("max_bring_to_front").unwrap().parse()?,
		false => match file_args.is_present("max_bring_to_front") {
			true => file_args.value_of("max_bring_to_front").unwrap().parse()?,
			false => 1_000,
		},
	};

	let process_cache_update = match args.is_present("process_cache_update") {
		true => args.value_of("process_cache_update").unwrap().parse()?,
		false => match file_args.is_present("process_cache_update") {
			true => file_args
				.value_of("process_cache_update")
				.unwrap()
				.parse()?,
			false => 1_000,
		},
	};

	let cache_recheck_fs_millis = match args.is_present("cache_recheck_fs_millis") {
		true => args.value_of("cache_recheck_fs_millis").unwrap().parse()?,
		false => match file_args.is_present("cache_recheck_fs_millis") {
			true => file_args
				.value_of("cache_recheck_fs_millis")
				.unwrap()
				.parse()?,
			false => 3_000,
		},
	};

	let connect_timeout = match args.is_present("connect_timeout") {
		true => args.value_of("connect_timeout").unwrap().parse()?,
		false => match file_args.is_present("connect_timeout") {
			true => file_args.value_of("connect_timeout").unwrap().parse()?,
			false => 30_000,
		},
	};

	let idle_timeout = match args.is_present("idle_timeout") {
		true => args.value_of("idle_timeout").unwrap().parse()?,
		false => match file_args.is_present("idle_timeout") {
			true => file_args.value_of("idle_timeout").unwrap().parse()?,
			false => 60_000,
		},
	};

	let read_buffer_size = match args.is_present("read_buffer_size") {
		true => args.value_of("read_buffer_size").unwrap().parse()?,
		false => match file_args.is_present("read_buffer_size") {
			true => file_args.value_of("read_buffer_size").unwrap().parse()?,
			false => 10_240,
		},
	};

	let max_rwhandles = match args.is_present("max_rwhandles") {
		true => args.value_of("max_rwhandles").unwrap().parse()?,
		false => match file_args.is_present("max_rwhandles") {
			true => file_args.value_of("max_rwhandles").unwrap().parse()?,
			false => 16_000,
		},
	};

	let max_handle_numeric_value = match args.is_present("max_handle_numeric_value") {
		true => args.value_of("max_handle_numeric_value").unwrap().parse()?,
		false => match file_args.is_present("max_handle_numeric_value") {
			true => file_args
				.value_of("max_handle_numeric_value")
				.unwrap()
				.parse()?,
			false => 16_100,
		},
	};

	let housekeeper_frequency = match args.is_present("housekeeper_frequency") {
		true => args.value_of("housekeeper_frequency").unwrap().parse()?,
		false => match file_args.is_present("housekeeper_frequency") {
			true => file_args
				.value_of("housekeeper_frequency")
				.unwrap()
				.parse()?,
			false => 1_000,
		},
	};

	let show_headers = match args.is_present("show_headers") {
		true => true,
		false => file_args.is_present("show_headers"),
	};

	let debug = match args.is_present("debug") {
		true => true,
		false => file_args.is_present("debug"),
	};

	let config = HttpConfig {
		listeners,
		fullchain_map,
		privkey_map,
		show_headers,
		listen_queue_size,
		max_header_size,
		max_header_entries,
		max_header_name_len,
		max_header_value_len,
		max_cache_files,
		max_cache_chunks,
		cache_chunk_size,
		max_load_factor,
		max_bring_to_front,
		process_cache_update,
		cache_recheck_fs_millis,
		connect_timeout,
		idle_timeout,
		mainlog_max_age,
		mainlog_max_size,
		webroot: webroot.as_bytes().to_vec(),
		debug,
		evh_config: EventHandlerConfig {
			threads,
			housekeeper_frequency,
			max_handle_numeric_value,
			max_rwhandles,
			read_buffer_size,
			..Default::default()
		},
		mainlog,
		..Default::default()
	};

	let home_dir = match dirs::home_dir() {
		Some(p) => p,
		None => PathBuf::new(),
	}
	.as_path()
	.display()
	.to_string();

	let mainlog = config.mainlog.replace("~", &home_dir);
	let mainlog = path_clean(&mainlog);

	let mut p = PathBuf::from(mainlog.clone());
	p.pop();
	fsutils::mkdir(&p.as_path().display().to_string());
	File::create(mainlog.clone())?;

	log_config!(LogConfig {
		show_line_num: false,
		show_log_level: false,
		show_bt: false,
		file_path: Some(mainlog),
		max_age_millis: config.mainlog_max_age,
		max_size: config.mainlog_max_size,
		auto_rotate: false,
		..Default::default()
	})?;

	let mut http = HttpServer::new(config)?;
	http.set_api_handler(move |_, _, _| Ok(()))?;
	http.start()?;
	std::thread::park();
	Ok(())
}
