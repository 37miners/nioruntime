// Copyright 2021 The BMW Developers
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

/*
use byte_tools::copy;
use byteorder::{LittleEndian, ReadBytesExt};
use clap::load_yaml;
use clap::App;
use native_tls::TlsConnector;
use nioruntime_err::{Error, ErrorKind};
use nioruntime_evh::EventHandler;
use nioruntime_evh::EventHandlerConfig;
use nioruntime_evh::TlsConfig;
use nioruntime_http::HttpConfig;
use nioruntime_http::HttpServer;
use nioruntime_log::*;
use rand::Rng;
use std::collections::HashMap;
use std::io::Cursor;
use std::io::Read;
use std::io::Write;
use std::net::TcpListener;
use std::net::TcpStream;
use std::sync::Arc;
use std::sync::Mutex;

debug!();

const MAX_BUF: usize = 100_000;

struct Buffer {
	data: [u8; MAX_BUF],
	len: usize,
}

impl Buffer {
	fn new() -> Self {
		let data = [0u8; MAX_BUF];
		let len = 0;
		Buffer { data, len }
	}
}

// include build information
pub mod built_info {
	include!(concat!(env!("OUT_DIR"), "/built.rs"));
}
*/

/*
use nioruntime_deps::failure::{self, Context, Fail};
use std::fmt::{self, Display};
use nioruntime_log::*;

/// Base Error struct which is used throught this crate and other crates
#[derive(Debug, Fail)]
pub struct Error {
	inner: Context<ErrorKind>,
}

#[derive(Clone, Eq, PartialEq, Debug, Fail)]
pub enum ErrorKind {
	#[fail(display = "Abc: {}", _0)]
	Abc(String),
}

impl Display for Error {
		fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
				let cause = match self.cause() {
						Some(c) => format!("{}", c),
						None => String::from("Unknown"),
				};
				let backtrace = match self.backtrace() {
						Some(b) => format!("{}", b),
						None => String::from("Unknown"),
				};
				let output = format!(
						"{} \n Cause: {} \n Backtrace: {}",
						self.inner, cause, backtrace
				);
				Display::fmt(&output, f)
		}
}

impl From<nioruntime_err::Error> for Error {
	fn from(error: nioruntime_err::Error) -> Error {
		Error { inner: Context::new(ErrorKind::Abc(format!("{}", error))) }
	}
}
*/

use nioruntime_log::*;

trace!();

fn main() -> Result<(), std::io::Error> {
	log_config!(LogConfig {
		show_bt: false,
		show_stdout: false,
		file_path: Some("abc".to_string()),
		..Default::default()
	})
	.expect("log config");

	fatal!("fatal").expect("failed to log");
	fatal_no_ts!("fatal_no_ts").expect("failed to log");
	fatal_all!("fatal all").expect("failed to log");

	error!("error").expect("failed to log");
	error_no_ts!("error_no_ts").expect("failed to log");
	error_all!("error all").expect("failed to log");

	warn!("warn").expect("failed to log");
	warn_no_ts!("warn_no_ts").expect("failed to log");
	warn_all!("warn all").expect("failed to log");

	info!("info").expect("failed to log");
	info_no_ts!("info no ts").expect("failed to log");
	info_all!("info all").expect("failed to log");

	debug!("debug").expect("failed to log");
	debug_no_ts!("debug no ts").expect("failed to log");
	debug_all!("debug all").expect("failed to log");

	trace!("trace").expect("failed to log");
	trace_no_ts!("trace_no_ts").expect("failed to log");
	trace_all!("trace all").expect("failed to log");

	Ok(())
	/*
		let res = real_main();
		match res {
			Ok(_) => {}
			Err(e) => error!("real_main generated Error: {}", e.to_string()),
		}
	*/
}

/*
fn client_thread(
	count: usize,
	id: usize,
	tlat_sum: Arc<Mutex<f64>>,
	tlat_max: Arc<Mutex<u128>>,
	min: u32,
	max: u32,
	tls: bool,
) -> Result<(), Error> {
	let mut lat_sum = 0.0;
	let mut lat_max = 0;
	let (mut stream, mut tls_stream) = {
		let _lock = tlat_sum.lock();
		let (stream, tls_stream) = if tls {
			let connector = TlsConnector::builder()
				.danger_accept_invalid_hostnames(true)
				.build()
				.unwrap();
			(
				None,
				Some(
					connector
						.connect("example.com", TcpStream::connect("127.0.0.1:9999")?)
						.unwrap(),
				),
			)
		} else {
			(Some(TcpStream::connect("127.0.0.1:9999")?), None)
		};

		(stream, tls_stream)
	};
	let buf = &mut [0u8; MAX_BUF];
	let buf2 = &mut [0u8; MAX_BUF];
	let start_itt = std::time::SystemTime::now();
	for i in 0..count {
		if i != 0 && i % 10000 == 0 {
			let elapsed = start_itt.elapsed().unwrap().as_millis();
			let qps = (i as f64 / elapsed as f64) * 1000 as f64;
			info!("Request {} on thread {}, qps={}", i, id, qps);
		}
		let start_query = std::time::SystemTime::now();
		let num: u32 = rand::thread_rng().gen_range(min..max);
		let num_buf = num.to_le_bytes();
		let offt: u8 = rand::thread_rng().gen_range(0..64);
		copy(&num_buf[0..4], &mut buf[0..4]);
		buf[4] = offt;
		let offt = offt as u32;
		for i in 0..num {
			buf[i as usize + 5] = ((i + offt) % 128) as u8;
		}
		let res = match stream {
			Some(ref mut stream) => stream.write(&buf[0..(num as usize + 5)]),
			None => {
				let stream = tls_stream.as_mut().unwrap();
				stream.write(&buf[0..(num as usize + 5)])
			}
		};

		match res {
			Ok(_x) => {}
			Err(e) => {
				info!("Write Error: {}", e.to_string());
				std::thread::sleep(std::time::Duration::from_millis(1));
			}
		}

		let mut len_sum = 0;
		loop {
			let res = match stream {
				Some(ref mut stream) => stream.read(&mut buf2[len_sum..]),
				None => {
					let stream = tls_stream.as_mut().unwrap();
					stream.read(&mut buf2[len_sum..])
				}
			};

			match res {
				Ok(_) => {}
				Err(ref e) => {
					info!("Read Error: {}", e.to_string());
					assert!(false);
				}
			}
			let len = res.unwrap();
			len_sum += len;
			if len_sum == num as usize + 5 {
				break;
			}
		}

		if num == 99990 {
			// we expect a close here. Try one more read
			let len = match stream {
				Some(ref mut stream) => stream.read(&mut buf2[0..])?,
				None => {
					let stream = tls_stream.as_mut().unwrap();
					stream.read(&mut buf2[0..])?
				}
			};

			// len should be 0
			assert_eq!(len, 0);
			// not that only a single request is currently supported in this mode.
			// TODO: support reconnect
			info!("Successful disconnect");
		}

		let elapsed = start_query.elapsed().unwrap().as_nanos();
		lat_sum += elapsed as f64;
		if elapsed > lat_max {
			lat_max = elapsed;
		}

		assert_eq!(len_sum, num as usize + 5);
		assert_eq!(Cursor::new(&buf2[0..4]).read_u32::<LittleEndian>()?, num);
		assert_eq!(buf2[4], offt as u8);
		for i in 0..num {
			if buf2[i as usize + 5] != ((i + offt) % 128) as u8 {
				info!("assertion at {} fails", i);
			}
			assert_eq!(buf2[i as usize + 5], ((i + offt) % 128) as u8);
		}
		// clear buf2
		for i in 0..MAX_BUF {
			buf2[i] = 0;
		}
	}

	{
		let mut tlat_sum = tlat_sum.lock().unwrap();
		(*tlat_sum) += lat_sum;
	}
	{
		let mut tlat_max = tlat_max.lock().unwrap();
		if lat_max > *tlat_max {
			(*tlat_max) = lat_max;
		}
	}

	Ok(())
}

fn real_main() -> Result<(), Error> {
	log_config!(nioruntime_log::LogConfig::default())?;

	let yml = load_yaml!("nio.yml");
	let args = App::from_yaml(yml)
		.version(built_info::PKG_VERSION)
		.get_matches();
	let client = args.is_present("client");
	let debug = args.is_present("debug");
	let print_headers = args.is_present("print_headers");
	let threads = args.is_present("threads");
	let count = args.is_present("count");
	let itt = args.is_present("itt");
	let http_port = args.is_present("http_port");
	let max = args.is_present("max");
	let min = args.is_present("min");
	let tor = args.is_present("tor_port");
	let bind_address = args.is_present("addr");
	let http = args.is_present("http");
	let certs = args.is_present("certs");
	let private_key = args.is_present("private_key");
	let tls = args.is_present("tls");

	if (certs && !private_key) || (!certs && private_key) {
		return Err(ErrorKind::SetupError(
			"either both or neither certs or private_key must be specified".to_string(),
		)
		.into());
	}

	let tls_config = match certs {
		true => Some(TlsConfig {
			certificates_file: args.value_of("certs").unwrap().to_string(),
			private_key_file: args.value_of("private_key").unwrap().to_string(),
		}),
		false => None,
	};

	let threads = match threads {
		true => args.value_of("threads").unwrap().parse().unwrap(),
		false => 1,
	};

	let count = match count {
		true => args.value_of("count").unwrap().parse().unwrap(),
		false => 1,
	};

	let tor = match tor {
		true => args.value_of("tor_port").unwrap().parse().unwrap(),
		false => 0,
	};

	let host = match bind_address {
		true => args.value_of("addr").unwrap().to_string(),
		false => "0.0.0.0".to_string(),
	};

	let itt = match itt {
		true => args.value_of("itt").unwrap().parse().unwrap(),
		false => 1,
	};

	let http_port = match http_port {
		true => args.value_of("http_port").unwrap().parse().unwrap(),
		false => 8080,
	};

	let max = match max {
		true => args.value_of("max").unwrap().parse().unwrap(),
		false => 100,
	};

	let min = match min {
		true => args.value_of("min").unwrap().parse().unwrap(),
		false => 1,
	};

	if http {
		let config = HttpConfig {
			debug,
			print_headers,
			tor_port: tor,
			host,
			port: http_port,
			evh_config: EventHandlerConfig {
				tls_config,
				..Default::default()
			},
			..Default::default()
		};
		let mut http_server: HttpServer = HttpServer::new(config);
		http_server.start()?;
		http_server.add_api_mapping("/rustlet".to_string())?;
		http_server.add_api_extension("rsp".to_string())?;
		std::thread::park();
	} else if client {
		info!("Running client");
		info!("Threads={}", threads);
		info!("Iterations={}", itt);
		info!("Requests per thread per iteration={}", count);
		info!("Request length: Max={},Min={}", max, min);
		info_no_ts!(
			"--------------------------------------------------------------------------------"
		);

		let time = std::time::SystemTime::now();
		let tlat_sum = Arc::new(Mutex::new(0.0));
		let tlat_max = Arc::new(Mutex::new(0));

		for x in 0..itt {
			let mut jhs = vec![];
			for i in 0..threads {
				let id = i.clone();
				let tlat_sum = tlat_sum.clone();
				let tlat_max = tlat_max.clone();
				jhs.push(std::thread::spawn(move || {
					let res =
						client_thread(count, id, tlat_sum.clone(), tlat_max.clone(), min, max, tls);
					match res {
						Ok(_) => {}
						Err(e) => {
							info!("Error in client thread: {}", e.to_string());
							assert!(false);
						}
					}
				}));
			}

			for jh in jhs {
				jh.join().expect("panic in thread");
			}
			info!("Iteration {} complete. ", x + 1);
		}

		let elapsed_millis = time.elapsed().unwrap().as_millis();
		let lat_max = tlat_max.lock().unwrap();
		info_no_ts!(
			"--------------------------------------------------------------------------------"
		);
		info!("Test complete in {} ms", elapsed_millis);
		let tlat = tlat_sum.lock().unwrap();
		let avg_lat = (*tlat) / (1_000_000 * count * threads * itt) as f64;
		//let qps_simple = (1000.0 / avg_lat) * threads as f64;
		let qps = (threads * count * itt * 1000) as f64 / elapsed_millis as f64;
		info!("QPS={}", qps);
		info!("Average latency={}ms", avg_lat,);
		info!("Max latency={}ms", (*lat_max) as f64 / (1_000_000 as f64));
	} else {
		let listener = TcpListener::bind("127.0.0.1:9999")?;
		info!("Listener Started");
		let mut eh = EventHandler::new(EventHandlerConfig {
			thread_count: 6,
			tls_config,
		});

		let buffers: Arc<Mutex<HashMap<u128, Arc<Mutex<Buffer>>>>> =
			Arc::new(Mutex::new(HashMap::new()));
		let buffers_clone = buffers.clone();
		let buffers_clone2 = buffers.clone();
		eh.set_on_read(move |buf, len, wh| {
			let held_buf;
			{
				let mut buffers = buffers_clone2.lock().unwrap();
				let held_buf2 = buffers.get_mut(&wh.get_connection_id()).unwrap();
				held_buf = held_buf2.clone()
			}

			let mut held_buf = held_buf.lock().unwrap();
			let hbuf_len = (*held_buf).len;
			copy(
				&buf[0..len],
				&mut (*held_buf).data[hbuf_len..hbuf_len + len],
			);
			(*held_buf).len += len;
			if (*held_buf).len < 5 {
				// not enough data
				Ok(())
			} else {
				let exp_len = Cursor::new(&(*held_buf).data[0..4]).read_u32::<LittleEndian>()?;
				let offt = (*held_buf).data[4] as u32;
				if exp_len + 5 == (*held_buf).len as u32 {
					let ret_len = (*held_buf).len;
					(*held_buf).len = 0;

					// do assertion for our test
					for i in 0..ret_len - 5 {
						if (*held_buf).data[i as usize + 5] != ((i + offt as usize) % 128) as u8 {
							info!("invalid data at index = {}", i + 5);
						}
						assert_eq!(
							(*held_buf).data[i as usize + 5],
							((i + offt as usize) % 128) as u8
						);
					}

					// special case, we disconnect at this len for testing.
					// client is aware and should do an assertion on disconnect.
					wh.write(&(*held_buf).data.to_vec()[0..ret_len])?;
					if exp_len == 99990 {
						wh.close()?;
					}
					Ok(())
				} else {
					Ok(())
				}
			}
		})?;
		eh.set_on_client_read(move |buf, len, wh| {
			wh.write(&buf.to_vec()[0..len])?;
			Ok(())
		})?;
		eh.set_on_accept(move |connection_id, _wh| {
			let mut buffers = buffers.lock().unwrap();

			buffers.insert(connection_id, Arc::new(Mutex::new(Buffer::new())));

			Ok(())
		})?;

		eh.set_on_close(move |connection_id| {
			let mut buffers = buffers_clone.lock().unwrap();
			buffers.remove(&connection_id);
			Ok(())
		})?;
		eh.start()?;
		eh.add_tcp_listener(&listener)?;
		std::thread::park();
	}
	Ok(())
}
*/
