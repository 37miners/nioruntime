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

const SEPARATOR: &str =
	"---------------------------------------------------------------------------------------------";
//123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890
//         1         2         3         4         5         6         7         8         9

use clap::load_yaml;
use clap::App;
use colored::Colorize;
use native_tls::TlsConnector;
use nioruntime_err::{Error, ErrorKind};
use nioruntime_evh::*;
use nioruntime_http::{HttpConfig, HttpServer};
use nioruntime_log::*;
use nioruntime_util::lockw;
use num_format::{Locale, ToFormattedString};
use std::alloc::{GlobalAlloc, Layout, System};
use std::convert::TryInto;
use std::io::{Read, Write};
use std::mem;
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::str::FromStr;
use std::sync::{Arc, RwLock};
use std::time::Instant;

// unix
#[cfg(unix)]
use nix::sys::socket::{InetAddr, SockAddr};
#[cfg(unix)]
use std::os::unix::io::{AsRawFd, FromRawFd};
#[cfg(unix)]
use std::os::unix::prelude::RawFd;

// windows
#[cfg(windows)]
use std::os::windows::io::{AsRawSocket, FromRawSocket};
#[cfg(windows)]
use std::os::windows::prelude::RawSocket;

debug!();

struct MonAllocator;

static mut MEM_ALLOCATED: i128 = 0;
static mut MEM_DEALLOCATED: i128 = 0;
static mut ALLOC_COUNT: i128 = 0;
static mut DEALLOC_COUNT: i128 = 0;

unsafe impl GlobalAlloc for MonAllocator {
	unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
		MEM_ALLOCATED += layout.size() as i128;
		ALLOC_COUNT += 1;
		System.alloc(layout)
	}

	unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
		MEM_DEALLOCATED += layout.size() as i128;
		DEALLOC_COUNT += 1;
		System.dealloc(ptr, layout)
	}
}

#[global_allocator]
static GLOBAL: MonAllocator = MonAllocator;

// structure to hold the histogram data
#[derive(Clone)]
struct Histo {
	buckets: Vec<Arc<RwLock<u64>>>,
	max: usize,
	bucket_count: usize,
}

impl Histo {
	fn new(max: usize, bucket_count: usize) -> Self {
		let mut buckets = vec![];

		// we make a bucket for each microsecond + one extra for above the max
		for _ in 0..max + 1 {
			buckets.push(Arc::new(RwLock::new(0)));
		}

		Histo {
			buckets,
			max,
			bucket_count,
		}
	}

	// increment the count for this bucket
	fn incr(&self, bucket_num: usize) -> Result<(), Error> {
		let mut bucket = self.buckets[bucket_num].write().map_err(|e| {
			let error: Error =
				ErrorKind::ApplicationError(format!("error obtaining lock: {}", e)).into();
			error
		})?;
		*bucket += 1;

		Ok(())
	}

	// get the value at this bucket
	fn get(&self, bucket_num: usize) -> Result<u64, Error> {
		let bucket = self.buckets[bucket_num].read().map_err(|e| {
			let error: Error =
				ErrorKind::ApplicationError(format!("error obtaining lock: {}", e)).into();
			error
		})?;
		Ok(*bucket)
	}

	// display the histogram in a readable fashion
	fn display(&self) -> Result<(), Error> {
		let bucket_divisor = self.max / self.bucket_count;
		let mut display_buckets_vec = vec![];
		for _ in 0..self.bucket_count + 1 {
			display_buckets_vec.push(0u64);
		}
		let display_buckets = &mut display_buckets_vec[..];
		let mut total = 0;
		for i in 0..self.max + 1 {
			let bucket_num = i / bucket_divisor;
			let num = self.get(i)?;
			display_buckets[bucket_num] += num;
			total += num;
		}
		for i in 0..self.bucket_count + 1 {
			let percentage = 100 as f64 * display_buckets[i] as f64 / total as f64;
			let percentage_int = percentage as u64;
			let mut line = "".to_string();
			line = format!("{}{}", line, "|".white());
			for _ in 0..percentage_int {
				line = format!("{}{}", line, "=".green());
			}

			if display_buckets[i] > 0 {
				line = format!("{}{}", line, ">".green());
			} else {
				line = format!("{} ", line);
			}
			for _ in percentage_int..50 {
				line = format!("{} ", line);
			}
			line = format!("{}{} ", line, "|".white());
			if percentage < 10.0 {
				line = format!("{} ", line);
			}
			let low_range = (bucket_divisor * i) as f64 / 1000 as f64;
			let high_range = (bucket_divisor * (1 + i)) as f64 / 1000 as f64;

			if i == self.bucket_count {
				line = format!(
					"{}{:.3}% ({:.2}ms and up  ) num={}",
					line,
					percentage,
					low_range,
					display_buckets[i].to_formatted_string(&Locale::en)
				);
				if percentage > 10.0 {
					info_no_ts!("{}", line.red())?;
				} else if percentage > 1.0 {
					info_no_ts!("{}", line.cyan())?;
				} else {
					info_no_ts!("{}", line)?;
				}
			} else {
				line = format!(
					"{}{:.3}% ({:.2}ms - {:.2}ms) num={}",
					line,
					percentage,
					low_range,
					high_range,
					display_buckets[i].to_formatted_string(&Locale::en)
				);

				if percentage > 10.0 {
					info_no_ts!("{}", line.red())?;
				} else if percentage > 1.0 {
					info_no_ts!("{}", line.cyan())?;
				} else {
					info_no_ts!("{}", line)?;
				}
			}
		}
		Ok(())
	}
}

#[cfg(unix)]
type Handle = RawFd;
#[cfg(windows)]
type Handle = u64;

#[cfg(unix)]
fn get_fd() -> Result<Handle, Error> {
	let raw_fd = nix::sys::socket::socket(
		nix::sys::socket::AddressFamily::Inet,
		nix::sys::socket::SockType::Stream,
		nix::sys::socket::SockFlag::empty(),
		None,
	)?;

	let optval: libc::c_int = 1;
	unsafe {
		libc::setsockopt(
			raw_fd,
			libc::SOL_SOCKET,
			libc::SO_REUSEPORT,
			&optval as *const _ as *const libc::c_void,
			mem::size_of_val(&optval) as libc::socklen_t,
		)
	};

	unsafe {
		libc::setsockopt(
			raw_fd,
			libc::SOL_SOCKET,
			libc::SO_REUSEADDR,
			&optval as *const _ as *const libc::c_void,
			mem::size_of_val(&optval) as libc::socklen_t,
		)
	};

	Ok(raw_fd)
}

#[cfg(windows)]
fn get_fd() -> Result<u64, Error> {
	Ok(0)
}

#[cfg(unix)]
fn get_handles(count: usize, addr: &str) -> Result<(Vec<Handle>, Vec<TcpListener>), Error> {
	let std_sa = SocketAddr::from_str(addr).unwrap();
	let inet_addr = InetAddr::from_std(&std_sa);
	let sock_addr = SockAddr::new_inet(inet_addr);

	let mut handles = vec![];
	let mut listeners = vec![];

	for _ in 0..count {
		let fd = get_fd()?;
		nix::sys::socket::bind(fd, &sock_addr)?;
		nix::sys::socket::listen(fd, 1000)?;

		#[cfg(unix)]
		let listener = unsafe { TcpListener::from_raw_fd(fd) };
		#[cfg(windows)]
		let listener = unsafe { TcpListener::from(OwnedSocket::from_raw_socket(RawSocket::from(fd))) };
		listener.set_nonblocking(true)?;

		#[cfg(unix)]
		handles.push(listener.as_raw_fd());
		#[cfg(windows)]
		handles.push(listener.as_raw_socket());
		listeners.push(listener);
	}

	Ok((handles, listeners))
}

#[cfg(windows)]
fn get_handles(count: usize, addr: &str) -> Result<(Vec<Handle>, Vec<TcpListener>), Error> {
	Ok((vec![], vec![]))
}

// include build information
pub mod built_info {
	include!(concat!(env!("OUT_DIR"), "/built.rs"));
}

fn print_alloc(first_used: i128) -> Result<(), Error> {
	let alloc = unsafe { MEM_ALLOCATED };
	let dealloc = unsafe { MEM_DEALLOCATED };
	let alloc_count = unsafe { ALLOC_COUNT };
	let dealloc_count = unsafe { DEALLOC_COUNT };
	let mem_used = alloc - dealloc;
	let change_from_start = mem_used - first_used;

	info!(
		"alloc={},dealloc={},alloc_count={},dealloc_count={},mem_used={},delta_from_init={}{:.2}mb",
		alloc,
		dealloc,
		alloc_count,
		dealloc_count,
		mem_used,
		if change_from_start >= 0 { "+" } else { "" },
		change_from_start as f64 / 1_000_000 as f64,
	)?;

	Ok(())
}

fn main() -> Result<(), Error> {
	let yml = load_yaml!("perf.yml");
	let args = App::from_yaml(yml)
		.version(built_info::PKG_VERSION)
		.get_matches();
	let is_client = args.is_present("client");
	let tls = args.is_present("tls");
	let is_server = !is_client;

	log_config!(LogConfig {
		show_line_num: false,
		show_log_level: false,
		show_bt: false,
		..Default::default()
	})?;

	if is_server {
		let http = args.is_present("http");

		let port = match args.is_present("port") {
			true => args.value_of("port").unwrap().parse()?,
			false => 8092,
		};

		if http {
			info!("Starting HTTP server!")?;
		} else {
			info!("Starting EventHandler!")?;
		}

		if tls && !args.is_present("tls_certificates_file") {
			return Err(ErrorKind::ApplicationError(
				"tls_certificates_file must be specified with tls enabled".to_string(),
			)
			.into());
		}

		if tls && !args.is_present("tls_private_key_file") {
			return Err(ErrorKind::ApplicationError(
				"tls_private_key_file must be specified with tls enabled".to_string(),
			)
			.into());
		}

		let tls_config = if tls {
			Some(TLSServerConfig {
				private_key_file: args.value_of("tls_private_key_file").unwrap().to_string(),
				certificates_file: args.value_of("tls_certificates_file").unwrap().to_string(),
			})
		} else {
			None
		};

		let threads = match args.is_present("threads") {
			true => args.value_of("threads").unwrap().parse()?,
			false => 1,
		};

		let max_rwhandles = match args.is_present("max_rwhandles") {
			true => args.value_of("max_rwhandles").unwrap().parse()?,
			false => 1_000_000,
		};

		let evh_config = EventHandlerConfig {
			threads,
			max_rwhandles,
			..EventHandlerConfig::default()
		};

		if http {
			let config = HttpConfig {
				addrs: vec![SocketAddr::from_str(&format!("127.0.0.1:{}", port)[..])?],
				//eventhandler_config: evh_config,
				..Default::default()
			};

			let mut http = HttpServer::new(config);
			http.start()?;

			std::thread::sleep(std::time::Duration::from_millis(3000));
			let first = unsafe { MEM_ALLOCATED } - unsafe { MEM_DEALLOCATED };
			loop {
				print_alloc(first as i128)?;
				std::thread::sleep(std::time::Duration::from_millis(3000));
			}
		} else {
			let mut evh = EventHandler::new(evh_config.clone())?;

			let (handles, _listeners) =
				get_handles(evh_config.threads, &format!("127.0.0.1:{}", port)[..])?;

			evh.set_on_accept(move |_conn_data, _| Ok(()))?;
			evh.set_on_close(move |conn_data, _| {
				trace!("on close for id = {}", conn_data.get_connection_id())?;
				Ok(())
			})?;
			evh.set_on_panic(move || Ok(()))?;

			evh.set_on_read(move |conn_data, buf, _| {
				conn_data.write(buf)?;
				Ok(())
			})?;
			evh.start()?;
			evh.add_listener_handles(handles, tls_config)?;
			std::thread::sleep(std::time::Duration::from_millis(3000));
			let first = unsafe { MEM_ALLOCATED } - unsafe { MEM_DEALLOCATED };
			loop {
				print_alloc(first as i128)?;
				std::thread::sleep(std::time::Duration::from_millis(3000));
			}
		}
	}
	if is_client {
		let http = args.is_present("http");

		let port = match args.is_present("port") {
			true => args.value_of("port").unwrap().parse()?,
			false => 8092,
		};

		let tls = args.is_present("tls");

		let count = match args.is_present("count") {
			true => args.value_of("count").unwrap().parse()?,
			false => 1,
		};

		let itt = match args.is_present("itt") {
			true => args.value_of("itt").unwrap().parse()?,
			false => 1,
		};

		let threads = match args.is_present("threads") {
			true => args.value_of("threads").unwrap().parse()?,
			false => 1,
		};

		let min = match args.is_present("min") {
			true => args.value_of("min").unwrap().parse()?,
			false => 50,
		};

		let max = match args.is_present("max") {
			true => args.value_of("max").unwrap().parse()?,
			false => 100,
		};

		let histo_max = args.is_present("histo_max");
		let bucket_count = args.is_present("bucket_count");

		let histo_max = match histo_max {
			true => args.value_of("histo_max").unwrap().parse().unwrap(),
			false => 1_000,
		};

		let bucket_count = match bucket_count {
			true => args.value_of("bucket_count").unwrap().parse().unwrap(),
			false => 20,
		};

		if histo_max % bucket_count != 0 {
			error!("histo_max must be divisible by bucket_count.")?;
			error!(
				"Supplied values (hist_max={},bucket_count={}) are not.",
				histo_max, bucket_count,
			)?;
			error!("Halting!")?;
			return Ok(());
		}

		let histo = match args.is_present("histo") {
			true => Some(Histo::new(histo_max, bucket_count)),
			false => None,
		};

		info!("Starting test client.")?;
		info_no_ts!("{}", SEPARATOR)?;

		let mut i = 0;
		let start = Instant::now();
		let mut total_lats = 0;

		loop {
			let start_itt = Instant::now();
			let mut jhs = vec![];
			let lat_sum_total = Arc::new(RwLock::new(0));

			for _ in 0..threads {
				let histo = histo.clone();
				let lat_sum_total_clone = lat_sum_total.clone();
				jhs.push(std::thread::spawn(move || {
					match run_thread(count, min, max, histo, tls, port, http) {
						Ok(lat_sum) => {
							let mut lat_sum_total = lockw!(lat_sum_total_clone).unwrap();
							*lat_sum_total += lat_sum;
						}
						Err(e) => {
							println!("{}", e);
							assert!(false);
						}
					}
				}));
			}

			for jh in jhs {
				jh.join().map_err(|e| {
					let error: Error = ErrorKind::ApplicationError(format!("{:?}", e)).into();
					error
				})?;
			}

			i += 1;
			let nanos = start_itt.elapsed().as_nanos();
			let total_messages: u64 = (threads * count).try_into().unwrap_or(0);
			let qps: f64 = (total_messages as f64 / nanos as f64) * 1_000_000_000 as f64;
			let qps_decimal: f64 = qps - (qps.floor() as f64);
			let qps_decimal = &qps_decimal.to_string()[1..];
			let qps = &format!(
				"{}{:.3}",
				(qps.floor() as u64).to_formatted_string(&Locale::en),
				qps_decimal
			);
			let avglat = {
				let lats = *(lockw!(lat_sum_total)?);
				total_lats += lats;
				(lats as f64 / 1_000_000 as f64) / (count as f64 * threads as f64)
			};

			info!(
				"Iteration {}:{} {:.2}s. Msgs = {}. QPS = {}, AvgLat={:.2}ms",
				i,
				match i < 10 {
					true => " ",
					false => "",
				},
				nanos as f64 / 1_000_000_000 as f64,
				total_messages.to_formatted_string(&Locale::en),
				qps,
				avglat,
			)?;

			if i == itt {
				break;
			}
		}

		let nanos = start.elapsed().as_nanos();
		let total_messages: u64 = (threads * count * itt).try_into().unwrap_or(0);
		let qps: f64 = (total_messages as f64 / nanos as f64) * 1_000_000_000 as f64;
		let qps_decimal: f64 = qps - (qps.floor() as f64);
		let qps_decimal = &qps_decimal.to_string()[1..];
		let qps = &format!(
			"{}{:.3}",
			(qps.floor() as u64).to_formatted_string(&Locale::en),
			qps_decimal
		);
		let avglat = { (total_lats as f64 / 1_000_000 as f64) / total_messages as f64 };

		info_no_ts!("{}", SEPARATOR)?;
		info!(
			"- {:.2}s! Total Messages = {}. QPS = {}, AvgLat={:.2}ms",
			nanos as f64 / 1_000_000_000 as f64,
			total_messages.to_formatted_string(&Locale::en),
			qps,
			avglat,
		)?;

		match histo {
			Some(histo) => {
				info_no_ts!("{}", SEPARATOR)?;
				info_no_ts!("{}", 
"---------------------------------------Latency Histogram-------------------------------------".cyan())?;
				//123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890
				//         1         2         3         4         5         6         7         8         9

				info_no_ts!("{}", SEPARATOR)?;
				histo.display()?;
				info_no_ts!("{}", SEPARATOR)?;
			}
			None => {}
		}
	}

	Ok(())
}

fn run_thread(
	count: usize,
	min: usize,
	max: usize,
	histo: Option<Histo>,
	tls: bool,
	port: u16,
	http: bool,
) -> Result<u128, Error> {
	let mut rbuf = vec![];
	let mut wbuf = vec![];
	if http {
		let request_string =
			format!("GET / HTTP/1.1\r\nHost: localhost:80\r\nConnection: keep-alive\r\n\r\n",);
		wbuf = request_string.as_bytes().to_vec();
		rbuf.resize(1000, 0u8);
	} else {
		let cap = if max > min { max } else { min };
		rbuf.resize(cap, 0u8);
		wbuf.resize(cap, 0u8);
		for i in 0..cap {
			wbuf[i] = (i % 256) as u8;
		}
	}

	let (mut stream, mut tls_stream) = match tls {
		true => {
			let connector = TlsConnector::builder()
				.danger_accept_invalid_hostnames(true)
				.danger_accept_invalid_certs(true)
				.build()
				.unwrap();
			(
				None,
				Some(
					connector
						.connect(
							"example.com",
							TcpStream::connect(&format!("127.0.0.1:{}", port)[..])?,
						)
						.unwrap(),
				),
			)
		}
		false => (
			Some(TcpStream::connect(&format!("127.0.0.1:{}", port)[..])?),
			None,
		),
	};
	let mut x = 0;
	let mut lat_sum = 0;
	loop {
		let r: usize = rand::random();
		let r = if max <= min { 0 } else { r % (max - min) };
		let wlen = if http { wbuf.len() } else { r + min };
		let mut len_sum = 0;

		let start_time = std::time::SystemTime::now();
		let _len = match stream {
			Some(ref mut stream) => stream.write(&wbuf[0..wlen])?,
			None => match tls_stream {
				Some(ref mut tls_stream) => tls_stream.write(&wbuf[0..wlen])?,
				None => {
					return Err(
						ErrorKind::ApplicationError("no streams configured".to_string()).into(),
					);
				}
			},
		};

		loop {
			let len = match stream {
				Some(ref mut stream) => stream.read(&mut rbuf[len_sum..])?,
				None => match tls_stream {
					Some(ref mut tls_stream) => tls_stream.read(&mut rbuf[len_sum..])?,
					None => {
						return Err(ErrorKind::ApplicationError(
							"no streams configured".to_string(),
						)
						.into());
					}
				},
			};
			len_sum += len;
			trace!("len={},len_sum={}", len, len_sum)?;
			if len_sum >= wlen {
				break;
			}

			assert!(len != 0);
		}
		let elapsed = std::time::SystemTime::now().duration_since(start_time)?;
		let nanos = elapsed.as_nanos();
		let mut micros = nanos as usize / 1000;
		lat_sum += nanos;

		match histo {
			Some(ref histo) => {
				if micros > histo.max {
					micros = histo.max;
				}
				histo.incr(micros.try_into().unwrap_or(histo.max))?;
			}
			None => {}
		}

		if !http {
			assert_eq!(len_sum, wlen);
			for i in 0..len_sum {
				if rbuf[i] != (i % 256) as u8 {
					error!("rbuf[{}] was {}. Expected value = {}", i, rbuf[i], i % 256)?;
					assert!(false);
				}
			}
		}

		x += 1;
		if x == count {
			break;
		}
	}
	Ok(lat_sum)
}
