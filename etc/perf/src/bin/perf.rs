// Copyright 2022 37 Miners, LLC
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

use clap::load_yaml;
use clap::App;
use nioruntime_err::{Error, ErrorKind};
use nioruntime_evh::*;
use nioruntime_log::*;
use nix::sys::socket::InetAddr;
use nix::sys::socket::SockAddr;
use std::io::{Read, Write};
use std::mem;
use std::net::{Shutdown, SocketAddr, TcpListener, TcpStream};
use std::os::unix::io::AsRawFd;
use std::os::unix::io::FromRawFd;
use std::os::unix::prelude::RawFd;
use std::str::FromStr;
use std::time::Instant;

debug!();

fn get_fd() -> Result<RawFd, Error> {
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

// include build information
pub mod built_info {
	include!(concat!(env!("OUT_DIR"), "/built.rs"));
}

fn main() -> Result<(), Error> {
	let yml = load_yaml!("perf.yml");
	let args = App::from_yaml(yml)
		.version(built_info::PKG_VERSION)
		.get_matches();
	let is_client = args.is_present("client");
	let is_server = !is_client;

	log_config!(LogConfig {
		show_line_num: false,
		..Default::default()
	})?;
	let mut evh = EventHandler::new(EventHandlerConfig {
		threads: 6,
		..EventHandlerConfig::default()
	})?;

	if is_server {
		info!("Starting EventHandler");
		let std_sa = SocketAddr::from_str("127.0.0.1:8092").unwrap();
		let inet_addr = InetAddr::from_std(&std_sa);
		let sock_addr = SockAddr::new_inet(inet_addr);

		let mut handles = vec![];
		let mut listeners = vec![];

		for _ in 0..6 {
			let fd = get_fd()?;
			nix::sys::socket::bind(fd, &sock_addr)?;
			nix::sys::socket::listen(fd, 1000)?;

			let listener = unsafe { TcpListener::from_raw_fd(fd) };
			listener.set_nonblocking(true)?;
			handles.push(listener.as_raw_fd());
			listeners.push(listener);
		}

		evh.set_on_accept(move |_conn_data| Ok(()))?;
		evh.set_on_close(move |_conn_data| Ok(()))?;
		evh.set_on_panic(move || Ok(()))?;

		evh.set_on_read(move |conn_data, buf| {
			conn_data.write(buf)?;
			Ok(())
		})?;
		evh.start()?;
		evh.add_listener_handles(handles)?;
		std::thread::park();
	}
	if is_client {
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

		info!("Starting test client.");

		let mut i = 0;
		let start = Instant::now();

		loop {
			let mut jhs = vec![];
			for _ in 0..threads {
				jhs.push(std::thread::spawn(move || match run_thread(count) {
					Ok(_) => {}
					Err(e) => error!("{}", e),
				}));
			}

			for jh in jhs {
				jh.join().map_err(|e| {
					let error: Error = ErrorKind::ApplicationError(format!("{:?}", e)).into();
					error
				})?;
			}

			i += 1;
			info!("Iteration {} complete.", i);
			if i == itt {
				break;
			}
		}

		info!(
			"complete in {}ms!",
			start.elapsed().as_nanos() as f64 / 1_000_000 as f64
		);
	}

	Ok(())
}

fn run_thread(count: usize) -> Result<(), Error> {
	info!("running a thread with count = {}", count);
	let buf = &mut [0u8; 10];
	let mut stream = TcpStream::connect("127.0.0.1:8092")?;
	let mut x = 0;
	loop {
		stream.write(&[1, 2, 3, 4, 5, 6, 7])?;
		let len = stream.read(&mut buf[..])?;
		assert_eq!(&buf[0..len], &[1, 2, 3, 4, 5, 6, 7]);
		x += 1;
		if x == count {
			break;
		}
	}
	Ok(())
}
