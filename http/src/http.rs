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

use nioruntime_deps::libc;
use nioruntime_deps::nix::sys::socket::{
	bind, listen, socket, AddressFamily, InetAddr, SockAddr, SockFlag, SockType,
};
use nioruntime_err::Error;
use nioruntime_evh::ConnectionData;
use nioruntime_evh::{EventHandler, EventHandlerConfig};
use nioruntime_log::*;
use std::mem;
use std::net::SocketAddr;
use std::net::TcpListener;
use std::os::unix::io::AsRawFd;
use std::os::unix::io::FromRawFd;
use std::str::FromStr;

use std::os::unix::prelude::RawFd;

debug!();

#[cfg(unix)]
type Handle = RawFd;
#[cfg(windows)]
type Handle = u64;

pub struct HttpConfig {
	pub addrs: Vec<SocketAddr>,
	pub threads: usize,
	pub listen_queue_size: usize,
}

impl Default for HttpConfig {
	fn default() -> Self {
		Self {
			addrs: vec![SocketAddr::from_str("127.0.0.1:8080").unwrap()],
			threads: 8,
			listen_queue_size: 100,
		}
	}
}

pub struct HttpServer {
	config: HttpConfig,
	_listeners: Vec<TcpListener>,
}

impl HttpServer {
	pub fn new(config: HttpConfig) -> Self {
		Self {
			config,
			_listeners: vec![],
		}
	}

	pub fn start(&mut self) -> Result<(), Error> {
		let mut evh = EventHandler::new(EventHandlerConfig {
			threads: self.config.threads,
			..EventHandlerConfig::default()
		})?;

		evh.set_on_read(move |conn_data, buf| Self::process_on_read(conn_data, buf))?;

		evh.set_on_accept(move |conn_data| Self::process_on_accept(conn_data))?;

		evh.set_on_close(move |conn_data| Self::process_on_close(conn_data))?;

		evh.set_on_panic(move || Ok(()))?;

		evh.start()?;

		for i in 0..self.config.addrs.len() {
			let inet_addr = InetAddr::from_std(&self.config.addrs[i]);
			let sock_addr = SockAddr::new_inet(inet_addr);

			let mut handles = vec![];
			for _ in 0..self.config.threads {
				let handle = Self::get_handle()?;
				bind(handle, &sock_addr)?;
				listen(handle, self.config.listen_queue_size)?;

				let listener = unsafe { TcpListener::from_raw_fd(handle) };
				listener.set_nonblocking(true)?;
				handles.push(listener.as_raw_fd());
				self._listeners.push(listener);
			}

			evh.add_listener_handles(handles, None)?;
		}

		info!("started")?;

		Ok(())
	}

	pub fn stop(&self) -> Result<(), Error> {
		Ok(())
	}

	fn process_on_read(conn_data: &ConnectionData, buf: &[u8]) -> Result<(), Error> {
		debug!(
			"on_read[{}] = '{:?}', acc_handle={:?}",
			conn_data.get_connection_id(),
			buf,
			conn_data.get_accept_handle()
		)?;

		Ok(())
	}

	fn process_on_accept(conn_data: &ConnectionData) -> Result<(), Error> {
		debug!(
			"on accept: {}, handle={}",
			conn_data.get_connection_id(),
			conn_data.get_handle()
		)?;
		Ok(())
	}

	fn process_on_close(conn_data: &ConnectionData) -> Result<(), Error> {
		debug!("on close: {}", conn_data.get_connection_id())?;
		Ok(())
	}

	fn get_handle() -> Result<Handle, Error> {
		let raw_fd = socket(
			AddressFamily::Inet,
			SockType::Stream,
			SockFlag::empty(),
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
}

#[cfg(test)]
mod test {
	use crate::http::{HttpConfig, HttpServer};
	use nioruntime_err::Error;
	use std::net::SocketAddr;
	use std::str::FromStr;

	#[test]
	fn test_http() -> Result<(), Error> {
		let config = HttpConfig {
			addrs: vec![
				SocketAddr::from_str("127.0.0.1:8080")?,
				SocketAddr::from_str("0.0.0.0:8081")?,
			],
			..Default::default()
		};
		let mut http = HttpServer::new(config);

		http.start()?;

		//std::thread::park();

		Ok(())
	}
}
