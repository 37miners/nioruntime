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
// limitations under the License

//! An event handler library.

use crate::eventhandler::rustls::sign::RsaSigningKey;
use nioruntime_deps::bitvec::prelude::*;
use nioruntime_deps::errno::{errno, set_errno, Errno};
use nioruntime_deps::libc::{self, accept, c_int, c_void, pipe, read, write};
use nioruntime_deps::rustls::server::ResolvesServerCertUsingSni;
use nioruntime_deps::rustls::sign::CertifiedKey;
use nioruntime_deps::{rand, rustls, rustls_pemfile};
use nioruntime_err::{Error, ErrorKind};
use nioruntime_log::*;
use nioruntime_util::{lockr, lockw, lockwp};
use nioruntime_util::{StaticHash, StaticHashConfig, StepAllocator, StepAllocatorConfig};
use rustls::{
	Certificate, ClientConfig, ClientConnection, PrivateKey, RootCertStore, ServerConfig,
	ServerConnection,
};
use std::any::Any;
use std::collections::HashSet;
use std::convert::TryInto;
use std::fmt::{Debug, Formatter};
use std::fs::File;
use std::io::{BufReader, Read, Write};
use std::net::SocketAddr;
use std::pin::Pin;
use std::str::FromStr;
use std::sync::{Arc, RwLock, RwLockReadGuard};
use std::time::{SystemTime, UNIX_EPOCH};

// unix specific
#[cfg(unix)]
use nioruntime_deps::libc::fcntl;
#[cfg(unix)]
use nioruntime_deps::nix::sys::socket::{getpeername, getsockname};
#[cfg(unix)]
use std::os::unix::prelude::RawFd;

// mac/bsd variant specific deps
#[cfg(any(
	target_os = "macos",
	target_os = "dragonfly",
	target_os = "netbsd",
	target_os = "openbsd",
	target_os = "freebsd"
))]
use libc::timespec;
#[cfg(any(
	target_os = "macos",
	target_os = "dragonfly",
	target_os = "netbsd",
	target_os = "openbsd",
	target_os = "freebsd"
))]
use nioruntime_deps::kqueue_sys::{kevent, kqueue, EventFilter, EventFlag, FilterFlag};
#[cfg(any(
	target_os = "macos",
	target_os = "dragonfly",
	target_os = "netbsd",
	target_os = "openbsd",
	target_os = "freebsd"
))]
use std::time::Duration;

// linux specific deps
#[cfg(target_os = "linux")]
use nioruntime_deps::nix::sys::epoll::{
	epoll_create1, epoll_ctl, epoll_wait, EpollCreateFlags, EpollEvent, EpollFlags, EpollOp,
};

#[cfg(windows)]
use nioruntime_deps::wepoll_sys::{
	epoll_create, epoll_ctl, epoll_data_t, epoll_event, epoll_wait, EPOLLIN, EPOLLOUT, EPOLLRDHUP,
	EPOLL_CTL_ADD, EPOLL_CTL_DEL, EPOLL_CTL_MOD,
};
#[cfg(windows)]
use nioruntime_deps::{winapi, ws2_32};
#[cfg(windows)]
use std::net::{TcpListener, TcpStream};
#[cfg(windows)]
use std::os::windows::io::AsRawSocket;

warn!();

const SIZEOF_USIZE: usize = std::mem::size_of::<usize>();
const SIZEOF_U128: usize = std::mem::size_of::<u128>();

const MAX_EVENTS: i32 = 100;
#[cfg(target_os = "windows")]
const WINSOCK_BUF_SIZE: winapi::c_int = 100_000_000;
const TLS_CHUNKS: usize = 5_120;

#[cfg(unix)]
type SelectorHandle = i32;
#[cfg(target_os = "windows")]
type SelectorHandle = u64;

#[cfg(windows)]
const HANDLE_SIZE: usize = 8;
#[cfg(unix)]
const HANDLE_SIZE: usize = 4;

#[cfg(unix)]
type Handle = RawFd;
#[cfg(windows)]
type Handle = u64;

#[derive(Debug, Clone)]
pub struct ConnectionContext {
	pub buffer: Vec<u8>,
	pub is_async_complete: bool,
	pub remote_peer: Option<SocketAddr>,
	pub local_peer: Option<SocketAddr>,
}

impl ConnectionContext {
	fn new(remote_peer: Option<SocketAddr>, local_peer: Option<SocketAddr>) -> Self {
		Self {
			buffer: vec![],
			is_async_complete: false,
			remote_peer,
			local_peer,
		}
	}

	pub fn get_buffer(&mut self) -> &mut Vec<u8> {
		&mut self.buffer
	}
}

impl Drop for ConnectionContext {
	fn drop(&mut self) {
		self.buffer.drain(..);
	}
}

#[derive(Debug, Clone)]
pub struct ConnectionData {
	connection_info: ReadWriteConnection,
	guarded_data: Arc<RwLock<GuardedData>>,
	wakeup: Wakeup,
	tid: usize,
	debug_pending: bool,
}

impl ConnectionData {
	fn new(
		connection_info: &ReadWriteConnection,
		guarded_data: &Arc<RwLock<GuardedData>>,
		wakeup: &Wakeup,
		tid: usize,
		debug_pending: bool,
	) -> Self {
		let connection_info = connection_info.clone();
		let guarded_data = guarded_data.clone();
		let wakeup = wakeup.clone();
		Self {
			connection_info,
			guarded_data,
			wakeup,
			tid,
			debug_pending,
		}
	}

	pub fn tid(&self) -> usize {
		self.tid
	}

	pub fn get_connection_id(&self) -> u128 {
		self.connection_info.get_connection_id()
	}

	pub fn get_handle(&self) -> Handle {
		self.connection_info.get_handle()
	}

	pub fn get_accept_handle(&self) -> Option<Handle> {
		self.connection_info.get_accept_handle()
	}

	pub fn get_buffer(&mut self) -> &mut Vec<u8> {
		self.connection_info.get_buffer()
	}

	pub fn async_complete(&self) -> Result<(), Error> {
		{
			let mut write_status = lockw!(self.connection_info.write_status)?;
			if (*write_status).is_closed() {
				return Err(ErrorKind::ConnectionClosedError(format!(
					"connection {} already closed",
					self.get_connection_id()
				))
				.into());
			}
			(*write_status).set_async_complete();
		}

		self.notify_selector_thread()?;

		Ok(())
	}

	pub fn close(&self) -> Result<(), Error> {
		{
			let mut write_status = lockw!(self.connection_info.write_status)?;
			if (*write_status).is_closed() {
				return Err(ErrorKind::ConnectionClosedError(format!(
					"connection {} already closed",
					self.get_connection_id()
				))
				.into());
			}
			(*write_status).set_close_oncomplete();
		}

		self.notify_selector_thread()?;

		Ok(())
	}

	pub fn write(&self, data: &[u8]) -> Result<(), Error> {
		match &self.connection_info.tls_server {
			Some(tls_conn) => {
				{
					let mut tls_conn = nioruntime_util::lockw!(tls_conn)?;
					let mut start = 0;
					loop {
						let mut wbuf = vec![];
						let mut end = data.len();
						if end - start > TLS_CHUNKS {
							end = start + TLS_CHUNKS;
						}
						tls_conn.writer().write_all(&data[start..end])?;
						tls_conn.write_tls(&mut wbuf)?;
						self.do_write(&wbuf)?;

						if end == data.len() {
							break;
						}
						start += TLS_CHUNKS;
					}
				}
				Ok(())
			}
			None => match &self.connection_info.tls_client {
				Some(tls_conn) => {
					{
						let mut tls_conn = nioruntime_util::lockw!(tls_conn)?;
						let mut start = 0;
						loop {
							let mut wbuf = vec![];
							let mut end = data.len();
							if end - start > TLS_CHUNKS {
								end = start + TLS_CHUNKS;
							}
							tls_conn.writer().write_all(&data[start..end])?;
							tls_conn.write_tls(&mut wbuf)?;
							self.do_write(&wbuf)?;
							if end == data.len() {
								break;
							}
							start += TLS_CHUNKS;
						}
					}

					Ok(())
				}
				None => self.do_write(data),
			},
		}
	}

	fn do_write(&self, data: &[u8]) -> Result<(), Error> {
		let len = data.len();
		if len == 0 {
			// nothing to write
			return Ok(());
		}
		let res = {
			// first try to write in our own thread, check if closed first.
			let mut write_status = lockw!(self.connection_info.write_status)?;

			if (*write_status).is_closed() {
				return Err(ErrorKind::ConnectionClosedError(format!(
					"connection {} already closed",
					self.get_connection_id()
				))
				.into());
			}

			if (*write_status).is_pending() || self.debug_pending {
				// there are pending writes, we cannot write here.
				// return that 0 bytes were written and pass on to
				// main thread loop
				(*write_status).write_buffer.append(&mut data.to_vec());
				0
			} else {
				let wlen = write_bytes(self.connection_info.get_handle(), &data)?;

				let start_data = if wlen > 0 { wlen as usize } else { 0 as usize };

				if start_data > 0 && start_data < data.len() {
					(*write_status).set_is_pending(true);
					(*write_status)
						.write_buffer
						.append(&mut data[start_data..].to_vec());
				} else if start_data == 0 && errno().0 == libc::EAGAIN {
					//============
					// blocking so add it to the buffer
					(*write_status).set_is_pending(true);
					(*write_status)
						.write_buffer
						.append(&mut data[start_data..].to_vec());
				}

				wlen
			}
		};

		if res == len.try_into()? {
			Ok(())
		} else if res < 0 {
			//============
			let e = errno().0;
			if e == libc::EAGAIN {
				// can't write right now. Would block. Pass to selector
				self.notify_selector_thread()
			} else {
				// actual write error. Return error
				Err(ErrorKind::IOError(format!(
					"failed writing to handle={},cid={} with error={}",
					self.connection_info.handle,
					self.get_connection_id(),
					std::io::Error::last_os_error()
				))
				.into())
			}
		} else {
			// otherwise, we have to pass to the other thread
			self.notify_selector_thread()
		}
	}

	fn notify_selector_thread(&self) -> Result<(), Error> {
		{
			let mut guarded_data = lockw!(self.guarded_data)?;
			guarded_data.write_queue.push(self.get_connection_id());
		}
		self.wakeup.wakeup()?;
		Ok(())
	}
}

#[derive(Clone, Copy)]
pub struct EventHandlerConfig {
	pub threads: usize,
	pub read_buffer_size: usize,
	pub max_rwhandles: usize,
	pub max_handle_numeric_value: usize,
	pub housekeeper_frequency: isize,
	pub step_size: usize,
	pub debug_pending: bool,
	pub debug_fatal: bool,
}

impl Default for EventHandlerConfig {
	fn default() -> Self {
		Self {
			threads: 6,
			read_buffer_size: 10 * 1024,
			max_rwhandles: 16_000,
			max_handle_numeric_value: 16_100,
			housekeeper_frequency: 1_000,
			step_size: 100,
			debug_pending: false,
			debug_fatal: false,
		}
	}
}

#[derive(Clone)]
pub struct EventHandler<OnRead, OnAccept, OnClose, OnPanic, OnHousekeep> {
	config: EventHandlerConfig,
	guarded_data: Arc<Vec<Arc<RwLock<GuardedData>>>>,
	wakeup: Vec<Wakeup>,
	callbacks: Callbacks<OnRead, OnAccept, OnClose, OnPanic, OnHousekeep>,
	stopped: Arc<RwLock<bool>>,
	cur_connections: Arc<RwLock<usize>>,
}

impl<OnRead, OnAccept, OnClose, OnPanic, OnHousekeep>
	EventHandler<OnRead, OnAccept, OnClose, OnPanic, OnHousekeep>
where
	OnRead: Fn(
			ConnectionData,
			&[u8],
			&mut ConnectionContext,
			&mut Box<dyn Any + Send + Sync>,
		) -> Result<(), Error>
		+ Send
		+ 'static
		+ Clone
		+ Sync
		+ Unpin,
	OnAccept: Fn(
			&ConnectionData,
			&mut ConnectionContext,
			&mut Box<dyn Any + Send + Sync>,
		) -> Result<(), Error>
		+ Send
		+ 'static
		+ Clone
		+ Sync
		+ Unpin,
	OnClose: Fn(
			&ConnectionData,
			&mut ConnectionContext,
			&mut Box<dyn Any + Send + Sync>,
		) -> Result<(), Error>
		+ Send
		+ 'static
		+ Clone
		+ Sync
		+ Unpin,
	OnPanic: Fn() -> Result<(), Error> + Send + 'static + Clone + Sync + Unpin,
	OnHousekeep: Fn(&mut Box<dyn Any + Send + Sync>, usize) -> Result<(), Error>
		+ Send
		+ 'static
		+ Clone
		+ Sync
		+ Unpin,
{
	pub fn new(config: EventHandlerConfig) -> Result<Self, Error> {
		if config.read_buffer_size < 6_120 {
			let msg = "read_buffer_len must be greater than or equal to 6_120".to_string();
			return Err(ErrorKind::EventHandlerConfigurationError(msg).into());
		}
		let mut guarded_data = vec![];
		let mut wakeup = vec![];
		for _ in 0..config.threads {
			guarded_data.push(Arc::new(RwLock::new(GuardedData::new())));
			wakeup.push(Wakeup::new()?);
		}
		let guarded_data = Arc::new(guarded_data);
		Ok(Self {
			config,
			callbacks: Callbacks {
				on_read: None,
				on_accept: None,
				on_close: None,
				on_panic: None,
				on_housekeep: None,
			},
			guarded_data,
			wakeup,
			stopped: Arc::new(RwLock::new(false)),
			cur_connections: Arc::new(RwLock::new(0)),
		})
	}

	pub fn set_on_read(&mut self, on_read: OnRead) -> Result<(), Error> {
		self.callbacks.on_read = Some(Box::pin(on_read));
		Ok(())
	}

	pub fn set_on_accept(&mut self, on_accept: OnAccept) -> Result<(), Error> {
		self.callbacks.on_accept = Some(Box::pin(on_accept));
		Ok(())
	}

	pub fn set_on_close(&mut self, on_close: OnClose) -> Result<(), Error> {
		self.callbacks.on_close = Some(Box::pin(on_close));
		Ok(())
	}

	pub fn set_on_panic(&mut self, on_panic: OnPanic) -> Result<(), Error> {
		self.callbacks.on_panic = Some(Box::pin(on_panic));
		Ok(())
	}

	pub fn set_on_housekeep(&mut self, on_housekeep: OnHousekeep) -> Result<(), Error> {
		self.callbacks.on_housekeep = Some(Box::pin(on_housekeep));
		Ok(())
	}

	pub fn start(&self) -> Result<(), Error> {
		self.check_callbacks()?;
		self.do_start()
	}

	pub fn stop(&self) -> Result<(), Error> {
		for i in 0..self.guarded_data.len() {
			let guarded_data = &self.guarded_data[i];
			{
				let mut guarded_data = lockw!(*guarded_data)?;
				(*guarded_data).stop = true;
			}
			self.wakeup[i].wakeup()?;
		}

		Ok(())
	}

	pub fn add_listener_handles(
		&self,
		handles: Vec<Handle>,
		tls_config: Option<TLSServerConfig>,
	) -> Result<(), Error> {
		for handle in &handles {
			if *handle >= self.config.max_handle_numeric_value.try_into()? {
				let max = self.config.max_handle_numeric_value;
				let msg = format!("Max numeric handle exceeded. Limit = {}", max);
				return Err(ErrorKind::MaxHandlesExceeded(msg).into());
			}
		}
		self.check_callbacks()?;

		if handles.len() != self.config.threads.try_into()? {
			let len = handles.len();
			let th = self.config.threads;
			let msg = format!("handles not equal to threads threads. {} != {}", len, th);
			return Err(ErrorKind::EventHandlerConfigurationError(msg).into());
		}

		let tls_config = match tls_config {
			Some(tls_config) => {
				let mut cert_resolver = ResolvesServerCertUsingSni::new();
				cert_resolver.add(
					&tls_config.sni_host,
					CertifiedKey {
						cert: load_certs(&tls_config.certificates_file)?,
						key: Arc::new(
							RsaSigningKey::new(&load_private_key(&tls_config.private_key_file)?)
								.map_err(|e| {
									let msg = format!("Signing error: {}", e);
									let ekind = ErrorKind::InternalError(msg);
									let error: Error = ekind.into();
									return error;
								})?,
						),
						ocsp: None,
						sct_list: None,
					},
				)?;

				let builder = ServerConfig::builder();
				let builder = builder.with_safe_defaults();
				let builder = builder.with_no_client_auth();
				let builder = builder.with_cert_resolver(Arc::new(cert_resolver));

				Some(builder)
			}
			None => None,
		};

		let connection_info = EventConnectionInfo::listener_connection(handles, tls_config);

		for i in 0..self.guarded_data.len() {
			let guarded_data = &self.guarded_data[i];
			{
				let mut guarded_data = lockw!(*guarded_data)?;
				(*guarded_data).nhandles.push(connection_info.clone());
			}
			self.wakeup[i].wakeup()?;
		}

		Ok(())
	}

	pub fn add_handle(
		&self,
		handle: Handle,
		tls_config: Option<TLSClientConfig>,
	) -> Result<ConnectionData, Error> {
		let evh_params = self.get_evh_params();
		evh_params.add_handle(handle, tls_config, None)
	}

	pub fn get_evh_params(&self) -> EvhParams {
		EvhParams {
			cur_connections: self.cur_connections.clone(),
			config: self.config.clone(),
			guarded_data: self.guarded_data.clone(),
			wakeup: self.wakeup.clone(),
		}
	}

	fn check_callbacks(&self) -> Result<(), Error> {
		if self.callbacks.on_read.is_none() {
			let msg = "set_on_read must be called before calling start".to_string();
			return Err(ErrorKind::EventHandlerConfigurationError(msg).into());
		}
		if self.callbacks.on_accept.is_none() {
			let msg = "set_on_accept must be called before calling start".to_string();
			return Err(ErrorKind::EventHandlerConfigurationError(msg).into());
		}
		if self.callbacks.on_close.is_none() {
			let msg = "set_on_close must be called before calling start".to_string();
			return Err(ErrorKind::EventHandlerConfigurationError(msg).into());
		}
		if self.callbacks.on_panic.is_none() {
			let msg = "set_on_panic must be called before calling start".to_string();
			return Err(ErrorKind::EventHandlerConfigurationError(msg).into());
		}
		if self.callbacks.on_housekeep.is_none() {
			let msg = "set_on_housekeep must be called before calling start".to_string();
			return Err(ErrorKind::EventHandlerConfigurationError(msg).into());
		}

		Ok(())
	}

	fn do_start(&self) -> Result<(), Error> {
		let stop_count = Arc::new(RwLock::new(0));
		for i in 0..self.config.threads {
			let gd = self.guarded_data[i].clone();
			let wk = self.wakeup[i].clone();
			let sc = stop_count.clone();
			self.start_thread(gd, wk, i, sc)?;
		}
		Ok(())
	}

	fn insert_step_allocator(
		connection_info: EventConnectionInfo,
		step_allocator: &mut StepAllocator,
		connection_index_handle_map: &mut StaticHash<(), ()>,
		connection_index_id_map: &mut StaticHash<(), ()>,
		tid: usize,
	) -> Result<(), Error> {
		let handle = connection_info.get_handle(tid);
		let id = connection_info.get_connection_id();
		let next = step_allocator.next();
		let next = if next.is_some() {
			next.unwrap()
		} else {
			step_allocator.step(&ConnectionHashData::new());
			step_allocator.next().unwrap()
		};

		#[cfg(unix)]
		let remote_peer = match getpeername(handle) {
			Ok(remote_peer) => Some(SocketAddr::from_str(&remote_peer.to_string())?),
			Err(_) => None,
		};
		#[cfg(windows)]
		let remote_peer: Option<SocketAddr> = None; // TODO: make work for windows

		#[cfg(unix)]
		let local_peer = match getsockname(handle) {
			Ok(local_peer) => Some(SocketAddr::from_str(&local_peer.to_string())?),
			Err(_) => None,
		};
		#[cfg(windows)]
		let local_peer: Option<SocketAddr> = None; // TODO: make work for windows

		let connection_hash_data = next.data_as_mut::<ConnectionHashData>().unwrap();
		connection_hash_data.connection_info = Some(connection_info);
		connection_hash_data.connection_context =
			Some(ConnectionContext::new(remote_peer, local_peer));

		connection_index_handle_map.insert_raw(
			&handle.to_be_bytes(),
			&(next.index() as usize).to_be_bytes(),
		)?;

		connection_index_id_map
			.insert_raw(&id.to_be_bytes(), &(next.index() as usize).to_be_bytes())?;

		Ok(())
	}

	fn start_thread(
		&self,
		guarded_data: Arc<RwLock<GuardedData>>,
		wakeup: Wakeup,
		tid: usize,
		stop_count: Arc<RwLock<usize>>,
	) -> Result<(), Error> {
		let callbacks = Arc::new(RwLock::new(self.callbacks.clone()));
		let events = Arc::new(RwLock::new(HashSet::new()));
		let mut ctx = Context::new(tid, guarded_data, self.config, self.cur_connections.clone())?;

		let mut step_allocator = StepAllocator::new(StepAllocatorConfig {
			step_size: self.config.step_size,
		});
		let max_entries = self.config.max_handle_numeric_value;
		let key_len = HANDLE_SIZE;
		let entry_len = SIZEOF_USIZE;
		let max_load_factor = 1.0;
		let iterator = false;
		let shc = StaticHashConfig {
			max_entries,
			key_len,
			max_load_factor,
			entry_len,
			iterator,
		};
		let mut connection_index_handle_map = StaticHash::new(shc)?;

		let max_entries = self.config.max_handle_numeric_value;
		let key_len = SIZEOF_U128;
		let entry_len = SIZEOF_USIZE;
		let max_load_factor = 1.0;
		let iterator = false;
		let shc = StaticHashConfig {
			max_entries,
			key_len,
			max_load_factor,
			entry_len,
			iterator,
		};
		let mut connection_index_id_map = StaticHash::new(shc)?;

		let config = self.config.clone();

		// add the wakeup handle to all hashtables
		let whr = wakeup.wakeup_handle_read;
		let connection_info = EventConnectionInfo::read_write_connection(whr, None, None, None);

		let ci = connection_info.clone();
		let sa = &mut step_allocator;
		let cihm = &mut connection_index_handle_map;
		let ciim = &mut connection_index_id_map;
		let tid = ctx.tid;
		Self::insert_step_allocator(ci, sa, cihm, ciim, tid)?;

		let handle = wakeup.wakeup_handle_read;
		let etype = EventType::Read;
		let event = Event { handle, etype };
		ctx.input_events.insert(event);

		let ctx = Arc::new(RwLock::new(ctx));
		let connection_index_handle_map = Arc::new(RwLock::new(connection_index_handle_map));
		let connection_index_id_map = Arc::new(RwLock::new(connection_index_id_map));
		let step_allocator = Arc::new(RwLock::new(step_allocator));
		let stopped = self.stopped.clone();

		std::thread::spawn(move || -> Result<(), Error> {
			loop {
				let events = events.clone();
				let ctx = ctx.clone();
				let connection_index_handle_map = connection_index_handle_map.clone();
				let connection_index_id_map = connection_index_id_map.clone();
				let step_allocator = step_allocator.clone();
				let callbacks = callbacks.clone();
				let callbacks_clone = callbacks.clone();
				let wakeup = wakeup.clone();

				let jh = std::thread::spawn(move || -> Result<(), Error> {
					let mut events: &mut HashSet<Event> = &mut *lockwp!(events);
					let mut ctx = &mut *lockwp!(ctx);
					let cihm = &connection_index_handle_map;
					let mut connection_index_handle_map = &mut *lockwp!(cihm);
					let mut connection_index_id_map = &mut *lockwp!(connection_index_id_map);
					let mut step_allocator = &mut *lockwp!(step_allocator);
					let callbacks = &mut *lockwp!(callbacks);

					let mut stop = false;

					// process any remaining events from a panic
					let next = ctx.counter + 1;
					let a = &mut ctx;
					let b = &config;
					let c = &mut events;
					let d = &wakeup;
					let e = &callbacks;
					let f = &mut connection_index_handle_map;
					let g = &mut connection_index_id_map;
					let h = &mut step_allocator;
					let i = next;

					let tl = Self::thread_loop(a, b, c, d, e, f, g, h, i);
					match tl {
						Ok(do_stop) => {
							stop = do_stop;
						}
						Err(e) => {
							fatal!("unexpected error in thread loop: {}", e)?;
						}
					}

					if stop {
						return Ok(()); //============
					}

					loop {
						let tl = Self::thread_loop(a, b, c, d, e, f, g, h, 0);
						match tl {
							Ok(do_stop) => {
								stop = do_stop;
								if do_stop {
									break; //============
								}
							}
							Err(e) => {
								fatal!("unexpected error in thread loop: {}", e)?;
								break; //============
							}
						}
					}

					if stop {
						return Ok(());
					}

					Ok(())
				});

				let stop = match jh.join() {
					Ok(_) => true,
					Err(_e) => {
						error!("thread panic!")?;
						false
					}
				};

				{
					let mut stop_count = lockw!(stop_count)?;
					*stop_count += 1;
					if *stop_count == config.threads {
						let mut stopped = lockw!(stopped)?;
						*stopped = true;
					}
				}
				if stop {
					break; //============
				}

				let callbacks = lockwp!(callbacks_clone);
				match &(*callbacks).on_panic {
					Some(on_panic) => {
						let panic_res = (on_panic)();
						if panic_res.is_err() {
							println!("on_panic generated error: {:?}", panic_res);
						}
					}
					None => {}
				}
			}
			Ok(())
		});
		Ok(())
	}

	fn check_housekeeper(
		config: &EventHandlerConfig,
		ctx: &mut Context,
		callbacks: &Callbacks<OnRead, OnAccept, OnClose, OnPanic, OnHousekeep>,
	) -> Result<(), Error> {
		let now = SystemTime::now().duration_since(UNIX_EPOCH)?.as_millis();

		if now - ctx.housekeeper_last > config.housekeeper_frequency.try_into()? {
			debug!("house keep: tid={},now={}", ctx.tid, now)?;
			match &callbacks.on_housekeep {
				Some(on_housekeeper) => match (on_housekeeper)(&mut ctx.user_data, ctx.tid) {
					Ok(_) => {}                                                       //============
					Err(e) => error!("housekeeper callback generated error: {}", e)?, //============
				},
				None => {
					//============
					error!("housekeeper not set")?;
				}
			}
			ctx.housekeeper_last = now;
		}

		Ok(())
	}

	fn thread_loop(
		ctx: &mut Context,
		config: &EventHandlerConfig,
		events: &mut HashSet<Event>,
		wakeup: &Wakeup,
		callbacks: &Callbacks<OnRead, OnAccept, OnClose, OnPanic, OnHousekeep>,
		connection_index_handle_map: &mut StaticHash<(), ()>,
		connection_index_id_map: &mut StaticHash<(), ()>,
		step_allocator: &mut StepAllocator,
		start: usize,
	) -> Result<bool, Error> {
		if config.debug_fatal {
			let msg = "thread loop fatal test".to_string();
			let ekind = ErrorKind::InternalError(msg);
			let error = ekind.into();
			return Err(error);
		}

		let c = config;
		let d = callbacks;
		let e = connection_index_handle_map;
		let f = connection_index_id_map;
		let g = step_allocator;
		let h = wakeup;

		// this is logic to deal with panics. If there was a panic, start will be > 0.
		// and we don't need to get new events yet.
		if start == 0 {
			let stop = Self::process_new(ctx, c, e, f, g, h, d)?;
			if stop {
				return Ok(stop);
			}
			{
				let (do_wakeup, _lock) = wakeup.pre_block()?;
				Self::get_events(config, ctx, events, do_wakeup)?;
			}
			wakeup.post_block()?;
			Self::check_housekeeper(config, ctx, callbacks)?;
			ctx.input_events.clear();

			debug!("event count = {}", events.len())?;
		}

		ctx.counter = start;

		let events = {
			//============
			let mut ret = vec![];
			for event in events.iter() {
				ret.push(event);
			}
			ret
		};

		loop {
			if ctx.counter >= events.len() {
				break; //============
			}
			let event = &events[ctx.counter];
			let a = event;
			match event.etype {
				EventType::Read => {
					let res = Self::process_read_event(a, ctx, c, d, e, f, g, h);

					match res {
						Ok(_) => {} //============
						Err(e) => {
							match e.kind() {
								ErrorKind::HandleNotFoundError(_e) => {
									// This is ok. Connection already disconnected
									// ignore.
								}
								_ => {
									//============
									return Err(e);
								}
							}
						}
					}
				}
				EventType::Write => Self::process_write_event(a, ctx, c, d, e, f, g, h)?,
				EventType::Error => Self::process_error_event(a, ctx, c, d, e, f, g, h)?,
				EventType::Accept => {} // accepts are returned as read.
			}
			ctx.counter += 1;
		}

		for handle in ctx.saturating_handles.clone() {
			let event = Event {
				handle: handle,
				etype: EventType::Read,
			};
			let a = &event;
			let res = Self::process_read_event(a, ctx, c, d, e, f, g, h);

			match res {
				Ok(_) => {}
				Err(e) => {
					match e.kind() {
						ErrorKind::HandleNotFoundError(_e) => {
							// This is ok. Connection already disconnected
							// ignore.
						}
						_ => {
							return Err(e);
						}
					}
				}
			}
		}

		Ok(false)
	}

	fn process_error_event(
		event: &Event,
		ctx: &mut Context,
		config: &EventHandlerConfig,
		callbacks: &Callbacks<OnRead, OnAccept, OnClose, OnPanic, OnHousekeep>,
		connection_index_handle_map: &mut StaticHash<(), ()>,
		connection_index_id_map: &mut StaticHash<(), ()>,
		step_allocator: &mut StepAllocator,
		wakeup: &Wakeup,
	) -> Result<(), Error> {
		let connection_info = match connection_index_handle_map.get_raw(&event.handle.to_be_bytes())
		{
			Some(index) => {
				let index = usize::from_be_bytes(index.try_into()?);
				match step_allocator.get(index)?.data_as::<ConnectionHashData>() {
					Some(connection_hash_data) => match &connection_hash_data.connection_info {
						Some(connection_info) => connection_info,
						None => {
							return Err(ErrorKind::HandleNotFoundError(format!(
								"Connection handle was not found for event 1: {:?}",
								event
							))
							.into());
						}
					},
					None => {
						return Err(ErrorKind::HandleNotFoundError(format!(
							"Connection handle was not found for event 2: {:?}",
							event
						))
						.into())
					}
				}
			}
			None => {
				return Err(ErrorKind::HandleNotFoundError(format!(
					"Connection handle was not found for event 3: {:?}",
					event
				))
				.into())
			}
		};

		let a = config;
		let b = connection_info.get_connection_id();
		let c = ctx;
		let d = callbacks;
		let e = connection_index_handle_map;
		let f = connection_index_id_map;
		let g = step_allocator;
		let h = wakeup;
		Self::close_connection(a, b, c, d, e, f, g, h, false)?;

		Ok(())
	}

	fn process_read_event(
		event: &Event,
		ctx: &mut Context,
		config: &EventHandlerConfig,
		callbacks: &Callbacks<OnRead, OnAccept, OnClose, OnPanic, OnHousekeep>,
		connection_index_handle_map: &mut StaticHash<(), ()>,
		connection_index_id_map: &mut StaticHash<(), ()>,
		step_allocator: &mut StepAllocator,
		wakeup: &Wakeup,
	) -> Result<(), Error> {
		debug!("process read: {:?}", event)?;

		let x: Option<(u128, Handle)> = {
			let (connection_info, connection_context) =
				match connection_index_handle_map.get_raw(&event.handle.to_be_bytes()) {
					Some(index) => {
						let index = usize::from_be_bytes(index.try_into()?);
						match step_allocator
							.get_mut(index)?
							.data_as_mut::<ConnectionHashData>()
						{
							Some(connection_hash_data) => match &mut connection_hash_data
								.connection_info
							{
								Some(connection_info) => {
									match &mut connection_hash_data.connection_context {
										Some(connection_context) => {
											(connection_info, connection_context)
										}
										None => {
											return Err(ErrorKind::HandleNotFoundError(format!(
												"Connection handle was not found for event 4: {:?}",
												event
											))
											.into());
										}
									}
								}
								None => {
									return Err(ErrorKind::HandleNotFoundError(format!(
										"Connection handle was not found for event 5: {:?}",
										event
									))
									.into());
								}
							},
							None => {
								return Err(ErrorKind::HandleNotFoundError(format!(
									"Connection handle was not found for event 6: {:?}",
									event
								))
								.into())
							}
						}
					}
					None => {
						return Err(ErrorKind::HandleNotFoundError(format!(
							"Connection handle was not found for event 7: {:?}",
							event
						))
						.into())
					}
				};

			let handle = event.handle;

			match &*connection_info {
				EventConnectionInfo::ListenerConnection(c) => {
					loop {
						if !Self::process_accept(
							handle,
							ctx,
							config,
							wakeup,
							callbacks,
							&c.tls_server_config,
						)? {
							break;
						}
					}
					None
				}
				EventConnectionInfo::ReadWriteConnection(c) => {
					debug!("start loop")?;
					let mut len;
					let mut sat_count = 0;
					loop {
						set_errno(Errno(0));
						len = Self::process_read(
							&c,
							ctx,
							wakeup,
							callbacks,
							config,
							connection_context,
						)?;
						debug!("len={}, c={:?}", len, c)?;
						if len <= 0 {
							ctx.saturating_handles.remove(&c.get_handle());
							break;
						}

						sat_count += 1;
						if sat_count >= 5 {
							ctx.saturating_handles.insert(c.get_handle());
							break;
						}
					}

					if len <= 0 {
						let e = errno().0;
						if e == libc::EAGAIN {
							// this is would block and not an error to close
							None
						} else {
							debug!(
								"error/close for {}, handle={}: {}",
								connection_info.get_connection_id(),
								connection_info.get_handle(ctx.tid),
								std::io::Error::last_os_error()
							)?;
							Some((
								connection_info.get_connection_id(),
								connection_info.get_handle(ctx.tid),
							))
						}
					} else {
						None
					}
				}
			}
		};

		match x {
			Some((id, _handle)) => {
				Self::close_connection(
					config,
					id,
					ctx,
					callbacks,
					connection_index_handle_map,
					connection_index_id_map,
					step_allocator,
					wakeup,
					true,
				)?;
			}
			None => {}
		}

		Ok(())
	}

	fn close_connection(
		config: &EventHandlerConfig,
		id: u128,
		ctx: &mut Context,
		callbacks: &Callbacks<OnRead, OnAccept, OnClose, OnPanic, OnHousekeep>,
		connection_index_handle_map: &mut StaticHash<(), ()>,
		connection_index_id_map: &mut StaticHash<(), ()>,
		step_allocator: &mut StepAllocator,
		wakeup: &Wakeup,
		close_handle: bool,
	) -> Result<(), Error> {
		let index_bytes = connection_index_id_map.remove_raw(&id.to_be_bytes());
		match index_bytes {
			Some(index_bytes) => {
				let index = usize::from_be_bytes(index_bytes.try_into()?);
				match step_allocator
					.get_mut(index)?
					.data_as_mut::<ConnectionHashData>()
				{
					Some(connection_hash_data) => match &mut connection_hash_data.connection_info {
						Some(connection_info) => {
							let handle = connection_info.get_handle(ctx.tid);
							connection_index_handle_map.remove_raw(&handle.to_be_bytes());
							let handle_as_usize: usize = handle.try_into()?;
							ctx.filter_set.set(handle_as_usize, false);

							match connection_info {
								EventConnectionInfo::ReadWriteConnection(ref c) => {
									{
										ctx.input_events.remove(&Event {
											handle,
											etype: EventType::Read,
										});
										ctx.input_events.remove(&Event {
											handle,
											etype: EventType::Write,
										});
										ctx.input_events.remove(&Event {
											handle,
											etype: EventType::Accept,
										});
										ctx.saturating_handles.remove(&handle);
										{
											let mut write_status = lockw!(c.write_status)?;
											(*write_status).set_is_closed();
											(*write_status).write_buffer.truncate(0);
										}
										{
											let mut cur_connections = lockw!(ctx.cur_connections)?;
											*cur_connections = (*cur_connections).saturating_sub(1);
										}
									}
									match callbacks.on_close.as_ref() {
										Some(on_close) => {
											match connection_hash_data.connection_context.as_mut() {
												Some(mut connection_context) => (on_close)(
													&ConnectionData::new(
														connection_info
															.get_read_write_connection_info()?,
														&ctx.guarded_data,
														&wakeup,
														ctx.tid,
														config.debug_pending,
													),
													&mut connection_context,
													&mut ctx.user_data,
												)?,
												None => error!("no context found for id = {}", id)?,
											}
										}
										None => warn!("no on_close callback")?,
									}

									if close_handle {
										#[cfg(unix)]
										unsafe {
											libc::close(handle);
										}
										#[cfg(windows)]
										unsafe {
											ws2_32::closesocket(handle);
										}
									}
								}
								_ => warn!("listener closed!")?,
							}
						}
						None => {
							error!("expected connection_info for {}", id)?;
						}
					},
					None => {
						error!("expected connection_hash_data for {}", id)?;
					}
				}

				step_allocator.free_index(index)?;
			}
			None => {
				error!("expected index_bytes for id = {}", id)?;
			}
		}

		Ok(())
	}

	fn process_accept(
		accept_handle: Handle,
		ctx: &mut Context,
		config: &EventHandlerConfig,
		wakeup: &Wakeup,
		callbacks: &Callbacks<OnRead, OnAccept, OnClose, OnPanic, OnHousekeep>,
		tls_server_config: &Option<ServerConfig>,
	) -> Result<bool, Error> {
		#[cfg(unix)]
		let handle = unsafe {
			set_errno(Errno(0));
			accept(
				accept_handle,
				&mut libc::sockaddr {
					..std::mem::zeroed()
				},
				&mut (std::mem::size_of::<libc::sockaddr>() as u32).try_into()?,
			)
		};
		#[cfg(windows)]
		let handle = unsafe {
			set_errno(Errno(0));
			ws2_32::accept(
				handle,
				&mut winapi::ws2def::SOCKADDR {
					..std::mem::zeroed()
				},
				&mut (std::mem::size_of::<winapi::ws2def::SOCKADDR>() as u32).try_into()?,
			)
		};

		if handle > 0 {
			// check that we have not exceeded maximum rwhandles before accepting
			{
				let cap_exceeded = {
					let mut cur_connections = lockw!(ctx.cur_connections)?;
					let ret = *cur_connections >= config.max_rwhandles;
					if !ret {
						*cur_connections += 1;
					}
					ret
				};

				if cap_exceeded {
					#[cfg(unix)]
					{
						unsafe { libc::close(handle) };
					}
					return Ok(false);
				}
			}

			// check max numeric value
			if handle >= config.max_handle_numeric_value.try_into()? {
				#[cfg(unix)]
				{
					unsafe { libc::close(handle) };
				}
				return Ok(false);
			}

			info!("Accepted handle = {} on tid={}", handle, ctx.tid)?;

			#[cfg(unix)]
			unsafe {
				fcntl(handle, libc::F_SETFL, libc::O_NONBLOCK)
			};
			#[cfg(target_os = "windows")]
			{
				let fionbio = 0x8004667eu32;
				let ioctl_res = unsafe { ws2_32::ioctlsocket(handle, fionbio as c_int, &mut 1) };

				if ioctl_res != 0 {
					error!("complete fion with error: {}", errno().to_string());
				}
				let sockoptres = unsafe {
					ws2_32::setsockopt(
						handle,
						winapi::SOL_SOCKET,
						winapi::SO_SNDBUF,
						&WINSOCK_BUF_SIZE as *const _ as *const i8,
						std::mem::size_of_val(&WINSOCK_BUF_SIZE) as winapi::c_int,
					)
				};

				if sockoptres != 0 {
					error!("setsockopt resulted in error: {}", errno().to_string());
				}
			}

			let tls_server = match tls_server_config {
				Some(tls_server_config) => {
					let tls_config = Arc::new(tls_server_config.clone());

					match ServerConnection::new(tls_config) {
						Ok(tls_conn) => Some(Arc::new(RwLock::new(tls_conn))),
						Err(e) => {
							error!("Error building tls_connection: {}", e.to_string())?;
							None
						}
					}
				}
				None => None,
			};

			let connection_info = EventConnectionInfo::read_write_connection(
				handle,
				Some(accept_handle),
				tls_server,
				None,
			);

			#[cfg(unix)]
			let remote_peer = Some(SocketAddr::from_str(&getpeername(handle)?.to_string())?);
			#[cfg(windows)]
			let remote_peer: Option<SocketAddr> = None; // TODO: make work for windows

			#[cfg(unix)]
			let local_peer = Some(SocketAddr::from_str(&getsockname(handle)?.to_string())?);
			#[cfg(windows)]
			let local_peer: Option<SocketAddr> = None; // TODO: make work for windows

			let mut connection_context = ConnectionContext::new(remote_peer, local_peer);

			match &callbacks.on_accept {
				Some(on_accept) => {
					let conn_data = ConnectionData::new(
						connection_info.get_read_write_connection_info()?,
						&ctx.guarded_data,
						&wakeup,
						ctx.tid,
						config.debug_pending,
					);
					match (on_accept)(&conn_data, &mut connection_context, &mut ctx.user_data) {
						Ok(_) => {}
						Err(e) => {
							warn!("on_accept Callback resulted in error: {}", e)?;
						}
					}
				}
				None => error!("no handler for on_accept!")?,
			};

			ctx.accepted_connections.push(connection_info);
			Ok(true)
		} else {
			if errno().0 != libc::EAGAIN {
				error!(
					"Error accepting connection: {}",
					std::io::Error::last_os_error()
				)?;
			}
			Ok(false)
		}
	}

	fn process_read(
		connection_info: &ReadWriteConnection,
		ctx: &mut Context,
		wakeup: &Wakeup,
		callbacks: &Callbacks<OnRead, OnAccept, OnClose, OnPanic, OnHousekeep>,
		config: &EventHandlerConfig,
		connection_context: &mut ConnectionContext,
	) -> Result<isize, Error> {
		debug!("read event on {:?}", connection_info)?;
		let (len, do_read_now) = match connection_info.tls_server {
			Some(ref tls_server) => {
				let (raw_len, tls_len) =
					Self::do_tls_server_read(&connection_info, ctx, wakeup, tls_server, config)?;
				let do_read_now = raw_len <= 0 || tls_len > 0;
				let len = if tls_len > 0 {
					tls_len.try_into()?
				} else {
					raw_len
				};
				(len, do_read_now)
			}
			None => match connection_info.tls_client {
				Some(ref tls_client) => {
					let (raw_len, tls_len) = Self::do_tls_client_read(
						&connection_info,
						ctx,
						wakeup,
						tls_client,
						config,
					)?;
					let do_read_now = raw_len <= 0 || tls_len > 0;
					let len = if tls_len > 0 {
						tls_len.try_into()?
					} else {
						raw_len
					};
					(len, do_read_now)
				}
				None => {
					let len = do_read(connection_info.handle, &mut ctx.buffer)?;
					(len, true)
				}
			},
		};

		if do_read_now {
			Self::process_read_result(
				connection_info,
				len,
				wakeup,
				callbacks,
				ctx,
				config,
				connection_context,
			)?;
		}

		Ok(len)
	}

	fn do_tls_client_read(
		connection_info: &ReadWriteConnection,
		ctx: &mut Context,
		wakeup: &Wakeup,
		tls_client: &Arc<RwLock<ClientConnection>>,
		config: &EventHandlerConfig,
	) -> Result<(isize, usize), Error> {
		let mut pt_len = 0;
		let handle = connection_info.handle;

		let len = do_read(handle, &mut ctx.buffer)?;

		let mut wbuf = vec![];
		if len > 0 {
			let mut tls_conn = nioruntime_util::lockw!(tls_client)?;
			tls_conn.read_tls(&mut &ctx.buffer[0..len.try_into()?])?;
			match tls_conn.process_new_packets() {
				Ok(io_state) => {
					pt_len = io_state.plaintext_bytes_to_read();

					if pt_len > ctx.buffer.len() {
						ctx.buffer.resize(pt_len, 0u8);
					}

					let buf = &mut ctx.buffer[0..pt_len];
					tls_conn.reader().read_exact(buf)?;
				}
				Err(e) => {
					warn!(
						"error generated processing packets for handle={}. Error={}",
						handle,
						e.to_string()
					)?;
					return Ok((-1, 0)); // invalid text received. Close conn.
				}
			}
			tls_conn.write_tls(&mut wbuf)?;
		}

		if len > 0 {
			let connection_data = &ConnectionData::new(
				connection_info,
				&ctx.guarded_data,
				&wakeup,
				ctx.tid,
				config.debug_pending,
			);
			connection_data.do_write(&wbuf)?;
		}

		Ok((len, pt_len))
	}

	fn do_tls_server_read(
		connection_info: &ReadWriteConnection,
		ctx: &mut Context,
		wakeup: &Wakeup,
		tls_server: &Arc<RwLock<ServerConnection>>,
		config: &EventHandlerConfig,
	) -> Result<(isize, usize), Error> {
		let mut pt_len = 0;
		let handle = connection_info.handle;

		let len = do_read(handle, &mut ctx.buffer)?;
		let mut wbuf = vec![];
		if len > 0 {
			let mut tls_conn = nioruntime_util::lockw!(tls_server)?;
			tls_conn.read_tls(&mut &ctx.buffer[0..len.try_into().unwrap_or(0)])?;

			match tls_conn.process_new_packets() {
				Ok(io_state) => {
					pt_len = io_state.plaintext_bytes_to_read();
					if pt_len > ctx.buffer.len() {
						ctx.buffer.resize(pt_len, 0u8);
					}
					let buf = &mut ctx.buffer[0..pt_len];
					tls_conn.reader().read_exact(&mut buf[..pt_len])?;
				}
				Err(e) => {
					warn!(
						"error generated processing packets for handle={}. Error={}",
						handle,
						e.to_string()
					)?;
					return Ok((-1, 0)); // invalid text received. Close conn.
				}
			}
			tls_conn.write_tls(&mut wbuf)?;
		}

		if len > 0 {
			let connection_data = &ConnectionData::new(
				connection_info,
				&ctx.guarded_data,
				&wakeup,
				ctx.tid,
				config.debug_pending,
			);

			connection_data.do_write(&wbuf)?;
		}

		Ok((len, pt_len))
	}

	fn process_read_result(
		connection_info: &ReadWriteConnection,
		len: isize,
		wakeup: &Wakeup,
		callbacks: &Callbacks<OnRead, OnAccept, OnClose, OnPanic, OnHousekeep>,
		ctx: &mut Context,
		config: &EventHandlerConfig,
		connection_context: &mut ConnectionContext,
	) -> Result<(), Error> {
		if len >= 0 {
			debug!("read {:?}", &ctx.buffer[0..len.try_into()?])?;
		} else {
			debug!("got a negative read: {} on conn={:?}", len, connection_info)?;
		}

		if wakeup.wakeup_handle_read == connection_info.handle {
			// wakeup event
		} else if len > 0 {
			debug!("read {} bytes", len)?;
			// non-wakeup, so execute on_read callback
			match &callbacks.on_read {
				Some(on_read) => {
					let connection_data = ConnectionData::new(
						connection_info,
						&ctx.guarded_data,
						&wakeup,
						ctx.tid,
						config.debug_pending,
					);
					match (on_read)(
						connection_data,
						&ctx.buffer[0..len.try_into()?],
						connection_context,
						&mut ctx.user_data,
					) {
						Ok(_) => {}
						Err(e) => {
							warn!("on_read Callback resulted in error: {}", e)?;
						}
					}
				}
				None => {
					error!("no on_read callback found!")?;
				}
			}
		}

		// now that read reasult has been processed, we resize the buffer if it was made
		// bigger for tls
		if ctx.buffer.len() > config.read_buffer_size {
			ctx.buffer.resize(config.read_buffer_size, 0u8);
		}

		Ok(())
	}

	fn process_write_event(
		event: &Event,
		ctx: &mut Context,
		config: &EventHandlerConfig,
		callbacks: &Callbacks<OnRead, OnAccept, OnClose, OnPanic, OnHousekeep>,
		connection_index_handle_map: &mut StaticHash<(), ()>,
		connection_index_id_map: &mut StaticHash<(), ()>,
		step_allocator: &mut StepAllocator,
		wakeup: &Wakeup,
	) -> Result<(), Error> {
		debug!("in process write for event: {:?}", event)?;

		let mut to_remove = vec![];

		let mut connection_info =
			match connection_index_handle_map.get_raw(&event.handle.to_be_bytes()) {
				Some(index) => {
					let index = usize::from_be_bytes(index.try_into()?);
					match step_allocator
						.get_mut(index)?
						.data_as_mut::<ConnectionHashData>()
					{
						Some(connection_hash_data) => match &connection_hash_data.connection_info {
							Some(connection_info) => connection_info,
							None => {
								return Err(ErrorKind::HandleNotFoundError(format!(
									"Connection handle was not found for event 8: {:?}",
									event
								))
								.into());
							}
						},
						None => {
							return Err(ErrorKind::HandleNotFoundError(format!(
								"Connection handle was not found for event 9: {:?}",
								event
							))
							.into())
						}
					}
				}
				None => {
					debug!("Write connection handle {} not found.", event.handle)?;
					// this is normal. The connection already closed.
					return Ok(());
				}
			};

		match &mut connection_info {
			EventConnectionInfo::ReadWriteConnection(connection_info) => {
				let connection_id = connection_info.get_connection_id();
				debug!("connection_info={:?}", connection_info)?;

				{
					let mut write_status = lockw!(connection_info.write_status)?;

					loop {
						if (*write_status).write_buffer.len() == 0 {
							(*write_status).set_is_pending(false);
							if (*write_status).close_oncomplete() {
								to_remove.push(connection_id);
							} else {
								let handle = connection_info.get_handle();
								let etype = EventType::Read;
								let event = Event { handle, etype };
								ctx.input_events.insert(event);
							}

							break; // we're done
						}
						let h = event.handle;
						let wb = &mut (*write_status).write_buffer;
						let (wr, _len) = Self::write_loop(h, wb)?;

						match wr {
							WriteResult::Ok => {}
							WriteResult::Err => {
								// error occurred. must close conn
								to_remove.push(connection_id);
								break;
							}
							WriteResult::Block => {
								// would block, need to exit write loop
								break;
							}
						}
					}
				}
			}
			EventConnectionInfo::ListenerConnection(_connection_info) => {
				warn!("tried to write to a listener: {:?}", event)?;
			}
		}

		for rem in to_remove {
			Self::close_connection(
				config,
				rem,
				ctx,
				callbacks,
				connection_index_handle_map,
				connection_index_id_map,
				step_allocator,
				wakeup,
				true,
			)?;
		}

		Ok(())
	}

	fn write_loop(handle: Handle, wbuf: &mut Vec<u8>) -> Result<(WriteResult, isize), Error> {
		let len = write_bytes(handle, &mut wbuf[..])?;
		if len < 0 {
			let e = errno().0;
			if e == libc::EAGAIN {
				Ok((WriteResult::Block, -1))
			} else {
				Ok((WriteResult::Err, -1))
			}
		} else {
			if len > 0 {
				let len: usize = len.try_into()?;
				if len == wbuf.len() {
					wbuf.clear();
				} else {
					let len: usize = len.try_into()?;
					wbuf.drain(..len);
				}
			}
			Ok((WriteResult::Ok, len))
		}
	}

	#[cfg(target_os = "windows")]
	fn get_events(
		config: &EventHandlerConfig,
		ctx: &mut Context,
		output_events: &mut HashSet<Event>,
		wakeup: bool,
	) -> Result<(), Error> {
		let epollfd = ctx.selector as *mut c_void;
		let filter_set = &mut ctx.filter_set;
		for evt in &ctx.input_events {
			if evt.etype == EventType::Read || evt.etype == EventType::Accept {
				let handle = evt.handle;

				let op = if filter_set.remove(&handle) {
					EPOLL_CTL_MOD
				} else {
					EPOLL_CTL_ADD
				};

				filter_set.insert(handle);

				let data = epoll_data_t {
					fd: handle.try_into()?,
				};

				let mut event = epoll_event {
					events: EPOLLIN | EPOLLRDHUP,
					data,
				};

				let res =
					unsafe { epoll_ctl(epollfd, op.try_into()?, handle as usize, &mut event) };

				if res != 0 {
					// socket already closed
					warn!("socket {} already closed in get_events", handle);
					filter_set.remove(&handle);
				};
			} else if evt.etype == EventType::Write {
				let handle = evt.handle;
				let op = if filter_set.remove(&handle) {
					EPOLL_CTL_MOD
				} else {
					EPOLL_CTL_ADD
				};
				filter_set.insert(handle);

				let data = epoll_data_t {
					fd: handle.try_into()?,
				};
				let mut event = epoll_event {
					events: EPOLLIN | EPOLLOUT | EPOLLRDHUP,
					data,
				};

				let res =
					unsafe { epoll_ctl(epollfd, op.try_into()?, handle.try_into()?, &mut event) };
				if res != 0 {
					filter_set.remove(&handle);
					error!(
						"epoll_ctl (write) resulted in an unexpected error: {}, fd={}, op={}, epoll_ctl_add={}",
						errno().to_string(), handle, op, EPOLL_CTL_ADD,
					);
				}
			}
		}

		let mut events: [epoll_event; MAX_EVENTS as usize] =
			unsafe { std::mem::MaybeUninit::uninit().assume_init() };
		let results = unsafe {
			epoll_wait(
				epollfd,
				events.as_mut_ptr(),
				MAX_EVENTS,
				match ctx.saturating_handles.len() > 0 || wakeup {
					true => 0,
					false => config.housekeeper_frequency,
				},
			)
		};

		if results > 0 {
			for i in 0..results {
				if !(events[i as usize].events & EPOLLOUT == 0) {
					output_events.insert(Event {
						handle: unsafe { events[i as usize].data.fd } as Handle,
						etype: EventType::Write,
					});
				}
				if !(events[i as usize].events & EPOLLIN == 0) {
					output_events.insert(Event {
						handle: unsafe { events[i as usize].data.fd } as Handle,
						etype: EventType::Read,
					});
				}
				if events[i as usize].events & (EPOLLIN | EPOLLOUT) == 0 {
					let fd = unsafe { events[i as usize].data.fd };
					let data = epoll_data_t {
						fd: fd.try_into().unwrap_or(0),
					};
					let mut event = epoll_event {
						events: 0, // not used for del
						data,
					};
					let res = unsafe {
						epoll_ctl(
							epollfd,
							EPOLL_CTL_DEL.try_into()?,
							fd.try_into()?,
							&mut event,
						)
					};

					if res != 0 {
						error!(
							"Unexpected error with EPOLLHUP. res = {}, err={}",
							res,
							errno().to_string(),
						);
					}
				}
			}
		}

		Ok(())
	}

	#[cfg(any(target_os = "linux"))]
	fn get_events(
		config: &EventHandlerConfig,
		ctx: &mut Context,
		events: &mut HashSet<Event>,
		wakeup: bool,
	) -> Result<(), Error> {
		debug!(
			"in get events with {} events. tid={}",
			ctx.input_events.len(),
			ctx.tid
		)?;

		events.clear();

		let epollfd = ctx.selector;
		for evt in &ctx.input_events {
			let mut interest = EpollFlags::empty();

			if evt.etype == EventType::Read || evt.etype == EventType::Accept {
				let fd = evt.handle;
				interest |= EpollFlags::EPOLLIN;
				interest |= EpollFlags::EPOLLET;
				interest |= EpollFlags::EPOLLRDHUP;

				let handle_as_usize: usize = fd.try_into()?;
				let op = match ctx.filter_set.get(handle_as_usize) {
					Some(bitref) => {
						if *bitref {
							EpollOp::EpollCtlMod
						} else {
							EpollOp::EpollCtlAdd
						}
					}
					None => EpollOp::EpollCtlAdd,
				};
				ctx.filter_set.set(handle_as_usize, true);

				let mut event = EpollEvent::new(interest, evt.handle.try_into().unwrap_or(0));
				let res = epoll_ctl(epollfd, op, evt.handle, &mut event);
				match res {
					Ok(_) => {}
					Err(e) => {
						events.insert(Event {
							handle: fd,
							etype: EventType::Error,
						});
						error!("Error epoll_ctl2: {}, fd={}, op={:?}", e, fd, op)?
					}
				}
			} else if evt.etype == EventType::Write {
				let fd = evt.handle;
				interest |= EpollFlags::EPOLLOUT;
				interest |= EpollFlags::EPOLLIN;
				interest |= EpollFlags::EPOLLRDHUP;
				interest |= EpollFlags::EPOLLET;

				let handle_as_usize: usize = fd.try_into()?;
				let op = match ctx.filter_set.get(handle_as_usize) {
					Some(bitref) => {
						if *bitref {
							EpollOp::EpollCtlMod
						} else {
							EpollOp::EpollCtlAdd
						}
					}
					None => EpollOp::EpollCtlAdd, //============
				};
				ctx.filter_set.set(handle_as_usize, true);

				let mut event = EpollEvent::new(interest, evt.handle.try_into().unwrap_or(0));
				let res = epoll_ctl(epollfd, op, evt.handle, &mut event);
				match res {
					Ok(_) => {} //============
					Err(e) => {
						//============
						events.insert(Event {
							handle: fd,
							etype: EventType::Error,
						});
						error!("Error epoll_ctl3: {}, fd={}, op={:?}", e, fd, op)? //============
					}
				}
			} else {
				return Err(
					//============
					ErrorKind::InternalError(format!("unexpected etype: {:?}", evt.etype)).into(),
				);
			}
		}

		let results = epoll_wait(
			epollfd, //============
			&mut ctx.epoll_events,
			match ctx.saturating_handles.len() > 0 || wakeup {
				true => 0,
				false => config.housekeeper_frequency,
			},
		);

		match results {
			Ok(results) => {
				if results > 0 {
					for i in 0..results {
						if !(ctx.epoll_events[i].events() & EpollFlags::EPOLLOUT).is_empty() {
							events.insert(Event {
								handle: ctx.epoll_events[i].data() as Handle,
								etype: EventType::Write, //============
							});
						}
						if !(ctx.epoll_events[i].events() & EpollFlags::EPOLLIN).is_empty() {
							events.insert(Event {
								handle: ctx.epoll_events[i].data() as Handle,
								etype: EventType::Read, //============
							});
						}
					}
				}
			}
			Err(e) => {
				error!("Error with epoll wait = {}", e.to_string())?; //============
			}
		}
		Ok(())
	}

	#[cfg(any(
		target_os = "macos",
		target_os = "dragonfly",
		target_os = "netbsd",
		target_os = "openbsd",
		target_os = "freebsd"
	))]
	#[cfg(not(tarpaulin_include))]
	fn get_events(
		config: &EventHandlerConfig,
		ctx: &mut Context,
		events: &mut HashSet<Event>,
		wakeup: bool,
	) -> Result<(), Error> {
		debug!(
			"in get events with {} events. tid={}",
			ctx.input_events.len(),
			ctx.tid
		)?;

		let mut kevs = vec![];
		// TODO: handle inserting an invalid fd
		for event in &ctx.input_events {
			debug!("pushing input event = {:?}", event)?;
			match event.etype {
				EventType::Accept => {
					trace!("pushing an accept")?;
					kevs.push(kevent::new(
						event.handle.try_into()?,
						EventFilter::EVFILT_READ,
						EventFlag::EV_ADD | EventFlag::EV_CLEAR,
						FilterFlag::empty(),
					));
				}
				EventType::Read => {
					info!("pushing a read: {}", event.handle)?;
					kevs.push(kevent::new(
						event.handle.try_into()?,
						EventFilter::EVFILT_READ,
						EventFlag::EV_ADD | EventFlag::EV_CLEAR,
						FilterFlag::empty(),
					));
				}
				EventType::Write => {
					trace!("pushing a write")?;
					kevs.push(kevent::new(
						event.handle.try_into()?,
						EventFilter::EVFILT_WRITE,
						EventFlag::EV_ADD | EventFlag::EV_CLEAR,
						FilterFlag::empty(),
					));
				}
				EventType::Error => {}
			}
		}

		let mut ret_kevs = vec![];
		for _ in 0..MAX_EVENTS {
			ret_kevs.push(kevent::new(
				0,
				EventFilter::EVFILT_SYSCOUNT,
				EventFlag::empty(),
				FilterFlag::empty(),
			));
		}

		let ret_count = unsafe {
			kevent(
				ctx.selector,
				kevs.as_ptr(),
				kevs.len() as i32,
				ret_kevs.as_mut_ptr(),
				MAX_EVENTS,
				&Self::duration_to_timespec(Duration::from_millis(
					match ctx.saturating_handles.len() > 0 || wakeup {
						true => 0,
						false => config.housekeeper_frequency.try_into()?,
					},
				)),
			)
		};

		debug!("kqueue wakeup with ret_count = {}", ret_count)?;
		events.clear();
		for i in 0..ret_count as usize {
			events.insert(Event {
				handle: ret_kevs[i].ident.try_into()?,
				etype: match ret_kevs[i].filter {
					EventFilter::EVFILT_READ => EventType::Read,
					EventFilter::EVFILT_WRITE => EventType::Write,
					_ => {
						return Err(ErrorKind::KqueueError(format!(
							"unexpected event type returned by kqueue: {:?}",
							ret_kevs[i]
						))
						.into())
					}
				},
			});
		}
		Ok(())
	}

	#[cfg(any(target_os = "macos", dragonfly, netbsd, openbsd))]
	#[cfg(not(tarpaulin_include))]
	fn duration_to_timespec(d: Duration) -> timespec {
		let tv_sec = d.as_secs() as i64;
		let tv_nsec = d.subsec_nanos() as i64;

		if tv_sec.is_negative() {
			panic!("Duration seconds is negative");
		}

		if tv_nsec.is_negative() {
			panic!("Duration nsecs is negative");
		}

		timespec { tv_sec, tv_nsec }
	}

	#[cfg(all(target_os = "freebsd", target_arch = "x86"))]
	#[cfg(not(tarpaulin_include))]
	fn duration_to_timespec(d: Duration) -> Result<timespec, Error> {
		let tv_sec = d.as_secs() as i32;
		let tv_nsec = d.subsec_nanos() as i32;

		if tv_sec.is_negative() {
			return Err(
				ErrorKind::TimespecError("Duration seconds is negative".to_string()).into(),
			);
		}

		if tv_nsec.is_negative() {
			return Err(ErrorKind::TimespecError("Duration nsecs is negative".to_string()).into());
		}

		timespec { tv_sec, tv_nsec }
	}

	fn process_new(
		ctx: &mut Context,
		config: &EventHandlerConfig,
		connection_index_handle_map: &mut StaticHash<(), ()>,
		connection_index_id_map: &mut StaticHash<(), ()>,
		step_allocator: &mut StepAllocator,
		wakeup: &Wakeup,
		callbacks: &Callbacks<OnRead, OnAccept, OnClose, OnPanic, OnHousekeep>,
	) -> Result<bool, Error> {
		let stop = {
			let mut guarded_data = lockw!(ctx.guarded_data)?;
			ctx.add_pending.append(&mut (*guarded_data).nhandles);
			ctx.nwrites.append(&mut (*guarded_data).write_queue);
			guarded_data.stop
		};

		if stop {
			Self::process_stop(wakeup)?;
		} else {
			ctx.add_pending.append(&mut ctx.accepted_connections);

			let tid = ctx.tid;
			let pen = &ctx.add_pending;
			debug!("adding pending conns: {:?} on tid={}", pen, tid)?;

			let b = connection_index_handle_map;
			let c = connection_index_id_map;
			let d = step_allocator;
			let e = wakeup;
			let f = callbacks;
			let g = config;

			Self::process_pending(ctx, b, c, d)?;
			ctx.add_pending.clear();

			Self::process_nwrites(ctx, c, d, e, f, g)?;
			ctx.nwrites.clear();
		}

		Ok(stop)
	}

	fn process_stop(wakeup: &Wakeup) -> Result<(), Error> {
		#[cfg(unix)]
		{
			unsafe {
				libc::close(wakeup.wakeup_handle_read);
			}

			unsafe {
				libc::close(wakeup.wakeup_handle_write);
			}
		}
		// TODO: close in windows.
		Ok(())
	}

	fn process_nwrites(
		ctx: &mut Context,
		connection_index_id_map: &mut StaticHash<(), ()>,
		step_allocator: &mut StepAllocator,
		wakeup: &Wakeup,
		callbacks: &Callbacks<OnRead, OnAccept, OnClose, OnPanic, OnHousekeep>,
		config: &EventHandlerConfig,
	) -> Result<(), Error> {
		debug!("process nwrites with {} connections", ctx.nwrites.len())?;
		for connection_id in &ctx.nwrites {
			let (connection_info, connection_context) = match connection_index_id_map
				.get_raw(&connection_id.to_be_bytes())
			{
				Some(index) => {
					let index = usize::from_be_bytes(index.try_into()?);
					match step_allocator
						.get_mut(index)? //============
						.data_as_mut::<ConnectionHashData>()
					{
						Some(connection_hash_data) => match &connection_hash_data.connection_info {
							Some(connection_info) => {
								match &mut connection_hash_data.connection_context {
									Some(connection_context) => {
										(connection_info, connection_context)
									}
									None => {
										//============
										return Err(ErrorKind::HandleNotFoundError(format!(
											"Connection info was not found for id : {}",
											connection_id
										))
										.into()); //============
									}
								}
							}
							None => {
								//============
								return Err(ErrorKind::HandleNotFoundError(format!(
									"Connection info was not found for id : {}",
									connection_id
								))
								.into()); //============
							}
						},
						None => {
							//============
							return Err(ErrorKind::HandleNotFoundError(format!(
								"Connection hash_data was not found for id: {}",
								connection_id
							))
							.into()); //============
						}
					}
				}
				None => {
					//============
					// connection already closed
					debug!("Attempt to write on closed connection: {:?}", connection_id)?;
					continue; //============
				}
			};

			match connection_info {
				EventConnectionInfo::ReadWriteConnection(item) => {
					let mut async_complete = false;
					{
						let mut write_status = lockw!(item.write_status)?;
						if (*write_status).write_buffer.len() == 0
							&& !(*write_status).is_closed()
							&& (*write_status).async_complete()
						{
							async_complete = true;
						}
					}

					if async_complete {
						match callbacks.on_read.as_ref() {
							Some(on_read) => {
								let connection_data = ConnectionData::new(
									&item,
									&ctx.guarded_data,
									&wakeup,
									ctx.tid,
									config.debug_pending,
								);
								connection_context.is_async_complete = true;
								let a = connection_data;
								let b = &ctx.buffer[0..0];
								let d = &mut ctx.user_data;
								match (on_read)(a, b, connection_context, d) {
									Ok(_) => {} //============
									Err(e) => {
										//============
										warn!("on_read Callback resulted in error: {}", e)?;
									}
								}
								connection_context.is_async_complete = false;
							}
							None => warn!("no onread handler found")?, //============
						}
					}

					let handle = item.handle;
					let etype = EventType::Write;
					ctx.input_events.insert(Event { handle, etype });
				}
				EventConnectionInfo::ListenerConnection(item) => {
					warn!("Got a write request on listener: {:?}", item)?; //============
				}
			}
		}

		Ok(())
	}

	fn process_pending(
		ctx: &mut Context,
		connection_index_handle_map: &mut StaticHash<(), ()>,
		connection_index_id_map: &mut StaticHash<(), ()>,
		step_allocator: &mut StepAllocator,
	) -> Result<(), Error> {
		debug!("process_pending with {} connections", ctx.add_pending.len())?;
		let b = step_allocator;
		let c = connection_index_handle_map;
		let d = connection_index_id_map;
		for pending in &ctx.add_pending {
			let a = pending.clone();
			Self::insert_step_allocator(a, b, c, d, ctx.tid)?;

			match pending {
				EventConnectionInfo::ReadWriteConnection(item) => {
					let handle = item.handle;
					let etype = EventType::Read;
					ctx.input_events.insert(Event { handle, etype });
				}
				EventConnectionInfo::ListenerConnection(item) => {
					let i = item.handles[ctx.tid];
					let t = ctx.tid;
					debug!("pushing accept handle: {} to tid={}", i, t)?;

					let handle = item.handles[ctx.tid];
					let etype = EventType::Accept;
					ctx.input_events.insert(Event { handle, etype });
				}
			}
		}
		Ok(())
	}
}

enum WriteResult {
	Ok,
	Err,
	Block,
}

fn do_read(handle: Handle, buf: &mut [u8]) -> Result<isize, Error> {
	#[cfg(unix)]
	{
		let cbuf: *mut c_void = buf as *mut _ as *mut c_void;
		Ok(unsafe { read(handle, cbuf, buf.len()) })
	}
	#[cfg(target_os = "windows")]
	{
		let cbuf: *mut i8 = buf as *mut _ as *mut i8;
		set_errno(Errno(0));
		let mut len = unsafe { ws2_32::recv(handle.try_into()?, cbuf, buf.len().try_into()?, 0) };
		if errno().0 == 10035 {
			// would block
			len = -2;
		}
		Ok(len.try_into().unwrap_or(-1))
	}
}

fn write_bytes(handle: Handle, buf: &[u8]) -> Result<isize, Error> {
	#[cfg(unix)]
	let len = {
		set_errno(Errno(0));
		let cbuf: *const c_void = buf as *const _ as *const c_void;
		unsafe { write(handle, cbuf, buf.len().into()) }
	};
	#[cfg(target_os = "windows")]
	let len = {
		let cbuf: *mut i8 = buf as *const _ as *mut i8;
		unsafe {
			ws2_32::send(
				handle.try_into().unwrap_or(0),
				cbuf,
				(buf.len()).try_into().unwrap_or(0),
				0,
			)
		}
	};
	Ok(len.try_into().unwrap_or(0))
}

#[derive(Clone)]
pub struct ConnectionHashData {
	connection_info: Option<EventConnectionInfo>,
	connection_context: Option<ConnectionContext>,
}

impl ConnectionHashData {
	pub fn new() -> Self {
		Self {
			connection_info: None,
			connection_context: None,
		}
	}
}

#[derive(Clone, Debug)]
pub struct TLSServerConfig {
	/// The location of the private_key file (privkey.pem).
	pub private_key_file: String,
	/// The location of the certificates file (fullchain.pem).
	pub certificates_file: String,
	/// The sni_host to use with the cert/key pair.
	pub sni_host: String,
}

pub struct TLSClientConfig {
	pub server_name: String,
	pub trusted_cert_full_chain_file: Option<String>,
}

fn make_config(trusted_cert_full_chain_file: Option<String>) -> Result<Arc<ClientConfig>, Error> {
	let mut root_store = RootCertStore::empty();
	match trusted_cert_full_chain_file {
		Some(trusted_cert_full_chain_file) => {
			let full_chain_certs = load_certs(&trusted_cert_full_chain_file)?;
			for i in 0..full_chain_certs.len() {
				root_store.add(&full_chain_certs[i]).map_err(|e| {
					let error: Error = ErrorKind::SetupError(format!(
						//============
						"adding certificate to root store generated error: {}",
						e.to_string() //============
					))
					.into();
					error
				})?;
			}
		}
		None => {}
	}

	let config = ClientConfig::builder()
		.with_safe_default_cipher_suites()
		.with_safe_default_kx_groups()
		.with_safe_default_protocol_versions()?
		.with_root_certificates(root_store)
		.with_no_client_auth();

	Ok(Arc::new(config))
}

fn load_certs(filename: &str) -> Result<Vec<Certificate>, Error> {
	let certfile = File::open(filename)?;
	let mut reader = BufReader::new(certfile);
	let certs = rustls_pemfile::certs(&mut reader)?;
	Ok(certs.iter().map(|v| Certificate(v.clone())).collect())
}

fn load_private_key(filename: &str) -> Result<PrivateKey, Error> {
	let keyfile = File::open(filename)?;
	let mut reader = BufReader::new(keyfile);

	loop {
		//============
		match rustls_pemfile::read_one(&mut reader)? {
			Some(rustls_pemfile::Item::RSAKey(key)) => return Ok(PrivateKey(key)), //============
			Some(rustls_pemfile::Item::PKCS8Key(key)) => return Ok(PrivateKey(key)),
			None => break,
			_ => {}
		}
	}

	Err(ErrorKind::TLSError(format!("no private keys found in file: {}", filename)).into())
	//============
}

#[derive(Debug, Clone)]
pub struct WriteStatus {
	write_buffer: Vec<u8>,
	flags: u8,
}

const FLAG_CLOSE_ONCOMPLETE: u8 = 0x1 << 0;
const FLAG_IS_CLOSED: u8 = 0x1 << 1;
const FLAG_IS_PENDING: u8 = 0x1 << 2;
const FLAG_ASYNC_COMPLETE: u8 = 0x1 << 3;

impl WriteStatus {
	fn new() -> Self {
		Self {
			write_buffer: vec![],
			flags: 0,
		}
	}

	fn set_async_complete(&mut self) {
		self.flags |= FLAG_ASYNC_COMPLETE;
	}

	fn async_complete(&mut self) -> bool {
		let ret = (self.flags & FLAG_ASYNC_COMPLETE) != 0;
		// now unset it
		self.flags &= !FLAG_ASYNC_COMPLETE;
		ret
	}

	fn set_close_oncomplete(&mut self) {
		self.set_is_closed();
		self.flags |= FLAG_CLOSE_ONCOMPLETE;
	}

	fn close_oncomplete(&self) -> bool {
		(self.flags & FLAG_CLOSE_ONCOMPLETE) != 0
	}

	fn set_is_pending(&mut self, value: bool) {
		if value {
			self.flags |= FLAG_IS_PENDING;
		} else {
			self.flags &= !FLAG_IS_PENDING;
		}
	}

	fn is_pending(&self) -> bool {
		(self.flags & FLAG_IS_PENDING) != 0
	}

	fn set_is_closed(&mut self) {
		self.flags |= FLAG_IS_CLOSED;
	}

	fn is_closed(&self) -> bool {
		(self.flags & FLAG_IS_CLOSED) != 0
	}
}

#[derive(Clone)]
pub struct ReadWriteConnection {
	id: u128,
	handle: Handle,
	accept_handle: Option<Handle>,
	write_status: Arc<RwLock<WriteStatus>>,
	tls_server: Option<Arc<RwLock<ServerConnection>>>,
	tls_client: Option<Arc<RwLock<ClientConnection>>>,
	buffer: Vec<u8>,
}

impl Debug for ReadWriteConnection {
	fn fmt(&self, f: &mut Formatter<'_>) -> Result<(), std::fmt::Error> {
		f.debug_struct("ListenerConnection")
			.field("id", &self.id)
			.field("handle", &self.handle)
			.field("accept_handle", &self.accept_handle)
			.field("write_status", &self.write_status)
			.field("tls_server", &self.tls_server)
			.field("tls_client", &self.tls_client)
			.finish()?;
		Ok(())
	}
}

impl ReadWriteConnection {
	fn new(
		id: u128,
		handle: Handle,
		accept_handle: Option<Handle>,
		tls_server: Option<Arc<RwLock<ServerConnection>>>,
		tls_client: Option<Arc<RwLock<ClientConnection>>>,
	) -> Self {
		Self {
			id,
			handle,
			accept_handle,
			write_status: Arc::new(RwLock::new(WriteStatus::new())),
			tls_server,
			tls_client,
			buffer: vec![],
		}
	}

	fn get_connection_id(&self) -> u128 {
		self.id
	}

	fn get_handle(&self) -> Handle {
		self.handle
	}

	fn get_accept_handle(&self) -> Option<Handle> {
		self.accept_handle
	}

	fn get_buffer(&mut self) -> &mut Vec<u8> {
		&mut self.buffer
	}
}

#[derive(Clone)]
struct ListenerConnection {
	id: u128,
	handles: Vec<Handle>,
	tls_server_config: Option<ServerConfig>,
}

impl Debug for ListenerConnection {
	fn fmt(&self, f: &mut Formatter<'_>) -> Result<(), std::fmt::Error> {
		//============
		f.debug_struct("ListenerConnection") //============
			.field("id", &self.id)
			.field("handles", &self.handles)
			.field("tls_server_config", &self.tls_server_config.is_some())
			.finish()?;
		Ok(()) //============
	}
}

impl ListenerConnection {
	fn get_handle(&self, tid: usize) -> Handle {
		self.handles[tid]
	}
}

#[derive(Clone, Debug)]
enum EventConnectionInfo {
	ListenerConnection(ListenerConnection),
	ReadWriteConnection(ReadWriteConnection),
}

impl EventConnectionInfo {
	fn as_read_write_connection(&self) -> Result<&ReadWriteConnection, Error> {
		match self {
			EventConnectionInfo::ReadWriteConnection(r) => Ok(&r),
			_ => {
				Err(ErrorKind::InvalidType("this is not a ReadWriteConnection".to_string()).into())
				//============
			}
		}
	}

	fn read_write_connection(
		handle: Handle,
		accept_handle: Option<Handle>,
		tls_server: Option<Arc<RwLock<ServerConnection>>>,
		tls_client: Option<Arc<RwLock<ClientConnection>>>,
	) -> EventConnectionInfo {
		EventConnectionInfo::ReadWriteConnection(ReadWriteConnection::new(
			rand::random(),
			handle,
			accept_handle,
			tls_server,
			tls_client,
		))
	}

	fn listener_connection(
		handles: Vec<Handle>,
		tls_server_config: Option<ServerConfig>,
	) -> EventConnectionInfo {
		EventConnectionInfo::ListenerConnection(ListenerConnection {
			id: rand::random(),
			handles,
			tls_server_config,
		})
	}

	fn get_connection_id(&self) -> u128 {
		match self {
			EventConnectionInfo::ListenerConnection(c) => c.id,
			EventConnectionInfo::ReadWriteConnection(c) => c.id,
		}
	}

	fn get_handle(&self, tid: usize) -> Handle {
		match self {
			EventConnectionInfo::ListenerConnection(c) => c.get_handle(tid),
			EventConnectionInfo::ReadWriteConnection(c) => c.get_handle(),
		}
	}

	fn get_read_write_connection_info(&self) -> Result<&ReadWriteConnection, Error> {
		match self {
			EventConnectionInfo::ReadWriteConnection(connection_info) => Ok(connection_info),
			EventConnectionInfo::ListenerConnection(_) => {
				Err(ErrorKind::WrongConnectionType("this is a listener".to_string()).into()) //============
			}
		}
	}
}

#[allow(dead_code)]
#[derive(Debug, PartialEq, Eq, Hash, Clone, Copy)]
enum EventType {
	Accept,
	Read,
	Write,
	Error,
}

#[derive(Debug, Hash, Eq, PartialEq)]
struct Event {
	handle: Handle,
	etype: EventType,
}

#[derive(Debug, Clone)]
pub struct Wakeup {
	wakeup_handle_read: Handle,
	wakeup_handle_write: Handle,
	needed: Arc<RwLock<bool>>,
	requested: Arc<RwLock<bool>>,
}

impl Wakeup {
	fn new() -> Result<Self, Error> {
		let (wakeup_handle_read, wakeup_handle_write) = Self::build_pipe()?;
		Ok(Self {
			wakeup_handle_read,
			wakeup_handle_write,
			needed: Arc::new(RwLock::new(false)),
			requested: Arc::new(RwLock::new(false)),
		})
	}

	fn wakeup(&self) -> Result<(), Error> {
		{
			let mut requested = lockw!(self.requested)?;
			*requested = true;
		}

		let need_wakeup = {
			let needed = lockr!(self.needed)?;
			*needed
		};

		if need_wakeup {
			write_bytes(self.wakeup_handle_write, &mut [0u8; 1])?;
		}
		Ok(())
	}

	fn pre_block(&self) -> Result<(bool, RwLockReadGuard<bool>), Error> {
		let requested = { *lockr!(self.requested)? };

		{
			*(lockw!(self.needed)?) = true;
		}
		let lock_guard = lockr!(self.needed)?;

		Ok((requested, lock_guard))
	}

	fn post_block(&self) -> Result<(), Error> {
		{
			let mut needed = lockw!(self.needed)?;
			*needed = false;
		}

		{
			let mut requested = lockw!(self.requested)?;
			*requested = false;
		}

		Ok(())
	}

	#[cfg(target_os = "windows")]
	fn socket_pipe(fds: *mut i32) -> Result<(TcpListener, TcpStream), Error> {
		let port = nioruntime_deps::portpicker::pick_unused_port().unwrap_or(9999);
		let listener = TcpListener::bind(format!("127.0.0.1:{}", port))?;
		let stream = TcpStream::connect(format!("127.0.0.1:{}", port))?;
		let res = unsafe {
			accept(
				listener.as_raw_socket().try_into().unwrap_or(0),
				&mut libc::sockaddr {
					..std::mem::zeroed()
				},
				&mut (std::mem::size_of::<libc::sockaddr>() as u32)
					.try_into()
					.unwrap_or(0),
			)
		};
		let fds: &mut [i32] = unsafe { std::slice::from_raw_parts_mut(fds, 2) };
		fds[0] = res as i32;
		fds[1] = stream.as_raw_socket().try_into().unwrap_or(0);

		Ok((listener, stream))
	}

	fn build_pipe() -> Result<(Handle, Handle), Error> {
		#[cfg(target_os = "windows")]
		{
			let mut rethandles = [0u64; 2];
			let handles: *mut c_int = &mut rethandles as *mut _ as *mut c_int;
			let res = Self::socket_pipe(handles);
			match res {
				Ok((listener, stream)) => {
					//self._pipe_listener[_i] = Some(listener);
					//self._pipe_stream[_i] = Some(stream);
				}
				Err(e) => {
					error!("Error creating socket_pipe on windows, {}", e.to_string());
				}
			}
			Ok((rethandles[0].try_into()?, rethandles[1].try_into()?))
		}
		#[cfg(unix)]
		{
			let mut retfds = [0i32; 2];
			let fds: *mut c_int = &mut retfds as *mut _ as *mut c_int;
			unsafe { pipe(fds) };
			unsafe { fcntl(retfds[0], libc::F_SETFL, libc::O_NONBLOCK) };
			unsafe { fcntl(retfds[1], libc::F_SETFL, libc::O_NONBLOCK) };
			Ok((retfds[0], retfds[1]))
		}
	}
}

#[derive(Debug)]
pub struct GuardedData {
	write_queue: Vec<u128>,
	nhandles: Vec<EventConnectionInfo>,
	stop: bool,
}

impl GuardedData {
	fn new() -> Self {
		Self {
			write_queue: vec![],
			nhandles: vec![],
			stop: false,
		}
	}
}

pub trait UserData {}
struct EmptyUserData {}
impl UserData for EmptyUserData {}

struct Context {
	guarded_data: Arc<RwLock<GuardedData>>,
	add_pending: Vec<EventConnectionInfo>,
	accepted_connections: Vec<EventConnectionInfo>,
	nwrites: Vec<u128>,
	input_events: HashSet<Event>,
	selector: SelectorHandle,
	tid: usize,
	buffer: Vec<u8>,
	filter_set: BitVec,
	#[cfg(target_os = "linux")]
	epoll_events: Vec<EpollEvent>,
	counter: usize, // used for handling panics
	saturating_handles: HashSet<Handle>,
	cur_connections: Arc<RwLock<usize>>,
	housekeeper_last: u128,
	user_data: Box<dyn Any + Send + Sync>,
}

impl Context {
	fn new(
		tid: usize,
		guarded_data: Arc<RwLock<GuardedData>>,
		config: EventHandlerConfig,
		cur_connections: Arc<RwLock<usize>>,
	) -> Result<Self, Error> {
		let mut buffer = vec![];
		buffer.resize(config.read_buffer_size, 0u8);
		#[cfg(target_os = "linux")]
		let epoll_events = [EpollEvent::new(EpollFlags::empty(), 0); MAX_EVENTS as usize].to_vec();

		let cap = config.max_handle_numeric_value;
		let mut filter_set: BitVec = BitVec::with_capacity(cap);
		filter_set.resize(cap, false);

		Ok(Self {
			counter: 0,
			#[cfg(target_os = "linux")]
			epoll_events,
			guarded_data,
			filter_set,
			add_pending: vec![],
			accepted_connections: vec![],
			nwrites: vec![],
			input_events: HashSet::new(),
			#[cfg(any(target_os = "linux"))]
			selector: epoll_create1(EpollCreateFlags::empty())?,
			#[cfg(any(
				target_os = "macos",
				target_os = "dragonfly",
				target_os = "netbsd",
				target_os = "openbsd",
				target_os = "freebsd"
			))]
			selector: unsafe { kqueue() },
			#[cfg(any(target_os = "windows"))]
			selector: unsafe { epoll_create(1) } as u64,
			tid,
			buffer,
			saturating_handles: HashSet::new(),
			cur_connections,
			housekeeper_last: 0,
			user_data: Box::new(0),
		})
	}
}

#[derive(Clone)]
struct Callbacks<OnRead, OnAccept, OnClose, OnPanic, OnHousekeep> {
	on_read: Option<Pin<Box<OnRead>>>,
	on_accept: Option<Pin<Box<OnAccept>>>,
	on_close: Option<Pin<Box<OnClose>>>,
	on_panic: Option<Pin<Box<OnPanic>>>,
	on_housekeep: Option<Pin<Box<OnHousekeep>>>,
}

#[derive(Clone)]
pub struct EvhParams {
	wakeup: Vec<Wakeup>,
	cur_connections: Arc<RwLock<usize>>,
	guarded_data: Arc<Vec<Arc<RwLock<GuardedData>>>>,
	config: EventHandlerConfig,
}

impl EvhParams {
	pub fn add_handle(
		&self,
		handle: Handle,
		tls_config: Option<TLSClientConfig>,
		tid: Option<usize>,
	) -> Result<ConnectionData, Error> {
		if handle >= self.config.max_handle_numeric_value.try_into()? {
			return Err(ErrorKind::MaxHandlesExceeded(format!(
				//============
				"Max numeric handle exceeded. Limit = {}",
				self.config.max_handle_numeric_value,
			))
			.into());
		}

		let cur_connections = &self.cur_connections;
		let config = &self.config;
		let guarded_data = &self.guarded_data;
		let wakeup = &self.wakeup;

		let cap_exceeded = {
			let mut cur_connections = lockw!(cur_connections)?;
			let ret = *cur_connections >= config.max_rwhandles;
			if !ret {
				*cur_connections += 1;
			}
			ret
		};

		if cap_exceeded {
			//============
			return Err(ErrorKind::MaxHandlesExceeded(format!(
				"Max Handles exceeded. Limit = {}",
				config.max_rwhandles,
			))
			.into());
		}

		let connection_info = match tls_config {
			Some(tls_config) => {
				let server_name: &str = &tls_config.server_name;
				let config = make_config(tls_config.trusted_cert_full_chain_file)?;
				let tls_client = Some(Arc::new(RwLock::new(ClientConnection::new(
					config,
					server_name.try_into()?,
				)?)));
				EventConnectionInfo::read_write_connection(handle, None, None, tls_client)
			}
			None => EventConnectionInfo::read_write_connection(handle, None, None, None),
		};

		// pick a random queue or the one specified
		let tid = match tid {
			Some(tid) => tid,
			None => {
				let rand: usize = rand::random();
				rand % config.threads
			}
		};
		let guarded_data: Arc<RwLock<GuardedData>> = guarded_data[tid].clone();
		let wakeup: Wakeup = wakeup[tid].clone();

		{
			let mut guarded_data = lockw!(guarded_data)?;
			guarded_data.nhandles.push(connection_info.clone());
		}

		wakeup.wakeup()?;

		Ok(ConnectionData::new(
			connection_info.as_read_write_connection()?,
			&guarded_data,
			&wakeup,
			tid,
			config.debug_pending,
		))
	}

	pub fn stop(&self) -> Result<(), Error> {
		for i in 0..self.guarded_data.len() {
			let guarded_data = &self.guarded_data[i];
			{
				let mut guarded_data = lockw!(*guarded_data)?;
				(*guarded_data).stop = true;
			}
			self.wakeup[i].wakeup()?;
		}

		Ok(())
	}
}

#[cfg(test)]
mod tests {
	use crate::eventhandler::*;
	use nioruntime_deps::nix::sys::socket::{
		bind, listen, socket, AddressFamily, InetAddr, SockAddr, SockFlag, SockType,
	};
	use nioruntime_deps::portpicker;
	use nioruntime_err::Error;
	use nioruntime_util::lockr;
	use std::io::{Read, Write};
	use std::mem;
	use std::net::{SocketAddr, TcpListener, TcpStream};
	use std::os::unix::io::AsRawFd;
	use std::os::unix::prelude::FromRawFd;
	use std::str::FromStr;

	debug!();

	fn get_fd() -> Result<RawFd, Error> {
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

	#[test]
	fn test_eventhandler() -> Result<(), Error> {
		let port = 8000;
		let addr = loop {
			if portpicker::is_free_tcp(port) {
				break format!("127.0.0.1:{}", port);
			}
		};

		info!("Starting Eventhandler on {}", addr)?;
		let mut evh = EventHandler::new(EventHandlerConfig {
			max_handle_numeric_value: 500,
			threads: 3,
			..EventHandlerConfig::default()
		})?;

		let lock = Arc::new(RwLock::new(0));
		let lock_clone1 = lock.clone();
		let lock_clone2 = lock.clone();

		let std_sa = SocketAddr::from_str(&addr).unwrap();
		let inet_addr = InetAddr::from_std(&std_sa);
		let sock_addr = SockAddr::new_inet(inet_addr);

		let mut handles = vec![];
		let mut listeners = vec![];
		for _ in 0..3 {
			let fd = get_fd()?;
			bind(fd, &sock_addr)?;
			listen(fd, 10)?;

			let listener = unsafe { TcpListener::from_raw_fd(fd) };
			listener.set_nonblocking(true)?;
			handles.push(listener.as_raw_fd());
			listeners.push(listener);
		}

		let cid_accept = Arc::new(RwLock::new(0));
		let cid_accept_clone = cid_accept.clone();
		let cid_read = Arc::new(RwLock::new(0));
		let cid_read_clone = cid_read.clone();

		evh.set_on_accept(move |conn_data, _, _| {
			{
				let mut cid = cid_accept.write().unwrap();
				*cid = conn_data.get_connection_id();
			}
			{
				let mut lock = lock_clone1.write().unwrap();
				*lock += 1;
			}
			Ok(())
		})?;
		evh.set_on_close(move |_conn_data, _, _| Ok(()))?;
		evh.set_on_panic(move || Ok(()))?;

		evh.set_on_read(move |conn_data, buf, _, _| {
			assert_eq!(buf, [1, 2, 3, 4]);
			{
				let mut cid_read = cid_read.write().unwrap();
				*cid_read = conn_data.get_connection_id();
			}
			{
				let mut lock = lock_clone2.write().unwrap();
				*lock += 1;
			}

			conn_data.write(&[5, 6, 7, 8, 9])?;
			Ok(())
		})?;

		evh.set_on_housekeep(move |_, _| Ok(()))?;
		evh.start()?;
		evh.add_listener_handles(handles, None)?;
		let mut stream = TcpStream::connect(addr)?;
		stream.write(&[1, 2, 3, 4])?;
		loop {
			{
				let lock = lock.write().unwrap();
				if *lock > 1 {
					break;
				}
			}
			std::thread::sleep(std::time::Duration::from_millis(1));
		}
		let mut buf = [0u8; 10];
		let len = stream.read(&mut buf)?;
		assert_eq!(&buf[0..len], &[5, 6, 7, 8, 9]);

		{
			let lock = lock.read().unwrap();
			assert_eq!(*lock, 2);
		}

		{
			let cid_accept = cid_accept_clone.read().unwrap();
			let cid_read = cid_read_clone.read().unwrap();
			assert_eq!(*cid_read, *cid_accept);
			assert!(*cid_read != 0);
		}

		Ok(())
	}

	#[test]
	fn test_pending() -> Result<(), Error> {
		let port = 8090;
		let addr = loop {
			if portpicker::is_free_tcp(port) {
				break format!("127.0.0.1:{}", port);
			}
		};

		info!("Starting Eventhandler on {}", addr)?;
		let mut evh = EventHandler::new(EventHandlerConfig {
			max_handle_numeric_value: 500,
			threads: 3,
			debug_pending: true,
			..EventHandlerConfig::default()
		})?;

		let lock = Arc::new(RwLock::new(0));
		let lock_clone1 = lock.clone();
		let lock_clone2 = lock.clone();

		let std_sa = SocketAddr::from_str(&addr).unwrap();
		let inet_addr = InetAddr::from_std(&std_sa);
		let sock_addr = SockAddr::new_inet(inet_addr);

		let mut handles = vec![];
		let mut listeners = vec![];
		for _ in 0..3 {
			let fd = get_fd()?;
			bind(fd, &sock_addr)?;
			listen(fd, 10)?;

			let listener = unsafe { TcpListener::from_raw_fd(fd) };
			listener.set_nonblocking(true)?;
			handles.push(listener.as_raw_fd());
			listeners.push(listener);
		}

		let cid_accept = Arc::new(RwLock::new(0));
		let cid_accept_clone = cid_accept.clone();
		let cid_read = Arc::new(RwLock::new(0));
		let cid_read_clone = cid_read.clone();

		evh.set_on_accept(move |conn_data, _, _| {
			{
				let mut cid = cid_accept.write().unwrap();
				*cid = conn_data.get_connection_id();
			}
			{
				let mut lock = lock_clone1.write().unwrap();
				*lock += 1;
			}
			Ok(())
		})?;
		evh.set_on_close(move |_conn_data, _, _| Ok(()))?;
		evh.set_on_panic(move || Ok(()))?;

		evh.set_on_read(move |conn_data, buf, _, _| {
			assert_eq!(buf, [1, 2, 3, 4]);
			{
				let mut cid_read = cid_read.write().unwrap();
				*cid_read = conn_data.get_connection_id();
			}
			{
				let mut lock = lock_clone2.write().unwrap();
				*lock += 1;
			}

			conn_data.write(&[5, 6, 7, 8, 9])?;
			Ok(())
		})?;

		evh.set_on_housekeep(move |_, _| Ok(()))?;
		evh.start()?;
		evh.add_listener_handles(handles, None)?;
		let mut stream = TcpStream::connect(addr)?;
		stream.write(&[1, 2, 3, 4])?;
		loop {
			{
				let lock = lock.write().unwrap();
				if *lock > 1 {
					break;
				}
			}
			std::thread::sleep(std::time::Duration::from_millis(1));
		}
		let mut buf = [0u8; 10];
		let len = stream.read(&mut buf)?;
		assert_eq!(&buf[0..len], &[5, 6, 7, 8, 9]);

		{
			let lock = lock.read().unwrap();
			assert_eq!(*lock, 2);
		}

		{
			let cid_accept = cid_accept_clone.read().unwrap();
			let cid_read = cid_read_clone.read().unwrap();
			assert_eq!(*cid_read, *cid_accept);
			assert!(*cid_read != 0);
		}

		Ok(())
	}

	#[test]
	fn test_step() -> Result<(), Error> {
		let port = 8107;
		let addr = loop {
			if portpicker::is_free_tcp(port) {
				break format!("127.0.0.1:{}", port);
			}
		};

		info!("Starting Eventhandler on {}", addr)?;
		let mut evh = EventHandler::new(EventHandlerConfig {
			max_handle_numeric_value: 500,
			threads: 1,
			step_size: 3,
			..EventHandlerConfig::default()
		})?;

		let std_sa = SocketAddr::from_str(&addr).unwrap();
		let inet_addr = InetAddr::from_std(&std_sa);
		let sock_addr = SockAddr::new_inet(inet_addr);

		let mut handles = vec![];
		let mut listeners = vec![];
		for _ in 0..1 {
			let fd = get_fd()?;
			bind(fd, &sock_addr)?;
			listen(fd, 10)?;

			let listener = unsafe { TcpListener::from_raw_fd(fd) };
			listener.set_nonblocking(true)?;
			handles.push(listener.as_raw_fd());
			listeners.push(listener);
		}

		evh.set_on_accept(move |_conn_data, _, _| Ok(()))?;
		evh.set_on_close(move |_conn_data, _, _| Ok(()))?;
		evh.set_on_panic(move || Ok(()))?;

		let c = Arc::new(RwLock::new(0));
		let cc = c.clone();

		evh.set_on_read(move |conn_data, buf, _, _| {
			info!("callback on {:?} with buf={:?}", conn_data, buf)?;
			assert_eq!(buf, &[0, 1, 2, 3]);
			let mut c = lockw!(c)?;
			*c += 1;
			Ok(())
		})?;

		evh.set_on_housekeep(move |_, _| Ok(()))?;

		evh.start()?;
		evh.add_listener_handles(handles, None)?;

		for _ in 0..5 {
			let mut stream = TcpStream::connect(addr.clone())?;
			stream.set_nonblocking(true)?;
			stream.write(&[0, 1, 2, 3])?;
		}

		loop {
			std::thread::sleep(std::time::Duration::from_millis(1));
			let c = lockr!(cc)?;
			if *c == 5 {
				break;
			}
			assert!(*c < 5);
		}

		Ok(())
	}

	#[test]
	fn test_client() -> Result<(), Error> {
		let port = 8100;
		let addr = loop {
			if portpicker::is_free_tcp(port) {
				break format!("127.0.0.1:{}", port);
			}
		};

		info!("Starting Eventhandler on {}", addr)?;
		let mut evh = EventHandler::new(EventHandlerConfig {
			max_handle_numeric_value: 500,
			threads: 3,
			..EventHandlerConfig::default()
		})?;

		let std_sa = SocketAddr::from_str(&addr).unwrap();
		let inet_addr = InetAddr::from_std(&std_sa);
		let sock_addr = SockAddr::new_inet(inet_addr);

		let mut handles = vec![];
		let mut listeners = vec![];
		for _ in 0..3 {
			let fd = get_fd()?;
			bind(fd, &sock_addr)?;
			listen(fd, 10)?;

			let listener = unsafe { TcpListener::from_raw_fd(fd) };
			listener.set_nonblocking(true)?;
			handles.push(listener.as_raw_fd());
			listeners.push(listener);
		}

		evh.set_on_accept(move |_conn_data, _, _| Ok(()))?;
		evh.set_on_close(move |_conn_data, _, _| Ok(()))?;
		evh.set_on_panic(move || Ok(()))?;

		let stream = TcpStream::connect(addr)?;
		let handle = stream.as_raw_fd();
		let client_id = Arc::new(RwLock::new(0));
		let client_id_clone = client_id.clone();

		let client_on_read_count = Arc::new(RwLock::new(0));
		let server_on_read_count = Arc::new(RwLock::new(0));
		let client_on_read_count_clone = client_on_read_count.clone();
		let server_on_read_count_clone = server_on_read_count.clone();

		evh.set_on_read(move |conn_data, buf, _, _| {
			info!("callback on {:?} with buf={:?}", conn_data, buf)?;
			if conn_data.get_connection_id() == *lockr!(client_id_clone)? {
				assert_eq!(buf, [5, 6, 7, 8, 9]);
				*(lockw!(client_on_read_count)?) += 1;
			} else {
				if buf.len() <= 5 {
					assert_eq!(buf, [1, 2, 3, 4]);
					conn_data.write(&[5, 6, 7, 8, 9])?;
					*(lockw!(server_on_read_count)?) += 1;
				}
			}
			Ok(())
		})?;

		evh.set_on_housekeep(move |_, _| Ok(()))?;

		evh.start()?;
		evh.add_listener_handles(handles, None)?;
		let conn_info = evh.add_handle(handle, None)?;
		{
			let mut client_id = lockw!(client_id)?;
			*client_id = conn_info.get_connection_id();
		}
		conn_info.write(&[1, 2, 3, 4])?;
		loop {
			std::thread::sleep(std::time::Duration::from_millis(1));
			if *(lockr!(client_on_read_count_clone)?) != 0 {
				break;
			}
		}

		assert_eq!(*(lockr!(server_on_read_count_clone)?), 1);
		assert_eq!(*(lockr!(client_on_read_count_clone)?), 1);

		Ok(())
	}

	#[test]
	fn test_ssl() -> Result<(), Error> {
		let port = 8200;
		let addr = loop {
			if portpicker::is_free_tcp(port) {
				break format!("127.0.0.1:{}", port);
			}
		};

		info!("Starting Eventhandler on {}", addr)?;
		let mut evh = EventHandler::new(EventHandlerConfig {
			max_handle_numeric_value: 500,
			threads: 3,
			..EventHandlerConfig::default()
		})?;

		let std_sa = SocketAddr::from_str(&addr).unwrap();
		let inet_addr = InetAddr::from_std(&std_sa);
		let sock_addr = SockAddr::new_inet(inet_addr);

		let mut handles = vec![];
		let mut listeners = vec![];
		for _ in 0..3 {
			let fd = get_fd()?;
			bind(fd, &sock_addr)?;
			listen(fd, 10)?;

			let listener = unsafe { TcpListener::from_raw_fd(fd) };
			listener.set_nonblocking(true)?;
			handles.push(listener.as_raw_fd());
			listeners.push(listener);
		}

		evh.set_on_accept(move |conn_data, _, _| {
			trace!("on accept for {}", conn_data.get_handle())?;
			Ok(())
		})?;
		evh.set_on_close(move |conn_data, _, _| {
			trace!("on close conn={}", conn_data.get_handle())?;
			Ok(())
		})?;
		evh.set_on_panic(move || Ok(()))?;

		let stream = TcpStream::connect(addr)?;
		stream.set_nonblocking(true)?;
		let handle = stream.as_raw_fd();
		let client_id = Arc::new(RwLock::new(0));
		let client_id_clone = client_id.clone();

		let write_50k = Arc::new(RwLock::new(false));
		let client_on_read_count = Arc::new(RwLock::new(0));
		let server_on_read_count = Arc::new(RwLock::new(0));
		let client_on_read_count_clone = client_on_read_count.clone();
		let server_on_read_count_clone = server_on_read_count.clone();
		let len_sum = Arc::new(RwLock::new(0));
		let len_sum_clone = len_sum.clone();

		evh.set_on_housekeep(move |_, _| Ok(()))?;
		evh.set_on_read(move |conn_data, buf, _, _| {
			trace!(
				"callback on {} with buf={:?}",
				conn_data.connection_info.handle,
				buf
			)?;
			warn!("onreadbuf.len={}", buf.len())?;
			{
				let mut len_sum = lockw!(len_sum_clone)?;
				*len_sum += buf.len();
			}
			if buf.len() > 5 {
				assert_eq!(buf[0], 0);

				{
					let mut write_50k = lockw!(write_50k)?;
					if *write_50k == false {
						let mut nbuf = vec![];
						for _ in 0..50_000 {
							nbuf.push(0);
						}
						warn!("write 50k")?;
						conn_data.write(&nbuf)?;
					}
					*write_50k = true;
				}
			} else if conn_data.get_connection_id() == *lockr!(client_id_clone)? {
				assert_eq!(buf, [5, 6, 7, 8, 9]);
				*(lockw!(client_on_read_count)?) += 1;
			} else {
				assert_eq!(buf, [1, 2, 3, 4]);
				conn_data.write(&[5, 6, 7, 8, 9])?;
				*(lockw!(server_on_read_count)?) += 1;
			}
			Ok(())
		})?;
		evh.start()?;

		// test bad private key
		assert!(evh
			.add_listener_handles(
				handles.clone(),
				Some(TLSServerConfig {
					certificates_file: "./src/resources/cert.pem".to_string(),
					private_key_file: "./src/resources/badkey.pem".to_string(),
					sni_host: "localhost".to_string(),
				}),
			)
			.is_err());

		evh.add_listener_handles(
			handles,
			Some(TLSServerConfig {
				certificates_file: "./src/resources/cert.pem".to_string(),
				private_key_file: "./src/resources/key.pem".to_string(),
				sni_host: "localhost".to_string(),
			}),
		)?;

		let conn_info = evh.add_handle(
			handle,
			Some(TLSClientConfig {
				server_name: "localhost".to_string(),
				trusted_cert_full_chain_file: Some("./src/resources/cert.pem".to_string()),
			}),
		)?;

		{
			let mut client_id = lockw!(client_id)?;
			*client_id = conn_info.get_connection_id();
		}

		conn_info.write(&[1, 2, 3, 4])?;
		loop {
			std::thread::sleep(std::time::Duration::from_millis(1));
			if *(lockr!(client_on_read_count_clone)?) != 0 {
				break;
			}
		}

		assert_eq!(*(lockr!(server_on_read_count_clone)?), 1);
		assert_eq!(*(lockr!(client_on_read_count_clone)?), 1);

		// write a large chunk
		let mut buf = vec![];
		for _ in 0..20_000 {
			buf.push(0);
		}
		conn_info.write(&buf)?;
		conn_info.write(&buf)?;

		loop {
			std::thread::sleep(std::time::Duration::from_millis(1));
			{
				let len_sum = lockr!(len_sum)?;
				warn!("len_sum = {}", *len_sum)?;
				if *len_sum == 90_009 {
					break;
				}
				assert!(*len_sum < 90_009);
			}
		}

		Ok(())
	}

	#[test]
	fn test_big_msg() -> Result<(), Error> {
		let port = 8300;
		let addr = loop {
			if portpicker::is_free_tcp(port) {
				break format!("127.0.0.1:{}", port);
			}
		};

		info!("Starting Eventhandler on {}", addr)?;
		let mut evh = EventHandler::new(EventHandlerConfig {
			max_handle_numeric_value: 500,
			threads: 3,
			..EventHandlerConfig::default()
		})?;

		let std_sa = SocketAddr::from_str(&addr).unwrap();
		let inet_addr = InetAddr::from_std(&std_sa);
		let sock_addr = SockAddr::new_inet(inet_addr);

		let mut handles = vec![];
		let mut listeners = vec![];
		for _ in 0..3 {
			let fd = get_fd()?;
			bind(fd, &sock_addr)?;
			listen(fd, 10)?;

			let listener = unsafe { TcpListener::from_raw_fd(fd) };
			listener.set_nonblocking(true)?;
			handles.push(listener.as_raw_fd());
			listeners.push(listener);
		}

		evh.set_on_accept(move |_, _, _| Ok(()))?;
		evh.set_on_close(move |_, _, _| Ok(()))?;
		evh.set_on_panic(move || Ok(()))?;

		let stream = TcpStream::connect(addr)?;
		stream.set_nonblocking(true)?;
		let handle = stream.as_raw_fd();
		let client_id = Arc::new(RwLock::new(0));
		let client_id_clone = client_id.clone();

		let client_on_read_count = Arc::new(RwLock::new(0));
		let server_on_read_count = Arc::new(RwLock::new(0));
		let client_on_read_count_clone = client_on_read_count.clone();
		let server_on_read_count_clone = server_on_read_count.clone();

		let mut msg = vec![];
		for i in 0..100_000_000 {
			if i % 20_000_000 == 0 {
				debug!("i = {}", i)?;
			}
			msg.push((i % 256) as u8);
		}
		let msg_clone = msg.clone();

		let cbuf: Vec<u8> = vec![];
		let sbuf: Vec<u8> = vec![];
		let client_buffer = Arc::new(RwLock::new(cbuf));
		let server_buffer = Arc::new(RwLock::new(sbuf));

		evh.set_on_housekeep(move |_, _| Ok(()))?;
		evh.set_on_read(move |conn_data, buf, _, _| {
			let msg = &msg_clone;

			if conn_data.get_connection_id() == *lockr!(client_id_clone)? {
				let mut client_buffer = lockw!(client_buffer)?;
				(*client_buffer).append(&mut buf.to_vec());
				if (*client_buffer).len() == msg.len() {
					assert_eq!((*client_buffer), *msg);
					info!("assertion on client successful, len = {}", (*msg).len())?;
					*(lockw!(client_on_read_count)?) += 1;
				}
			} else {
				let mut server_buffer = lockw!(server_buffer)?;
				(*server_buffer).append(&mut buf.to_vec());
				if (*server_buffer).len() == msg.len() {
					assert_eq!((*server_buffer), *msg);
					info!("assertion on server successful, len = {}", (*msg).len())?;
					conn_data.write(&msg)?;
					*(lockw!(server_on_read_count)?) += 1;
				}
			}
			Ok(())
		})?;
		evh.start()?;
		evh.add_listener_handles(handles, None)?;
		let conn_info = evh.add_handle(handle, None)?;

		info!("clientid={}", conn_info.get_connection_id())?;
		{
			let mut client_id = lockw!(client_id)?;
			*client_id = conn_info.get_connection_id();
		}

		conn_info.write(&msg[..])?;
		loop {
			std::thread::sleep(std::time::Duration::from_millis(1));
			if *(lockr!(client_on_read_count_clone)?) != 0 {
				break;
			}
		}

		assert_eq!(*(lockr!(server_on_read_count_clone)?), 1);
		assert_eq!(*(lockr!(client_on_read_count_clone)?), 1);
		Ok(())
	}

	#[test]
	fn test_stop() -> Result<(), Error> {
		let port = 8400;
		let addr = loop {
			if portpicker::is_free_tcp(port) {
				break format!("127.0.0.1:{}", port);
			}
		};

		info!("Starting Eventhandler on {}", addr)?;
		let mut evh = EventHandler::new(EventHandlerConfig {
			max_handle_numeric_value: 500,
			threads: 3,
			..EventHandlerConfig::default()
		})?;

		let std_sa = SocketAddr::from_str(&addr).unwrap();
		let inet_addr = InetAddr::from_std(&std_sa);
		let sock_addr = SockAddr::new_inet(inet_addr);

		let mut handles = vec![];
		let mut listeners = vec![];
		for _ in 0..3 {
			let fd = get_fd()?;
			bind(fd, &sock_addr)?;
			listen(fd, 10)?;

			let listener = unsafe { TcpListener::from_raw_fd(fd) };
			listener.set_nonblocking(true)?;
			handles.push(listener.as_raw_fd());
			listeners.push(listener);
		}

		evh.set_on_accept(move |_conn_data, _, _| Ok(()))?;
		evh.set_on_close(move |_conn_data, _, _| Ok(()))?;
		evh.set_on_panic(move || Ok(()))?;
		evh.set_on_read(move |_conn_data, _buf, _, _| Ok(()))?;
		evh.set_on_housekeep(move |_, _| Ok(()))?;
		evh.start()?;

		evh.stop()?;

		loop {
			std::thread::sleep(std::time::Duration::from_millis(1));
			{
				let stopped = lockw!(evh.stopped)?;
				if *stopped {
					break;
				}
			}
		}

		{
			let stopped = lockw!(evh.stopped)?;
			assert!(*stopped);
		}

		Ok(())
	}

	#[test]
	fn test_max_rwhandles() -> Result<(), Error> {
		let port = 8500;
		let addr = loop {
			if portpicker::is_free_tcp(port) {
				break format!("127.0.0.1:{}", port);
			}
		};

		info!("Starting Eventhandler on {}", addr)?;
		let mut evh = EventHandler::new(EventHandlerConfig {
			max_handle_numeric_value: 500,
			threads: 3,
			max_rwhandles: 2,
			..EventHandlerConfig::default()
		})?;

		let std_sa = SocketAddr::from_str(&addr).unwrap();
		let inet_addr = InetAddr::from_std(&std_sa);
		let sock_addr = SockAddr::new_inet(inet_addr);

		let mut handles = vec![];
		let mut listeners = vec![];
		for _ in 0..3 {
			let fd = get_fd()?;
			bind(fd, &sock_addr)?;
			listen(fd, 10)?;

			let listener = unsafe { TcpListener::from_raw_fd(fd) };
			listener.set_nonblocking(true)?;
			handles.push(listener.as_raw_fd());
			listeners.push(listener);
		}

		evh.set_on_accept(move |_conn_data, _, _| Ok(()))?;
		evh.set_on_close(move |_conn_data, _, _| Ok(()))?;
		evh.set_on_panic(move || Ok(()))?;

		let resp_len = Arc::new(RwLock::new(0));
		let resp_len_clone = resp_len.clone();

		evh.set_on_housekeep(move |_, _| Ok(()))?;
		evh.set_on_read(move |_conn_data, buf, _, _| {
			let mut resp_len = lockw!(resp_len_clone)?;
			*resp_len += buf.len();

			Ok(())
		})?;
		evh.start()?;

		handles.push(1);
		assert!(evh.add_listener_handles(handles.clone(), None).is_err());
		handles.pop();
		evh.add_listener_handles(handles.clone(), None)?;
		handles.pop();
		// test too high numeric value
		handles.push(1000);
		assert!(evh.add_listener_handles(handles.clone(), None).is_err());

		let mut stream1 = TcpStream::connect(addr.clone())?;
		let mut stream2 = TcpStream::connect(addr.clone())?;
		let mut stream3 = TcpStream::connect(addr)?;
		stream1.write(&[5, 6, 7, 8, 9])?;
		stream2.write(&[5, 6, 7, 8, 9])?;
		stream3.write(&[5, 6, 7, 8, 9])?;

		loop {
			std::thread::sleep(std::time::Duration::from_millis(10));
			let resp_len = lockr!(resp_len)?;
			if *resp_len < 10 {
				continue;
			}
			assert_eq!(*resp_len, 10);
			break;
		}

		Ok(())
	}

	#[test]
	fn test_wakeup() -> Result<(), Error> {
		let check = Arc::new(RwLock::new(false));
		let check_clone = check.clone();

		let wakeup = Wakeup::new()?;
		let wakeup_clone = wakeup.clone();

		std::thread::spawn(move || -> Result<(), Error> {
			let wakeup = wakeup_clone;
			{
				let _lock = wakeup.pre_block();
				let mut buf = [0u8; 1];
				do_read(wakeup.wakeup_handle_read, &mut buf)?;
			}
			wakeup.post_block()?;

			let mut check = lockw!(check_clone)?;
			*check = true;

			Ok(())
		});

		std::thread::sleep(std::time::Duration::from_millis(100));

		wakeup.wakeup()?;

		loop {
			std::thread::sleep(std::time::Duration::from_millis(1));
			let check = lockw!(check)?;
			if *check {
				break;
			}
		}

		Ok(())
	}

	fn check_config(evh_config: &EventHandlerConfig, valid: bool) -> Result<(), Error> {
		let evh = EventHandler::new(*evh_config);

		if !valid {
			assert!(evh.is_err());
		} else {
			assert!(evh.is_ok());
		}

		match evh {
			Ok(mut evh) => {
				assert!(evh.start().is_err());
				evh.set_on_read(move |_, _, _, _| Ok(()))?;
				assert!(evh.start().is_err());
				evh.set_on_accept(move |_, _, _| Ok(()))?;
				assert!(evh.start().is_err());
				evh.set_on_close(move |_, _, _| Ok(()))?;
				assert!(evh.start().is_err());
				evh.set_on_panic(move || Ok(()))?;
				assert!(evh.start().is_err());
				evh.set_on_housekeep(move |_, _| Ok(()))?;
				assert!(evh.start().is_ok());
			}
			Err(_) => {}
		}
		Ok(())
	}

	#[test]
	fn test_bad_config() -> Result<(), Error> {
		check_config(
			&EventHandlerConfig {
				read_buffer_size: 1_000,
				..EventHandlerConfig::default()
			},
			false,
		)?;

		check_config(
			&EventHandlerConfig {
				read_buffer_size: 10_000,
				debug_fatal: true,
				..EventHandlerConfig::default()
			},
			true,
		)?;

		// wait so threads can start to get fatal
		std::thread::sleep(std::time::Duration::from_millis(100));

		Ok(())
	}

	#[test]
	fn test_close() -> Result<(), Error> {
		let port = 8600;
		let addr = loop {
			if portpicker::is_free_tcp(port) {
				break format!("127.0.0.1:{}", port);
			}
		};

		info!("Starting Eventhandler on {}", addr)?;
		let mut evh = EventHandler::new(EventHandlerConfig {
			max_handle_numeric_value: 500,
			threads: 3,
			..EventHandlerConfig::default()
		})?;

		let std_sa = SocketAddr::from_str(&addr).unwrap();
		let inet_addr = InetAddr::from_std(&std_sa);
		let sock_addr = SockAddr::new_inet(inet_addr);

		let mut handles = vec![];
		let mut listeners = vec![];
		for _ in 0..3 {
			let fd = get_fd()?;
			bind(fd, &sock_addr)?;
			listen(fd, 10)?;

			let listener = unsafe { TcpListener::from_raw_fd(fd) };
			listener.set_nonblocking(true)?;
			handles.push(listener.as_raw_fd());
			listeners.push(listener);
		}

		let on_close_counter = Arc::new(RwLock::new(0));
		let on_read_counter = Arc::new(RwLock::new(0));
		let closing_success = Arc::new(RwLock::new(false));
		let on_close_counter_clone = on_close_counter.clone();
		let on_read_counter_clone = on_read_counter.clone();
		let closing_success_clone = closing_success.clone();

		evh.set_on_accept(move |_conn_data, _, _| Ok(()))?;
		evh.set_on_close(move |_conn_data, _, _| {
			{
				(*(lockw!(on_close_counter_clone)?)) += 1;
			}
			Ok(())
		})?;
		evh.set_on_panic(move || Ok(()))?;

		evh.set_on_housekeep(move |_, _| Ok(()))?;
		evh.set_on_read(move |conn_data, buf, _, _| {
			{
				(*(lockw!(on_read_counter_clone)?)) += 1;
			}
			if buf == &[1] {
				info!("closing conn {}", conn_data.get_connection_id())?;
				conn_data.close()?;

				// test some functions with close.
				std::thread::sleep(std::time::Duration::from_millis(50));
				assert!(conn_data.close().is_err());
				assert!(conn_data.async_complete().is_err());
				assert!(conn_data.write(&[0]).is_err());
				(*(lockw!(closing_success_clone)?)) = true;
			}
			Ok(())
		})?;
		evh.start()?;
		evh.add_listener_handles(handles, None)?;

		let mut stream1 = TcpStream::connect(addr.clone())?;
		let mut stream2 = TcpStream::connect(addr.clone())?;
		let mut stream3 = TcpStream::connect(addr)?;

		stream1.write(&[1])?;
		stream2.write(&[5, 6, 7, 8, 9])?;
		stream3.write(&[5, 6, 7, 8, 9])?;

		loop {
			std::thread::sleep(std::time::Duration::from_millis(1));

			if *(lockr!(on_read_counter)?) < 3 || *(lockr!(on_close_counter)?) < 1 {
				continue;
			}
			assert_eq!(*(lockr!(on_close_counter)?), 1);
			assert_eq!(*(lockr!(on_read_counter)?), 3);
			break;
		}

		stream1.write(&[0])?;
		stream2.write(&[5, 6, 7, 8, 9])?;
		stream3.write(&[5, 6, 7, 8, 9])?;

		std::thread::sleep(std::time::Duration::from_millis(100));

		assert_eq!(*(lockr!(on_close_counter)?), 1);
		assert_eq!(*(lockr!(on_read_counter)?), 5);
		assert_eq!(*(lockr!(closing_success)?), true);

		Ok(())
	}

	#[test]
	fn test_panic() -> Result<(), Error> {
		do_test_panic(true)?;
		do_test_panic(false)?;
		Ok(())
	}

	fn do_test_panic(do_err: bool) -> Result<(), Error> {
		let port = 8700;
		let addr = loop {
			if portpicker::is_free_tcp(port) {
				break format!("127.0.0.1:{}", port);
			}
		};

		info!("Starting Eventhandler on {}", addr)?;
		let mut evh = EventHandler::new(EventHandlerConfig {
			threads: 1,
			max_handle_numeric_value: 500,
			..EventHandlerConfig::default()
		})?;

		let std_sa = SocketAddr::from_str(&addr).unwrap();
		let inet_addr = InetAddr::from_std(&std_sa);
		let sock_addr = SockAddr::new_inet(inet_addr);

		let mut handles = vec![];
		let mut listeners = vec![];

		let fd = get_fd()?;
		bind(fd, &sock_addr)?;
		listen(fd, 10)?;

		let listener = unsafe { TcpListener::from_raw_fd(fd) };
		listener.set_nonblocking(true)?;
		handles.push(listener.as_raw_fd());
		listeners.push(listener);

		evh.set_on_accept(move |_conn_data, _, _| Ok(()))?;
		evh.set_on_close(move |_conn_data, _, _| Ok(()))?;

		let on_panic_counter = Arc::new(RwLock::new(0));
		let on_panic_counter_clone = on_panic_counter.clone();

		evh.set_on_panic(move || {
			let mut on_panic_counter = lockw!(on_panic_counter_clone)?;
			*on_panic_counter += 1;
			if do_err {
				Err(ErrorKind::InternalError("".to_string()).into())
			} else {
				Ok(())
			}
		})?;

		evh.set_on_housekeep(move |_, _| Ok(()))?;

		let counter = Arc::new(RwLock::new(0));
		let complete_count = Arc::new(RwLock::new(0));
		let complete_count_clone = complete_count.clone();
		let panic_count = Arc::new(RwLock::new(0));
		let panic_count_clone = panic_count.clone();
		let in_wait_mode = Arc::new(RwLock::new(false));
		let in_wait_mode_clone = in_wait_mode.clone();

		let error_counter = Arc::new(RwLock::new(0));
		let error_complete_count = Arc::new(RwLock::new(0));
		let error_complete_count_clone = error_complete_count.clone();

		evh.set_on_read(move |mut conn_data, buf, _, _| {
			assert!(conn_data.get_accept_handle().is_some());
			assert!(conn_data.get_buffer().len() == 0);
			match buf[0] {
				// sleep to wait for other requests to queue up
				0 => {
					{
						let mut in_wait_mode = lockw!(in_wait_mode_clone)?;
						*in_wait_mode = true;
					}
					std::thread::sleep(std::time::Duration::from_millis(100));
				}
				// respond normally
				1 | 2 | 3 => {
					let mut counter = lockwp!(counter);
					*counter += 1;
					if *counter == 2 {
						{
							let mut panic_count = lockw!(panic_count_clone)?;
							*panic_count += 1;
						}
						let a: Option<usize> = None;
						a.unwrap();
					} else {
						let mut complete_count = lockw!(complete_count_clone)?;
						*complete_count += 1;
					}
				}
				4 | 5 | 6 => {
					let mut error_counter = lockwp!(error_counter);
					*error_counter += 1;
					if *error_counter == 2 {
						return Err(ErrorKind::ApplicationError("anything".to_string()).into());
					} else {
						let mut error_complete_count = lockw!(error_complete_count_clone)?;
						*error_complete_count += 1;
					}
				}
				_ => {}
			}

			Ok(())
		})?;
		evh.start()?;
		evh.add_listener_handles(handles, None)?;
		let mut stream1 = TcpStream::connect(addr.clone())?;
		let mut stream2 = TcpStream::connect(addr.clone())?;
		let mut stream3 = TcpStream::connect(addr.clone())?;
		let mut stream4 = TcpStream::connect(addr)?;

		stream1.write(&[0])?;
		loop {
			std::thread::sleep(std::time::Duration::from_millis(1));
			if *(lockw!(in_wait_mode)?) {
				break;
			}
		}
		stream2.write(&[1])?;
		stream3.write(&[2])?;
		stream4.write(&[3])?;

		loop {
			std::thread::sleep(std::time::Duration::from_millis(1));
			{
				let complete_count = lockw!(complete_count)?;
				if *complete_count < 2 {
					continue;
				}
				assert_eq!(*complete_count, 2);
			}

			{
				let panic_count = lockw!(panic_count)?;
				assert_eq!(*panic_count, 1);
			}
			break;
		}
		loop {
			std::thread::sleep(std::time::Duration::from_millis(1));
			let on_panic_counter = lockr!(on_panic_counter)?;
			if *on_panic_counter == 0 {
				continue;
			}

			assert_eq!(*on_panic_counter, 1);
			break;
		}
		{
			(*(lockw!(in_wait_mode)?)) = false;
		}

		stream4.write(&[0])?;
		loop {
			std::thread::sleep(std::time::Duration::from_millis(1));
			if *(lockw!(in_wait_mode)?) {
				break;
			}
		}

		stream1.write(&[4])?;
		stream2.write(&[5])?;
		stream3.write(&[6])?;
		loop {
			std::thread::sleep(std::time::Duration::from_millis(1));
			{
				let error_complete_count = lockw!(error_complete_count)?;
				if *error_complete_count < 2 {
					continue;
				}
				assert_eq!(*error_complete_count, 2);
			}

			{
				let panic_count = lockw!(panic_count)?;
				assert_eq!(*panic_count, 1);
			}
			break;
		}

		Ok(())
	}
}
