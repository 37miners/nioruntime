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
// limitations under the License

//! An event handler library.

use errno::{errno, set_errno, Errno};
use libc::{accept, c_int, c_void, fcntl, pipe, read, timespec, write};
use nioruntime_err::{Error, ErrorKind};
use nioruntime_log::*;
use nioruntime_util::{lockr, lockw};
use std::collections::HashMap;
use std::convert::TryInto;
use std::os::unix::prelude::RawFd;
use std::pin::Pin;
use std::sync::{Arc, RwLock};
use std::time::Duration;

use kqueue_sys::{kevent, kqueue, EventFilter, EventFlag, FilterFlag};

fatal!();

const MAX_EVENTS: i32 = 100;
const READ_BUFFER_SIZE: usize = 1024 * 10;

type SelectorHandle = i32;
type Handle = RawFd;

#[derive(Debug)]
pub struct ConnectionData {
	connection_info: ReadWriteConnection,
	guarded_data: Arc<RwLock<GuardedData>>,
	wakeup: Wakeup,
}

impl ConnectionData {
	fn new(
		connection_info: ReadWriteConnection,
		guarded_data: Arc<RwLock<GuardedData>>,
		wakeup: Wakeup,
	) -> Self {
		Self {
			connection_info,
			guarded_data,
			wakeup,
		}
	}

	pub fn get_connection_id(&self) -> u128 {
		self.connection_info.get_connection_id()
	}

	pub fn write(&self, data: &[u8]) -> Result<(), Error> {
		let len = data.len();
		if len == 0 {
			// nothing to write
			return Ok(());
		}

		let wb = WriteBuffer::new(self.get_connection_id(), data.to_vec(), false);

		{
			let mut guarded_data = lockw!(self.guarded_data)?;
			guarded_data.write_queue.push(wb);
		}

		self.wakeup.wakeup()?;

		Ok(())
	}

	pub fn close(&self) -> Result<(), Error> {
		let wb = WriteBuffer::new(self.get_connection_id(), vec![], true);

		{
			let mut guarded_data = lockw!(self.guarded_data)?;
			guarded_data.write_queue.push(wb);
		}

		self.wakeup.wakeup()?;

		Ok(())
	}
}

#[derive(Clone)]
pub struct EventHandlerConfig {
	pub threads: usize,
}

impl Default for EventHandlerConfig {
	fn default() -> Self {
		Self { threads: 6 }
	}
}

pub struct EventHandler<OnRead, OnAccept, OnClose, OnPanic> {
	config: EventHandlerConfig,
	guarded_data: Arc<Vec<Arc<RwLock<GuardedData>>>>,
	wakeup: Vec<Wakeup>,
	callbacks: Callbacks<OnRead, OnAccept, OnClose, OnPanic>,
}

impl<OnRead, OnAccept, OnClose, OnPanic> EventHandler<OnRead, OnAccept, OnClose, OnPanic>
where
	OnRead: Fn(&ConnectionData, &[u8]) -> Result<(), Error> + Send + 'static + Clone + Sync + Unpin,
	OnAccept: Fn(&ConnectionData) -> Result<(), Error> + Send + 'static + Clone + Sync + Unpin,
	OnClose: Fn(&ConnectionData) -> Result<(), Error> + Send + 'static + Clone + Sync + Unpin,
	OnPanic: Fn() -> Result<(), Error> + Send + 'static + Clone + Sync + Unpin,
{
	pub fn new(config: EventHandlerConfig) -> Result<Self, Error> {
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
			},
			guarded_data,
			wakeup,
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

	pub fn start(&self) -> Result<(), Error> {
		self.check_callbacks()?;
		self.do_start()
	}

	pub fn add_listener_handles(&self, handles: Vec<Handle>) -> Result<(), Error> {
		self.check_callbacks()?;

		if handles.len() != self.config.threads.try_into()? {
			return Err(ErrorKind::EventHandlerConfigurationError(format!(
				"must add exactly the number of handles as threads. {} != {}",
				handles.len(),
				self.config.threads,
			))
			.into());
		}

		let connection_info = EventConnectionInfo::listener_connection(handles);

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

	pub fn add_handle(&self, handle: Handle) -> Result<(), Error> {
		self.check_callbacks()?;
		let connection_info = EventConnectionInfo::read_write_connection(handle);

		// pick a random queue
		let rand: usize = rand::random();
		let guarded_data: Arc<RwLock<GuardedData>> =
			self.guarded_data[rand % self.config.threads].clone();

		{
			let mut guarded_data = lockw!(guarded_data)?;
			guarded_data.nhandles.push(connection_info);
		}
		Ok(())
	}

	fn check_callbacks(&self) -> Result<(), Error> {
		if self.callbacks.on_read.is_none() {
			return Err(ErrorKind::EventHandlerConfigurationError(
				"set_on_read must be called before calling start".to_string(),
			)
			.into());
		}
		if self.callbacks.on_accept.is_none() {
			return Err(ErrorKind::EventHandlerConfigurationError(
				"set_on_accept must be called before calling start".to_string(),
			)
			.into());
		}
		if self.callbacks.on_close.is_none() {
			return Err(ErrorKind::EventHandlerConfigurationError(
				"set_on_close must be called before calling start".to_string(),
			)
			.into());
		}
		if self.callbacks.on_panic.is_none() {
			return Err(ErrorKind::EventHandlerConfigurationError(
				"set_on_panic must be called before calling start".to_string(),
			)
			.into());
		}

		Ok(())
	}

	fn do_start(&self) -> Result<(), Error> {
		for i in 0..self.config.threads {
			self.start_thread(self.guarded_data[i].clone(), self.wakeup[i].clone(), i)?;
		}
		Ok(())
	}

	fn start_thread(
		&self,
		guarded_data: Arc<RwLock<GuardedData>>,
		wakeup: Wakeup,
		tid: usize,
	) -> Result<(), Error> {
		let config = self.config.clone();
		let callbacks = self.callbacks.clone();
		let mut ctx: Context = Context::new(tid, guarded_data)?;
		std::thread::spawn(move || {
			debug!("starting thread {}", tid);
			let mut events = vec![];
			let mut connection_id_map = HashMap::new();
			let mut connection_handle_map = HashMap::new();

			let connection_info =
				EventConnectionInfo::read_write_connection(wakeup.wakeup_handle_read);
			let connection_id = connection_info.get_connection_id();
			let connection_info = Arc::new(RwLock::new(connection_info));
			connection_handle_map.insert(wakeup.wakeup_handle_read, connection_info.clone());
			connection_id_map.insert(connection_id, connection_info);
			ctx.input_events.push(Event {
				handle: wakeup.wakeup_handle_read,
				etype: EventType::Read,
			});

			loop {
				info!("thread loop {}", tid);
				match Self::thread_loop(
					&mut ctx,
					&config,
					&mut events,
					&wakeup,
					&callbacks,
					&mut connection_id_map,
					&mut connection_handle_map,
				) {
					Ok(_) => {}
					Err(e) => {
						fatal!("unexpected error in thread loop: {}", e);
						break;
					}
				}
			}
		});

		Ok(())
	}

	fn thread_loop(
		ctx: &mut Context,
		config: &EventHandlerConfig,
		events: &mut Vec<Event>,
		wakeup: &Wakeup,
		callbacks: &Callbacks<OnRead, OnAccept, OnClose, OnPanic>,
		connection_id_map: &mut HashMap<u128, Arc<RwLock<EventConnectionInfo>>>,
		connection_handle_map: &mut HashMap<Handle, Arc<RwLock<EventConnectionInfo>>>,
	) -> Result<(), Error> {
		Self::process_new(ctx, config, connection_id_map, connection_handle_map)?;
		Self::get_events(ctx, events)?;
		debug!("event count = {}", events.len());
		for event in events {
			match event.etype {
				EventType::Read => {
					let res = Self::process_read_event(
						event,
						ctx,
						config,
						callbacks,
						connection_id_map,
						connection_handle_map,
						wakeup,
					)?;
				}
				EventType::Write => Self::process_write_event(
					event,
					ctx,
					config,
					callbacks,
					connection_id_map,
					connection_handle_map,
				)?,
				EventType::Accept => {} // accepts are returned as read.
			}
		}
		Ok(())
	}

	fn process_read_event(
		event: &Event,
		ctx: &mut Context,
		_config: &EventHandlerConfig,
		callbacks: &Callbacks<OnRead, OnAccept, OnClose, OnPanic>,
		connection_id_map: &mut HashMap<u128, Arc<RwLock<EventConnectionInfo>>>,
		connection_handle_map: &mut HashMap<Handle, Arc<RwLock<EventConnectionInfo>>>,
		wakeup: &Wakeup,
	) -> Result<(), Error> {
		debug!("process read: {:?}", event);

		let x: Option<(u128, Handle)> = {
			let connection_info = match connection_handle_map.get(&event.handle) {
				Some(connection_info) => connection_info,
				None => {
					return Err(ErrorKind::HandleNotFoundError(format!(
						"Connection handle was not found for event: {:?}",
						event
					))
					.into())
				}
			};
			let connection_info = lockr!(connection_info)?;
			let _connection_id = (*connection_info).get_connection_id();
			let handle = (*connection_info).get_handle(ctx.tid);

			debug!("process conn_info: {:?}", connection_info);

			match &*connection_info {
				EventConnectionInfo::ListenerConnection(_c) => {
					loop {
						if !Self::process_accept(handle, ctx, wakeup, callbacks)? {
							break;
						}
					}
					None
				}
				EventConnectionInfo::ReadWriteConnection(c) => {
					info!("start loop");
					let mut len;
					loop {
						info!("pre");
						set_errno(Errno(0));
						len = Self::process_read(c.clone(), ctx, wakeup, callbacks)?;
						info!("len={}, c={:?}", len, c);
						if len <= 0 {
							break;
						}
					}

					if len <= 0 {
						let e = errno();
						if e.0 != libc::EAGAIN {
							// this is would block and not an error to close
							Some((
								connection_info.get_connection_id(),
								connection_info.get_handle(ctx.tid),
							))
						} else {
							info!(
								"it was an eagain for {}",
								connection_info.get_connection_id()
							);
							None
						}
					} else {
						None
					}
				}
			}
		};

		match x {
			Some((id, handle)) => {
				info!("rem {},{} from maps", id, handle);
				connection_id_map.remove(&id);
				connection_handle_map.remove(&handle);
				unsafe {
					libc::close(handle);
				}
			}
			None => {}
		}

		Ok(())
	}

	fn process_accept(
		handle: Handle,
		ctx: &mut Context,
		wakeup: &Wakeup,
		callbacks: &Callbacks<OnRead, OnAccept, OnClose, OnPanic>,
	) -> Result<bool, Error> {
		let handle = unsafe {
			accept(
				handle,
				&mut libc::sockaddr {
					..std::mem::zeroed()
				},
				&mut (std::mem::size_of::<libc::sockaddr>() as u32)
					.try_into()
					.unwrap_or(0),
			)
		};

		if handle > 0 {
			info!("Accepted handle = {} on tid={}", handle, ctx.tid);
			unsafe { fcntl(handle, libc::F_SETFL, libc::O_NONBLOCK) };

			let connection_info = EventConnectionInfo::read_write_connection(handle);

			match &callbacks.on_accept {
				Some(on_accept) => {
					match (on_accept)(&ConnectionData::new(
						connection_info.get_read_write_connection_info()?.clone(),
						ctx.guarded_data.clone(),
						wakeup.clone(),
					)) {
						Ok(_) => {}
						Err(e) => {
							warn!("on_accept Callback resulted in error: {}", e);
						}
					}
				}
				None => error!("no handler for on_accept!"),
			};

			ctx.accepted_connections.push(connection_info);
			Ok(true)
		} else {
			error!(
				"Error accepting connection: {}",
				std::io::Error::last_os_error()
			);
			Ok(false)
		}
	}

	fn process_read(
		connection_info: ReadWriteConnection,
		ctx: &mut Context,
		wakeup: &Wakeup,
		callbacks: &Callbacks<OnRead, OnAccept, OnClose, OnPanic>,
	) -> Result<isize, Error> {
		debug!("read event on {:?}", connection_info);
		let len = {
			let cbuf: *mut c_void = &mut ctx.buffer as *mut _ as *mut c_void;
			unsafe { read(connection_info.handle, cbuf, READ_BUFFER_SIZE) }
		};

		if len >= 0 {
			debug!("read {:?}", &ctx.buffer[0..len.try_into()?]);
		} else {
			debug!("got a negative read: {} on conn={:?}", len, connection_info);
		}

		if wakeup.wakeup_handle_read == connection_info.handle {
			// wakeup event
			trace!("wakeup len read = {}", len);
		} else if len > 0 {
			info!("read {} bytes", len);
			// non-wakeup, so execute on_read callback
			match &callbacks.on_read {
				Some(on_read) => {
					let connection_data = &ConnectionData::new(
						connection_info,
						ctx.guarded_data.clone(),
						wakeup.clone(),
					);
					match (on_read)(connection_data, &ctx.buffer[0..len.try_into()?]) {
						Ok(_) => {}
						Err(e) => {
							warn!("on_read Callback resulted in error: {}", e);
						}
					}
				}
				None => {
					error!("no on_read callback found!");
				}
			}
		} else {
			info!("len less than or equal to 0. Might be a close or no data");
			// len <= 0 close don't do anything here
		}

		Ok(len)
	}

	fn process_write_event(
		event: &Event,
		_ctx: &mut Context,
		_config: &EventHandlerConfig,
		_callbacks: &Callbacks<OnRead, OnAccept, OnClose, OnPanic>,
		_connection_id_map: &mut HashMap<u128, Arc<RwLock<EventConnectionInfo>>>,
		connection_handle_map: &mut HashMap<Handle, Arc<RwLock<EventConnectionInfo>>>,
	) -> Result<(), Error> {
		debug!("in process write for event: {:?}", event);

		let connection_info = match connection_handle_map.get_mut(&event.handle) {
			Some(connection_info) => connection_info,
			None => {
				return Err(ErrorKind::HandleNotFoundError(format!(
					"Connection handle was not found for event: {:?}",
					event
				))
				.into())
			}
		};

		let mut connection_info = lockw!(connection_info)?;
		match &mut *connection_info {
			EventConnectionInfo::ReadWriteConnection(connection_info) => {
				info!("connection_info={:?}", connection_info);
				for wbuf in &mut connection_info.pending_wbufs {
					let len = write_bytes(event.handle, &mut wbuf.buf)?;
					info!("len written = {}", len);
				}
				connection_info.pending_wbufs.clear();
			}
			EventConnectionInfo::ListenerConnection(_connection_info) => {
				warn!("tried to write to a listener: {:?}", event);
			}
		}

		Ok(())
	}

	fn get_events(ctx: &mut Context, events: &mut Vec<Event>) -> Result<(), Error> {
		debug!(
			"in get events with {} events. tid={}",
			ctx.input_events.len(),
			ctx.tid
		);

		let mut kevs = vec![];
		for event in &ctx.input_events {
			debug!("pushing input event = {:?}", event);
			match event.etype {
				EventType::Accept => {
					trace!("pushing an accept");
					kevs.push(kevent::new(
						event.handle.try_into()?,
						EventFilter::EVFILT_READ,
						EventFlag::EV_ADD | EventFlag::EV_CLEAR,
						FilterFlag::empty(),
					));
				}
				EventType::Read => {
					info!("pushing a read: {}", event.handle);
					kevs.push(kevent::new(
						event.handle.try_into()?,
						EventFilter::EVFILT_READ,
						EventFlag::EV_ADD | EventFlag::EV_CLEAR,
						FilterFlag::empty(),
					));
				}
				EventType::Write => {
					trace!("pushing a write");
					kevs.push(kevent::new(
						event.handle.try_into()?,
						EventFilter::EVFILT_WRITE,
						EventFlag::EV_ADD | EventFlag::EV_CLEAR,
						FilterFlag::empty(),
					));
				}
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
				&Self::duration_to_timespec(Duration::from_millis(30000000)),
			)
		};

		debug!("kqueue wakeup with ret_count = {}", ret_count);
		events.clear();
		for i in 0..ret_count as usize {
			events.push(Event {
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

		ctx.input_events.clear();
		Ok(())
	}

	#[cfg(any(target_os = "macos", dragonfly, netbsd, openbsd))]
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
		_config: &EventHandlerConfig,
		connection_id_map: &mut HashMap<u128, Arc<RwLock<EventConnectionInfo>>>,
		connection_handle_map: &mut HashMap<Handle, Arc<RwLock<EventConnectionInfo>>>,
	) -> Result<(), Error> {
		{
			let mut guarded_data = lockw!(ctx.guarded_data)?;
			ctx.add_pending.append(&mut (*guarded_data).nhandles);
			ctx.nwrites.append(&mut (*guarded_data).write_queue);
		}

		ctx.add_pending.append(&mut ctx.accepted_connections);

		debug!(
			"adding pending conns: {:?} on tid={}",
			ctx.add_pending, ctx.tid
		);
		Self::process_pending(ctx, connection_id_map, connection_handle_map)?;
		ctx.add_pending.clear();

		Self::process_nwrites(ctx, connection_id_map, connection_handle_map)?;
		ctx.nwrites.clear();

		Ok(())
	}

	fn process_nwrites(
		ctx: &mut Context,
		connection_id_map: &mut HashMap<u128, Arc<RwLock<EventConnectionInfo>>>,
		_connection_handle_map: &mut HashMap<Handle, Arc<RwLock<EventConnectionInfo>>>,
	) -> Result<(), Error> {
		debug!("process nwrites with {} connections", ctx.nwrites.len());
		for wbuf in &ctx.nwrites {
			match connection_id_map.get_mut(&wbuf.connection_id) {
				Some(conn_info) => {
					let mut conn_info = lockw!(conn_info)?;
					match &mut *conn_info {
						EventConnectionInfo::ReadWriteConnection(item) => {
							item.pending_wbufs.push(wbuf.clone());
							info!("pushing wbuf to item = {:?}", item);
							ctx.input_events.push(Event {
								handle: item.handle,
								etype: EventType::Write,
							});
						}
						EventConnectionInfo::ListenerConnection(item) => {
							warn!("Got a write request on listener: {:?}", item);
						}
					}
				}
				None => {
					trace!("Attempt to write on closed connection: {:?}", wbuf);
				} // connection already disconnected
			}
		}

		Ok(())
	}

	fn process_pending(
		ctx: &mut Context,
		connection_id_map: &mut HashMap<u128, Arc<RwLock<EventConnectionInfo>>>,
		connection_handle_map: &mut HashMap<Handle, Arc<RwLock<EventConnectionInfo>>>,
	) -> Result<(), Error> {
		debug!("process_pending with {} connections", ctx.add_pending.len());
		for pending in &ctx.add_pending {
			match pending {
				EventConnectionInfo::ReadWriteConnection(item) => {
					let pending = Arc::new(RwLock::new(pending.clone()));
					connection_id_map.insert(item.id, pending.clone());
					connection_handle_map.insert(item.handle, pending);
					ctx.input_events.push(Event {
						handle: item.handle,
						etype: EventType::Read,
					});
				}
				EventConnectionInfo::ListenerConnection(item) => {
					let pending = Arc::new(RwLock::new(pending.clone()));
					connection_id_map.insert(item.id, pending.clone());
					connection_handle_map.insert(item.handles[ctx.tid], pending);
					info!(
						"pushing accept handle: {} to tid={}",
						item.handles[ctx.tid], ctx.tid
					);
					ctx.input_events.push(Event {
						handle: item.handles[ctx.tid],
						etype: EventType::Accept,
					});
				}
			}
		}
		Ok(())
	}
}

fn write_bytes(handle: Handle, buf: &mut [u8]) -> Result<isize, Error> {
	#[cfg(unix)]
	let len = {
		let cbuf: *const c_void = buf as *const _ as *const c_void;
		unsafe { write(handle, cbuf, buf.len().into()) }
	};
	#[cfg(target_os = "windows")]
	let len = {
		let cbuf: *mut i8 = buf as *mut _ as *mut i8;
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

#[derive(Clone, Debug)]
pub struct ReadWriteConnection {
	id: u128,
	handle: Handle,
	pending_wbufs: Vec<WriteBuffer>,
}

impl ReadWriteConnection {
	fn new(id: u128, handle: Handle) -> Self {
		Self {
			id,
			handle,
			pending_wbufs: vec![],
		}
	}

	fn get_connection_id(&self) -> u128 {
		self.id
	}

	fn _get_handle(&self) -> Handle {
		self.handle
	}
}

#[derive(Clone, Debug)]
struct ListenerConnection {
	id: u128,
	handles: Vec<Handle>,
}

#[derive(Clone, Debug)]
enum EventConnectionInfo {
	ListenerConnection(ListenerConnection),
	ReadWriteConnection(ReadWriteConnection),
}

impl EventConnectionInfo {
	fn read_write_connection(handle: Handle) -> EventConnectionInfo {
		EventConnectionInfo::ReadWriteConnection(ReadWriteConnection::new(rand::random(), handle))
	}

	fn listener_connection(handles: Vec<Handle>) -> EventConnectionInfo {
		EventConnectionInfo::ListenerConnection(ListenerConnection {
			id: rand::random(),
			handles,
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
			EventConnectionInfo::ListenerConnection(c) => c.handles[tid],
			EventConnectionInfo::ReadWriteConnection(c) => c.handle,
		}
	}

	fn get_read_write_connection_info(&self) -> Result<&ReadWriteConnection, Error> {
		match self {
			EventConnectionInfo::ReadWriteConnection(connection_info) => Ok(connection_info),
			EventConnectionInfo::ListenerConnection(_) => {
				Err(ErrorKind::WrongConnectionType("this is a listener".to_string()).into())
			}
		}
	}
}

#[derive(Debug)]
enum EventType {
	Accept,
	Read,
	Write,
}

#[derive(Debug)]
struct Event {
	handle: Handle,
	etype: EventType,
}

#[derive(Clone, Debug)]
struct WriteBuffer {
	connection_id: u128,
	buf: Vec<u8>,
	_cur: usize,
	_close: bool,
}

impl WriteBuffer {
	fn new(connection_id: u128, buf: Vec<u8>, _close: bool) -> Self {
		let _cur = 0;
		Self {
			connection_id,
			buf,
			_cur,
			_close,
		}
	}
}

#[derive(Debug, Clone)]
struct Wakeup {
	wakeup_handle_read: Handle,
	wakeup_handle_write: Handle,
}

impl Wakeup {
	fn new() -> Result<Self, Error> {
		let (wakeup_handle_read, wakeup_handle_write) = Self::build_pipe()?;
		Ok(Self {
			wakeup_handle_read,
			wakeup_handle_write,
		})
	}

	fn wakeup(&self) -> Result<(), Error> {
		write_bytes(self.wakeup_handle_write, &mut [0u8; 1])?;
		Ok(())
	}

	fn build_pipe() -> Result<(Handle, Handle), Error> {
		#[cfg(target_os = "windows")]
		{
			// TODO: support windows
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
struct GuardedData {
	write_queue: Vec<WriteBuffer>,
	nhandles: Vec<EventConnectionInfo>,
}

impl GuardedData {
	fn new() -> Self {
		Self {
			write_queue: vec![],
			nhandles: vec![],
		}
	}
}

struct Context {
	guarded_data: Arc<RwLock<GuardedData>>,
	add_pending: Vec<EventConnectionInfo>,
	accepted_connections: Vec<EventConnectionInfo>,
	nwrites: Vec<WriteBuffer>,
	input_events: Vec<Event>,
	selector: SelectorHandle,
	tid: usize,
	buffer: [u8; READ_BUFFER_SIZE],
}

impl Context {
	fn new(tid: usize, guarded_data: Arc<RwLock<GuardedData>>) -> Result<Self, Error> {
		Ok(Self {
			guarded_data,
			add_pending: vec![],
			accepted_connections: vec![],
			nwrites: vec![],
			input_events: vec![],
			selector: unsafe { kqueue() },
			tid,
			buffer: [0u8; READ_BUFFER_SIZE],
		})
	}
}

#[derive(Clone)]
struct Callbacks<OnRead, OnAccept, OnClose, OnPanic> {
	on_read: Option<Pin<Box<OnRead>>>,
	on_accept: Option<Pin<Box<OnAccept>>>,
	on_close: Option<Pin<Box<OnClose>>>,
	on_panic: Option<Pin<Box<OnPanic>>>,
}

#[cfg(test)]
mod tests {
	use crate::eventhandler::*;
	use nioruntime_err::Error;
	use nix::sys::socket::InetAddr;
	use nix::sys::socket::SockAddr;
	use std::io::{Read, Write};
	use std::mem;
	use std::net::{SocketAddr, TcpListener, TcpStream};
	use std::os::unix::io::AsRawFd;
	use std::os::unix::prelude::FromRawFd;
	use std::str::FromStr;

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

	#[test]
	fn test_eventhandler() -> Result<(), Error> {
		debug!("Starting Eventhandler");
		let mut evh = EventHandler::new(EventHandlerConfig {
			threads: 3,
			..EventHandlerConfig::default()
		})?;

		let lock = Arc::new(RwLock::new(0));
		let lock_clone1 = lock.clone();
		let lock_clone2 = lock.clone();

		let std_sa = SocketAddr::from_str("0.0.0.0:8092").unwrap();
		let inet_addr = InetAddr::from_std(&std_sa);
		let sock_addr = SockAddr::new_inet(inet_addr);

		let mut handles = vec![];
		let mut listeners = vec![];
		for _ in 0..3 {
			let fd = get_fd()?;
			nix::sys::socket::bind(fd, &sock_addr)?;
			nix::sys::socket::listen(fd, 10)?;

			let listener = unsafe { TcpListener::from_raw_fd(fd) };
			listener.set_nonblocking(true)?;
			handles.push(listener.as_raw_fd());
			listeners.push(listener);
		}

		let cid_accept = Arc::new(RwLock::new(0));
		let cid_accept_clone = cid_accept.clone();
		let cid_read = Arc::new(RwLock::new(0));
		let cid_read_clone = cid_read.clone();

		evh.set_on_accept(move |conn_data| {
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
		evh.set_on_close(move |_conn_data| Ok(()))?;
		evh.set_on_panic(move || Ok(()))?;

		evh.set_on_read(move |conn_data, buf| {
			info!("callback on {:?} with buf={:?}", conn_data, buf);
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
		evh.start()?;
		evh.add_listener_handles(handles)?;
		let mut stream = TcpStream::connect("127.0.0.1:8092")?;
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
}
