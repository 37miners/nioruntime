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

use crate::cache::HttpCache;
use crate::proxy::{
	process_health_check, process_health_check_response, process_proxy_inbound,
	process_proxy_outbound, socket_connect,
};
use crate::types::*;
use crate::websocket::{process_websocket_data, WsHandler};
use include_dir::include_dir;
use nioruntime_deps::base64;
use nioruntime_deps::bytefmt;
use nioruntime_deps::chrono::{DateTime, Datelike, NaiveDateTime, Timelike, Utc, Weekday};
use nioruntime_deps::colored::Colorize;
use nioruntime_deps::dirs;
use nioruntime_deps::fsutils;
use nioruntime_deps::hex;
use nioruntime_deps::libc::{
	self, c_void, setsockopt, socklen_t, SOL_SOCKET, SO_REUSEADDR, SO_REUSEPORT,
};
use nioruntime_deps::nix::sys::socket::SockType::Stream;
use nioruntime_deps::nix::sys::socket::{
	bind, listen, socket, AddressFamily, InetAddr, SockAddr, SockFlag,
};
use nioruntime_deps::num_format::{Locale, ToFormattedString};
use nioruntime_deps::path_clean::clean as path_clean;
use nioruntime_deps::rand;
use nioruntime_deps::sha1::Sha1;
use nioruntime_deps::sha2::{Digest, Sha256};
use nioruntime_err::{Error, ErrorKind};
use nioruntime_evh::TLSServerConfig;
use nioruntime_evh::{ConnectionContext, ConnectionData};
use nioruntime_evh::{EventHandler, EvhParams};
use nioruntime_log::*;
use nioruntime_util::slabs::SlabAllocator;
use nioruntime_util::{lockr, lockw};
use std::any::Any;
use std::collections::{HashMap, HashSet};
use std::convert::TryInto;
use std::fs::{metadata, File, Metadata};
use std::io::{Read, Write};
use std::mem;
use std::net::SocketAddr;
use std::net::TcpListener;
use std::os::unix::io::AsRawFd;
use std::os::unix::io::FromRawFd;
use std::path::PathBuf;
use std::pin::Pin;
use std::str::from_utf8;
use std::sync::{Arc, RwLock};
use std::time::{Instant, SystemTime, UNIX_EPOCH};

info!();

const MIN_LENGTH_STARTUP_LINE_NAME: usize = 30;
const SEPARATOR: &str = "\
----------\
----------\
----------\
----------\
----------\
----------\
----------\
----------\
----------";

pub struct HttpServer<ApiHandler> {
	config: HttpConfig,
	_listeners: Vec<TcpListener>,
	api_config: Arc<RwLock<HttpApiConfig>>,
	api_handler: Option<Pin<Box<ApiHandler>>>,
	ws_handler: Option<Pin<Box<WsHandler>>>,
	evh_params: Option<EvhParams>,
}

impl<ApiHandler> HttpServer<ApiHandler>
where
	ApiHandler: Fn(&ConnectionData, &HttpHeaders, &mut ApiContext) -> Result<(), Error>
		+ Send
		+ 'static
		+ Clone
		+ Sync
		+ Unpin,
{
	pub fn new(config: HttpConfig) -> Result<Self, Error> {
		Self::check_config(&config)?;

		let home_dir = match dirs::home_dir() {
			Some(p) => p,
			None => PathBuf::new(),
		}
		.as_path()
		.display()
		.to_string();

		let webroot = std::str::from_utf8(&config.webroot).unwrap().to_string();
		let webroot = webroot.replace("~", &home_dir);
		let webroot = path_clean(&webroot);

		let mainlog = config.mainlog.replace("~", &home_dir);
		let mainlog = path_clean(&mainlog);
		let temp_dir = config.temp_dir.replace("~", &home_dir);

		if std::fs::metadata(webroot.clone()).is_err() {
			Self::init_webroot(&webroot)?;
		}

		if std::fs::metadata(mainlog.clone()).is_err() {
			Self::init_mainlog(&mainlog)?;
		}

		if std::fs::metadata(temp_dir.clone()).is_err() {
			Self::init_temp_dir(&temp_dir)?;
		}

		Ok(Self {
			config,
			_listeners: vec![],
			api_config: Arc::new(RwLock::new(HttpApiConfig::default())),
			api_handler: None,
			ws_handler: None,
			evh_params: None,
		})
	}

	#[rustfmt::skip]
	pub fn stop(&mut self) -> Result<(), Error> {
		match &self.evh_params { Some(e) => e.stop()?, _ => {} }
		self._listeners = vec![];
		Ok(())
	}

	#[rustfmt::skip]
	pub fn start(&mut self) -> Result<(), Error> {
		let mut evh = EventHandler::new(self.config.evh_config)?;

		let evh_params = evh.get_evh_params();
		let evh_params_clone = evh_params.clone();
		let evh_params_clone2 = evh_params.clone();

		self.evh_params = Some(evh_params_clone2);

		let config1 = self.config.clone();
		let config2 = self.config.clone();
		let config3 = self.config.clone();
		let config4 = self.config.clone();
		let cache = Arc::new(RwLock::new(HttpCache::new(
			self.config.max_cache_files,
			self.config.max_cache_chunks,
			self.config.cache_chunk_size,
			self.config.max_load_factor,
		)?));

		let slabs = Arc::new(RwLock::new(SlabAllocator::new(
			self.config.content_upload_slab_count,
			self.config.content_upload_slab_size,
		)));

		let api_config = self.api_config.clone();
		let api_handler = self.api_handler.clone();
                let ws_handler = self.ws_handler.clone();

		evh.set_on_read(move |conn_data, buf, ctx, user_data| {
                        Self::init_user_data(user_data, &config1)?;
                        let thread_context = user_data.downcast_mut::<ThreadContext>().unwrap();
			match Self::process_on_read(
                                thread_context,
				&conn_data,
				buf,
				ctx,
				&config1,
				&cache,
				&api_config,
				&api_handler,
				&evh_params,
				&slabs,
                                ws_handler.as_ref(),
			) {
                            Ok(_) => {},
                            Err(e) => {
                                error!("on_read returned error: {}", e)?;
                            }
                        }

                        Self::update_thread_context(thread_context, &config1, &cache)?;

                        Ok(())
		})?;
		evh.set_on_accept(move |conn_data, ctx, user_data| {
			Self::process_on_accept(conn_data, ctx, &config2, user_data)
		})?;
		evh.set_on_close(move |conn_data, ctx, user_data| {
			Self::process_on_close(conn_data, ctx, &config3, user_data)
		})?;
		evh.set_on_panic(move || Ok(()))?;
		evh.set_on_housekeep(move |user_data, tid| {
			match Self::process_on_housekeeper(&config4, user_data, &evh_params_clone, tid) {
				Ok(_) => {},
				Err(e) => debug!("housekeeping generated error: {}", e)?,
			}
			Ok(())
		})?;

		evh.start()?;

		for i in 0..self.config.listeners.len() {
			let inet_addr = InetAddr::from_std(&self.config.listeners[i].1);
			let sock_addr = SockAddr::new_inet(inet_addr);

			let mut handles = vec![];
			for _ in 0..self.config.evh_config.threads {
				let handle = Self::get_handle()?;
				bind(handle, &sock_addr)?;
				listen(handle, self.config.listen_queue_size)?;

				let listener = unsafe { TcpListener::from_raw_fd(handle) };
				listener.set_nonblocking(true)?;
				handles.push(listener.as_raw_fd());
				self._listeners.push(listener);
			}

			let tls_config = if self.config.listeners[i].0 == ListenerType::Tls {
				let port = self.config.listeners[i].1.port();
				let private_key_file = match self.config.privkey_map.get(&port) {
					Some(private_key_file) => private_key_file.to_string(),
					None => {
                                		return Err(ErrorKind::Configuration(format!(
                                        		"No privkey file specified for port {}",
                                        		self.config.listeners[i].1.port()
                                		)).into());
					},
				};

                                let certificates_file = match self.config.fullchain_map.get(&port) {
                                        Some(certificates_file) => certificates_file.to_string(),
                                        None => {
                                		return Err(ErrorKind::Configuration(format!(
                                        		"No fullchain file specified for port {}",
                                        		self.config.listeners[i].1.port()
                                		)).into());
                                        },
                                };

				Some(
					TLSServerConfig {
						certificates_file,
						private_key_file,
					}
				)
			} else {
				None
			};
			evh.add_listener_handles(handles, tls_config)?;
		}

		self.show_config()?;

		set_config_option!(Settings::Level, true)?;
                let server_startup = format!(
                        "Server started in {} ms.", self.config.start.elapsed().as_millis()
                );
		info!("{}", server_startup.cyan())?;
		set_config_option!(Settings::LineNum, true)?;
		if !self.config.debug {
			set_config_option!(Settings::Stdout, false)?;
		}

		Ok(())
	}

	pub fn set_ws_handler(&mut self, ws_handler: WsHandler) -> Result<(), Error> {
		self.ws_handler = Some(Box::pin(ws_handler));
		Ok(())
	}

	pub fn set_api_handler(&mut self, handler: ApiHandler) -> Result<(), Error> {
		self.api_handler = Some(Box::pin(handler));
		Ok(())
	}

	pub fn set_api_config(&mut self, api_config: HttpApiConfig) -> Result<(), Error> {
		let mut self_config = lockw!(self.api_config)?;
		*self_config = api_config;
		Ok(())
	}

	fn check_config(config: &HttpConfig) -> Result<(), Error> {
		for listener in &config.listeners {
			let res = socket_connect(&listener.1);
			if res.is_ok() {
				let handle = res.unwrap();
				#[cfg(unix)]
				unsafe {
					libc::close(handle);
				}
				#[cfg(windows)]
				unsafe {
					ws2_32::closesocket(handle);
				}
				return Err(ErrorKind::Configuration(format!(
					"Port {} already in use.",
					listener.1.port()
				))
				.into());
			}
		}
		Ok(())
	}

	fn format_bytes(n: u64) -> String {
		if n >= 1_000_000 {
			bytefmt::format_to(n, bytefmt::Unit::MB)
		} else if n >= 1_000 {
			bytefmt::format_to(n, bytefmt::Unit::KB)
		} else {
			bytefmt::format_to(n, bytefmt::Unit::B)
		}
	}

	fn format_time(n: u128) -> String {
		let duration = std::time::Duration::from_millis(n.try_into().unwrap_or(u64::MAX));
		if n >= 1000 * 60 {
			format!("{} Minute(s)", (duration.as_secs() / 60))
		} else if n >= 1000 {
			format!("{} Second(s)", duration.as_secs())
		} else {
			format!("{} Millisecond(s)", duration.as_millis())
		}
	}

	fn startup_line(&self, name: &str, value: &str) -> Result<(), Error> {
		let mut name = format!("{}:", name);
		for _ in 0..MIN_LENGTH_STARTUP_LINE_NAME.saturating_sub(name.len()) {
			name = format!("{} ", name);
		}
		info!("{} '{}'", name.yellow(), value)?;
		Ok(())
	}

	fn debug_flag(&self, name: &str, is_set: bool) -> Result<(), Error> {
		if is_set {
			info_no_ts!("{}: '{}' flag is set.", "WARNING:".red(), name.green())?;
		}
		Ok(())
	}

	fn show_config(&self) -> Result<(), Error> {
		info!("{}", from_utf8(&self.config.server_name)?.green())?;
		info_no_ts!("{}", SEPARATOR)?;

		self.startup_line(
			"Listener Addresses",
			&format!("{:?}", &self.config.listeners)[..],
		)?;

		self.startup_line("mainlog", &self.config.mainlog)?;

		self.startup_line(
			"mainlog_max_age",
			&Self::format_time(self.config.mainlog_max_age),
		)?;
		self.startup_line(
			"mainlog_max_size",
			&Self::format_bytes(self.config.mainlog_max_size.try_into()?),
		)?;

		self.startup_line(
			"listen_queue_size",
			&format!(
				"{}",
				self.config
					.listen_queue_size
					.to_formatted_string(&Locale::en)
			)[..],
		)?;

		self.startup_line(
			"max_header_size",
			&format!(
				"{}",
				Self::format_bytes(self.config.max_header_size.try_into()?)
			)[..],
		)?;

		self.startup_line(
			"max_header_entries",
			&format!(
				"{}",
				self.config
					.max_header_entries
					.to_formatted_string(&Locale::en)
			)[..],
		)?;

		self.startup_line(
			"max_header_name_len",
			&format!(
				"{}",
				Self::format_bytes(self.config.max_header_name_len.try_into()?)
			)[..],
		)?;

		self.startup_line(
			"max_header_value_len",
			&format!(
				"{}",
				Self::format_bytes(self.config.max_header_value_len.try_into()?)
			)[..],
		)?;

		self.startup_line(
			"webroot",
			&format!("{}", from_utf8(&self.config.webroot)?)[..],
		)?;

		self.startup_line("temp_dir", &format!("{}", self.config.temp_dir))?;

		self.startup_line(
			"max_cache_files",
			&format!(
				"{}",
				self.config.max_cache_files.to_formatted_string(&Locale::en)
			)[..],
		)?;

		self.startup_line(
			"max_cache_chunks",
			&format!(
				"{}",
				self.config
					.max_cache_chunks
					.to_formatted_string(&Locale::en)
			)[..],
		)?;

		self.startup_line(
			"cache_chunk_size",
			&format!(
				"{}",
				Self::format_bytes(self.config.cache_chunk_size.try_into()?)
			)[..],
		)?;

		self.startup_line(
			"max_load_factor",
			&format!("{}", self.config.max_load_factor)[..],
		)?;

		self.startup_line(
			"max_bring_to_front",
			&format!(
				"{}",
				self.config
					.max_bring_to_front
					.to_formatted_string(&Locale::en)
			)[..],
		)?;

		self.startup_line(
			"process_cache_update",
			&format!("{}", Self::format_time(self.config.process_cache_update))[..],
		)?;

		self.startup_line(
			"cache_recheck_fs_millis",
			&format!("{}", Self::format_time(self.config.cache_recheck_fs_millis))[..],
		)?;

		self.startup_line(
			"connect_timeout",
			&format!("{}", Self::format_time(self.config.connect_timeout))[..],
		)?;

		self.startup_line(
			"idle_timeout",
			&format!("{}", Self::format_time(self.config.idle_timeout))[..],
		)?;

		self.startup_line(
			"threads",
			&format!(
				"{}",
				self.config
					.evh_config
					.threads
					.to_formatted_string(&Locale::en)
			)[..],
		)?;

		self.startup_line(
			"read_buffer_size",
			&format!(
				"{}",
				Self::format_bytes(self.config.evh_config.read_buffer_size.try_into()?)
			)[..],
		)?;

		self.startup_line(
			"max_rwhandles",
			&format!(
				"{}",
				self.config
					.evh_config
					.max_rwhandles
					.to_formatted_string(&Locale::en)
			)[..],
		)?;

		self.startup_line(
			"max_handle_numeric_value",
			&format!(
				"{}",
				self.config
					.evh_config
					.max_handle_numeric_value
					.to_formatted_string(&Locale::en)
			)[..],
		)?;

		self.startup_line(
			"housekeeper_frequency",
			&format!(
				"{}",
				Self::format_time(self.config.evh_config.housekeeper_frequency.try_into()?)
			)[..],
		)?;

		self.debug_flag("--show_request_headers", self.config.show_request_headers)?;
		self.debug_flag("--show_response_headers", self.config.show_response_headers)?;
		self.debug_flag("--debug", self.config.debug)?;
		self.debug_flag("--debug_post", self.config.debug_post)?;
		self.debug_flag("--debug_websocket", self.config.debug_websocket)?;

		info_no_ts!("{}", SEPARATOR)?;

		Ok(())
	}

	fn init_mainlog(mainlog: &String) -> Result<(), Error> {
		let mut p = PathBuf::from(mainlog);
		p.pop();
		fsutils::mkdir(&p.as_path().display().to_string());
		File::create(mainlog)?;

		Ok(())
	}

	fn init_temp_dir(temp_dir: &String) -> Result<(), Error> {
		fsutils::mkdir(temp_dir);
		Ok(())
	}

	#[rustfmt::skip]
	fn init_webroot(root_dir: &str) -> Result<(), Error> {
		fsutils::mkdir(root_dir);
		for file in include_dir!("$CARGO_MANIFEST_DIR/src/resources/www").files() {
			let file_path = file.path().file_name().unwrap().to_str().unwrap().to_string();
			let root_dir = root_dir.to_string();
			let contents = file.contents();
			Self::create_file_from_bytes(file_path, root_dir, contents)?;
		}

		Ok(())
	}

	fn create_file_from_bytes(
		resource: String,
		root_dir: String,
		bytes: &[u8],
	) -> Result<(), Error> {
		let path = format!("{}/{}", root_dir, resource);
		let mut file = File::create(&path)?;
		file.write_all(bytes)?;
		Ok(())
	}

	fn init_user_data(
		user_data: &mut Box<dyn Any + Send + Sync>,
		config: &HttpConfig,
	) -> Result<(), Error> {
		match user_data.downcast_ref::<ThreadContext>() {
			Some(_) => {}
			None => {
				let mut value = ThreadContext::new(config)?;

				for (k, v) in &config.mime_map {
					value
						.mime_map
						.insert(k.as_bytes().to_vec(), v.as_bytes().to_vec());
				}

				*user_data = Box::new(value);
			}
		}
		Ok(())
	}

	fn process_async(
		ctx: &mut ConnectionContext,
		thread_context: &ThreadContext,
		conn_data: &ConnectionData,
	) -> Result<(), Error> {
		if ctx.is_async_complete {
			let mut async_connections = lockw!(thread_context.async_connections)?;
			async_connections.remove(&conn_data.get_connection_id());
		}
		Ok(())
	}

	fn update_conn_info(
		thread_context: &mut ThreadContext,
		conn_data: &ConnectionData,
		now: SystemTime,
	) -> Result<(), Error> {
		let id = conn_data.get_connection_id();
		let now = now.duration_since(UNIX_EPOCH)?.as_micros();
		match thread_context.active_connections.get_mut(&id) {
			Some(conn_info) => conn_info.last_data = now,
			None => error!("No connection info found for connection {}", id)?,
		}
		Ok(())
	}

	fn process_post_await(
		connection_id: u128,
		conn_info: &mut ConnectionInfo,
		nbuf: &[u8],
	) -> Result<(bool, usize), Error> {
		let (rem, overflow) = match conn_info.api_context.as_mut() {
			Some(ctx) => {
				if ctx.is_proxy() {
					let remaining = ctx.remaining();
					let rem = remaining.saturating_sub(nbuf.len());
					let overflow = if rem == 0 {
						nbuf.len().saturating_sub(remaining)
					} else {
						0
					};
					match ctx.proxy_conn() {
						Some(proxy_conn) => proxy_conn.write(nbuf)?,
						None => error!("expected connection data on conn_id={}", connection_id)?,
					}

					ctx.update_offset(nbuf.len().saturating_sub(overflow));
					if rem == 0 {
						ctx.async_complete()?;
					}
					(rem == 0, overflow)
				} else {
					let (rem, pushed) = ctx.push_bytes(nbuf)?;
					if rem == 0 {
						ctx.async_complete_no_file()?;
					}
					(rem == 0, nbuf.len().saturating_sub(pushed))
				}
			}
			None => {
				return Ok((false, 0));
			}
		};
		if rem {
			conn_info.api_context = None;
		}

		Ok((true, overflow))
	}

	fn process_on_read(
		thread_context: &mut ThreadContext,
		conn_data: &ConnectionData,
		nbuf: &[u8],
		ctx: &mut ConnectionContext,
		config: &HttpConfig,
		cache: &Arc<RwLock<HttpCache>>,
		api_config: &Arc<RwLock<HttpApiConfig>>,
		api_handler: &Option<Pin<Box<ApiHandler>>>,
		evh_params: &EvhParams,
		slabs: &Arc<RwLock<SlabAllocator>>,
		ws_handler: Option<&Pin<Box<WsHandler>>>,
	) -> Result<(), Error> {
		let now = SystemTime::now();
		Self::process_async(ctx, thread_context, conn_data)?;
		Self::update_conn_info(thread_context, conn_data, now)?;

		let remote_peer = &ctx.remote_peer.clone();
		let buffer = ctx.get_buffer();
		let buffer_len = buffer.len();
		let connection_id = conn_data.get_connection_id();

		debug!(
			"on_read[{}] = '{:?}', acc_handle={:?}, buffer_len={}",
			connection_id,
			nbuf,
			conn_data.get_accept_handle(),
			buffer_len
		)?;

		if buffer_len == 0 && nbuf.len() == 0 {
			// there's nothing to do
			return Ok(());
		}

		let is_async = {
			let async_connections = lockr!(thread_context.async_connections)?;
			async_connections.get(&connection_id).is_some()
		};
		let (was_post_await, overflow) = {
			let conn_info = match thread_context.active_connections.get_mut(&connection_id) {
				Some(conn_info) => conn_info,
				None => {
					error!(
						"Expected connection info for connection_id={}",
						connection_id
					)?;
					return Err(ErrorKind::InternalError(
						format!("No connection info for connection id {}", connection_id).into(),
					)
					.into());
				}
			};
			Self::process_post_await(connection_id, conn_info, nbuf)?
		};

		if was_post_await {
			if overflow > 0 {
				let nbuf = &nbuf[nbuf.len().saturating_sub(overflow)..];
				Self::process_sync(
					conn_data,
					evh_params,
					nbuf,
					buffer,
					connection_id,
					now,
					thread_context,
					remote_peer,
					api_config,
					cache,
					config,
					api_handler,
					slabs,
					ws_handler,
				)?;
			}
			return Ok(());
		}

		if !is_async {
			let conn_info = match thread_context.active_connections.get_mut(&connection_id) {
				Some(conn_info) => conn_info,
				None => {
					error!(
						"Expected connection info for connection_id={}",
						connection_id
					)?;
					return Err(ErrorKind::InternalError(
						format!("No connection info for connection id {}", connection_id).into(),
					)
					.into());
				}
			};

			if process_health_check_response(
				conn_info,
				conn_data,
				nbuf,
				&mut thread_context.proxy_state,
			)? {
				return Ok(());
			}

			match &conn_info.proxy_info {
				Some(_proxy_info) => {
					process_proxy_inbound(
						conn_data,
						nbuf,
						conn_info,
						&mut thread_context.proxy_state,
						&mut thread_context.idle_proxy_connections,
						now,
					)?;
					return Ok(());
				}
				None => {}
			}
		}

		if is_async {
			// it's async just append to the buffer and return
			Self::append_buffer(nbuf, buffer)?;
		} else if buffer_len > 0 {
			Self::append_buffer(nbuf, buffer)?;
			loop {
				let amt = Self::process_buffer(
					conn_data,
					buffer,
					config,
					cache,
					api_config,
					thread_context,
					api_handler,
					evh_params,
					now,
					remote_peer,
					slabs,
					ws_handler,
				)?;
				if amt == 0 {
					break;
				}
				buffer.drain(..amt);

				// if were now async, we must break
				if lockr!(thread_context.async_connections)?
					.get(&connection_id)
					.is_some()
				{
					break;
				}
			}
		} else {
			Self::process_sync(
				conn_data,
				evh_params,
				nbuf,
				buffer,
				connection_id,
				now,
				thread_context,
				remote_peer,
				api_config,
				cache,
				config,
				api_handler,
				slabs,
				ws_handler,
			)?;
		}

		Ok(())
	}

	fn process_sync(
		conn_data: &ConnectionData,
		evh_params: &EvhParams,
		nbuf: &[u8],
		buffer: &mut Vec<u8>,
		connection_id: u128,
		now: SystemTime,
		thread_context: &mut ThreadContext,
		remote_peer: &Option<SocketAddr>,
		api_config: &Arc<RwLock<HttpApiConfig>>,
		cache: &Arc<RwLock<HttpCache>>,
		config: &HttpConfig,
		api_handler: &Option<Pin<Box<ApiHandler>>>,
		slabs: &Arc<RwLock<SlabAllocator>>,
		ws_handler: Option<&Pin<Box<WsHandler>>>,
	) -> Result<(), Error> {
		let mut offset = 0;
		loop {
			let pbuf = &nbuf[offset..];
			if pbuf.len() == 0 {
				break;
			}

			// premptively try to process the incoming buffer without appending
			// in many cases this will work and be faster
			let amt = Self::process_buffer(
				conn_data,
				pbuf,
				config,
				cache,
				api_config,
				thread_context,
				api_handler,
				evh_params,
				now,
				remote_peer,
				slabs,
				ws_handler,
			)?;
			if amt == 0 {
				Self::append_buffer(&pbuf, buffer)?;
				break;
			}

			offset += amt;

			// if were now async, we must break
			if lockr!(thread_context.async_connections)?
				.get(&connection_id)
				.is_some()
			{
				Self::append_buffer(&nbuf[offset..], buffer)?;
				break;
			}
		}
		Ok(())
	}

	fn check_expect_100_continue(
		headers: &HttpHeaders,
		conn_data: &ConnectionData,
	) -> Result<(), Error> {
		match headers.get_header_value(&"Expect".to_string())? {
			Some(values) => {
				for value in values {
					if value == "100-continue" {
						conn_data.write(HTTP_CONTINUE_100)?;
					}
				}
			}
			None => {}
		}

		Ok(())
	}

	fn process_proxy_request(
		conn_data: &ConnectionData,
		config: &HttpConfig,
		headers: &HttpHeaders,
		buffer: &[u8],
		evh_params: &EvhParams,
		idle_proxy_connections: &mut HashMap<ProxyEntry, HashMap<SocketAddr, HashSet<ProxyInfo>>>,
		proxy_state: &mut HashMap<ProxyEntry, ProxyState>,
		async_connections: &Arc<RwLock<HashSet<u128>>>,
		active_connections: &mut HashMap<u128, ConnectionInfo>,
		slabs: &Arc<RwLock<SlabAllocator>>,
		remote_peer: &Option<SocketAddr>,
		now: SystemTime,
	) -> Result<(bool, Option<ApiContext>), Error> {
		let mut proxy_entry = None;
		match config.proxy_config.extensions.get(headers.extension()) {
			Some(entry) => proxy_entry = Some(entry),
			None => {}
		}

		if proxy_entry.is_none() {
			match config.proxy_config.mappings.get(headers.get_uri()) {
				Some(entry) => proxy_entry = Some(entry),
				None => {}
			}
		}

		Ok(match proxy_entry {
			Some(proxy_entry) => {
				let clen = headers.content_len()?;
				let headers_len = headers.len();
				let buf_len = buffer.len();

				let api_context = match process_proxy_outbound(
					conn_data,
					&headers,
					config,
					&proxy_entry,
					buffer,
					evh_params,
					active_connections,
					idle_proxy_connections,
					proxy_state,
					async_connections,
					&remote_peer,
					now,
					slabs,
				) {
					Ok(ctx) => {
						if clen > 0 {
							let rem = if clen + headers_len > buf_len {
								(headers_len + clen).saturating_sub(buf_len)
							} else {
								0
							};
							if rem > 0 {
								Some(ctx.clone())
							} else {
								None
							}
						} else {
							None
						}
					}
					Err(e) => {
						warn!("Error while communicating with proxy: {}", e.kind(),)?;
						conn_data.write(HTTP_ERROR_502)?;
						None
					}
				};
				(true, api_context)
			}
			None => (false, None),
		})
	}

	fn send_websocket_handshake_response(
		conn_data: &ConnectionData,
		key: &String,
		sha1: &mut Sha1,
	) -> Result<(), Error> {
		let hash = format!("{}{}", key, WEBSOCKET_GUID);
		sha1.update(hash.as_bytes());
		let b = sha1.clone().finalize();
		let msg = format!(
                        "HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Accept: {}\r\n\r\n",
                        base64::encode(b),
                );
		let response = msg.as_bytes();
		conn_data.write(response)?;
		Ok(())
	}

	fn check_websocket(
		conn_data: &ConnectionData,
		headers: Option<&HttpHeaders>,
		conn_info: &mut ConnectionInfo,
		buffer: &[u8],
		sha1: &mut Sha1,
		ws_handler: &WsHandler,
	) -> Result<(bool, usize), Error> {
		Ok(match conn_info.is_websocket {
			true => {
				let (close, len) = process_websocket_data(conn_data, buffer, ws_handler)?;
				if close {
					conn_data.close()?;
				}
				(true, len)
			}
			false => match headers {
				Some(headers) => match headers.get_header_value(&"Upgrade".to_string())?
					== Some(vec!["websocket".to_string()])
				{
					true => {
						let sec_key = headers.get_header_value(&"Sec-WebSocket-Key".to_string())?;
						match sec_key {
							Some(sec_key) => {
								if sec_key.len() > 0 {
									conn_info.is_websocket = true;
									Self::send_websocket_handshake_response(
										conn_data,
										&sec_key[0],
										sha1,
									)?;
									(true, headers.len())
								} else {
									(false, 0)
								}
							}
							None => (false, 0),
						}
					}
					false => (false, 0),
				},
				None => (false, 0),
			},
		})
	}

	fn process_buffer(
		conn_data: &ConnectionData,
		buffer: &[u8],
		config: &HttpConfig,
		cache: &Arc<RwLock<HttpCache>>,
		api_config: &Arc<RwLock<HttpApiConfig>>,
		thread_context: &mut ThreadContext,
		api_handler: &Option<Pin<Box<ApiHandler>>>,
		evh_params: &EvhParams,
		now: SystemTime,
		remote_peer: &Option<SocketAddr>,
		slabs: &Arc<RwLock<SlabAllocator>>,
		ws_handler: Option<&Pin<Box<WsHandler>>>,
	) -> Result<usize, Error> {
		let mime_map = &thread_context.mime_map;
		let async_connections = &thread_context.async_connections;
		let connection_id = conn_data.get_connection_id();

		match ws_handler {
			Some(ws_handler) => {
				let conn_info = match thread_context.active_connections.get_mut(&connection_id) {
					Some(conn_info) => conn_info,
					None => {
						error!(
							"Expected connection info for connection_id={}",
							connection_id
						)?;
						return Err(ErrorKind::InternalError(
							format!("No connection info for connection id {}", connection_id)
								.into(),
						)
						.into());
					}
				};
				let (is_ws, len) = Self::check_websocket(
					conn_data,
					None,
					conn_info,
					buffer,
					&mut thread_context.sha1,
					&ws_handler,
				)?;

				if is_ws {
					return Ok(len);
				}
			}
			None => {}
		}

		let headers = match HttpHeaders::new(
			buffer,
			config,
			&mut thread_context.header_map,
			&mut thread_context.key_buf,
			&mut thread_context.value_buf,
		) {
			Ok(headers) => headers,
			Err(e) => {
				match e.kind() {
					ErrorKind::HttpError400(_) => {
						conn_data.write(HTTP_ERROR_400)?;
						conn_data.close()?;
					}
					ErrorKind::HttpError405(_) => {
						conn_data.write(HTTP_ERROR_405)?;
						conn_data.close()?;
					}
					ErrorKind::HttpError431(_) => {
						conn_data.write(HTTP_ERROR_431)?;
						conn_data.close()?;
					}
					_ => {
						error!("Internal server error: {}", e)?;
						conn_data.write(HTTP_ERROR_500)?;
						conn_data.close()?;
					}
				}
				debug!("parsing headers generated error: {}", e)?;
				return Ok(0);
			}
		};

		let (len, key) = match headers {
			Some(headers) => {
				if config.show_request_headers {
					warn!("HTTP Request:\n{}", headers)?;
				}

				match ws_handler {
					Some(ws_handler) => {
						let conn_info =
							match thread_context.active_connections.get_mut(&connection_id) {
								Some(conn_info) => conn_info,
								None => {
									error!(
										"Expected connection info for connection_id={}",
										connection_id
									)?;
									return Err(ErrorKind::InternalError(
										format!(
											"No connection info for connection id {}",
											connection_id
										)
										.into(),
									)
									.into());
								}
							};
						let (is_ws, len) = Self::check_websocket(
							conn_data,
							Some(&headers),
							conn_info,
							buffer,
							&mut thread_context.sha1,
							&ws_handler,
						)?;
						if is_ws {
							return Ok(len);
						}
					}
					None => {}
				}
				if headers.content_len()? > config.max_content_len {
					conn_data.write(HTTP_ERROR_413)?;
					conn_data.close()?;
					return Ok(0);
				}

				Self::check_expect_100_continue(&headers, conn_data)?;

				let range: Option<(usize, usize)> = if headers.has_range() {
					let range = headers.get_header_value(&"Range".to_string())?;
					match range {
						Some(range) => {
							if range.len() < 1 {
								None
							} else {
								let range = &range[0];
								let start_index = range.find("=");
								match start_index {
									Some(start_index) => {
										let dash_index = range.find("-");
										match dash_index {
											Some(dash_index) => {
												let end = range.len();
												let start_str =
													&range[(start_index + 1)..dash_index];
												let end_str = &range[(dash_index + 1)..end];
												Some((start_str.parse()?, end_str.parse()?))
											}
											None => None,
										}
									}
									None => None,
								}
							}
						}
						None => None,
					}
				} else {
					None
				};
				let mut key = None;

				let was_proxy = {
					let (was_proxy, api_context) = Self::process_proxy_request(
						conn_data,
						config,
						&headers,
						buffer,
						evh_params,
						&mut thread_context.idle_proxy_connections,
						&mut thread_context.proxy_state,
						async_connections,
						&mut thread_context.active_connections,
						slabs,
						remote_peer,
						now,
					)?;

					match api_context {
						Some(api_context) => {
							let conn_info =
								match thread_context.active_connections.get_mut(&connection_id) {
									Some(conn_info) => conn_info,
									None => {
										error!(
											"Expected connection info for connection_id={}",
											connection_id
										)?;
										return Err(ErrorKind::InternalError(
											format!(
												"No connection info for connection id {}",
												connection_id
											)
											.into(),
										)
										.into());
									}
								};
							conn_info.api_context = Some(api_context);
						}
						None => {}
					}

					was_proxy
				};

				// check for api mapping/extension
				let was_api = {
					let conn_info = match thread_context.active_connections.get_mut(&connection_id)
					{
						Some(conn_info) => conn_info,
						None => {
							error!(
								"Expected connection info for connection_id={}",
								connection_id
							)?;
							return Err(ErrorKind::InternalError(
								format!("No connection info for connection id {}", connection_id)
									.into(),
							)
							.into());
						}
					};
					Self::process_api(
						buffer,
						was_proxy,
						&headers,
						api_config,
						api_handler,
						&thread_context.async_connections,
						conn_info,
						conn_data,
						&thread_context.temp_dir,
						slabs,
					)?
				};

				if !was_api && !was_proxy {
					match Self::send_file(
						&headers.get_uri(),
						conn_data,
						config,
						cache,
						headers.get_version(),
						headers.get_method(),
						range,
						&mime_map,
						&async_connections,
						now,
						&thread_context.webroot,
						slabs,
					) {
						Ok(k) => {
							key = k;
						}
						Err(e) => {
							match e.kind() {
								ErrorKind::HttpError404(_) => {
									match Self::send_file(
										&config.error_page,
										conn_data,
										config,
										cache,
										headers.get_version(),
										headers.get_method(),
										range,
										&mime_map,
										&async_connections,
										now,
										&thread_context.webroot,
										slabs,
									) {
										Ok(k) => key = k,
										Err(_e) => {
											conn_data.write(HTTP_ERROR_404)?;
										}
									}
								}
								ErrorKind::HttpError405(_) => {
									conn_data.write(HTTP_ERROR_405)?;
									conn_data.close()?;
								}
								ErrorKind::HttpError403(_) => {
									conn_data.write(HTTP_ERROR_403)?;
								}
								_ => {
									error!("Internal server error: {}", e)?;
									conn_data.write(HTTP_ERROR_500)?;
									conn_data.close()?;
								}
							}
							debug!(
								"sending file {} generated error: {}",
								std::str::from_utf8(&headers.get_uri())?,
								e
							)?;
						}
					}
				}

				let clen = headers.content_len()?;
				let headers_len = headers.len();
				let end = if clen + headers_len > buffer.len() {
					buffer.len()
				} else {
					clen + headers_len
				};

				(end, key)
			}
			None => (0, None),
		};

		match key {
			Some(key) => {
				let ch = &mut thread_context.cache_hits;
				ch.insert_raw(&key, &[0u8; 16])?;
			}
			None => {}
		}

		Ok(len)
	}

	fn process_api(
		buf: &[u8],
		was_proxy: bool,
		headers: &HttpHeaders,
		api_config: &Arc<RwLock<HttpApiConfig>>,
		api_handler: &Option<Pin<Box<ApiHandler>>>,
		async_connections: &Arc<RwLock<HashSet<u128>>>,
		conn_info: &mut ConnectionInfo,
		conn_data: &ConnectionData,
		temp_dir: &String,
		slabs: &Arc<RwLock<SlabAllocator>>,
	) -> Result<bool, Error> {
		let api_config = lockr!(api_config)?;
		if was_proxy {
			Ok(false)
		} else if api_config.mappings.get(headers.get_uri()).is_some()
			|| api_config.extensions.get(headers.extension()).is_some()
		{
			match api_handler {
				Some(api_handler) => {
					let clen = headers.content_len()?;
					let mut ctx = ApiContext::new(
						async_connections.clone(),
						conn_data.clone(),
						slabs.clone(),
						false,
						None,
					);
					if clen > 0 {
						let headers_len = headers.len();
						let buf_len = buf.len();
						let rem = if clen + headers_len > buf_len {
							(headers_len + clen).saturating_sub(buf_len)
						} else {
							0
						};
						ctx.set_expected(clen, temp_dir, false)?;
						if buf_len > headers_len {
							let end = if clen + headers_len > buf_len {
								buf_len
							} else {
								clen + headers_len
							};
							ctx.push_bytes(&buf[headers_len..end])?;
						}
						if rem > 0 {
							conn_info.api_context = Some(ctx.clone());
						}
					}
					(api_handler)(conn_data, &headers, &mut ctx)?;
					Ok(true)
				}
				None => {
					error!("no api handler configured!")?;
					Ok(false)
				}
			}
		} else {
			Ok(false)
		}
	}

	#[rustfmt::skip]
	fn update_thread_context(
		thread_context: &mut ThreadContext,
		config: &HttpConfig,
		cache: &Arc<RwLock<HttpCache>>,
	) -> Result<(), Error> {
		if thread_context.instant.elapsed().as_millis() > config.process_cache_update {
                        let ch = &mut thread_context.cache_hits;
			let mut cache = lockw!(cache)?;
			let itr = ch.iter_raw();
			for (k, _v) in itr { cache.bring_to_front(k.try_into()?)?; }
			ch.clear()?;
			thread_context.instant = Instant::now();
		}

		thread_context.header_map.clear()?;

		Ok(())
	}

	fn clean(path: &mut Vec<u8>) -> Result<(), Error> {
		clean(path)
	}

	fn check_path(path: &[u8], root_dir: &[u8]) -> Result<(), Error> {
		let root_dir_len = root_dir.len();
		if path.len() < root_dir_len {
			return Err(ErrorKind::HttpError403("Forbidden".into()).into());
		}

		for i in 0..root_dir_len {
			if path[i] != root_dir[i] {
				return Err(ErrorKind::HttpError403("Forbidden".into()).into());
			}
		}

		Ok(())
	}

	fn send_file(
		uri: &[u8],
		conn_data: &ConnectionData,
		config: &HttpConfig,
		cache: &Arc<RwLock<HttpCache>>,
		http_version: &HttpVersion,
		http_method: &HttpMethod,
		range: Option<(usize, usize)>,
		mime_map: &HashMap<Vec<u8>, Vec<u8>>,
		async_connections: &Arc<RwLock<HashSet<u128>>>,
		now: SystemTime,
		webroot: &Vec<u8>,
		slabs: &Arc<RwLock<SlabAllocator>>,
	) -> Result<Option<[u8; 32]>, Error> {
		if http_method != &HttpMethod::Get && http_method != &HttpMethod::Head {
			return Err(ErrorKind::HttpError405("Method not allowed.".into()).into());
		}

		let mut path = webroot.clone();
		path.extend_from_slice(&uri);
		Self::clean(&mut path)?;
		Self::check_path(&path, &webroot)?;

		// try both the exact path and the version with index appended (metadata too expensive)
		let (found, need_update, key) = Self::try_send_cache(
			conn_data,
			&config,
			&path,
			&cache,
			now,
			http_version,
			http_method,
			range,
			mime_map,
		)?;
		let need_update = if found && !need_update {
			return Ok(Some(key));
		} else if !found {
			let mut path2 = path.clone();
			path2.extend_from_slice(INDEX_HTML_BYTES);
			let (found, need_update, key) = Self::try_send_cache(
				conn_data,
				config,
				&path2,
				cache,
				now,
				http_version,
				http_method,
				range,
				mime_map,
			)?;
			if found && !need_update {
				match http_version {
					HttpVersion::V10 | HttpVersion::Unknown => conn_data.close()?,
					HttpVersion::V11 | HttpVersion::V20 => {}
				}
				return Ok(Some(key));
			}
			need_update
		} else {
			need_update
		};

		// if neither found, we have to try to read the file
		let md = match metadata(std::str::from_utf8(&path)?) {
			Ok(md) => md,
			Err(_e) => {
				return Err(ErrorKind::HttpError404("Not found".into()).into());
			}
		};

		let (path, md) = if md.is_dir() {
			path.extend_from_slice(INDEX_HTML_BYTES);
			let md = match metadata(std::str::from_utf8(&path)?) {
				Ok(md) => md,
				Err(_e) => {
					return Err(ErrorKind::HttpError404("Not found".into()).into());
				}
			};
			(path, md)
		} else {
			(path, md)
		};

		Self::load_cache(
			path,
			conn_data.clone(),
			config.clone(),
			md,
			cache.clone(),
			now,
			http_version,
			http_method.clone(),
			range,
			need_update,
			mime_map,
			async_connections,
			slabs,
		)?;

		Ok(None)
	}

	// found, need_update, key
	fn try_send_cache(
		conn_data: &ConnectionData,
		config: &HttpConfig,
		path: &Vec<u8>,
		cache: &Arc<RwLock<HttpCache>>,
		now: SystemTime,
		http_version: &HttpVersion,
		http_method: &HttpMethod,
		range: Option<(usize, usize)>,
		mime_map: &HashMap<Vec<u8>, Vec<u8>>,
	) -> Result<(bool, bool, [u8; 32]), Error> {
		let (key, update_lc, etag) = {
			let cache = lockr!(cache)?;
			let mut headers_sent = false;
			let (iter, len, key, last_check, last_modified, etag) = cache.iter(&path)?;
			if last_check == 0 && last_modified == 0 && len == 0 {
				// not in the cache at all
				return Ok((false, false, key));
			}
			let now_millis = now.duration_since(UNIX_EPOCH)?.as_millis();
			let (out_dated, update_lc) = if last_check != 0
				&& now_millis.saturating_sub(last_check) > config.cache_recheck_fs_millis
			{
				let path_str = std::str::from_utf8(&path)?;
				let md = metadata(&path_str)?;
				let md_mod = md.modified()?;
				let modified = md_mod.duration_since(UNIX_EPOCH)?.as_millis();
				if modified == last_modified {
					(false, Some(md_mod))
				} else {
					(true, None)
				}
			} else {
				(false, None)
			};

			if out_dated {
				// it's found, but outdated
				return Ok((true, true, key));
			} else {
				let mut len_sum = 0;
				let now = now.duration_since(UNIX_EPOCH)?.as_millis();
				for chunk in iter {
					let chunk_len = chunk.len();
					let wlen = if chunk_len + len_sum < len.try_into()? {
						chunk_len as usize
					} else {
						len as usize - len_sum
					};
					if !headers_sent {
						Self::send_headers(
							&conn_data,
							config,
							len,
							if http_method == &HttpMethod::Head {
								None
							} else {
								Some(&chunk[..wlen])
							},
							now,
							last_modified,
							http_version,
							etag,
							range,
							path,
							mime_map,
						)?;
						headers_sent = true;
					} else {
						Self::write_range(conn_data, &chunk[..wlen], range, len_sum)?;
					}

					len_sum += chunk_len;
				}
				if update_lc.is_none() {
					// it's found, it doesn't need an update to last check
					return Ok((true, false, key));
				}

				(key, update_lc, etag)
			}
		};

		match update_lc {
			Some(modified) => {
				// update last_check value
				let mut cache = lockw!(cache)?;
				cache.update_timestamp(&path, now, modified, etag)?;
			}
			None => {}
		}

		Ok((true, false, key))
	}

	fn load_cache(
		path: Vec<u8>,
		conn_data: ConnectionData,
		config: HttpConfig,
		md: Metadata,
		cache: Arc<RwLock<HttpCache>>,
		now: SystemTime,
		http_version: &HttpVersion,
		http_method: HttpMethod,
		range: Option<(usize, usize)>,
		need_update: bool,
		mime_map: &HashMap<Vec<u8>, Vec<u8>>,
		async_connections: &Arc<RwLock<HashSet<u128>>>,
		slabs: &Arc<RwLock<SlabAllocator>>,
	) -> Result<(), Error> {
		let http_version = http_version.clone();
		let mime_map = mime_map.clone();

		let mut ctx = ApiContext::new(
			async_connections.clone(),
			conn_data.clone(),
			slabs.clone(),
			false,
			None,
		);

		ctx.set_async()?;
		let mut ctx = ctx.clone();
		std::thread::spawn(move || -> Result<(), Error> {
			let path_str = std::str::from_utf8(&path)?;
			let md_len = md.len();
			let mut in_buf = vec![];
			in_buf.resize(config.cache_chunk_size.try_into()?, 0u8);

			let mut sha256 = Sha256::new();
			sha256.write(
				&md.modified()?
					.duration_since(UNIX_EPOCH)?
					.as_millis()
					.to_be_bytes(),
			)?;
			sha256.write(&md.len().to_be_bytes())?;
			let hash = sha256.finalize();
			let etag: [u8; 8] = hash[0..8].try_into()?;
			let now_u128 = now.duration_since(UNIX_EPOCH)?.as_millis();

			let mut file = File::open(&path_str)?;
			Self::send_headers(
				&conn_data,
				&config,
				md.len(),
				None,
				now_u128,
				md.modified()?.duration_since(UNIX_EPOCH)?.as_millis(),
				&http_version,
				etag,
				range,
				&path,
				&mime_map,
			)?;

			let mut len_sum = 0;
			let mut len_written = 0;
			if http_method != HttpMethod::Head {
				loop {
					let len = file.read(&mut in_buf)?;
					let nslice = &in_buf[0..len];
					if len > 0
						&& md_len
							<= (config.max_cache_chunks * config.cache_chunk_size).try_into()?
					{
						let mut cache = lockw!(cache)?;
						if need_update {
							cache.remove(&path)?;
						}
						if len_sum != 0 || !(*cache).exists(&path)? {
							len_sum += len;
							(*cache).append_file_chunk(
								&path,
								nslice,
								Some(md_len),
								Some(etag),
								len_sum as u64 == md_len,
								now,
								md.modified().unwrap_or(now),
							)?;
						}
					}

					Self::write_range(&conn_data, nslice, range, len_written)?;
					len_written += nslice.len();

					if len <= 0 {
						break;
					}
				}
			}

			match http_version {
				HttpVersion::V10 | HttpVersion::Unknown => conn_data.close()?,
				HttpVersion::V11 | HttpVersion::V20 => {}
			}

			ctx.async_complete()?;
			Ok(())
		});
		Ok(())
	}

	fn write_range(
		conn_data: &ConnectionData,
		nslice: &[u8],
		range: Option<(usize, usize)>,
		len_written: usize,
	) -> Result<(), Error> {
		match range {
			Some(range) => {
				let nslice_len = nslice.len();
				if !(len_written > (1 + range.1) || len_written + nslice_len < range.0) {
					let mut start = 0;
					let mut end = nslice_len;
					if len_written + nslice_len >= (1 + range.1) {
						end = nslice_len - ((len_written + nslice_len) - (1 + range.1));
					}
					if len_written < range.0 {
						start = range.0 - len_written;
					}
					if start < end {
						conn_data.write(&nslice[start..end])?;
					}
				}
			}
			None => {
				conn_data.write(nslice)?;
			}
		}
		Ok(())
	}

	fn extend_len(response: &mut Vec<u8>, len: u64) -> Result<(), Error> {
		if len >= 1_000_000_000_000 {
			return Err(ErrorKind::TooLargeRead("File too big".into()).into());
		}
		if len >= 100_000_000_000 {
			response.push((((len % 1_000_000_000_000) / 100_000_000_000) as u8 + '0' as u8) as u8);
		}
		if len >= 10_000_000_000 {
			response.push((((len % 100_000_000_000) / 10_000_000_000) as u8 + '0' as u8) as u8);
		}
		if len >= 1_000_000_000 {
			response.push((((len % 10_000_000_000) / 1_000_000_000) as u8 + '0' as u8) as u8);
		}
		if len >= 100_000_000 {
			response.push((((len % 1_000_000_000) / 100_000_000) as u8 + '0' as u8) as u8);
		}
		if len >= 10_000_000 {
			response.push((((len % 100_000_000) / 10_000_000) as u8 + '0' as u8) as u8);
		}
		if len >= 1_000_000 {
			response.push((((len % 10_000_000) / 1_000_000) as u8 + '0' as u8) as u8);
		}
		if len >= 100_000 {
			response.push((((len % 1_000_000) / 100_000) as u8 + '0' as u8) as u8);
		}
		if len >= 10_000 {
			response.push((((len % 100_000) / 10_000) as u8 + '0' as u8) as u8);
		}
		if len >= 1_000 {
			response.push((((len % 10_000) / 1_000) as u8 + '0' as u8) as u8);
		}
		if len >= 100 {
			response.push((((len % 1_000) / 100) as u8 + '0' as u8) as u8);
		}
		if len >= 10 {
			response.push((((len % 100) / 10) as u8 + '0' as u8) as u8);
		}
		response.push(((len % 10) as u8 + '0' as u8) as u8);
		Ok(())
	}

	fn extend_date(response: &mut Vec<u8>, date: u128) -> Result<(), Error> {
		let date: DateTime<Utc> = DateTime::<Utc>::from_utc(
			NaiveDateTime::from_timestamp((date / 1000).try_into()?, 0),
			Utc,
		);
		let date: DateTime<Utc> = date.into();
		match date.weekday() {
			Weekday::Mon => {
				response.extend_from_slice(MON_BYTES);
			}
			Weekday::Tue => {
				response.extend_from_slice(TUE_BYTES);
			}
			Weekday::Wed => {
				response.extend_from_slice(WED_BYTES);
			}
			Weekday::Thu => {
				response.extend_from_slice(THU_BYTES);
			}
			Weekday::Fri => {
				response.extend_from_slice(FRI_BYTES);
			}
			Weekday::Sat => {
				response.extend_from_slice(SAT_BYTES);
			}
			Weekday::Sun => {
				response.extend_from_slice(SUN_BYTES);
			}
		}

		let day = date.day();
		if day < 10 {
			response.extend_from_slice(&['0' as u8]);
		} else {
			response.extend_from_slice(&[(day / 10) as u8 + '0' as u8]);
		}
		response.extend_from_slice(&[(day % 10) as u8 + '0' as u8]);

		match date.month() {
			1 => {
				response.extend_from_slice(JAN_BYTES);
			}
			2 => {
				response.extend_from_slice(FEB_BYTES);
			}
			3 => {
				response.extend_from_slice(MAR_BYTES);
			}
			4 => {
				response.extend_from_slice(APR_BYTES);
			}
			5 => {
				response.extend_from_slice(MAY_BYTES);
			}
			6 => {
				response.extend_from_slice(JUN_BYTES);
			}
			7 => {
				response.extend_from_slice(JUL_BYTES);
			}
			8 => {
				response.extend_from_slice(AUG_BYTES);
			}
			9 => {
				response.extend_from_slice(SEP_BYTES);
			}
			10 => {
				response.extend_from_slice(OCT_BYTES);
			}
			11 => {
				response.extend_from_slice(NOV_BYTES);
			}
			12 => {
				response.extend_from_slice(DEC_BYTES);
			}
			_ => {}
		}

		let year = date.year();
		response.extend_from_slice(&[(year / 1000) as u8 + '0' as u8]);
		response.extend_from_slice(&[((year % 1000) / 100) as u8 + '0' as u8]);
		response.extend_from_slice(&[((year % 100) / 10) as u8 + '0' as u8]);
		response.extend_from_slice(&[(year % 10) as u8 + '0' as u8]);

		let hour = date.hour();
		if hour < 10 {
			response.extend_from_slice(&[' ' as u8, '0' as u8]);
		} else {
			response.extend_from_slice(&[' ' as u8, (hour / 10) as u8 + '0' as u8]);
		}
		response.extend_from_slice(&[(hour % 10) as u8 + '0' as u8, ':' as u8]);

		let min = date.minute();
		if min < 10 {
			response.extend_from_slice(&['0' as u8]);
		} else {
			response.extend_from_slice(&[(min / 10) as u8 + '0' as u8]);
		}
		response.extend_from_slice(&[(min % 10) as u8 + '0' as u8, ':' as u8]);

		let second = date.second();
		if second < 10 {
			response.extend_from_slice(&['0' as u8]);
		} else {
			response.extend_from_slice(&[(second / 10) as u8 + '0' as u8]);
		}
		response.extend_from_slice(&[(second % 10) as u8 + '0' as u8]);

		Ok(())
	}

	fn extend_etag(response: &mut Vec<u8>, etag: [u8; 8]) -> Result<(), Error> {
		response.extend_from_slice(hex::encode(etag).as_bytes());
		Ok(())
	}

	fn extend_content_type(
		response: &mut Vec<u8>,
		path: &Vec<u8>,
		mime_map: &HashMap<Vec<u8>, Vec<u8>>,
	) -> Result<(), Error> {
		let mut last_dot = None;
		let mut itt = path.len().saturating_sub(1);
		loop {
			if itt <= 0 {
				break;
			}
			if path[itt] == '.' as u8 {
				last_dot = Some(itt);
				break;
			}
			itt -= 1;
		}

		match last_dot {
			Some(last_dot) => {
				let mime = &path[(1 + last_dot)..];
				match mime_map.get(&mime.to_vec()) {
					Some(ctype) => {
						response.extend_from_slice(CONTENT_TYPE_BYTES);
						response.extend_from_slice(&ctype);
					}
					None => {}
				}
			}
			None => {}
		}

		Ok(())
	}

	fn send_headers(
		conn_data: &ConnectionData,
		config: &HttpConfig,
		len: u64,
		chunk: Option<&[u8]>,
		now: u128,
		last_modified: u128,
		http_version: &HttpVersion,
		etag: [u8; 8],
		range: Option<(usize, usize)>,
		path: &Vec<u8>,
		mime_map: &HashMap<Vec<u8>, Vec<u8>>,
	) -> Result<(), Error> {
		let mut response = vec![];
		match http_version {
			HttpVersion::V10 | HttpVersion::Unknown => response.extend_from_slice(&HTTP10_BYTES),
			HttpVersion::V11 => response.extend_from_slice(&HTTP11_BYTES),
			HttpVersion::V20 => response.extend_from_slice(&HTTP11_BYTES),
		}
		match range {
			Some(_range) => response.extend_from_slice(&HTTP_PARTIAL_206_HEADERS_VEC[0]),
			None => response.extend_from_slice(&HTTP_OK_200_HEADERS_VEC[0]),
		}
		response.extend_from_slice(&config.server_name);
		response.extend_from_slice(&HTTP_OK_200_HEADERS_VEC[1]);
		Self::extend_date(&mut response, now)?;
		response.extend_from_slice(&HTTP_OK_200_HEADERS_VEC[2]);
		Self::extend_date(&mut response, last_modified)?;
		response.extend_from_slice(&HTTP_OK_200_HEADERS_VEC[3]);
		match http_version {
			HttpVersion::V10 | HttpVersion::Unknown => response.extend_from_slice(&CLOSE_BYTES),
			HttpVersion::V11 | HttpVersion::V20 => response.extend_from_slice(&KEEP_ALIVE_BYTES),
		}
		response.extend_from_slice(&HTTP_OK_200_HEADERS_VEC[4]);
		match range {
			Some(range) => {
				let mut rlen = (1 + range.1).saturating_sub(range.0).try_into()?;
				if rlen > len {
					rlen = len;
				}

				Self::extend_len(&mut response, rlen)?
			}
			None => Self::extend_len(&mut response, len)?,
		}

		Self::extend_content_type(&mut response, path, mime_map)?;

		response.extend_from_slice(&HTTP_OK_200_HEADERS_VEC[5]);
		Self::extend_etag(&mut response, etag)?;
		match range {
			Some(range) => {
				response.extend_from_slice(&HTTP_PARTIAL_206_HEADERS_VEC[1]);
				Self::extend_len(&mut response, range.0.try_into()?)?;
				response.extend_from_slice(&HTTP_PARTIAL_206_HEADERS_VEC[2]);
				Self::extend_len(&mut response, range.1.try_into()?)?;
				response.extend_from_slice(&HTTP_PARTIAL_206_HEADERS_VEC[3]);
				Self::extend_len(&mut response, len)?;
				response.extend_from_slice(&HTTP_PARTIAL_206_HEADERS_VEC[4]);
			}
			None => response.extend_from_slice(&HTTP_OK_200_HEADERS_VEC[6]),
		}

		if config.show_response_headers {
			warn!("HTTP Response Headers:\n{}", from_utf8(&response)?)?;
		}

		match range {
			Some(_range) => response.extend_from_slice(&HTTP_PARTIAL_206_HEADERS_VEC[5]),
			None => response.extend_from_slice(&HTTP_OK_200_HEADERS_VEC[7]),
		}

		match chunk {
			Some(chunk) => match range {
				Some(range) => {
					let chunk_len = chunk.len();
					let start = range.0;
					let mut end = range.1 + 1;
					if end > chunk_len {
						end = chunk_len;
					}
					if start < end {
						response.extend_from_slice(&chunk[start..end]);
					}
				}
				None => {
					response.extend_from_slice(&chunk);
				}
			},
			None => {}
		}

		conn_data.write(&response)?;

		Ok(())
	}

	fn append_buffer(nbuf: &[u8], buffer: &mut Vec<u8>) -> Result<(), Error> {
		buffer.append(&mut nbuf.to_vec());
		Ok(())
	}

	fn process_on_accept(
		conn_data: &ConnectionData,
		_ctx: &mut ConnectionContext,
		config: &HttpConfig,
		user_data: &mut Box<dyn Any + Send + Sync>,
	) -> Result<(), Error> {
		let id = conn_data.get_connection_id();
		let handle = conn_data.get_handle();
		debug!("on accept: {}, handle={}", id, handle)?;

		Self::init_user_data(user_data, config)?;
		let thread_context = user_data.downcast_mut::<ThreadContext>().unwrap();

		let cinfo = ConnectionInfo::new(conn_data.clone());
		thread_context.active_connections.insert(id, cinfo);

		Ok(())
	}

	fn process_on_close(
		conn_data: &ConnectionData,
		_ctx: &mut ConnectionContext,
		config: &HttpConfig,
		user_data: &mut Box<dyn Any + Send + Sync>,
	) -> Result<(), Error> {
		debug!("on close: {}", conn_data.get_connection_id())?;

		Self::init_user_data(user_data, config)?;
		let thread_context = user_data.downcast_mut::<ThreadContext>().unwrap();

		let connection_id = conn_data.get_connection_id();

		let conn_info = thread_context.active_connections.remove(&connection_id);

		match conn_info {
			Some(conn_info) => {
				match conn_info.proxy_info {
					Some(proxy_info) => {
						match thread_context
							.idle_proxy_connections
							.get_mut(&proxy_info.proxy_entry)
						{
							Some(map) => match map.get_mut(&proxy_info.sock_addr) {
								Some(hashset) => {
									hashset.remove(&proxy_info);
								}
								None => {}
							},
							None => {}
						}

						let state = thread_context.proxy_state.get_mut(&proxy_info.proxy_entry);
						match state {
							Some(state) => {
								state.cur_connections = state.cur_connections.saturating_sub(1);
							}
							None => {}
						}
					}
					None => {}
				}

				match conn_info.api_context {
					Some(api_context) => {
						let mut post_status = lockw!(api_context.post_status)?;
						(*post_status).is_disconnected = true;
						match &(*post_status).send {
							Some(send) => {
								let _ = send.send(());
							}
							None => {}
						}
					}
					None => {}
				}
			}
			None => {}
		}

		// async connections should be removed by user, but if left to this point, we remove.
		// we don't want to block in the general case, so we try a read lock first.
		let found = {
			let async_connections = lockr!(thread_context.async_connections)?;
			async_connections.get(&connection_id).is_some()
		};

		if found {
			let mut async_connections = lockw!(thread_context.async_connections)?;
			async_connections.remove(&connection_id);
		}

		Ok(())
	}

	fn check_log_rotation(tid: usize) -> Result<(), Error> {
		if tid == 0 {
			match rotation_status!()? {
				RotationStatus::Needed => {
					let nfile = rotate!()?;
					match nfile {
						Some(nfile) => info!("Mainlog rotated. Rotated to: '{}'", nfile)?,
						None => {}
					}
				}
				_ => {}
			}
		}

		Ok(())
	}

	fn process_on_housekeeper(
		config: &HttpConfig,
		user_data: &mut Box<dyn Any + Send + Sync>,
		evh_params: &EvhParams,
		tid: usize,
	) -> Result<(), Error> {
		Self::check_log_rotation(tid)?;
		let now = SystemTime::now().duration_since(UNIX_EPOCH)?.as_micros();
		Self::init_user_data(user_data, config)?;
		let thread_context = user_data.downcast_mut::<ThreadContext>().unwrap();

		process_health_check(thread_context, config, evh_params, tid)?;

		for (_id, connection) in &thread_context.active_connections {
			if now.saturating_sub(connection.last_data) >= config.idle_timeout * 1_000 {
				// read timeout
				connection.conn_data.close()?;
			} else if connection.last_data == connection.connection
				&& now.saturating_sub(connection.connection) >= config.connect_timeout * 1_000
			{
				// connect timeout
				connection.conn_data.close()?;
			}
		}

		Ok(())
	}

	#[rustfmt::skip]
	fn get_handle() -> Result<Handle, Error> {
		let r = socket(AddressFamily::Inet, Stream, SockFlag::empty(), None)?;
		let o: libc::c_int = 1;
		let s = mem::size_of_val(&o);

		unsafe { setsockopt(r, SOL_SOCKET, SO_REUSEPORT, &o as *const _ as *const c_void, s as socklen_t) };

		unsafe { setsockopt(r, SOL_SOCKET, SO_REUSEADDR, &o as *const _ as *const c_void, s as socklen_t) };

		Ok(r)
	}
}

fn clean(path: &mut Vec<u8>) -> Result<(), Error> {
	let mut i = 0;
	let mut prev = 0;
	let mut prev_prev = 0;
	let mut prev_prev_prev = 0;
	let mut path_len = path.len();
	loop {
		if prev_prev_prev == '/' as u8 && prev_prev == '.' as u8 && prev == '.' as u8 {
			// delete and remove prev dir
			if i < 4 {
				return Err(ErrorKind::HttpError403("Forbidden".into()).into());
			}
			let mut j = i - 4;
			loop {
				if path[j] == '/' as u8 || j <= 0 {
					break;
				}

				j -= 1;
			}
			path.drain(j..i);
			path_len = path.len();
			i = j;
			if i >= path_len {
				break;
			}
			prev = if i > 0 { path[i] } else { 0 };
			prev_prev = if i as i32 - 1 >= 0 { path[i - 1] } else { 0 };
			prev_prev_prev = if i as i32 - 2 >= 0 { path[i - 2] } else { 0 };
			continue;
		} else if prev_prev == '/' as u8 && prev == '.' as u8 {
			if i >= path_len {
				path.drain((i - 1)..);
				break;
			}
			if path[i] == '/' as u8 {
				// delete
				path.drain(i - 2..i);
				path_len = path.len();
				i = i.saturating_sub(2);
				prev = if i > 0 { path[i] } else { 0 };
				prev_prev = if i as i32 - 1 >= 0 { path[i - 1] } else { 0 };
				prev_prev_prev = if i as i32 - 2 > 0 { path[i - 2] } else { 0 };
				continue;
			}
		}
		if i >= path_len {
			break;
		}

		prev_prev_prev = prev_prev;
		prev_prev = prev;
		prev = path[i];

		i += 1;
	}

	path_len = path.len();
	if path_len > 1 && path[path_len - 1] == '/' as u8 {
		path.drain((path_len - 1)..);
	}

	Ok(())
}

#[cfg(test)]
mod test {
	use crate::http::{clean, ConnectionData, HttpConfig, HttpServer};
	use crate::types::{
		ApiContext, HealthCheck, HttpMethod, HttpVersion, ListenerType, ProxyConfig, ProxyEntry,
		ProxyRotation, Upstream,
	};
	use crate::HttpApiConfig;
	use crate::HttpHeaders;
	use nioruntime_deps::rand;
	use nioruntime_err::{Error, ErrorKind};
	use nioruntime_evh::EventHandlerConfig;
	use nioruntime_log::*;
	use nioruntime_util::bytes_find;
	use nioruntime_util::{lockr, lockw};
	use std::collections::HashMap;
	use std::collections::HashSet;
	use std::io::{Read, Write};
	use std::net::SocketAddr;
	use std::net::TcpStream;
	use std::str::FromStr;
	use std::sync::{Arc, RwLock};
	use std::thread::sleep;
	use std::time::Duration;

	debug!();

	fn setup_test_dir(name: &str) -> Result<(), Error> {
		crate::test::test::init_logger()?;

		let _ = std::fs::remove_dir_all(name);
		std::fs::create_dir_all(name)?;

		Ok(())
	}

	fn tear_down_test_dir(name: &str) -> Result<(), Error> {
		std::fs::remove_dir_all(name)?;
		Ok(())
	}

	#[test]
	fn test_http() -> Result<(), Error> {
		let root_dir = "./.test_http.nio";
		setup_test_dir(root_dir)?;

		let port = 18999;
		let config = HttpConfig {
			listeners: vec![(
				ListenerType::Plain,
				SocketAddr::from_str(&format!("127.0.0.1:{}", port)[..])?,
			)],
			webroot: format!("{}/www", root_dir).as_bytes().to_vec(),
			mainlog: format!("{}/logs/mainlog.log", root_dir),
			temp_dir: format!("{}/tmp", root_dir),
			debug: true,
			show_request_headers: true,
			..Default::default()
		};

		let mut http = HttpServer::new(config).unwrap();

		let x = Arc::new(RwLock::new(0));
		let x_clone = x.clone();
		http.set_api_handler(move |conn_data, headers, _ctx| {
			let mut x = lockw!(x)?;
			*x += 1;
			conn_data.write(b"msg")?;
			assert_eq!(headers.get_uri(), b"/api");
			assert_eq!(headers.get_query(), b"abc");
			assert_eq!(headers.get_method(), &HttpMethod::Get);
			Ok(())
		})?;
		let mut mappings = HashSet::new();
		mappings.insert(b"/api".to_vec());

		http.set_api_config(HttpApiConfig {
			mappings,
			..Default::default()
		})?;
		http.start()?;

		let mut strm =
			TcpStream::connect(SocketAddr::from_str(&format!("127.0.0.1:{}", port)[..])?)?;
		strm.write(b"GET /api?abc HTTP/1.0\r\n\r\n")?;

		let mut buf = vec![];
		buf.resize(10, 0u8);
		let mut len_sum = 0;
		loop {
			let len = strm.read(&mut buf[len_sum..])?;
			len_sum += len;
			if len_sum == 3 {
				break;
			}
		}

		assert_eq!(len_sum, 3);
		assert_eq!(&buf[0..3], &b"msg"[..]);

		loop {
			sleep(Duration::from_millis(1));
			if *(lockr!(x_clone)?) == 1 {
				break;
			}
		}

		// test partial write
		let mut strm =
			TcpStream::connect(SocketAddr::from_str(&format!("127.0.0.1:{}", port)[..])?)?;
		strm.write(b"GET /api?abc HTTP/1.1\r\n")?;
		sleep(Duration::from_millis(10));
		strm.write(b"Host: localhost\r\n")?;
		sleep(Duration::from_millis(10));
		strm.write(b"User-Agent: test\r\n")?;
		sleep(Duration::from_millis(10));
		strm.write(b"\r\n")?;

		let mut buf = vec![];
		buf.resize(10, 0u8);
		let mut len_sum = 0;
		loop {
			let len = strm.read(&mut buf[len_sum..])?;
			len_sum += len;
			if len_sum == 3 {
				break;
			}
		}

		assert_eq!(len_sum, 3);
		assert_eq!(&buf[0..3], &b"msg"[..]);

		loop {
			sleep(Duration::from_millis(1));
			if *(lockr!(x_clone)?) == 2 {
				break;
			}
		}

		http.stop()?;

		tear_down_test_dir(root_dir)?;

		Ok(())
	}

	#[test]
	fn test_async() -> Result<(), Error> {
		let root_dir = "./.test_async.nio";
		setup_test_dir(root_dir)?;

		let port = 18899;
		let config = HttpConfig {
			listeners: vec![(
				ListenerType::Plain,
				SocketAddr::from_str(&format!("127.0.0.1:{}", port)[..])?,
			)],
			webroot: format!("{}/www", root_dir).as_bytes().to_vec(),
			mainlog: format!("{}/logs/mainlog.log", root_dir),
			temp_dir: format!("{}/tmp", root_dir),
			debug: true,
			show_request_headers: true,
			evh_config: EventHandlerConfig {
				threads: 1,
				..Default::default()
			},
			..Default::default()
		};

		let mut http = HttpServer::new(config).unwrap();

		http.set_api_handler(move |conn_data, headers, ctx| {
			if headers.get_query() == b"abc" {
				debug!("sleep 5 seconds")?;
				ctx.set_async()?;
				let mut ctx_clone = ctx.clone();
				let conn_data = conn_data.clone();
				std::thread::spawn(move || -> Result<(), Error> {
					sleep(Duration::from_millis(5_000));
					conn_data.write(b"1111")?;
					ctx_clone.async_complete()?;
					Ok(())
				});
			} else {
				conn_data.write(b"2222")?;
			}

			Ok(())
		})?;
		let mut mappings = HashSet::new();
		mappings.insert(b"/api".to_vec());

		http.set_api_config(HttpApiConfig {
			mappings,
			..Default::default()
		})?;
		http.start()?;

		let mut strm =
			TcpStream::connect(SocketAddr::from_str(&format!("127.0.0.1:{}", port)[..])?)?;
		strm.write(b"GET /api?abc HTTP/1.1\r\nHost: localhost\r\n\r\n")?;
		sleep(Duration::from_millis(2500));
		strm.write(b"GET /api?def HTTP/1.1\r\nHost: localhost\r\n\r\n")?;

		let mut buf = vec![];
		buf.resize(4, 0u8);
		let mut len_sum = 0;
		loop {
			let len = strm.read(&mut buf[len_sum..])?;
			len_sum += len;
			if len_sum == 4 {
				break;
			}
		}

		assert_eq!(len_sum, 4);
		assert_eq!(&buf[0..4], &b"1111"[..]);

		let mut buf = vec![];
		buf.resize(40, 0u8);
		let mut len_sum = 0;
		loop {
			let len = strm.read(&mut buf[len_sum..])?;
			len_sum += len;
			if len_sum == 4 {
				break;
			}
		}

		assert_eq!(len_sum, 4);
		assert_eq!(&buf[0..4], &b"2222"[..]);

		let mut strm =
			TcpStream::connect(SocketAddr::from_str(&format!("127.0.0.1:{}", port)[..])?)?;
		strm.write(b"GET")?;
		sleep(Duration::from_millis(2500));
		strm.write(
			b" /api?abc HTTP/1.1\r\nHost: localhost\r\n\r\n\
GET /api?def HTTP/1.1\r\nHost: localhost\r\n\r\n",
		)?;

		let mut buf = vec![];
		buf.resize(4, 0u8);
		let mut len_sum = 0;
		loop {
			let len = strm.read(&mut buf[len_sum..])?;
			len_sum += len;
			if len_sum == 4 {
				break;
			}
		}

		assert_eq!(len_sum, 4);
		assert_eq!(&buf[0..4], &b"1111"[..]);

		let mut buf = vec![];
		buf.resize(40, 0u8);
		let mut len_sum = 0;
		loop {
			let len = strm.read(&mut buf[len_sum..])?;
			len_sum += len;
			if len_sum == 4 {
				break;
			}
		}

		assert_eq!(len_sum, 4);
		assert_eq!(&buf[0..4], &b"2222"[..]);

		http.stop()?;

		tear_down_test_dir(root_dir)?;

		Ok(())
	}

	#[test]
	fn test_restart() -> Result<(), Error> {
		let root_dir = "./.test_restart.nio";
		setup_test_dir(root_dir)?;

		let port = 18995;
		let config = HttpConfig {
			listeners: vec![(
				ListenerType::Plain,
				SocketAddr::from_str(&format!("127.0.0.1:{}", port)[..])?,
			)],
			webroot: format!("{}/www", root_dir).as_bytes().to_vec(),
			mainlog: format!("{}/logs/mainlog.log", root_dir),
			temp_dir: format!("{}/tmp", root_dir),
			debug: true,
			show_request_headers: true,
			..Default::default()
		};

		let mut http = HttpServer::new(config).unwrap();

		let x = Arc::new(RwLock::new(0));
		let x_clone = x.clone();
		http.set_api_handler(move |conn_data, headers, _ctx| {
			let mut x = lockw!(x)?;
			*x += 1;
			conn_data.write(b"msg")?;
			assert_eq!(headers.get_uri(), b"/api");
			assert_eq!(headers.get_query(), b"abc");
			assert_eq!(headers.get_version(), &HttpVersion::V10);
			assert_eq!(headers.get_method(), &HttpMethod::Get);
			Ok(())
		})?;
		let mut mappings = HashSet::new();
		mappings.insert(b"/api".to_vec());

		http.set_api_config(HttpApiConfig {
			mappings,
			..Default::default()
		})?;
		http.start()?;

		let mut strm =
			TcpStream::connect(SocketAddr::from_str(&format!("127.0.0.1:{}", port)[..])?)?;
		strm.write(b"GET /api?abc HTTP/1.0\r\n\r\n")?;

		let mut buf = vec![];
		buf.resize(10, 0u8);
		let mut len_sum = 0;
		loop {
			let len = strm.read(&mut buf[len_sum..])?;
			len_sum += len;
			if len_sum == 3 {
				break;
			}
		}
		assert_eq!(len_sum, 3);
		assert_eq!(&buf[0..3], &b"msg"[..]);

		loop {
			sleep(Duration::from_millis(1));
			if *(lockr!(x_clone)?) == 1 {
				break;
			}
		}
		http.stop()?;
		http.start()?;

		let mut strm =
			TcpStream::connect(SocketAddr::from_str(&format!("127.0.0.1:{}", port)[..])?)?;
		strm.write(b"GET /api?abc HTTP/1.0\r\n\r\n")?;

		let mut buf = vec![];
		buf.resize(10, 0u8);
		let mut len_sum = 0;
		loop {
			let len = strm.read(&mut buf[len_sum..])?;
			len_sum += len;
			if len_sum == 3 {
				break;
			}
		}

		assert_eq!(len_sum, 3);
		assert_eq!(&buf[0..3], &b"msg"[..]);
		loop {
			sleep(Duration::from_millis(1));
			if *(lockr!(x_clone)?) == 2 {
				break;
			}
		}
		http.stop()?;

		tear_down_test_dir(root_dir)?;

		Ok(())
	}

	#[test]
	fn test_forbidden() -> Result<(), Error> {
		let root_dir = "./.test_forbidden.nio";
		setup_test_dir(root_dir)?;

		let port = 18996;
		let config = HttpConfig {
			listeners: vec![(
				ListenerType::Plain,
				SocketAddr::from_str(&format!("127.0.0.1:{}", port)[..])?,
			)],
			webroot: format!("{}/www", root_dir).as_bytes().to_vec(),
			mainlog: format!("{}/logs/mainlog.log", root_dir),
			temp_dir: format!("{}/tmp", root_dir),
			debug: true,
			show_request_headers: true,
			..Default::default()
		};

		let mut http = HttpServer::new(config).unwrap();

		http.set_api_handler(move |_conn_data, _headers, _ctx| Ok(()))?;
		http.set_api_config(HttpApiConfig {
			..Default::default()
		})?;
		http.start()?;

		let mut strm =
			TcpStream::connect(SocketAddr::from_str(&format!("127.0.0.1:{}", port)[..])?)?;
		strm.write(b"GET /../test.txt HTTP/1.0\r\n\r\n")?;

		let mut buf = vec![];
		buf.resize(10000, 0u8);
		let mut len_sum = 0;
		loop {
			let len = strm.read(&mut buf[len_sum..])?;
			len_sum += len;

			let mut do_break = false;
			for i in 3..len_sum {
				if buf[i - 3] == '\r' as u8
					&& buf[i - 2] == '\n' as u8
					&& buf[i - 1] == '\r' as u8
					&& buf[i] == '\n' as u8
				{
					let str = std::str::from_utf8(&buf[0..len_sum])?;
					let index = str.find("Content-Length: ");
					let index = index.unwrap();
					let str = &str[index + 16..];
					let end = str.find("\r").unwrap();
					let mut len: usize = str[0..end].parse()?;
					len += i + 1;
					if len_sum >= len {
						do_break = true;
						break;
					}
				}
			}

			assert!(len != 0);
			if do_break {
				break;
			}
		}

		let full_response = std::str::from_utf8(&buf[0..len_sum])?;
		assert_eq!(full_response.find("403 Forbidden").is_some(), true);

		let mut strm =
			TcpStream::connect(SocketAddr::from_str(&format!("127.0.0.1:{}", port)[..])?)?;
		strm.write(b"GET /.. HTTP/1.0\r\n\r\n")?;

		let mut buf = vec![];
		buf.resize(10000, 0u8);
		let mut len_sum = 0;
		loop {
			let len = strm.read(&mut buf[len_sum..])?;
			len_sum += len;

			let mut do_break = false;
			for i in 3..len_sum {
				if buf[i - 3] == '\r' as u8
					&& buf[i - 2] == '\n' as u8
					&& buf[i - 1] == '\r' as u8
					&& buf[i] == '\n' as u8
				{
					let str = std::str::from_utf8(&buf[0..len_sum])?;
					let index = str.find("Content-Length: ");
					let index = index.unwrap();
					let str = &str[index + 16..];
					let end = str.find("\r").unwrap();
					let mut len: usize = str[0..end].parse()?;
					len += i + 1;
					if len_sum >= len {
						do_break = true;
						break;
					}
				}
			}

			assert!(len != 0);
			if do_break {
				break;
			}
		}

		let full_response = std::str::from_utf8(&buf[0..len_sum])?;
		assert_eq!(full_response.find("403 Forbidden").is_some(), true);

		http.stop()?;

		tear_down_test_dir(root_dir)?;

		Ok(())
	}

	#[test]
	fn test_file() -> Result<(), Error> {
		let root_dir = "./.test_file.nio";
		setup_test_dir(root_dir)?;

		let port = 18998;
		let config = HttpConfig {
			listeners: vec![(
				ListenerType::Plain,
				SocketAddr::from_str(&format!("127.0.0.1:{}", port)[..])?,
			)],
			webroot: format!("{}/www", root_dir).as_bytes().to_vec(),
			mainlog: format!("{}/logs/mainlog.log", root_dir),
			temp_dir: format!("{}/tmp", root_dir),
			debug: true,
			show_request_headers: true,
			..Default::default()
		};

		let mut http = HttpServer::new(config).unwrap();

		http.set_api_handler(move |_conn_data, _headers, _ctx| Ok(()))?;
		http.set_api_config(HttpApiConfig {
			..Default::default()
		})?;
		http.start()?;

		let mut strm =
			TcpStream::connect(SocketAddr::from_str(&format!("127.0.0.1:{}", port)[..])?)?;
		strm.write(b"GET /index.html HTTP/1.0\r\n\r\n")?;

		let mut buf = vec![];
		buf.resize(10000, 0u8);
		let mut len_sum = 0;
		loop {
			let len = strm.read(&mut buf[len_sum..])?;
			len_sum += len;

			let mut do_break = false;
			for i in 3..len_sum {
				if buf[i - 3] == '\r' as u8
					&& buf[i - 2] == '\n' as u8
					&& buf[i - 1] == '\r' as u8
					&& buf[i] == '\n' as u8
				{
					let str = std::str::from_utf8(&buf[0..len_sum])?;
					let index = str.find("Content-Length: ");
					let index = index.unwrap();
					let str = &str[index + 16..];
					let end = str.find("\r").unwrap();
					let mut len: usize = str[0..end].parse()?;
					len += i + 1;
					if len_sum >= len {
						do_break = true;
						break;
					}
				}
			}
			assert!(len != 0);
			if do_break {
				break;
			}
		}

		let full_response = std::str::from_utf8(&buf[0..len_sum])?;
		assert_eq!(full_response.find("Connection: close").is_some(), true);

		// test partial write
		let mut strm =
			TcpStream::connect(SocketAddr::from_str(&format!("127.0.0.1:{}", port)[..])?)?;
		strm.write(b"GET /index.html HTTP/1.0\r\n")?;
		sleep(Duration::from_millis(10));
		strm.write(b"Host: localhost\r\n")?;
		sleep(Duration::from_millis(10));
		strm.write(b"User-Agent: test\r\n")?;
		sleep(Duration::from_millis(10));
		strm.write(b"\r\n")?;

		let mut buf = vec![];
		buf.resize(10000, 0u8);
		let mut len_sum = 0;
		loop {
			let len = strm.read(&mut buf[len_sum..])?;
			len_sum += len;

			let mut do_break = false;
			for i in 3..len_sum {
				if buf[i - 3] == '\r' as u8
					&& buf[i - 2] == '\n' as u8
					&& buf[i - 1] == '\r' as u8
					&& buf[i] == '\n' as u8
				{
					let str = std::str::from_utf8(&buf[0..len_sum])?;
					let index = str.find("Content-Length: ");
					let index = index.unwrap();
					let str = &str[index + 16..];
					let end = str.find("\r").unwrap();
					let mut len: usize = str[0..end].parse()?;
					len += i + 1;
					if len_sum >= len {
						do_break = true;
						break;
					}
				}
			}
			assert!(len != 0);
			if do_break {
				break;
			}
		}

		let full_response = std::str::from_utf8(&buf[0..len_sum])?;
		assert_eq!(full_response.find("Connection: close").is_some(), true);

		http.stop()?;

		tear_down_test_dir(root_dir)?;

		Ok(())
	}

	#[test]
	fn test_timeout() -> Result<(), Error> {
		let root_dir = "./.test_timeout.nio";
		setup_test_dir(root_dir)?;

		let port = 18997;
		let config = HttpConfig {
			listeners: vec![(
				ListenerType::Plain,
				SocketAddr::from_str(&format!("127.0.0.1:{}", port)[..])?,
			)],
			mainlog: format!("{}/logs/mainlog.log", root_dir),
			temp_dir: format!("{}/tmp", root_dir),
			debug: true,
			show_request_headers: true,
			webroot: format!("{}/www", root_dir).as_bytes().to_vec(),
			connect_timeout: 2_000,
			idle_timeout: 3_000,
			..Default::default()
		};

		let mut http = HttpServer::new(config).unwrap();

		http.set_api_handler(move |_conn_data, _headers, _ctx| Ok(()))?;
		http.set_api_config(HttpApiConfig {
			..Default::default()
		})?;
		http.start()?;

		let mut strm =
			TcpStream::connect(SocketAddr::from_str(&format!("127.0.0.1:{}", port)[..])?)?;
		let mut buf = vec![];
		buf.resize(10, 0u8);
		let len = strm.read(&mut buf)?;
		assert_eq!(len, 0);

		let mut strm =
			TcpStream::connect(SocketAddr::from_str(&format!("127.0.0.1:{}", port)[..])?)?;

		strm.write(b"GET /index.html HTTP/1.1\r\n")?;
		let len = strm.read(&mut buf)?;
		assert_eq!(len, 0);

		http.stop()?;

		tear_down_test_dir(root_dir)?;
		Ok(())
	}

	#[test]
	fn test_proxy() -> Result<(), Error> {
		let root_dir = "./.test_proxy.nio";
		setup_test_dir(root_dir)?;

		let port1 = 18990;
		let port2 = 18991;

		let config1 = HttpConfig {
			listeners: vec![(
				ListenerType::Plain,
				SocketAddr::from_str(&format!("127.0.0.1:{}", port1)[..])?,
			)],
			show_request_headers: true,
			webroot: format!("{}/www", root_dir).as_bytes().to_vec(),
			mainlog: format!("{}/logs/mainlog.log", root_dir),
			temp_dir: format!("{}/tmp", root_dir),
			debug: true,
			evh_config: EventHandlerConfig {
				threads: 1,
				..Default::default()
			},
			..Default::default()
		};

		let mut extensions = HashMap::new();
		extensions.insert(
			"html".as_bytes().to_vec(),
			ProxyEntry::multi_socket_addr(
				vec![
					Upstream::new(
						SocketAddr::from_str(&format!("127.0.0.1:{}", port1)[..]).unwrap(),
						1,
					),
					Upstream::new(
						SocketAddr::from_str(&format!("127.0.0.1:{}", port2)[..]).unwrap(),
						1,
					),
				],
				100,
				Some(HealthCheck {
					check_secs: 3,
					path: "/".to_string(),
					expect_text: "n".to_string(),
				}),
				ProxyRotation::Random,
				10,
				1,
			),
		);

		let config2 = HttpConfig {
			listeners: vec![(
				ListenerType::Plain,
				SocketAddr::from_str(&format!("127.0.0.1:{}", port2)[..])?,
			)],
			webroot: format!("{}/www", root_dir).as_bytes().to_vec(),
			mainlog: format!("{}/logs/mainlog.log", root_dir),
			temp_dir: format!("{}/tmp", root_dir),
			debug: true,
			show_request_headers: true,
			proxy_config: ProxyConfig {
				extensions,
				mappings: HashMap::new(),
			},
			evh_config: EventHandlerConfig {
				threads: 1,
				..Default::default()
			},
			..Default::default()
		};

		let mut http1 = HttpServer::new(config1).unwrap();

		http1.set_api_handler(move |_conn_data, _headers, _ctx| Ok(()))?;
		http1.set_api_config(HttpApiConfig {
			..Default::default()
		})?;
		http1.start()?;

		let mut http2 = HttpServer::new(config2).unwrap();

		http2.set_api_handler(move |_conn_data, _headers, _ctx| Ok(()))?;
		http2.set_api_config(HttpApiConfig {
			..Default::default()
		})?;
		http2.start()?;

		let mut strm =
			TcpStream::connect(SocketAddr::from_str(&format!("127.0.0.1:{}", port2)[..])?)?;
		strm.write(b"GET /index.html HTTP/1.0\r\n\r\n")?;

		let mut buf = vec![];
		buf.resize(10000, 0u8);
		let mut len_sum = 0;
		loop {
			let len = strm.read(&mut buf[len_sum..])?;
			len_sum += len;

			let mut do_break = false;
			for i in 3..len_sum {
				if buf[i - 3] == '\r' as u8
					&& buf[i - 2] == '\n' as u8
					&& buf[i - 1] == '\r' as u8
					&& buf[i] == '\n' as u8
				{
					let str = std::str::from_utf8(&buf[0..len_sum])?;
					let index = str.find("Content-Length: ");
					let index = index.unwrap();
					let str = &str[index + 16..];
					let end = str.find("\r").unwrap();
					let mut len: usize = str[0..end].parse()?;
					len += i + 1;
					if len_sum >= len {
						do_break = true;
						break;
					}
				}
			}
			assert!(len != 0);
			if do_break {
				break;
			}
		}

		let full_response = std::str::from_utf8(&buf[0..len_sum])?;
		assert_eq!(full_response.find("Connection: close").is_some(), true);

		http1.stop()?;
		http2.stop()?;

		tear_down_test_dir(root_dir)?;

		Ok(())
	}

	#[test]
	fn test_range() -> Result<(), Error> {
		let root_dir = "./.test_range.nio";
		setup_test_dir(root_dir)?;

		let port = 18897;
		let config = HttpConfig {
			listeners: vec![(
				ListenerType::Plain,
				SocketAddr::from_str(&format!("127.0.0.1:{}", port)[..])?,
			)],
			webroot: format!("{}/www", root_dir).as_bytes().to_vec(),
			mainlog: format!("{}/logs/mainlog.log", root_dir),
			temp_dir: format!("{}/tmp", root_dir),
			debug: true,
			show_request_headers: true,
			..Default::default()
		};

		let mut http = HttpServer::new(config).unwrap();

		http.set_api_handler(move |_conn_data, _headers, _ctx| Ok(()))?;
		http.set_api_config(HttpApiConfig {
			..Default::default()
		})?;
		http.start()?;

		let mut strm =
			TcpStream::connect(SocketAddr::from_str(&format!("127.0.0.1:{}", port)[..])?)?;

		strm.write(b"GET /index.html HTTP/1.1\r\nHost: localhost\r\nRange: bytes=0-10\r\n\r\n")?;
		let mut buf = vec![];
		buf.resize(10000, 0u8);
		let mut len_sum = 0;
		loop {
			let len = strm.read(&mut buf[len_sum..])?;
			len_sum += len;

			let mut do_break = false;
			for i in 3..len_sum {
				if buf[i - 3] == '\r' as u8
					&& buf[i - 2] == '\n' as u8
					&& buf[i - 1] == '\r' as u8
					&& buf[i] == '\n' as u8
				{
					let str = std::str::from_utf8(&buf[0..len_sum])?;
					let index = str.find("Content-Length: ");
					let index = index.unwrap();
					let str = &str[index + 16..];
					let end = str.find("\r").unwrap();
					let mut len: usize = str[0..end].parse()?;
					len += i + 1;
					if len_sum >= len {
						do_break = true;
						break;
					}
				}
			}
			assert!(len != 0);
			if do_break {
				break;
			}
		}

		let s = bytes_find(&buf[0..len_sum], "\r\n\r\n".as_bytes()).unwrap();
		let content = &buf[(4 + s)..len_sum];
		assert_eq!(content.len(), 11);

		strm.write(b"GET /index.html HTTP/1.1\r\nHost: localhost\r\nRange: bytes=4-17\r\n\r\n")?;
		let mut buf = vec![];
		buf.resize(10000, 0u8);
		let mut len_sum = 0;
		loop {
			let len = strm.read(&mut buf[len_sum..])?;
			len_sum += len;

			let mut do_break = false;
			for i in 3..len_sum {
				if buf[i - 3] == '\r' as u8
					&& buf[i - 2] == '\n' as u8
					&& buf[i - 1] == '\r' as u8
					&& buf[i] == '\n' as u8
				{
					let str = std::str::from_utf8(&buf[0..len_sum])?;
					let index = str.find("Content-Length: ");
					let index = index.unwrap();
					let str = &str[index + 16..];
					let end = str.find("\r").unwrap();
					let mut len: usize = str[0..end].parse()?;
					len += i + 1;
					if len_sum >= len {
						do_break = true;
						break;
					}
				}
			}
			assert!(len != 0);
			if do_break {
				break;
			}
		}

		let s = bytes_find(&buf[0..len_sum], "\r\n\r\n".as_bytes()).unwrap();
		let content = &buf[(4 + s)..len_sum];
		assert_eq!(content.len(), 14);

		http.stop()?;

		tear_down_test_dir(root_dir)?;
		Ok(())
	}

	#[test]
	fn test_post1() -> Result<(), Error> {
		let root_dir = "./.test_post.nio";
		setup_test_dir(root_dir)?;

		let port = 18797;
		let config = HttpConfig {
			listeners: vec![(
				ListenerType::Plain,
				SocketAddr::from_str(&format!("127.0.0.1:{}", port)[..])?,
			)],
			webroot: format!("{}/www", root_dir).as_bytes().to_vec(),
			mainlog: format!("{}/logs/mainlog.log", root_dir),
			temp_dir: format!("{}/tmp", root_dir),
			debug: true,
			show_request_headers: true,
			..Default::default()
		};

		let mut http = HttpServer::new(config).unwrap();

		http.set_api_handler(move |conn_data, _headers, ctx| {
			ctx.set_async()?;
			let mut ctx = ctx.clone();
			let conn_data = conn_data.clone();
			std::thread::spawn(move || -> Result<(), Error> {
				let mut buf = vec![];
				buf.resize(100, 0u8);
				let len = ctx.pull_bytes(&mut buf)?;
				assert_eq!(ctx.remaining(), 0);
				assert_eq!(len, 10);
				assert_eq!(&buf[0..len], b"0123456789");
				conn_data.write(
					b"200 Ok HTTP/1.1\r\nConnection: close\r\nContent-Length: 10\r\n\r\nmsg1234567",
				)?;
				ctx.async_complete()?;

				Ok(())
			});

			Ok(())
		})?;
		let mut mappings = HashSet::new();
		mappings.insert(b"/api".to_vec());

		http.set_api_config(HttpApiConfig {
			mappings,
			..Default::default()
		})?;

		http.start()?;

		let mut strm =
			TcpStream::connect(SocketAddr::from_str(&format!("127.0.0.1:{}", port)[..])?)?;

		strm.write(
			b"POST /api HTTP/1.1\r\n\
Host: localhost\r\n\
Content-Length: 10\r\n\
\r\n0123456789",
		)?;

		let mut buf = vec![];
		buf.resize(10000, 0u8);
		let mut len_sum = 0;
		loop {
			let len = strm.read(&mut buf[len_sum..])?;
			len_sum += len;

			let mut do_break = false;
			for i in 3..len_sum {
				if buf[i - 3] == '\r' as u8
					&& buf[i - 2] == '\n' as u8
					&& buf[i - 1] == '\r' as u8
					&& buf[i] == '\n' as u8
				{
					let str = std::str::from_utf8(&buf[0..len_sum])?;
					let index = str.find("Content-Length: ");
					let index = index.unwrap();
					let str = &str[index + 16..];
					let end = str.find("\r").unwrap();
					let mut len: usize = str[0..end].parse()?;
					len += i + 1;
					if len_sum >= len {
						do_break = true;
						break;
					}
				}
			}
			assert!(len != 0);
			if do_break {
				break;
			}
		}

		assert!(bytes_find(&buf[0..len_sum], "msg1234".as_bytes()).is_some());

		tear_down_test_dir(root_dir)?;

		Ok(())
	}

	#[test]
	fn test_partial_read_post() -> Result<(), Error> {
		let root_dir = "./.test_partialreadpost.nio";
		setup_test_dir(root_dir)?;

		let port = 18791;
		let config = HttpConfig {
			listeners: vec![(
				ListenerType::Plain,
				SocketAddr::from_str(&format!("127.0.0.1:{}", port)[..])?,
			)],
			webroot: format!("{}/www", root_dir).as_bytes().to_vec(),
			mainlog: format!("{}/logs/mainlog.log", root_dir),
			temp_dir: format!("{}/tmp", root_dir),
			debug: true,
			show_request_headers: true,
			..Default::default()
		};

		let mut http = HttpServer::new(config).unwrap();

		http.set_api_handler(move |conn_data, _headers, ctx| {
			ctx.set_async()?;
			let mut ctx = ctx.clone();
			let conn_data = conn_data.clone();
			std::thread::spawn(move || -> Result<(), Error> {
				let mut buf = vec![];
				buf.resize(1, 0u8);

				let mut counter = 0;
				loop {
					let len = ctx.pull_bytes(&mut buf)?;
					assert_eq!(buf[0], '0' as u8 + counter as u8 % 10);
					assert_eq!(len, 1);
					counter += 1;
					assert_eq!(ctx.remaining(), 30 - counter);
					if ctx.remaining() == 0 {
						assert_eq!(counter, 30);
						break;
					}
				}

				conn_data.write(
					b"200 Ok HTTP/1.1\r\nConnection: close\r\nContent-Length: 10\r\n\r\nmsg1234567",
				)?;

				ctx.async_complete()?;

				Ok(())
			});

			Ok(())
		})?;
		let mut mappings = HashSet::new();
		mappings.insert(b"/api".to_vec());

		http.set_api_config(HttpApiConfig {
			mappings,
			..Default::default()
		})?;

		http.start()?;

		let mut strm =
			TcpStream::connect(SocketAddr::from_str(&format!("127.0.0.1:{}", port)[..])?)?;

		strm.write(
			b"POST /api HTTP/1.1\r\n\
Host: localhost\r\n\
Content-Length: 30\r\n\
\r\n0123456789",
		)?;

		sleep(Duration::from_millis(1000));
		strm.write(b"0123456789")?;
		sleep(Duration::from_millis(1000));
		strm.write(b"0123456789")?;

		let mut buf = vec![];
		buf.resize(10000, 0u8);
		let mut len_sum = 0;
		loop {
			let len = strm.read(&mut buf[len_sum..])?;
			len_sum += len;

			let mut do_break = false;
			for i in 3..len_sum {
				if buf[i - 3] == '\r' as u8
					&& buf[i - 2] == '\n' as u8
					&& buf[i - 1] == '\r' as u8
					&& buf[i] == '\n' as u8
				{
					let str = std::str::from_utf8(&buf[0..len_sum])?;
					let index = str.find("Content-Length: ");
					let index = index.unwrap();
					let str = &str[index + 16..];
					let end = str.find("\r").unwrap();
					let mut len: usize = str[0..end].parse()?;
					len += i + 1;
					if len_sum >= len {
						do_break = true;
						break;
					}
				}
			}
			assert!(len != 0);
			if do_break {
				break;
			}
		}

		assert!(bytes_find(&buf[0..len_sum], "msg1234".as_bytes()).is_some());

		tear_down_test_dir(root_dir)?;

		Ok(())
	}

	#[test]
	fn test_post_and_then_get() -> Result<(), Error> {
		let root_dir = "./.test_post_and_then_get.nio";
		setup_test_dir(root_dir)?;

		let port = 18792;
		let config = HttpConfig {
			listeners: vec![(
				ListenerType::Plain,
				SocketAddr::from_str(&format!("127.0.0.1:{}", port)[..])?,
			)],
			webroot: format!("{}/www", root_dir).as_bytes().to_vec(),
			mainlog: format!("{}/logs/mainlog.log", root_dir),
			temp_dir: format!("{}/tmp", root_dir),
			debug: true,
			show_request_headers: true,
			..Default::default()
		};

		let mut http = HttpServer::new(config).unwrap();

		http.set_api_handler(move |conn_data, headers, ctx| {
			ctx.set_async()?;
			let mut ctx = ctx.clone();
			let conn_data = conn_data.clone();
			match headers.get_method() {
				HttpMethod::Post => {
					std::thread::spawn(move || -> Result<(), Error> {
						let mut buf = vec![];
						buf.resize(100, 0u8);

						let len = ctx.pull_bytes(&mut buf)?;
						assert_eq!(len, 30);
						assert_eq!(ctx.remaining(), 0);

						conn_data.write(
                                                    b"200 Ok HTTP/1.1\r\nConnection: keep-alive\r\nContent-Length: 10\r\n\r\nmsg1234567",
						)?;

						ctx.async_complete()?;

						Ok(())
					});
				},
				HttpMethod::Get => {
					conn_data.write(
                                                b"200 Ok HTTP/1.1\r\nConnection: keep-alive\r\nContent-Length: 10\r\n\r\nmsg0123456",
                                        )?;
				},
				_ => {},
			}

			Ok(())
		})?;
		let mut mappings = HashSet::new();
		mappings.insert(b"/apix".to_vec());

		http.set_api_config(HttpApiConfig {
			mappings,
			..Default::default()
		})?;

		http.start()?;

		let mut strm =
			TcpStream::connect(SocketAddr::from_str(&format!("127.0.0.1:{}", port)[..])?)?;

		strm.write(
			b"POST /apix HTTP/1.1\r\n\
Host: localhost\r\n\
Content-Length: 30\r\n\
\r\n0123456789",
		)?;

		sleep(Duration::from_millis(1000));
		strm.write(b"0123456789")?;
		sleep(Duration::from_millis(1000));
		strm.write(b"0123456789GET /apix HTTP/1.1\r\nHost: localhost\r\n\r\n")?;

		let mut buf = vec![];
		buf.resize(10000, 0u8);
		let mut len_sum = 0;
		loop {
			let len = strm.read(&mut buf[len_sum..])?;
			len_sum += len;

			let mut do_break = 0;
			for i in 3..len_sum {
				if buf[i - 3] == '\r' as u8
					&& buf[i - 2] == '\n' as u8
					&& buf[i - 1] == '\r' as u8
					&& buf[i] == '\n' as u8
				{
					let str = std::str::from_utf8(&buf[0..len_sum])?;
					let index = str.find("Content-Length: ");
					let index = index.unwrap();
					let str = &str[index + 16..];
					let end = str.find("\r").unwrap();
					let mut len: usize = str[0..end].parse()?;
					len += i + 1;
					if len_sum >= len {
						do_break += 1;
						if do_break == 2 {
							break;
						}
					}
				}
			}
			assert!(len != 0);
			if do_break == 2 {
				break;
			}
		}
		assert!(bytes_find(&buf[0..len_sum], "msg1234".as_bytes()).is_some());
		assert!(bytes_find(&buf[0..len_sum], "msg0123".as_bytes()).is_some());

		strm.write(
			b"POST /apix HTTP/1.1\r\n\
Host: localhost\r\n\
Content-Length: 30\r\n\
\r\n012345678901234567890123456789GET /apix HTTP/1.1\r\nHost: localhost\r\n\r\n",
		)?;

		let mut buf = vec![];
		buf.resize(10000, 0u8);
		let mut len_sum = 0;
		loop {
			let len = strm.read(&mut buf[len_sum..])?;
			len_sum += len;

			let mut do_break = 0;
			for i in 3..len_sum {
				if buf[i - 3] == '\r' as u8
					&& buf[i - 2] == '\n' as u8
					&& buf[i - 1] == '\r' as u8
					&& buf[i] == '\n' as u8
				{
					let str = std::str::from_utf8(&buf[0..len_sum])?;
					let index = str.find("Content-Length: ");
					let index = index.unwrap();
					let str = &str[index + 16..];
					let end = str.find("\r").unwrap();
					let mut len: usize = str[0..end].parse()?;
					len += i + 1;
					if len_sum >= len {
						do_break += 1;
						if do_break == 2 {
							break;
						}
					}
				}
			}
			assert!(len != 0);
			if do_break == 2 {
				break;
			}
		}
		assert!(bytes_find(&buf[0..len_sum], "msg1234".as_bytes()).is_some());
		assert!(bytes_find(&buf[0..len_sum], "msg0123".as_bytes()).is_some());

		tear_down_test_dir(root_dir)?;

		Ok(())
	}

	#[test]
	fn test_slow_post() -> Result<(), Error> {
		let root_dir = "./.test_slowpost.nio";
		setup_test_dir(root_dir)?;

		let port = 18790;
		let config = HttpConfig {
			listeners: vec![(
				ListenerType::Plain,
				SocketAddr::from_str(&format!("127.0.0.1:{}", port)[..])?,
			)],
			webroot: format!("{}/www", root_dir).as_bytes().to_vec(),
			mainlog: format!("{}/logs/mainlog.log", root_dir),
			temp_dir: format!("{}/tmp", root_dir),
			debug: true,
			show_request_headers: true,
			..Default::default()
		};

		let mut http = HttpServer::new(config).unwrap();

		http.set_api_handler(move |conn_data, _headers, ctx| {
			ctx.set_async()?;
			let mut ctx = ctx.clone();
			let conn_data = conn_data.clone();
			std::thread::spawn(move || -> Result<(), Error> {
				let mut buf = vec![];
				buf.resize(100, 0u8);
				let len = ctx.pull_bytes(&mut buf)?;
				assert_eq!(ctx.remaining(), 0);
				assert_eq!(len, 30);
				assert_eq!(&buf[0..len], b"012345678901234567890123456789");
				conn_data.write(
					b"200 Ok HTTP/1.1\r\nConnection: close\r\nContent-Length: 10\r\n\r\nmsg1234567",
				)?;

				ctx.async_complete()?;

				Ok(())
			});

			Ok(())
		})?;
		let mut mappings = HashSet::new();
		mappings.insert(b"/api".to_vec());

		http.set_api_config(HttpApiConfig {
			mappings,
			..Default::default()
		})?;

		http.start()?;

		let mut strm =
			TcpStream::connect(SocketAddr::from_str(&format!("127.0.0.1:{}", port)[..])?)?;

		strm.write(
			b"POST /api HTTP/1.1\r\n\
Host: localhost\r\n\
Content-Length: 30\r\n\
\r\n0123456789",
		)?;

		sleep(Duration::from_millis(1000));
		strm.write(b"0123456789")?;
		sleep(Duration::from_millis(1000));
		strm.write(b"0123456789")?;

		let mut buf = vec![];
		buf.resize(10000, 0u8);
		let mut len_sum = 0;
		loop {
			let len = strm.read(&mut buf[len_sum..])?;
			len_sum += len;

			let mut do_break = false;
			for i in 3..len_sum {
				if buf[i - 3] == '\r' as u8
					&& buf[i - 2] == '\n' as u8
					&& buf[i - 1] == '\r' as u8
					&& buf[i] == '\n' as u8
				{
					let str = std::str::from_utf8(&buf[0..len_sum])?;
					let index = str.find("Content-Length: ");
					let index = index.unwrap();
					let str = &str[index + 16..];
					let end = str.find("\r").unwrap();
					let mut len: usize = str[0..end].parse()?;
					len += i + 1;
					if len_sum >= len {
						do_break = true;
						break;
					}
				}
			}
			assert!(len != 0);
			if do_break {
				break;
			}
		}

		assert!(bytes_find(&buf[0..len_sum], "msg1234".as_bytes()).is_some());

		tear_down_test_dir(root_dir)?;

		Ok(())
	}

	fn process_proxy_pipeline_request(
		conn_data: &ConnectionData,
		header: &HttpHeaders,
		ctx: &mut ApiContext,
	) -> Result<(), Error> {
		if header.get_query() == b"abc" {
			debug!("sleep 5 seconds")?;
			ctx.set_async()?;
			let mut ctx_clone = ctx.clone();
			let conn_data = conn_data.clone();
			std::thread::spawn(move || -> Result<(), Error> {
				sleep(Duration::from_millis(5_000));
				conn_data.write(
					b"200 Ok HTTP/1.1\r\nServer: test\r\nContent-Length: 10\r\n\r\na123456789",
				)?;
				ctx_clone.async_complete()?;
				Ok(())
			});
		} else {
			conn_data.write(
				b"200 Ok HTTP/1.1\r\nServer: test\r\nContent-Length: 10\r\n\r\n0123456789",
			)?;
		}
		Ok(())
	}

	#[test]
	fn test_proxy_pipeline() -> Result<(), Error> {
		let root_dir = "./.test_proxy_pipeline.nio";
		setup_test_dir(root_dir)?;

		let port1 = 18690;
		let port2 = 18691;

		let config1 = HttpConfig {
			listeners: vec![(
				ListenerType::Plain,
				SocketAddr::from_str(&format!("127.0.0.1:{}", port1)[..])?,
			)],
			show_request_headers: true,
			webroot: format!("{}/www1", root_dir).as_bytes().to_vec(),
			mainlog: format!("{}/logs1/mainlog.log", root_dir),
			temp_dir: format!("{}/tmp", root_dir),
			debug: true,
			evh_config: EventHandlerConfig {
				threads: 1,
				..Default::default()
			},
			..Default::default()
		};

		let mut extensions = HashMap::new();
		extensions.insert(
			"api".as_bytes().to_vec(),
			ProxyEntry::multi_socket_addr(
				vec![Upstream::new(
					SocketAddr::from_str(&format!("127.0.0.1:{}", port1)[..]).unwrap(),
					1,
				)],
				100,
				Some(HealthCheck {
					check_secs: 3,
					path: "/".to_string(),
					expect_text: "n".to_string(),
				}),
				ProxyRotation::Random,
				10,
				1,
			),
		);

		let config2 = HttpConfig {
			listeners: vec![(
				ListenerType::Plain,
				SocketAddr::from_str(&format!("127.0.0.1:{}", port2)[..])?,
			)],
			webroot: format!("{}/www2", root_dir).as_bytes().to_vec(),
			mainlog: format!("{}/logs2/mainlog.log", root_dir),
			temp_dir: format!("{}/tmp", root_dir),
			debug: true,
			show_request_headers: true,
			proxy_config: ProxyConfig {
				extensions,
				mappings: HashMap::new(),
			},
			evh_config: EventHandlerConfig {
				threads: 1,
				..Default::default()
			},
			..Default::default()
		};

		let mut http1 = HttpServer::new(config1).unwrap();

		http1.set_api_handler(move |conn_data, headers, ctx| {
			process_proxy_pipeline_request(conn_data, headers, ctx)?;
			Ok(())
		})?;
		let mut extensions = HashSet::new();
		extensions.insert("api".as_bytes().to_vec());

		http1.set_api_config(HttpApiConfig {
			extensions: extensions.clone(),
			..Default::default()
		})?;
		http1.start()?;

		let mut http2 = HttpServer::new(config2).unwrap();

		http2.set_api_handler(move |_conn_data, _headers, _ctx| Ok(()))?;
		http2.set_api_config(HttpApiConfig {
			..Default::default()
		})?;
		http2.start()?;

		let mut strm =
			TcpStream::connect(SocketAddr::from_str(&format!("127.0.0.1:{}", port2)[..])?)?;
		strm.write(b"GET /index.api?abc HTTP/1.1\r\nHost: localhost\r\n\r\n")?;
		strm.write(b"GET /index.api HTTP/1.1\r\nHost: localhost\r\n\r\n")?;

		let mut buf = vec![];
		buf.resize(10000, 0u8);
		let mut len_sum = 0;
		loop {
			let len = strm.read(&mut buf[len_sum..])?;
			len_sum += len;

			let mut do_break = false;
			for i in 3..len_sum {
				if buf[i - 3] == '\r' as u8
					&& buf[i - 2] == '\n' as u8
					&& buf[i - 1] == '\r' as u8
					&& buf[i] == '\n' as u8
				{
					let str = std::str::from_utf8(&buf[0..len_sum])?;
					let index = str.find("Content-Length: ");
					let index = index.unwrap();
					let str = &str[index + 16..];
					let end = str.find("\r").unwrap();
					let mut len: usize = str[0..end].parse()?;
					len += i + 3;
					if len_sum >= len {
						do_break = true;
						break;
					}
				}
			}
			assert!(len != 0);
			if do_break {
				break;
			}
		}

		let full_response = std::str::from_utf8(&buf[0..len_sum])?;
		assert_eq!(full_response.find("a123456789").is_some(), true);

		if len_sum > 65 {
			// if we got the second response too
			assert_eq!(full_response.find("0123456789").is_some(), true);
			assert!(
				full_response.find("0123456789").unwrap()
					> full_response.find("a123456789").unwrap()
			);
		} else {
			let mut buf = vec![];
			buf.resize(10000, 0u8);
			let mut len_sum = 0;
			loop {
				let len = strm.read(&mut buf[len_sum..])?;
				len_sum += len;

				let mut do_break = false;
				for i in 3..len_sum {
					if buf[i - 3] == '\r' as u8
						&& buf[i - 2] == '\n' as u8
						&& buf[i - 1] == '\r' as u8
						&& buf[i] == '\n' as u8
					{
						let str = std::str::from_utf8(&buf[0..len_sum])?;
						let index = str.find("Content-Length: ");
						let index = index.unwrap();
						let str = &str[index + 16..];
						let end = str.find("\r").unwrap();
						let mut len: usize = str[0..end].parse()?;
						len += i + 3;
						if len_sum >= len {
							do_break = true;
							break;
						}
					}
				}
				assert!(len != 0);
				if do_break {
					break;
				}
			}

			let full_response = std::str::from_utf8(&buf[0..len_sum])?;
			assert_eq!(full_response.find("0123456789").is_some(), true);
		}

		http1.stop()?;
		http2.stop()?;

		tear_down_test_dir(root_dir)?;

		Ok(())
	}

	#[test]
	fn test_multi_slab() -> Result<(), Error> {
		let root_dir = "./.test_multi_slab.nio";
		setup_test_dir(root_dir)?;

		let port = 18740;
		let config = HttpConfig {
			listeners: vec![(
				ListenerType::Plain,
				SocketAddr::from_str(&format!("127.0.0.1:{}", port)[..])?,
			)],
			content_upload_slab_count: 1000,
			content_upload_slab_size: 8,

			webroot: format!("{}/www", root_dir).as_bytes().to_vec(),
			mainlog: format!("{}/logs/mainlog.log", root_dir),
			temp_dir: format!("{}/tmp", root_dir),
			debug: true,
			show_request_headers: true,
			..Default::default()
		};

		let mut http = HttpServer::new(config).unwrap();

		http.set_api_handler(move |conn_data, _headers, ctx| {
			ctx.set_async()?;
			let mut ctx = ctx.clone();
			let conn_data = conn_data.clone();
			std::thread::spawn(move || -> Result<(), Error> {
				let mut buf = vec![];
				buf.resize(100, 0u8);
				let len = ctx.pull_bytes(&mut buf)?;
				assert_eq!(ctx.remaining(), 0);
				assert_eq!(len, 30);
				assert_eq!(&buf[0..len], b"012345678901234567890123456789");
				conn_data.write(
					b"200 Ok HTTP/1.1\r\nConnection: close\r\nContent-Length: 10\r\n\r\nmsg1234567",
				)?;

				ctx.async_complete()?;

				Ok(())
			});

			Ok(())
		})?;
		let mut mappings = HashSet::new();
		mappings.insert(b"/api".to_vec());

		http.set_api_config(HttpApiConfig {
			mappings,
			..Default::default()
		})?;

		http.start()?;

		let mut strm =
			TcpStream::connect(SocketAddr::from_str(&format!("127.0.0.1:{}", port)[..])?)?;

		strm.write(
			b"POST /api HTTP/1.1\r\n\
Host: localhost\r\n\
Content-Length: 30\r\n\
\r\n0123456789",
		)?;

		sleep(Duration::from_millis(1000));
		strm.write(b"0123456789")?;
		sleep(Duration::from_millis(1000));
		strm.write(b"0123456789")?;

		let mut buf = vec![];
		buf.resize(10000, 0u8);
		let mut len_sum = 0;
		loop {
			let len = strm.read(&mut buf[len_sum..])?;
			len_sum += len;

			let mut do_break = false;
			for i in 3..len_sum {
				if buf[i - 3] == '\r' as u8
					&& buf[i - 2] == '\n' as u8
					&& buf[i - 1] == '\r' as u8
					&& buf[i] == '\n' as u8
				{
					let str = std::str::from_utf8(&buf[0..len_sum])?;
					let index = str.find("Content-Length: ");
					let index = index.unwrap();
					let str = &str[index + 16..];
					let end = str.find("\r").unwrap();
					let mut len: usize = str[0..end].parse()?;
					len += i + 1;
					if len_sum >= len {
						do_break = true;
						break;
					}
				}
			}
			assert!(len != 0);
			if do_break {
				break;
			}
		}

		assert!(bytes_find(&buf[0..len_sum], "msg1234".as_bytes()).is_some());

		tear_down_test_dir(root_dir)?;

		Ok(())
	}

	#[test]
	fn test_proxy_post() -> Result<(), Error> {
		let root_dir = "./.test_proxy_post.nio";
		setup_test_dir(root_dir)?;

		let port1 = 17990;
		let port2 = 17991;

		let config1 = HttpConfig {
			listeners: vec![(
				ListenerType::Plain,
				SocketAddr::from_str(&format!("127.0.0.1:{}", port1)[..])?,
			)],
			show_request_headers: true,
			webroot: format!("{}/www", root_dir).as_bytes().to_vec(),
			mainlog: format!("{}/logs/mainlog.log", root_dir),
			temp_dir: format!("{}/tmp", root_dir),
			debug: true,
			evh_config: EventHandlerConfig {
				threads: 1,
				..Default::default()
			},
			..Default::default()
		};

		let mut extensions = HashMap::new();
		extensions.insert(
			"html".as_bytes().to_vec(),
			ProxyEntry::multi_socket_addr(
				vec![
					Upstream::new(
						SocketAddr::from_str(&format!("127.0.0.1:{}", port1)[..]).unwrap(),
						1,
					),
					Upstream::new(
						SocketAddr::from_str(&format!("127.0.0.1:{}", port2)[..]).unwrap(),
						1,
					),
				],
				100,
				None,
				ProxyRotation::Random,
				10,
				1,
			),
		);

		let config2 = HttpConfig {
			listeners: vec![(
				ListenerType::Plain,
				SocketAddr::from_str(&format!("127.0.0.1:{}", port2)[..])?,
			)],
			webroot: format!("{}/www", root_dir).as_bytes().to_vec(),
			mainlog: format!("{}/logs/mainlog.log", root_dir),
			temp_dir: format!("{}/tmp", root_dir),
			debug: true,
			show_request_headers: true,
			proxy_config: ProxyConfig {
				extensions,
				mappings: HashMap::new(),
			},
			evh_config: EventHandlerConfig {
				threads: 1,
				..Default::default()
			},
			..Default::default()
		};

		let mut http1 = HttpServer::new(config1).unwrap();
		let mut http2 = HttpServer::new(config2).unwrap();

		let mut mappings = HashSet::new();
		mappings.insert("/api_proxy_post.html".as_bytes().to_vec());
		mappings.insert("/api_proxy_post2.html".as_bytes().to_vec());
		http1.set_api_handler(move |conn_data, headers, ctx| {
                        match headers.get_method() {
                            HttpMethod::Get => {
                                conn_data.write(
                                    b"200 Ok HTTP/1.1\r\nConnection: keep-alive\r\nContent-Length: 7\r\n\r\nhello\r\n"
                                )?;
                            },
                            _ => {
			        ctx.set_async()?;
			        let mut ctx = ctx.clone();
			        let conn_data = conn_data.clone();
			        std::thread::spawn(move || -> Result<(), Error> {
				    let mut buf = vec![];
				    buf.resize(100, 0u8);
				    let len = ctx.pull_bytes(&mut buf)?;
				    conn_data.write(
					format!(
                                            "200 Ok HTTP/1.1\r\nConnection: keep-alive\r\nContent-Length: {}\r\n\r\nContent: {}",
                                            len + 9, std::str::from_utf8(&buf[0..len])?
                                        ).as_bytes(),
				    )?;
				    ctx.async_complete()?;
                                    Ok(())
			        });
                            },
                        }
			Ok(())
		})?;
		http1.set_api_config(HttpApiConfig {
			mappings,
			..Default::default()
		})?;

		http2.set_api_handler(move |_conn_data, _headers, _ctx| Ok(()))?;
		http2.set_api_config(HttpApiConfig {
			..Default::default()
		})?;

		http1.start()?;
		http2.start()?;

		let mut strm =
			TcpStream::connect(SocketAddr::from_str(&format!("127.0.0.1:{}", port2)[..])?)?;
		strm.write(b"POST /api_proxy_post.html HTTP/1.1\r\nHost: localhost\r\nContent-Length: 10\r\n\r\nabcdefghij")?;

		let mut buf = vec![];
		buf.resize(10000, 0u8);
		let mut len_sum = 0;
		loop {
			let len = strm.read(&mut buf[len_sum..])?;
			len_sum += len;

			let mut do_break = false;
			for i in 3..len_sum {
				if buf[i - 3] == '\r' as u8
					&& buf[i - 2] == '\n' as u8
					&& buf[i - 1] == '\r' as u8
					&& buf[i] == '\n' as u8
				{
					let str = std::str::from_utf8(&buf[0..len_sum])?;
					let index = str.find("Content-Length: ");
					let index = index.unwrap();
					let str = &str[index + 16..];
					let end = str.find("\r").unwrap();
					let mut len: usize = str[0..end].parse()?;
					len += i + 1;
					if len_sum >= len {
						do_break = true;
						break;
					}
				}
			}
			assert!(len != 0);
			if do_break {
				break;
			}
		}

		let full_response = std::str::from_utf8(&buf[0..len_sum])?;
		assert_eq!(full_response.find("abcdefghij").is_some(), true);
		sleep(Duration::from_millis(5000));

		strm.write(b"POST /api_proxy_post.html HTTP/1.1\r\nHost: localhost\r\nContent-Length: 10\r\n\r\nabcdqq")?;
		sleep(Duration::from_millis(1000));
		strm.write(b"ghiq")?;

		let mut buf = vec![];
		buf.resize(10000, 0u8);
		let mut len_sum = 0;
		loop {
			let len = strm.read(&mut buf[len_sum..])?;
			len_sum += len;

			let mut do_break = false;
			for i in 3..len_sum {
				if buf[i - 3] == '\r' as u8
					&& buf[i - 2] == '\n' as u8
					&& buf[i - 1] == '\r' as u8
					&& buf[i] == '\n' as u8
				{
					let str = std::str::from_utf8(&buf[0..len_sum])?;
					let index = str.find("Content-Length: ");
					let index = index.unwrap();
					let str = &str[index + 16..];
					let end = str.find("\r").unwrap();
					let mut len: usize = str[0..end].parse()?;
					len += i + 1;
					if len_sum >= len {
						do_break = true;
						break;
					}
				}
			}
			assert!(len != 0);
			if do_break {
				break;
			}
		}

		let full_response = std::str::from_utf8(&buf[0..len_sum])?;
		assert_eq!(full_response.find("abcdqqghiq").is_some(), true);

		strm.write(b"GET /api_proxy_post2.html HTTP/1.1\r\nHost: localhost\r\n\r\n")?;

		let mut buf = vec![];
		buf.resize(10000, 0u8);
		let mut len_sum = 0;
		loop {
			let len = strm.read(&mut buf[len_sum..])?;
			len_sum += len;

			let mut do_break = false;
			for i in 3..len_sum {
				if buf[i - 3] == '\r' as u8
					&& buf[i - 2] == '\n' as u8
					&& buf[i - 1] == '\r' as u8
					&& buf[i] == '\n' as u8
				{
					let str = std::str::from_utf8(&buf[0..len_sum])?;
					let index = str.find("Content-Length: ");
					let index = index.unwrap();
					let str = &str[index + 16..];
					let end = str.find("\r").unwrap();
					let mut len: usize = str[0..end].parse()?;
					len += i + 1;
					if len_sum >= len {
						do_break = true;
						break;
					}
				}
			}
			assert!(len != 0);
			if do_break {
				break;
			}
		}

		let full_response = std::str::from_utf8(&buf[0..len_sum])?;
		assert_eq!(full_response.find("hello").is_some(), true);

		http1.stop()?;
		http2.stop()?;
		tear_down_test_dir(root_dir)?;

		Ok(())
	}

	#[test]
	fn test_clean() -> Result<(), Error> {
		crate::test::test::init_logger()?;
		let mut path = "/abc".as_bytes().to_vec();
		clean(&mut path)?;
		assert_eq!("/abc".as_bytes(), path);

		let mut path = "/abc/".as_bytes().to_vec();
		clean(&mut path)?;
		assert_eq!("/abc".as_bytes(), path);

		let mut path = "/abc/def/../ok".as_bytes().to_vec();
		clean(&mut path)?;
		assert_eq!("/abc/ok", std::str::from_utf8(&path)?);

		let mut path = "/abc/def/./ok".as_bytes().to_vec();
		clean(&mut path)?;
		assert_eq!("/abc/def/ok", std::str::from_utf8(&path)?);

		let mut path = "/abc/def/./ok/./abc".as_bytes().to_vec();
		clean(&mut path)?;
		assert_eq!("/abc/def/ok/abc", std::str::from_utf8(&path)?);

		let mut path = "/abc/def/././ghi".as_bytes().to_vec();
		clean(&mut path)?;
		assert_eq!("/abc/def/ghi", std::str::from_utf8(&path)?);

		let mut path = "/x/abcdef/../ghi/def/abc/../xyz".as_bytes().to_vec();
		clean(&mut path)?;
		assert_eq!("/x/ghi/def/xyz", std::str::from_utf8(&path)?);

		let mut path = "/x/abcdef/../ghi/def/abc/../xyz/".as_bytes().to_vec();
		clean(&mut path)?;
		assert_eq!("/x/ghi/def/xyz", std::str::from_utf8(&path)?);

		let mut path = "/abcdefghji/../xyz".as_bytes().to_vec();
		clean(&mut path)?;
		assert_eq!("/xyz", std::str::from_utf8(&path)?);

		let mut path = "/../abcdefghji/../xyz".as_bytes().to_vec();
		assert!(clean(&mut path).is_err());

		let mut path = "/abcdefghji/../xyz/../ok/1/2".as_bytes().to_vec();
		clean(&mut path)?;
		assert_eq!("/ok/1/2", std::str::from_utf8(&path)?);

		let mut path = "/abcdefghji/../xyz/.././ok/1/2".as_bytes().to_vec();
		clean(&mut path)?;
		assert_eq!("/ok/1/2", std::str::from_utf8(&path)?);

		let mut path = "/abcdefghji/../xyz/.././ok/1/2/".as_bytes().to_vec();
		clean(&mut path)?;
		assert_eq!("/ok/1/2", std::str::from_utf8(&path)?);

		let mut path = "/home/abc/.niohttpd/1".as_bytes().to_vec();
		clean(&mut path)?;
		assert_eq!("/home/abc/.niohttpd/1", std::str::from_utf8(&path)?);

		let mut path = "/..".as_bytes().to_vec();
		assert!(clean(&mut path).is_err());

		let mut path = "/.".as_bytes().to_vec();
		clean(&mut path)?;
		assert_eq!("/", std::str::from_utf8(&path)?);

		Ok(())
	}
}
