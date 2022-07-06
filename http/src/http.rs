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
use crate::stats::LOG_ITEM_SIZE;
use crate::stats::{HttpStats, MAX_LOG_STR_LEN};
use crate::types::*;
use crate::websocket::{
	process_websocket_data, send_websocket_message, WebSocketMessage, WebSocketMessageType,
};
use crate::LogItem;
use include_dir::include_dir;
use nioruntime_deps::base58::ToBase58;
use nioruntime_deps::base64;
use nioruntime_deps::bytefmt;
use nioruntime_deps::chrono::{DateTime, Datelike, NaiveDateTime, Timelike, Utc, Weekday};
use nioruntime_deps::colored::Colorize;
use nioruntime_deps::dirs;
use nioruntime_deps::flate2::write::GzEncoder;
use nioruntime_deps::flate2::Compression;
use nioruntime_deps::fsutils;
use nioruntime_deps::hex;
use nioruntime_deps::libc::fcntl;
use nioruntime_deps::libc::read;
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
use nioruntime_deps::rand_core::{OsRng, RngCore};
use nioruntime_deps::sha1::Sha1;
use nioruntime_deps::sha2::{Digest, Sha256};
use nioruntime_err::{Error, ErrorKind};
use nioruntime_evh::{ConnectionContext, ConnectionData};
use nioruntime_evh::{EventHandler, EvhParams};
use nioruntime_log::*;
use nioruntime_util::bytes_eq;
use nioruntime_util::bytes_find;
use nioruntime_util::slabs::SlabAllocator;
use nioruntime_util::threadpool::StaticThreadPool;
use nioruntime_util::StaticHash;
use nioruntime_util::StaticQueue;
use nioruntime_util::{lockr, lockw};
use nioruntime_util::{DataHolder, StepAllocator};
use std::any::Any;
use std::collections::{HashMap, HashSet};
use std::convert::TryInto;
use std::fs::{metadata, File, Metadata};
use std::io::Write;
use std::mem;
use std::net::SocketAddr;
use std::net::TcpListener;
use std::os::unix::io::AsRawFd;
use std::os::unix::io::FromRawFd;
use std::os::unix::prelude::RawFd;
use std::path::PathBuf;
use std::pin::Pin;
use std::str::from_utf8;
use std::sync::{Arc, RwLock};
use std::time::{Instant, SystemTime, UNIX_EPOCH};

#[cfg(unix)]
type Handle = RawFd;
#[cfg(windows)]
type Handle = u64;

info!();

const WS_ADMIN_GET_STATS_REQUEST: u8 = 0u8;
const WS_ADMIN_GET_STATS_RESPONSE: u8 = 0u8;
const WS_ADMIN_PING: u8 = 1u8;
const WS_ADMIN_PONG: u8 = 1u8;
const WS_ADMIN_GET_STATS_AFTER_TIMESTAMP_REQUEST: u8 = 2u8;
const WS_ADMIN_GET_RECENT_REQUESTS: u8 = 3u8;
const WS_ADMIN_RECENT_REQUESTS_RESPONSE: u8 = 3u8;
const WS_ADMIN_REQUEST_CHART_REQUEST: u8 = 4u8;
const WS_ADMIN_REQUEST_CHART_RESPONSE: u8 = 4u8;

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

pub struct HttpServer<ApiHandler, WsHandler> {
	config: HttpConfig,
	_listeners: Vec<TcpListener>,
	api_config: Arc<RwLock<HttpApiConfig>>,
	api_handler: Option<Pin<Box<ApiHandler>>>,
	ws_handler: Option<Pin<Box<WsHandler>>>,
	stat_handler: StatHandler,
	evh_params: Option<EvhParams>,
	internal_files: HashMap<String, Vec<u8>>,
}

impl<ApiHandler, WsHandler> HttpServer<ApiHandler, WsHandler>
where
	ApiHandler: Fn(&ConnectionData, &HttpHeaders, &mut ApiContext) -> Result<(), Error>
		+ Send
		+ 'static
		+ Clone
		+ Sync
		+ Unpin,
	WsHandler: Fn(&ConnectionData, &Vec<u8>, WebSocketMessage) -> Result<bool, Error>
		+ Send
		+ 'static
		+ Clone
		+ Sync
		+ Unpin,
{
	pub fn new(mut config: HttpConfig) -> Result<Self, Error> {
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

		let stat_handler = StatHandler::new(
			config.main_log_queue_size,
			config.evh_config.threads,
			config.debug_log_queue,
			config.request_log_config.clone(),
			config.lmdb_dir.clone(),
			config.debug_show_stats,
			config.stats_frequency,
		)?;

		if config.admin_uri.len() == 0 {
			let mut key = [0u8; 32];
			OsRng.fill_bytes(&mut key);
			let random_u64_1 = OsRng.next_u64();
			let random_u64_2 = OsRng.next_u64();
			let random_u64_3 = OsRng.next_u64();
			let random_u64_4 = OsRng.next_u64();
			let mut rand_bytes = vec![];
			rand_bytes.append(&mut random_u64_1.to_be_bytes().to_vec());
			rand_bytes.append(&mut random_u64_2.to_be_bytes().to_vec());
			rand_bytes.append(&mut random_u64_3.to_be_bytes().to_vec());
			rand_bytes.append(&mut random_u64_4.to_be_bytes().to_vec());
			let mut rand_bytes = rand_bytes.to_base58().as_bytes().to_vec();
			let mut admin_uri = vec!['/' as u8];
			admin_uri.append(&mut rand_bytes);
			admin_uri.push('/' as u8);
			config.admin_uri = admin_uri;
		}

		Ok(Self {
			config,
			_listeners: vec![],
			api_config: Arc::new(RwLock::new(HttpApiConfig::default())),
			api_handler: None,
			ws_handler: None,
			evh_params: None,
			stat_handler,
			internal_files: HashMap::new(),
		})
	}

	pub fn stop(&mut self) -> Result<(), Error> {
		match &self.evh_params {
			Some(e) => e.stop()?,
			_ => {}
		}
		self._listeners = vec![];
		Ok(())
	}

	pub fn start(&mut self) -> Result<(), Error> {
		self.init_internal()?;

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

		let thread_pool = StaticThreadPool::new()?;
		thread_pool.start(self.config.evh_config.threads)?;
		let thread_pool = Arc::new(RwLock::new(thread_pool));

		let api_config = self.api_config.clone();
		let api_handler = self.api_handler.clone();
		let ws_handler = self.ws_handler.clone();
		let stat_handler = self.stat_handler.clone();
		let internal = self.internal_files.clone();

		evh.set_on_read(move |conn_data, buf, ctx, user_data| {
			let thread_context = Self::init_user_data(user_data, &config1, &stat_handler)?;
			let (nconns, nupdates) = match Self::process_on_read(
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
				&stat_handler,
				&internal,
				&thread_pool,
			) {
				Ok((nconns, nupdates)) => (nconns, nupdates),
				Err(e) => {
					error!("on_read returned error: {}", e)?;
					(vec![], vec![])
				}
			};
			for nconn in nconns {
				let conn_data = nconn.conn_data.unwrap();
				let connection_id = conn_data.get_connection_id();
				let connection_info = insert_step_allocator(
					conn_data,
					&mut thread_context.active_connections,
					&mut thread_context.active_connection_index_map,
				)?;
				let connection_info = thread_context
					.active_connections
					.get_mut(connection_info)?
					.data_as_mut::<ConnectionInfo>();
				match connection_info {
					Some(connection_info) => {
						connection_info.proxy_info = nconn.proxy_info;
					}
					None => {
						warn!(
							"no connection info found for connection_id = {}",
							connection_id,
						)?;
					}
				}
			}

			for nupdate in nupdates {
				match active_connection_get_mut(
					nupdate.1,
					&mut thread_context.active_connections,
					&mut thread_context.active_connection_index_map,
				) {
					Ok(conn_info) => match conn_info {
						Some(conn_info) => match conn_info.proxy_info.as_mut() {
							Some(proxy_info) => {
								let now = SystemTime::now();
								proxy_info.response_conn_data = Some(nupdate.0.clone());
								proxy_info.request_start_time =
									now.duration_since(UNIX_EPOCH)?.as_micros();
							}
							None => {
								return Err(ErrorKind::InternalError(
									"proxy connection not found".into(),
								)
								.into());
							}
						},
						None => {
							return Err(ErrorKind::InternalError(
								"proxy connection not found".into(),
							)
							.into());
						}
					},
					Err(e) => {
						return Err(ErrorKind::InternalError(format!(
							"proxy connection not found due to: {}",
							e
						))
						.into());
					}
				}
			}

			Self::update_thread_context(thread_context, &config1, &cache)?;

			Ok(())
		})?;

		let stat_handler = self.stat_handler.clone();
		evh.set_on_accept(move |conn_data, ctx, user_data| {
			Self::process_on_accept(conn_data, ctx, &config2, user_data, &stat_handler)
		})?;
		let stat_handler = self.stat_handler.clone();
		evh.set_on_close(move |conn_data, ctx, user_data| {
			Self::process_on_close(conn_data, ctx, &config3, user_data, &stat_handler)
		})?;
		evh.set_on_panic(move || Ok(()))?;
		let stat_handler = self.stat_handler.clone();
		evh.set_on_housekeep(move |user_data, tid| {
			match Self::process_on_housekeeper(
				&config4,
				user_data,
				&evh_params_clone,
				tid,
				&stat_handler,
			) {
				Ok(_) => {}
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
				self.config.listeners[i].2.clone()
			} else {
				None
			};
			evh.add_listener_handles(handles, tls_config)?;
		}

		self.run_stats_processor()?;

		self.show_config()?;

		set_config_option!(Settings::Level, true)?;
		let server_startup = format!(
			"Server started in {} ms.",
			self.config.start.elapsed().as_millis()
		);
		info!("{}", server_startup.cyan())?;
		set_config_option!(Settings::LineNum, false)?;
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

		if config.gzip_compression_level > 10 {
			return Err(ErrorKind::Configuration(format!(
                                        "gzip_compression_level must be between 0 and 10 inclusive. The value {} was specified",
                                        config.gzip_compression_level,
                                ))
                                .into());
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

		let mut virtual_host_map = HashMap::new();
		for (k, v) in &self.config.virtual_hosts {
			virtual_host_map.insert(from_utf8(&k)?.to_string(), from_utf8(&v)?.to_string());
		}

		let mut virtual_ip_map = HashMap::new();
		for (k, v) in &self.config.virtual_ips {
			virtual_ip_map.insert(k, from_utf8(&v)?.to_string());
		}

		self.startup_line("virtual_hosts", &format!("{:?}", virtual_host_map))?;
		self.startup_line("virtual_ips", &format!("{:?}", virtual_ip_map))?;

		self.startup_line(
			"requestlog",
			&self.config.request_log_config.file_path.as_ref().unwrap(),
		)?;

		self.startup_line(
			"requestlog_max_age",
			&Self::format_time(self.config.request_log_config.max_age_millis),
		)?;
		self.startup_line(
			"requestlog_max_size",
			&Self::format_bytes(self.config.request_log_config.max_size.try_into()?),
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

		let mut extensions = "[".to_string();
		let mut first = true;
		for extension in &self.config.gzip_extensions {
			if first {
				extensions = format!("{}{}", extensions, std::str::from_utf8(&extension)?);
			} else {
				extensions = format!("{}, {}", extensions, std::str::from_utf8(&extension)?);
			};
			first = false;
		}
		let extensions = format!("{}]", extensions);
		self.startup_line("gzip_extensions", &extensions)?;

		self.startup_line(
			"gzip_compression_level",
			&format!(
				"{}",
				self.config
					.gzip_compression_level
					.to_formatted_string(&Locale::en)
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
			"max_active_connections",
			&format!(
				"{}",
				self.config
					.max_active_connections
					.to_formatted_string(&Locale::en)
			)[..],
		)?;

		self.startup_line(
			"max_async_connections",
			&format!(
				"{}",
				self.config
					.max_async_connections
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

		self.startup_line(
			"thread_log_queue_size",
			&format!(
				"{}",
				self.config
					.thread_log_queue_size
					.to_formatted_string(&Locale::en)
			)[..],
		)?;

		self.startup_line(
			"main_log_queue_size",
			&format!(
				"{}",
				self.config
					.main_log_queue_size
					.to_formatted_string(&Locale::en)
			)[..],
		)?;

		self.startup_line(
			"stats_frequency",
			&format!(
				"{}",
				Self::format_time(self.config.stats_frequency.try_into()?)
			)[..],
		)?;

		info_no_ts!("{}", SEPARATOR)?;
		info_no_ts!(
			"{}:\nhttp://127.0.0.1:8080{}",
			"admin_uri".yellow(),
			std::str::from_utf8(&self.config.admin_uri)?
		)?;
		info_no_ts!("{}", SEPARATOR)?;

		self.debug_flag("--show_request_headers", self.config.show_request_headers)?;
		self.debug_flag("--show_response_headers", self.config.show_response_headers)?;
		self.debug_flag("--debug", self.config.debug)?;
		self.debug_flag("--debug_api", self.config.debug_api)?;
		self.debug_flag("--debug_websocket", self.config.debug_websocket)?;
		self.debug_flag("--debug_proxy", self.config.debug_proxy)?;
		self.debug_flag("--debug_log_queue", self.config.debug_log_queue)?;
		self.debug_flag("--debug_show_stats", self.config.debug_show_stats)?;

		info_no_ts!("{}", SEPARATOR)?;

		Ok(())
	}

	fn init_mainlog(mainlog: &String) -> Result<(), Error> {
		let mut p = PathBuf::from(mainlog);
		p.pop();
		fsutils::mkdir(&p.as_path().display().to_string());

		Ok(())
	}

	fn init_temp_dir(temp_dir: &String) -> Result<(), Error> {
		fsutils::mkdir(temp_dir);
		Ok(())
	}

	fn init_webroot(root_dir: &str) -> Result<(), Error> {
		fsutils::mkdir(root_dir);
		for file in include_dir!("$CARGO_MANIFEST_DIR/src/resources/www").files() {
			let file_path = file
				.path()
				.file_name()
				.unwrap()
				.to_str()
				.unwrap()
				.to_string();
			let root_dir = root_dir.to_string();
			let contents = file.contents();
			Self::create_file_from_bytes(file_path, root_dir, contents)?;
		}

		Ok(())
	}

	fn init_internal(&mut self) -> Result<(), Error> {
		for file in include_dir!("$CARGO_MANIFEST_DIR/src/resources/internal").files() {
			let file_name = file
				.path()
				.file_name()
				.unwrap()
				.to_str()
				.unwrap()
				.to_string();
			let contents = file.contents();
			self.internal_files.insert(file_name, contents.to_vec());
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

	fn init_user_data<'a>(
		user_data: &'a mut Box<dyn Any + Send + Sync>,
		config: &HttpConfig,
		stat_handler: &StatHandler,
	) -> Result<&'a mut ThreadContext, Error> {
		match user_data.downcast_ref::<ThreadContext>() {
			Some(_) => {}
			None => {
				let mut value = ThreadContext::new(config, stat_handler)?;
				for (k, v) in &config.mime_map {
					value
						.mime_map
						.insert(k.as_bytes().to_vec(), v.as_bytes().to_vec());
				}
				*user_data = Box::new(value);
			}
		}

		Ok(user_data.downcast_mut::<ThreadContext>().unwrap())
	}

	fn process_async(
		ctx: &mut ConnectionContext,
		thread_context: &mut ThreadContext,
		conn_data: &ConnectionData,
	) -> Result<(), Error> {
		if ctx.is_async_complete {
			let mut async_connections = lockw!(thread_context.async_connections)?;
			match async_connections.remove_raw(&conn_data.get_connection_id().to_be_bytes()) {
				Some(li_bytes) => {
					let mut log_item = LogItem::default();
					log_item.read(li_bytes.try_into()?)?;
					Self::process_stats(
						&mut log_item,
						Some(&mut thread_context.log_queue),
						None,
						&mut thread_context.dropped_log_items,
						&mut thread_context.dropped_lat_sum,
					)?;
				}
				None => {}
			}
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
		match active_connection_get_mut(
			id,
			&mut thread_context.active_connections,
			&mut thread_context.active_connection_index_map,
		) {
			Ok(mut conn_info) => match conn_info {
				Some(ref mut conn_info) => conn_info.last_data = now,
				None => error!("No connection info found for connection {}", id)?,
			},
			Err(e) => error!(
				"No connection info found for connection {} due to error: {}",
				id, e
			)?,
		}
		Ok(())
	}

	fn process_post_await(
		conn_info: &mut ConnectionInfo,
		conn_data: &ConnectionData,
		evh_params: &EvhParams,
		nbuf: &[u8],
		buffer: &mut Vec<u8>,
		connection_id: u128,
		now: SystemTime,
		remote_peer: &Option<SocketAddr>,
		api_config: &Arc<RwLock<HttpApiConfig>>,
		cache: &Arc<RwLock<HttpCache>>,
		config: &HttpConfig,
		api_handler: &Option<Pin<Box<ApiHandler>>>,
		slabs: &Arc<RwLock<SlabAllocator>>,
		ws_handler: Option<&Pin<Box<WsHandler>>>,
		sha1: &mut Sha1,
		ch: &mut StaticHash<(), ()>,
		header_map: &mut StaticHash<(), ()>,
		key_buf: &mut Vec<u8>,
		value_buf: &mut Vec<u8>,
		webroot: &Vec<u8>,
		temp_dir: &String,
		idle_proxy_connections: &mut HashMap<ProxyEntry, HashMap<SocketAddr, HashSet<ProxyInfo>>>,
		proxy_state: &mut HashMap<ProxyEntry, ProxyState>,
		mime_map: &HashMap<Vec<u8>, Vec<u8>>,
		async_connections: &Arc<RwLock<StaticHash<(), ()>>>,
		local_peer: &Option<SocketAddr>,
		log_queue: &mut StaticQueue<LogItem>,
		stat_handler: &StatHandler,
		dropped_log_items: &mut u64,
		internal: &HashMap<String, Vec<u8>>,
		dropped_lat_sum: &mut u64,
		thread_pool: &Arc<RwLock<StaticThreadPool>>,
	) -> Result<
		(
			bool,
			usize,
			Vec<ConnectionInfo>,
			Vec<(ConnectionData, u128)>,
		),
		Error,
	> {
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
				return Ok((false, 0, vec![], vec![]));
			}
		};
		if rem {
			conn_info.api_context = None;
		}

		let mut nconns = vec![];
		let mut nupdates = vec![];
		if overflow > 0 {
			let nbuf = &nbuf[nbuf.len().saturating_sub(overflow)..];
			(nconns, nupdates) = Self::process_sync(
				conn_info,
				conn_data,
				evh_params,
				nbuf,
				buffer,
				connection_id,
				now,
				remote_peer,
				api_config,
				cache,
				config,
				api_handler,
				slabs,
				ws_handler,
				sha1,
				ch,
				header_map,
				key_buf,
				value_buf,
				webroot,
				temp_dir,
				idle_proxy_connections,
				proxy_state,
				mime_map,
				async_connections,
				local_peer,
				log_queue,
				stat_handler,
				dropped_log_items,
				internal,
				dropped_lat_sum,
				thread_pool,
			)?;
		}

		Ok((true, overflow, nconns, nupdates))
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
		stat_handler: &StatHandler,
		internal: &HashMap<String, Vec<u8>>,
		thread_pool: &Arc<RwLock<StaticThreadPool>>,
	) -> Result<(Vec<ConnectionInfo>, Vec<(ConnectionData, u128)>), Error> {
		let now = SystemTime::now();
		Self::process_async(ctx, thread_context, conn_data)?;
		Self::update_conn_info(thread_context, conn_data, now)?;

		let remote_peer = &ctx.remote_peer.clone();
		let local_peer = &ctx.local_peer.clone();
		let buffer = ctx.get_buffer();
		let buffer_len = buffer.len();
		let connection_id = conn_data.get_connection_id();

		debug!(
			"on_read[{}] = '{:?}', acc_handle={:?}, buffer_len={}, l={:?}",
			connection_id,
			nbuf,
			conn_data.get_accept_handle(),
			buffer_len,
			config.listeners,
		)?;

		if buffer_len == 0 && nbuf.len() == 0 {
			// there's nothing to do
			return Ok((vec![], vec![]));
		}

		let is_async = {
			let async_connections = lockr!(thread_context.async_connections)?;
			async_connections
				.get_raw(&connection_id.to_be_bytes())
				.is_some()
		};

		let conn_info = match active_connection_get_mut(
			connection_id,
			&mut thread_context.active_connections,
			&mut thread_context.active_connection_index_map,
		)? {
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

		let (was_post_await, _overflow, nconns, nupdates) = Self::process_post_await(
			conn_info,
			conn_data,
			evh_params,
			nbuf,
			buffer,
			connection_id,
			now,
			remote_peer,
			api_config,
			cache,
			config,
			api_handler,
			slabs,
			ws_handler,
			&mut thread_context.sha1,
			&mut thread_context.cache_hits,
			&mut thread_context.header_map,
			&mut thread_context.key_buf,
			&mut thread_context.value_buf,
			&mut thread_context.webroot,
			&mut thread_context.temp_dir,
			&mut thread_context.idle_proxy_connections,
			&mut thread_context.proxy_state,
			&mut thread_context.mime_map,
			&mut thread_context.async_connections,
			local_peer,
			&mut thread_context.log_queue,
			stat_handler,
			&mut thread_context.dropped_log_items,
			internal,
			&mut thread_context.dropped_lat_sum,
			thread_pool,
		)?;

		if was_post_await {
			return Ok((nconns, nupdates));
		}

		if !is_async {
			if process_health_check_response(
				conn_info,
				conn_data,
				nbuf,
				&mut thread_context.proxy_state,
			)? {
				return Ok((vec![], vec![]));
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
						&mut thread_context.async_connections,
					)?;
					return Ok((vec![], vec![]));
				}
				None => {}
			}
		}

		let mut nconns = vec![];
		let mut nupdates = vec![];

		if is_async {
			// it's async just append to the buffer and return
			Self::append_buffer(nbuf, buffer)?;
		} else if buffer_len > 0 {
			Self::append_buffer(nbuf, buffer)?;
			loop {
				let (amt, nconn, update_info) = Self::process_buffer(
					conn_info,
					conn_data,
					buffer,
					config,
					cache,
					api_config,
					api_handler,
					evh_params,
					now,
					remote_peer,
					slabs,
					ws_handler,
					&mut thread_context.sha1,
					&mut thread_context.cache_hits,
					&mut thread_context.header_map,
					&mut thread_context.key_buf,
					&mut thread_context.value_buf,
					&mut thread_context.webroot,
					&mut thread_context.temp_dir,
					&mut thread_context.idle_proxy_connections,
					&mut thread_context.proxy_state,
					&mut thread_context.mime_map,
					&mut thread_context.async_connections,
					local_peer,
					&mut thread_context.log_queue,
					stat_handler,
					&mut thread_context.dropped_log_items,
					internal,
					&mut thread_context.dropped_lat_sum,
					thread_pool,
				)?;

				match nconn {
					Some(nconn) => {
						nconns.push(nconn);
					}
					None => {}
				}

				match update_info {
					Some(update_info) => {
						nupdates.push(update_info);
					}
					None => {}
				}
				if amt == 0 {
					break;
				}
				buffer.drain(..amt);

				// if were now async, we must break
				if lockr!(thread_context.async_connections)?
					.get_raw(&connection_id.to_be_bytes())
					.is_some()
				{
					break;
				}
			}
		} else {
			let (mut ps_nconns, mut ps_nupdates) = Self::process_sync(
				conn_info,
				conn_data,
				evh_params,
				nbuf,
				buffer,
				connection_id,
				now,
				remote_peer,
				api_config,
				cache,
				config,
				api_handler,
				slabs,
				ws_handler,
				&mut thread_context.sha1,
				&mut thread_context.cache_hits,
				&mut thread_context.header_map,
				&mut thread_context.key_buf,
				&mut thread_context.value_buf,
				&mut thread_context.webroot,
				&mut thread_context.temp_dir,
				&mut thread_context.idle_proxy_connections,
				&mut thread_context.proxy_state,
				&mut thread_context.mime_map,
				&mut thread_context.async_connections,
				local_peer,
				&mut thread_context.log_queue,
				stat_handler,
				&mut thread_context.dropped_log_items,
				internal,
				&mut thread_context.dropped_lat_sum,
				thread_pool,
			)?;
			nconns.append(&mut ps_nconns);
			nupdates.append(&mut ps_nupdates);
		}

		Ok((nconns, nupdates))
	}

	fn process_sync(
		conn_info: &mut ConnectionInfo,
		conn_data: &ConnectionData,
		evh_params: &EvhParams,
		nbuf: &[u8],
		buffer: &mut Vec<u8>,
		connection_id: u128,
		now: SystemTime,
		remote_peer: &Option<SocketAddr>,
		api_config: &Arc<RwLock<HttpApiConfig>>,
		cache: &Arc<RwLock<HttpCache>>,
		config: &HttpConfig,
		api_handler: &Option<Pin<Box<ApiHandler>>>,
		slabs: &Arc<RwLock<SlabAllocator>>,
		ws_handler: Option<&Pin<Box<WsHandler>>>,
		sha1: &mut Sha1,
		ch: &mut StaticHash<(), ()>,
		header_map: &mut StaticHash<(), ()>,
		key_buf: &mut Vec<u8>,
		value_buf: &mut Vec<u8>,
		webroot: &Vec<u8>,
		temp_dir: &String,
		idle_proxy_connections: &mut HashMap<ProxyEntry, HashMap<SocketAddr, HashSet<ProxyInfo>>>,
		proxy_state: &mut HashMap<ProxyEntry, ProxyState>,
		mime_map: &HashMap<Vec<u8>, Vec<u8>>,
		async_connections: &Arc<RwLock<StaticHash<(), ()>>>,
		local_peer: &Option<SocketAddr>,
		log_queue: &mut StaticQueue<LogItem>,
		stat_handler: &StatHandler,
		dropped_log_items: &mut u64,
		internal: &HashMap<String, Vec<u8>>,
		dropped_lat_sum: &mut u64,
		thread_pool: &Arc<RwLock<StaticThreadPool>>,
	) -> Result<(Vec<ConnectionInfo>, Vec<(ConnectionData, u128)>), Error> {
		let mut offset = 0;
		let mut nconns = vec![];
		let mut nupdates = vec![];
		loop {
			let pbuf = &nbuf[offset..];
			if pbuf.len() == 0 {
				break;
			}

			// premptively try to process the incoming buffer without appending
			// in many cases this will work and be faster
			let (amt, nconn, update_info) = Self::process_buffer(
				conn_info,
				conn_data,
				pbuf,
				config,
				cache,
				api_config,
				api_handler,
				evh_params,
				now,
				remote_peer,
				slabs,
				ws_handler,
				sha1,
				ch,
				header_map,
				key_buf,
				value_buf,
				webroot,
				temp_dir,
				idle_proxy_connections,
				proxy_state,
				mime_map,
				async_connections,
				local_peer,
				log_queue,
				stat_handler,
				dropped_log_items,
				internal,
				dropped_lat_sum,
				thread_pool,
			)?;
			if amt == 0 {
				Self::append_buffer(&pbuf, buffer)?;
				break;
			}

			match nconn {
				Some(nconn) => nconns.push(nconn),
				None => {}
			}

			match update_info {
				Some(update_info) => nupdates.push(update_info),
				None => {}
			}

			offset += amt;

			// if were now async, we must break
			if lockr!(async_connections)?
				.get_raw(&connection_id.to_be_bytes())
				.is_some()
			{
				Self::append_buffer(&nbuf[offset..], buffer)?;
				break;
			}
		}
		Ok((nconns, nupdates))
	}

	fn check_expect_100_continue(
		headers: &HttpHeaders,
		conn_data: &ConnectionData,
	) -> Result<(), Error> {
		if headers.has_expect() {
			match headers.get_header_value(EXPECT_BYTES)? {
				Some(values) => {
					for value in values {
						if value == "100-continue".as_bytes() {
							conn_data.write(HTTP_CONTINUE_100)?;
						}
					}
				}
				None => {}
			}
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
		async_connections: &Arc<RwLock<StaticHash<(), ()>>>,
		slabs: &Arc<RwLock<SlabAllocator>>,
		remote_peer: &Option<SocketAddr>,
		now: SystemTime,
		cache: &Arc<RwLock<HttpCache>>,
		webroot: &Vec<u8>,
		mime_map: &HashMap<Vec<u8>, Vec<u8>>,
		local_peer: &Option<SocketAddr>,
		log_queue: &mut StaticQueue<LogItem>,
		stat_handler: &StatHandler,
		dropped_log_items: &mut u64,
		dropped_lat_sum: &mut u64,
		thread_pool: &Arc<RwLock<StaticThreadPool>>,
	) -> Result<
		(
			bool,
			Option<ApiContext>,
			Option<ConnectionInfo>,
			Option<(ConnectionData, u128)>,
		),
		Error,
	> {
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

				let (api_context, nconn, update_info) = match process_proxy_outbound(
					conn_data,
					&headers,
					config,
					&proxy_entry,
					buffer,
					evh_params,
					idle_proxy_connections,
					proxy_state,
					async_connections,
					&remote_peer,
					now,
					slabs,
					stat_handler.clone(),
				) {
					Ok((ctx, nconn, update_info)) => {
						if clen > 0 {
							let rem = if clen + headers_len > buf_len {
								(headers_len + clen).saturating_sub(buf_len)
							} else {
								0
							};
							if rem > 0 {
								(Some(ctx.clone()), nconn, update_info)
							} else {
								(None, nconn, update_info)
							}
						} else {
							(None, nconn, update_info)
						}
					}
					Err(e) => {
						warn!("Error while communicating with proxy: {}", e.kind(),)?;

						match Self::send_file(
							HTTP_CODE_502,
							502,
							&headers.get_uri(),
							&config.error_page,
							&headers.get_query(),
							headers.get_user_agent(),
							headers.get_referer(),
							conn_data,
							config,
							cache,
							headers.get_version(),
							headers.get_method(),
							None,
							&mime_map,
							&async_connections,
							now,
							webroot,
							slabs,
							headers.is_close(),
							&None,
							&None,
							false,
							headers.get_header_value(HOST_BYTES)?,
							local_peer,
							log_queue,
							stat_handler,
							dropped_log_items,
							dropped_lat_sum,
							thread_pool,
						) {
							Ok(_) => {}
							Err(_e) => {
								conn_data.write(HTTP_ERROR_502)?;
								conn_data.close()?;
							}
						}
						(None, None, None)
					}
				};
				(true, api_context, nconn, update_info)
			}
			None => (false, None, None, None),
		})
	}

	fn send_websocket_handshake_response(
		conn_data: &ConnectionData,
		key: &String,
		sha1: &mut Sha1,
	) -> Result<(), Error> {
		let hash = format!("{}{}", key, WEBSOCKET_GUID);
		let mut sha1 = sha1.clone();
		sha1.update(hash.as_bytes());
		let b = sha1.finalize();
		let msg = format!(
			"HTTP/1.1 101 Switching Protocols\r\n\
Upgrade: websocket\r\n\
Connection: Upgrade\r\n\
Sec-WebSocket-Accept: {}\r\n\r\n",
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
		ws_handler: Option<&Pin<Box<WsHandler>>>,
		internal_handler: Option<&dyn Fn(&ConnectionData, WebSocketMessage) -> Result<bool, Error>>,
		config: &HttpConfig,
	) -> Result<(bool, usize), Error> {
		Ok(match conn_info.is_websocket {
			true => {
				let ws_handler = ws_handler.clone();
				let (close, len) =
					process_websocket_data(conn_data, buffer, &move |connection_data,
					                                                 web_socket_message|
					      -> Result<bool, Error> {
						let res = match internal_handler {
							Some(internal_handler_fn) => {
								(internal_handler_fn)(connection_data, web_socket_message)?
							}
							None => match ws_handler {
								Some(ws_handler) => ws_handler(
									connection_data,
									conn_info.websocket_uri.as_ref().unwrap_or(&vec![]),
									web_socket_message,
								)?,
								None => {
									warn!("unexpected no internal or extenral handler")?;
									false
								}
							},
						};
						Ok(res)
					})?;
				if close {
					conn_data.close()?;
				}
				(true, len)
			}
			false => match headers {
				Some(headers) => {
					let uri = headers.get_uri();
					if bytes_find(uri, &config.admin_uri) == Some(0) && internal_handler.is_none() {
						(false, 0)
					} else if headers.has_websocket_upgrade() {
						let sec_key = headers.get_header_value(SEC_WEBSOCKET_KEY_BYTES)?;
						match sec_key {
							Some(sec_key) => {
								if sec_key.len() > 0 {
									conn_info.is_websocket = true;
									Self::send_websocket_handshake_response(
										conn_data,
										&from_utf8(&sec_key[0])?.to_string(),
										sha1,
									)?;
									conn_info.websocket_uri = Some(uri.to_vec());
									(true, headers.len())
								} else {
									(false, 0)
								}
							}
							None => (false, 0),
						}
					} else {
						(false, 0)
					}
				}
				None => (false, 0),
			},
		})
	}

	fn process_admin_ws(
		conn_data: &ConnectionData,
		msg: WebSocketMessage,
		http_stats: &HttpStats,
	) -> Result<bool, Error> {
		if msg.mtype == WebSocketMessageType::Close {
			Ok(false)
		} else {
			if msg.payload.len() == 0 {
				return Ok(false);
			}

			match msg.payload[0] {
				WS_ADMIN_GET_STATS_REQUEST => {
					let start = u64::from_be_bytes(msg.payload[1..9].try_into()?);
					let end = u64::from_be_bytes(msg.payload[9..17].try_into()?);
					let records = http_stats.get_stats_aggregation(start, end)?;
					let mut payload = vec![WS_ADMIN_GET_STATS_RESPONSE];
					payload.append(
						&mut ((SystemTime::now().duration_since(UNIX_EPOCH)?.as_millis() as u64)
							.to_be_bytes())
						.to_vec(),
					);
					payload.append(&mut ((records.len() as u64).to_be_bytes()).to_vec());
					for record in records {
						payload.append(&mut record.get_bytes());
					}

					send_websocket_message(
						conn_data,
						&WebSocketMessage {
							payload,
							mtype: WebSocketMessageType::Binary,
							mask: false,
						},
					)?;
				}
				WS_ADMIN_GET_STATS_AFTER_TIMESTAMP_REQUEST => {
					let timestamp = u64::from_be_bytes(msg.payload[1..9].try_into()?);
					let quantity = u64::from_be_bytes(msg.payload[9..17].try_into()?);
					let records = http_stats.get_stats_aggregation_after(timestamp, quantity)?;
					let mut payload = vec![WS_ADMIN_GET_STATS_RESPONSE];
					payload.append(
						&mut ((SystemTime::now().duration_since(UNIX_EPOCH)?.as_millis() as u64)
							.to_be_bytes())
						.to_vec(),
					);
					payload.append(&mut ((records.len() as u64).to_be_bytes()).to_vec());
					for record in records {
						payload.append(&mut record.get_bytes());
					}

					send_websocket_message(
						conn_data,
						&WebSocketMessage {
							payload,
							mtype: WebSocketMessageType::Binary,
							mask: false,
						},
					)?;
				}
				WS_ADMIN_GET_RECENT_REQUESTS => {
					let since_timestamp = u64::from_be_bytes(msg.payload[1..9].try_into()?);
					let records = http_stats.get_recent_requests()?;
					let mut payload = vec![WS_ADMIN_RECENT_REQUESTS_RESPONSE];
					payload.append(
						&mut ((SystemTime::now().duration_since(UNIX_EPOCH)?.as_millis() as u64)
							.to_be_bytes())
						.to_vec(),
					);

					let mut count = 0;
					for record in &records {
						if record.end_micros > since_timestamp {
							count += 1;
						}
					}

					payload.append(&mut ((count as u64).to_be_bytes()).to_vec());
					for record in records {
						if record.end_micros > since_timestamp {
							let mut ser = [0u8; LOG_ITEM_SIZE];
							record.write(&mut ser)?;
							payload.append(&mut ser.to_vec());
						}
					}

					send_websocket_message(
						conn_data,
						&WebSocketMessage {
							payload,
							mtype: WebSocketMessageType::Binary,
							mask: false,
						},
					)?;
				}
				WS_ADMIN_PING => {
					let mut payload = vec![WS_ADMIN_PONG];
					let records = http_stats.get_stats_aggregation(0, 2)?;
					payload.append(
						&mut ((SystemTime::now().duration_since(UNIX_EPOCH)?.as_millis() as u64)
							.to_be_bytes())
						.to_vec(),
					);
					payload.append(&mut ((records.len() as u64).to_be_bytes()).to_vec());
					for record in records {
						payload.append(&mut record.get_bytes());
					}

					send_websocket_message(
						conn_data,
						&WebSocketMessage {
							payload,
							mtype: WebSocketMessageType::Binary,
							mask: false,
						},
					)?;
				}
				WS_ADMIN_REQUEST_CHART_REQUEST => {
					let mut payload = vec![WS_ADMIN_REQUEST_CHART_RESPONSE];
					let records = http_stats.get_stats_aggregation(0, 8640)?;
					let time_now = SystemTime::now().duration_since(UNIX_EPOCH)?.as_millis() as u64;
					payload.append(&mut (time_now.to_be_bytes()).to_vec());

					let mut count: u64 = 0;
					for record in &records {
						if time_now.saturating_sub(record.timestamp.try_into()?)
							< 24 * 60 * 60 * 1000
						{
							count += 1;
						} else {
							break;
						}
					}

					payload.append(&mut ((count).to_be_bytes()).to_vec());
					for record in records {
						if time_now.saturating_sub(record.timestamp.try_into()?)
							< 24 * 60 * 60 * 1000
						{
							payload.append(&mut record.requests.to_be_bytes().to_vec());
							payload.append(&mut record.lat_sum_micros.to_be_bytes().to_vec());
							payload.append(&mut record.connects.to_be_bytes().to_vec());
							payload.append(&mut (record.timestamp as u64).to_be_bytes().to_vec());
							payload
								.append(&mut (record.prev_timestamp as u64).to_be_bytes().to_vec());
							payload
								.append(&mut (record.memory_bytes as u64).to_be_bytes().to_vec());
						}
					}

					send_websocket_message(
						conn_data,
						&WebSocketMessage {
							payload,
							mtype: WebSocketMessageType::Binary,
							mask: false,
						},
					)?;
				}
				_ => {
					warn!("unknown ws admin command. msg = {:?}", msg)?;
				}
			}
			Ok(true)
		}
	}

	fn process_buffer(
		conn_info: &mut ConnectionInfo,
		conn_data: &ConnectionData,
		buffer: &[u8],
		config: &HttpConfig,
		cache: &Arc<RwLock<HttpCache>>,
		api_config: &Arc<RwLock<HttpApiConfig>>,
		api_handler: &Option<Pin<Box<ApiHandler>>>,
		evh_params: &EvhParams,
		now: SystemTime,
		remote_peer: &Option<SocketAddr>,
		slabs: &Arc<RwLock<SlabAllocator>>,
		ws_handler: Option<&Pin<Box<WsHandler>>>,
		sha1: &mut Sha1,
		ch: &mut StaticHash<(), ()>,
		header_map: &mut StaticHash<(), ()>,
		key_buf: &mut Vec<u8>,
		value_buf: &mut Vec<u8>,
		webroot: &Vec<u8>,
		temp_dir: &String,
		idle_proxy_connections: &mut HashMap<ProxyEntry, HashMap<SocketAddr, HashSet<ProxyInfo>>>,
		proxy_state: &mut HashMap<ProxyEntry, ProxyState>,
		mime_map: &HashMap<Vec<u8>, Vec<u8>>,
		async_connections: &Arc<RwLock<StaticHash<(), ()>>>,
		local_peer: &Option<SocketAddr>,
		log_queue: &mut StaticQueue<LogItem>,
		stat_handler: &StatHandler,
		dropped_log_items: &mut u64,
		internal: &HashMap<String, Vec<u8>>,
		dropped_lat_sum: &mut u64,
		thread_pool: &Arc<RwLock<StaticThreadPool>>,
	) -> Result<
		(
			usize,
			Option<ConnectionInfo>,
			Option<(ConnectionData, u128)>,
		),
		Error,
	> {
		if conn_info.is_admin && conn_info.is_websocket {
			let (_is_ws, len) = Self::check_websocket(
				conn_data,
				None,
				conn_info,
				buffer,
				sha1,
				ws_handler,
				Some(&move |conn_data, msg| {
					Self::process_admin_ws(conn_data, msg, &stat_handler.http_stats)
				}),
				config,
			)?;
			return Ok((len, None, None));
		} else if conn_info.is_websocket {
			match ws_handler {
				Some(_) => {
					let (is_ws, len) = Self::check_websocket(
						conn_data, None, conn_info, buffer, sha1, ws_handler, None, config,
					)?;

					if is_ws {
						return Ok((len, None, None));
					}
				}
				None => {}
			}
		}

		let headers = match HttpHeaders::new(buffer, config, header_map, key_buf, value_buf) {
			Ok(headers) => headers,
			Err(e) => {
				match e.kind() {
					ErrorKind::HttpError400(_) => {
						match Self::send_file(
							HTTP_CODE_400,
							400,
							&[],
							&config.error_page,
							&[],
							&[],
							&[],
							conn_data,
							config,
							cache,
							&HttpVersion::V10,
							&HttpMethod::Get,
							None,
							&mime_map,
							&async_connections,
							now,
							webroot,
							slabs,
							true,
							&None,
							&None,
							false,
							None,
							local_peer,
							log_queue,
							stat_handler,
							dropped_log_items,
							dropped_lat_sum,
							thread_pool,
						) {
							Ok(_) => {}
							Err(_e) => {
								conn_data.write(HTTP_ERROR_400)?;
								conn_data.close()?;
							}
						}
					}
					ErrorKind::HttpError405(_) => {
						match Self::send_file(
							HTTP_CODE_405,
							405,
							&[],
							&config.error_page,
							&[],
							&[],
							&[],
							conn_data,
							config,
							cache,
							&HttpVersion::V10,
							&HttpMethod::Get,
							None,
							&mime_map,
							&async_connections,
							now,
							webroot,
							slabs,
							true,
							&None,
							&None,
							false,
							None,
							local_peer,
							log_queue,
							stat_handler,
							dropped_log_items,
							dropped_lat_sum,
							thread_pool,
						) {
							Ok(_) => {}
							Err(_e) => {
								conn_data.write(HTTP_ERROR_405)?;
								conn_data.close()?;
							}
						}
					}
					ErrorKind::HttpError431(_) => {
						match Self::send_file(
							HTTP_CODE_431,
							431,
							&[],
							&config.error_page,
							&[],
							&[],
							&[],
							conn_data,
							config,
							cache,
							&HttpVersion::V10,
							&HttpMethod::Get,
							None,
							&mime_map,
							&async_connections,
							now,
							webroot,
							slabs,
							true,
							&None,
							&None,
							false,
							None,
							local_peer,
							log_queue,
							stat_handler,
							dropped_log_items,
							dropped_lat_sum,
							thread_pool,
						) {
							Ok(_) => {}
							Err(_e) => {
								conn_data.write(HTTP_ERROR_431)?;
								conn_data.close()?;
							}
						}
					}
					_ => {
						error!("Internal server error: {}", e)?;
						match Self::send_file(
							HTTP_CODE_500,
							500,
							&config.error_page,
							&[],
							&[],
							&[],
							&[],
							conn_data,
							config,
							cache,
							&HttpVersion::V10,
							&HttpMethod::Get,
							None,
							&mime_map,
							&async_connections,
							now,
							webroot,
							slabs,
							true,
							&None,
							&None,
							false,
							None,
							local_peer,
							log_queue,
							stat_handler,
							dropped_log_items,
							dropped_lat_sum,
							thread_pool,
						) {
							Ok(_) => {}
							Err(_e) => {
								conn_data.write(HTTP_ERROR_500)?;
								conn_data.close()?;
							}
						}
					}
				}
				debug!("parsing headers generated error: {}", e)?;
				return Ok((0, None, None));
			}
		};

		let (len, key, nconn, update_info) = match headers {
			Some(headers) => {
				if config.show_request_headers {
					warn!(
						"HTTP Request ({}):\n{}",
						conn_data.get_connection_id(),
						headers
					)?;
				}
				match ws_handler {
					Some(_) => {
						let (is_ws, len) = Self::check_websocket(
							conn_data,
							Some(&headers),
							conn_info,
							buffer,
							sha1,
							ws_handler,
							None,
							config,
						)?;
						if is_ws {
							return Ok((len, None, None));
						}
					}
					None => {}
				}
				if headers.content_len()? > config.max_content_len {
					match Self::send_file(
						HTTP_CODE_413,
						413,
						headers.get_uri(),
						&config.error_page,
						&headers.get_query(),
						headers.get_user_agent(),
						headers.get_referer(),
						conn_data,
						config,
						cache,
						headers.get_version(),
						headers.get_method(),
						None,
						&mime_map,
						&async_connections,
						now,
						webroot,
						slabs,
						true,
						&None,
						&None,
						false,
						headers.get_header_value(HOST_BYTES)?,
						local_peer,
						log_queue,
						stat_handler,
						dropped_log_items,
						dropped_lat_sum,
						thread_pool,
					) {
						Ok(_) => {}
						Err(_e) => {
							conn_data.write(HTTP_ERROR_413)?;
							conn_data.close()?;
						}
					}
					return Ok((0, None, None));
				}

				// check for api mapping/extension
				let was_api = {
					Self::process_api(
						now,
						buffer,
						&headers,
						api_config,
						api_handler,
						async_connections,
						conn_info,
						conn_data,
						temp_dir,
						slabs,
						log_queue,
						dropped_log_items,
						stat_handler,
						dropped_lat_sum,
					)?
				};

				if !was_api {
					Self::check_expect_100_continue(&headers, conn_data)?;
				}

				let range: Option<(usize, usize)> = if was_api {
					None
				} else if headers.has_range() {
					let range = &headers.get_header_value(RANGE_BYTES)?;
					match range {
						Some(range) => {
							if range.len() < 1 {
								None
							} else {
								let range = from_utf8(&range[0])?;
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
												Some((
													start_str.parse().unwrap_or(0),
													end_str.parse().unwrap_or(u32::MAX as usize),
												))
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

				let (was_proxy, nconn, update_info) = if was_api {
					(false, None, None)
				} else {
					let (was_proxy, api_context, nconn, update_info) = Self::process_proxy_request(
						conn_data,
						config,
						&headers,
						buffer,
						evh_params,
						idle_proxy_connections,
						proxy_state,
						async_connections,
						slabs,
						remote_peer,
						now,
						cache,
						webroot,
						mime_map,
						local_peer,
						log_queue,
						stat_handler,
						dropped_log_items,
						dropped_lat_sum,
						thread_pool,
					)?;

					match api_context {
						Some(api_context) => {
							conn_info.api_context = Some(api_context);
						}
						None => {}
					}

					(was_proxy, nconn, update_info)
				};

				let was_admin = if !was_api && !was_proxy {
					let (is_admin, is_ws, clen) = Self::process_admin_request(
						now,
						buffer,
						&headers,
						conn_data,
						config,
						stat_handler,
						internal,
						conn_info,
						sha1,
						ws_handler,
					)?;

					if is_admin && is_ws {
						return Ok((clen, None, None));
					}

					is_admin
				} else {
					false
				};

				if !was_api && !was_proxy && !was_admin {
					let if_modified_since = if headers.has_if_modified_since() {
						headers.get_header_value(IF_MODIFIED_SINCE)?
					} else {
						None
					};

					let if_none_match = if headers.has_if_none_match() {
						headers.get_header_value(IF_NONE_MATCH)?
					} else {
						None
					};

					let gzip = if headers.accept_gzip() {
						if config.gzip_extensions.len() == 0 {
							false
						} else {
							if config
								.gzip_extensions
								.get(&headers.extension().to_vec())
								.is_some()
							{
								true
							} else {
								false
							}
						}
					} else {
						false
					};

					match Self::send_file(
						HTTP_CODE_200,
						200,
						&headers.get_uri(),
						&headers.get_uri(),
						&headers.get_query(),
						&headers.get_user_agent(),
						&headers.get_referer(),
						conn_data,
						config,
						cache,
						headers.get_version(),
						headers.get_method(),
						range,
						&mime_map,
						&async_connections,
						now,
						webroot,
						slabs,
						headers.is_close(),
						&if_modified_since,
						&if_none_match,
						gzip,
						headers.get_header_value(HOST_BYTES)?,
						local_peer,
						log_queue,
						stat_handler,
						dropped_log_items,
						dropped_lat_sum,
						thread_pool,
					) {
						Ok(k) => {
							key = k;
						}
						Err(e) => {
							match e.kind() {
								ErrorKind::HttpError404(_) => {
									match Self::send_file(
										HTTP_CODE_404,
										404,
										&headers.get_uri(),
										&config.error_page,
										&headers.get_query(),
										&headers.get_user_agent(),
										&headers.get_referer(),
										conn_data,
										config,
										cache,
										headers.get_version(),
										headers.get_method(),
										range,
										&mime_map,
										&async_connections,
										now,
										webroot,
										slabs,
										headers.is_close(),
										&None,
										&None,
										false,
										headers.get_header_value(HOST_BYTES)?,
										local_peer,
										log_queue,
										stat_handler,
										dropped_log_items,
										dropped_lat_sum,
										thread_pool,
									) {
										Ok(k) => key = k,
										Err(_e) => {
											conn_data.write(HTTP_ERROR_404)?;
											conn_data.close()?;
										}
									}
								}
								ErrorKind::HttpError405(_) => {
									match Self::send_file(
										HTTP_CODE_405,
										405,
										&headers.get_uri(),
										&config.error_page,
										&headers.get_query(),
										&headers.get_user_agent(),
										&headers.get_referer(),
										conn_data,
										config,
										cache,
										headers.get_version(),
										&HttpMethod::Get,
										range,
										&mime_map,
										&async_connections,
										now,
										webroot,
										slabs,
										true,
										&None,
										&None,
										false,
										headers.get_header_value(HOST_BYTES)?,
										local_peer,
										log_queue,
										stat_handler,
										dropped_log_items,
										dropped_lat_sum,
										thread_pool,
									) {
										Ok(k) => key = k,
										Err(_e) => {
											conn_data.write(HTTP_ERROR_405)?;
											conn_data.close()?;
										}
									}
								}
								ErrorKind::HttpError403(_) => {
									match Self::send_file(
										HTTP_CODE_403,
										403,
										&headers.get_uri(),
										&config.error_page,
										&headers.get_query(),
										headers.get_user_agent(),
										headers.get_referer(),
										conn_data,
										config,
										cache,
										headers.get_version(),
										headers.get_method(),
										range,
										&mime_map,
										&async_connections,
										now,
										webroot,
										slabs,
										headers.is_close(),
										&None,
										&None,
										false,
										headers.get_header_value(HOST_BYTES)?,
										local_peer,
										log_queue,
										stat_handler,
										dropped_log_items,
										dropped_lat_sum,
										thread_pool,
									) {
										Ok(k) => key = k,
										Err(_e) => {
											conn_data.write(HTTP_ERROR_403)?;
											conn_data.close()?;
										}
									}
								}
								_ => {
									error!("Internal server error: {}", e)?;
									match Self::send_file(
										HTTP_CODE_500,
										500,
										&headers.get_uri(),
										&config.error_page,
										&headers.get_query(),
										headers.get_user_agent(),
										headers.get_referer(),
										conn_data,
										config,
										cache,
										headers.get_version(),
										headers.get_method(),
										range,
										&mime_map,
										&async_connections,
										now,
										webroot,
										slabs,
										true,
										&None,
										&None,
										false,
										headers.get_header_value(HOST_BYTES)?,
										local_peer,
										log_queue,
										stat_handler,
										dropped_log_items,
										dropped_lat_sum,
										thread_pool,
									) {
										Ok(k) => key = k,
										Err(_e) => {
											conn_data.write(HTTP_ERROR_500)?;
											conn_data.close()?;
										}
									}
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

				(end, key, nconn, update_info)
			}
			None => (0, None, None, None),
		};

		match key {
			Some(key) => {
				ch.insert_raw(&key, &[0u8; 16])?;
			}
			None => {}
		}

		Ok((len, nconn, update_info))
	}

	fn process_admin_request(
		_now: SystemTime,
		buf: &[u8],
		headers: &HttpHeaders,
		conn_data: &ConnectionData,
		config: &HttpConfig,
		_stats: &StatHandler,
		internal: &HashMap<String, Vec<u8>>,
		conn_info: &mut ConnectionInfo,
		sha1: &mut Sha1,
		ws_handler: Option<&Pin<Box<WsHandler>>>,
	) -> Result<(bool, bool, usize), Error> {
		let request_uri = headers.get_uri();
		if bytes_eq(request_uri, &config.admin_uri) {
			// get_stats_aggregation
			//let stat_record = stats.http_stats.get_stats_aggregation(0, 10)?;
			//let mut content = format!("{:?}", stat_record);
			let query = headers.get_query();

			let content = if query.len() == 0 || bytes_eq(query, b"index") {
				internal.get("index.html").unwrap().to_vec()
			} else if bytes_eq(query, b"styles.css") {
				internal.get("styles.css").unwrap().to_vec()
			} else if bytes_eq(query, b"banner.png") {
				internal.get("banner.png").unwrap().to_vec()
			} else if bytes_eq(query, b"tableft.gif") {
				internal.get("tableft.gif").unwrap().to_vec()
			} else if bytes_eq(query, b"tabright.gif") {
				internal.get("tabright.gif").unwrap().to_vec()
			} else if bytes_eq(query, b"requests") {
				internal.get("requests.html").unwrap().to_vec()
			} else if bytes_eq(query, b"uptime") {
				internal.get("uptime.html").unwrap().to_vec()
			} else if bytes_eq(query, b"analytics") {
				internal.get("analytics.html").unwrap().to_vec()
			} else if bytes_eq(query, b"niohttpd") {
				internal.get("niohttpd.js").unwrap().to_vec()
			} else if bytes_eq(query, b"jsbn") {
				internal.get("jsbn.js").unwrap().to_vec()
			} else if bytes_eq(query, b"jsbn2") {
				internal.get("jsbn2.js").unwrap().to_vec()
			} else if bytes_eq(query, b"play") {
				internal.get("play-button.png").unwrap().to_vec()
			} else if bytes_eq(query, b"pause") {
				internal.get("pause-button.png").unwrap().to_vec()
			} else if bytes_eq(query, b"chartjs") {
				internal.get("chart.js").unwrap().to_vec()
			} else if bytes_eq(query, b"loading") {
				internal.get("Loading_icon.gif").unwrap().to_vec()
			} else if bytes_eq(query, b"ws") {
				let (_ws, len) = Self::check_websocket(
					conn_data,
					Some(headers),
					conn_info,
					buf,
					sha1,
					ws_handler,
					Some(&move |_conn_data, _msg| Ok(false)),
					config,
				)?;
				conn_info.is_admin = true;
				return Ok((true, true, len));
			} else {
				("unknown".as_bytes()).to_vec()
			};

			let response_prefix = format!(
				"HTTP/1.1 200 Ok\r\nContent-Length: {}\r\n\r\n",
				content.len(),
			);
			conn_data.write(response_prefix.as_bytes())?;
			conn_data.write(&content)?;
			if config.show_response_headers {
				warn!("HTTP Response Headers:\n{}", response_prefix)?;
			}

			Ok((true, false, 0))
		} else {
			Ok((false, false, 0))
		}
	}

	fn process_api(
		now: SystemTime,
		buf: &[u8],
		headers: &HttpHeaders,
		api_config: &Arc<RwLock<HttpApiConfig>>,
		api_handler: &Option<Pin<Box<ApiHandler>>>,
		async_connections: &Arc<RwLock<StaticHash<(), ()>>>,
		conn_info: &mut ConnectionInfo,
		conn_data: &ConnectionData,
		temp_dir: &String,
		slabs: &Arc<RwLock<SlabAllocator>>,
		log_queue: &mut StaticQueue<LogItem>,
		dropped_log_items: &mut u64,
		stat_handler: &StatHandler,
		dropped_lat_sum: &mut u64,
	) -> Result<bool, Error> {
		let api_config = lockr!(api_config)?;
		if api_config.mappings.get(headers.get_uri()).is_some()
			|| api_config.extensions.get(headers.extension()).is_some()
		{
			match api_handler {
				Some(api_handler) => {
					let clen = headers.content_len()?;

					let mut uri = [0u8; MAX_LOG_STR_LEN];
					let headers_uri = headers.get_uri();
					let mut max = headers_uri.len();
					if max > MAX_LOG_STR_LEN {
						max = MAX_LOG_STR_LEN;
					};
					uri[0..max].clone_from_slice(&headers_uri[0..max]);

					let mut query = [0u8; MAX_LOG_STR_LEN];
					let headers_query = headers.get_query();
					let mut max = headers_query.len();
					if max > MAX_LOG_STR_LEN {
						max = MAX_LOG_STR_LEN;
					};
					query[0..max].clone_from_slice(&headers_query[0..max]);

					let headers_user_agent = headers.get_user_agent();
					let mut user_agent = [0u8; MAX_LOG_STR_LEN];
					let mut max = headers_user_agent.len();
					if max > MAX_LOG_STR_LEN {
						max = MAX_LOG_STR_LEN;
					};
					user_agent[0..max].clone_from_slice(&headers_user_agent[0..max]);

					let mut referer = [0u8; MAX_LOG_STR_LEN];
					let headers_referer = headers.get_referer();
					let mut max = headers_referer.len();
					if max > MAX_LOG_STR_LEN {
						max = MAX_LOG_STR_LEN;
					}
					referer[0..max].clone_from_slice(&headers_referer[0..max]);

					let log_item = LogItem {
						http_method: headers.get_method().clone(),
						http_version: headers.get_version().clone(),
						uri,
						query,
						referer,
						user_agent,
						content_len: clen.try_into()?,
						start_micros: now.duration_since(UNIX_EPOCH)?.as_micros() as u64,
						end_micros: 0,
						uri_requested: uri,
						response_code: 200,
					};

					let mut ctx = ApiContext::new(
						async_connections.clone(),
						conn_data.clone(),
						slabs.clone(),
						false,
						None,
						stat_handler.clone(),
						log_item,
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

					if !ctx.is_async() {
						Self::process_stats(
							ctx.log_item(),
							Some(log_queue),
							None,
							dropped_log_items,
							dropped_lat_sum,
						)?;
					}

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

	fn update_thread_context(
		thread_context: &mut ThreadContext,
		config: &HttpConfig,
		cache: &Arc<RwLock<HttpCache>>,
	) -> Result<(), Error> {
		if thread_context.instant.elapsed().as_millis() > config.process_cache_update {
			let ch = &mut thread_context.cache_hits;
			let mut cache = lockw!(cache)?;
			let itr = ch.iter_raw();
			for (k, _v) in itr {
				cache.bring_to_front(k.try_into()?)?;
			}
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
		code: &[u8],
		response_code: u16,
		uri_requested: &[u8],
		uri: &[u8],
		query: &[u8],
		user_agent: &[u8],
		referer: &[u8],
		conn_data: &ConnectionData,
		config: &HttpConfig,
		cache: &Arc<RwLock<HttpCache>>,
		http_version: &HttpVersion,
		http_method: &HttpMethod,
		range: Option<(usize, usize)>,
		mime_map: &HashMap<Vec<u8>, Vec<u8>>,
		async_connections: &Arc<RwLock<StaticHash<(), ()>>>,
		now: SystemTime,
		webroot: &Vec<u8>,
		slabs: &Arc<RwLock<SlabAllocator>>,
		close: bool,
		if_modified_since: &Option<Vec<Vec<u8>>>,
		if_none_match: &Option<Vec<Vec<u8>>>,
		gzip: bool,
		host: Option<Vec<Vec<u8>>>,
		local_peer: &Option<SocketAddr>,
		log_queue: &mut StaticQueue<LogItem>,
		stat_handler: &StatHandler,
		dropped_log_items: &mut u64,
		dropped_lat_sum: &mut u64,
		thread_pool: &Arc<RwLock<StaticThreadPool>>,
	) -> Result<Option<[u8; 32]>, Error> {
		if http_method != &HttpMethod::Get && http_method != &HttpMethod::Head {
			return Err(ErrorKind::HttpError405("Method not allowed.".into()).into());
		}

		let mut webroot_applied = webroot;
		let path = if config.virtual_hosts.len() > 0 {
			match host {
				Some(host) => {
					if host.len() > 0 {
						let host = match bytes_find(&host[0], &[':' as u8]) {
							Some(index) => &host[0][0..index],
							None => &host[0][..],
						};

						match config.virtual_hosts.get(host) {
							Some(host) => {
								webroot_applied = host;
								Some(host.clone())
							}
							None => None,
						}
					} else {
						None
					}
				}
				None => None,
			}
		} else {
			None
		};

		let mut path = if path.is_none() && config.virtual_ips.len() > 0 {
			match local_peer {
				Some(local_peer) => match config.virtual_ips.get(&local_peer) {
					Some(local_peer) => {
						webroot_applied = local_peer;
						local_peer.clone()
					}
					None => webroot.clone(),
				},
				None => webroot.clone(),
			}
		} else if path.is_none() {
			webroot.clone()
		} else {
			path.unwrap()
		};

		let webroot = webroot_applied;

		path.extend_from_slice(&uri);
		Self::clean(&mut path)?;
		Self::check_path(&path, &webroot)?;

		// try both the exact path and the version with index appended (metadata too expensive)
		let (found, need_update, key) = Self::try_send_cache(
			code,
			response_code,
			conn_data,
			&config,
			&path,
			&uri_requested.to_vec(),
			&uri.to_vec(),
			&query.to_vec(),
			&user_agent.to_vec(),
			&referer.to_vec(),
			&cache,
			now,
			http_version,
			http_method,
			range,
			mime_map,
			if_modified_since,
			if_none_match,
			gzip,
			log_queue,
			dropped_log_items,
			dropped_lat_sum,
		)?;
		let need_update = if found && !need_update {
			match http_version {
				HttpVersion::V10 | HttpVersion::Unknown => conn_data.close()?,
				HttpVersion::V11 | HttpVersion::V20 => match close {
					true => {
						conn_data.close()?;
					}
					false => {}
				},
			}

			return Ok(Some(key));
		} else if !found {
			let mut path2 = path.clone();
			path2.extend_from_slice(INDEX_HTML_BYTES);
			let (found, need_update, key) = Self::try_send_cache(
				code,
				response_code,
				conn_data,
				config,
				&path2,
				&uri_requested.to_vec(),
				&uri.to_vec(),
				&query.to_vec(),
				&user_agent.to_vec(),
				&referer.to_vec(),
				cache,
				now,
				http_version,
				http_method,
				range,
				mime_map,
				if_modified_since,
				if_none_match,
				gzip,
				log_queue,
				dropped_log_items,
				dropped_lat_sum,
			)?;

			if found && !need_update {
				match http_version {
					HttpVersion::V10 | HttpVersion::Unknown => conn_data.close()?,
					HttpVersion::V11 | HttpVersion::V20 => match close {
						true => {
							conn_data.close()?;
						}
						false => {}
					},
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
			code,
			response_code,
			path,
			uri_requested.to_vec(),
			uri.to_vec(),
			query.to_vec(),
			user_agent.to_vec(),
			referer.to_vec(),
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
			close,
			if_modified_since,
			if_none_match,
			gzip,
			stat_handler,
			thread_pool,
		)?;

		Ok(None)
	}

	fn not_modified(
		if_modified_since: &Option<Vec<Vec<u8>>>,
		if_none_match: &Option<Vec<Vec<u8>>>,
		etag: &[u8],
		last_modified: u128,
	) -> Result<bool, Error> {
		match &*if_modified_since {
			Some(if_modified_since) => {
				let mut date_fmt = vec![];
				Self::extend_date(&mut date_fmt, last_modified)?;
				let x = from_utf8(&date_fmt)?;
				if x.as_bytes() == if_modified_since[0] {
					return Ok(true);
				}
			}
			None => {}
		}

		match &*if_none_match {
			Some(if_none_match) => {
				let if_none_match_len = if_none_match.len();
				if if_none_match_len > 0 {
					let if_none_match = &if_none_match[0];
					if if_none_match.len() > 3 {
						let if_none_match_len = if_none_match.len();
						let if_none_match = &if_none_match[1..(if_none_match_len - 1)];
						if hex::encode(etag).as_bytes() == if_none_match {
							return Ok(true);
						}
					}
				}
			}
			None => {}
		}
		Ok(false)
	}

	// found, need_update, key
	fn try_send_cache(
		code: &[u8],
		response_code: u16,
		conn_data: &ConnectionData,
		config: &HttpConfig,
		path: &Vec<u8>,
		uri_requested: &Vec<u8>,
		uri: &Vec<u8>,
		query: &Vec<u8>,
		user_agent: &Vec<u8>,
		headers_referer: &Vec<u8>,
		cache: &Arc<RwLock<HttpCache>>,
		now: SystemTime,
		http_version: &HttpVersion,
		http_method: &HttpMethod,
		range: Option<(usize, usize)>,
		mime_map: &HashMap<Vec<u8>, Vec<u8>>,
		if_modified_since: &Option<Vec<Vec<u8>>>,
		if_none_match: &Option<Vec<Vec<u8>>>,
		gzip: bool,
		log_queue: &mut StaticQueue<LogItem>,
		dropped_log_items: &mut u64,
		dropped_lat_sum: &mut u64,
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
				let mut is_304 = false;
				for chunk in iter {
					let chunk_len = chunk.len();
					let wlen = if chunk_len + len_sum < len.try_into()? {
						chunk_len as usize
					} else {
						len as usize - len_sum
					};

					if !headers_sent {
						if Self::not_modified(
							if_modified_since,
							if_none_match,
							&etag,
							last_modified,
						)? {
							is_304 = true;
							Self::send_headers(
								HTTP_CODE_304,
								304,
								&conn_data,
								config,
								0,
								None,
								now_millis,
								now,
								last_modified,
								http_version,
								http_method,
								etag,
								range,
								path,
								uri_requested,
								uri,
								query,
								user_agent,
								headers_referer,
								mime_map,
								gzip,
								Some(log_queue),
								None,
								dropped_log_items,
								dropped_lat_sum,
							)?;
						} else {
							Self::send_headers(
								code,
								response_code,
								&conn_data,
								config,
								len,
								if http_method == &HttpMethod::Head {
									None
								} else {
									Some(&chunk[..wlen])
								},
								now_millis,
								now,
								last_modified,
								http_version,
								http_method,
								etag,
								range,
								path,
								uri_requested,
								uri,
								query,
								user_agent,
								headers_referer,
								mime_map,
								gzip,
								Some(log_queue),
								None,
								dropped_log_items,
								dropped_lat_sum,
							)?;
						}
						headers_sent = true;
					} else if !is_304 {
						Self::write_range(conn_data, &chunk[..wlen], range, len_sum, gzip, config)?;
					}

					len_sum += chunk_len;
				}

				if gzip {
					conn_data.write("0\r\n\r\n".as_bytes())?;
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
		code: &[u8],
		response_code: u16,
		path: Vec<u8>,
		uri_requested_headers: Vec<u8>,
		uri_headers: Vec<u8>,
		query: Vec<u8>,
		headers_user_agent: Vec<u8>,
		headers_referer: Vec<u8>,
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
		async_connections: &Arc<RwLock<StaticHash<(), ()>>>,
		slabs: &Arc<RwLock<SlabAllocator>>,
		close: bool,
		if_modified_since: &Option<Vec<Vec<u8>>>,
		if_none_match: &Option<Vec<Vec<u8>>>,
		gzip: bool,
		stat_handler: &StatHandler,
		thread_pool: &Arc<RwLock<StaticThreadPool>>,
	) -> Result<(), Error> {
		let http_version = http_version.clone();
		let mime_map = mime_map.clone();
		let len = md.len();

		let mut uri = [0u8; MAX_LOG_STR_LEN];
		let mut max = uri_headers.len();
		if max > MAX_LOG_STR_LEN {
			max = MAX_LOG_STR_LEN;
		};
		uri[0..max].clone_from_slice(&uri_headers[0..max]);

		let mut query_fixed = [0u8; MAX_LOG_STR_LEN];
		let mut max = query.len();
		if max > MAX_LOG_STR_LEN {
			max = MAX_LOG_STR_LEN;
		};
		query_fixed[0..max].clone_from_slice(&query[0..max]);

		let mut user_agent = [0u8; MAX_LOG_STR_LEN];
		let mut max = headers_user_agent.len();
		if max > MAX_LOG_STR_LEN {
			max = MAX_LOG_STR_LEN;
		};
		user_agent[0..max].clone_from_slice(&headers_user_agent[0..max]);

		let mut referer = [0u8; MAX_LOG_STR_LEN];
		let mut max = headers_referer.len();
		if max > MAX_LOG_STR_LEN {
			max = MAX_LOG_STR_LEN;
		}
		referer[0..max].clone_from_slice(&headers_referer[0..max]);

		let mut uri_requested = [0u8; MAX_LOG_STR_LEN];
		let mut max = uri_requested_headers.len();
		if max > MAX_LOG_STR_LEN {
			max = MAX_LOG_STR_LEN;
		}
		uri_requested[0..max].clone_from_slice(&uri_requested_headers[0..max]);

		let log_item = LogItem {
			http_method: http_method.clone(),
			http_version: http_version.clone(),
			uri,
			query: query_fixed,
			referer,
			user_agent,
			content_len: len,
			start_micros: now.duration_since(UNIX_EPOCH)?.as_micros() as u64,
			end_micros: 0,
			uri_requested,
			response_code,
		};

		let mut ctx = ApiContext::new(
			async_connections.clone(),
			conn_data.clone(),
			slabs.clone(),
			false,
			None,
			stat_handler.clone(),
			log_item,
		);

		ctx.set_async()?;

		let mut ctx = ctx.clone();
		let code = code.to_vec();
		let if_modified_since = if_modified_since.clone();
		let if_none_match = if_none_match.clone();
		let stat_handler = stat_handler.clone();

		let thread_pool = lockw!(thread_pool)?;

		thread_pool.execute(async move {
			let path_str = std::str::from_utf8(&path)?;
			let md_len = md.len();

			let chunk_size = config.cache_chunk_size;

			let mut sha256 = Sha256::new();
			let last_modified = md.modified()?.duration_since(UNIX_EPOCH)?.as_millis();
			sha256.write(&last_modified.to_be_bytes())?;
			sha256.write(&md.len().to_be_bytes())?;
			let hash = sha256.finalize();
			let etag: [u8; 8] = hash[0..8].try_into()?;
			let now_u128 = now.duration_since(UNIX_EPOCH)?.as_millis();

			let file = File::open(&path_str)?;
			let mut is_304 = false;

			if Self::not_modified(&if_modified_since, &if_none_match, &etag, last_modified)? {
				is_304 = true;
				ctx.set_response_code_logging(304)?;
				Self::send_headers(
					HTTP_CODE_304,
					304,
					&conn_data,
					&config,
					0,
					None,
					now_u128,
					now,
					last_modified,
					&http_version,
					&http_method,
					etag,
					range,
					&path,
					&uri_requested_headers.to_vec(),
					&uri.to_vec(),
					&query,
					&headers_user_agent,
					&headers_referer,
					&mime_map,
					gzip,
					None,
					Some(stat_handler),
					&mut 0,
					&mut 0,
				)?;
			} else {
				ctx.set_response_code_logging(response_code)?;
				Self::send_headers(
					&code,
					response_code,
					&conn_data,
					&config,
					md.len(),
					None,
					now_u128,
					now,
					md.modified()?.duration_since(UNIX_EPOCH)?.as_millis(),
					&http_version,
					&http_method,
					etag,
					range,
					&path,
					&uri_requested_headers.to_vec(),
					&uri.to_vec(),
					&query,
					&headers_user_agent,
					&headers_referer,
					&mime_map,
					gzip,
					None,
					Some(stat_handler),
					&mut 0,
					&mut 0,
				)?;
			}

			let mut len_sum = 0;
			let mut len_written = 0;
			if http_method != HttpMethod::Head {
				let handle;
				#[cfg(unix)]
				{
					handle = file.as_raw_fd();
				}
				#[cfg(target_os = "windows")]
				{
					handle = file.as_raw_handle();
				}

				let mut in_buf = Vec::with_capacity(chunk_size.try_into()?);
				in_buf.resize(chunk_size.try_into()?, 0u8);

				let whandle = conn_data.get_handle();
				#[cfg(unix)]
				unsafe {
					let flags = fcntl(whandle, libc::F_GETFL, 0);
					let flags = flags & !libc::O_NONBLOCK;
					fcntl(whandle, libc::F_SETFL, flags);
				}

				loop {
					let len = do_read(handle, &mut in_buf)?;
					if len <= 0 {
						break;
					}
					let nslice = &in_buf[0..len as usize];
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

					if !is_304 {
						match Self::write_range(
							&conn_data,
							nslice,
							range,
							len_written,
							gzip,
							&config,
						) {
							Ok(_) => {}
							Err(_) => {
								let whandle = conn_data.get_handle();
								#[cfg(unix)]
								unsafe {
									let flags = fcntl(whandle, libc::F_GETFL, 0);
									let flags = flags | libc::O_NONBLOCK;
									fcntl(whandle, libc::F_SETFL, flags);
								}

								// normal occurance. Other side closed.
								return Ok(());
							}
						}
					}
					len_written += nslice.len();
				}

				if gzip {
					conn_data.write("0\r\n\r\n".as_bytes())?;
				}
			}

			let whandle = conn_data.get_handle();
			#[cfg(unix)]
			unsafe {
				let flags = fcntl(whandle, libc::F_GETFL, 0);
				let flags = flags | libc::O_NONBLOCK;
				fcntl(whandle, libc::F_SETFL, flags);
			}

			match http_version {
				HttpVersion::V10 | HttpVersion::Unknown => conn_data.close()?,
				HttpVersion::V11 | HttpVersion::V20 => match close {
					true => {
						conn_data.close()?;
					}
					false => {}
				},
			}

			ctx.async_complete()?;

			Ok(())
		})?;

		Ok(())
	}

	fn write_range(
		conn_data: &ConnectionData,
		nslice: &[u8],
		range: Option<(usize, usize)>,
		len_written: usize,
		gzip: bool,
		config: &HttpConfig,
	) -> Result<(), Error> {
		let mut response;
		let slice = match range {
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
						&nslice[start..end]
					} else {
						&[]
					}
				} else {
					&[]
				}
			}
			None => &nslice,
		};
		if slice.len() > 0 {
			let slice = if gzip {
				response = vec![];
				let mut encoder =
					GzEncoder::new(Vec::new(), Compression::new(config.gzip_compression_level));
				encoder.write(slice)?;
				let gzip_vec = encoder.finish()?;
				response.extend_from_slice(format!("{:X}\r\n", gzip_vec.len()).as_bytes());
				response.extend_from_slice(&gzip_vec[..]);
				response.extend_from_slice("\r\n".as_bytes());
				&response[..]
			} else {
				slice
			};
			conn_data.write(slice)?;
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
		code: &[u8],
		response_code: u16,
		conn_data: &ConnectionData,
		config: &HttpConfig,
		len: u64,
		chunk: Option<&[u8]>,
		now: u128,
		now_system_time: SystemTime,
		last_modified: u128,
		http_version: &HttpVersion,
		http_method: &HttpMethod,
		etag: [u8; 8],
		range: Option<(usize, usize)>,
		path: &Vec<u8>,
		uri_requested_headers: &Vec<u8>,
		uri_headers: &Vec<u8>,
		query: &Vec<u8>,
		headers_user_agent: &Vec<u8>,
		headers_referer: &Vec<u8>,
		mime_map: &HashMap<Vec<u8>, Vec<u8>>,
		gzip: bool,
		log_queue: Option<&mut StaticQueue<LogItem>>,
		stat_handler: Option<StatHandler>,
		dropped_log_items: &mut u64,
		dropped_lat_sum: &mut u64,
	) -> Result<(), Error> {
		let mut response = vec![];
		match http_version {
			HttpVersion::V10 | HttpVersion::Unknown => {
				response.extend_from_slice(&HTTP10_BYTES_DISPLAY)
			}
			HttpVersion::V11 => response.extend_from_slice(&HTTP11_BYTES_DISPLAY),
			HttpVersion::V20 => response.extend_from_slice(&HTTP11_BYTES_DISPLAY),
		}
		match range {
			Some(_range) => {
				response.extend_from_slice(&HTTP_CODE_206);
				response.extend_from_slice(&HTTP_PARTIAL_206_HEADERS_VEC[0])
			}
			None => {
				response.extend_from_slice(&code);
				response.extend_from_slice(&HTTP_OK_200_HEADERS_VEC[0])
			}
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

		if gzip {
			response.extend_from_slice(TRANSFER_ENCODING_CHUNKED);
			response.extend_from_slice(GZIP_ENCODING);
		} else {
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
						if gzip {
							let mut encoder = GzEncoder::new(
								Vec::new(),
								Compression::new(config.gzip_compression_level),
							);
							encoder.write(&chunk[start..end])?;
							let gzip_vec = encoder.finish()?;
							response
								.extend_from_slice(format!("{:X}\r\n", gzip_vec.len()).as_bytes());
							response.extend_from_slice(&gzip_vec[..]);
							response.extend_from_slice("\r\n".as_bytes());
						} else {
							response.extend_from_slice(&chunk[start..end]);
						}
					}
				}
				None => {
					if gzip {
						let mut encoder = GzEncoder::new(
							Vec::new(),
							Compression::new(config.gzip_compression_level),
						);
						encoder.write(chunk)?;
						let gzip_vec = encoder.finish()?;
						response.extend_from_slice(format!("{:X}\r\n", gzip_vec.len()).as_bytes());
						response.extend_from_slice(&gzip_vec[..]);
						response.extend_from_slice("\r\n".as_bytes());
					} else {
						response.extend_from_slice(&chunk);
					}
				}
			},
			None => {}
		}

		conn_data.write(&response)?;

		let mut uri = [0u8; MAX_LOG_STR_LEN];
		let mut max = uri_headers.len();
		if max > MAX_LOG_STR_LEN {
			max = MAX_LOG_STR_LEN;
		};
		uri[0..max].clone_from_slice(&uri_headers[0..max]);

		let mut query_fixed = [0u8; MAX_LOG_STR_LEN];
		let mut max = query.len();
		if max > MAX_LOG_STR_LEN {
			max = MAX_LOG_STR_LEN;
		};
		query_fixed[0..max].clone_from_slice(&query[0..max]);

		let mut user_agent = [0u8; MAX_LOG_STR_LEN];
		let mut max = headers_user_agent.len();
		if max > MAX_LOG_STR_LEN {
			max = MAX_LOG_STR_LEN;
		};
		user_agent[0..max].clone_from_slice(&headers_user_agent[0..max]);

		let mut referer = [0u8; MAX_LOG_STR_LEN];
		let mut max = headers_referer.len();
		if max > MAX_LOG_STR_LEN {
			max = MAX_LOG_STR_LEN;
		}
		referer[0..max].clone_from_slice(&headers_referer[0..max]);

		let mut uri_requested = [0u8; MAX_LOG_STR_LEN];
		let mut max = uri_requested_headers.len();
		if max > MAX_LOG_STR_LEN {
			max = MAX_LOG_STR_LEN;
		}
		uri_requested[0..max].clone_from_slice(&uri_requested_headers[0..max]);

		let mut log_item = LogItem {
			http_method: http_method.clone(),
			http_version: http_version.clone(),
			uri,
			query: query_fixed,
			referer,
			user_agent,
			content_len: len,
			start_micros: now_system_time.duration_since(UNIX_EPOCH)?.as_micros() as u64,
			end_micros: 0,
			uri_requested,
			response_code,
		};

		Self::process_stats(
			&mut log_item,
			log_queue,
			stat_handler,
			dropped_log_items,
			dropped_lat_sum,
		)?;

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
		stat_handler: &StatHandler,
	) -> Result<(), Error> {
		let id = conn_data.get_connection_id();
		let handle = conn_data.get_handle();
		debug!("on accept: {}, handle={}", id, handle)?;
		let thread_context = Self::init_user_data(user_data, config, stat_handler)?;
		thread_context.connects += 1;
		insert_step_allocator(
			conn_data.clone(),
			&mut thread_context.active_connections,
			&mut thread_context.active_connection_index_map,
		)?;

		Ok(())
	}

	fn process_on_close(
		conn_data: &ConnectionData,
		_ctx: &mut ConnectionContext,
		config: &HttpConfig,
		user_data: &mut Box<dyn Any + Send + Sync>,
		stat_handler: &StatHandler,
	) -> Result<(), Error> {
		debug!("on close: {}", conn_data.get_connection_id())?;

		let thread_context = Self::init_user_data(user_data, config, stat_handler)?;

		let connection_id = conn_data.get_connection_id();

		match thread_context
			.active_connection_index_map
			.remove_raw(&connection_id.to_be_bytes())
		{
			Some(index) => {
				let index = usize::from_be_bytes(index.try_into()?);
				match thread_context
					.active_connections
					.get_mut(index)?
					.data_as_mut::<ConnectionInfo>()
				{
					Some(conn_info) => {
						match &conn_info.proxy_info {
							Some(proxy_info) => {
								// proxy connection
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

								let state =
									thread_context.proxy_state.get_mut(&proxy_info.proxy_entry);
								match state {
									Some(state) => {
										state.cur_connections =
											state.cur_connections.saturating_sub(1);
									}
									None => {}
								}

								match &proxy_info.response_conn_data {
									Some(conn_data) => {
										let mut async_connections =
											lockw!(thread_context.async_connections)?;
										match async_connections.remove_raw(
											&conn_data.get_connection_id().to_be_bytes(),
										) {
											Some(li_bytes) => {
												let mut log_item = LogItem::default();
												log_item.read(li_bytes.try_into()?)?;
												Self::process_stats(
													&mut log_item,
													Some(&mut thread_context.log_queue),
													None,
													&mut thread_context.dropped_log_items,
													&mut thread_context.dropped_lat_sum,
												)?;
											}
											None => {}
										}
									}
									None => {}
								}
							}
							None => {
								// regular connection
								thread_context.disconnects += 1;
							}
						}

						match &conn_info.api_context {
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

						conn_info.conn_data = None;
						conn_info.proxy_info = None;
						conn_info.api_context = None;
						conn_info.health_check_info = None;
					}
					None => {
						warn!("expected conn_info for id = {}", connection_id)?;
					}
				}
				thread_context.active_connections.free_index(index)?;
			}
			None => {
				warn!("expected index for id = {}", connection_id)?;
			}
		}

		// async connections should be removed by user, but if left to this point, we remove.
		// we don't want to block in the general case, so we try a read lock first.
		let found = {
			let async_connections = lockr!(thread_context.async_connections)?;
			async_connections
				.get_raw(&connection_id.to_be_bytes())
				.is_some()
		};

		if found {
			let mut async_connections = lockw!(thread_context.async_connections)?;
			async_connections.remove_raw(&connection_id.to_be_bytes());
		}

		Ok(())
	}

	fn check_log_rotation(tid: usize) -> Result<(), Error> {
		if tid == 0 {
			match rotation_status!()? {
				RotationStatus::Needed => {
					let nfile = rotate!()?;
					match nfile {
						Some(nfile) => info!("Main log rotated. [{}]", nfile)?,
						None => {}
					}
				}
				_ => {}
			}
		}

		Ok(())
	}

	fn process_stats_queue(stat_handler: &mut StatHandler) -> Result<(), Error> {
		let (log_items, log_events);
		{
			let mut queue = lockw!(stat_handler.queue)?;
			log_events = (*queue).log_events.clone();
			log_items = (*queue).log_items.clone();
			(*queue).log_items.clear()?;
			(*queue).log_events.clear()?;
		}

		match stat_handler
			.http_stats
			.store_log_items(log_items.into_iter(), log_events.into_iter())
		{
			Ok(_) => {}
			Err(e) => {
				error!("store_log items error: {}", e)?;
			}
		}

		Ok(())
	}

	fn run_stats_processor(&self) -> Result<(), Error> {
		let mut stat_handler = self.stat_handler.clone();

		std::thread::spawn(move || -> Result<(), Error> {
			loop {
				std::thread::sleep(std::time::Duration::from_millis(300));
				// to remove warning
				if false {
					break;
				}
				match Self::process_stats_queue(&mut stat_handler) {
					Ok(_) => {}
					Err(e) => error!("process_stats_queue generated: {}", e)?,
				}
			}
			Ok(())
		});
		Ok(())
	}

	fn process_stats(
		log_item: &mut LogItem,
		log_queue: Option<&mut StaticQueue<LogItem>>,
		_stat_handler: Option<StatHandler>,
		dropped_log_items: &mut u64,
		dropped_lat_sum: &mut u64,
	) -> Result<(), Error> {
		match log_queue {
			Some(log_queue) => {
				log_item.end_micros =
					SystemTime::now().duration_since(UNIX_EPOCH)?.as_micros() as u64;
				match log_queue.enqueue(*log_item) {
					Ok(_) => {}
					Err(_) => {
						// log queue is full
						*dropped_log_items += 1;
						*dropped_lat_sum += (SystemTime::now()
							.duration_since(UNIX_EPOCH)?
							.as_micros() as u64) - log_item.start_micros;
					}
				}
			}
			None => {}
		}

		Ok(())
	}

	fn process_housekeep_log_queue(thread_context: &mut ThreadContext) -> Result<(), Error> {
		{
			{
				let mut queue = lockw!(thread_context.stat_handler.queue)?;
				let mut i: u64 = 0;
				let size = thread_context.log_queue.size() as u64;
				for item in &thread_context.log_queue {
					match queue.log_items.enqueue(item) {
						Ok(_) => {}
						Err(_) => {
							// queue full
							thread_context.dropped_log_items += size.saturating_sub(i);
							break;
						}
					}
					i += 1;
				}

				let le = LogEvent {
					dropped_count: thread_context.dropped_log_items,
					read_timeout_count: thread_context.read_timeouts,
					connect_timeout_count: thread_context.connect_timeouts,
					connect_count: thread_context.connects,
					disconnect_count: thread_context.disconnects,
					dropped_lat_sum: thread_context.dropped_lat_sum,
				};
				queue.log_events.enqueue(le)?;
			}

			thread_context.dropped_log_items = 0;
			thread_context.read_timeouts = 0;
			thread_context.connect_timeouts = 0;
			thread_context.connects = 0;
			thread_context.disconnects = 0;
			thread_context.dropped_lat_sum = 0;
			thread_context.log_queue.clear()?;
		}

		Ok(())
	}

	fn process_on_housekeeper(
		config: &HttpConfig,
		user_data: &mut Box<dyn Any + Send + Sync>,
		evh_params: &EvhParams,
		tid: usize,
		stat_handler: &StatHandler,
	) -> Result<(), Error> {
		Self::check_log_rotation(tid)?;
		let now = SystemTime::now().duration_since(UNIX_EPOCH)?.as_micros();
		let thread_context = Self::init_user_data(user_data, config, stat_handler)?;

		let res = Self::process_housekeep_log_queue(thread_context);
		if res.is_err() {
			warn!("house keep err = {:?}", res)?;
		}

		process_health_check(thread_context, config, evh_params, tid)?;

		let mut index_list = vec![];
		for (_id, index) in thread_context.active_connection_index_map.iter_raw() {
			index_list.push(usize::from_be_bytes(index.try_into()?));
		}

		for index in index_list {
			match thread_context
				.active_connections
				.get_mut(index)?
				.data_as_mut::<ConnectionInfo>()
			{
				Some(connection) => {
					if now.saturating_sub(connection.last_data) >= config.idle_timeout * 1_000 {
						// read timeout
						thread_context.read_timeouts += 1;
						match &connection.conn_data {
							Some(conn_data) => conn_data.close()?,
							None => {
								warn!("expected conn_data for index {}", index)?;
							}
						}
					} else if connection.last_data == connection.connection
						&& now.saturating_sub(connection.connection)
							>= config.connect_timeout * 1_000
					{
						// connect timeout
						thread_context.connect_timeouts += 1;
						match &connection.conn_data {
							Some(conn_data) => conn_data.close()?,
							None => {
								warn!("expected conn_data for index {}", index)?;
							}
						}
					}
				}
				None => {
					warn!("index not found in housekeeper: {}", index)?;
				}
			}
		}

		Ok(())
	}

	fn get_handle() -> Result<Handle, Error> {
		let r = socket(AddressFamily::Inet, Stream, SockFlag::empty(), None)?;
		let o: libc::c_int = 1;
		let s = mem::size_of_val(&o);

		unsafe {
			setsockopt(
				r,
				SOL_SOCKET,
				SO_REUSEPORT,
				&o as *const _ as *const c_void,
				s as socklen_t,
			)
		};

		unsafe {
			setsockopt(
				r,
				SOL_SOCKET,
				SO_REUSEADDR,
				&o as *const _ as *const c_void,
				s as socklen_t,
			)
		};

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

pub fn active_connection_get_mut<'a>(
	id: u128,
	step_allocator: &'a mut StepAllocator,
	active_connection_index_map: &'a mut StaticHash<(), ()>,
) -> Result<Option<&'a mut ConnectionInfo>, Error> {
	Ok(
		match active_connection_index_map.get_raw(&id.to_be_bytes()) {
			Some(index) => step_allocator
				.get_mut(usize::from_be_bytes(index.try_into()?))?
				.data_as_mut::<ConnectionInfo>(),
			None => None,
		},
	)
}

pub fn insert_step_allocator<'a>(
	conn_data: ConnectionData,
	step_allocator: &mut StepAllocator,
	active_connection_index_map: &mut StaticHash<(), ()>,
) -> Result<usize, Error> {
	match step_allocator.next() {
		Some(next) => {
			let ret = next.index();
			populate_next(next, conn_data, active_connection_index_map)?;
			Ok(ret)
		}
		None => {
			step_allocator.step(&ConnectionInfo::new_empty());
			let next = step_allocator.next().unwrap();
			let ret = next.index();
			populate_next(next, conn_data, active_connection_index_map)?;
			Ok(ret)
		}
	}
}

fn populate_next<'a>(
	next: &mut DataHolder,
	conn_data: ConnectionData,
	active_connection_index_map: &mut StaticHash<(), ()>,
) -> Result<(), Error> {
	let connection_id = conn_data.get_connection_id();
	let index = next.index();
	let connection_info = next.data_as_mut::<ConnectionInfo>().unwrap();
	let now = SystemTime::now()
		.duration_since(UNIX_EPOCH)
		.unwrap()
		.as_micros();
	connection_info.set(now, now, conn_data, None, None, None, false);

	active_connection_index_map.insert_raw(
		&connection_id.to_be_bytes(),
		&(index as usize).to_be_bytes(),
	)?;
	Ok(())
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
			// would
			// block
			len = -2;
		}
		Ok(len.try_into().unwrap_or(-1))
	}
}

#[cfg(test)]
mod test {
	use crate::http::{clean, ConnectionData, HttpConfig, HttpServer};
	use crate::send_websocket_message;
	use crate::types::{
		ApiContext, HealthCheck, HttpMethod, HttpVersion, ListenerType, ProxyConfig, ProxyEntry,
		ProxyRotation, Upstream,
	};
	use crate::websocket::WebSocketMessage;
	use crate::websocket::WebSocketMessageType;
	use crate::HttpApiConfig;
	use crate::HttpHeaders;
	use nioruntime_deps::flate2::read::GzDecoder;
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
	use std::time::SystemTime;

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
				None,
			)],
			webroot: format!("{}/www", root_dir).as_bytes().to_vec(),
			mainlog: format!("{}/logs/mainlog.log", root_dir),
			lmdb_dir: format!("{}/lmdb", root_dir),
			request_log_config: LogConfig {
				file_path: Some(format!("{}/logs/requestlog.log", root_dir)),
				..Default::default()
			},
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
		http.set_ws_handler(move |_, _, _| Ok(false))?;
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

		let port = 14899;
		let config = HttpConfig {
			listeners: vec![(
				ListenerType::Plain,
				SocketAddr::from_str(&format!("127.0.0.1:{}", port)[..])?,
				None,
			)],
			webroot: format!("{}/www", root_dir).as_bytes().to_vec(),
			mainlog: format!("{}/logs/mainlog.log", root_dir),
			lmdb_dir: format!("{}/lmdb", root_dir),
			request_log_config: LogConfig {
				file_path: Some(format!("{}/logs/requestlog.log", root_dir)),
				..Default::default()
			},
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
		http.set_ws_handler(move |_, _, _| Ok(false))?;
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
				None,
			)],
			webroot: format!("{}/www", root_dir).as_bytes().to_vec(),
			mainlog: format!("{}/logs/mainlog.log", root_dir),
			lmdb_dir: format!("{}/lmdb", root_dir),
			request_log_config: LogConfig {
				file_path: Some(format!("{}/logs/requestlog.log", root_dir)),
				..Default::default()
			},
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
		http.set_ws_handler(move |_, _, _| Ok(false))?;
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
				None,
			)],
			webroot: format!("{}/www", root_dir).as_bytes().to_vec(),
			mainlog: format!("{}/logs/mainlog.log", root_dir),
			lmdb_dir: format!("{}/lmdb", root_dir),
			request_log_config: LogConfig {
				file_path: Some(format!("{}/logs/requestlog.log", root_dir)),
				..Default::default()
			},
			temp_dir: format!("{}/tmp", root_dir),
			debug: true,
			show_request_headers: true,
			..Default::default()
		};

		let mut http = HttpServer::new(config).unwrap();

		http.set_api_handler(move |_conn_data, _headers, _ctx| Ok(()))?;
		http.set_ws_handler(move |_, _, _| Ok(false))?;
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
				None,
			)],
			webroot: format!("{}/www", root_dir).as_bytes().to_vec(),
			mainlog: format!("{}/logs/mainlog.log", root_dir),
			lmdb_dir: format!("{}/lmdb", root_dir),
			request_log_config: LogConfig {
				file_path: Some(format!("{}/logs/requestlog.log", root_dir)),
				..Default::default()
			},
			temp_dir: format!("{}/tmp", root_dir),
			debug: true,
			show_request_headers: true,
			..Default::default()
		};

		let mut http = HttpServer::new(config).unwrap();

		http.set_api_handler(move |_conn_data, _headers, _ctx| Ok(()))?;
		http.set_ws_handler(move |_, _, _| Ok(false))?;
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
				None,
			)],
			mainlog: format!("{}/logs/mainlog.log", root_dir),
			lmdb_dir: format!("{}/lmdb", root_dir),
			request_log_config: LogConfig {
				file_path: Some(format!("{}/logs/requestlog.log", root_dir)),
				..Default::default()
			},
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
		http.set_ws_handler(move |_, _, _| Ok(false))?;
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
	fn test_proxy1() -> Result<(), Error> {
		let root_dir = "./.test_proxy.nio";
		setup_test_dir(root_dir)?;

		let port1 = 18990;
		let port2 = 18991;

		let config1 = HttpConfig {
			listeners: vec![(
				ListenerType::Plain,
				SocketAddr::from_str(&format!("127.0.0.1:{}", port1)[..])?,
				None,
			)],
			show_request_headers: true,
			webroot: format!("{}/www", root_dir).as_bytes().to_vec(),
			mainlog: format!("{}/logs/mainlog.log", root_dir),
			lmdb_dir: format!("{}/lmdb", root_dir),
			request_log_config: LogConfig {
				file_path: Some(format!("{}/logs/requestlog.log", root_dir)),
				..Default::default()
			},
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
				vec![Upstream::new(
					SocketAddr::from_str(&format!("127.0.0.1:{}", port1)[..]).unwrap(),
					1,
				)],
				100,
				Some(HealthCheck {
					check_secs: 3000,
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
				None,
			)],
			webroot: format!("{}/www", root_dir).as_bytes().to_vec(),
			mainlog: format!("{}/logs/mainlog.log", root_dir),
			lmdb_dir: format!("{}/lmdb", root_dir),
			request_log_config: LogConfig {
				file_path: Some(format!("{}/logs/requestlog.log", root_dir)),
				..Default::default()
			},
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
		http1.set_ws_handler(move |_, _, _| Ok(false))?;
		http1.set_api_config(HttpApiConfig {
			..Default::default()
		})?;
		http1.start()?;

		let mut http2 = HttpServer::new(config2).unwrap();

		http2.set_api_handler(move |_conn_data, _headers, _ctx| Ok(()))?;
		http2.set_ws_handler(move |_, _, _| Ok(false))?;
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
				None,
			)],
			webroot: format!("{}/www", root_dir).as_bytes().to_vec(),
			mainlog: format!("{}/logs/mainlog.log", root_dir),
			lmdb_dir: format!("{}/lmdb", root_dir),
			request_log_config: LogConfig {
				file_path: Some(format!("{}/logs/requestlog.log", root_dir)),
				..Default::default()
			},
			temp_dir: format!("{}/tmp", root_dir),
			debug: true,
			show_request_headers: true,
			..Default::default()
		};

		let mut http = HttpServer::new(config).unwrap();

		http.set_api_handler(move |_conn_data, _headers, _ctx| Ok(()))?;
		http.set_ws_handler(move |_, _, _| Ok(false))?;
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
				None,
			)],
			webroot: format!("{}/www", root_dir).as_bytes().to_vec(),
			mainlog: format!("{}/logs/mainlog.log", root_dir),
			lmdb_dir: format!("{}/lmdb", root_dir),
			request_log_config: LogConfig {
				file_path: Some(format!("{}/logs/requestlog.log", root_dir)),
				..Default::default()
			},
			temp_dir: format!("{}/tmp", root_dir),
			debug: true,
			show_request_headers: true,
			..Default::default()
		};

		let mut http = HttpServer::new(config).unwrap();

		http.set_ws_handler(move |_, _, _| Ok(false))?;
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
				None,
			)],
			webroot: format!("{}/www", root_dir).as_bytes().to_vec(),
			mainlog: format!("{}/logs/mainlog.log", root_dir),
			lmdb_dir: format!("{}/lmdb", root_dir),
			request_log_config: LogConfig {
				file_path: Some(format!("{}/logs/requestlog.log", root_dir)),
				..Default::default()
			},
			temp_dir: format!("{}/tmp", root_dir),
			debug: true,
			show_request_headers: true,
			..Default::default()
		};

		let mut http = HttpServer::new(config).unwrap();

		http.set_ws_handler(move |_, _, _| Ok(false))?;
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
				None,
			)],
			webroot: format!("{}/www", root_dir).as_bytes().to_vec(),
			mainlog: format!("{}/logs/mainlog.log", root_dir),
			lmdb_dir: format!("{}/lmdb", root_dir),
			request_log_config: LogConfig {
				file_path: Some(format!("{}/logs/requestlog.log", root_dir)),
				..Default::default()
			},
			temp_dir: format!("{}/tmp", root_dir),
			debug: true,
			show_request_headers: true,
			..Default::default()
		};

		let mut http = HttpServer::new(config).unwrap();

		http.set_ws_handler(move |_, _, _| Ok(false))?;
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
				None,
			)],
			webroot: format!("{}/www", root_dir).as_bytes().to_vec(),
			mainlog: format!("{}/logs/mainlog.log", root_dir),
			lmdb_dir: format!("{}/lmdb", root_dir),
			request_log_config: LogConfig {
				file_path: Some(format!("{}/logs/requestlog.log", root_dir)),
				..Default::default()
			},
			temp_dir: format!("{}/tmp", root_dir),
			debug: true,
			show_request_headers: true,
			..Default::default()
		};

		let mut http = HttpServer::new(config).unwrap();

		http.set_ws_handler(move |_, _, _| Ok(false))?;
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
				None,
			)],
			show_request_headers: true,
			webroot: format!("{}/www1", root_dir).as_bytes().to_vec(),
			mainlog: format!("{}/logs1/mainlog.log", root_dir),
			lmdb_dir: format!("{}/lmdb1", root_dir),
			request_log_config: LogConfig {
				file_path: Some(format!("{}/logs1/requestlog.log", root_dir)),
				..Default::default()
			},
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
				None,
			)],
			webroot: format!("{}/www2", root_dir).as_bytes().to_vec(),
			mainlog: format!("{}/logs2/mainlog.log", root_dir),
			lmdb_dir: format!("{}/lmdb2", root_dir),
			request_log_config: LogConfig {
				file_path: Some(format!("{}/logs2/requestlog.log", root_dir)),
				..Default::default()
			},
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

		http1.set_ws_handler(move |_, _, _| Ok(false))?;
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
		http2.set_ws_handler(move |_, _, _| Ok(false))?;

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
				None,
			)],
			content_upload_slab_count: 1000,
			content_upload_slab_size: 8,

			webroot: format!("{}/www", root_dir).as_bytes().to_vec(),
			mainlog: format!("{}/logs/mainlog.log", root_dir),
			lmdb_dir: format!("{}/lmdb", root_dir),
			request_log_config: LogConfig {
				file_path: Some(format!("{}/logs/requestlog.log", root_dir)),
				..Default::default()
			},
			temp_dir: format!("{}/tmp", root_dir),
			debug: true,
			show_request_headers: true,
			..Default::default()
		};

		let mut http = HttpServer::new(config).unwrap();

		http.set_ws_handler(move |_, _, _| Ok(false))?;
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
				None,
			)],
			show_request_headers: true,
			webroot: format!("{}/www", root_dir).as_bytes().to_vec(),
			mainlog: format!("{}/logs/mainlog.log", root_dir),
			lmdb_dir: format!("{}/lmdb", root_dir),
			request_log_config: LogConfig {
				file_path: Some(format!("{}/logs/requestlog.log", root_dir)),
				..Default::default()
			},
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
				None,
			)],
			webroot: format!("{}/www", root_dir).as_bytes().to_vec(),
			mainlog: format!("{}/logs/mainlog.log", root_dir),
			lmdb_dir: format!("{}/lmdb", root_dir),
			request_log_config: LogConfig {
				file_path: Some(format!("{}/logs/requestlog.log", root_dir)),
				..Default::default()
			},
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
		http1.set_ws_handler(move |_, _, _| Ok(false))?;
		let mut http2 = HttpServer::new(config2).unwrap();
		http2.set_ws_handler(move |_, _, _| Ok(false))?;

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
	fn test_websocket() -> Result<(), Error> {
		let root_dir = "./.test_websocket.nio";
		setup_test_dir(root_dir)?;

		let port = 8999;

		let config = HttpConfig {
			listeners: vec![(
				ListenerType::Plain,
				SocketAddr::from_str(&format!("127.0.0.1:{}", port)[..])?,
				None,
			)],
			webroot: format!("{}/www", root_dir).as_bytes().to_vec(),
			mainlog: format!("{}/logs/mainlog.log", root_dir),
			lmdb_dir: format!("{}/lmdb", root_dir),
			request_log_config: LogConfig {
				file_path: Some(format!("{}/logs/requestlog.log", root_dir)),
				..Default::default()
			},
			temp_dir: format!("{}/tmp", root_dir),
			debug: true,
			show_request_headers: true,
			..Default::default()
		};

		let mut http = HttpServer::new(config).unwrap();
		let x = Arc::new(RwLock::new(false));
		let x_clone = x.clone();
		http.set_ws_handler(move |conn_data, uri, msg| {
			info!("uri={}", std::str::from_utf8(uri)?)?;
			assert_eq!(uri, &(b"/myws".to_vec()));
			assert_eq!(msg.payload, &[1]);
			send_websocket_message(
				conn_data,
				&WebSocketMessage {
					payload: vec![1, 2, 3, 4, 5],
					mtype: WebSocketMessageType::Text,
					mask: false,
				},
			)?;
			let mut x = lockw!(x)?;
			*x = true;
			Ok(true)
		})?;
		http.set_api_handler(move |_conn_data, _headers, _ctx| Ok(()))?;
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
			b"GET /myws HTTP/1.1\r\nUpgrade: websocket\r\nSec-WebSocket-Key: 123456\r\n\r\n",
		)?;

		const SIMPLE_WS_MESSAGE: &[u8] = &[130, 1, 1]; // binary data with a single byte of data, unmasked
		strm.write(SIMPLE_WS_MESSAGE)?;
		let start = SystemTime::now();
		loop {
			std::thread::sleep(std::time::Duration::from_millis(1));
			if start.elapsed()?.as_secs() > 30 {
				assert!(false);
			}
			if *lockr!(x_clone)? {
				break;
			}
		}

		let mut buf = [0u8; 10000];
		let len = strm.read(&mut buf)?;

		assert!(len >= 11);
		assert_eq!(buf[len - 1], 5);
		assert_eq!(buf[len - 2], 4);
		assert_eq!(buf[len - 3], 3);
		assert_eq!(buf[len - 4], 2);
		assert_eq!(buf[len - 5], 1);
		assert_eq!(buf[len - 6], 5);
		assert_eq!(buf[len - 7], 129);
		assert_eq!(buf[len - 8], 10);
		assert_eq!(buf[len - 9], 13);
		assert_eq!(buf[len - 10], 10);
		assert_eq!(buf[len - 11], 13);

		assert!(*lockr!(x_clone)?);

		Ok(())
	}

	#[test]
	fn test_gzip() -> Result<(), Error> {
		let root_dir = "./.test_gzip.nio";
		setup_test_dir(root_dir)?;

		let port = 19999;
		let mut gzip_extensions = HashSet::new();
		gzip_extensions.insert((b"html").to_vec());

		let config = HttpConfig {
			listeners: vec![(
				ListenerType::Plain,
				SocketAddr::from_str(&format!("127.0.0.1:{}", port)[..])?,
				None,
			)],
			webroot: format!("{}/www", root_dir).as_bytes().to_vec(),
			mainlog: format!("{}/logs/mainlog.log", root_dir),
			lmdb_dir: format!("{}/lmdb", root_dir),
			request_log_config: LogConfig {
				file_path: Some(format!("{}/logs/requestlog.log", root_dir)),
				..Default::default()
			},
			gzip_extensions,
			temp_dir: format!("{}/tmp", root_dir),
			debug: true,
			show_request_headers: true,
			..Default::default()
		};

		let mut http = HttpServer::new(config).unwrap();
		http.set_ws_handler(move |_, _, _| Ok(false))?;
		http.set_api_handler(move |_conn_data, _headers, _ctx| Ok(()))?;
		let mut mappings = HashSet::new();
		mappings.insert(b"/api".to_vec());

		http.set_api_config(HttpApiConfig {
			mappings,
			..Default::default()
		})?;
		http.start()?;

		let mut strm =
			TcpStream::connect(SocketAddr::from_str(&format!("127.0.0.1:{}", port)[..])?)?;
		strm.write(b"GET /index.html HTTP/1.0\r\nAccept-Encoding: gzip\r\n\r\n")?;

		let mut buf = vec![];
		buf.resize(1000, 0u8);
		let mut len_sum = 0;
		loop {
			let len = strm.read(&mut buf[len_sum..])?;
			len_sum += len;
			if len == 0 {
				break;
			}
		}

		let find = bytes_find(&buf[0..len_sum], "\r\n\r\n".as_bytes());
		assert!(find.is_some());
		let mut gz = GzDecoder::new(&buf[(find.unwrap() + 8)..(buf.len() - 5)]);
		let mut s = String::new();
		gz.read_to_string(&mut s)?;

		let mut strm =
			TcpStream::connect(SocketAddr::from_str(&format!("127.0.0.1:{}", port)[..])?)?;
		strm.write(b"GET /index.html HTTP/1.0\r\n\r\n")?;

		let mut buf = vec![];
		buf.resize(1000, 0u8);
		let mut len_sum = 0;
		loop {
			let len = strm.read(&mut buf[len_sum..])?;
			len_sum += len;
			if len == 0 {
				break;
			}
		}

		let resp = std::str::from_utf8(&buf[0..len_sum])?;

		// resp should contain the delated portion of the first response
		assert!(resp.find(&s).is_some());

		http.stop()?;

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
