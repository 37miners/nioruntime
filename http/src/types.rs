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

use crate::admin::FunctionalRule;
use crate::admin::HttpAdmin;
use crate::data::HttpData;
use crate::stats::{HttpStats, HttpStatsConfig, LOG_ITEM_SIZE};
use crate::LogItem;
use nioruntime_deps::base58;
use nioruntime_deps::digest::Digest;
use nioruntime_deps::dirs;
use nioruntime_deps::lazy_static::lazy_static;
use nioruntime_deps::path_clean::clean as path_clean;
use nioruntime_deps::rand;
use nioruntime_deps::sha1::Sha1;
use nioruntime_err::{Error, ErrorKind};
use nioruntime_evh::TLSServerConfig;
use nioruntime_evh::{ConnectionData, EventHandlerConfig};
use nioruntime_log::*;
use nioruntime_util::bytes_find;
use nioruntime_util::bytes_to_usize;
use nioruntime_util::multi_match::{Dictionary, Match, MultiMatch, Pattern};
use nioruntime_util::slabs::SlabAllocator;
use nioruntime_util::StaticQueue;
use nioruntime_util::{lockr, lockw};
use nioruntime_util::{StaticHash, StaticHashConfig, StepAllocator, StepAllocatorConfig};
use std::collections::{HashMap, HashSet};
use std::convert::TryInto;
use std::fmt::{Display, Formatter};
use std::fs::{remove_file, File, OpenOptions};
use std::hash::Hasher;
use std::io::{Read, Seek, SeekFrom, Write};
use std::net::SocketAddr;
use std::path::Path;
use std::path::PathBuf;
use std::str::FromStr;
use std::sync::mpsc::channel;
use std::sync::mpsc::{sync_channel, Receiver, SyncSender};
use std::sync::{Arc, RwLock};
use std::time::{Instant, SystemTime, UNIX_EPOCH};

use std::os::unix::prelude::RawFd;

lazy_static! {
	pub static ref HTTP_PARTIAL_206_HEADERS_VEC: Vec<Vec<u8>> = vec![
		"\r\nServer: ".as_bytes().to_vec(),
		"\"\r\nContent-Range: bytes ".as_bytes().to_vec(),
		"-".as_bytes().to_vec(),
		"/".as_bytes().to_vec(),
		"".as_bytes().to_vec(),
		"\r\n\r\n".as_bytes().to_vec(),
	];
	pub static ref HTTP_OK_200_HEADERS_VEC: Vec<Vec<u8>> = vec![
		"\r\nServer: ".as_bytes().to_vec(),
		"\r\nDate: ".as_bytes().to_vec(),
		"\r\nLast-Modified: ".as_bytes().to_vec(),
		"\r\nConnection: ".as_bytes().to_vec(),
		"\r\nContent-Length: ".as_bytes().to_vec(),
		"\r\nETag: \"".as_bytes().to_vec(),
		"\"\r\nAccept-Ranges: bytes".as_bytes().to_vec(),
		"\r\n\r\n".as_bytes().to_vec(),
	];
	pub static ref HEALTH_CHECK_VEC: Vec<Vec<u8>> = vec![
		"GET ".as_bytes().to_vec(),
		" HTTP/1.1\r\n\
Host: localhost\r\n\
Connection: close\r\n\r\n"
			.as_bytes()
			.to_vec(),
	];
}

const SIZEOF_USIZE: usize = std::mem::size_of::<usize>();
const SIZEOF_U128: usize = std::mem::size_of::<u128>();

pub const INDEX_HTML_BYTES: &[u8] = "/index.html".as_bytes();
pub const CONTENT_TYPE_BYTES: &[u8] = "\r\nContent-Type: ".as_bytes();
pub const BACK_R: &[u8] = "\r".as_bytes();

pub const HTTP_CODE_206: &[u8] = "206 Partial Content".as_bytes();
pub const HTTP_CODE_200: &[u8] = "200 OK".as_bytes();
pub const HTTP_CODE_304: &[u8] = "304 Not Modified".as_bytes();
pub const HTTP_CODE_400: &[u8] = "400 Bad request".as_bytes();
pub const HTTP_CODE_403: &[u8] = "403 Forbidden".as_bytes();
pub const HTTP_CODE_404: &[u8] = "404 Not Found".as_bytes();
pub const HTTP_CODE_405: &[u8] = "405 Method not supported".as_bytes();
pub const HTTP_CODE_413: &[u8] = "413 Request Entity Too Large".as_bytes();
pub const HTTP_CODE_431: &[u8] = "431 Request Header Fields Too Large".as_bytes();
pub const HTTP_CODE_500: &[u8] = "500 Internal Server Error".as_bytes();
pub const HTTP_CODE_502: &[u8] = "502 Bad Gateway".as_bytes();

pub const VERSION: &'static str = env!("CARGO_PKG_VERSION");

pub const END_HEADERS: &[u8] = "\r\n\r\n".as_bytes();
pub const CONTENT_LENGTH: &[u8] = "\r\nContent-Length: ".as_bytes();
pub const CONNECTION_CLOSE: &[u8] = "\r\nConnection: close\r\n".as_bytes();
pub const TRANSFER_ENCODING_CHUNKED: &[u8] = "\r\nTransfer-Encoding: chunked".as_bytes();
pub const GZIP_ENCODING: &[u8] = "\r\nContent-Encoding: gzip".as_bytes();

pub const HTML_EXTENSION: &[u8] = "html".as_bytes();
pub const SLASH: &[u8] = "/".as_bytes();
pub const EMPTY: &[u8] = "".as_bytes();
pub const SPACE: &[u8] = " ".as_bytes();
pub const QUESTION_MARK: &[u8] = "?".as_bytes();
pub const DOT: &[u8] = ".".as_bytes();

pub const MON_BYTES: &[u8] = "Mon, ".as_bytes();
pub const TUE_BYTES: &[u8] = "Tue, ".as_bytes();
pub const WED_BYTES: &[u8] = "Wed, ".as_bytes();
pub const THU_BYTES: &[u8] = "Thu, ".as_bytes();
pub const FRI_BYTES: &[u8] = "Fri, ".as_bytes();
pub const SAT_BYTES: &[u8] = "Sat, ".as_bytes();
pub const SUN_BYTES: &[u8] = "Sun, ".as_bytes();

pub const JAN_BYTES: &[u8] = " Jan ".as_bytes();
pub const FEB_BYTES: &[u8] = " Feb ".as_bytes();
pub const MAR_BYTES: &[u8] = " Mar ".as_bytes();
pub const APR_BYTES: &[u8] = " Apr ".as_bytes();
pub const MAY_BYTES: &[u8] = " May ".as_bytes();
pub const JUN_BYTES: &[u8] = " Jun ".as_bytes();
pub const JUL_BYTES: &[u8] = " Jul ".as_bytes();
pub const AUG_BYTES: &[u8] = " Aug ".as_bytes();
pub const SEP_BYTES: &[u8] = " Sep ".as_bytes();
pub const OCT_BYTES: &[u8] = " Oct ".as_bytes();
pub const NOV_BYTES: &[u8] = " Nov ".as_bytes();
pub const DEC_BYTES: &[u8] = " Dec ".as_bytes();

pub const HTTP10_BYTES_DISPLAY: &[u8] = "HTTP/1.0 ".as_bytes();
pub const HTTP11_BYTES_DISPLAY: &[u8] = "HTTP/1.1 ".as_bytes();

pub const KEEP_ALIVE_BYTES: &[u8] = "keep-alive".as_bytes();
pub const CLOSE_BYTES: &[u8] = "close".as_bytes();

pub const WEBSOCKET_GUID: &str = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11";

pub const HTTP_CONTINUE_100: &[u8] = b"HTTP/1.1 100 Continue\r\n\r\n";

pub const HTTP_ERROR_400: &[u8] = b"HTTP/1.1 400 Bad request\r\n\
Server: nioruntime httpd/0.0.3-beta.1\r\n\
Content-Type: text/html\r\n\
Content-Length: 14\r\n\
Connection: close\r\n\
\r\n\
Bad Request.\r\n";

pub const HTTP_ERROR_403: &[u8] = b"HTTP/1.1 403 Forbidden\r\n\
Server: nioruntime httpd/0.0.3-beta.1\r\n\
Content-Type: text/html\r\n\
Content-Length: 12\r\n\
Connection: close\r\n\
\r\n\
Forbidden.\r\n";

pub const HTTP_ERROR_404: &[u8] = b"HTTP/1.1 404 Not found\r\n\
Server: nioruntime httpd/0.0.3-beta.1\r\n\
Content-Type: text/html\r\n\
Content-Length: 12\r\n\
Connection: close\r\n\r\n\
Not found.\r\n";

pub const HTTP_ERROR_405: &[u8] = b"HTTP/1.1 405 Method not supported\r\n\
Server: nioruntime httpd/0.0.3-beta.1\r\n\
Content-Type: text/html\r\n\
Content-Length: 23\r\n\
Connection: close\r\n\
\r\n\
Method Not supported.\r\n";

pub const HTTP_ERROR_413: &[u8] = b"HTTP/1.1 413 Request Entity Too Large\r\n\
Server: nioruntime httpd/0.0.3-beta.1\r\n\
Content-Type: text/html\r\n\
Content-Length: 27\r\n\
Connection: close\r\n\r\n\
Request Entity Too Large.\r\n";

pub const HTTP_ERROR_431: &[u8] = b"HTTP/1.1 431 Request Header Fields Too Large\r\n\
Server: nioruntime httpd/0.0.3-beta.1\r\n\
Content-Type: text/html\r\n\
Content-Length: 34\r\n\
Connection: close\r\n\
\r\n\
Request Header Fields Too Large.\r\n";

pub const HTTP_ERROR_502: &[u8] = b"HTTP/1.1 502 Bad Gateway\r\n\
Server: nioruntime httpd/0.0.3-beta.1\r\n\
Content-Type: text/html\r\n\
Content-Length: 14\r\n\
Connection: close\r\n\
\r\n\
Bad Gateway.\r\n";

pub const HTTP_ERROR_503: &[u8] = b"HTTP/1.1 503 Service Unavailable\r\n\
Server: nioruntime httpd/0.0.3-beta.1\r\n\
Content-Type: text/html\r\n\
Content-Length: 22\r\n\
Connection: close\r\n\
\r\n\
Service Unavailable.\r\n";

pub const HTTP_ERROR_500: &[u8] = b"HTTP/1.1 500 Internal Server Error\r\n\
Server: nioruntime httpd/0.0.3-beta.1\r\n\
Content-Type: text/html\r\n\
Content-Length: 24\r\n\
Connection: close\r\n\
\r\n\
Internal Server Error.\r\n";

pub const MATCH_TERMINATE_HEADERS: u64 = 1;
pub const MATCH_HEADER_NAME: u64 = 2;

pub const MATCH_HEADER_REFERER: u64 = 3;
pub const MATCH_HEADER_CONTENT_LENGTH: u64 = 4;
pub const MATCH_HEADER_HOST: u64 = 5;
pub const MATCH_HEADER_COOKIE: u64 = 6;
pub const MATCH_HEADER_UPGRADE_WEBSOCKET: u64 = 7;
pub const MATCH_HEADER_SEC_WEBSOCKET_KEY: u64 = 8;
pub const MATCH_HEADER_RANGE: u64 = 9;
pub const MATCH_HEADER_USER_AGENT: u64 = 10;
pub const MATCH_HEADER_CONTENT_TYPE: u64 = 11;
pub const MATCH_HEADER_CONNECTION_CLOSE: u64 = 12;
pub const MATCH_HEADER_IF_NONE_MATCH: u64 = 13;
pub const MATCH_HEADER_IF_MODIFIED_SINCE: u64 = 14;
pub const MATCH_HEADER_ACCEPT_ENCODING: u64 = 15;
pub const MATCH_HEADER_EXPECT: u64 = 16;

pub const MATCH_GET: u64 = 1_001;
pub const MATCH_POST: u64 = 1_002;
pub const MATCH_DELETE: u64 = 1_003;
pub const MATCH_HEAD: u64 = 1_004;
pub const MATCH_PUT: u64 = 1_005;
pub const MATCH_OPTIONS: u64 = 1_006;
pub const MATCH_CONNECT: u64 = 1_007;
pub const MATCH_PATCH: u64 = 1_008;
pub const MATCH_TRACE: u64 = 1_009;

#[cfg(unix)]
pub type Handle = RawFd;
#[cfg(windows)]
pub type Handle = u64;

warn!();

#[derive(Debug, Clone, PartialEq)]
pub enum ListenerType {
	Tls,
	Plain,
}

#[derive(Debug, Clone)]
pub struct ConnectionInfo {
	pub last_data: u128,
	pub connection: u128,
	pub conn_data: Option<ConnectionData>,
	pub proxy_info: Option<ProxyInfo>,
	pub api_context: Option<ApiContext>,
	pub health_check_info: Option<(ProxyEntry, SocketAddr)>,
	pub websocket_uri: Option<Vec<u8>>,
	pub is_websocket: bool,
	pub is_admin: bool,
}

impl ConnectionInfo {
	pub fn new(conn_data: ConnectionData) -> Self {
		let now = SystemTime::now()
			.duration_since(UNIX_EPOCH)
			.unwrap()
			.as_micros();
		Self {
			connection: now,
			last_data: now,
			conn_data: Some(conn_data),
			proxy_info: None,
			api_context: None,
			health_check_info: None,
			is_websocket: false,
			websocket_uri: None,
			is_admin: false,
		}
	}

	pub fn new_empty() -> Self {
		let now = SystemTime::now()
			.duration_since(UNIX_EPOCH)
			.unwrap()
			.as_micros();
		Self {
			connection: now,
			last_data: now,
			conn_data: None,
			proxy_info: None,
			api_context: None,
			health_check_info: None,
			is_websocket: false,
			websocket_uri: None,
			is_admin: false,
		}
	}

	pub fn set(
		&mut self,
		last_data: u128,
		connection: u128,
		conn_data: ConnectionData,
		proxy_info: Option<ProxyInfo>,
		api_context: Option<ApiContext>,
		health_check_info: Option<(ProxyEntry, SocketAddr)>,
		is_websocket: bool,
	) {
		self.last_data = last_data;
		self.connection = connection;
		self.conn_data = Some(conn_data);
		self.proxy_info = proxy_info;
		self.api_context = api_context;
		self.health_check_info = health_check_info;
		self.is_websocket = is_websocket;
	}
}

#[derive(Debug)]
pub struct ProxyInfo {
	pub handle: Handle,
	pub proxy_conn: ConnectionData,
	pub response_conn_data: Option<ConnectionData>,
	pub buffer: Vec<u8>,
	pub sock_addr: SocketAddr,
	pub proxy_entry: ProxyEntry,
	pub request_start_time: u128,
}

impl std::hash::Hash for ProxyInfo {
	fn hash<H: Hasher>(&self, state: &mut H) {
		self.handle.hash(state);
		self.buffer.hash(state);
		self.sock_addr.hash(state);
	}
}

impl PartialEq for ProxyInfo {
	fn eq(&self, other: &ProxyInfo) -> bool {
		self.handle == other.handle
			&& self.sock_addr == other.sock_addr
			&& self.proxy_entry == other.proxy_entry
	}
}

impl Eq for ProxyInfo {}

impl Clone for ProxyInfo {
	fn clone(&self) -> Self {
		Self {
			handle: self.handle.clone(),
			response_conn_data: self.response_conn_data.clone(),
			buffer: self.buffer.clone(),
			sock_addr: self.sock_addr.clone(),
			proxy_conn: self.proxy_conn.clone(),
			proxy_entry: self.proxy_entry.clone(),
			request_start_time: self.request_start_time,
		}
	}
}

#[derive(Debug)]
pub struct ProxyState {
	pub cur_connections: usize,
	pub healthy_sockets: Vec<SocketAddr>,
	pub last_health_check: u128,
	pub last_healthy_reply: HashMap<SocketAddr, u128>,
	pub last_lat_micros: HashMap<SocketAddr, (usize, Vec<u128>, usize)>,
}

impl ProxyState {
	pub fn new(proxy_entry: ProxyEntry) -> Result<Self, Error> {
		let mut last_healthy_reply = HashMap::new();
		let mut healthy_sockets = vec![];
		let mut last_lat_micros = HashMap::new();
		let mut index = 0;
		for upstream in proxy_entry.get_upstream() {
			last_healthy_reply.insert(upstream.sock_addr.clone(), 0);
			for _ in 0..upstream.weight {
				healthy_sockets.push(upstream.sock_addr.clone());
			}
			let mut last_lat = vec![];
			last_lat.resize(proxy_entry.last_lat_count, 0u128);
			last_lat_micros.insert(upstream.sock_addr.clone(), (0, last_lat, index));
			index += 1;
		}

		Ok(Self {
			cur_connections: 0,
			healthy_sockets,
			last_health_check: 0,
			last_healthy_reply,
			last_lat_micros,
		})
	}
}

#[derive(Debug)]
pub struct StatQueues {
	pub log_items: StaticQueue<LogItem>,
	pub log_events: Vec<LogEvent>,
}

impl StatQueues {
	fn new(capacity: usize, threads: usize) -> Self {
		Self {
			log_items: StaticQueue::new(capacity),
			// 1 per thread + buffer
			log_events: Vec::with_capacity(threads + 100),
		}
	}
}

#[derive(Clone, Debug, Default)]
pub struct LogEvent {
	pub dropped_count: u64,
	pub read_timeout_count: u64,
	pub connect_timeout_count: u64,
	pub connect_count: u64,
	pub disconnect_count: u64,
	pub dropped_lat_sum: u64,
	pub user_matches: Vec<(u64, u64)>,
}

#[derive(Clone, Debug)]
pub struct StatHandler {
	pub queue: Arc<RwLock<StatQueues>>,
	pub http_stats: HttpStats,
}

impl StatHandler {
	pub fn new(
		capacity: usize,
		threads: usize,
		debug_log_queue: bool,
		request_log_config: LogConfig,
		debug_show_stats: bool,
		stats_frequency: u64,
		data: HttpData,
	) -> Result<Self, Error> {
		Ok(Self {
			queue: Arc::new(RwLock::new(StatQueues::new(capacity, threads))),
			http_stats: HttpStats::new(
				HttpStatsConfig {
					debug_log_queue,
					debug_show_stats,
					request_log_config,
					stats_frequency,
				},
				data,
			)?,
		})
	}
}

pub struct ThreadPoolContext {
	pub in_buf: Vec<u8>,
}

impl ThreadPoolContext {
	pub fn new() -> Self {
		let in_buf = vec![];
		Self { in_buf }
	}
}

pub struct RuleUpdate {
	pub version: u64,
	pub rules: Option<Vec<FunctionalRule>>,
}

pub struct ThreadContext {
	pub cache_hits: StaticHash<(), ()>,
	pub key_buf: Vec<u8>,
	pub value_buf: Vec<u8>,
	pub instant: Instant,
	pub mime_map: HashMap<Vec<u8>, Vec<u8>>,
	pub async_connections: Arc<RwLock<StaticHash<(), ()>>>,
	pub active_connection_index_map: StaticHash<(), ()>,
	pub active_connections: StepAllocator,
	pub idle_proxy_connections: HashMap<ProxyEntry, HashMap<SocketAddr, HashSet<ProxyInfo>>>,
	pub proxy_state: HashMap<ProxyEntry, ProxyState>,
	pub webroot: Vec<u8>,
	pub temp_dir: String,
	pub sha1: Sha1,
	pub stat_handler: StatHandler,
	pub dropped_log_items: u64,
	pub connects: u64,
	pub disconnects: u64,
	pub connect_timeouts: u64,
	pub read_timeouts: u64,
	pub dropped_lat_sum: u64,
	pub log_queue: StaticQueue<LogItem>,
	pub thread_pool_context: Arc<RwLock<ThreadPoolContext>>,
	pub matcher: MultiMatch,
	pub rules: Vec<FunctionalRule>,
	pub rule_update: Arc<RwLock<RuleUpdate>>,
	pub rule_version: u64,
	pub match_ids: Vec<u64>,
	pub id_match_count: usize,
	pub user_defined_matches: StaticHash<(), ()>,
	pub match_accumulator: StaticHash<(), ()>,
}

impl ThreadContext {
	pub fn new(
		config: &HttpConfig,
		stat_handler: &StatHandler,
		admin: &HttpAdmin,
		rule_update: &Arc<RwLock<RuleUpdate>>,
	) -> Result<Self, Error> {
		let user_defined_matches: StaticHash<(), ()>;
		user_defined_matches = StaticHash::new(StaticHashConfig {
			max_entries: config.max_matches * 2,
			key_len: 8,
			entry_len: 0,
			max_load_factor: 0.95,
			..Default::default()
		})?;

		let match_accumulator: StaticHash<(), ()>;
		match_accumulator = StaticHash::new(StaticHashConfig {
			max_entries: config.max_matches * 2,
			key_len: 8,
			entry_len: 8,
			max_load_factor: 0.95,
			..Default::default()
		})?;

		let id_match_count = 0;
		let mut match_ids = vec![];
		match_ids.resize(config.max_matches, 0);

		let cache_hits_conf = StaticHashConfig {
			key_len: 32,
			entry_len: 16,
			max_entries: config.max_bring_to_front,
			max_load_factor: 1.0,
			..Default::default()
		};
		let mut key_buf = vec![];
		let mut value_buf = vec![];
		key_buf.resize(config.max_header_name_len, 0u8);
		value_buf.resize(config.max_header_value_len, 0u8);

		let mut proxy_state = HashMap::new();
		let mut idle_proxy_connections = HashMap::new();
		for (_k, v) in &config.proxy_config.mappings {
			proxy_state.insert(v.clone(), ProxyState::new(v.clone())?);
			idle_proxy_connections.insert(v.clone(), HashMap::new());
		}
		for (_k, v) in &config.proxy_config.extensions {
			proxy_state.insert(v.clone(), ProxyState::new(v.clone())?);
			idle_proxy_connections.insert(v.clone(), HashMap::new());
		}

		let webroot = std::str::from_utf8(&config.webroot)?.to_string();
		let home_dir = match dirs::home_dir() {
			Some(p) => p,
			None => PathBuf::new(),
		}
		.as_path()
		.display()
		.to_string();

		let webroot = webroot.replace("~", &home_dir);
		let webroot = path_clean(&webroot).as_bytes().to_vec();

		let temp_dir = config.temp_dir.replace("~", &home_dir);

		let async_connections = Arc::new(RwLock::new(StaticHash::new(StaticHashConfig {
			key_len: SIZEOF_U128,
			entry_len: LOG_ITEM_SIZE,
			max_entries: config.max_async_connections,
			max_load_factor: 1.0,
			iterator: false,
			..Default::default()
		})?));

		let mut active_connections = StepAllocator::new(StepAllocatorConfig { step_size: 100 });

		let active_connection_index_map = StaticHash::new(StaticHashConfig {
			key_len: SIZEOF_U128,
			entry_len: SIZEOF_USIZE,
			max_entries: config.max_active_connections,
			max_load_factor: 1.0,
			iterator: true,
			..Default::default()
		})?;

		// preallocate a single step here
		active_connections.step(&ConnectionInfo::new_empty());

		let log_queue = StaticQueue::new(config.thread_log_queue_size);
		let thread_pool_context = Arc::new(RwLock::new(ThreadPoolContext::new()));

		let rules = admin.get_active_rules()?;

		let matcher = Self::build_matcher(
			config.max_matches,
			config.max_header_size,
			config.dictionary_capacity,
			config.max_header_size,
			rules.clone(),
		)?;

		let rule_update = rule_update.clone();

		Ok(Self {
			cache_hits: StaticHash::new(cache_hits_conf)?,
			key_buf,
			value_buf,
			instant: Instant::now(),
			mime_map: HashMap::new(),
			async_connections,
			active_connections,
			active_connection_index_map,
			idle_proxy_connections,
			proxy_state,
			webroot,
			temp_dir,
			sha1: Sha1::new(),
			log_queue,
			stat_handler: stat_handler.clone(),
			dropped_log_items: 0,
			connects: 0,
			disconnects: 0,
			connect_timeouts: 0,
			read_timeouts: 0,
			dropped_lat_sum: 0,
			thread_pool_context,
			matcher,
			rules,
			rule_update,
			rule_version: 0,
			user_defined_matches,
			id_match_count,
			match_ids,
			match_accumulator,
		})
	}

	pub fn build_matcher(
		max_matches: usize,
		max_header_size: usize,
		dictionary_capacity: usize,
		max_wildcard: usize,
		active_rules: Vec<FunctionalRule>,
	) -> Result<MultiMatch, Error> {
		let mut dictionary = Dictionary::new(dictionary_capacity, false, max_wildcard);
		dictionary.add(
			Pattern {
				regex: "\r\n\r\n".to_string(),
				id: MATCH_TERMINATE_HEADERS,
				multi_line: true,
			},
			true,
		)?;
		dictionary.add(
			Pattern {
				regex: "\r\n.*: ".to_string(),
				id: MATCH_HEADER_NAME,
				multi_line: true,
			},
			false,
		)?;
		dictionary.add(
			Pattern {
				regex: "\r\nREFERER: ".to_string(),
				id: MATCH_HEADER_REFERER,
				multi_line: true,
			},
			false,
		)?;
		dictionary.add(
			Pattern {
				regex: "\r\nCONTENT-LENGTH: ".to_string(),
				id: MATCH_HEADER_CONTENT_LENGTH,
				multi_line: true,
			},
			false,
		)?;

		dictionary.add(
			Pattern {
				regex: "\r\nHOST: ".to_string(),
				id: MATCH_HEADER_HOST,
				multi_line: true,
			},
			false,
		)?;

		dictionary.add(
			Pattern {
				regex: "\r\nCOOKIE: ".to_string(),
				id: MATCH_HEADER_COOKIE,
				multi_line: true,
			},
			false,
		)?;

		dictionary.add(
			Pattern {
				regex: "\r\nUPGRADE: WEBSOCKET".to_string(),
				id: MATCH_HEADER_UPGRADE_WEBSOCKET,
				multi_line: true,
			},
			false,
		)?;

		dictionary.add(
			Pattern {
				regex: "\r\nSEC-WEBSOCKET-KEY: ".to_string(),
				id: MATCH_HEADER_SEC_WEBSOCKET_KEY,
				multi_line: true,
			},
			false,
		)?;
		dictionary.add(
			Pattern {
				regex: "\r\nRange: ".to_string(),
				id: MATCH_HEADER_RANGE,
				multi_line: true,
			},
			false,
		)?;
		dictionary.add(
			Pattern {
				regex: "\r\nUSER-AGENT: ".to_string(),
				id: MATCH_HEADER_USER_AGENT,
				multi_line: true,
			},
			false,
		)?;
		dictionary.add(
			Pattern {
				regex: "\r\nCONTENT-TYPE: ".to_string(),
				id: MATCH_HEADER_CONTENT_TYPE,
				multi_line: true,
			},
			false,
		)?;
		dictionary.add(
			Pattern {
				regex: "\r\nCONNECTION: CLOSE\r\n".to_string(),
				id: MATCH_HEADER_CONNECTION_CLOSE,
				multi_line: true,
			},
			false,
		)?;
		dictionary.add(
			Pattern {
				regex: "\r\nIF-NONE-MATCH: ".to_string(),
				id: MATCH_HEADER_IF_NONE_MATCH,
				multi_line: true,
			},
			false,
		)?;
		dictionary.add(
			Pattern {
				regex: "\r\nIF-MODIFIED-SINCE: ".to_string(),
				id: MATCH_HEADER_IF_MODIFIED_SINCE,
				multi_line: true,
			},
			false,
		)?;
		dictionary.add(
			Pattern {
				regex: "\r\nACCEPT-ENCODING: ".to_string(),
				id: MATCH_HEADER_ACCEPT_ENCODING,
				multi_line: true,
			},
			false,
		)?;
		dictionary.add(
			Pattern {
				regex: "\r\nEXPECT: 100-continue".to_string(),
				id: MATCH_HEADER_EXPECT,
				multi_line: true,
			},
			false,
		)?;
		dictionary.add(
			Pattern {
				regex: "^GET ".to_string(),
				id: MATCH_GET,
				multi_line: false,
			},
			false,
		)?;
		dictionary.add(
			Pattern {
				regex: "^POST ".to_string(),
				id: MATCH_POST,
				multi_line: false,
			},
			false,
		)?;
		dictionary.add(
			Pattern {
				regex: "^DELETE ".to_string(),
				id: MATCH_DELETE,
				multi_line: false,
			},
			false,
		)?;
		dictionary.add(
			Pattern {
				regex: "^HEAD ".to_string(),
				id: MATCH_HEAD,
				multi_line: false,
			},
			false,
		)?;
		dictionary.add(
			Pattern {
				regex: "^PUT ".to_string(),
				id: MATCH_PUT,
				multi_line: false,
			},
			false,
		)?;
		dictionary.add(
			Pattern {
				regex: "^OPTIONS ".to_string(),
				id: MATCH_OPTIONS,
				multi_line: false,
			},
			false,
		)?;
		dictionary.add(
			Pattern {
				regex: "^CONNECT ".to_string(),
				id: MATCH_CONNECT,
				multi_line: false,
			},
			false,
		)?;
		dictionary.add(
			Pattern {
				regex: "^PATCH ".to_string(),
				id: MATCH_PATCH,
				multi_line: false,
			},
			false,
		)?;
		dictionary.add(
			Pattern {
				regex: "^TRACE ".to_string(),
				id: MATCH_TRACE,
				multi_line: false,
			},
			false,
		)?;

		let mut id_set = HashMap::new();
		for i in 0..active_rules.len() {
			let patterns = active_rules[i].get_all_patterns()?;
			for pattern in patterns.clone() {
				let id = pattern.id;
				let pattern_cur = id_set.get(&id);
				if pattern_cur.is_none() {
					dictionary.add(pattern.clone(), false)?;
					id_set.insert(id, pattern);
				} else {
					let pattern_cur = pattern_cur.unwrap();
					if &pattern != pattern_cur {
						debug!(
							"Duplicate pattern id detected for pattern = {:?} \
which was not equal to previous pattern with the same id = {:?}",
							pattern, pattern_cur
						)?;
					}
				}
			}
		}

		let matcher = MultiMatch::new(max_matches, dictionary, Some(max_header_size));
		Ok(matcher)
	}
}

#[derive(Clone, Debug, PartialEq, Copy)]
pub enum HttpMethod {
	Get,
	Post,
	Delete,
	Head,
	Put,
	Options,
	Connect,
	Patch,
	Trace,
}

impl Display for HttpMethod {
	fn fmt(&self, f: &mut Formatter) -> std::fmt::Result {
		match self {
			HttpMethod::Get => write!(f, "GET")?,
			HttpMethod::Post => write!(f, "POST")?,
			HttpMethod::Delete => write!(f, "DELETE")?,
			HttpMethod::Head => write!(f, "HEAD")?,
			HttpMethod::Put => write!(f, "PUT")?,
			HttpMethod::Options => write!(f, "OPTIONS")?,
			HttpMethod::Connect => write!(f, "CONNECT")?,
			HttpMethod::Patch => write!(f, "PATCH")?,
			HttpMethod::Trace => write!(f, "TRACE")?,
		}
		Ok(())
	}
}

#[derive(PartialEq, Debug, Clone, Copy)]
pub enum HttpVersion {
	V10,
	V11,
	V20,
	Unknown,
}

#[derive(Debug, Clone)]
pub struct HttpHeaders<'a> {
	method: HttpMethod,
	version: HttpVersion,
	uri: &'a [u8],
	query: &'a [u8],
	user_agent: &'a [u8],
	host: &'a [u8],
	referer: &'a [u8],
	extension: &'a [u8],
	range: &'a [u8],
	cookies: Vec<&'a [u8]>,
	header_map: Option<HashMap<String, Vec<String>>>,
	len: usize,
	expect: bool,
	if_modified_since: &'a [u8],
	if_none_match: &'a [u8],
	websocket_upgrade: bool,
	websocket_sec_key: &'a [u8],
	connection_close: bool,
	content_length: usize,
	accept_gzip_encoding: bool,
	matcher: &'a MultiMatch,
	buffer: &'a [u8],
	match_ids: &'a [u64],
	id_match_count: usize,
}

impl<'a> Display for HttpHeaders<'a> {
	fn fmt(&self, f: &mut Formatter) -> std::fmt::Result {
		let mut header_clone = self.clone();
		write!(f, "method:  '{:?}'\n", header_clone.get_method())?;
		write!(f, "version: '{:?}'\n", header_clone.get_version())?;
		write!(
			f,
			"uri:     '{}'\n",
			std::str::from_utf8(header_clone.get_uri()).unwrap_or("[non-utf8-string]")
		)?;
		write!(
			f,
			"query:   '{}'\n",
			std::str::from_utf8(header_clone.get_query()).unwrap_or("[non-utf8-string]")
		)?;
		write!(f, "\nHTTP Headers:")?;
		let mut names = vec![];
		for name in header_clone
			.get_header_names()
			.map_err(|_e| std::fmt::Error)?
		{
			names.push(name.clone());
		}
		for name in names {
			let values = header_clone
				.get_header_value(&name)
				.map_err(|_e| std::fmt::Error)?;
			for value in values {
				let mut spacing = "".to_string();
				for _ in name.len()..20 {
					spacing = format!("{} ", spacing);
				}
				write!(f, "\n{}:{} '{}'", name, spacing, value,)?;
			}
		}
		write!(f, "\n\nPattern Matches:")?;
		let id_match_count = header_clone.get_id_match_count();
		let id_matches = header_clone.get_match_ids();
		for i in 0..id_match_count {
			let id = id_matches[i];
			write!(f, "\n{}", id)?;
		}
		Ok(())
	}
}

impl<'a> HttpHeaders<'a> {
	pub fn new(
		buffer: &'a [u8],
		config: &HttpConfig,
		matcher: &'a mut MultiMatch,
		rules: &Vec<FunctionalRule>,
		id_match_count: &mut usize,
		match_ids: &'a mut Vec<u64>,
		user_defined_matches: &mut StaticHash<(), ()>,
	) -> Result<Option<Self>, Error> {
		user_defined_matches.clear()?;

		matcher.runmatch(buffer)?;

		let match_count = matcher.match_count();
		let matches = matcher.matches();

		// check if we didn't terminate
		if match_count <= 0 || matches[match_count - 1].id != MATCH_TERMINATE_HEADERS {
			if buffer.len() > config.max_header_size {
				return Err(
					ErrorKind::HttpError431("Request Header Fields Too Large".into()).into(),
				);
			}
			return Ok(None);
		}

		let len = matches[match_count - 1].end;
		let mut start_headers = matches[match_count - 1].start;

		if len > config.max_header_size {
			return Err(ErrorKind::HttpError431("Request Header Fields Too Large".into()).into());
		}

		let mut method = HttpMethod::Get;
		let mut found_method = false;
		let mut host = EMPTY;
		let mut range = EMPTY;
		let mut cookies = vec![];
		let mut expect = false;
		let mut if_modified_since = EMPTY;
		let mut if_none_match = EMPTY;
		let mut websocket_upgrade = false;
		let mut websocket_sec_key = EMPTY;
		let mut connection_close = false;
		let mut content_length = 0;
		let mut accept_gzip_encoding = false;
		let mut referer = EMPTY;
		let mut user_agent = EMPTY;

		for i in 0..match_count {
			match matches[i].id {
				MATCH_HEADER_REFERER => {
					referer = Self::find_header(&matches[i], buffer);
				}
				MATCH_HEADER_USER_AGENT => {
					user_agent = Self::find_header(&matches[i], buffer);
				}
				MATCH_GET => {
					found_method = true;
					method = HttpMethod::Get;
				}
				MATCH_POST => {
					found_method = true;
					method = HttpMethod::Post;
				}
				MATCH_DELETE => {
					found_method = true;
					method = HttpMethod::Delete;
				}
				MATCH_HEAD => {
					found_method = true;
					method = HttpMethod::Head;
				}
				MATCH_PUT => {
					found_method = true;
					method = HttpMethod::Put;
				}
				MATCH_OPTIONS => {
					found_method = true;
					method = HttpMethod::Options;
				}
				MATCH_CONNECT => {
					found_method = true;
					method = HttpMethod::Connect;
				}
				MATCH_PATCH => {
					found_method = true;
					method = HttpMethod::Patch;
				}
				MATCH_TRACE => {
					found_method = true;
					method = HttpMethod::Trace;
				}
				MATCH_HEADER_RANGE => {
					range = Self::find_header(&matches[i], buffer);
				}
				MATCH_HEADER_EXPECT => {
					expect = true;
				}
				MATCH_HEADER_IF_MODIFIED_SINCE => {
					if_modified_since = Self::find_header(&matches[i], buffer);
				}
				MATCH_HEADER_IF_NONE_MATCH => {
					if_none_match = Self::find_header(&matches[i], buffer);
				}
				MATCH_HEADER_ACCEPT_ENCODING => {
					let header = Self::find_header(&matches[i], buffer);
					accept_gzip_encoding = bytes_find(&header, b"gzip").is_some();
				}
				MATCH_HEADER_CONNECTION_CLOSE => {
					connection_close = true;
				}
				MATCH_HEADER_UPGRADE_WEBSOCKET => {
					websocket_upgrade = true;
				}
				MATCH_HEADER_SEC_WEBSOCKET_KEY => {
					websocket_sec_key = Self::find_header(&matches[i], buffer);
				}
				MATCH_HEADER_COOKIE => {
					let cookie = Self::find_header(&matches[i], buffer);
					cookies.push(cookie);
				}
				MATCH_HEADER_HOST => {
					host = Self::find_header(&matches[i], buffer);
				}
				MATCH_HEADER_CONTENT_LENGTH => {
					let mut itt = matches[i].end;

					// we know there is a newline because
					// MATCH_TERMINATE_HEADERS was found
					loop {
						if buffer[itt] == '\r' as u8 || buffer[itt] == '\n' as u8 {
							break;
						}
						itt += 1;
					}
					content_length = bytes_to_usize(&buffer[matches[i].end..itt])?;
				}
				MATCH_HEADER_NAME => {
					if matches[i].end.saturating_sub(matches[i].start)
						> config.max_header_name_len + 4
					{
						return Err(ErrorKind::HttpError431(
							"Request Header Field Name Too Large".into(),
						)
						.into());
					}

					if Self::find_header(&matches[i], buffer).len() > config.max_header_value_len {
						return Err(ErrorKind::HttpError431(
							"Request Header Field Value Too Large".into(),
						)
						.into());
					}
					if matches[i].start < start_headers {
						start_headers = matches[i].start;
					}
				}
				_ => {
					// these must be user defined patterns
					user_defined_matches.insert_raw(&matches[i].id.to_be_bytes(), &[])?;
				}
			}
		}

		*id_match_count = 0;
		for rule in rules {
			if rule.evaluate(&user_defined_matches)? == true {
				match_ids[*id_match_count] = rule.id();
				*id_match_count += 1;
			}
		}

		let (uri, query, extension, version) = Self::parse_uri_parts(start_headers, buffer)?;

		if !found_method {
			return Err(ErrorKind::HttpError405("Method not supported".into()).into());
		}

		Ok(Some(Self {
			method,
			version,
			uri,
			query,
			host,
			user_agent,
			referer,
			extension,
			header_map: None,
			len,
			range,
			expect,
			connection_close,
			websocket_upgrade,
			websocket_sec_key,
			if_modified_since,
			if_none_match,
			content_length,
			accept_gzip_encoding,
			cookies,
			matcher,
			buffer,
			match_ids,
			id_match_count: *id_match_count,
		}))
	}

	pub fn get_match_ids(&self) -> &'a [u64] {
		&self.match_ids
	}

	pub fn get_id_match_count(&self) -> usize {
		self.id_match_count
	}

	pub fn get_cookies(&self) -> &Vec<&[u8]> {
		&self.cookies
	}

	pub fn websocket_sec_key(&self) -> &[u8] {
		&self.websocket_sec_key
	}

	pub fn content_len(&self) -> Result<usize, Error> {
		Ok(self.content_length)
	}

	pub fn extension(&self) -> &[u8] {
		match self.extension == SLASH {
			true => HTML_EXTENSION,
			false => self.extension,
		}
	}

	pub fn has_websocket_upgrade(&self) -> bool {
		self.websocket_upgrade
	}

	pub fn has_expect(&self) -> bool {
		self.expect
	}

	pub fn accept_gzip(&self) -> bool {
		self.accept_gzip_encoding
	}

	pub fn range(&self) -> &[u8] {
		&self.range
	}

	pub fn if_modified_since(&self) -> &[u8] {
		&self.if_modified_since
	}

	pub fn if_none_match(&self) -> &[u8] {
		&self.if_none_match
	}

	pub fn is_close(&self) -> bool {
		self.connection_close
	}

	pub fn len(&self) -> usize {
		self.len
	}

	pub fn get_method(&self) -> &HttpMethod {
		&self.method
	}

	pub fn get_version(&self) -> &HttpVersion {
		&self.version
	}

	pub fn get_query(&self) -> &[u8] {
		&self.query
	}

	pub fn get_uri(&self) -> &[u8] {
		&self.uri
	}

	pub fn get_user_agent(&self) -> &[u8] {
		&self.user_agent
	}

	pub fn get_referer(&self) -> &[u8] {
		&self.referer
	}

	pub fn get_host(&self) -> &[u8] {
		&self.host
	}

	pub fn get_header_value(&mut self, name: &String) -> Result<Vec<String>, Error> {
		if !self.header_map.is_some() {
			self.build_header_map()?;
		}
		let header_map = self.header_map.as_ref().unwrap();
		match header_map.get(&name.to_lowercase()) {
			Some(value) => Ok(value.to_vec()),
			None => Ok(vec![]),
		}
	}

	pub fn get_header_names(&mut self) -> Result<Vec<&String>, Error> {
		if !self.header_map.is_some() {
			self.build_header_map()?;
		}
		let header_map = self.header_map.as_ref().unwrap();
		let mut ret = vec![];
		for (name, _) in header_map {
			ret.push(name);
		}
		Ok(ret)
	}

	pub fn build_header_map(&mut self) -> Result<(), Error> {
		let mut header_map = HashMap::new();
		let match_count = self.matcher.match_count();
		let matches = self.matcher.matches();
		for i in 0..match_count {
			let next = &matches[i];
			if next.id == MATCH_HEADER_NAME {
				let name =
					std::str::from_utf8(&self.buffer[next.start + 2..next.end - 2])?.to_lowercase();
				let value = std::str::from_utf8(Self::find_header(&next, self.buffer))?;
				self.insert_value(&mut header_map, name.to_string(), value.to_string())?;
			}
		}
		self.header_map = Some(header_map);

		Ok(())
	}

	fn insert_value(
		&self,
		header_map: &mut HashMap<String, Vec<String>>,
		name: String,
		value: String,
	) -> Result<(), Error> {
		let inserted = match header_map.get_mut(&name) {
			Some(value_vec) => {
				value_vec.push(value.clone());
				true
			}
			None => false,
		};

		if !inserted {
			header_map.insert(name, vec![value]);
		}

		Ok(())
	}

	fn find_header(m: &Match, buffer: &'a [u8]) -> &'a [u8] {
		let mut back_r = m.end;
		let buffer_len = buffer.len();
		loop {
			if back_r >= buffer_len || buffer[back_r] == '\r' as u8 || buffer[back_r] == '\n' as u8
			{
				break;
			}
			back_r += 1;
		}
		&buffer[m.end..back_r]
	}

	fn parse_uri_parts(
		end: usize,
		buffer: &'a [u8],
	) -> Result<(&'a [u8], &'a [u8], &'a [u8], HttpVersion), Error> {
		let start_uri = match bytes_find(buffer, SPACE) {
			Some(index) => index + 1,
			None => {
				return Err(ErrorKind::HttpError400("Bad request: no space in URI".into()).into())
			}
		};
		let uri = &buffer[start_uri..end];
		let mut space_count = 0;
		for i in start_uri..end {
			if buffer[i] == ' ' as u8 {
				space_count += 1;
			}
		}

		if space_count != 1 {
			return Err(ErrorKind::HttpError400("Bad request: invalid format".into()).into());
		}

		let version = match bytes_find(uri, b" HTTP/1.1") {
			Some(_) => HttpVersion::V11,
			None => match bytes_find(uri, b" HTTP/2.0") {
				Some(_) => HttpVersion::V20,
				None => match bytes_find(uri, b" HTTP/1.0") {
					Some(_) => HttpVersion::V10,
					None => match bytes_find(uri, b" HTTP/") {
						Some(_) => HttpVersion::Unknown,
						None => {
							return Err(ErrorKind::HttpError400(
								"Bad request: version not found".into(),
							)
							.into());
						}
					},
				},
			},
		};

		let end = bytes_find(uri, SPACE).unwrap_or(0);
		let (uri, query) = if end == 0 {
			return Err(ErrorKind::HttpError400("Bad request: version not found".into()).into());
		} else {
			match bytes_find(uri, QUESTION_MARK) {
				Some(index) => (&uri[0..index], &uri[(index + 1)..end]),
				None => (&uri[0..end], EMPTY),
			}
		};
		let extension = match bytes_find(uri, DOT) {
			Some(_) => {
				let mut i = uri.len().saturating_sub(1);
				loop {
					if i == 0 || uri[i] == '.' as u8 {
						break;
					}
					i = i.saturating_sub(1);
				}
				&uri[(i + 1)..]
			}
			None => b"html",
		};
		Ok((uri, query, extension, version))
	}
}

#[derive(Debug, Clone, PartialEq, Hash, Eq)]
pub struct Upstream {
	pub sock_addr: SocketAddr,
	pub weight: usize,
}

impl Upstream {
	pub fn new(sock_addr: SocketAddr, weight: usize) -> Self {
		Self { sock_addr, weight }
	}
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ProxyRotation {
	Random,
	StickyIp,
	StickyCookie(String),
	LeastLatency,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProxyEntry {
	pub upstream: Vec<Upstream>,
	pub max_connections_per_thread: usize,
	pub health_check: Option<HealthCheck>,
	pub nonce: u128,
	pub proxy_rotation: ProxyRotation,
	pub control_percent: usize,
	pub last_lat_count: usize,
}

impl std::hash::Hash for ProxyEntry {
	fn hash<H: Hasher>(&self, state: &mut H) {
		self.nonce.hash(state);
	}
}

impl ProxyEntry {
	pub fn from_socket_addr(sock_addr: SocketAddr, health_check: Option<HealthCheck>) -> Self {
		let proxy_rotation = ProxyRotation::Random;
		Self {
			upstream: vec![Upstream::new(sock_addr, 1)],
			max_connections_per_thread: usize::MAX,
			health_check,
			nonce: rand::random(),
			proxy_rotation,
			control_percent: 0,
			last_lat_count: 0,
		}
	}

	pub fn from_socket_addr_with_limit(
		sock_addr: SocketAddr,
		max_connections_per_thread: usize,
		health_check: Option<HealthCheck>,
	) -> Self {
		let proxy_rotation = ProxyRotation::Random;
		Self {
			upstream: vec![Upstream::new(sock_addr, 1)],
			max_connections_per_thread,
			health_check,
			nonce: rand::random(),
			proxy_rotation,
			control_percent: 0,
			last_lat_count: 0,
		}
	}

	pub fn multi_socket_addr(
		upstream: Vec<Upstream>,
		max_connections_per_thread: usize,
		health_check: Option<HealthCheck>,
		proxy_rotation: ProxyRotation,
		last_lat_count: usize,
		control_percent: usize,
	) -> Self {
		Self {
			upstream,
			max_connections_per_thread,
			health_check,
			nonce: rand::random(),
			proxy_rotation,
			control_percent,
			last_lat_count,
		}
	}

	fn get_upstream(&self) -> &Vec<Upstream> {
		&self.upstream
	}
}

#[derive(Hash, PartialEq, Eq, Debug, Clone)]
pub struct HealthCheck {
	pub path: String,
	pub check_secs: u128,
	pub expect_text: String,
}

#[derive(Clone)]
pub struct ProxyConfig {
	pub mappings: HashMap<Vec<u8>, ProxyEntry>,
	pub extensions: HashMap<Vec<u8>, ProxyEntry>,
}

impl Default for ProxyConfig {
	fn default() -> Self {
		let mappings = HashMap::new();
		let extensions = HashMap::new();

		Self {
			mappings,
			extensions,
		}
	}
}

#[derive(Clone)]
pub struct HttpConfig {
	pub start: Instant,
	pub listeners: Vec<(ListenerType, SocketAddr, Option<TLSServerConfig>)>,
	pub listen_queue_size: usize,
	pub max_content_len: usize,
	pub max_header_size: usize,
	pub max_header_entries: usize,
	pub max_header_name_len: usize,
	pub max_header_value_len: usize,
	pub max_matches: usize,
	pub dictionary_capacity: usize,
	pub webroot: Vec<u8>,
	pub max_cache_files: usize,
	pub max_cache_chunks: u64,
	pub cache_chunk_size: u64,
	pub max_load_factor: f64,
	pub server_name: Vec<u8>,
	pub max_bring_to_front: usize,
	pub process_cache_update: u128,
	pub cache_recheck_fs_millis: u128,
	pub connect_timeout: u128,
	pub idle_timeout: u128,
	pub async_timeout: u128,
	pub mime_map: Vec<(String, String)>,
	pub proxy_config: ProxyConfig,
	pub temp_dir: String,
	pub show_request_headers: bool,
	pub show_response_headers: bool,
	pub debug: bool,
	pub debug_api: bool,
	pub debug_websocket: bool,
	pub debug_proxy: bool,
	pub debug_log_queue: bool,
	pub mainlog: String,
	pub mainlog_max_age: u128,
	pub mainlog_max_size: u64,
	pub content_upload_slab_count: u64,
	pub content_upload_slab_size: u64,
	pub virtual_hosts: HashMap<Vec<u8>, Vec<u8>>,
	pub virtual_ips: HashMap<SocketAddr, Vec<u8>>,
	pub error_page: Vec<u8>,
	pub max_async_connections: usize,
	pub max_active_connections: usize,
	pub gzip_compression_level: u32,
	pub gzip_extensions: HashSet<Vec<u8>>,
	pub evh_config: EventHandlerConfig,
	pub main_log_queue_size: usize,
	pub thread_log_queue_size: usize,
	pub request_log_config: LogConfig,
	pub lmdb_dir: String,
	pub debug_show_stats: bool,
	pub stats_frequency: u64,
	pub admin_uri: Vec<u8>,
}

impl Default for HttpConfig {
	fn default() -> Self {
		let mut version = format!("[niohttp-{}]", VERSION);
		loop {
			if version.len() >= 21 {
				break;
			}
			version = format!("{} ", version);
		}
		let file_header = format!(
			"{}: method|uri_rendered|uri_requested|query|User-Agent|Referer|ProcTime\n\
------------------------------------------------------------------------------------------",
			version
		);

		Self {
			start: Instant::now(),
			proxy_config: ProxyConfig::default(),
			listeners: vec![(
				ListenerType::Plain,
				SocketAddr::from_str("127.0.0.1:8080").unwrap(),
				None,
			)],
			listen_queue_size: 1000,
			max_header_size: 16 * 1024,
			max_header_name_len: 128,
			max_header_value_len: 1024,
			max_header_entries: 1_000,
			max_matches: 200,
			dictionary_capacity: 500,
			webroot: "~/.niohttpd/www".to_string().as_bytes().to_vec(),
			mainlog: "~/.niohttpd/logs/mainlog.log".to_string(),
			temp_dir: "~/.niohttpd/tmp".to_string(),
			lmdb_dir: "~/.niohttpd/lmdb".to_string(),
			mainlog_max_age: 6 * 60 * 60 * 1000,
			mainlog_max_size: 1024 * 1024 * 1,
			max_cache_files: 1_000,
			max_cache_chunks: 100,
			max_bring_to_front: 1_000,
			cache_chunk_size: 1024 * 1024,
			max_content_len: 1024 * 1024,
			content_upload_slab_count: 1024 * 10,
			content_upload_slab_size: 1024,
			max_load_factor: 0.9,
			max_async_connections: 10 * 1024,
			max_active_connections: 16 * 1024,
			virtual_ips: HashMap::new(),
			virtual_hosts: HashMap::new(),
			server_name: format!("NIORuntime Httpd/{}", VERSION).as_bytes().to_vec(),
			gzip_compression_level: 7,
			gzip_extensions: HashSet::new(),
			process_cache_update: 1_000,    // 1 second
			cache_recheck_fs_millis: 3_000, // 3 seconds
			connect_timeout: 30_000,        // 30 seconds
			idle_timeout: 60_000,           // 1 minute
			async_timeout: 3_600_000,       // 1 hour
			show_request_headers: false,    // debug: show request headers
			show_response_headers: false,   // debug: show response headers
			debug_api: false, // debug: dummy post/get request handler (note: we just display the flag here,
			// /src/main.rs responsible for creating it.
			debug_websocket: false, // debug: dummy websocket handler (note: we just display the flag here,
			// /src/main.rs responsible for creating it.
			debug_proxy: false, // same as above
			debug_log_queue: false,
			debug_show_stats: false,
			debug: false, // general debugging including log to stdout
			error_page: "/error.html".as_bytes().to_vec(),
			main_log_queue_size: 10_000,
			thread_log_queue_size: 2_000,
			stats_frequency: 10_000,
			admin_uri: vec![],
			request_log_config: LogConfig {
				file_path: Some("~/.niohttpd/logs/request.log".to_string()),
				show_log_level: false,
				show_line_num: false,
				show_bt: false,
				colors: false,
				show_stdout: false,
				file_header,
				auto_rotate: false,
				..Default::default()
			},
			evh_config: EventHandlerConfig::default(),
			mime_map: vec![
				("html".to_string(), "text/html".to_string()),
				("htm".to_string(), "text/html".to_string()),
				("shtml".to_string(), "text/html".to_string()),
				("txt".to_string(), "text/plain".to_string()),
				("css".to_string(), "text/css".to_string()),
				("xml".to_string(), "text/xml".to_string()),
				("gif".to_string(), "image/gif".to_string()),
				("jpeg".to_string(), "image/jpeg".to_string()),
				("jpg".to_string(), "image/jpeg".to_string()),
				("js".to_string(), "application/javascript".to_string()),
				("atom".to_string(), "application/atom+xml".to_string()),
				("rss".to_string(), "application/rss+xml".to_string()),
				("mml".to_string(), "text/mathml".to_string()),
				(
					"jad".to_string(),
					"text/vnd.sun.j2me.app-descriptor".to_string(),
				),
				("wml".to_string(), "text/vnd.wap.wml".to_string()),
				("htc".to_string(), "text/x-component".to_string()),
				("avif".to_string(), "image/avif".to_string()),
				("png".to_string(), "image/png".to_string()),
				("svg".to_string(), "image/svg+xml".to_string()),
				("svgz".to_string(), "image/svg+xml".to_string()),
				("tif".to_string(), "image/tiff".to_string()),
				("tiff".to_string(), "image/tiff".to_string()),
				("wbmp".to_string(), "image/vnd.wap.wbmp".to_string()),
				("webp".to_string(), "image/webp".to_string()),
				("ico".to_string(), "image/x-icon".to_string()),
				("jng".to_string(), "image/x-jng".to_string()),
				("bmp".to_string(), "image/x-ms-bmp".to_string()),
				("woff".to_string(), "font/woff".to_string()),
				("woff2".to_string(), "font/woff2".to_string()),
				("jar".to_string(), "application/java-archive".to_string()),
				("war".to_string(), "application/java-archive".to_string()),
				("ear".to_string(), "application/java-archive".to_string()),
				("json".to_string(), "application/json".to_string()),
				("hqx".to_string(), "application/mac-binhex40".to_string()),
				("doc".to_string(), "application/msword".to_string()),
				("pdf".to_string(), "application/pdf".to_string()),
				("ps".to_string(), "application/postscript".to_string()),
				("eps".to_string(), "application/postscript".to_string()),
				("ai".to_string(), "application/postscript".to_string()),
				("rtf".to_string(), "application/rtf".to_string()),
				(
					"m3u8".to_string(),
					"application/vnd.apple.mpegurl".to_string(),
				),
				(
					"kml".to_string(),
					"application/vnd.google-earth.kml+xml".to_string(),
				),
				(
					"kmz".to_string(),
					"application/vnd.google-earth.kmz".to_string(),
				),
				("xls".to_string(), "application/vnd.ms-excel".to_string()),
				(
					"eot".to_string(),
					"application/vnd.ms-fontobject".to_string(),
				),
				(
					"ppt".to_string(),
					"application/vnd.ms-powerpoint".to_string(),
				),
				(
					"odg".to_string(),
					"application/vnd.oasis.opendocument.graphics".to_string(),
				),
				(
					"odp".to_string(),
					"application/vnd.oasis.opendocument.presentation".to_string(),
				),
				(
					"ods".to_string(),
					"application/vnd.oasis.opendocument.spreadsheet".to_string(),
				),
				(
					"odt".to_string(),
					"application/vnd.oasis.opendocument.text".to_string(),
				),
				(
					"pptx".to_string(),
					"application/vnd.openxmlformats-officedocument.presentationml.presentation"
						.to_string(),
				),
				(
					"xlsx".to_string(),
					"application/vnd.openxmlformats-officedocument.spreadsheetml.sheet".to_string(),
				),
				(
					"docx".to_string(),
					"application/vnd.openxmlformats-officedocument.wordprocessingml.document"
						.to_string(),
				),
				("wmlc".to_string(), "application/vnd.wap.wmlc".to_string()),
				("wasm".to_string(), "application/wasm".to_string()),
				("7z".to_string(), "application/x-7z-compressed".to_string()),
				("cco".to_string(), "application/x-cocoa".to_string()),
				(
					"jardiff".to_string(),
					"application/x-java-archive-diff".to_string(),
				),
				(
					"jnlp".to_string(),
					"application/x-java-jnlp-file".to_string(),
				),
				("run".to_string(), "application/x-makeself".to_string()),
				("pl".to_string(), "application/x-perl".to_string()),
				("pm".to_string(), "application/x-perl".to_string()),
				("prc".to_string(), "application/x-pilot".to_string()),
				("pbd".to_string(), "application/x-pilot".to_string()),
				(
					"rar".to_string(),
					"application/x-rar-compressed".to_string(),
				),
				(
					"rpm".to_string(),
					"application/x-redhat-package-manager".to_string(),
				),
				("sea".to_string(), "application/x-sea".to_string()),
				(
					"swf".to_string(),
					"application/x-shockwave-flash".to_string(),
				),
				("sit".to_string(), "application/x-stuffit".to_string()),
				("tcl".to_string(), "application/x-tcl".to_string()),
				("tk".to_string(), "application/x-tcl".to_string()),
				("der".to_string(), "application/x-x509-ca-cert".to_string()),
				("pem".to_string(), "application/x-x509-ca-cert".to_string()),
				("crt".to_string(), "application/x-x509-ca-cert".to_string()),
				("xpi".to_string(), "application/x-xpinstall".to_string()),
				("xhtml".to_string(), "application/xhtml+xml".to_string()),
				("xspf".to_string(), "application/xspf+xml".to_string()),
				("zip".to_string(), "application/zip".to_string()),
				("bin".to_string(), "application/octet-stream".to_string()),
				("exe".to_string(), "application/octet-stream".to_string()),
				("dll".to_string(), "application/octet-stream".to_string()),
				("deb".to_string(), "application/octet-stream".to_string()),
				("dmg".to_string(), "application/octet-stream".to_string()),
				("iso".to_string(), "application/octet-stream".to_string()),
				("img".to_string(), "application/octet-stream".to_string()),
				("msi".to_string(), "application/octet-stream".to_string()),
				("msp".to_string(), "application/octet-stream".to_string()),
				("msm".to_string(), "application/octet-stream".to_string()),
				("mid".to_string(), "audio/midi".to_string()),
				("midi".to_string(), "audio/midi".to_string()),
				("kar".to_string(), "audio/midi".to_string()),
				("mp3".to_string(), "audio/mpeg".to_string()),
				("ogg".to_string(), "audio/ogg".to_string()),
				("m4a".to_string(), "audio/x-m4a".to_string()),
				("ra".to_string(), "audio/x-realaudio".to_string()),
				("3gpg".to_string(), "video/3gpp".to_string()),
				("3gp".to_string(), "video/mp2t".to_string()),
				("ts".to_string(), "video/mp2t".to_string()),
				("mp4".to_string(), "video/mp4".to_string()),
				("mpeg".to_string(), "video/mpeg".to_string()),
				("mpg".to_string(), "video/mpeg".to_string()),
				("mov".to_string(), "video/quicktime".to_string()),
				("webm".to_string(), "video/webm".to_string()),
				("flv".to_string(), "video/x-flv".to_string()),
				("m4v".to_string(), "video/x-m4v".to_string()),
				("mng".to_string(), "video/x-mng".to_string()),
				("asx".to_string(), "video/x-ms-asf".to_string()),
				("asf".to_string(), "video/x-ms-asf".to_string()),
				("wmv".to_string(), "video/x-ms-wmv".to_string()),
				("avi".to_string(), "video/x-msvideo".to_string()),
			],
		}
	}
}

pub struct HttpApiConfig {
	pub mappings: HashSet<Vec<u8>>,
	pub extensions: HashSet<Vec<u8>>,
}

impl Default for HttpApiConfig {
	fn default() -> Self {
		Self {
			mappings: HashSet::new(),
			extensions: HashSet::new(),
		}
	}
}

#[derive(Clone, Debug)]
pub(crate) struct PostStatus {
	pub(crate) is_disconnected: bool,
	slab_woffset: usize,
	pub(crate) send: Option<SyncSender<()>>,
}

impl PostStatus {
	fn new() -> Self {
		Self {
			is_disconnected: false,
			slab_woffset: 0,
			send: None,
		}
	}
}

#[derive(Clone, Debug)]
pub struct ApiContext {
	async_connections: Arc<RwLock<StaticHash<(), ()>>>,
	conn_data: ConnectionData,
	temp_file: Option<String>,
	offset: usize,
	expected: usize,
	rem: usize,
	slaballocator: Arc<RwLock<SlabAllocator>>,
	slab_ids: Vec<u64>,
	slab_size: usize,
	is_proxy: bool,
	is_async: bool,
	proxy_conn: Option<ConnectionData>,
	stat_handler: StatHandler,
	log_item: LogItem,
	response_code: u16,
	pub(crate) post_status: Arc<RwLock<PostStatus>>,
}

impl ApiContext {
	pub fn new(
		async_connections: Arc<RwLock<StaticHash<(), ()>>>,
		conn_data: ConnectionData,
		slaballocator: Arc<RwLock<SlabAllocator>>,
		is_proxy: bool,
		proxy_conn: Option<ConnectionData>,
		stat_handler: StatHandler,
		log_item: LogItem,
	) -> Self {
		Self {
			async_connections,
			conn_data,
			temp_file: None,
			offset: 0,
			expected: 0,
			rem: 0,
			slaballocator,
			slab_ids: vec![],
			slab_size: 0,
			post_status: Arc::new(RwLock::new(PostStatus::new())),
			is_proxy,
			is_async: false,
			proxy_conn,
			stat_handler,
			log_item,
			response_code: 200,
		}
	}

	pub fn set_response_code_logging(&mut self, response_code: u16) -> Result<(), Error> {
		self.response_code = response_code;
		Ok(())
	}

	pub fn log_item(&mut self) -> &mut LogItem {
		&mut self.log_item
	}

	pub fn proxy_conn(&self) -> Option<&ConnectionData> {
		self.proxy_conn.as_ref()
	}

	pub fn is_proxy(&self) -> bool {
		self.is_proxy
	}

	pub fn is_async(&self) -> bool {
		self.is_async
	}

	pub fn set_async(&mut self) -> Result<(), Error> {
		self.is_async = true;
		let mut async_connections = lockw!(self.async_connections)?;
		let mut li_bytes = [0u8; LOG_ITEM_SIZE];
		self.log_item.write(&mut li_bytes)?;
		async_connections
			.insert_raw(&self.conn_data.get_connection_id().to_be_bytes(), &li_bytes)?;
		Ok(())
	}

	pub fn async_complete(&mut self) -> Result<(), Error> {
		// remove the temp file, if it exists
		// free slabs
		self.remove_file_and_free_slabs()?;

		{
			let mut async_connections = lockw!(self.async_connections)?;

			match async_connections.remove_raw(&self.conn_data.get_connection_id().to_be_bytes()) {
				Some(li_bytes) => {
					let mut log_item = LogItem::default();
					log_item.read(li_bytes.try_into()?)?;
					log_item.response_code = self.response_code;
					log_item.end_micros =
						SystemTime::now().duration_since(UNIX_EPOCH)?.as_micros() as u64;
					match self
						.stat_handler
						.http_stats
						.store_log_items(vec![log_item].into_iter(), vec![].into_iter())
					{
						Ok(_) => {}
						Err(e) => {
							error!("store_log items error: {}", e)?;
						}
					}
				}
				None => {}
			}
		}
		self.conn_data.async_complete()?;
		Ok(())
	}

	pub(crate) fn remove_file_and_free_slabs(&mut self) -> Result<(), Error> {
		if self.slab_ids.len() == 0 {
			match &self.temp_file {
				Some(file) => match remove_file(file) {
					Ok(_) => {}
					Err(e) => {
						warn!("could not remove file: '{}' due to:  {}", file, e)?;
					}
				},
				None => {}
			}
		} else {
			let mut slaballocator = lockw!(self.slaballocator)?;
			for id in &self.slab_ids {
				slaballocator.free_id(*id)?;
			}
			self.slab_ids = vec![];
		}
		Ok(())
	}

	pub(crate) fn async_complete_no_file(&mut self) -> Result<(), Error> {
		{
			let mut async_connections = lockw!(self.async_connections)?;
			match async_connections.remove_raw(&self.conn_data.get_connection_id().to_be_bytes()) {
				Some(li_bytes) => {
					let mut log_item = LogItem::default();
					log_item.read(li_bytes.try_into()?)?;
					log_item.response_code = self.response_code;
					log_item.end_micros =
						SystemTime::now().duration_since(UNIX_EPOCH)?.as_micros() as u64;
					match self
						.stat_handler
						.http_stats
						.store_log_items(vec![log_item].into_iter(), vec![].into_iter())
					{
						Ok(_) => {}
						Err(e) => {
							error!("store_log items error: {}", e)?;
						}
					}
				}
				None => {}
			}
		}
		self.conn_data.async_complete()?;
		Ok(())
	}

	pub fn update_offset(&mut self, amt: usize) {
		self.offset += amt;
	}

	pub fn remaining(&self) -> usize {
		self.expected.saturating_sub(self.offset)
	}

	pub fn copy_bytes(&mut self, dst: String) -> Result<(), Error> {
		let recv = {
			let mut post_status = lockw!(self.post_status)?;
			let cur_size = match self.slab_ids.len() {
				0 => match &self.temp_file {
					Some(file) => {
						match std::fs::metadata(file) {
							Ok(metadata) => metadata.len().try_into()?,
							Err(_e) => {
								// sometimes we get here before the
								// file was created it means 0 length
								0
							}
						}
					}
					None => 0,
				},
				_ => post_status.slab_woffset,
			};

			if cur_size < self.expected {
				let send: SyncSender<()>;
				let recv: Receiver<()>;
				(send, recv) = sync_channel(1);
				(*post_status).send = Some(send);
				Some(recv)
			} else {
				None
			}
		};

		match recv {
			Some(receive) => {
				receive.recv().map_err(|err| {
					let error: Error =
						ErrorKind::InternalError(format!("Recv Error: {}", err)).into();
					error
				})?;
			}
			None => {}
		}

		match self.slab_ids.len() {
			0 => match &self.temp_file {
				Some(file) => {
					std::fs::copy(file, dst)?;
				}
				None => {
					return Err(
						ErrorKind::InternalError("Expected temp file to exist".into()).into(),
					)
				}
			},
			_ => {
				let mut i = 0;
				let mut buf_itt = 0;
				File::create(dst.clone())?;
				let mut file = OpenOptions::new().write(true).append(true).open(dst)?;
				loop {
					let slab = i / self.slab_size;
					let slab_offset = i % self.slab_size;
					let slaballocator = lockr!(self.slaballocator)?;
					let slab = slaballocator.get(self.slab_ids[slab])?;

					let mut len = self.slab_size.saturating_sub(slab_offset);
					if len + buf_itt > self.expected {
						len = self.expected.saturating_sub(buf_itt);
					}

					file.write(&slab.data[slab_offset..(slab_offset + len)])?;

					buf_itt += len;
					i += len;
					if buf_itt >= self.expected {
						break;
					}
				}
			}
		}

		self.offset = self.expected;

		Ok(())
	}

	// note that pull bytes potentially blocks. It must only be called in a thread outside of the
	// main server loop. TODO: add thread local variable to ensure it's not called in the
	// server loop.
	pub fn pull_bytes(&mut self, buf: &mut [u8]) -> Result<usize, Error> {
		let recv = {
			let mut post_status = lockw!(self.post_status)?;
			let cur_size = match self.slab_ids.len() {
				0 => match &self.temp_file {
					Some(file) => {
						match std::fs::metadata(file) {
							Ok(metadata) => metadata.len().try_into()?,
							Err(_e) => {
								// sometimes we get here before the
								// file was created it means 0 length
								0
							}
						}
					}
					None => 0,
				},
				_ => post_status.slab_woffset,
			};

			if cur_size < self.expected {
				let send: SyncSender<()>;
				let recv: Receiver<()>;
				(send, recv) = sync_channel(1);
				(*post_status).send = Some(send);
				Some(recv)
			} else {
				None
			}
		};
		match recv {
			Some(receive) => receive.recv().map_err(|err| {
				let error: Error = ErrorKind::InternalError(format!("Recv Error: {}", err)).into();
				error
			})?,
			None => {}
		}

		{
			let post_status = lockr!(self.post_status)?;
			if (*post_status).is_disconnected {
				return Err(
					ErrorKind::ConnectionCloseError("Connection already closed".into()).into(),
				);
			}
		}

		let mut requested = self.expected.saturating_sub(self.offset);
		if requested > buf.len() {
			requested = buf.len();
		}

		match self.slab_ids.len() {
			0 => match &self.temp_file {
				Some(file) => {
					let mut file = OpenOptions::new().read(true).open(file)?;
					file.seek(SeekFrom::Start(self.offset.try_into()?))?;
					file.read_exact(&mut buf[0..requested])?;
					self.offset += requested;
					Ok(requested)
				}
				None => Ok(0),
			},
			_ => {
				let mut i = self.offset;
				let mut buf_itt = 0;
				loop {
					let slab = i / self.slab_size;
					let slab_offset = i % self.slab_size;
					let slaballocator = lockr!(self.slaballocator)?;
					let slab = slaballocator.get(self.slab_ids[slab])?;

					let mut len = self.slab_size.saturating_sub(slab_offset);
					if len + buf_itt > requested {
						len = requested.saturating_sub(buf_itt);
					}

					buf[buf_itt..(buf_itt + len)]
						.clone_from_slice(&slab.data[slab_offset..(slab_offset + len)]);

					buf_itt += len;
					i += len;
					if buf_itt >= requested {
						break;
					}
				}
				self.offset += requested;
				Ok(requested)
			}
		}
	}

	pub fn set_expected(
		&mut self,
		expected: usize,
		temp_dir: &String,
		is_proxy: bool,
	) -> Result<(), Error> {
		self.expected = expected;
		self.rem = expected;

		if !is_proxy {
			let mut slaballocator = lockw!(self.slaballocator)?;

			let free_count = slaballocator.free_count() as usize;
			let slab_size = slaballocator.slab_size() as usize;
			let size_available = free_count * slab_size;
			self.slab_size = slab_size;
			if size_available >= expected {
				let mut slabs_needed = expected / slab_size;
				if expected % slab_size > 0 {
					slabs_needed += 1;
				}
				for _ in 0..slabs_needed {
					let slab = slaballocator.allocate()?;
					self.slab_ids.push(slab.id);
				}
			} else {
				let r: [u8; 16] = rand::random();
				let r: &[u8] = &r[0..16];
				let file = format!("{}/nioruntime.{}", temp_dir, base58::ToBase58::to_base58(r));
				warn!(
					"content too big ({} bytes) to use in memory slabs. Using temp file: '{}'",
					expected, file
				)?;
				self.temp_file = Some(file.clone());
			}
		}

		Ok(())
	}

	pub fn push_bytes(&mut self, buffer: &[u8]) -> Result<(usize, usize), Error> {
		if self.rem == 0 || buffer.len() == 0 {
			return Ok((self.rem, 0));
		}

		let buf = if buffer.len() > self.rem {
			&buffer[0..self.rem]
		} else {
			&buffer[..]
		};

		let pushed = buf.len();

		self.rem = self.rem.saturating_sub(buf.len());

		let post_status = self.post_status.clone();
		let buf: Vec<u8> = buf.to_vec();
		let rem = self.rem;
		let slab_ids = self.slab_ids.clone();
		let slab_size = self.slab_size;
		let slaballocator = self.slaballocator.clone();
		let temp_file = self.temp_file.clone();

		let (seqsend, seqrecv) = channel::<()>();

		std::thread::spawn(move || -> Result<(), Error> {
			// first we obtain the lock for this API context
			let mut post_status = lockw!(post_status)?;

			seqsend.send(()).map_err(|e| {
				let error: Error = ErrorKind::ApplicationError(format!("Send error: {}", e)).into();
				error
			})?;

			match slab_ids.len() {
				0 => {
					let file = match temp_file {
						Some(file) => file.clone(),
						None => {
							return Err(ErrorKind::InternalError(
								"Expected temp file to be created.".into(),
							)
							.into());
						}
					};
					if !Path::new(&file).exists() {
						File::create(&file)?;
					}

					let mut file = OpenOptions::new().write(true).append(true).open(file)?;
					file.write_all(&buf)?;
				}
				_ => {
					let slab_woffset_value = post_status.slab_woffset;
					let buf_len = buf.len();

					let mut i = slab_woffset_value;
					let mut buf_itt = 0;
					let mut slaballocator = lockw!(slaballocator)?;
					loop {
						let slab = i / slab_size;
						let slab_offset = i % slab_size;
						let slab = slaballocator.get_mut(slab_ids[slab])?;

						let mut len = slab_size.saturating_sub(slab_offset);
						if len + buf_itt > buf_len {
							len = buf_len.saturating_sub(buf_itt);
						}
						slab.data[slab_offset..(slab_offset + len)]
							.clone_from_slice(&buf[buf_itt..(buf_itt + len)]);

						buf_itt += len;
						i += len;
						if buf_itt >= buf_len {
							break;
						}
					}

					{
						(*post_status).slab_woffset += buf_len;
					}
				}
			}

			if rem == 0 {
				match &(*post_status).send {
					Some(send) => {
						send.send(()).map_err(|e| {
							let error: Error =
								ErrorKind::ApplicationError(format!("Send error: {}", e)).into();
							error
						})?;
					}
					None => {}
				}
			}

			Ok(())
		});
		seqrecv.recv().map_err(|err| {
			let error: Error = ErrorKind::InternalError(format!("Recv Error: {}", err)).into();
			error
		})?;

		Ok((self.rem, pushed))
	}
}

#[cfg(test)]
mod test {
	use crate::types::*;
	use nioruntime_err::{Error, ErrorKind};

	#[test]
	fn test_headers() -> Result<(), Error> {
		let buffer = b"GET / HTTP/1.1\r\n\
Host: localhost\r\n\
X: 1\r\n\
Y012345678: 01234567890123456789\r\n\r\n";
		let mut matcher = ThreadContext::build_matcher(500, 200, 1000, 200, vec![])?;
		let mut config = HttpConfig::default();
		config.max_header_size = 200;
		config.max_header_name_len = 10;
		config.max_header_value_len = 20;
		let v1 = &mut vec![];
		let v2 = &mut vec![];
		let mut headers = HttpHeaders::new(
			buffer,
			&config,
			&mut matcher,
			v1,
			&mut 0,
			v2,
			&mut StaticHash::new(StaticHashConfig {
				max_entries: 100,
				key_len: 8,
				entry_len: 0,
				max_load_factor: 0.95,
				..Default::default()
			})?,
		)?
		.unwrap();

		assert_eq!(headers.get_uri(), b"/");
		assert_eq!(headers.get_query(), b"");
		assert_eq!(headers.extension(), b"html");
		assert_eq!(
			headers.get_header_names().unwrap().sort(),
			vec!["Host", "Y", "X"].sort()
		);

		// test incomplete header
		assert!(HttpHeaders::new(
			b"GET / HTTP/1.1\r\nHost: localhost\r\nX01234567: 1\r\nY: 2\r\n\r",
			&config,
			&mut matcher,
			&vec![],
			&mut 0,
			&mut vec![],
			&mut StaticHash::new(StaticHashConfig {
				max_entries: 100,
				key_len: 8,
				entry_len: 0,
				max_load_factor: 0.95,
				..Default::default()
			})?,
		)?
		.is_none());

		// test too long headers
		assert_eq!(
			HttpHeaders::new(
				b"GET / HTTP/1.1\r\nHost: localhost\r\nX: 1\r\nA0123456789: 0\r\n\r\n",
				&config,
				&mut matcher,
				&vec![],
				&mut 0,
				&mut vec![],
				&mut StaticHash::new(StaticHashConfig {
					max_entries: 100,
					key_len: 8,
					entry_len: 0,
					max_load_factor: 0.95,
					..Default::default()
				})?,
			)
			.unwrap_err()
			.kind(),
			ErrorKind::HttpError431("Request Header Field Name Too Large".into())
		);

		assert_eq!(
			HttpHeaders::new(
				b"GET / HTTP/1.1\r\nHost: localhost\r\nX: 1\r\nA: 012345678901234567890\r\n\r\n",
				&config,
				&mut matcher,
				&vec![],
				&mut 0,
				&mut vec![],
				&mut StaticHash::new(StaticHashConfig {
					max_entries: 100,
					key_len: 8,
					entry_len: 0,
					max_load_factor: 0.95,
					..Default::default()
				})?,
			)
			.unwrap_err()
			.kind(),
			ErrorKind::HttpError431("Request Header Field Value Too Large".into())
		);

		assert_eq!(
							HttpHeaders::new(b"GET / HTTP/1.1\r\nHost: localhost\r\nX: 1\r\n\
		A: \
		0123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789\
		0123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789\r\n\r\n",
								&config,
								&mut matcher,
								&vec![],
								&mut 0,
								&mut vec![],
								&mut StaticHash::new(StaticHashConfig {
                                                                                                  max_entries: 100,
                                                                                                                                          key_len: 8,
                                                                                                                                                                                  entry_len: 0,
                                                                                                                                                                                                                          max_load_factor: 0.95,
									..Default::default()
								})?,
							).unwrap_err().kind(), ErrorKind::HttpError431("Request Header Fields Too Large".into()));

		assert_eq!(
			HttpHeaders::new(
				b"GETT / HTTP/1.1\r\nHost: localhost\r\nX: 1\r\n\
                        A: ok\r\n\r\n",
				&config,
				&mut matcher,
				&vec![],
				&mut 0,
				&mut vec![],
				&mut StaticHash::new(StaticHashConfig {
					max_entries: 100,
					key_len: 8,
					entry_len: 0,
					max_load_factor: 0.95,
					..Default::default()
				})?,
			)
			.unwrap_err()
			.kind(),
			ErrorKind::HttpError405("Method not supported".into())
		);

		assert_eq!(
			HttpHeaders::new(
				b"GET / HTP/1.1\r\nHost: localhost\r\nX: 1\r\n\
A: ok\r\n\r\n",
				&config,
				&mut matcher,
				&vec![],
				&mut 0,
				&mut vec![],
				&mut StaticHash::new(StaticHashConfig {
					max_entries: 100,
					key_len: 8,
					entry_len: 0,
					max_load_factor: 0.95,
					..Default::default()
				})?,
			)
			.unwrap_err()
			.kind(),
			ErrorKind::HttpError400("Bad request: version not found".into())
		);

		assert_eq!(
			HttpHeaders::new(
				b"POST /abc /def HTTP/1.1\r\nHost: localhost\r\nX: 1\r\n\
                                                                                A: ok\r\n\r\n",
				&config,
				&mut matcher,
				&vec![],
				&mut 0,
				&mut vec![],
				&mut StaticHash::new(StaticHashConfig {
					max_entries: 100,
					key_len: 8,
					entry_len: 0,
					max_load_factor: 0.95,
					..Default::default()
				})?,
			)
			.unwrap_err()
			.kind(),
			ErrorKind::HttpError400("Bad request: invalid format".into())
		);

		assert_eq!(
			HttpHeaders::new(
				b"PUT / HTTP/1.1\r\nRange: bytes=10..20\r\n\r\n",
				&config,
				&mut matcher,
				&vec![],
				&mut 0,
				&mut vec![],
				&mut StaticHash::new(StaticHashConfig {
					max_entries: 100,
					key_len: 8,
					entry_len: 0,
					max_load_factor: 0.95,
					..Default::default()
				})?,
			)
			.unwrap()
			.unwrap()
			.range(),
			b"bytes=10..20"
		);

		assert_eq!(
			HttpHeaders::new(
				b"GET / HTTP/1.1\r\nRange: bytes=10..20\r\n\r\n",
				&config,
				&mut matcher,
				&vec![],
				&mut 0,
				&mut vec![],
				&mut StaticHash::new(StaticHashConfig {
					max_entries: 100,
					key_len: 8,
					entry_len: 0,
					max_load_factor: 0.95,
					..Default::default()
				})?,
			)
			.unwrap()
			.unwrap()
			.get_method(),
			&HttpMethod::Get
		);

		assert_eq!(
			HttpHeaders::new(
				b"HEAD / HTTP/1.1\r\nRange: bytes=10..20\r\n\r\n",
				&config,
				&mut matcher,
				&vec![],
				&mut 0,
				&mut vec![],
				&mut StaticHash::new(StaticHashConfig {
					max_entries: 100,
					key_len: 8,
					entry_len: 0,
					max_load_factor: 0.95,
					..Default::default()
				})?,
			)
			.unwrap()
			.unwrap()
			.get_method(),
			&HttpMethod::Head
		);

		assert_eq!(
			HttpHeaders::new(
				b"TRACE / HTTP/1.1\r\nRange: bytes=10..20\r\n\r\n",
				&config,
				&mut matcher,
				&vec![],
				&mut 0,
				&mut vec![],
				&mut StaticHash::new(StaticHashConfig {
					max_entries: 100,
					key_len: 8,
					entry_len: 0,
					max_load_factor: 0.95,
					..Default::default()
				})?,
			)
			.unwrap()
			.unwrap()
			.get_method(),
			&HttpMethod::Trace
		);

		assert_eq!(
			HttpHeaders::new(
				b"OPTIONS / HTTP/1.1\r\nRange: bytes=10..20\r\n\r\n",
				&config,
				&mut matcher,
				&vec![],
				&mut 0,
				&mut vec![],
				&mut StaticHash::new(StaticHashConfig {
					max_entries: 100,
					key_len: 8,
					entry_len: 0,
					max_load_factor: 0.95,
					..Default::default()
				})?,
			)
			.unwrap()
			.unwrap()
			.get_method(),
			&HttpMethod::Options
		);

		assert_eq!(
			HttpHeaders::new(
				b"PATCH / HTTP/1.1\r\nRange: bytes=10..20\r\n\r\n",
				&config,
				&mut matcher,
				&vec![],
				&mut 0,
				&mut vec![],
				&mut StaticHash::new(StaticHashConfig {
					max_entries: 100,
					key_len: 8,
					entry_len: 0,
					max_load_factor: 0.95,
					..Default::default()
				})?,
			)
			.unwrap()
			.unwrap()
			.get_method(),
			&HttpMethod::Patch
		);

		assert_eq!(
			HttpHeaders::new(
				b"CONNECT / HTTP/1.1\r\nRange: bytes=10..20\r\n\r\n",
				&config,
				&mut matcher,
				&vec![],
				&mut 0,
				&mut vec![],
				&mut StaticHash::new(StaticHashConfig {
					max_entries: 100,
					key_len: 8,
					entry_len: 0,
					max_load_factor: 0.95,
					..Default::default()
				})?,
			)
			.unwrap()
			.unwrap()
			.get_method(),
			&HttpMethod::Connect
		);

		assert_eq!(
			HttpHeaders::new(
				b"POST / HTTP/1.1\r\nRange: bytes=10..20\r\n\r\n",
				&config,
				&mut matcher,
				&vec![],
				&mut 0,
				&mut vec![],
				&mut StaticHash::new(StaticHashConfig {
					max_entries: 100,
					key_len: 8,
					entry_len: 0,
					max_load_factor: 0.95,
					..Default::default()
				})?,
			)
			.unwrap()
			.unwrap()
			.get_method(),
			&HttpMethod::Post
		);

		assert_eq!(
			HttpHeaders::new(
				b"DELETE / HTTP/1.1\r\nRange: bytes=10..20\r\n\r\n",
				&config,
				&mut matcher,
				&vec![],
				&mut 0,
				&mut vec![],
				&mut StaticHash::new(StaticHashConfig {
					max_entries: 100,
					key_len: 8,
					entry_len: 0,
					max_load_factor: 0.95,
					..Default::default()
				})?,
			)
			.unwrap()
			.unwrap()
			.get_method(),
			&HttpMethod::Delete
		);

		config.max_header_name_len = 20;
		config.max_header_value_len = 40;

		assert_eq!(
			HttpHeaders::new(
				b"POST / HTTP/1.1\r\nContent-Length: 24\r\n\r\n01234567890123456789\r\n\r\n",
				&config,
				&mut matcher,
				&vec![],
				&mut 0,
				&mut vec![],
				&mut StaticHash::new(StaticHashConfig {
					max_entries: 100,
					key_len: 8,
					entry_len: 0,
					max_load_factor: 0.95,
					..Default::default()
				})?,
			)
			.unwrap()
			.unwrap()
			.content_len()
			.unwrap(),
			24
		);

		assert_eq!(
			HttpHeaders::new(
				b"POST / HTTP/1.1\r\nContent-Length: 24\r\nHost: example.com\r\n\r\n01234567890123456789\r\n\r\n",
				&config,
				&mut matcher,
								&vec![],
								&mut 0,
								&mut vec![],
								&mut StaticHash::new(StaticHashConfig {
                                                                        max_entries: 100,
                                                                        key_len: 8,
                                                                        entry_len: 0,
                                                                        max_load_factor: 0.95,
									..Default::default()
								})?,
			)
			.unwrap()
			.unwrap()
			.get_host(),
			b"example.com"
		);

		assert_eq!(
			HttpHeaders::new(
				b"GET /abc.def?abc=123 HTTP/1.1\r\nHost: example.com\r\n\r\n",
				&config,
				&mut matcher,
				&vec![],
				&mut 0,
				&mut vec![],
				&mut StaticHash::new(StaticHashConfig {
					max_entries: 100,
					key_len: 8,
					entry_len: 0,
					max_load_factor: 0.95,
					..Default::default()
				})?,
			)
			.unwrap()
			.unwrap()
			.extension(),
			b"def"
		);

		assert_eq!(
			HttpHeaders::new(
				b"GET /abc.def?abc=123 HTTP/1.1\r\nHost: example.com\r\n\r\n",
				&config,
				&mut matcher,
				&vec![],
				&mut 0,
				&mut vec![],
				&mut StaticHash::new(StaticHashConfig {
					max_entries: 100,
					key_len: 8,
					entry_len: 0,
					max_load_factor: 0.95,
					..Default::default()
				})?,
			)
			.unwrap()
			.unwrap()
			.get_uri(),
			b"/abc.def"
		);

		assert_eq!(
			HttpHeaders::new(
				b"GET /abc.def?abc=123 HTTP/1.1\r\nHost: example.com\r\n\r\n",
				&config,
				&mut matcher,
				&vec![],
				&mut 0,
				&mut vec![],
				&mut StaticHash::new(StaticHashConfig {
					max_entries: 100,
					key_len: 8,
					entry_len: 0,
					max_load_factor: 0.95,
					..Default::default()
				})?,
			)
			.unwrap()
			.unwrap()
			.get_query(),
			b"abc=123"
		);

		assert_eq!(
			HttpHeaders::new(
				b"GET /?abc=123 HTTP/1.1\r\nHost: example.com\r\n\r\n",
				&config,
				&mut matcher,
				&vec![],
				&mut 0,
				&mut vec![],
				&mut StaticHash::new(StaticHashConfig {
					max_entries: 100,
					key_len: 8,
					entry_len: 0,
					max_load_factor: 0.95,
					..Default::default()
				})?,
			)
			.unwrap()
			.unwrap()
			.get_query(),
			b"abc=123"
		);

		assert_eq!(
			HttpHeaders::new(
				b"GET /?abc=123 HTTP/1.1\r\nHost: example.com\r\n\r\n",
				&config,
				&mut matcher,
				&vec![],
				&mut 0,
				&mut vec![],
				&mut StaticHash::new(StaticHashConfig {
					max_entries: 100,
					key_len: 8,
					entry_len: 0,
					max_load_factor: 0.95,
					..Default::default()
				})?,
			)
			.unwrap()
			.unwrap()
			.get_uri(),
			b"/"
		);

		assert_eq!(
			std::str::from_utf8(
				HttpHeaders::new(
					b"GET /?abc=123 HTTP/1.1\r\nHost: example.com\r\n\r\n",
					&config,
					&mut matcher,
					&vec![],
					&mut 0,
					&mut vec![],
					&mut StaticHash::new(StaticHashConfig {
						max_entries: 100,
						key_len: 8,
						entry_len: 0,
						max_load_factor: 0.95,
						..Default::default()
					})?,
				)
				.unwrap()
				.unwrap()
				.extension()
			)?,
			"html"
		);

		assert_eq!(
			HttpHeaders::new(
				b"GET /. HTTP/1.1\r\nHost: example.com\r\n\r\n",
				&config,
				&mut matcher,
				&vec![],
				&mut 0,
				&mut vec![],
				&mut StaticHash::new(StaticHashConfig {
					max_entries: 100,
					key_len: 8,
					entry_len: 0,
					max_load_factor: 0.95,
					..Default::default()
				})?,
			)
			.unwrap()
			.unwrap()
			.extension(),
			b""
		);

		assert_eq!(
			HttpHeaders::new(
				b"GET /. HTTP/1.1\r\nHost: example.com\r\n\r\n",
				&config,
				&mut matcher,
				&vec![],
				&mut 0,
				&mut vec![],
				&mut StaticHash::new(StaticHashConfig {
					max_entries: 100,
					key_len: 8,
					entry_len: 0,
					max_load_factor: 0.95,
					..Default::default()
				})?,
			)
			.unwrap()
			.unwrap()
			.get_uri(),
			b"/."
		);

		assert_eq!(
			HttpHeaders::new(
				b"GET /.? HTTP/1.1\r\nHost: example.com\r\n\r\n",
				&config,
				&mut matcher,
				&vec![],
				&mut 0,
				&mut vec![],
				&mut StaticHash::new(StaticHashConfig {
					max_entries: 100,
					key_len: 8,
					entry_len: 0,
					max_load_factor: 0.95,
					..Default::default()
				})?,
			)
			.unwrap()
			.unwrap()
			.get_uri(),
			b"/."
		);

		assert_eq!(
			HttpHeaders::new(
				b"GET /.? HTTP/1.1\r\nHost: example.com\r\n\r\n",
				&config,
				&mut matcher,
				&vec![],
				&mut 0,
				&mut vec![],
				&mut StaticHash::new(StaticHashConfig {
					max_entries: 100,
					key_len: 8,
					entry_len: 0,
					max_load_factor: 0.95,
					..Default::default()
				})?,
			)
			.unwrap()
			.unwrap()
			.get_query(),
			b""
		);

		assert_eq!(
			HttpHeaders::new(
				b"GET /.?  HTTP/1.1\r\nHost: example.com\r\n\r\n",
				&config,
				&mut matcher,
				&vec![],
				&mut 0,
				&mut vec![],
				&mut StaticHash::new(StaticHashConfig {
					max_entries: 100,
					key_len: 8,
					entry_len: 0,
					max_load_factor: 0.95,
					..Default::default()
				})?,
			)
			.unwrap_err()
			.kind(),
			ErrorKind::HttpError400("Bad request: invalid format".into())
		);

		assert_eq!(
			HttpHeaders::new(
				b"GET /.? HTTP/1.1\r\nHost: example.com\r\n\r\n",
				&config,
				&mut matcher,
				&vec![],
				&mut 0,
				&mut vec![],
				&mut StaticHash::new(StaticHashConfig {
					max_entries: 100,
					key_len: 8,
					entry_len: 0,
					max_load_factor: 0.95,
					..Default::default()
				})?,
			)
			.unwrap()
			.unwrap()
			.get_version(),
			&HttpVersion::V11
		);

		assert_eq!(
			HttpHeaders::new(
				b"GET /.? HTTP/1.0\r\nHost: example.com\r\n\r\n",
				&config,
				&mut matcher,
				&vec![],
				&mut 0,
				&mut vec![],
				&mut StaticHash::new(StaticHashConfig {
					max_entries: 100,
					key_len: 8,
					entry_len: 0,
					max_load_factor: 0.95,
					..Default::default()
				})?,
			)
			.unwrap()
			.unwrap()
			.get_version(),
			&HttpVersion::V10
		);

		assert_eq!(
			HttpHeaders::new(
				b"GET /.? HTTP/2.0\r\nHost: example.com\r\n\r\n",
				&config,
				&mut matcher,
				&vec![],
				&mut 0,
				&mut vec![],
				&mut StaticHash::new(StaticHashConfig {
					max_entries: 100,
					key_len: 8,
					entry_len: 0,
					max_load_factor: 0.95,
					..Default::default()
				})?,
			)
			.unwrap()
			.unwrap()
			.get_version(),
			&HttpVersion::V20
		);

		assert_eq!(
			HttpHeaders::new(
				b"GET /.? HTTP/2.1\r\nHost: example.com\r\n\r\n",
				&config,
				&mut matcher,
				&vec![],
				&mut 0,
				&mut vec![],
				&mut StaticHash::new(StaticHashConfig {
					max_entries: 100,
					key_len: 8,
					entry_len: 0,
					max_load_factor: 0.95,
					..Default::default()
				})?,
			)
			.unwrap()
			.unwrap()
			.get_version(),
			&HttpVersion::Unknown,
		);

		assert_eq!(
			HttpHeaders::new(
				b"GET / HTTP/1.1\r\nCookie: abc=123;\r\nCookie: def=123;\r\n\r\n",
				&config,
				&mut matcher,
				&vec![],
				&mut 0,
				&mut vec![],
				&mut StaticHash::new(StaticHashConfig {
					max_entries: 100,
					key_len: 8,
					entry_len: 0,
					max_load_factor: 0.95,
					..Default::default()
				})?,
			)
			.unwrap()
			.unwrap()
			.get_cookies()[0],
			b"abc=123;"
		);

		assert_eq!(
			HttpHeaders::new(
				b"GET / HTTP/1.1\r\nCookie: abc=123;\r\nCookie: def=456;\r\n\r\n",
				&config,
				&mut matcher,
				&vec![],
				&mut 0,
				&mut vec![],
				&mut StaticHash::new(StaticHashConfig {
					max_entries: 100,
					key_len: 8,
					entry_len: 0,
					max_load_factor: 0.95,
					..Default::default()
				})?,
			)
			.unwrap()
			.unwrap()
			.get_cookies()[1],
			b"def=456;"
		);

		assert_eq!(
			HttpHeaders::new(
				b"GET / HTTP/1.1\r\nSec-WebSocket-Key: 1234\r\n\r\n",
				&config,
				&mut matcher,
				&vec![],
				&mut 0,
				&mut vec![],
				&mut StaticHash::new(StaticHashConfig {
					max_entries: 100,
					key_len: 8,
					entry_len: 0,
					max_load_factor: 0.95,
					..Default::default()
				})?,
			)
			.unwrap()
			.unwrap()
			.websocket_sec_key(),
			b"1234"
		);

		assert_eq!(
			HttpHeaders::new(
				b"GET / HTTP/1.1\r\nSec-WebSocket-Key: 1234\r\nUpgrade: Websocket\r\n\r\n",
				&config,
				&mut matcher,
				&vec![],
				&mut 0,
				&mut vec![],
				&mut StaticHash::new(StaticHashConfig {
					max_entries: 100,
					key_len: 8,
					entry_len: 0,
					max_load_factor: 0.95,
					..Default::default()
				})?,
			)
			.unwrap()
			.unwrap()
			.has_websocket_upgrade(),
			true
		);

		assert_eq!(
			HttpHeaders::new(
				b"GET / HTTP/1.1\r\nSec-WebSocket-Key: 1234\r\nUpgrade2: Websocket\r\n\r\n",
				&config,
				&mut matcher,
				&vec![],
				&mut 0,
				&mut vec![],
				&mut StaticHash::new(StaticHashConfig {
					max_entries: 100,
					key_len: 8,
					entry_len: 0,
					max_load_factor: 0.95,
					..Default::default()
				})?,
			)
			.unwrap()
			.unwrap()
			.has_websocket_upgrade(),
			false
		);

		assert_eq!(
			HttpHeaders::new(
				b"GET / HTTP/1.1\r\nSec-WebSocket-Key: 1234\r\nExpect: 100-continue\r\n\r\n",
				&config,
				&mut matcher,
				&vec![],
				&mut 0,
				&mut vec![],
				&mut StaticHash::new(StaticHashConfig {
					max_entries: 100,
					key_len: 8,
					entry_len: 0,
					max_load_factor: 0.95,
					..Default::default()
				})?,
			)
			.unwrap()
			.unwrap()
			.has_expect(),
			true
		);

		assert_eq!(
			HttpHeaders::new(
				b"GET / HTTP/1.1\r\nSec-WebSocket-Key: 1234\r\nExpect: 200-continue\r\n\r\n",
				&config,
				&mut matcher,
				&vec![],
				&mut 0,
				&mut vec![],
				&mut StaticHash::new(StaticHashConfig {
					max_entries: 100,
					key_len: 8,
					entry_len: 0,
					max_load_factor: 0.95,
					..Default::default()
				})?,
			)
			.unwrap()
			.unwrap()
			.has_expect(),
			false
		);

		assert_eq!(
			HttpHeaders::new(
				b"GET / HTTP/1.1\r\nReferer: http://www.example.com/abc\r\n\r\n",
				&config,
				&mut matcher,
				&vec![],
				&mut 0,
				&mut vec![],
				&mut StaticHash::new(StaticHashConfig {
					max_entries: 100,
					key_len: 8,
					entry_len: 0,
					max_load_factor: 0.95,
					..Default::default()
				})?,
			)
			.unwrap()
			.unwrap()
			.get_referer(),
			b"http://www.example.com/abc",
		);

		assert_eq!(
			HttpHeaders::new(
				b"GET / HTTP/1.1\r\nUser-Agent: myagent1.0\r\n\r\n",
				&config,
				&mut matcher,
				&vec![],
				&mut 0,
				&mut vec![],
				&mut StaticHash::new(StaticHashConfig {
					max_entries: 100,
					key_len: 8,
					entry_len: 0,
					max_load_factor: 0.95,
					..Default::default()
				})?,
			)
			.unwrap()
			.unwrap()
			.get_user_agent(),
			b"myagent1.0",
		);

		assert_eq!(
			HttpHeaders::new(
				b"GET / HTTP/1.1\r\nAccept-Encoding: deflate, gzip\r\n\r\n",
				&config,
				&mut matcher,
				&vec![],
				&mut 0,
				&mut vec![],
				&mut StaticHash::new(StaticHashConfig {
					max_entries: 100,
					key_len: 8,
					entry_len: 0,
					max_load_factor: 0.95,
					..Default::default()
				})?,
			)
			.unwrap()
			.unwrap()
			.accept_gzip(),
			true,
		);

		assert_eq!(
			HttpHeaders::new(
				b"GET / HTTP/1.1\r\nAccept-Encoding: gzip\r\n\r\n",
				&config,
				&mut matcher,
				&vec![],
				&mut 0,
				&mut vec![],
				&mut StaticHash::new(StaticHashConfig {
					max_entries: 100,
					key_len: 8,
					entry_len: 0,
					max_load_factor: 0.95,
					..Default::default()
				})?,
			)
			.unwrap()
			.unwrap()
			.accept_gzip(),
			true,
		);

		assert_eq!(
			HttpHeaders::new(
				b"GET / HTTP/1.1\r\nAccept-Encoding: deflate\r\n\r\n",
				&config,
				&mut matcher,
				&vec![],
				&mut 0,
				&mut vec![],
				&mut StaticHash::new(StaticHashConfig {
					max_entries: 100,
					key_len: 8,
					entry_len: 0,
					max_load_factor: 0.95,
					..Default::default()
				})?,
			)
			.unwrap()
			.unwrap()
			.accept_gzip(),
			false,
		);

		//is_close

		assert_eq!(
			HttpHeaders::new(
				b"GET / HTTP/1.1\r\nConnection: close\r\n\r\n",
				&config,
				&mut matcher,
				&vec![],
				&mut 0,
				&mut vec![],
				&mut StaticHash::new(StaticHashConfig {
					max_entries: 100,
					key_len: 8,
					entry_len: 0,
					max_load_factor: 0.95,
					..Default::default()
				})?,
			)
			.unwrap()
			.unwrap()
			.is_close(),
			true,
		);

		assert_eq!(
			HttpHeaders::new(
				b"GET / HTTP/1.1\r\nConnection: keep-alive\r\n\r\n",
				&config,
				&mut matcher,
				&vec![],
				&mut 0,
				&mut vec![],
				&mut StaticHash::new(StaticHashConfig {
					max_entries: 100,
					key_len: 8,
					entry_len: 0,
					max_load_factor: 0.95,
					..Default::default()
				})?,
			)
			.unwrap()
			.unwrap()
			.is_close(),
			false,
		);

		assert_eq!(
			HttpHeaders::new(
				b"GET / HTTP/1.1\r\nHost: localhost\r\n\r\n",
				&config,
				&mut matcher,
				&vec![],
				&mut 0,
				&mut vec![],
				&mut StaticHash::new(StaticHashConfig {
					max_entries: 100,
					key_len: 8,
					entry_len: 0,
					max_load_factor: 0.95,
					..Default::default()
				})?,
			)
			.unwrap()
			.unwrap()
			.is_close(),
			false,
		);

		assert_eq!(
			HttpHeaders::new(
				b"GET / HTTP/1.1\r\nHost: localhost\r\nif-modified-since: 1234\r\n\r\n",
				&config,
				&mut matcher,
				&vec![],
				&mut 0,
				&mut vec![],
				&mut StaticHash::new(StaticHashConfig {
					max_entries: 100,
					key_len: 8,
					entry_len: 0,
					max_load_factor: 0.95,
					..Default::default()
				})?,
			)
			.unwrap()
			.unwrap()
			.if_modified_since(),
			b"1234",
		);

		assert_eq!(
			HttpHeaders::new(
				b"GET / HTTP/1.1\r\nHost: localhost\r\nabc: 1234\r\n\r\n",
				&config,
				&mut matcher,
				&vec![],
				&mut 0,
				&mut vec![],
				&mut StaticHash::new(StaticHashConfig {
					max_entries: 100,
					key_len: 8,
					entry_len: 0,
					max_load_factor: 0.95,
					..Default::default()
				})?,
			)
			.unwrap()
			.unwrap()
			.if_modified_since(),
			b"",
		);

		assert_eq!(
			HttpHeaders::new(
				b"GET / HTTP/1.1\r\nHost: localhost\r\nif-none-match: 5678\r\n\r\n",
				&config,
				&mut matcher,
				&vec![],
				&mut 0,
				&mut vec![],
				&mut StaticHash::new(StaticHashConfig {
					max_entries: 100,
					key_len: 8,
					entry_len: 0,
					max_load_factor: 0.95,
					..Default::default()
				})?,
			)
			.unwrap()
			.unwrap()
			.if_none_match(),
			b"5678",
		);

		assert_eq!(
			HttpHeaders::new(
				b"GET / HTTP/1.1\r\nHost: localhost\r\nabc: 1234\r\n\r\n",
				&config,
				&mut matcher,
				&vec![],
				&mut 0,
				&mut vec![],
				&mut StaticHash::new(StaticHashConfig {
					max_entries: 100,
					key_len: 8,
					entry_len: 0,
					max_load_factor: 0.95,
					..Default::default()
				})?,
			)
			.unwrap()
			.unwrap()
			.if_none_match(),
			b"",
		);

		assert_eq!(
			HttpHeaders::new(
				b"GET / HTTP/1.0\r\n\r\n",
				&config,
				&mut matcher,
				&vec![],
				&mut 0,
				&mut vec![],
				&mut StaticHash::new(StaticHashConfig {
					max_entries: 100,
					key_len: 8,
					entry_len: 0,
					max_load_factor: 0.95,
					..Default::default()
				})?,
			)
			.unwrap()
			.unwrap()
			.len(),
			18,
		);

		assert_eq!(
			HttpHeaders::new(
				b"POST / HTTP/1.1\r\nContent-Length: 10\r\n\r\n012345\r\n\r\n",
				&config,
				&mut matcher,
				&vec![],
				&mut 0,
				&mut vec![],
				&mut StaticHash::new(StaticHashConfig {
					max_entries: 100,
					key_len: 8,
					entry_len: 0,
					max_load_factor: 0.95,
					..Default::default()
				})?,
			)
			.unwrap()
			.unwrap()
			.len(),
			39,
		);

		assert_eq!(
			HttpHeaders::new(
				b"GET / HTTP/1.1\r\nA: 1\r\nB: 2\r\nB: 3\r\nC: 4\r\n\r\n",
				&config,
				&mut matcher,
				&vec![],
				&mut 0,
				&mut vec![],
				&mut StaticHash::new(StaticHashConfig {
					max_entries: 100,
					key_len: 8,
					entry_len: 0,
					max_load_factor: 0.95,
					..Default::default()
				})?,
			)
			.unwrap()
			.unwrap()
			.get_header_value(&"A".to_string())
			.unwrap(),
			vec!["1".to_string()]
		);

		assert_eq!(
			HttpHeaders::new(
				b"GET / HTTP/1.1\r\nA: 1\r\nB: 2\r\nB: 3\r\nC: 4\r\n\r\n",
				&config,
				&mut matcher,
				&vec![],
				&mut 0,
				&mut vec![],
				&mut StaticHash::new(StaticHashConfig {
					max_entries: 100,
					key_len: 8,
					entry_len: 0,
					max_load_factor: 0.95,
					..Default::default()
				})?,
			)
			.unwrap()
			.unwrap()
			.get_header_value(&"a".to_string())
			.unwrap(),
			vec!["1".to_string()]
		);

		let mut left = HttpHeaders::new(
			b"GET / HTTP/1.1\r\nA: 1\r\nB: 2\r\nB: 3\r\nC: 4\r\n\r\n",
			&config,
			&mut matcher,
			&vec![],
			&mut 0,
			&mut vec![],
			&mut StaticHash::new(StaticHashConfig {
				max_entries: 100,
				key_len: 8,
				entry_len: 0,
				max_load_factor: 0.95,
				..Default::default()
			})?,
		)
		.unwrap()
		.unwrap()
		.get_header_value(&"B".to_string())
		.unwrap();
		left.sort();
		let mut right = vec!["2".to_string(), "3".to_string()];
		right.sort();

		assert_eq!(left, right);

		let c: Vec<String> = vec![];
		assert_eq!(
			HttpHeaders::new(
				b"GET / HTTP/1.1\r\nA: 1\r\nB: 2\r\nB: 3\r\nC: 4\r\n\r\n",
				&config,
				&mut matcher,
				&vec![],
				&mut 0,
				&mut vec![],
				&mut StaticHash::new(StaticHashConfig {
					max_entries: 100,
					key_len: 8,
					entry_len: 0,
					max_load_factor: 0.95,
					..Default::default()
				})?,
			)
			.unwrap()
			.unwrap()
			.get_header_value(&"D".to_string())
			.unwrap(),
			c,
		);

		Ok(())
	}
}
