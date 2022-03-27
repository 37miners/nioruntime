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

use nioruntime_deps::base58;
use nioruntime_deps::dirs;
use nioruntime_deps::lazy_static::lazy_static;
use nioruntime_deps::path_clean::clean as path_clean;
use nioruntime_deps::rand;
use nioruntime_err::{Error, ErrorKind};
use nioruntime_evh::{ConnectionData, EventHandlerConfig};
use nioruntime_log::*;
use nioruntime_util::lockw;
use nioruntime_util::{bytes_eq, StaticHash, StaticHashConfig};
use std::collections::{HashMap, HashSet};
use std::convert::TryInto;
use std::fmt::{Display, Formatter};
use std::fs::{remove_file, File, OpenOptions};
use std::hash::Hasher;
use std::io::{Read, Seek, SeekFrom, Write};
use std::net::SocketAddr;
use std::path::PathBuf;
use std::str::FromStr;
use std::sync::mpsc::{sync_channel, Receiver, SyncSender};
use std::sync::{Arc, RwLock};
use std::time::{Instant, SystemTime, UNIX_EPOCH};

use std::os::unix::prelude::RawFd;

lazy_static! {
	pub static ref HTTP_PARTIAL_206_HEADERS_VEC: Vec<Vec<u8>> = vec![
		" 206 Partial Content\r\nServer: ".as_bytes().to_vec(),
		"\"\r\nContent-Range: bytes ".as_bytes().to_vec(),
		"-".as_bytes().to_vec(),
		"/".as_bytes().to_vec(),
		"\r\n\r\n".as_bytes().to_vec(),
	];
	pub static ref HTTP_OK_200_HEADERS_VEC: Vec<Vec<u8>> = vec![
		" 200 OK\r\nServer: ".as_bytes().to_vec(),
		"\r\nDate: ".as_bytes().to_vec(),
		"\r\nLast-Modified: ".as_bytes().to_vec(),
		"\r\nConnection: ".as_bytes().to_vec(),
		"\r\nContent-Length: ".as_bytes().to_vec(),
		"\r\nETag: \"".as_bytes().to_vec(),
		"\"\r\nAccept-Ranges: bytes\r\n\r\n".as_bytes().to_vec(),
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

pub const VERSION: &'static str = env!("CARGO_PKG_VERSION");

pub const END_HEADERS: &[u8] = "\r\n\r\n".as_bytes();
pub const CONTENT_LENGTH: &[u8] = "\r\nContent-Length: ".as_bytes();
pub const CONNECTION_CLOSE: &[u8] = "\r\nConnection: close\r\n".as_bytes();
pub const TRANSFER_ENCODING_CHUNKED: &[u8] = "\r\nTransfer-Encoding: chunked\r\n".as_bytes();

pub const RANGE_BYTES: &[u8] = "Range".as_bytes();
pub const CONTENT_TYPE_BYTES: &[u8] = "\r\nContent-Type: ".as_bytes();
pub const BACK_R: &[u8] = "\r".as_bytes();

pub const GET_BYTES: &[u8] = "GET ".as_bytes();
pub const POST_BYTES: &[u8] = "POST ".as_bytes();
pub const HEAD_BYTES: &[u8] = "HEAD ".as_bytes();
pub const DELETE_BYTES: &[u8] = "DELETE ".as_bytes();
pub const PUT_BYTES: &[u8] = "PUT ".as_bytes();
pub const OPTIONS_BYTES: &[u8] = "OPTIONS ".as_bytes();
pub const CONNECT_BYTES: &[u8] = "CONNECT ".as_bytes();
pub const PATCH_BYTES: &[u8] = "PATCH ".as_bytes();
pub const TRACE_BYTES: &[u8] = "TRACE ".as_bytes();

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

pub const HTTP10_BYTES: &[u8] = "HTTP/1.0".as_bytes();
pub const HTTP11_BYTES: &[u8] = "HTTP/1.1".as_bytes();
pub const HTTP20_BYTES: &[u8] = "HTTP/2.0".as_bytes();

pub const KEEP_ALIVE_BYTES: &[u8] = "keep-alive".as_bytes();
pub const CLOSE_BYTES: &[u8] = "close".as_bytes();

pub const _SIMPLE: &[u8] = b"HTTP/1.1 200 Ok\r\n\
Server: nioruntime httpd/0.0.3-beta.1\r\n\
Date: Wed, 09 Mar 2022 22:03:11 GMT\r\n\
Content-Type: text/html\r\n\
Last-Modified: Fri, 30 Jul 2021 06:40:15 GMT\r\n\
Content-Length: 7\r\n\
Connection: keep-alive\r\n\
\r\n\
Hello\r\n";

pub const HTTP_ERROR_400: &[u8] = b"HTTP/1.1 400 Bad request\r\n\
Server: nioruntime httpd/0.0.3-beta.1\r\n\
Date: Wed, 09 Mar 2022 22:03:11 GMT\r\n\
Content-Type: text/html\r\n\
Last-Modified: Fri, 30 Jul 2021 06:40:15 GMT\r\n\
Connection: close\r\n\
\r\n";

pub const HTTP_ERROR_403: &[u8] = b"HTTP/1.1 403 Forbidden\r\n\
Server: nioruntime httpd/0.0.3-beta.1\r\n\
Date: Wed, 09 Mar 2022 22:03:11 GMT\r\n\
Content-Type: text/html\r\n\
Content-Length: 12\r\n\
Last-Modified: Fri, 30 Jul 2021 06:40:15 GMT\r\n\
Connection: close\r\n\
\r\n\
Forbidden.\r\n";

pub const HTTP_ERROR_404: &[u8] = b"HTTP/1.1 404 Not found\r\n\
Server: nioruntime httpd/0.0.3-beta.1\r\n\
Date: Wed, 09 Mar 2022 22:03:11 GMT\r\n\
Content-Type: text/html\r\n\
Content-Length: 12\r\n\
Last-Modified: Fri, 30 Jul 2021 06:40:15 GMT\r\n\
Connection: close\r\n\
\r\n\
Not found.\r\n";

pub const HTTP_ERROR_405: &[u8] = b"HTTP/1.1 405 Method not supported\r\n\
Server: nioruntime httpd/0.0.3-beta.1\r\n\
Date: Wed, 09 Mar 2022 22:03:11 GMT\r\n\
Content-Type: text/html\r\n\
Last-Modified: Fri, 30 Jul 2021 06:40:15 GMT\r\n\
Connection: close\r\n\
\r\n\
Method Not supported.\r\n";

pub const HTTP_ERROR_431: &[u8] = b"HTTP/1.1 431 Request Header Fields Too Large\r\n\
Server: nioruntime httpd/0.0.3-beta.1\r\n\
Date: Wed, 09 Mar 2022 22:03:11 GMT\r\n\
Content-Type: text/html\r\n\
Last-Modified: Fri, 30 Jul 2021 06:40:15 GMT\r\n\
Connection: close\r\n\
\r\n\
Request Header Fields Too Large.\r\n";

pub const HTTP_ERROR_502: &[u8] = b"HTTP/1.1 502 Bad Gateway\r\n\
Server: nioruntime httpd/0.0.3-beta.1\r\n\
Date: Wed, 09 Mar 2022 22:03:11 GMT\r\n\
Content-Type: text/html\r\n\
Content-Length: 14\r\n\
Last-Modified: Fri, 30 Jul 2021 06:40:15 GMT\r\n\
Connection: close\r\n\
\r\n\
Bad Gateway.\r\n";

pub const HTTP_ERROR_503: &[u8] = b"HTTP/1.1 503 Service Unavailable\r\n\
Server: nioruntime httpd/0.0.3-beta.1\r\n\
Date: Wed, 09 Mar 2022 22:03:11 GMT\r\n\
Content-Type: text/html\r\n\
Content-Length: 22\r\n\
Last-Modified: Fri, 30 Jul 2021 06:40:15 GMT\r\n\
Connection: close\r\n\
\r\n\
Service Unavailable.\r\n";

pub const HTTP_ERROR_500: &[u8] = b"HTTP/1.1 Internal Server Error\r\n\
Server: nioruntime httpd/0.0.3-beta.1\r\n\
Date: Wed, 09 Mar 2022 22:03:11 GMT\r\n\
Content-Type: text/html\r\n\
Last-Modified: Fri, 30 Jul 2021 06:40:15 GMT\r\n\
Connection: close\r\n\
\r\n\
Internal Server Error.\r\n";

#[cfg(unix)]
pub type Handle = RawFd;
#[cfg(windows)]
pub type Handle = u64;
debug!();

#[derive(Debug, Clone, PartialEq)]
pub enum ListenerType {
	Tls,
	Plain,
}

pub struct ConnectionInfo {
	pub last_data: u128,
	pub connection: u128,
	pub conn_data: ConnectionData,
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
			conn_data,
		}
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

pub struct ThreadContext {
	pub header_map: StaticHash<(), ()>,
	pub cache_hits: StaticHash<(), ()>,
	pub key_buf: Vec<u8>,
	pub value_buf: Vec<u8>,
	pub instant: Instant,
	pub mime_map: HashMap<Vec<u8>, Vec<u8>>,
	pub async_connections: Arc<RwLock<HashSet<u128>>>,
	pub active_connections: HashMap<u128, ConnectionInfo>,
	pub proxy_connections: HashMap<u128, ProxyInfo>,
	pub idle_proxy_connections: HashMap<ProxyEntry, HashMap<SocketAddr, HashSet<ProxyInfo>>>,
	pub post_await_connections: HashMap<u128, ApiContext>,
	pub proxy_state: HashMap<ProxyEntry, ProxyState>,
	pub health_check_connections: HashMap<u128, (ProxyEntry, SocketAddr)>,
	pub webroot: Vec<u8>,
}

impl ThreadContext {
	pub fn new(config: &HttpConfig) -> Result<Self, Error> {
		let header_map_conf = StaticHashConfig {
			key_len: config.max_header_name_len,
			entry_len: config.max_header_value_len,
			max_entries: config.max_header_entries + 1,
			max_load_factor: 1.0,
			..Default::default()
		};

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

		let health_check_connections = HashMap::new();

		let webroot = std::str::from_utf8(&config.webroot).unwrap().to_string();
		let home_dir = match dirs::home_dir() {
			Some(p) => p,
			None => PathBuf::new(),
		}
		.as_path()
		.display()
		.to_string();

		let webroot = webroot.replace("~", &home_dir);
		let webroot = path_clean(&webroot).as_bytes().to_vec();

		Ok(Self {
			header_map: StaticHash::new(header_map_conf)?,
			cache_hits: StaticHash::new(cache_hits_conf)?,
			key_buf,
			value_buf,
			instant: Instant::now(),
			mime_map: HashMap::new(),
			async_connections: Arc::new(RwLock::new(HashSet::new())),
			active_connections: HashMap::new(),
			proxy_connections: HashMap::new(),
			post_await_connections: HashMap::new(),
			idle_proxy_connections,
			proxy_state,
			health_check_connections,
			webroot,
		})
	}
}

#[derive(Clone, Debug, PartialEq)]
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

#[derive(PartialEq, Debug, Clone)]
pub enum HttpVersion {
	V10,
	V11,
	V20,
	Unknown,
}

#[derive(Debug)]
pub struct HttpHeaders<'a> {
	method: HttpMethod,
	version: HttpVersion,
	uri: &'a [u8],
	query: &'a [u8],
	extension: &'a [u8],
	header_map: &'a StaticHash<(), ()>,
	len: usize,
	range: bool,
}

impl<'a> Display for HttpHeaders<'a> {
	fn fmt(&self, f: &mut Formatter) -> std::fmt::Result {
		write!(f, "method:  '{:?}'\n", self.get_method())?;
		write!(f, "version: '{:?}'\n", self.get_version())?;
		write!(
			f,
			"uri:     '{}'\n",
			std::str::from_utf8(self.get_uri()).unwrap_or("[non-utf8-string]")
		)?;
		write!(
			f,
			"query:   '{}'\n",
			std::str::from_utf8(self.get_query()).unwrap_or("[non-utf8-string]")
		)?;
		write!(f, "\nHTTP Headers:\n")?;
		for name in self.get_header_names().map_err(|_e| std::fmt::Error)? {
			let values = self.get_header_value(&name).map_err(|_e| std::fmt::Error)?;
			match values {
				Some(values) => {
					for value in values {
						let mut spacing = "".to_string();
						for _ in name.len()..20 {
							spacing = format!("{} ", spacing);
						}
						write!(f, "{}:{} '{}'\n", name, spacing, value)?;
					}
				}
				None => {}
			}
		}
		Ok(())
	}
}

impl<'a> HttpHeaders<'a> {
	pub fn new(
		buffer: &'a [u8],
		config: &HttpConfig,
		header_map: &'a mut StaticHash<(), ()>,
		key_buf: &'a mut Vec<u8>,
		value_buf: &'a mut Vec<u8>,
	) -> Result<Option<Self>, Error> {
		let (method, offset) = match Self::parse_method(buffer, config)? {
			Some((method, offset)) => (method, offset),
			None => return Ok(None),
		};
		trace!("method={:?},offset={}", method, offset)?;
		let (uri, extension, offset) = match Self::parse_uri(&buffer[offset..], config)? {
			Some((uri, extension, noffset)) => (uri, extension, noffset + offset),
			None => return Ok(None),
		};
		trace!("uri={:?},offset={}", uri, offset)?;
		let (query, offset) = match Self::parse_query(&buffer[offset..], config)? {
			Some((query, noffset)) => (query, noffset + offset),
			None => return Ok(None),
		};
		trace!("query={:?}", query)?;
		let (version, offset) = match Self::parse_version(&buffer[offset..], config)? {
			Some((version, noffset)) => (version, noffset + offset),
			None => return Ok(None),
		};
		trace!("version={:?}", version)?;

		if offset + 2 >= buffer.len() {
			return Ok(None);
		}

		let (len, range) = match Self::parse_headers(
			&buffer[(offset + 2)..],
			config,
			header_map,
			key_buf,
			value_buf,
		)? {
			Some((noffset, range)) => (noffset + offset + 2, range),
			None => return Ok(None),
		};

		if len > config.max_header_size {
			return Err(ErrorKind::HttpError431("Request Header Fields Too Large".into()).into());
		}

		Ok(Some(Self {
			method,
			version,
			uri,
			query,
			extension,
			header_map,
			len,
			range,
		}))
	}

	pub fn content_len(&self) -> Result<usize, Error> {
		match self.get_header_value(&"Content-Length".to_string())? {
			Some(clen) => {
				if clen.len() >= 1 {
					Ok(clen[0].parse()?)
				} else {
					Ok(0)
				}
			}
			None => Ok(0),
		}
	}

	pub fn extension(&self) -> &[u8] {
		self.extension
	}

	pub fn has_range(&self) -> bool {
		self.range
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

	pub fn get_header_value(&self, name: &String) -> Result<Option<Vec<String>>, Error> {
		let mut name_bytes = name.as_bytes().to_vec();
		let key_len = self.header_map.config().key_len;
		for _ in name_bytes.len()..key_len {
			name_bytes.push(0);
		}
		match self.header_map.get_raw(&name_bytes) {
			Some(value) => {
				let mut ret = vec![];
				let mut offset = 0;
				loop {
					if offset + 4 >= value.len() {
						break;
					}
					let len = u32::from_be_bytes(value[offset..offset + 4].try_into()?) as usize;
					if len == 0 {
						break;
					}
					ret.push(
						std::str::from_utf8(&value[offset + 4..offset + 4 + len])?.to_string(),
					);
					offset += 4 + len;
				}

				Ok(Some(ret))
			}
			None => Ok(None),
		}
	}

	pub fn get_header_names(&self) -> Result<Vec<String>, Error> {
		let mut ret = vec![];
		for (header, _) in self.header_map.iter_raw() {
			let len = header.len();
			let mut header_ret = vec![];
			for i in 0..len {
				if header[i] == 0 {
					break;
				}
				header_ret.push(header[i]);
			}
			ret.push(std::str::from_utf8(&header_ret)?.to_string());
		}
		Ok(ret)
	}

	fn parse_method(
		buffer: &[u8],
		_config: &HttpConfig,
	) -> Result<Option<(HttpMethod, usize)>, Error> {
		if buffer.len() < POST_BYTES.len() {
			Ok(None)
		} else if bytes_eq(&buffer[0..4], GET_BYTES) {
			Ok(Some((HttpMethod::Get, 4)))
		} else if bytes_eq(&buffer[0..5], POST_BYTES) {
			Ok(Some((HttpMethod::Post, 5)))
		} else if bytes_eq(&buffer[0..5], HEAD_BYTES) {
			Ok(Some((HttpMethod::Head, 5)))
		} else if bytes_eq(&buffer[0..4], PUT_BYTES) {
			Ok(Some((HttpMethod::Put, 4)))
		} else {
			if buffer.len() < OPTIONS_BYTES.len() {
				Ok(None)
			} else if bytes_eq(&buffer[0..8], OPTIONS_BYTES) {
				Ok(Some((HttpMethod::Options, 8)))
			} else if bytes_eq(&buffer[0..8], CONNECT_BYTES) {
				Ok(Some((HttpMethod::Connect, 8)))
			} else if bytes_eq(&buffer[0..7], DELETE_BYTES) {
				Ok(Some((HttpMethod::Delete, 7)))
			} else if bytes_eq(&buffer[0..6], PATCH_BYTES) {
				Ok(Some((HttpMethod::Patch, 6)))
			} else if bytes_eq(&buffer[0..6], TRACE_BYTES) {
				Ok(Some((HttpMethod::Trace, 6)))
			} else {
				Err(ErrorKind::HttpError405("Method not supported".into()).into())
			}
		}
	}

	fn parse_version(
		buffer: &[u8],
		config: &HttpConfig,
	) -> Result<Option<(HttpVersion, usize)>, Error> {
		let buffer_len = buffer.len();
		let http_bytes_len = HTTP10_BYTES.len();
		if buffer_len < http_bytes_len {
			Ok(None)
		} else if bytes_eq(&buffer[0..http_bytes_len], HTTP10_BYTES) {
			Ok(Some((HttpVersion::V10, http_bytes_len)))
		} else if bytes_eq(&buffer[0..http_bytes_len], HTTP11_BYTES) {
			Ok(Some((HttpVersion::V11, http_bytes_len)))
		} else if bytes_eq(&buffer[0..http_bytes_len], HTTP20_BYTES) {
			Ok(Some((HttpVersion::V20, http_bytes_len)))
		} else {
			let mut offset = 0;
			for i in 0..buffer_len {
				if i > config.max_header_size {
					return Err(
						ErrorKind::HttpError431("Request Header Fields Too Large".into()).into(),
					);
				}
				if buffer[i] == '\r' as u8 {
					offset = i;
					break;
				}
			}
			Ok(Some((HttpVersion::Unknown, offset)))
		}
	}

	fn parse_uri(
		buffer: &'a [u8],
		config: &HttpConfig,
	) -> Result<Option<(&'a [u8], &'a [u8], usize)>, Error> {
		let buffer_len = buffer.len();
		let mut i = 0;
		let mut x = 0;
		let mut qpresent = false;
		loop {
			if i > config.max_header_size {
				return Err(
					ErrorKind::HttpError431("Request Header Fields Too Large".into()).into(),
				);
			}
			if i >= buffer_len {
				return Ok(None);
			}
			if buffer[i] == '.' as u8 {
				x = i;
			}
			if buffer[i] == '?' as u8
				|| buffer[i] == ' ' as u8
				|| buffer[i] == '\r' as u8
				|| buffer[i] == '\n' as u8
			{
				if buffer[i] == '?' as u8 {
					qpresent = true;
				}
				break;
			}
			i += 1;
		}

		if i == 0 || i + 1 >= buffer_len {
			Ok(None)
		} else {
			if x != 0 {
				x += 1;
			}
			Ok(Some((
				&buffer[0..i],
				&buffer[x..i],
				if qpresent { i + 1 } else { i },
			)))
		}
	}

	fn parse_query(
		buffer: &'a [u8],
		config: &HttpConfig,
	) -> Result<Option<(&'a [u8], usize)>, Error> {
		let buffer_len = buffer.len();
		let mut i = 0;
		loop {
			if i > config.max_header_size {
				return Err(
					ErrorKind::HttpError431("Request Header Fields Too Large".into()).into(),
				);
			}
			if i >= buffer_len {
				return Ok(None);
			}
			if buffer[i] == ' ' as u8 || buffer[i] == '\r' as u8 || buffer[i] == '\n' as u8 {
				break;
			}
			i += 1;
		}

		if i + 1 >= buffer_len {
			Ok(None)
		} else {
			Ok(Some((
				&buffer[0..i],
				match buffer[i] {
					13 => i,
					_ => i + 1,
				},
			)))
		}
	}

	fn parse_headers(
		buffer: &[u8],
		config: &HttpConfig,
		header_map: &mut StaticHash<(), ()>,
		key_buf: &mut Vec<u8>,
		value_buf: &mut Vec<u8>,
	) -> Result<Option<(usize, bool)>, Error> {
		let mut i = 0;
		let buffer_len = buffer.len();
		let mut proc_key = true;
		let mut key_offset = 0;
		let mut value_offset = 4;
		let mut range = false;

		loop {
			if i > config.max_header_size {
				return Err(
					ErrorKind::HttpError431("Request Header Fields Too Large".into()).into(),
				);
			}
			if i >= buffer_len {
				break;
			}

			if proc_key && buffer[i] != ':' as u8 {
				if buffer[i] == '\r' as u8 || buffer[i] == '\n' as u8 {
					if i == 0 {
						// there is a valid no header case
						if buffer_len < 2 {
							return Ok(None);
						}

						if buffer[0] == '\r' as u8 && buffer[1] == '\n' as u8 {
							// no headers
							return Ok(Some((i + 2, range)));
						}
					}
					return Err(ErrorKind::HttpError400("Bad request: 1".into()).into());
				}

				if key_offset >= key_buf.len() {
					return Err(
						ErrorKind::HttpError431("Request Header Fields Too Large".into()).into(),
					);
				}

				key_buf[key_offset] = buffer[i];
				key_offset += 1;
			} else if proc_key {
				i += 1; // skip over the empty space
				proc_key = false;
			} else if buffer[i] != '\r' as u8 && buffer[i] != '\n' as u8 {
				if value_offset >= value_buf.len() {
					return Err(
						ErrorKind::HttpError431("Request Header Fields Too Large".into()).into(),
					);
				}
				value_buf[value_offset] = buffer[i];
				value_offset += 1;
			} else {
				value_buf[0..4]
					.clone_from_slice(&((value_offset.saturating_sub(4)) as u32).to_be_bytes());

				if bytes_eq(&key_buf[0..key_offset], RANGE_BYTES) {
					range = true;
				}
				match header_map.get_raw(&key_buf) {
					Some(value) => {
						if value.len() + 4 + value_offset > config.max_header_value_len {
							return Err(ErrorKind::HttpError431(
								"Request Header Fields Too Large".into(),
							)
							.into());
						}
						value_buf.extend_from_slice(&(value.len() as u32).to_be_bytes());
						value_buf.extend_from_slice(value);
						header_map
							.insert_raw(&key_buf, &value_buf[0..config.max_header_value_len])?;
						value_buf.resize(config.max_header_value_len, 0u8);
					}
					None => {
						header_map.insert_raw(&key_buf, &value_buf)?;
					}
				}

				for j in 0..key_offset {
					key_buf[j] = 0;
				}
				for j in 0..value_offset {
					value_buf[j] = 0;
				}

				i += 1;
				proc_key = true;
				key_offset = 0;
				value_offset = 4;

				if i + 2 < buffer_len && buffer[i + 1] == '\r' as u8 && buffer[i + 2] == '\n' as u8
				{
					// end of headers
					return Ok(Some(((i + 3), range)));
				}
			}
			i += 1;
		}

		Ok(None)
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
	pub listeners: Vec<(ListenerType, SocketAddr)>,
	pub fullchain_map: HashMap<u16, String>,
	pub privkey_map: HashMap<u16, String>,
	pub listen_queue_size: usize,
	pub max_header_size: usize,
	pub max_header_entries: usize,
	pub max_header_name_len: usize,
	pub max_header_value_len: usize,
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
	pub mime_map: Vec<(String, String)>,
	pub proxy_config: ProxyConfig,
	pub show_headers: bool,
	pub debug: bool,
	pub mainlog: String,
	pub mainlog_max_age: u128,
	pub mainlog_max_size: u64,
	pub error_page: Vec<u8>,
	pub evh_config: EventHandlerConfig,
}

impl Default for HttpConfig {
	fn default() -> Self {
		Self {
			proxy_config: ProxyConfig::default(),
			listeners: vec![(
				ListenerType::Plain,
				SocketAddr::from_str("127.0.0.1:8080").unwrap(),
			)],
			fullchain_map: HashMap::new(),
			privkey_map: HashMap::new(),
			listen_queue_size: 1000,
			max_header_size: 16 * 1024,
			max_header_name_len: 128,
			max_header_value_len: 1024,
			max_header_entries: 1_000,
			webroot: "~/.niohttpd/www".to_string().as_bytes().to_vec(),
			mainlog: "~/.niohttpd/logs/mainlog.log".to_string(),
			mainlog_max_age: 6 * 60 * 60 * 1000,
			mainlog_max_size: 1024 * 1024 * 1,
			max_cache_files: 1_000,
			max_cache_chunks: 100,
			max_bring_to_front: 1_000,
			cache_chunk_size: 1024 * 1024,
			max_load_factor: 0.9,
			server_name: format!("NIORuntime Httpd/{}", VERSION).as_bytes().to_vec(),
			process_cache_update: 1_000,    // 1 second
			cache_recheck_fs_millis: 3_000, // 3 seconds
			connect_timeout: 30_000,        // 30 seconds
			idle_timeout: 60_000,           // 1 minute
			show_headers: false,            // debug: show headers
			debug: false,                   // general debugging including log to stdout
			error_page: "/error.html".as_bytes().to_vec(),
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

#[derive(Clone)]
pub struct ApiContext {
	async_connections: Arc<RwLock<HashSet<u128>>>,
	conn_data: ConnectionData,
	temp_file: Option<String>,
	offset: usize,
	expected: usize,
	rem: usize,
	send: Arc<RwLock<Option<SyncSender<()>>>>,
}

impl ApiContext {
	pub fn new(async_connections: Arc<RwLock<HashSet<u128>>>, conn_data: ConnectionData) -> Self {
		Self {
			async_connections,
			conn_data,
			temp_file: None,
			offset: 0,
			expected: 0,
			rem: 0,
			send: Arc::new(RwLock::new(None)),
		}
	}

	pub fn set_async(&mut self) -> Result<(), Error> {
		let mut async_connections = lockw!(self.async_connections)?;
		async_connections.insert(self.conn_data.get_connection_id());
		Ok(())
	}

	pub fn async_complete(&mut self) -> Result<(), Error> {
		// remove the temp file, if it exists
		match &self.temp_file {
			Some(file) => match remove_file(file) {
				Ok(_) => {}
				Err(e) => {
					warn!("could not remove file: '{}' due to:  {}", file, e)?;
				}
			},
			None => {}
		}

		{
			let mut async_connections = lockw!(self.async_connections)?;
			async_connections.remove(&self.conn_data.get_connection_id());
		}
		self.conn_data.async_complete()?;
		Ok(())
	}

	pub fn remaining(&self) -> usize {
		self.expected.saturating_sub(self.offset)
	}

	pub fn pull_bytes(&mut self, buf: &mut [u8]) -> Result<usize, Error> {
		match &self.temp_file {
			Some(file) => {
				let recv = {
					let mut sender = lockw!(self.send)?;

					let metadata = match std::fs::metadata(file) {
						Ok(metadata) => metadata,
						Err(e) => {
							warn!("metadata returned: {}", e)?;
							return Err(ErrorKind::IOError(
								"could not read file metadata".to_string(),
							)
							.into());
						}
					};

					let metadata_len: usize = metadata.len().try_into()?;
					if metadata_len < self.expected {
						let send: SyncSender<()>;
						let recv: Receiver<()>;
						(send, recv) = sync_channel(1);
						*sender = Some(send);
						Some(recv)
					} else {
						None
					}
				};

				match recv {
					Some(receive) => {
						receive.recv()?;
					}
					_ => {}
				};

				let mut requested = self.expected.saturating_sub(self.offset);
				if requested > buf.len() {
					requested = buf.len();
				}

				let mut file = OpenOptions::new().read(true).open(file)?;
				file.seek(SeekFrom::Start(self.offset.try_into()?))?;
				file.read_exact(&mut buf[0..requested])?;
				self.offset += requested;
				Ok(requested)
			}
			None => Ok(0),
		}
	}

	pub fn set_expected(&mut self, expected: usize) -> Result<(), Error> {
		self.expected = expected;
		self.rem = expected;
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

		let file = match &self.temp_file {
			Some(file) => file.clone(),
			None => {
				let r: [u8; 16] = rand::random();
				let r: &[u8] = &r[0..16];
				let file = format!("/tmp/nioruntime.{}", base58::ToBase58::to_base58(r));
				self.temp_file = Some(file.clone());
				File::create(&file)?;
				file
			}
		};

		let send = self.send.clone();
		let buf: Vec<u8> = buf.to_vec();
		let rem = self.rem;

		std::thread::spawn(move || -> Result<(), Error> {
			let mut file = OpenOptions::new().write(true).append(true).open(file)?;
			file.write_all(&buf)?;
			if rem == 0 {
				let send = lockw!(send)?;
				match &*send {
					Some(send) => {
						send.send(()).map_err(|e| {
							let error: Error =
								ErrorKind::ApplicationError(format!("Send error: {}", e)).into();
							error
						})?;
					}
					None => {}
				};
			}

			Ok(())
		});

		Ok((self.rem, pushed))
	}
}
