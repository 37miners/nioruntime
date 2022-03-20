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
use nioruntime_deps::chrono::{DateTime, Datelike, NaiveDateTime, Timelike, Utc, Weekday};
use nioruntime_deps::dirs;
use nioruntime_deps::hex;
use nioruntime_deps::lazy_static::lazy_static;
use nioruntime_deps::libc;
use nioruntime_deps::libc::fcntl;
use nioruntime_deps::nix::sys::socket::AddressFamily::Inet;
use nioruntime_deps::nix::sys::socket::SockType::Stream;
use nioruntime_deps::nix::sys::socket::{
	bind, connect, listen, socket, AddressFamily, InetAddr, SockAddr, SockFlag,
};
use nioruntime_deps::path_clean::clean as path_clean;
use nioruntime_deps::rand;
use nioruntime_deps::sha2::{Digest, Sha256};
use nioruntime_err::{Error, ErrorKind};
use nioruntime_evh::{ConnectionContext, ConnectionData};
use nioruntime_evh::{EventHandler, EventHandlerConfig, EvhParams};
use nioruntime_log::*;
use nioruntime_util::{
	bytes_eq, bytes_find, bytes_parse_number_header, StaticHash, StaticHashConfig,
};
use nioruntime_util::{lockr, lockw};
use std::any::Any;
use std::collections::{HashMap, HashSet};
use std::convert::TryInto;
use std::fs::{metadata, File, Metadata};
use std::hash::Hasher;
use std::io::{Read, Write};
use std::mem;
use std::net::SocketAddr;
use std::net::TcpListener;
use std::os::unix::io::AsRawFd;
use std::os::unix::io::FromRawFd;
use std::path::PathBuf;
use std::pin::Pin;
use std::str::FromStr;
use std::sync::{Arc, RwLock};
use std::time::{Instant, SystemTime, UNIX_EPOCH};

use std::os::unix::prelude::RawFd;

lazy_static! {
	static ref HTTP_PARTIAL_206_HEADERS_VEC: Vec<Vec<u8>> = vec![
		" 206 Partial Content\r\nServer: ".as_bytes().to_vec(),
		"\"\r\nContent-Range: bytes ".as_bytes().to_vec(),
		"-".as_bytes().to_vec(),
		"/".as_bytes().to_vec(),
		"\r\n\r\n".as_bytes().to_vec(),
	];
	static ref HTTP_OK_200_HEADERS_VEC: Vec<Vec<u8>> = vec![
		" 200 OK\r\nServer: ".as_bytes().to_vec(),
		"\r\nDate: ".as_bytes().to_vec(),
		"\r\nLast-Modified: ".as_bytes().to_vec(),
		"\r\nConnection: ".as_bytes().to_vec(),
		"\r\nContent-Length: ".as_bytes().to_vec(),
		"\r\nETag: \"".as_bytes().to_vec(),
		"\"\r\nAccept-Ranges: bytes\r\n\r\n".as_bytes().to_vec(),
	];
}

const VERSION: &'static str = env!("CARGO_PKG_VERSION");

const END_HEADERS: &[u8] = "\r\n\r\n".as_bytes();
const CONTENT_LENGTH: &[u8] = "\r\nContent-Length: ".as_bytes();
const CONNECTION_CLOSE: &[u8] = "\r\nConnection: close\r\n".as_bytes();

const RANGE_BYTES: &[u8] = "Range".as_bytes();
const CONTENT_TYPE_BYTES: &[u8] = "\r\nContent-Type: ".as_bytes();

const GET_BYTES: &[u8] = "GET ".as_bytes();
const POST_BYTES: &[u8] = "POST ".as_bytes();
const HEAD_BYTES: &[u8] = "HEAD ".as_bytes();
const DELETE_BYTES: &[u8] = "DELETE ".as_bytes();
const PUT_BYTES: &[u8] = "PUT ".as_bytes();
const OPTIONS_BYTES: &[u8] = "OPTIONS ".as_bytes();
const CONNECT_BYTES: &[u8] = "CONNECT ".as_bytes();
const PATCH_BYTES: &[u8] = "PATCH ".as_bytes();
const TRACE_BYTES: &[u8] = "TRACE ".as_bytes();

const MON_BYTES: &[u8] = "Mon, ".as_bytes();
const TUE_BYTES: &[u8] = "Tue, ".as_bytes();
const WED_BYTES: &[u8] = "Wed, ".as_bytes();
const THU_BYTES: &[u8] = "Thu, ".as_bytes();
const FRI_BYTES: &[u8] = "Fri, ".as_bytes();
const SAT_BYTES: &[u8] = "Sat, ".as_bytes();
const SUN_BYTES: &[u8] = "Sun, ".as_bytes();

const JAN_BYTES: &[u8] = " Jan ".as_bytes();
const FEB_BYTES: &[u8] = " Feb ".as_bytes();
const MAR_BYTES: &[u8] = " Mar ".as_bytes();
const APR_BYTES: &[u8] = " Apr ".as_bytes();
const MAY_BYTES: &[u8] = " May ".as_bytes();
const JUN_BYTES: &[u8] = " Jun ".as_bytes();
const JUL_BYTES: &[u8] = " Jul ".as_bytes();
const AUG_BYTES: &[u8] = " Aug ".as_bytes();
const SEP_BYTES: &[u8] = " Sep ".as_bytes();
const OCT_BYTES: &[u8] = " Oct ".as_bytes();
const NOV_BYTES: &[u8] = " Nov ".as_bytes();
const DEC_BYTES: &[u8] = " Dec ".as_bytes();

const HTTP10_BYTES: &[u8] = "HTTP/1.0".as_bytes();
const HTTP11_BYTES: &[u8] = "HTTP/1.1".as_bytes();
const HTTP20_BYTES: &[u8] = "HTTP/2.0".as_bytes();

const KEEP_ALIVE_BYTES: &[u8] = "keep-alive".as_bytes();
const CLOSE_BYTES: &[u8] = "close".as_bytes();

warn!();

const _SIMPLE: &[u8] = b"HTTP/1.1 200 Ok\r\n\
Server: nioruntime httpd/0.0.3-beta.1\r\n\
Date: Wed, 09 Mar 2022 22:03:11 GMT\r\n\
Content-Type: text/html\r\n\
Last-Modified: Fri, 30 Jul 2021 06:40:15 GMT\r\n\
Content-Length: 7\r\n\
Connection: keep-alive\r\n\
\r\n\
Hello\r\n";

const HTTP_ERROR_400: &[u8] = b"HTTP/1.1 400 Bad request\r\n\
Server: nioruntime httpd/0.0.3-beta.1\r\n\
Date: Wed, 09 Mar 2022 22:03:11 GMT\r\n\
Content-Type: text/html\r\n\
Last-Modified: Fri, 30 Jul 2021 06:40:15 GMT\r\n\
Connection: close\r\n\
\r\n\
Bad request.\r\n";

const HTTP_ERROR_403: &[u8] = b"HTTP/1.1 403 Forbidden\r\n\
Server: nioruntime httpd/0.0.3-beta.1\r\n\
Date: Wed, 09 Mar 2022 22:03:11 GMT\r\n\
Content-Type: text/html\r\n\
Last-Modified: Fri, 30 Jul 2021 06:40:15 GMT\r\n\
Connection: close\r\n\
\r\n\
Forbidden.\r\n";

const HTTP_ERROR_404: &[u8] = b"HTTP/1.1 404 Not found\r\n\
Server: nioruntime httpd/0.0.3-beta.1\r\n\
Date: Wed, 09 Mar 2022 22:03:11 GMT\r\n\
Content-Type: text/html\r\n\
Content-Length: 12\r\n\
Last-Modified: Fri, 30 Jul 2021 06:40:15 GMT\r\n\
Connection: close\r\n\
\r\n\
Not found.\r\n";

const HTTP_ERROR_405: &[u8] = b"HTTP/1.1 405 Method not supported\r\n\
Server: nioruntime httpd/0.0.3-beta.1\r\n\
Date: Wed, 09 Mar 2022 22:03:11 GMT\r\n\
Content-Type: text/html\r\n\
Last-Modified: Fri, 30 Jul 2021 06:40:15 GMT\r\n\
Connection: close\r\n\
\r\n\
Method Not supported.\r\n";

const HTTP_ERROR_431: &[u8] = b"HTTP/1.1 431 Request Header Fields Too Large\r\n\
Server: nioruntime httpd/0.0.3-beta.1\r\n\
Date: Wed, 09 Mar 2022 22:03:11 GMT\r\n\
Content-Type: text/html\r\n\
Last-Modified: Fri, 30 Jul 2021 06:40:15 GMT\r\n\
Connection: close\r\n\
\r\n\
Request Header Fields Too Large.\r\n";

const HTTP_ERROR_502: &[u8] = b"HTTP/1.1 502 Bad Gateway\r\n\
Server: nioruntime httpd/0.0.3-beta.1\r\n\
Date: Wed, 09 Mar 2022 22:03:11 GMT\r\n\
Content-Type: text/html\r\n\
Content-Length: 14\r\n\
Last-Modified: Fri, 30 Jul 2021 06:40:15 GMT\r\n\
Connection: close\r\n\
\r\n\
Bad Gateway.\r\n";

const HTTP_ERROR_503: &[u8] = b"HTTP/1.1 503 Service Unavailable\r\n\
Server: nioruntime httpd/0.0.3-beta.1\r\n\
Date: Wed, 09 Mar 2022 22:03:11 GMT\r\n\
Content-Type: text/html\r\n\
Content-Length: 22\r\n\
Last-Modified: Fri, 30 Jul 2021 06:40:15 GMT\r\n\
Connection: close\r\n\
\r\n\
Service Unavailable.\r\n";

const HTTP_ERROR_500: &[u8] = b"HTTP/1.1 Internal Server Error\r\n\
Server: nioruntime httpd/0.0.3-beta.1\r\n\
Date: Wed, 09 Mar 2022 22:03:11 GMT\r\n\
Content-Type: text/html\r\n\
Last-Modified: Fri, 30 Jul 2021 06:40:15 GMT\r\n\
Connection: close\r\n\
\r\n\
Internal Server Error.\r\n";

#[cfg(unix)]
type Handle = RawFd;
#[cfg(windows)]
type Handle = u64;

struct ConnectionInfo {
	last_data: u128,
	connection: u128,
	conn_data: ConnectionData,
}

impl ConnectionInfo {
	fn new(conn_data: ConnectionData) -> Self {
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
struct ProxyInfo {
	handle: Handle,
	proxy_conn: ConnectionData,
	response_conn_data: Option<ConnectionData>,
	buffer: Vec<u8>,
	sock_addr: SocketAddr,
	proxy_entry: ProxyEntry,
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
		}
	}
}

pub struct ProxyState {
	pub cur_connections: usize,
}

impl ProxyState {
	fn new() -> Self {
		Self { cur_connections: 0 }
	}
}

struct ThreadContext {
	header_map: StaticHash<(), ()>,
	cache_hits: StaticHash<(), ()>,
	key_buf: Vec<u8>,
	value_buf: Vec<u8>,
	instant: Instant,
	mime_map: HashMap<Vec<u8>, Vec<u8>>,
	async_connections: Arc<RwLock<HashSet<u128>>>,
	active_connections: HashMap<u128, ConnectionInfo>,
	proxy_connections: HashMap<u128, ProxyInfo>,
	idle_proxy_connections: HashMap<ProxyEntry, HashSet<ProxyInfo>>,
	proxy_state: HashMap<ProxyEntry, ProxyState>,
}

impl ThreadContext {
	fn new(config: &HttpConfig) -> Result<Self, Error> {
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
		for (_k, v) in &config.proxy_config.mappings {
			proxy_state.insert(v.clone(), ProxyState::new());
		}
		for (_k, v) in &config.proxy_config.extensions {
			proxy_state.insert(v.clone(), ProxyState::new());
		}

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
			idle_proxy_connections: HashMap::new(),
			proxy_state,
		})
	}
}

#[derive(Debug)]
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

#[derive(Debug, Clone)]
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

impl<'a> HttpHeaders<'a> {
	fn new(
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

	pub fn get_header_value(&self, name: String) -> Result<Option<String>, Error> {
		let mut name_bytes = name.as_bytes().to_vec();
		let key_len = self.header_map.config().key_len;
		for _ in name_bytes.len()..key_len {
			name_bytes.push(0);
		}
		match self.header_map.get_raw(&name_bytes) {
			Some(value) => {
				let len = u32::from_be_bytes(value[0..4].try_into().unwrap()) as usize;
				Ok(Some(std::str::from_utf8(&value[4..4 + len])?.to_string()))
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
				header_map.insert_raw(&key_buf, &value_buf)?;

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
pub struct ProxyEntry {
	pub sock_addrs: Vec<SocketAddr>,
	pub max_connections_per_thread: usize,
	nonce: u128,
}

impl ProxyEntry {
	pub fn from_socket_addr(sock_addr: SocketAddr) -> Self {
		Self {
			sock_addrs: vec![sock_addr],
			max_connections_per_thread: usize::MAX,
			nonce: rand::random(),
		}
	}

	pub fn from_socket_addr_with_limit(
		sock_addr: SocketAddr,
		max_connections_per_thread: usize,
	) -> Self {
		Self {
			sock_addrs: vec![sock_addr],
			max_connections_per_thread,
			nonce: rand::random(),
		}
	}

	pub fn multi_socket_addr(
		sock_addrs: Vec<SocketAddr>,
		max_connections_per_thread: usize,
	) -> Self {
		Self {
			sock_addrs,
			max_connections_per_thread,
			nonce: rand::random(),
		}
	}
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
	pub addrs: Vec<SocketAddr>,
	pub threads: usize,
	pub listen_queue_size: usize,
	pub max_header_size: usize,
	pub max_header_entries: usize,
	pub max_header_name_len: usize,
	pub max_header_value_len: usize,
	pub root_dir: Vec<u8>,
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
}

impl Default for HttpConfig {
	fn default() -> Self {
		Self {
			proxy_config: ProxyConfig::default(),
			addrs: vec![SocketAddr::from_str("127.0.0.1:8080").unwrap()],
			threads: 8,
			listen_queue_size: 100,
			max_header_size: 16 * 1024,
			max_header_name_len: 128,
			max_header_value_len: 1024,
			max_header_entries: 1_000,
			root_dir: "~/.niohttpd".to_string().as_bytes().to_vec(),
			max_cache_files: 1_000,
			max_cache_chunks: 100,
			max_bring_to_front: 1_000,
			cache_chunk_size: 1024 * 1024,
			max_load_factor: 0.9,
			server_name: format!("nioruntime httpd/{}", VERSION).as_bytes().to_vec(),
			process_cache_update: 1_000,    // 1 second
			cache_recheck_fs_millis: 3_000, // 3 seconds
			connect_timeout: 30_000,        // 30 seconds
			idle_timeout: 60_000,           // 1 minute
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
}

impl ApiContext {
	pub fn set_async(&mut self) -> Result<(), Error> {
		let mut async_connections = lockw!(self.async_connections)?;
		async_connections.insert(self.conn_data.get_connection_id());
		Ok(())
	}

	pub fn async_complete(&mut self) -> Result<(), Error> {
		self.conn_data.async_complete()?;
		Ok(())
	}

	fn new(async_connections: Arc<RwLock<HashSet<u128>>>, conn_data: ConnectionData) -> Self {
		Self {
			async_connections,
			conn_data,
		}
	}
}

pub struct HttpServer<ApiHandler> {
	config: HttpConfig,
	_listeners: Vec<TcpListener>,
	api_config: Arc<RwLock<HttpApiConfig>>,
	api_handler: Option<Pin<Box<ApiHandler>>>,
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
	pub fn new(mut config: HttpConfig) -> Self {
		let home_dir = match dirs::home_dir() {
			Some(p) => p,
			None => PathBuf::new(),
		}
		.as_path()
		.display()
		.to_string();

		let mut root_dir = std::str::from_utf8(&config.root_dir).unwrap().to_string();

		root_dir = root_dir.replace("~", &home_dir);
		root_dir = path_clean(&root_dir);
		root_dir = format!("{}/www", root_dir);
		config.root_dir = root_dir.as_bytes().to_vec();

		Self {
			config,
			_listeners: vec![],
			api_config: Arc::new(RwLock::new(HttpApiConfig::default())),
			api_handler: None,
		}
	}

	pub fn start(&mut self) -> Result<(), Error> {
		let mut evh = EventHandler::new(EventHandlerConfig {
			threads: self.config.threads,
			..EventHandlerConfig::default()
		})?;

		let evh_params = evh.get_evh_params();

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

		let api_config = self.api_config.clone();
		let api_handler = self.api_handler.clone();

		evh.set_on_read(move |conn_data, buf, ctx, user_data| {
			Self::process_on_read(
				&conn_data,
				buf,
				ctx,
				&config1,
				&cache,
				&api_config,
				&api_handler,
				&evh_params,
				user_data,
			)
		})?;
		evh.set_on_accept(move |conn_data, ctx, user_data| {
			Self::process_on_accept(conn_data, ctx, &config2, user_data)
		})?;
		evh.set_on_close(move |conn_data, ctx, user_data| {
			Self::process_on_close(conn_data, ctx, &config3, user_data)
		})?;
		evh.set_on_panic(move || Ok(()))?;
		evh.set_on_housekeep(move |user_data| Self::process_on_housekeeper(&config4, user_data))?;

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

	pub fn set_api_handler(&mut self, handler: ApiHandler) -> Result<(), Error> {
		self.api_handler = Some(Box::pin(handler));
		Ok(())
	}

	pub fn set_api_config(&mut self, api_config: HttpApiConfig) -> Result<(), Error> {
		let mut self_config = lockw!(self.api_config)?;
		*self_config = api_config;
		Ok(())
	}

	fn init_user_data(
		user_data: &mut Box<dyn Any + Send + Sync>,
		config: &HttpConfig,
	) -> Result<(), Error> {
		match user_data.downcast_ref::<ThreadContext>() {
			Some(_value) => {}
			None => {
				let mut value = ThreadContext::new(config)?;

				for entry in &config.mime_map {
					let (k, v) = entry;
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
		match thread_context
			.active_connections
			.get_mut(&conn_data.get_connection_id())
		{
			Some(conn_info) => {
				conn_info.last_data = now.duration_since(UNIX_EPOCH)?.as_micros();
			}
			None => {
				error!(
					"No connection info found for connection {}",
					conn_data.get_connection_id(),
				)?;
			}
		}

		Ok(())
	}

	// whether complete or not and also whether Connection is set to 'close'.
	fn check_complete(buffer: &[u8]) -> (bool, bool) {
		match bytes_find(buffer, END_HEADERS) {
			Some(end) => {
				let clen = bytes_find(buffer, CONTENT_LENGTH);
				match clen {
					Some(clen) => {
						if clen < end {
							let len = bytes_parse_number_header(buffer, clen);
							match len {
								Some(len) => {
									let complete = len + end <= buffer.len();
									let close = if complete {
										bytes_find(buffer, CONNECTION_CLOSE).is_some()
									} else {
										false
									};
									(complete, close)
								}
								None => (false, false), // TODO: how do we handle this?
							}
						} else {
							// no content, just headers
							let complete = end <= buffer.len();
							let close = if complete {
								bytes_find(buffer, CONNECTION_CLOSE).is_some()
							} else {
								false
							};
							(complete, close)
						}
					}
					None => {
						// TODO: handle chunked encoding
						let complete = end <= buffer.len();
						let close = if complete {
							bytes_find(buffer, CONNECTION_CLOSE).is_some()
						} else {
							false
						};
						(complete, close)
					}
				}
			}
			None => (false, false),
		}
	}

	fn socket_connect(socket_addr: &SocketAddr) -> Result<Handle, Error> {
		// TODO: support windows
		let handle = socket(Inet, Stream, SockFlag::empty(), None)?;

		let inet_addr = InetAddr::from_std(socket_addr);
		let sock_addr = SockAddr::new_inet(inet_addr);
		match connect(handle, &sock_addr) {
			Ok(_) => {}
			Err(e) => {
				#[cfg(unix)]
				unsafe {
					libc::close(handle);
				}
				#[cfg(windows)]
				unsafe {
					ws2_32::closesocket(handle);
				}
				warn!("error connecting to {}: {}", sock_addr, e)?;
				return Err(ErrorKind::IOError(format!("connect generated error: {}", e)).into());
			}
		};

		unsafe { fcntl(handle, libc::F_SETFL, libc::O_NONBLOCK) };

		Ok(handle)
	}

	fn process_proxy_outbound(
		inbound: &ConnectionData,
		_headers: &HttpHeaders,
		//sock_addr: &SocketAddr,
		proxy_entry: &ProxyEntry,
		buffer: &[u8],
		evh_params: &EvhParams,
		proxy_connections: &mut HashMap<u128, ProxyInfo>,
		active_connections: &mut HashMap<u128, ConnectionInfo>,
		idle_proxy_connections: &mut HashMap<ProxyEntry, HashSet<ProxyInfo>>,
		proxy_state: &mut HashMap<ProxyEntry, ProxyState>,
	) -> Result<(), Error> {
		let proxy_info = match idle_proxy_connections.get_mut(proxy_entry) {
			Some(hashset) => match hashset.iter().next() {
				Some(proxy_info) => Some(proxy_info.clone()),
				None => None,
			},
			None => None,
		};

		let conn_data = match proxy_info {
			Some(proxy_info) => {
				match proxy_connections.get_mut(&proxy_info.proxy_conn.get_connection_id()) {
					Some(proxy_info) => {
						proxy_info.response_conn_data = Some(inbound.clone());
					}
					None => debug!("no proxy found")?,
				}

				match idle_proxy_connections.get_mut(proxy_entry) {
					Some(hashset) => {
						hashset.remove(&proxy_info);
					}
					None => {}
				}

				proxy_info.proxy_conn
			}
			None => {
				let state = proxy_state.get_mut(proxy_entry);
				let state = match state {
					Some(state) => {
						if state.cur_connections >= proxy_entry.max_connections_per_thread {
							inbound.write(HTTP_ERROR_503)?;
							return Ok(());
						}
						state
					}
					None => {
						return Err(ErrorKind::InternalError(format!(
							"no proxy state for sock_addr = {:?}",
							proxy_entry
						))
						.into());
					}
				};
				let tid = inbound.tid();
				// choose a random socket_addr
				let rand_entry: usize = rand::random();
				let sock_addr = proxy_entry.sock_addrs[rand_entry % proxy_entry.sock_addrs.len()];

				let (handle, conn_data) = match Self::connect_outbound(&sock_addr, tid, evh_params)
				{
					Ok((handle, conn_data)) => {
						state.cur_connections += 1;
						(handle, conn_data)
					}
					Err(e) => {
						return Err(ErrorKind::IOError(format!(
							"Error connecting to proxy: {}",
							e
						))
						.into());
					}
				};

				debug!(
					"proxy added handle = {}, conn_id = {}",
					handle,
					conn_data.get_connection_id()
				)?;

				proxy_connections.insert(
					conn_data.get_connection_id(),
					ProxyInfo {
						handle,
						response_conn_data: Some(inbound.clone()),
						buffer: vec![],
						sock_addr,
						proxy_conn: conn_data.clone(),
						proxy_entry: proxy_entry.clone(),
					},
				);

				active_connections.insert(
					conn_data.get_connection_id(),
					ConnectionInfo::new(conn_data.clone()),
				);

				conn_data
			}
		};

		conn_data.write(buffer)?;

		Ok(())
	}

	fn connect_outbound(
		sock_addr: &SocketAddr,
		tid: usize,
		evh_params: &EvhParams,
	) -> Result<(Handle, ConnectionData), Error> {
		let handle = Self::socket_connect(sock_addr)?;
		let conn_data = evh_params.add_handle(handle, None, Some(tid))?;
		Ok((handle, conn_data))
	}

	fn process_proxy_inbound(
		conn_data: &ConnectionData,
		nbuf: &[u8],
		proxy_connections: &mut HashMap<u128, ProxyInfo>,
		idle_proxy_connections: &mut HashMap<ProxyEntry, HashSet<ProxyInfo>>,
	) -> Result<(), Error> {
		let proxy_info = proxy_connections.get_mut(&conn_data.get_connection_id());
		match proxy_info {
			Some(proxy_info) => {
				let (is_complete, is_close) = if proxy_info.buffer.len() > 0 {
					proxy_info.buffer.extend_from_slice(nbuf);
					let (ret, close) = Self::check_complete(&proxy_info.buffer);
					if ret {
						proxy_info.buffer.clear();
					}
					(ret, close)
				} else {
					Self::check_complete(nbuf)
				};

				// we write whether we're done or not
				match &proxy_info.response_conn_data {
					Some(conn_data) => match conn_data.write(nbuf) {
						Ok(_) => {}
						Err(e) => {
							warn!("proxy request generated error: {}", e)?;
						}
					},
					None => {
						warn!("no proxy")?;
					}
				}
				if is_complete && !is_close {
					// put this connection into the idle pool
					proxy_info.response_conn_data = None;
					let added = match idle_proxy_connections.get_mut(&proxy_info.proxy_entry) {
						Some(conns) => {
							conns.insert(proxy_info.clone());
							true
						}
						None => false,
					};

					if !added {
						let mut nhashset = HashSet::new();
						nhashset.insert(proxy_info.clone());
						idle_proxy_connections.insert(proxy_info.proxy_entry.clone(), nhashset);
					}
				} else if !is_close {
					proxy_info.buffer.extend_from_slice(nbuf);
				}
			}
			None => {
				error!("no proxy information found for this connection")?;
			}
		}

		Ok(())
	}

	fn process_on_read(
		conn_data: &ConnectionData,
		nbuf: &[u8],
		ctx: &mut ConnectionContext,
		config: &HttpConfig,
		cache: &Arc<RwLock<HttpCache>>,
		api_config: &Arc<RwLock<HttpApiConfig>>,
		api_handler: &Option<Pin<Box<ApiHandler>>>,
		evh_params: &EvhParams,
		user_data: &mut Box<dyn Any + Send + Sync>,
	) -> Result<(), Error> {
		let now = SystemTime::now();
		Self::init_user_data(user_data, config)?;
		let thread_context = user_data.downcast_mut::<ThreadContext>().unwrap();
		Self::process_async(ctx, thread_context, conn_data)?;
		Self::update_conn_info(thread_context, conn_data, now)?;

		let buffer = ctx.get_buffer();
		let buffer_len = buffer.len();
		let connection_id = conn_data.get_connection_id();

		debug!(
			"on_read[{}] = '{:?}', acc_handle={:?}, buffer_len={}",
			connection_id,
			nbuf,
			conn_data.get_accept_handle(),
			buffer_len,
		)?;

		match thread_context.proxy_connections.get(&connection_id) {
			Some(_proxy_info) => {
				Self::process_proxy_inbound(
					conn_data,
					nbuf,
					&mut thread_context.proxy_connections,
					&mut thread_context.idle_proxy_connections,
				)?;
				return Ok(());
			}
			None => {}
		}

		let is_async = {
			let async_connections = lockr!(thread_context.async_connections)?;
			async_connections.get(&connection_id).is_some()
		};

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
				)?;
				if amt == 0 {
					break;
				}
				buffer.drain(..amt);

				// if were now async, we must break
				{
					if lockr!(thread_context.async_connections)?
						.get(&connection_id)
						.is_some()
					{
						break;
					}
				}
			}
		} else {
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
				)?;
				if amt == 0 {
					Self::append_buffer(&pbuf, buffer)?;
					break;
				}

				offset += amt;

				// if were now async, we must break
				{
					if lockr!(thread_context.async_connections)?
						.get(&connection_id)
						.is_some()
					{
						Self::append_buffer(&nbuf[offset..], buffer)?;
						break;
					}
				}
			}
		}

		Ok(())
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
	) -> Result<usize, Error> {
		let mime_map = &thread_context.mime_map;
		let async_connections = &thread_context.async_connections;
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
				let range: Option<(usize, usize)> = if headers.has_range() {
					let range = headers.get_header_value("Range".to_string())?;
					match range {
						Some(range) => {
							let start_index = range.find("=");
							match start_index {
								Some(start_index) => {
									let dash_index = range.find("-");
									match dash_index {
										Some(dash_index) => {
											let end = range.len();
											let start_str = &range[(start_index + 1)..dash_index];
											let end_str = &range[(dash_index + 1)..end];
											Some((start_str.parse()?, end_str.parse()?))
										}
										None => None,
									}
								}
								None => None,
							}
						}
						None => None,
					}
				} else {
					None
				};
				let mut key = None;

				let was_proxy = {
					let mut proxy_entry = None;
					match config.proxy_config.extensions.get(headers.extension()) {
						Some(entry) => proxy_entry = Some(entry),
						None => {}
					}

					if proxy_entry.is_none() {
						match config.proxy_config.mappings.get(headers.uri) {
							Some(entry) => proxy_entry = Some(entry),
							None => {}
						}
					}

					match proxy_entry {
						Some(proxy_entry) => {
							match Self::process_proxy_outbound(
								conn_data,
								&headers,
								&proxy_entry,
								buffer,
								evh_params,
								&mut thread_context.proxy_connections,
								&mut thread_context.active_connections,
								&mut thread_context.idle_proxy_connections,
								&mut thread_context.proxy_state,
							) {
								Ok(_) => {}
								Err(e) => {
									warn!("Error while communicating with proxy: {}", e.kind(),)?;
									conn_data.write(HTTP_ERROR_502)?;
								}
							}
							true
						}
						None => false,
					}
				};

				// check for api mapping/extension
				let was_api = {
					let api_config = lockr!(api_config)?;
					if was_proxy {
						false
					} else if api_config.mappings.get(headers.uri).is_some()
						|| api_config.extensions.get(headers.extension()).is_some()
					{
						match api_handler {
							Some(api_handler) => {
								let mut ctx = ApiContext::new(
									thread_context.async_connections.clone(),
									conn_data.clone(),
								);
								(api_handler)(conn_data, &headers, &mut ctx)?;
								true
							}
							None => {
								error!("no api handler configured!")?;
								false
							}
						}
					} else {
						false
					}
				};

				if !was_api && !was_proxy {
					match Self::send_file(
						&headers.uri,
						conn_data,
						config,
						cache,
						headers.get_version(),
						range,
						&mime_map,
						&async_connections,
						now,
					) {
						Ok(k) => {
							key = k;
						}
						Err(e) => {
							match e.kind() {
								ErrorKind::HttpError404(_) => {
									conn_data.write(HTTP_ERROR_404)?;
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
								std::str::from_utf8(&headers.uri)?,
								e
							)?;
						}
					}
				}
				(headers.len(), key)
			}
			None => (0, None),
		};

		Self::update_thread_context(thread_context, key, config, cache)?;

		Ok(len)
	}

	fn update_thread_context(
		thread_context: &mut ThreadContext,
		key: Option<[u8; 32]>,
		config: &HttpConfig,
		cache: &Arc<RwLock<HttpCache>>,
	) -> Result<(), Error> {
		match key {
			Some(key) => {
				thread_context.cache_hits.insert_raw(&key, &[0u8; 16])?;
			}
			None => {}
		}

		match thread_context.instant.elapsed().as_millis() > config.process_cache_update {
			true => {
				let mut cache = lockw!(cache)?;
				for (k, _v) in thread_context.cache_hits.iter_raw() {
					cache.bring_to_front(k.try_into()?)?;
				}
				thread_context.cache_hits.clear()?;
				thread_context.instant = Instant::now();
			}
			false => {}
		}

		thread_context.header_map.clear()?;

		Ok(())
	}

	fn clean(path: &mut Vec<u8>) -> Result<(), Error> {
		clean(path)
		/*
				let mut i = 0;
				let mut prev = 0;
				let mut prev_prev = 0;
				let mut prev_prev_prev = 0;
				let mut path_len = path.len();
				loop {
					if i >= path_len {
						break;
					}
					if prev_prev_prev == '/' as u8 && prev_prev == '.' as u8 && prev == '.' as u8 {
						// delete and remove prev dir
						if i < 4 {
							return Err(ErrorKind::HttpError403("Forbidden".into()).into());
						}
						let mut j = i - 4;
						loop {
							if path[j] == '/' as u8 {
								break;
							}

							j -= 1;
						}
						path.drain(j..i);
						path_len = path.len();
						i = j;
						prev = if i > 0 { path[i] } else { 0 };
						prev_prev = if i as i32 - 1 >= 0 { path[i - 1] } else { 0 };
						prev_prev_prev = if i as i32 - 2 >= 0 { path[i - 2] } else { 0 };
						continue;
					} else if prev_prev == '/' as u8 && prev == '.' as u8 {
						if path[i] == '/' as u8 {
							// delete
							path.drain(i - 2..i);
							path_len = path.len();
							i -= 2;
							prev = if i > 0 { path[i] } else { 0 };
							prev_prev = if i as i32 - 1 >= 0 { path[i - 1] } else { 0 };
							prev_prev_prev = if i as i32 - 2 > 0 { path[i - 2] } else { 0 };
							continue;
						}
					}

					prev_prev_prev = prev_prev;
					prev_prev = prev;
					prev = path[i];

					i += 1;
				}

				path_len = path.len();
				if path_len > 0 && path[path_len - 1] == '/' as u8 {
					path.drain(path_len - 1..);
				}

				Ok(())
		*/
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
		range: Option<(usize, usize)>,
		mime_map: &HashMap<Vec<u8>, Vec<u8>>,
		async_connections: &Arc<RwLock<HashSet<u128>>>,
		now: SystemTime,
	) -> Result<Option<[u8; 32]>, Error> {
		let mut path = config.root_dir.clone();
		path.extend_from_slice(&uri);
		Self::clean(&mut path)?;
		Self::check_path(&path, &config.root_dir)?;

		// try both the exact path and the version with index appended (metadata too expensive)
		let (found, need_update, key) = Self::try_send_cache(
			conn_data,
			&config,
			&path,
			&cache,
			now,
			http_version,
			range,
			mime_map,
		)?;
		let need_update = if found && !need_update {
			return Ok(Some(key));
		} else if !found {
			let mut path2 = path.clone();
			path2.extend_from_slice("/index.html".as_bytes());
			let (found, need_update, key) = Self::try_send_cache(
				conn_data,
				config,
				&path2,
				cache,
				now,
				http_version,
				range,
				mime_map,
			)?;
			if found && !need_update {
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
			path.extend_from_slice("/index.html".as_bytes());
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
			range,
			need_update,
			mime_map,
			async_connections,
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
							Some(&chunk[..wlen]),
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
		range: Option<(usize, usize)>,
		need_update: bool,
		mime_map: &HashMap<Vec<u8>, Vec<u8>>,
		async_connections: &Arc<RwLock<HashSet<u128>>>,
	) -> Result<(), Error> {
		let http_version = http_version.clone();
		let mime_map = mime_map.clone();

		let mut ctx = ApiContext::new(async_connections.clone(), conn_data.clone());

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
			loop {
				let len = file.read(&mut in_buf)?;
				let nslice = &in_buf[0..len];
				if len > 0
					&& md_len <= (config.max_cache_chunks * config.cache_chunk_size).try_into()?
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
		let mut itt = path.len() - 1;
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

		match http_version {
			HttpVersion::V10 | HttpVersion::Unknown => conn_data.close()?,
			HttpVersion::V11 | HttpVersion::V20 => {}
		}

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
		debug!(
			"on accept: {}, handle={}",
			conn_data.get_connection_id(),
			conn_data.get_handle()
		)?;

		Self::init_user_data(user_data, config)?;
		let thread_context = user_data.downcast_mut::<ThreadContext>().unwrap();

		thread_context.active_connections.insert(
			conn_data.get_connection_id(),
			ConnectionInfo::new(conn_data.clone()),
		);

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

		thread_context.active_connections.remove(&connection_id);

		match thread_context.proxy_connections.remove(&connection_id) {
			Some(proxy_info) => {
				match thread_context
					.idle_proxy_connections
					.get_mut(&proxy_info.proxy_entry)
				{
					Some(hashset) => {
						hashset.remove(&proxy_info);
					}
					None => {}
				}

				let state = thread_context.proxy_state.get_mut(&proxy_info.proxy_entry);
				match state {
					Some(state) => {
						state.cur_connections -= 1;
					}
					None => {}
				}
			}
			None => {}
		}

		Ok(())
	}

	fn process_on_housekeeper(
		config: &HttpConfig,
		user_data: &mut Box<dyn Any + Send + Sync>,
	) -> Result<(), Error> {
		let now = SystemTime::now().duration_since(UNIX_EPOCH)?.as_micros();
		Self::init_user_data(user_data, config)?;
		let thread_context = user_data.downcast_mut::<ThreadContext>().unwrap();

		debug!("housekeeping thread called")?;

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

	fn get_handle() -> Result<Handle, Error> {
		let raw_fd = socket(AddressFamily::Inet, Stream, SockFlag::empty(), None)?;

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

fn clean(path: &mut Vec<u8>) -> Result<(), Error> {
	let mut i = 0;
	let mut prev = 0;
	let mut prev_prev = 0;
	let mut prev_prev_prev = 0;
	let mut path_len = path.len();
	loop {
		if i >= path_len {
			break;
		}
		if prev_prev_prev == '/' as u8 && prev_prev == '.' as u8 && prev == '.' as u8 {
			// delete and remove prev dir
			if i < 4 {
				return Err(ErrorKind::HttpError403("Forbidden".into()).into());
			}
			let mut j = i - 4;
			loop {
				if path[j] == '/' as u8 {
					break;
				}

				j -= 1;
			}
			path.drain(j..i);
			path_len = path.len();
			i = j;
			prev = if i > 0 { path[i] } else { 0 };
			prev_prev = if i as i32 - 1 >= 0 { path[i - 1] } else { 0 };
			prev_prev_prev = if i as i32 - 2 >= 0 { path[i - 2] } else { 0 };
			continue;
		} else if prev_prev == '/' as u8 && prev == '.' as u8 {
			if path[i] == '/' as u8 {
				// delete
				path.drain(i - 2..i);
				path_len = path.len();
				i -= 2;
				prev = if i > 0 { path[i] } else { 0 };
				prev_prev = if i as i32 - 1 >= 0 { path[i - 1] } else { 0 };
				prev_prev_prev = if i as i32 - 2 > 0 { path[i - 2] } else { 0 };
				continue;
			}
		}

		prev_prev_prev = prev_prev;
		prev_prev = prev;
		prev = path[i];

		i += 1;
	}

	path_len = path.len();
	if path_len > 0 && path[path_len - 1] == '/' as u8 {
		path.drain(path_len - 1..);
	}

	Ok(())
}

#[cfg(test)]
mod test {
	use crate::http::{clean, HttpConfig, HttpServer};
	use nioruntime_err::Error;
	use nioruntime_log::*;
	use std::net::SocketAddr;
	use std::str::FromStr;

	debug!();

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
		http.set_api_handler(move |_, _, _| Ok(()))?;
		http.start()?;
		//std::thread::park();

		Ok(())
	}

	#[test]
	fn test_clean() -> Result<(), Error> {
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

		Ok(())
	}
}
