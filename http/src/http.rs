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
use nioruntime_deps::chrono::{DateTime, Datelike, Timelike, Utc, Weekday};
use nioruntime_deps::dirs;
use nioruntime_deps::lazy_static::lazy_static;
use nioruntime_deps::libc;
use nioruntime_deps::nix::sys::socket::{
	bind, listen, socket, AddressFamily, InetAddr, SockAddr, SockFlag, SockType,
};
use nioruntime_deps::path_clean::clean;
use nioruntime_deps::rand;
use nioruntime_err::{Error, ErrorKind};
use nioruntime_evh::{ConnectionContext, ConnectionData, ThreadContext};
use nioruntime_evh::{EventHandler, EventHandlerConfig};
use nioruntime_log::*;
use nioruntime_util::{lockr, lockw};
use nioruntime_util::{StaticHash, StaticHashConfig};
use std::convert::TryInto;
use std::fs::{metadata, File, Metadata};
use std::io::Read;
use std::mem;
use std::net::SocketAddr;
use std::net::TcpListener;
use std::os::unix::io::AsRawFd;
use std::os::unix::io::FromRawFd;
use std::path::PathBuf;
use std::str::FromStr;
use std::sync::{Arc, RwLock};
use std::time::SystemTime;

use std::os::unix::prelude::RawFd;

lazy_static! {
	static ref HTTP_OK_200_HEADERS_VEC: Vec<Vec<u8>> = vec![
		" 200 OK\r\nServer: ".as_bytes().to_vec(),
		"\r\nDate: ".as_bytes().to_vec(),
		"\r\nLast-Modified: ".as_bytes().to_vec(),
		"\r\nConnection: ".as_bytes().to_vec(),
		"\r\nContent-Length: ".as_bytes().to_vec(),
		"\r\nAccept-Ranges: bytes\r\n\r\n".as_bytes().to_vec(),
	];
}

const VERSION: &'static str = env!("CARGO_PKG_VERSION");

const GET_BYTES: &[u8] = "GET ".as_bytes();
const POST_BYTES: &[u8] = "POST ".as_bytes();

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

const KEEP_ALIVE_BYTES: &[u8] = "Keep-alive".as_bytes();
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

fn bytes_eq(bytes1: &[u8], bytes2: &[u8]) -> bool {
	let b1_len = bytes1.len();
	let b2_len = bytes2.len();
	if b1_len != b2_len {
		false
	} else {
		let mut ret = true;
		for i in 0..b1_len {
			if bytes1[i] != bytes2[i] {
				ret = false;
				break;
			}
		}

		ret
	}
}

/// Currently just support GET/POST.
#[derive(Debug)]
pub enum HttpMethod {
	Get,
	Post,
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
	user_map: &'a StaticHash<(), ()>,
	len: usize,
}

impl<'a> HttpHeaders<'a> {
	fn new(
		buffer: &'a [u8],
		config: &HttpConfig,
		user_map: &'a mut StaticHash<(), ()>,
		user_key_buf: &mut Vec<u8>,
		user_value_buf: &mut Vec<u8>,
	) -> Result<Option<Self>, Error> {
		let (method, offset) = match Self::parse_method(buffer, config)? {
			Some((method, offset)) => (method, offset),
			None => return Ok(None),
		};
		trace!("method={:?},offset={}", method, offset)?;
		let (uri, offset) = match Self::parse_uri(&buffer[offset..], config)? {
			Some((uri, noffset)) => (uri, noffset + offset),
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

		let len = match Self::parse_headers(
			&buffer[(offset + 2)..],
			config,
			user_map,
			user_key_buf,
			user_value_buf,
		)? {
			Some(noffset) => noffset + offset + 2,
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
			user_map,
			len,
		}))
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
		let key_len = self.user_map.config().key_len;
		for _ in name_bytes.len()..key_len {
			name_bytes.push(0);
		}
		match self.user_map.get_raw(&name_bytes) {
			Some(value) => {
				let len = u32::from_be_bytes(value[0..4].try_into().unwrap()) as usize;
				Ok(Some(std::str::from_utf8(&value[4..4 + len])?.to_string()))
			}
			None => Ok(None),
		}
	}

	pub fn get_header_names(&self) -> Result<Vec<String>, Error> {
		let mut ret = vec![];
		for (header, _) in self.user_map.iter_raw() {
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
		} else {
			Err(ErrorKind::HttpError405("Method not supported".into()).into())
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
	) -> Result<Option<(&'a [u8], usize)>, Error> {
		let buffer_len = buffer.len();
		let mut i = 0;
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
			Ok(Some((&buffer[0..i], if qpresent { i + 1 } else { i })))
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
		user_map: &mut StaticHash<(), ()>,
		user_key_buf: &mut Vec<u8>,
		user_value_buf: &mut Vec<u8>,
	) -> Result<Option<usize>, Error> {
		let mut i = 0;
		let buffer_len = buffer.len();
		let mut proc_key = true;
		let mut key_offset = 0;
		let mut value_offset = 4;

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
							return Ok(Some(i + 2));
						}
					}
					return Err(ErrorKind::HttpError400("Bad request: 1".into()).into());
				}

				if key_offset >= user_key_buf.len() {
					return Err(
						ErrorKind::HttpError431("Request Header Fields Too Large".into()).into(),
					);
				}

				user_key_buf[key_offset] = buffer[i];
				key_offset += 1;
			} else if proc_key {
				i += 1; // skip over the empty space
				proc_key = false;
			} else if buffer[i] != '\r' as u8 && buffer[i] != '\n' as u8 {
				if value_offset >= user_value_buf.len() {
					return Err(
						ErrorKind::HttpError431("Request Header Fields Too Large".into()).into(),
					);
				}
				user_value_buf[value_offset] = buffer[i];
				value_offset += 1;
			} else {
				user_value_buf[0..4].clone_from_slice(&(value_offset as u32).to_be_bytes());

				user_map.insert_raw(&user_key_buf, &user_value_buf)?;

				for j in 0..key_offset {
					user_key_buf[j] = 0;
				}
				for j in 0..value_offset {
					user_value_buf[j] = 0;
				}

				i += 1;
				proc_key = true;

				if i + 2 < buffer_len && buffer[i + 1] == '\r' as u8 && buffer[i + 2] == '\n' as u8
				{
					// end of headers
					return Ok(Some(i + 3));
				}
			}
			i += 1;
		}

		Ok(None)
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
}

impl Default for HttpConfig {
	fn default() -> Self {
		Self {
			addrs: vec![SocketAddr::from_str("127.0.0.1:8080").unwrap()],
			threads: 8,
			listen_queue_size: 100,
			max_header_size: 16 * 1024,
			max_header_name_len: 128,
			max_header_value_len: 1024,
			max_header_entries: 1_000,
			root_dir: "~/.niohttpd".to_string().as_bytes().to_vec(),
			max_cache_files: 1_000,
			max_cache_chunks: 10_000,
			cache_chunk_size: 1024,
			max_load_factor: 0.9,
			server_name: format!("nioruntime httpd/{}", VERSION).as_bytes().to_vec(),
		}
	}
}

pub struct HttpServer {
	config: HttpConfig,
	_listeners: Vec<TcpListener>,
}

impl HttpServer {
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
		root_dir = clean(&root_dir);
		root_dir = format!("{}/www", root_dir);
		config.root_dir = root_dir.as_bytes().to_vec();

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

		let config1 = self.config.clone();
		let config2 = self.config.clone();
		let config3 = self.config.clone();
		let cache = Arc::new(RwLock::new(HttpCache::new(
			self.config.max_cache_files,
			self.config.max_cache_chunks,
			self.config.cache_chunk_size,
			self.config.max_load_factor,
		)?));

		evh.set_on_read(move |conn_data, buf, ctx, thread_ctx| {
			Self::process_on_read(&conn_data, buf, ctx, &config1, &cache, thread_ctx)
		})?;
		evh.set_on_accept(move |conn_data, ctx| Self::process_on_accept(conn_data, ctx, &config2))?;
		evh.set_on_close(move |conn_data, ctx| Self::process_on_close(conn_data, ctx, &config3))?;
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

	fn init_thread_context(
		thread_context: &mut ThreadContext,
		config: &HttpConfig,
	) -> Result<(), Error> {
		let needed = match &mut thread_context.user_map {
			Some(_map) => false,
			None => true,
		};

		if needed {
			let c = StaticHashConfig {
				key_len: config.max_header_name_len,
				entry_len: config.max_header_value_len,
				max_entries: config.max_header_entries + 1,
				max_load_factor: 0.999999,
				..Default::default()
			};
			thread_context.user_map = Some(StaticHash::new(c)?);
			thread_context
				.user_key_buf
				.resize(config.max_header_name_len, 0u8);
			thread_context
				.user_value_buf
				.resize(config.max_header_value_len, 0u8);
		}

		Ok(())
	}

	fn process_on_read(
		conn_data: &ConnectionData,
		nbuf: &[u8],
		ctx: &mut ConnectionContext,
		config: &HttpConfig,
		cache: &Arc<RwLock<HttpCache>>,
		thread_context: &mut ThreadContext,
	) -> Result<(), Error> {
		Self::init_thread_context(thread_context, config)?;

		let buffer = ctx.get_buffer();
		let buffer_len = buffer.len();

		debug!(
			"on_read[{}] = '{:?}', acc_handle={:?}, buffer_len={}",
			conn_data.get_connection_id(),
			nbuf,
			conn_data.get_accept_handle(),
			buffer_len,
		)?;

		if buffer_len > 0 {
			Self::append_buffer(nbuf, buffer)?;
			loop {
				let amt = Self::process_buffer(
					conn_data,
					buffer,
					config,
					cache,
					thread_context.user_map.as_mut().unwrap(),
					&mut thread_context.user_key_buf,
					&mut thread_context.user_value_buf,
				)?;
				if amt == 0 {
					break;
				}
				buffer.drain(..amt);
			}
		} else {
			let mut offset = 0;
			loop {
				// premptively try to process the incoming buffer without appending
				// in many cases this will work and be faster
				let amt = Self::process_buffer(
					conn_data,
					&nbuf[offset..],
					config,
					cache,
					thread_context.user_map.as_mut().unwrap(),
					&mut thread_context.user_key_buf,
					&mut thread_context.user_value_buf,
				)?;
				if amt == 0 {
					Self::append_buffer(&nbuf[offset..], buffer)?;
					break;
				}
				offset += amt;
			}
		}

		Ok(())
	}

	fn process_buffer(
		conn_data: &ConnectionData,
		buffer: &[u8],
		config: &HttpConfig,
		cache: &Arc<RwLock<HttpCache>>,
		user_map: &mut StaticHash<(), ()>,
		user_key_buf: &mut Vec<u8>,
		user_value_buf: &mut Vec<u8>,
	) -> Result<usize, Error> {
		let headers = match HttpHeaders::new(buffer, config, user_map, user_key_buf, user_value_buf)
		{
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
						conn_data.write(HTTP_ERROR_500)?;
						conn_data.close()?;
					}
				}
				debug!("parsing headers generated error: {}", e)?;
				return Ok(0);
			}
		};

		debug!("header = {:?}", headers)?;

		let len = match headers {
			Some(headers) => {
				match Self::send_file(
					&headers.uri,
					conn_data,
					config,
					cache,
					headers.get_version(),
				) {
					Ok(_) => {}
					Err(e) => {
						match e.kind() {
							ErrorKind::HttpError404(_) => {
								conn_data.write(HTTP_ERROR_404)?;
							}
							ErrorKind::HttpError403(_) => {
								conn_data.write(HTTP_ERROR_403)?;
							}
							_ => {
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
				headers.len()
			}
			None => 0,
		};

		user_map.clear()?;

		Ok(len)
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
	) -> Result<(), Error> {
		let now = SystemTime::now();

		let mut path = config.root_dir.clone();
		path.extend_from_slice(&uri);
		Self::clean(&mut path)?;
		Self::check_path(&path, &config.root_dir)?;

		// try both the exact path and the version with index appended (metadata too expensive)
		if Self::try_send_cache(conn_data, &config, &path, &cache, now, http_version)? {
			return Ok(());
		} else {
			let mut path2 = path.clone();
			path2.extend_from_slice("/index.html".as_bytes());
			if Self::try_send_cache(conn_data, config, &path2, cache, now, http_version)? {
				return Ok(());
			}
		}

		// if neither found, we have to try to read the file
		let md = match metadata(std::str::from_utf8(&path)?) {
			Ok(md) => md,
			Err(e) => {
				warn!("metadata generated error: {}", e)?;
				return Err(ErrorKind::HttpError404("Not found".into()).into());
			}
		};

		let (path, md) = if md.is_dir() {
			path.extend_from_slice("/index.html".as_bytes());
			let md = match metadata(std::str::from_utf8(&path)?) {
				Ok(md) => md,
				Err(e) => {
					warn!("metadata generated error: {}", e)?;
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
		)?;

		Ok(())
	}

	fn try_send_cache(
		conn_data: &ConnectionData,
		config: &HttpConfig,
		path: &Vec<u8>,
		cache: &Arc<RwLock<HttpCache>>,
		now: SystemTime,
		http_version: &HttpVersion,
	) -> Result<bool, Error> {
		let found = {
			let cache = lockr!(cache)?;
			let mut headers_sent = false;
			let (iter, len) = cache.iter(&path)?;
			let mut len_sum = 0;
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
						http_version,
					)?;
					headers_sent = true;
				} else {
					conn_data.write(&chunk[..wlen])?;
				}

				len_sum += chunk_len;
			}
			headers_sent
		};

		Ok(found)
	}

	fn load_cache(
		path: Vec<u8>,
		conn_data: ConnectionData,
		config: HttpConfig,
		md: Metadata,
		cache: Arc<RwLock<HttpCache>>,
		now: SystemTime,
		http_version: &HttpVersion,
	) -> Result<(), Error> {
		let http_version = http_version.clone();
		std::thread::spawn(move || -> Result<(), Error> {
			let path_str = std::str::from_utf8(&path)?;
			let md_len = md.len();
			let mut in_buf = vec![];
			in_buf.resize(config.cache_chunk_size.try_into()?, 0u8);
			let mut file = File::open(&path_str)?;
			Self::send_headers(&conn_data, &config, md.len(), None, now, &http_version)?;

			let mut len_sum = 0;
			loop {
				let len = file.read(&mut in_buf)?;
				let nslice = &in_buf[0..len];
				if len > 0 {
					let mut cache = lockw!(cache)?;

					if len_sum != 0 || !(*cache).exists(&path)? {
						len_sum += len;
						(*cache).append_file_chunk(
							&path,
							nslice,
							Some(md_len),
							len_sum as u64 == md_len,
						)?;
					}
				}
				conn_data.write(nslice)?;

				if len <= 0 {
					break;
				}
			}

			Ok(())
		});
		Ok(())
	}

	fn extend_len(response: &mut Vec<u8>, len: u64) -> Result<(), Error> {
		if len > 1_000_000_000_000 {
			return Err(ErrorKind::TooLargeRead("File too big".into()).into());
		}
		if len > 100_000_000_000 {
			response.push((((len % 1_000_000_000_000) / 100_000_000_000) as u8 + '0' as u8) as u8);
		}
		if len > 10_000_000_000 {
			response.push((((len % 100_000_000_000) / 10_000_000_000) as u8 + '0' as u8) as u8);
		}
		if len > 1_000_000_000 {
			response.push((((len % 10_000_000_000) / 1_000_000_000) as u8 + '0' as u8) as u8);
		}
		if len > 100_000_000 {
			response.push((((len % 1_000_000_000) / 100_000_000) as u8 + '0' as u8) as u8);
		}
		if len > 10_000_000 {
			response.push((((len % 100_000_000) / 10_000_000) as u8 + '0' as u8) as u8);
		}
		if len > 1_000_000 {
			response.push((((len % 10_000_000) / 1_000_000) as u8 + '0' as u8) as u8);
		}
		if len > 100_000 {
			response.push((((len % 1_000_000) / 100_000) as u8 + '0' as u8) as u8);
		}
		if len > 10_000 {
			response.push((((len % 100_000) / 10_000) as u8 + '0' as u8) as u8);
		}
		if len > 1_000 {
			response.push((((len % 10_000) / 1_000) as u8 + '0' as u8) as u8);
		}
		if len > 100 {
			response.push((((len % 1_000) / 100) as u8 + '0' as u8) as u8);
		}
		if len > 10 {
			response.push((((len % 100) / 10) as u8 + '0' as u8) as u8);
		}
		response.push(((len % 10) as u8 + '0' as u8) as u8);
		Ok(())
	}

	fn extend_date(response: &mut Vec<u8>, date: SystemTime) -> Result<(), Error> {
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

	fn send_headers(
		conn_data: &ConnectionData,
		config: &HttpConfig,
		len: u64,
		chunk: Option<&[u8]>,
		now: SystemTime,
		http_version: &HttpVersion,
	) -> Result<(), Error> {
		let mut response = vec![];
		match http_version {
			HttpVersion::V10 | HttpVersion::Unknown => response.extend_from_slice(&HTTP10_BYTES),
			HttpVersion::V11 => response.extend_from_slice(&HTTP11_BYTES),
			HttpVersion::V20 => response.extend_from_slice(&HTTP11_BYTES),
		}
		response.extend_from_slice(&HTTP_OK_200_HEADERS_VEC[0]);
		response.extend_from_slice(&config.server_name);
		response.extend_from_slice(&HTTP_OK_200_HEADERS_VEC[1]);
		Self::extend_date(&mut response, now)?;
		response.extend_from_slice(&HTTP_OK_200_HEADERS_VEC[2]);
		Self::extend_date(&mut response, now)?;
		response.extend_from_slice(&HTTP_OK_200_HEADERS_VEC[3]);
		match http_version {
			HttpVersion::V10 | HttpVersion::Unknown => response.extend_from_slice(&CLOSE_BYTES),
			HttpVersion::V11 | HttpVersion::V20 => response.extend_from_slice(&KEEP_ALIVE_BYTES),
		}
		response.extend_from_slice(&HTTP_OK_200_HEADERS_VEC[4]);
		Self::extend_len(&mut response, len)?;
		response.extend_from_slice(&HTTP_OK_200_HEADERS_VEC[5]);
		match chunk {
			Some(chunk) => response.extend_from_slice(&chunk),
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
		_config: &HttpConfig,
	) -> Result<(), Error> {
		debug!(
			"on accept: {}, handle={}",
			conn_data.get_connection_id(),
			conn_data.get_handle()
		)?;

		Ok(())
	}

	fn process_on_close(
		conn_data: &ConnectionData,
		_ctx: &mut ConnectionContext,
		_config: &HttpConfig,
	) -> Result<(), Error> {
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
		http.start()?;
		//std::thread::park();

		Ok(())
	}

	#[test]
	fn test_clean() -> Result<(), Error> {
		let mut path = "/abc".as_bytes().to_vec();
		HttpServer::clean(&mut path)?;
		assert_eq!("/abc".as_bytes(), path);

		let mut path = "/abc/".as_bytes().to_vec();
		HttpServer::clean(&mut path)?;
		assert_eq!("/abc".as_bytes(), path);

		let mut path = "/abc/def/../ok".as_bytes().to_vec();
		HttpServer::clean(&mut path)?;
		assert_eq!("/abc/ok", std::str::from_utf8(&path)?);

		let mut path = "/abc/def/./ok".as_bytes().to_vec();
		HttpServer::clean(&mut path)?;
		assert_eq!("/abc/def/ok", std::str::from_utf8(&path)?);

		let mut path = "/abc/def/./ok/./abc".as_bytes().to_vec();
		HttpServer::clean(&mut path)?;
		assert_eq!("/abc/def/ok/abc", std::str::from_utf8(&path)?);

		let mut path = "/abc/def/././ghi".as_bytes().to_vec();
		HttpServer::clean(&mut path)?;
		assert_eq!("/abc/def/ghi", std::str::from_utf8(&path)?);

		let mut path = "/x/abcdef/../ghi/def/abc/../xyz".as_bytes().to_vec();
		HttpServer::clean(&mut path)?;
		assert_eq!("/x/ghi/def/xyz", std::str::from_utf8(&path)?);

		let mut path = "/x/abcdef/../ghi/def/abc/../xyz/".as_bytes().to_vec();
		HttpServer::clean(&mut path)?;
		assert_eq!("/x/ghi/def/xyz", std::str::from_utf8(&path)?);

		let mut path = "/abcdefghji/../xyz".as_bytes().to_vec();
		HttpServer::clean(&mut path)?;
		assert_eq!("/xyz", std::str::from_utf8(&path)?);

		let mut path = "/../abcdefghji/../xyz".as_bytes().to_vec();
		assert!(HttpServer::clean(&mut path).is_err());

		let mut path = "/abcdefghji/../xyz/../ok/1/2".as_bytes().to_vec();
		HttpServer::clean(&mut path)?;
		assert_eq!("/ok/1/2", std::str::from_utf8(&path)?);

		let mut path = "/abcdefghji/../xyz/.././ok/1/2".as_bytes().to_vec();
		HttpServer::clean(&mut path)?;
		assert_eq!("/ok/1/2", std::str::from_utf8(&path)?);

		let mut path = "/abcdefghji/../xyz/.././ok/1/2/".as_bytes().to_vec();
		HttpServer::clean(&mut path)?;
		assert_eq!("/ok/1/2", std::str::from_utf8(&path)?);

		let mut path = "/home/abc/.niohttpd/1".as_bytes().to_vec();
		HttpServer::clean(&mut path)?;
		assert_eq!("/home/abc/.niohttpd/1", std::str::from_utf8(&path)?);

		Ok(())
	}
}
