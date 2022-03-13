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
use nioruntime_deps::dirs;
use nioruntime_deps::libc;
use nioruntime_deps::nix::sys::socket::{
	bind, listen, socket, AddressFamily, InetAddr, SockAddr, SockFlag, SockType,
};
use nioruntime_deps::path_clean::clean;
use nioruntime_deps::rand;
use nioruntime_err::{Error, ErrorKind};
use nioruntime_evh::{ConnectionContext, ConnectionData};
use nioruntime_evh::{EventHandler, EventHandlerConfig};
use nioruntime_log::*;
use nioruntime_util::{lockr, lockw};
use std::collections::HashMap;
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

use std::os::unix::prelude::RawFd;

const HTTP10_STRING: &str = "HTTP/1.0";
const HTTP11_STRING: &str = "HTTP/1.1";
const HTTP20_STRING: &str = "HTTP/2.0";

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

const HTTP_OK_200_HEADERS: &str = "HTTP/1.1 200 OK\r\n\
Server: %1%\r\n\
Date: %2%\r\n\
Last-Modified: %3%\r\n\
Connection: %4%\r\n\
Content-Length: %5%\r\n\
\r\n";

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

/// Currently just support GET/POST.
#[derive(Debug)]
pub enum HttpMethod {
	Get,
	Post,
}

#[derive(Debug)]
pub enum HttpVersion {
	V10,
	V11,
	V20,
	Unknown,
}

#[derive(Debug)]
pub struct HttpHeaders {
	method: HttpMethod,
	version: HttpVersion,
	uri: String,
	query: String,
	lookup: HashMap<String, String>,
	len: usize,
}

impl HttpHeaders {
	fn new(buffer: &[u8], config: &HttpConfig) -> Result<Option<Self>, Error> {
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

		let (lookup, len) = match Self::parse_headers(&buffer[(offset + 2)..], config)? {
			Some((lookup, noffset)) => (lookup, noffset + offset + 2),
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
			lookup,
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

	pub fn get_query(&self) -> &String {
		&self.query
	}

	pub fn get_uri(&self) -> &String {
		&self.uri
	}

	pub fn get_header_value(&self, name: String) -> Option<&String> {
		self.lookup.get(&name)
	}

	pub fn get_header_names(&self) -> Vec<&String> {
		let mut ret = vec![];
		for (header, _) in self.lookup.iter() {
			ret.push(header);
		}

		ret
	}

	fn parse_method(
		buffer: &[u8],
		_config: &HttpConfig,
	) -> Result<Option<(HttpMethod, usize)>, Error> {
		if buffer.len() < 4 {
			Ok(None)
		} else if buffer[0] == 'G' as u8
			&& buffer[1] == 'E' as u8
			&& buffer[2] == 'T' as u8
			&& buffer[3] == ' ' as u8
		{
			Ok(Some((HttpMethod::Get, 4)))
		} else if buffer[0] == 'P' as u8
			&& buffer[1] == 'O' as u8
			&& buffer[2] == 'S' as u8
			&& buffer[3] == 'T' as u8
			&& buffer[4] == ' ' as u8
		{
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
		let mut ver_buf = vec![];
		for i in 0..buffer_len {
			if i > config.max_header_size {
				return Err(
					ErrorKind::HttpError431("Request Header Fields Too Large".into()).into(),
				);
			}
			if buffer[i] == '\r' as u8 || buffer[i] == '\n' as u8 {
				break;
			}
			ver_buf.push(buffer[i]);
		}
		let ver_string = std::str::from_utf8(&ver_buf)?;
		Ok(Some((
			match ver_string {
				HTTP20_STRING => HttpVersion::V20,
				HTTP11_STRING => HttpVersion::V11,
				HTTP10_STRING => HttpVersion::V10,
				_ => HttpVersion::Unknown,
			},
			ver_buf.len(),
		)))
	}

	fn parse_uri(buffer: &[u8], config: &HttpConfig) -> Result<Option<(String, usize)>, Error> {
		let buffer_len = buffer.len();
		let mut uri = vec![];
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
			uri.push(buffer[i]);
			i += 1;
		}

		if uri.len() == 0 || i + 1 >= buffer_len {
			Ok(None)
		} else {
			Ok(Some((
				std::str::from_utf8(&uri)?.to_string(),
				if qpresent { i + 1 } else { i },
			)))
		}
	}

	fn parse_query(buffer: &[u8], config: &HttpConfig) -> Result<Option<(String, usize)>, Error> {
		let buffer_len = buffer.len();
		let mut query = vec![];
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
			query.push(buffer[i]);
			i += 1;
		}

		if i + 1 >= buffer_len {
			Ok(None)
		} else {
			Ok(Some((
				std::str::from_utf8(&query)?.to_string(),
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
	) -> Result<Option<(HashMap<String, String>, usize)>, Error> {
		let mut i = 0;
		let buffer_len = buffer.len();
		let mut key = vec![];
		let mut value = vec![];
		let mut proc_key = true;

		let mut map = HashMap::new();

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
							return Ok(Some((map, i + 2)));
						}
					}
					return Err(ErrorKind::HttpError400("Bad request: 1".into()).into());
				}
				key.push(buffer[i]);
			} else if proc_key {
				i += 1; // skip over the empty space
				proc_key = false;
			} else if buffer[i] != '\r' as u8 && buffer[i] != '\n' as u8 {
				value.push(buffer[i]);
			} else {
				// full key/value
				map.insert(
					std::str::from_utf8(&key)?.to_string(),
					std::str::from_utf8(&value)?.to_string(),
				);

				key.clear();
				value.clear();

				i += 1;
				proc_key = true;

				if i + 2 < buffer_len && buffer[i + 1] == '\r' as u8 && buffer[i + 2] == '\n' as u8
				{
					// end of headers
					return Ok(Some((map, i + 3)));
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
	pub root_dir: String,
	pub max_cache_files: usize,
	pub max_cache_chunks: u64,
	pub cache_chunk_size: u64,
	pub max_load_factor: f64,
}

impl Default for HttpConfig {
	fn default() -> Self {
		Self {
			addrs: vec![SocketAddr::from_str("127.0.0.1:8080").unwrap()],
			threads: 8,
			listen_queue_size: 100,
			max_header_size: 16 * 1024,
			root_dir: "~/.niohttpd".to_string(),
			max_cache_files: 1_000,
			max_cache_chunks: 10_000,
			cache_chunk_size: 1024,
			max_load_factor: 0.9,
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

		let config1 = self.config.clone();
		let config2 = self.config.clone();
		let config3 = self.config.clone();
		let cache = Arc::new(RwLock::new(HttpCache::new(
			self.config.max_cache_files,
			self.config.max_cache_chunks,
			self.config.cache_chunk_size,
			self.config.max_load_factor,
		)?));

		evh.set_on_read(move |conn_data, buf, ctx| {
			Self::process_on_read(&conn_data, buf, ctx, &config1, &cache)
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

	fn get_root_dir(config: &HttpConfig) -> Result<String, Error> {
		let home_dir = match dirs::home_dir() {
			Some(p) => p,
			None => PathBuf::new(),
		}
		.as_path()
		.display()
		.to_string();

		Ok(config.root_dir.replace("~", &home_dir))
	}

	fn process_on_read(
		conn_data: &ConnectionData,
		nbuf: &[u8],
		ctx: &mut ConnectionContext,
		config: &HttpConfig,
		cache: &Arc<RwLock<HttpCache>>,
	) -> Result<(), Error> {
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
				let amt = Self::process_buffer(conn_data, buffer, config, cache)?;
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
				let amt = Self::process_buffer(conn_data, &nbuf[offset..], config, cache)?;
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
	) -> Result<usize, Error> {
		let headers = match HttpHeaders::new(buffer, config) {
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

		match headers {
			Some(headers) => {
				match Self::send_file(&headers.uri, conn_data, config, cache) {
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
						debug!("sending file {} generated error: {}", &headers.uri, e)?;
					}
				}
				Ok(headers.len())
			}
			None => Ok(0),
		}
	}

	fn send_file(
		path: &String,
		conn_data: &ConnectionData,
		config: &HttpConfig,
		cache: &Arc<RwLock<HttpCache>>,
	) -> Result<(), Error> {
		let base = format!("{}/www", Self::get_root_dir(config)?);
		let path = format!("{}{}", base, path);
		let path = &clean(&path)[..];
		if !path.starts_with(&base) {
			return Err(ErrorKind::HttpError403("Forbidden".into()).into());
		}

		// try both the exact path and the version with index appended (metadata too expensive)
		if Self::try_send_cache(conn_data, &config, path.to_string(), &cache)? {
			return Ok(());
		} else if Self::try_send_cache(
			conn_data,
			config,
			format!("{}{}", path, "/index.html"),
			cache,
		)? {
			return Ok(());
		}

		// if neither found, we have to try to read the file
		let md = match metadata(path) {
			Ok(md) => md,
			Err(e) => {
				debug!("metadata generated error: {}", e)?;
				return Err(ErrorKind::HttpError404("Not found".into()).into());
			}
		};

		let (path, md) = if md.is_dir() {
			let path = format!("{}{}", path, "/index.html");
			let md = match metadata(path.clone()) {
				Ok(md) => md,
				Err(e) => {
					debug!("metadata generated error: {}", e)?;
					return Err(ErrorKind::HttpError404("Not found".into()).into());
				}
			};
			(path, md)
		} else {
			(path.to_string(), md)
		};

		Self::load_cache(path, conn_data.clone(), config.clone(), md, cache.clone())?;

		Ok(())
	}

	fn try_send_cache(
		conn_data: &ConnectionData,
		config: &HttpConfig,
		path: String,
		cache: &Arc<RwLock<HttpCache>>,
	) -> Result<bool, Error> {
		let found = {
			let cache = lockr!(cache)?;
			let mut headers_sent = false;
			let (iter, len) = cache.iter(&path)?;
			for chunk in iter {
				if !headers_sent {
					Self::send_headers(&conn_data, config, len, Some(&chunk[..]))?;
					headers_sent = true;
				} else {
					conn_data.write(&chunk)?;
				}
			}
			headers_sent
		};

		Ok(found)
	}

	fn load_cache(
		path: String,
		conn_data: ConnectionData,
		config: HttpConfig,
		md: Metadata,
		cache: Arc<RwLock<HttpCache>>,
	) -> Result<(), Error> {
		std::thread::spawn(move || -> Result<(), Error> {
			let md_len = md.len();
			let mut in_buf = vec![];
			in_buf.resize(config.cache_chunk_size.try_into()?, 0u8);
			let mut file = File::open(path.clone())?;
			Self::send_headers(&conn_data, &config, md.len(), None)?;

			let mut len_sum = 0;
			loop {
				let len = file.read(&mut in_buf)?;
				let nslice = &in_buf[0..len];
				if len > 0 {
					let mut cache = lockw!(cache)?;

					if len_sum == 0 && (*cache).exists(&path)? {
						break;
					}

					len_sum += len;
					(*cache).append_file_chunk(
						&path,
						nslice,
						Some(md_len),
						len_sum as u64 == md_len,
					)?;
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

	fn send_headers(
		conn_data: &ConnectionData,
		_config: &HttpConfig,
		len: u64,
		chunk: Option<&[u8]>,
	) -> Result<(), Error> {
		let response = HTTP_OK_200_HEADERS
			.replace("%1%", "nioruntime httpd/0.0.3-beta.1")
			.replace("%2%", "Wed, 09 Mar 2022 22:03:11 GMT")
			.replace("%3%", "Fri, 30 Jul 2021 06:40:15 GMT")
			.replace("%4%", "Keep-alive")
			.replace("%5%", &len.to_string());

		let mut response = response.as_bytes().to_vec();
		match chunk {
			Some(chunk) => response.append(&mut chunk.to_vec()),
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
