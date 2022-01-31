// Copyright 2021 The BMW Developers
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

use crate::{process_websocket_data, send_websocket_message};
use crate::{WebSocketMessage, WebSocketMessageType};
use bytefmt;
use chrono::prelude::*;
use dirs;
use ed25519_dalek::ExpandedSecretKey;
use ed25519_dalek::PublicKey;
use ed25519_dalek::Signature;
use ed25519_dalek::Verifier;
use lazy_static::lazy_static;
use nioruntime_err::{Error, ErrorKind};
pub use nioruntime_evh::{EventHandler, EventHandlerConfig, State, WriteHandle};
use nioruntime_log::*;
use nioruntime_tor::config as tor_config;
use nioruntime_tor::ov3::OnionV3Address;
use nioruntime_tor::ov3::OnionV3Error;
use nioruntime_tor::process as tor_process;
use nioruntime_tor::process::TorProcess;
use nioruntime_util::threadpool::OnPanic;
use num_format::{Locale, ToFormattedString};
use sha1::Digest;
use sha1::Sha1;
use std::collections::HashMap;
use std::collections::HashSet;
use std::convert::TryInto;
use std::fs::metadata;
use std::fs::File;
use std::io::Read;
use std::io::Write;
use std::net::TcpListener;
use std::path::Path;
use std::path::PathBuf;
use std::sync::{Arc, RwLock, RwLockWriteGuard};
use std::time::Instant;

debug!();

lazy_static! {
	static ref START_TIME: Instant = Instant::now();
}

const SUN_BYTES: &[u8] = "Sun, ".as_bytes();
const MON_BYTES: &[u8] = "Mon, ".as_bytes();
const TUE_BYTES: &[u8] = "Tue, ".as_bytes();
const WED_BYTES: &[u8] = "Wed, ".as_bytes();
const THU_BYTES: &[u8] = "Thu, ".as_bytes();
const FRI_BYTES: &[u8] = "Fri, ".as_bytes();
const SAT_BYTES: &[u8] = "Sat, ".as_bytes();
const JAN_BYTES: &[u8] = "Jan ".as_bytes();
const FEB_BYTES: &[u8] = "Feb ".as_bytes();
const MAR_BYTES: &[u8] = "Mar ".as_bytes();
const APR_BYTES: &[u8] = "Apr ".as_bytes();
const MAY_BYTES: &[u8] = "May ".as_bytes();
const JUN_BYTES: &[u8] = "Jun ".as_bytes();
const JUL_BYTES: &[u8] = "Jul ".as_bytes();
const AUG_BYTES: &[u8] = "Aug ".as_bytes();
const SEP_BYTES: &[u8] = "Sep ".as_bytes();
const OCT_BYTES: &[u8] = "Oct ".as_bytes();
const NOV_BYTES: &[u8] = "Nov ".as_bytes();
const DEC_BYTES: &[u8] = "Dec ".as_bytes();
const DATE_PRE: &[u8] = "Date: ".as_bytes();
const DATE_POST: &[u8] = "GMT\r\n".as_bytes();
const SERVER_PRE: &[u8] = "Server: ".as_bytes();
const RESPONSE_404: &str = "<html><body>404 Page not found!</body></html>";
const CHUNKED_ENCODING: &[u8] = "Transfer-Encoding: chunked\r\n".as_bytes();
const NOT_FOUND_NO_CONTENT: &[u8] = "Content-Length: 45\r\n".as_bytes();
const FOUND_NO_KEEP_ALIVE: &[u8] = "".as_bytes();
const SEPARATOR_BYTES: &[u8] = "\r\n".as_bytes();
const FOUND_BYTES: &[u8] = "HTTP/1.1 200 OK\r\n".as_bytes();
const NOT_FOUND_BYTES: &[u8] = "HTTP/1.1 404 Not Found\r\n".as_bytes();
const MAIN_LOG: &str = "mainlog";
const STATS_LOG: &str = "statslog";
const HEADER: &str =
	"-------------------------------------------------------------------------------------------------------------------------------";
const VERSION: &'static str = env!("CARGO_PKG_VERSION");
const MAX_CHUNK_SIZE: u64 = 10 * 1024 * 1024;
const HTTP_GET: &[u8] = &['G' as u8, 'E' as u8, 'T' as u8];
const HTTP_POST: &[u8] = &['P' as u8, 'O' as u8, 'S' as u8, 'T' as u8];
const END_HEADERS: &[u8] = &['\r' as u8, '\n' as u8, '\r' as u8, '\n' as u8];
const CONNECTION_HEADER: &[u8] = "Connection".as_bytes();
const KEEP_ALIVE: &[u8] = "keep-alive".as_bytes();
const CONTENT_LENGTH: &[u8] = "Content-Length".as_bytes();
const WEBSOCKET: &[u8] = "websocket".as_bytes();
const UPGRADE: &[u8] = "Upgrade".as_bytes();
const WEBSOCKET_KEY: &[u8] = "Sec-WebSocket-Key".as_bytes();
const WEBSOCKET_GUID: &str = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11";

#[derive(Clone)]
struct RequestLogItem {
	uri: String,
	query: String,
	headers: Vec<(Vec<u8>, Vec<u8>)>,
	method: HttpMethod,
	elapsed: u128,
	is_async: bool,
}

impl RequestLogItem {
	fn new(
		uri: String,
		query: String,
		headers: Vec<(Vec<u8>, Vec<u8>)>,
		method: HttpMethod,
		elapsed: u128,
		is_async: bool,
	) -> Self {
		RequestLogItem {
			uri,
			query,
			headers,
			method,
			elapsed,
			is_async,
		}
	}
}

#[derive(Debug, Clone, PartialEq)]
pub enum HttpMethod {
	Get,
	Post,
}

#[derive(Clone, Debug, PartialEq)]
pub enum HttpVersion {
	V20,
	V11,
	V10,
	V09,
}

/// Header information about the request. May be used by WebSockets.
#[derive(PartialEq, Debug, Clone)]
pub struct HeaderInfo {
	/// The HttpMethod of the request. Currently only Get/Post are supported
	pub method: HttpMethod,
	/// The Http Version for this request
	pub http_version: HttpVersion,
	/// The URI of the request
	pub uri: String,
	/// The query of the request
	pub query: String,
	/// The request headers
	pub sep_headers_vec: Vec<(Vec<u8>, Vec<u8>)>,
	/// Whether this request is a "keep-alive" request.
	pub keep_alive: bool,
	/// The length of the content.
	pub content_len: usize,
	/// Is this a websocket?
	pub is_websocket: bool,
	/// optional websocket key if supplied by the client.
	pub websocket_key: Option<String>,
}

fn index_of(pattern: &Vec<u8>, data: &Vec<u8>) -> Option<usize> {
	let mut match_index: Option<usize> = None;
	let data_len = data.len();
	for i in 0..data_len {
		let mut check = true;
		for j in 0..pattern.len() {
			if i + j >= data_len {
				check = false;
				break;
			}
			if pattern[j] != data[i + j] {
				check = false;
				break;
			}
		}
		if check {
			match_index = Some(i);
			break;
		}
	}

	match_index
}

type Housekeeper = fn() -> Result<(), Error>;

pub type WsHandler = fn(conn_data: &mut ConnData, message: WebSocketMessage) -> Result<bool, Error>;

fn empty_ws_handler(_conn_data: &mut ConnData, _message: WebSocketMessage) -> Result<bool, Error> {
	Ok(true)
}

type Callback = fn(
	Arc<RwLock<bool>>,
	&mut RwLockWriteGuard<ConnData>,
	bool,
	usize,
	usize,
	HttpMethod,
	HttpConfig,
	WriteHandle,
	HttpVersion,
	&str,
	&str,
	Vec<(Vec<u8>, Vec<u8>)>,
	bool,
) -> Result<(), Error>;

fn empty_callback(
	_: Arc<RwLock<bool>>,
	_: &mut RwLockWriteGuard<ConnData>,
	_: bool,
	_: usize,
	_: usize,
	_: HttpMethod,
	_: HttpConfig,
	_: WriteHandle,
	_: HttpVersion,
	_: &str,                    // uri
	_: &str,                    // query
	_: Vec<(Vec<u8>, Vec<u8>)>, // headers
	_: bool,                    // keep-alive
) -> Result<(), Error> {
	Ok(())
}

fn empty_on_panic() -> Result<(), Error> {
	Ok(())
}

fn empty_housekeeper() -> Result<(), Error> {
	Ok(())
}

/// The configuration struct for an [`HttpServer`]. The [`Default`] trait
/// is implemented for this struct so default can be used like below.
/// # Examples
///
/// ```
/// use nioruntime_http::HttpConfig;
/// let config = HttpConfig {
///     port: 80,
///     ..HttpConfig::default()
/// };
/// ```
#[derive(Clone)]
pub struct HttpConfig {
	/// The host to bind to. In most cases, this is `0.0.0.0` or `127.0.0.1`.
	/// By default this is `0.0.0.0`.
	pub host: String,
	/// The port to bind to. The default is 8080.
	pub port: u16,
	/// The root directory of the http daemon. By default ~/.niohttpd is used.
	pub root_dir: String,
	/// The name of the server. The default is `"NIORuntime Httpd <version>"`
	pub server_name: String,
	/// Which parameters to log into the request log. The default values are:
	/// * `method` - Http Method of the request.
	/// * `uri` - Http URI of the request.
	/// * `query` - The query string of the request.
	/// * `User-Agent` - The user-agent making the request.
	/// * `Referer` - The Http referer of this request.
	/// Any additional header may be chosen. If it exists, it will be logged in
	/// the request log.
	pub request_log_params: Vec<String>,
	/// The separator char of the request log. By default `|` is used.
	pub request_log_separator_char: char,
	/// The maximum size in bytes of the request log.
	pub request_log_max_size: u64,
	/// The maximum age in milliseconds of the request log.
	pub request_log_max_age_millis: u128,
	/// Whether to delete the request log on every rotation. (Only used for testing)
	pub delete_request_rotation: bool,
	/// The maximum size in bytes of the main log.
	pub main_log_max_size: u64,
	/// The maximum age in milliseconds of the main log.
	pub main_log_max_age_millis: u128,
	/// The maximum size in bytes of the stats log.
	pub stats_log_max_size: u64,
	/// The maximum age in milliseconds of the stats log.
	pub stats_log_max_age_millis: u128,
	/// The amount of time in milliseconds to wait beforing closing a connection.
	/// This is set to 2 minutes by default. This means that if a request is made,
	/// and no additional requests are made for two minutes, the connection will be
	/// closed.
	pub last_request_timeout: u128,
	/// The amount of time in milliseconds between printing out to the statistical
	/// log. The default is 5000 (5 seconds).
	pub stats_frequency: u64,
	/// The amount of time in milliseconds before disconnecting a connection. By
	/// default, this is 30 seconds. This is different than `last_request_timeout`
	/// in that that parameter is used if a request has already been made on a connection.
	/// This one is used if no requests have been made.
	pub read_timeout: u128,
	/// The callback used for APIs. This is specified by the rustlet project for example.
	pub callback: Callback,
	/// The callback used for WebSockets. This is specified by the rustlet project for example.
	pub ws_handler: WsHandler,
	/// The handler for panics that occur in the thread pool.
	pub on_panic: OnPanic,
	/// The handler that is called every second by the Housekeeper thread.
	pub on_housekeeper: Housekeeper,
	/// The EventHandler Configuration.
	pub evh_config: EventHandlerConfig,
	/// The maximum number of entries to allow in the log queue before dropping logging items.
	/// The default value is 100,000.
	pub max_log_queue: usize,
	/// Port to run tor listener on. Default is 0, which is disabled.
	pub tor_port: u16,
	/// The maximum size of the Content-Length header. If a request with larger than this size
	/// is made an error is returned. The default value is 1mb.
	pub max_content_length: usize,
	/// Whether or not to print debugging information to stdout.
	pub debug: bool,
	/// A debugging option to print headers on all requests
	pub print_headers: bool,
}

impl Default for HttpConfig {
	fn default() -> HttpConfig {
		HttpConfig {
			host: "0.0.0.0".to_string(),
			port: 8080,
			root_dir: "~/.niohttpd".to_string(),
			server_name: format!("NIORuntime Httpd {}", VERSION),
			request_log_params: vec![
				"method".to_string(),
				"uri".to_string(),
				"query".to_string(),
				"User-Agent".to_string(),
				"Referer".to_string(),
			],
			request_log_separator_char: '|',
			request_log_max_size: 10 * 1024 * 1024,       // 10 mb
			request_log_max_age_millis: 1000 * 60 * 60,   // 1 hr
			delete_request_rotation: false,               // do not delete
			main_log_max_size: 10 * 1024 * 1024,          // 10 mb
			main_log_max_age_millis: 6 * 1000 * 60 * 60,  // 6 hr
			stats_frequency: 5000,                        // 5 seconds
			stats_log_max_size: 10 * 1024 * 1024,         // 10 mb
			stats_log_max_age_millis: 6 * 1000 * 60 * 60, // 6 hr
			last_request_timeout: 1000 * 120,             // 2 mins
			read_timeout: 1000 * 30,                      // 30 seconds
			max_content_length: 1024 * 1024,              // 1 mb
			evh_config: EventHandlerConfig::default(),
			callback: empty_callback,
			ws_handler: empty_ws_handler,
			on_panic: empty_on_panic,
			on_housekeeper: empty_housekeeper,
			max_log_queue: 100_000,
			tor_port: 0,
			debug: false,
			print_headers: false,
		}
	}
}

/// Connection Data used internally
/// It is held in a lock that is used to determine if the thread has panicked.
#[derive(Clone)]
pub struct ConnData {
	buffer: Vec<u8>,
	wh: WriteHandle,
	config: HttpConfig,
	create_time: u128,
	last_request_time: u128,
	needed_len: usize,
	is_async: Arc<RwLock<bool>>,
	begin_request_time: u128,
	is_websocket: bool,
	is_closed_websocket: bool,
	data: Option<u128>,
}

impl ConnData {
	fn new(wh: WriteHandle, config: HttpConfig) -> Self {
		let start_time = *START_TIME;
		let since_start = Instant::now().duration_since(start_time);
		ConnData {
			buffer: vec![],
			config,
			wh,
			create_time: since_start.as_millis(),
			last_request_time: 0,
			needed_len: 0,
			is_async: Arc::new(RwLock::new(false)),
			begin_request_time: 0,
			is_websocket: false,
			is_closed_websocket: false,
			data: None,
		}
	}

	pub fn set_data(&mut self, data: u128) -> Result<(), Error> {
		self.data = Some(data);
		Ok(())
	}

	pub fn get_data(&self) -> Option<u128> {
		self.data
	}

	pub fn get_buffer(&mut self) -> &mut Vec<u8> {
		&mut self.buffer
	}

	pub fn get_connection_id(&self) -> u128 {
		self.wh.get_connection_id()
	}

	pub fn get_wh(&self) -> &WriteHandle {
		&self.wh
	}
}

struct HttpStats {
	requests: u64,
	conns: u64,
	connects: u64,
	idledisc: u64,
	rtimeout: u64,
	lat_sum: u128,
	lat_requests: u64,
	max_lat: u128,
}

impl HttpStats {
	fn new() -> Self {
		HttpStats {
			requests: 0,
			conns: 0,
			connects: 0,
			idledisc: 0,
			rtimeout: 0,
			lat_sum: 0,
			lat_requests: 0,
			max_lat: 0,
		}
	}
}

pub struct HttpContext {
	stop: bool,
	map: Arc<RwLock<HashMap<u128, Arc<RwLock<ConnData>>>>>,
	stats: HttpStats,
	api_mappings: HashSet<String>,
	api_extensions: HashSet<String>,
	log_queue: Vec<RequestLogItem>,
	last_log_queue_overflow_message_time: u128,
}

impl HttpContext {
	fn new() -> Self {
		HttpContext {
			stop: false,
			map: Arc::new(RwLock::new(HashMap::new())),
			stats: HttpStats::new(),
			api_mappings: HashSet::new(),
			api_extensions: HashSet::new(),
			log_queue: vec![],
			last_log_queue_overflow_message_time: 0,
		}
	}
}

/// The main struct representing an [`HttpServer`].
/// # Examples
///
/// ```
/// use nioruntime_http::HttpConfig;
/// use nioruntime_http::HttpServer;
/// use nioruntime_err::Error;
///
/// fn test() -> Result<(), Error> {
///     let config = HttpConfig {
///         port: 80,
///         ..HttpConfig::default()
///     };
///     let mut http_server = HttpServer::new(config);
///     http_server.start()?;
///     Ok(())
/// }
/// ```
pub struct HttpServer {
	/// The config of this [`HttpServer`].
	pub config: HttpConfig,
	listener: Option<TcpListener>,
	onion_address: Option<String>,
	onion_secret: Option<ExpandedSecretKey>,
	pub http_context: Option<Arc<RwLock<HttpContext>>>,
	_tor_process: Option<Arc<RwLock<TorProcess>>>,
}

impl HttpServer {
	/// Create a new HttpServer instance based on the [`HttpConfig`]
	/// specified.
	pub fn new(config: HttpConfig) -> Self {
		let mut cloned_config = config.clone();
		let home_dir = match dirs::home_dir() {
			Some(p) => p,
			None => PathBuf::new(),
		}
		.as_path()
		.display()
		.to_string();
		cloned_config.root_dir = config.root_dir.replace("~", &home_dir);

		let exists = match std::fs::metadata(cloned_config.root_dir.clone()) {
			Ok(md) => md.is_dir(),
			Err(_) => false,
		};

		if !exists {
			match Self::build_webroot(cloned_config.root_dir.clone()) {
				Ok(_) => {}
				Err(e) => {
					log_multi!(
						ERROR,
						MAIN_LOG,
						"building webroot generated error: {}",
						e.to_string()
					);
				}
			}
		}

		HttpServer {
			config: cloned_config,
			listener: None,
			onion_address: None,
			onion_secret: None,
			http_context: None,
			_tor_process: None,
		}
	}

	pub fn tor_sign(&self, message: &[u8]) -> Result<[u8; 64], Error> {
		let pubkey = self.get_tor_pubkey()?;
		if pubkey.is_none() {
			return Err(ErrorKind::NotOnion(format!("tor not configured.")).into());
		}
		let pubkey = pubkey.unwrap();
		let pubkey = PublicKey::from_bytes(&pubkey)?;

		let secret_key = self.onion_secret.as_ref();
		if secret_key.is_none() {
			return Err(ErrorKind::NotOnion(format!("tor not configured.")).into());
		}
		let secret_key = secret_key.unwrap();

		Ok(secret_key.sign(message, &pubkey).to_bytes())
	}

	pub fn verify(
		&self,
		message: &[u8],
		pubkey: Option<[u8; 32]>,
		signature: [u8; 64],
	) -> Result<bool, Error> {
		if pubkey.is_none() {
			return Err(ErrorKind::NotOnion(format!("tor not configured.")).into());
		}
		let pubkey = pubkey.unwrap();
		let pubkey = PublicKey::from_bytes(&pubkey)?;

		Ok(pubkey
			.verify(message, &Signature::from_bytes(&signature)?)
			.is_ok())
	}

	pub fn get_tor_pubkey(&self) -> Result<Option<[u8; 32]>, Error> {
		match &self.onion_address {
			None => Ok(None),
			Some(onion_address) => {
				let onion_address: &str = &onion_address[..];
				let onion_address: OnionV3Address =
					onion_address.try_into().map_err(|e: OnionV3Error| {
						let error: Error = ErrorKind::NotOnion(format!(
							"onion address was not valid: {}",
							e.to_string()
						))
						.into();
						error
					})?;
				Ok(Some(*onion_address.as_bytes()))
			}
		}
	}

	/// add an API extension such that any requests that end in this extension
	/// will be sent to the the specified [`HttpConfig::callback`]. This is used
	/// by rsps to map all paths that end in ".rsp" to the rustlet container instead
	/// of being processed by the [`HttpServer`].
	pub fn add_api_extension(&self, extension: String) -> Result<(), Error> {
		match &self.http_context {
			Some(http_context) => {
				let mut context = nioruntime_util::lockw!(http_context)?;
				context.api_extensions.insert(extension.to_lowercase());
			}
			None => {
				return Err(ErrorKind::SetupError(
					"Context not set, must call start first.".to_string(),
				)
				.into());
			}
		}

		Ok(())
	}

	/// Add an API mapping such that any requests that have this URI will be sent to the specified
	/// [`HttpConfig::callback`] instead of being processed by the [`HttpServer`]. This is used
	/// by rustlet mappings.
	pub fn add_api_mapping(&self, path: String) -> Result<(), Error> {
		match &self.http_context {
			Some(http_context) => {
				let mut context = nioruntime_util::lockw!(http_context)?;
				context.api_mappings.insert(path);
			}
			None => {
				return Err(ErrorKind::SetupError(
					"Context not set, must call start first.".to_string(),
				)
				.into());
			}
		}

		Ok(())
	}

	fn check_config(&self) -> Result<(), Error> {
		if self.config.stats_frequency < 1000 {
			log_multi!(
                        	INFO,
                        	MAIN_LOG,
                        	"Error: Invalid config. config.stats_frequency must be equal to or greater than 1,000 ms"
                	);
			Err(ErrorKind::SetupError(
				"config.stats_frequency must be equal to or greater than 1,000 ms".to_string(),
			)
			.into())
		} else {
			Ok(())
		}
	}

	/// Start the [`HttpServer`]. This function will print some startup parameters to the mainlog,
	/// which is initially configured to print to both standard output and the mainlog log file
	/// location. After the startup parameters are printed, the server has begun and logging only
	/// is printed to the mainlog file location.
	pub fn start(&mut self) -> Result<(), Error> {
		let addr = format!("{}:{}", self.config.host, self.config.port,);
		let certificates_file = match self.config.evh_config.tls_config.as_ref() {
			Some(tls_config) => format!("'{}'", tls_config.certificates_file.clone()),
			None => "None".to_string(),
		};
		let private_key_file = match self.config.evh_config.tls_config.as_ref() {
			Some(tls_config) => format!("'{}'", tls_config.private_key_file.clone()),
			None => "None".to_string(),
		};

		log_config_multi!(
			MAIN_LOG,
			LogConfig {
				file_path: format!("{}/logs/mainlog.log", self.config.root_dir),
				show_log_level: false,
				..Default::default()
			}
		)?;

		self.check_config()?;

		// check if tor is configured. If so, start it.
		let (mut onion_address, tor_process);
		onion_address = "".to_string();
		if self.config.tor_port != 0 {
			let (returned_onion_address, returned_tor_process) =
				self.start_tor(self.config.tor_port, self.config.port)?;
			onion_address = returned_onion_address;
			self.onion_address = Some(onion_address.clone());
			tor_process = returned_tor_process;
			self._tor_process = Some(tor_process);

			let tor_dir = format!("{}/tor/onion_service_addresses", self.config.root_dir);
			let paths = std::fs::read_dir(tor_dir)?;
			let mut service_dir = "".to_string();

			for path in paths {
				service_dir = format!("{}", path?.path().display());
			}

			let secret_file = format!("{}/hs_ed25519_secret_key", service_dir);

			let mut f = File::open(&secret_file)?;
			let metadata = std::fs::metadata(&secret_file)?;
			let mut buffer = vec![0; metadata.len() as usize];
			f.read(&mut buffer)?;
			let secret_bytes = &buffer[32..];
			self.onion_secret = Some(ExpandedSecretKey::from_bytes(secret_bytes)?);
		}

		log_multi!(INFO, MAIN_LOG, "{}", self.config.server_name);
		log_no_ts_multi!(INFO, MAIN_LOG, "{}", HEADER);
		log_multi!(
			INFO,
			MAIN_LOG,
			"root_dir:             '{}'",
			self.config.root_dir
		);
		log_multi!(
			INFO,
			MAIN_LOG,
			"webroot:              '{}/www'",
			self.config.root_dir
		);
		log_multi!(INFO, MAIN_LOG, "bind_address:         {}", addr);
		log_multi!(
			INFO,
			MAIN_LOG,
			"thread_pool_size:     {}",
			self.config.evh_config.thread_count,
		);
		log_multi!(
			INFO,
			MAIN_LOG,
			"request_log_location: '{}/logs/request.log'",
			self.config.root_dir
		);
		log_multi!(
			INFO,
			MAIN_LOG,
			"request_log_max_size: {}",
			Self::format_bytes(self.config.request_log_max_size)
		);
		log_multi!(
			INFO,
			MAIN_LOG,
			"request_log_max_age:  {}",
			Self::format_time(self.config.request_log_max_age_millis)
		);
		log_multi!(
			INFO,
			MAIN_LOG,
			"mainlog_location:     '{}/logs/mainlog.log'",
			self.config.root_dir
		);
		log_multi!(
			INFO,
			MAIN_LOG,
			"mainlog_max_size:     {}",
			Self::format_bytes(self.config.main_log_max_size)
		);
		log_multi!(
			INFO,
			MAIN_LOG,
			"mainlog_max_age:      {}",
			Self::format_time(self.config.main_log_max_age_millis)
		);
		log_multi!(
			INFO,
			MAIN_LOG,
			"stats_log_location:   '{}/logs/stats.log'",
			self.config.root_dir
		);
		log_multi!(
			INFO,
			MAIN_LOG,
			"stats_log_max_size:   {}",
			Self::format_bytes(self.config.stats_log_max_size)
		);
		log_multi!(
			INFO,
			MAIN_LOG,
			"stats_log_max_age:    {}",
			Self::format_time(self.config.stats_log_max_age_millis)
		);
		log_multi!(
			INFO,
			MAIN_LOG,
			"stats_frequency:      {}",
			Self::format_time(self.config.stats_frequency.into())
		);
		log_multi!(
			INFO,
			MAIN_LOG,
			"max_log_queue:        {}",
			self.config.max_log_queue.to_formatted_string(&Locale::en),
		);
		log_multi!(
			INFO,
			MAIN_LOG,
			"tls_cert_file:        {}",
			certificates_file,
		);
		log_multi!(INFO, MAIN_LOG, "tls_private_key_file: {}", private_key_file,);

		if self.config.tor_port == 0 {
			log_multi!(INFO, MAIN_LOG, "onion_port:           DISABLED");
			log_multi!(INFO, MAIN_LOG, "onion_address:        DISABLED");
		} else {
			log_multi!(
				INFO,
				MAIN_LOG,
				"onion_port:           {}",
				self.config.tor_port
			);
			log_multi!(
				INFO,
				MAIN_LOG,
				"onion_address:        http://{}.onion",
				onion_address
			);
		}

		if self.config.debug {
			log_multi!(WARN, MAIN_LOG, "WARNING! flag set:    'debug'");
		}
		if self.config.print_headers {
			log_multi!(WARN, MAIN_LOG, "WARNING! flag set:    'print_headers'");
		}
		if self.config.delete_request_rotation {
			log_multi!(
				WARN,
				MAIN_LOG,
				"WARNING! flag set:    'delete_request_rotation'"
			);
		}

		log_no_ts_multi!(INFO, MAIN_LOG, "{}", HEADER);

		let listener = TcpListener::bind(addr.clone())?;

		let http_config = self.config.clone();
		let http_config_clone = http_config.clone();
		let http_config_clone2 = http_config.clone();
		let http_config_clone3 = http_config.clone();
		let http_config_clone4 = http_config.clone();
		let http_config_clone5 = http_config.clone();

		let http_context = HttpContext::new();

		let http_context = Arc::new(RwLock::new(http_context));
		let http_context_clone = http_context.clone();
		let http_context_clone2 = http_context.clone();
		let http_context_clone3 = http_context.clone();
		let http_context_clone4 = http_context.clone();
		let http_context_clone5 = http_context.clone();
		let http_context_clone6 = http_context.clone();
		let http_context_clone7 = http_context.clone();

		let mut eh = EventHandler::new(http_config.evh_config.clone());
		eh.set_on_panic(http_config.on_panic)?;

		let sha1 = sha1::Sha1::new();
		eh.set_on_read(move |buf, len, wh| {
			let sha1 = sha1.clone();
			Self::process_read(
				http_context.clone(),
				http_config.clone(),
				buf,
				len,
				wh,
				sha1,
			)
		})?;
		eh.set_on_accept(move |id, wh| {
			Self::process_accept(
				http_context_clone.clone(),
				http_config_clone.clone(),
				id,
				wh,
			)
		})?;
		eh.set_on_client_read(|_, _, _| Ok(()))?;
		eh.set_on_close(move |id| {
			Self::process_close(http_context_clone2.clone(), http_config_clone2.clone(), id)
		})?;
		eh.start()?;
		eh.add_tcp_listener(&listener)?;
		self.listener = Some(listener);
		self.http_context = Some(http_context_clone3);

		std::thread::spawn(move || loop {
			std::thread::sleep(std::time::Duration::from_millis(100));
			{
				let stop = {
					let http_context = match nioruntime_util::lockr!(http_context_clone4) {
						Ok(http_context) => http_context,
						Err(e) => {
							log_multi!(
								ERROR,
								MAIN_LOG,
								"unexpected error obtaining lock on http_context: {}",
								e.to_string()
							);
							break;
						}
					};
					http_context.stop
				};

				if stop {
					log_multi!(INFO, MAIN_LOG, "Stopping HttpServer");
					let stop_res = eh.stop();
					match stop_res {
						Ok(_) => {}
						Err(e) => {
							log_multi!(
								ERROR,
								MAIN_LOG,
								"unexpected error stopping eventhandler: {}",
								e.to_string()
							);
						}
					}
					break;
				}
			}
		});

		std::thread::spawn(move || {
			Self::request_log(http_context_clone5, http_config_clone3.clone())
		});

		std::thread::spawn(move || {
			Self::stats_log(http_context_clone6, http_config_clone4.clone())
		});

		std::thread::spawn(move || Self::house_keeper(&http_context_clone7, &http_config_clone5));

		log_multi!(INFO, MAIN_LOG, "Server Started");

		log_config_multi!(
			MAIN_LOG,
			LogConfig {
				file_path: format!("{}/logs/mainlog.log", self.config.root_dir),
				show_stdout: self.config.debug,
				max_age_millis: self.config.main_log_max_age_millis,
				max_size: self.config.main_log_max_size,
				show_log_level: false,
				..Default::default()
			}
		)?;

		Ok(())
	}

	/// If configured, start the tor process
	fn start_tor(
		&self,
		tor_port: u16,
		http_port: u16,
	) -> Result<(String, Arc<RwLock<TorProcess>>), Error> {
		let tor_dir = format!("{}/tor", self.config.root_dir);
		let addr = format!("127.0.0.1:{}", http_port);
		let scoped_vec;
		let mut sec_key_vec = None;
		let onion_service_dir = format!("{}/onion_service_addresses", tor_dir.clone());
		let mut onion_address = "".to_string();
		let mut existing_onion = None;
		let mut found = false;
		if std::path::Path::new(&onion_service_dir).exists() {
			for entry in std::fs::read_dir(onion_service_dir.clone())? {
				onion_address = entry.unwrap().file_name().into_string().unwrap();
				found = true;
			}
		}
		let socks_port = tor_port;

		if !found {
			let sec_key = secp256k1zkp::SecretKey::new(
				&secp256k1zkp::Secp256k1::new(),
				&mut rand::thread_rng(),
			);
			scoped_vec = vec![sec_key.clone()];
			sec_key_vec = Some((scoped_vec).as_slice());
		} else {
			existing_onion = Some(onion_address.clone());
		}

		tor_config::output_tor_listener_config(
			&tor_dir,
			&addr,
			sec_key_vec,
			existing_onion,
			socks_port,
		)
		.map_err(|e| {
			error!("failed to configure tor due to {:?}. Halting!", e);
			std::process::exit(-1);
		})
		.unwrap();

		if !found {
			// now that it's configured, read it
			if std::path::Path::new(&onion_service_dir).exists() {
				for entry in std::fs::read_dir(onion_service_dir)? {
					onion_address = entry.unwrap().file_name().into_string().unwrap();
				}
			}
		}

		// Start Tor process
		let tor_path = PathBuf::from(format!("{}/torrc", tor_dir));
		let tor_path = std::fs::canonicalize(&tor_path)?;
		let tor_path = Self::adjust_canonicalization(tor_path);

		let mut process = tor_process::TorProcess::new();

		let res = process
			.torrc_path(&tor_path)
			.working_dir(&tor_dir)
			.timeout(200)
			.completion_percent(100)
			.launch();

		match res {
			Err(e) => {
				let error: Error = ErrorKind::Configuration(e.to_string()).into();
				Err(error)
			}
			Ok(_) => Ok((onion_address.to_string(), Arc::new(RwLock::new(process)))),
		}
	}

	#[cfg(not(target_os = "windows"))]
	fn adjust_canonicalization<P: AsRef<Path>>(p: P) -> String {
		p.as_ref().display().to_string()
	}

	#[cfg(target_os = "windows")]
	fn adjust_canonicalization<P: AsRef<Path>>(p: P) -> String {
		const VERBATIM_PREFIX: &str = r#"\\?\"#;
		let p = p.as_ref().display().to_string();
		if p.starts_with(VERBATIM_PREFIX) {
			p[VERBATIM_PREFIX.len()..].to_string()
		} else {
			p
		}
	}

	/// Stop the [`HttpServer`]. All resources including threads and file descriptors will be released.
	pub fn stop(&mut self) -> Result<(), Error> {
		match &self.http_context {
			Some(http_context) => {
				let mut http_context = nioruntime_util::lockw!(http_context)?;
				http_context.stop = true;
			}
			None => {
				log_multi!(
					WARN,
					MAIN_LOG,
					"Tried to stop an HttpServer that never started."
				);
			}
		}

		match self.listener.as_ref() {
			Some(listener) => drop(listener),
			None => {}
		}
		self.listener = None;
		Ok(())
	}

	/// Get the path of the file specified based on the the [`HttpConfig`] and the uri.
	pub fn get_path(config: &HttpConfig, uri: &str) -> Result<String, Error> {
		Ok(format!("{}/www{}", config.root_dir, uri))
	}

	/// Write headers the connection associated with this WriteHandle.
	/// * `wh` - The write handle to use to write.
	/// * `config` - The [`HttpConfig`] associated with this connection.
	/// * `found` - Whether or not this file was found.
	/// * `keep-alive` - Whether or not to keep the connection alive after this response is sent.
	/// * `additional_headers` - Additional headers to send with this response.
	/// * `redirect` - Optional redirect for this request.
	pub fn write_headers(
		wh: &WriteHandle,
		config: &HttpConfig,
		found: bool,
		found_404_content: bool,
		keep_alive: bool,
		additional_headers: Vec<(String, String)>,
		redirect: Option<String>,
	) -> Result<(), Error> {
		let mut buf = vec![];
		let mut size = 1000;
		for i in 0..additional_headers.len() {
			size += additional_headers[i].0.len() + additional_headers[i].1.len() + 10;
		}
		buf.resize(size, 0);
		let len = Self::build_headers(
			config,
			found,
			found_404_content,
			keep_alive,
			additional_headers,
			redirect,
			&mut buf,
		)?;
		wh.write(&buf[0..len])?;
		if !found && !found_404_content && !keep_alive {
			wh.close()?;
		}

		Ok(())
	}

	fn build_date(buf: &mut [u8], itt: usize) -> Result<usize, Error> {
		let now = chrono::Utc::now();
		let mut itt = Self::clone_in_bytes(DATE_PRE, buf, itt, DATE_PRE.len())?;
		let day_of_week_bytes = match now.weekday() {
			Weekday::Sun => SUN_BYTES,
			Weekday::Mon => MON_BYTES,
			Weekday::Tue => TUE_BYTES,
			Weekday::Wed => WED_BYTES,
			Weekday::Thu => THU_BYTES,
			Weekday::Fri => FRI_BYTES,
			Weekday::Sat => SAT_BYTES,
		};
		itt = Self::clone_in_bytes(day_of_week_bytes, buf, itt, day_of_week_bytes.len())?;
		let day_of_month = now.day();
		if day_of_month < 10 {
			buf[itt] = '0' as u8;
			itt += 1;
			buf[itt] = day_of_month as u8 + '0' as u8;
			itt += 1;
		} else {
			buf[itt] = '0' as u8 + (day_of_month / 10) as u8;
			itt += 1;
			buf[itt] = '0' as u8 + (day_of_month % 10) as u8;
			itt += 1;
		}
		buf[itt] = ' ' as u8;
		itt += 1;
		let month = now.month();
		let month_bytes = match month {
			1 => JAN_BYTES,
			2 => FEB_BYTES,
			3 => MAR_BYTES,
			4 => APR_BYTES,
			5 => MAY_BYTES,
			6 => JUN_BYTES,
			7 => JUL_BYTES,
			8 => AUG_BYTES,
			9 => SEP_BYTES,
			10 => OCT_BYTES,
			11 => NOV_BYTES,
			12 => DEC_BYTES,
			_ => DEC_BYTES, // should not happen
		};
		itt = Self::clone_in_bytes(month_bytes, buf, itt, month_bytes.len())?;
		itoa::write(&mut buf[itt..], now.year())?;
		itt += 4;
		buf[itt] = ' ' as u8;
		itt += 1;
		let hour = now.hour();
		if hour < 10 {
			buf[itt] = '0' as u8;
			itt += 1;
			buf[itt] = '0' as u8 + hour as u8;
			itt += 1;
		} else {
			buf[itt] = '0' as u8 + (hour / 10) as u8;
			itt += 1;
			buf[itt] = '0' as u8 + (hour % 10) as u8;
			itt += 1;
		}
		buf[itt] = ':' as u8;
		itt += 1;

		let minute = now.minute();
		if minute < 10 {
			buf[itt] = '0' as u8;
			itt += 1;
			buf[itt] = '0' as u8 + minute as u8;
			itt += 1;
		} else {
			buf[itt] = '0' as u8 + (minute / 10) as u8;
			itt += 1;
			buf[itt] = '0' as u8 + (minute % 10) as u8;
			itt += 1;
		}
		buf[itt] = ':' as u8;
		itt += 1;

		let second = now.second();
		if second < 10 {
			buf[itt] = '0' as u8;
			itt += 1;
			buf[itt] = '0' as u8 + second as u8;
			itt += 1;
		} else {
			buf[itt] = '0' as u8 + (second / 10) as u8;
			itt += 1;
			buf[itt] = '0' as u8 + (second % 10) as u8;
			itt += 1;
		}
		buf[itt] = ' ' as u8;
		itt += 1;

		itt = Self::clone_in_bytes(DATE_POST, buf, itt, DATE_POST.len())?;
		Ok(itt)
	}

	/// Build (but do not write) headers based on specified parameters.
	/// * `config` - The [`HttpConfig`] associated with this connection.
	/// * `found` - Whether or not this file was found.
	/// * `keep-alive` - Whether or not to keep the connection alive after this response is sent.
	/// * `additional_headers` - Additional headers to send with this response.
	/// * `redirect` - Optional redirect for this request.
	/// * `buf` - The buffer to write the response into. Note: the caller is responsible for
	/// * ensuring the capacity of this buffer is sufficient.
	pub fn build_headers(
		config: &HttpConfig,
		found: bool,
		found_404_content: bool,
		keep_alive: bool,
		additional_headers: Vec<(String, String)>,
		redirect: Option<String>,
		buf: &mut [u8],
	) -> Result<usize, Error> {
		let server_bytes = config.server_name.as_bytes();

		let transfer_encoding_bytes = if keep_alive {
			CHUNKED_ENCODING
		} else if !found && !found_404_content {
			NOT_FOUND_NO_CONTENT
		} else {
			FOUND_NO_KEEP_ALIVE
		};

		let mut itt = 0;
		if redirect.is_some() {
			let redir_str = format!(
				"HTTP/1.1 301 Moved Permanently\r\nLocation: {}\r\n",
				redirect.as_ref().unwrap_or(&"".to_string())
			);
			let redir_bytes = redir_str.as_bytes();
			itt = Self::clone_in_bytes(redir_bytes, buf, itt, redir_bytes.len())?;
		} else if found {
			itt = Self::clone_in_bytes(FOUND_BYTES, buf, itt, FOUND_BYTES.len())?;
		} else {
			itt = Self::clone_in_bytes(NOT_FOUND_BYTES, buf, itt, NOT_FOUND_BYTES.len())?;
		}

		itt = Self::build_date(buf, itt)?;
		itt = if additional_headers.len() > 0 {
			let mut additional_headers_formatted = String::new();
			for header in additional_headers {
				additional_headers_formatted = format!(
					"{}{}: {}\r\n",
					additional_headers_formatted, header.0, header.1,
				);
			}
			let additional_headers_formatted_bytes = additional_headers_formatted.as_bytes();
			Self::clone_in_bytes(
				additional_headers_formatted_bytes,
				buf,
				itt,
				additional_headers_formatted_bytes.len(),
			)?
		} else {
			itt
		};
		itt = Self::clone_in_bytes(SERVER_PRE, buf, itt, SERVER_PRE.len())?;
		itt = Self::clone_in_bytes(server_bytes, buf, itt, server_bytes.len())?;
		itt = Self::clone_in_bytes(SEPARATOR_BYTES, buf, itt, SEPARATOR_BYTES.len())?;
		itt = Self::clone_in_bytes(
			transfer_encoding_bytes,
			buf,
			itt,
			transfer_encoding_bytes.len(),
		)?;
		itt = Self::clone_in_bytes(SEPARATOR_BYTES, buf, itt, SEPARATOR_BYTES.len())?;
		itt = if found || found_404_content {
			itt
		} else if keep_alive {
			let not_found_message =
				format!("{:X}\r\n{}\r\n0\r\n\r\n", RESPONSE_404.len(), RESPONSE_404);
			let not_found_message_bytes = not_found_message.as_bytes();
			Self::clone_in_bytes(
				not_found_message_bytes,
				buf,
				itt,
				not_found_message_bytes.len(),
			)?
		} else {
			let not_found_message = format!("{}\r\n", RESPONSE_404);
			let not_found_message_bytes = not_found_message.as_bytes();
			Self::clone_in_bytes(
				not_found_message_bytes,
				buf,
				itt,
				not_found_message_bytes.len(),
			)?
		};
		Ok(itt)
	}

	fn clone_in_bytes(
		src: &[u8],
		dst: &mut [u8],
		offset: usize,
		len: usize,
	) -> Result<usize, Error> {
		dst[offset..offset + len].clone_from_slice(&src[0..len]);
		Ok(offset + len)
	}

	fn create_file_from_bytes(
		resource: String,
		root_dir: String,
		bytes: &[u8],
	) -> Result<(), Error> {
		let path = format!("{}/www/{}", root_dir, resource);
		let mut file = File::create(&path)?;
		file.write_all(bytes)?;
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
			format!("{} Minutes", (duration.as_secs() / 60))
		} else if n >= 1000 {
			format!("{} Seconds", duration.as_secs())
		} else {
			format!("{} Milliseconds", duration.as_millis())
		}
	}

	fn format_float(num: f64) -> String {
		if num < 10.0 {
			format!("{:.7}", num)
		} else if num < 100.0 {
			format!("{:.6}", num)
		} else if num < 1_000.0 {
			format!("{:.5}", num)
		} else if num < 10_000.0 {
			format!("{:.4}", num)
		} else if num < 100_000.0 {
			format!("{:.3}", num)
		} else {
			format!("{:.2}", num)
		}
	}

	fn stats_log(
		http_context: Arc<RwLock<HttpContext>>,
		http_config: HttpConfig,
	) -> Result<(), Error> {
		let start = Instant::now();
		let header_titles =
"Statistical Log V_1.0:         REQUESTS       CONNS        CONNECTS         QPS   IDLE_DISC    RTIMEOUT     AVG_LAT     MAX_LAT"
.to_string();
		let file_header = format!("{}\n{}", header_titles, HEADER);
		log_config_multi!(
			STATS_LOG,
			LogConfig {
				file_path: format!("{}/logs/statslog.log", http_config.root_dir),
				show_stdout: false,
				file_header: file_header.clone(),
				max_age_millis: http_config.stats_log_max_age_millis,
				max_size: http_config.stats_log_max_size,
				show_log_level: false,
				..Default::default()
			}
		)?;

		let mut itt = 1;
		let mut last_requests = 0;
		let mut last_connects = 0;
		let mut last_idledisc = 0;
		let mut last_rtimeout = 0;
		let mut last_lat_sum = 0;
		let mut last_lat_reqs = 0;
		let mut max_lat_perm = 0;
		loop {
			{
				let mut http_context = nioruntime_util::lockw!(http_context)?;
				http_context.stats.max_lat = 0;
			}

			std::thread::sleep(std::time::Duration::from_millis(
				http_config.stats_frequency,
			));

			let http_context = nioruntime_util::lockr!(http_context)?;

			if itt % 6 == 0 {
				log_no_ts_multi!(INFO, STATS_LOG, "{}", HEADER);
				log_no_ts_multi!(INFO, STATS_LOG, "{}", header_titles);
				log_no_ts_multi!(INFO, STATS_LOG, "{}", HEADER);

				let secs = start.elapsed().as_secs();
				let days = secs / 86400;
				let fsecs = secs % 60;
				let fmins = (secs / 60) % 60;
				let fhours = (secs / (60 * 60)) % 24;
				let format_elapsed_time = if days > 10_000 {
					format!(
						" {} Days {:02}:{:02}:{:02}",
						days.to_formatted_string(&Locale::en),
						fhours,
						fmins,
						fsecs,
					)
				} else if days > 1_000 {
					format!(
						"  {} Days {:02}:{:02}:{:02}",
						days.to_formatted_string(&Locale::en),
						fhours,
						fmins,
						fsecs,
					)
				} else if days > 100 {
					format!("    {} Days {:02}:{:02}:{:02}", days, fhours, fmins, fsecs,)
				} else if days > 10 {
					format!("     {} Days {:02}:{:02}:{:02}", days, fhours, fmins, fsecs,)
				} else {
					format!(
						"      {} Days {:02}:{:02}:{:02}",
						days, fhours, fmins, fsecs,
					)
				};

				let avg_lat = if http_context.stats.lat_requests == 0 {
					0.0
				} else {
					http_context.stats.lat_sum as f64
						/ (http_context.stats.lat_requests * 1_000_000) as f64
				};
				let max_lat = max_lat_perm as f64 / 1_000_000 as f64;

				log_no_ts_multi!(
					INFO,
					STATS_LOG,
					"{}: {:>16}{:>12}{:>16}   {}{:12}{:12}   {}   {}",
					format_elapsed_time,
					http_context.stats.requests.to_formatted_string(&Locale::en),
					http_context.stats.conns.to_formatted_string(&Locale::en),
					http_context.stats.connects.to_formatted_string(&Locale::en),
					Self::format_float(http_context.stats.requests as f64 / secs as f64),
					http_context.stats.idledisc,
					http_context.stats.rtimeout,
					Self::format_float(avg_lat),
					Self::format_float(max_lat),
				);
				log_no_ts_multi!(INFO, STATS_LOG, "{}", HEADER);
			}

			let qps = (http_context.stats.requests - last_requests) as f64
				/ (http_config.stats_frequency / 1000) as f64;
			let avg_lat = if http_context.stats.lat_requests - last_lat_reqs == 0 {
				0.0
			} else {
				(http_context.stats.lat_sum - last_lat_sum) as f64
					/ ((http_context.stats.lat_requests - last_lat_reqs) * 1_000_000) as f64
			};
			let max_lat = http_context.stats.max_lat as f64 / 1_000_000 as f64;

			log_multi!(
				INFO,
				STATS_LOG,
				"{:>16}{:>12}{:>16}   {}{:12}{:12}   {}   {}",
				(http_context.stats.requests - last_requests).to_formatted_string(&Locale::en),
				http_context.stats.conns.to_formatted_string(&Locale::en),
				(http_context.stats.connects - last_connects).to_formatted_string(&Locale::en),
				Self::format_float(qps),
				http_context.stats.idledisc - last_idledisc,
				http_context.stats.rtimeout - last_rtimeout,
				Self::format_float(avg_lat),
				Self::format_float(max_lat),
			);

			if http_context.stop {
				break;
			}

			// check rotation of mainlog:
			let mut rotate_complete = false;
			let mut auto_rotate_complete = false;
			{
				let static_log = &STATIC_LOG;
				let log_map = static_log.lock();

				match log_map {
					Ok(mut log_map) => {
						let log = log_map.get_mut(STATS_LOG);
						match log {
							Some(log) => {
								match log.rotation_status()? {
									RotationStatus::Needed => match log.rotate() {
										Ok(_) => {
											rotate_complete = true;
										}
										Err(e) => {
											println!("unexpected stats log err: {}", e.to_string());
										}
									},
									RotationStatus::AutoRotated => {
										auto_rotate_complete = true;
									}
									RotationStatus::NotNeeded => {}
								};
							}
							None => {}
						}
					}
					Err(e) => {
						println!("Unexpected error rotate statslog: {}", e.to_string());
					}
				}
			}

			if auto_rotate_complete {
				log_multi!(INFO, MAIN_LOG, "statslog rotated.");
			} else if rotate_complete {
				log_multi!(INFO, MAIN_LOG, "statslog rotated.");
			}

			itt += 1;
			last_requests = http_context.stats.requests;
			last_connects = http_context.stats.connects;
			last_rtimeout = http_context.stats.rtimeout;
			last_idledisc = http_context.stats.idledisc;
			last_lat_sum = http_context.stats.lat_sum;
			last_lat_reqs = http_context.stats.lat_requests;
			max_lat_perm = if http_context.stats.max_lat > max_lat_perm {
				http_context.stats.max_lat
			} else {
				max_lat_perm
			};
		}

		Ok(())
	}

	fn request_log(
		http_context: Arc<RwLock<HttpContext>>,
		http_config: HttpConfig,
	) -> Result<(), Error> {
		let mut log = Log::new();

		let mut header = format!("");
		let len = http_config.request_log_params.len();
		for i in 0..len {
			header = format!(
				"{}{}{}",
				header, http_config.request_log_separator_char, http_config.request_log_params[i],
			);
		}
		header = format!(
			"{}{}{}",
			header, http_config.request_log_separator_char, "ProcTime"
		);
		log.config(
			Some(format!("{}/logs/request.log", http_config.root_dir)),
			http_config.request_log_max_size,
			http_config.request_log_max_age_millis,
			true,
			&header,
			false,
			http_config.delete_request_rotation,
			false,
		)?;

		let len = http_config.request_log_params.len();
		let mut hash_set = HashSet::new();
		let mut header_map = HashMap::new();
		for i in 0..len {
			hash_set.insert(http_config.request_log_params[i].clone());
		}

		let mut to_log;
		loop {
			std::thread::sleep(std::time::Duration::from_millis(100));
			let stop = {
				let mut http_context = nioruntime_util::lockw!(http_context)?;
				to_log = http_context.log_queue.clone();
				(*http_context).log_queue.clear();
				http_context.stop
			};

			for item in to_log {
				if !item.is_async {
					let res =
						Self::log_item(item, &mut log, &hash_set, &http_config, &mut header_map);

					match res {
						Ok(_) => {}
						Err(e) => {
							log_multi!(
								ERROR,
								MAIN_LOG,
								"Unexpected error with request log: {}",
								e.to_string()
							);
						}
					}
				}
			}

			if stop {
				break;
			}

			// check if rotation is needed
			let status = log.rotation_status();
			match status {
				Ok(status) => match status {
					RotationStatus::Needed => match log.rotate() {
						Ok(_) => {
							log_multi!(INFO, MAIN_LOG, "requestlog rotated.");
						}
						Err(e) => {
							log_multi!(
								ERROR,
								MAIN_LOG,
								"Unexpected error with request log rotation: {}",
								e.to_string(),
							);
						}
					},
					RotationStatus::NotNeeded => {}
					RotationStatus::AutoRotated => {
						log_multi!(INFO, MAIN_LOG, "requestlog rotated.");
					}
				},
				Err(e) => {
					log_multi!(
						ERROR,
						MAIN_LOG,
						"Unexpected error with request log rotation: {}",
						e.to_string()
					);
				}
			}

			// check rotation of mainlog:
			let mut rotate_complete = false;
			let mut auto_rotate_complete = false;
			{
				let static_log = &STATIC_LOG;
				let log_map = static_log.lock();

				match log_map {
					Ok(mut log_map) => {
						let log = log_map.get_mut(MAIN_LOG);
						match log {
							Some(log) => {
								match log.rotation_status()? {
									RotationStatus::Needed => match log.rotate() {
										Ok(_) => {
											rotate_complete = true;
										}
										Err(e) => {
											println!("unexpected mainlog err: {}", e.to_string());
										}
									},
									RotationStatus::AutoRotated => {
										auto_rotate_complete = true;
									}
									RotationStatus::NotNeeded => {}
								};
							}
							None => {}
						}
					}
					Err(e) => {
						println!("Unexpected error rotate mainlog: {}", e.to_string());
					}
				}
			}

			if auto_rotate_complete {
				log_multi!(INFO, MAIN_LOG, "mainlog rotated.");
			} else if rotate_complete {
				log_multi!(INFO, MAIN_LOG, "mainlog rotated.");
			}
		}

		Ok(())
	}

	fn log_item(
		item: RequestLogItem,
		log: &mut Log,
		hash_set: &HashSet<String>,
		http_config: &HttpConfig,
		header_map: &mut HashMap<Vec<u8>, Vec<u8>>,
	) -> Result<(), Error> {
		let len = http_config.request_log_params.len();
		let mut log_line = "".to_string();
		if hash_set.get("method").is_some() {
			log_line = format!(
				"{}{}{}",
				log_line,
				http_config.request_log_separator_char,
				if item.method == HttpMethod::Get {
					"GET"
				} else {
					"POST"
				},
			);
		}
		if hash_set.get("uri").is_some() {
			log_line = format!(
				"{}{}{}",
				log_line, http_config.request_log_separator_char, item.uri
			);
		}
		if hash_set.get("query").is_some() {
			log_line = format!(
				"{}{}{}",
				log_line, http_config.request_log_separator_char, item.query
			);
		}

		header_map.clear();
		for header in item.headers {
			header_map.insert(header.0, header.1);
		}

		for i in 0..len {
			let config_name = &http_config.request_log_params[i];
			if config_name != "query" && config_name != "method" && config_name != "uri" {
				let config_value = header_map.get(config_name.as_bytes());
				match config_value {
					Some(config_value) => {
						log_line = format!(
							"{}{}{}",
							log_line,
							http_config.request_log_separator_char,
							std::str::from_utf8(&config_value)?
						);
					}
					None => {
						log_line =
							format!("{}{}", log_line, http_config.request_log_separator_char,);
					}
				}
			}
		}

		if item.elapsed != 0 {
			log_line = format!(
				"{}{}{}ms",
				log_line,
				http_config.request_log_separator_char,
				item.elapsed as f64 / 1_000_000 as f64
			);
		} else {
			log_line = format!("{}{}", log_line, http_config.request_log_separator_char,);
		}

		log.log(&log_line)?;

		Ok(())
	}

	pub fn do_house_keeping(
		http_context: &Arc<RwLock<HttpContext>>,
		http_config: &HttpConfig,
	) -> Result<bool, Error> {
		let mut idledisc_incr = 0;
		let mut rtimeout_incr = 0;

		let mut del_list = vec![];

		{
			let mut varr: Vec<(u128, Arc<RwLock<ConnData>>)> = vec![];
			{
				let http_context = nioruntime_util::lockr!(http_context)?;
				let map = { nioruntime_util::lockr!(http_context.map)? };

				for (k, v) in &*map {
					varr.push((k.clone(), v.clone()));
				}
			}

			let start_time = *START_TIME;
			let since_start = Instant::now().duration_since(start_time);
			let time_now = since_start.as_millis();
			let last_request_timeout = http_config.last_request_timeout;
			let read_timeout = http_config.read_timeout;

			for (k, v) in &varr {
				let (idledisc, rtimeout) =
					match Self::check_idle(time_now, v, last_request_timeout, read_timeout) {
						Ok(x) => x,
						Err(e) => {
							del_list.push(k.clone());
							log_multi!(
							ERROR,
							MAIN_LOG,
							"error in check_idle (possible thread panic) ConnData for {}, err={}",
							k,
							e.to_string(),
						);
							(false, false)
						}
					};

				if idledisc {
					idledisc_incr += 1;
				}
				if rtimeout {
					rtimeout_incr += 1;
				}
			}
		}

		let stop;
		let conn_data_list = {
			let mut ret = vec![];
			let http_context = nioruntime_util::lockr!(http_context)?;
			let mut map = {
				stop = http_context.stop;
				nioruntime_util::lockw!(http_context.map)?
			};
			for d in del_list {
				let conn_data = map.remove(&d);
				ret.push(conn_data);
			}

			ret
		};

		for conn_data in conn_data_list {
			match conn_data {
				Some(conn_data) => {
					Self::close_conn_data(&mut *nioruntime_util::lockw!(conn_data)?, http_config)?;
				}
				None => {}
			}
		}

		if stop {
			return Ok(true);
		}

		if idledisc_incr > 0 || rtimeout_incr > 0 {
			let mut http_context = nioruntime_util::lockw!(http_context)?;
			http_context.stats.idledisc += idledisc_incr;
			http_context.stats.rtimeout += rtimeout_incr;
		}

		match (http_config.on_housekeeper)() {
			Ok(_) => {}
			Err(e) => {
				log_multi!(
					ERROR,
					MAIN_LOG,
					"error in on_housekeeper, err={}",
					e.to_string(),
				);
			}
		}
		Ok(false)
	}

	fn house_keeper(
		http_context: &Arc<RwLock<HttpContext>>,
		http_config: &HttpConfig,
	) -> Result<(), Error> {
		loop {
			std::thread::sleep(std::time::Duration::from_millis(1000));
			if Self::do_house_keeping(http_context, http_config)? {
				break;
			}
		}
		Ok(())
	}

	fn check_idle(
		time_now: u128,
		conn_data: &Arc<RwLock<ConnData>>,
		last_request_timeout: u128,
		read_timeout: u128,
	) -> Result<(bool, bool), Error> {
		let conn_data = conn_data.write().map_err(|e| {
			let conn_data = e.into_inner();

			{
				let state_is_init = {
					match nioruntime_util::lockr!(conn_data.wh.callback_state) {
						Ok(state) => *state == State::Init,
						Err(_) => false,
					}
				};
				if state_is_init {
					let res = Self::write_headers(
						&conn_data.wh,
						&conn_data.config,
						true,
						true,
						false,
						vec![],
						None,
					);
					match res {
						Ok(_) => {}
						Err(e) => {
							log_multi!(ERROR, MAIN_LOG, "error writing headers: {}", e.to_string(),);
						}
					}
				}
			}
			{
				let state_is_headers_chunked = {
					match nioruntime_util::lockr!(conn_data.wh.callback_state) {
						Ok(state) => *state == State::HeadersChunked,
						Err(_) => false,
					}
				};
				if state_is_headers_chunked {
					let byte_msg = format!(
						"</br>{}</br>Internal Server Error. See logs for details.",
						HEADER
					);
					let byte_msg = byte_msg.as_bytes();
					let msg = format!("{:X}\r\n", byte_msg.len());
					let _ = conn_data.wh.write(msg.as_bytes());
					let _ = conn_data.wh.write(&byte_msg);
					let _ = conn_data.wh.write("\r\n0\r\n\r\n".as_bytes());
				} else {
					let res = conn_data
						.wh
						.write("Internal Server Error. See logs for details.".as_bytes());
					match res {
						Ok(_) => {}
						Err(e) => {
							log_multi!(
								ERROR,
								MAIN_LOG,
								"error writing panic message: {}",
								e.to_string(),
							);
						}
					}
				}
			}
			match conn_data.wh.close() {
				Ok(_) => {}
				Err(e) => {
					log_multi!(
						ERROR,
						MAIN_LOG,
						"error closing conn_data from poison error: {}",
						e.to_string(),
					);
				}
			}
			let error: Error =
				ErrorKind::PoisonError(format!("poison error getting conn_data")).into();
			error
		})?;
		let mut idledisc = false;
		let mut rtimeout = false;
		if conn_data.last_request_time != 0
			&& time_now > conn_data.last_request_time // overflow case
			&& time_now - conn_data.last_request_time > last_request_timeout
		{
			conn_data.wh.close()?;
			idledisc = true;
		}

		if conn_data.last_request_time == 0
			&& time_now > conn_data.create_time // overflow case
			&& time_now - conn_data.create_time > read_timeout
		{
			conn_data.wh.close()?;
			rtimeout = true;
		}

		Ok((idledisc, rtimeout))
	}

	fn process_accept(
		http_context: Arc<RwLock<HttpContext>>,
		http_config: HttpConfig,
		id: u128,
		wh: WriteHandle,
	) -> Result<(), Error> {
		let mut http_context = nioruntime_util::lockw!(http_context)?;
		http_context.stats.conns += 1;
		http_context.stats.connects += 1;

		let mut map = nioruntime_util::lockw!(http_context.map)?;

		map.insert(id, Arc::new(RwLock::new(ConnData::new(wh, http_config))));
		Ok(())
	}

	fn process_read(
		http_context: Arc<RwLock<HttpContext>>,
		http_config: HttpConfig,
		buf: &[u8],
		len: usize,
		wh: WriteHandle,
		sha1: Sha1,
	) -> Result<(), Error> {
		let (conn_data, mappings, extensions) = {
			let http_context = nioruntime_util::lockw!(http_context)?;
			let mut map = nioruntime_util::lockw!(http_context.map)?;

			let conn_data = map.get_mut(&wh.get_connection_id());

			match conn_data {
				Some(conn_data) => (
					conn_data.clone(),
					http_context.api_mappings.clone(),
					http_context.api_extensions.clone(),
				),
				None => {
					log_multi!(
						ERROR,
						MAIN_LOG,
						"unexpected error getting ConnData for {}",
						wh.get_connection_id()
					);
					return Err(ErrorKind::InternalError(
						"unexpected error getting ConnData".to_string(),
					)
					.into());
				}
			}
		};

		let log_items = {
			let mut conn_data = nioruntime_util::lockw!(conn_data)?;

			let start_time = *START_TIME;
			let since_start = Instant::now().duration_since(start_time);
			conn_data.last_request_time = since_start.as_millis();

			for i in 0..len {
				conn_data.buffer.push(buf[i]);
			}

			match Self::process_request(
				http_config.clone(),
				&mut conn_data,
				wh,
				mappings,
				extensions,
				&http_config.ws_handler,
				sha1,
			) {
				Ok(log_item) => log_item,
				Err(e) => {
					log_multi!(
						ERROR,
						MAIN_LOG,
						"unexpected error processing request: {}",
						e.to_string()
					);
					vec![]
				}
			}
		};

		{
			let mut http_context = nioruntime_util::lockw!(http_context)?;
			http_context.stats.requests += log_items.len().try_into().unwrap_or(0);
			for item in &log_items {
				if item.elapsed != 0 {
					http_context.stats.lat_requests += 1;
					http_context.stats.lat_sum += item.elapsed;
					if item.elapsed > http_context.stats.max_lat {
						http_context.stats.max_lat = item.elapsed;
					}
				}
			}

			let log_queue = &mut http_context.log_queue;
			if log_queue.len() < http_config.max_log_queue {
				for item in log_items {
					log_queue.push(item);
				}
			} else {
				let start_time = *START_TIME;
				let since_start = Instant::now().duration_since(start_time).as_nanos();
				let diff = since_start - http_context.last_log_queue_overflow_message_time;
				// print this a maximum of once per 5 seconds
				if diff > 5_000_000 {
					log_multi!(
						WARN,
						MAIN_LOG,
						"WARNING: log queue overflow. More than config.max_log_queue={} items queued. Dropping item(s).",
						http_config.max_log_queue,
					);
					http_context.last_log_queue_overflow_message_time =
						Instant::now().duration_since(start_time).as_nanos();
				}
			}
		}

		Ok(())
	}

	fn parse_headers(
		conn_data: &mut ConnData,
		wh: &WriteHandle,
		buffer: Vec<u8>,
		config: &HttpConfig,
		end_buf: &mut usize,
	) -> Result<Option<HeaderInfo>, Error> {
		let connection_id = conn_data.wh.get_connection_id();
		let mut websocket_key = None;

		let len = buffer.len();
		let is_get = match index_of(&HTTP_GET.to_vec(), &buffer[0..4].to_vec()) {
			None => false,
			Some(index) => index == 0,
		};
		let is_post = if is_get {
			false
		} else {
			match index_of(&HTTP_POST.to_vec(), &buffer[0..4].to_vec()) {
				None => false,
				Some(index) => index == 0,
			}
		};

		if !is_get && !is_post {
			// we only support GET/POST for now.
			warn!(
				"invalid request on connection_id = {}, data = '{:?}'",
				connection_id,
				std::str::from_utf8(&conn_data.buffer[0..len]),
			);
			Self::send_bad_request_error(&wh, "Only GET/POST supported")?;
			return Ok(None);
		}
		let method = if is_get {
			HttpMethod::Get
		} else {
			HttpMethod::Post
		};

		let mut space_count = 0;
		let mut uri = vec![];
		let mut http_ver_string = vec![];

		for j in 0..len {
			if conn_data.buffer[j] == ' ' as u8
				|| conn_data.buffer[j] == '\r' as u8
				|| conn_data.buffer[j] == '\n' as u8
			{
				space_count += 1;
			}
			if space_count == 1 {
				if conn_data.buffer[j] != ' ' as u8 {
					uri.push(conn_data.buffer[j]);
				}
			} else if space_count == 2 {
				if conn_data.buffer[j] != ' ' as u8 {
					http_ver_string.push(conn_data.buffer[j]);
				}
			} else if space_count > 2 {
				break;
			}
		}

		let mut keep_alive = false;
		let http_ver_string = std::str::from_utf8(&http_ver_string[..])?;
		let http_version = if http_ver_string == "HTTP/1.1" {
			HttpVersion::V11
		} else if http_ver_string == "HTTP/2.0" {
			HttpVersion::V20
		} else if http_ver_string == "HTTP/1.0" {
			keep_alive = false;
			HttpVersion::V10
		} else {
			// we don't know so go with 0.9 and turn off keep-alive
			keep_alive = false;
			HttpVersion::V09
		};

		// get headers
		let mut nl_count = 0;
		let mut headers_vec = vec![];
		let mut is_websocket = false;
		for j in 0..len {
			if conn_data.buffer[j] == '\n' as u8 {
				nl_count += 1;
				if j + 2 < len
					&& conn_data.buffer[j + 1] == '\r' as u8
					&& conn_data.buffer[j + 2] == '\n' as u8
				{
					break;
				}
				headers_vec.push(vec![]);
			}
			if conn_data.buffer[j] != '\n' as u8 && nl_count > 0 {
				headers_vec[nl_count - 1].push(conn_data.buffer[j]);
			}
		}

		let mut sep_headers_vec = vec![];
		let headers_vec_len = headers_vec.len();
		let mut content_len: usize = 0;
		for j in 0..headers_vec_len {
			let header_j_len = headers_vec[j].len();
			sep_headers_vec.push((vec![], vec![]));
			let mut found_sep = false;
			let mut found_sep_plus_1 = false;
			for k in 0..header_j_len {
				if !found_sep && headers_vec[j][k] == ':' as u8 {
					found_sep = true;
				} else if !found_sep {
					sep_headers_vec[j].0.push(headers_vec[j][k]);
				} else {
					if found_sep_plus_1 {
						if headers_vec[j][k] != '\r' as u8 && headers_vec[j][k] != '\n' as u8 {
							sep_headers_vec[j].1.push(headers_vec[j][k]);
						}
					}
					found_sep_plus_1 = true;
				}
			}

			if sep_headers_vec[j].0 == CONNECTION_HEADER.to_vec() {
				if sep_headers_vec[j].1 == KEEP_ALIVE.to_vec() {
					keep_alive = true;
				}
			} else if sep_headers_vec[j].0 == CONTENT_LENGTH {
				content_len = std::str::from_utf8(&sep_headers_vec[j].1[..])?.parse()?;

				if content_len > config.max_content_length {
					Self::send_bad_request_error(
						&wh,
						&format!(
							"content length exceeded. max = {}, cur = {}",
							config.max_content_length, content_len
						),
					)?;
					return Ok(None);
				}

				*end_buf += content_len;
				if *end_buf >= len {
					// we don't have enough data
					// return here and wait for more
					conn_data.needed_len = *end_buf;
					return Ok(None);
				}
			} else if sep_headers_vec[j].0 == UPGRADE {
				if sep_headers_vec[j].1 == WEBSOCKET {
					is_websocket = true;
				}
			} else if sep_headers_vec[j].0 == WEBSOCKET_KEY {
				websocket_key = Some(std::str::from_utf8(&sep_headers_vec[j].1)?.to_string());
			}
		}

		let mut query_string = vec![];
		let mut uri_path = vec![];
		let mut start_query = false;
		for j in 0..uri.len() {
			if !start_query && uri[j] != '?' as u8 {
				uri_path.push(uri[j]);
			} else if !start_query && uri[j] == '?' as u8 {
				start_query = true;
			} else {
				query_string.push(uri[j]);
			}
		}

		let uri = std::str::from_utf8(&uri_path[..])?.to_string();
		let query = std::str::from_utf8(&query_string[..])?.to_string();

		Ok(Some(HeaderInfo {
			method,
			http_version,
			uri,
			query,
			sep_headers_vec,
			keep_alive,
			content_len,
			is_websocket,
			websocket_key,
		}))
	}

	// try to process a page. If a page was processed return true, otherwise, false.
	fn try_process_page(
		conn_data: &mut RwLockWriteGuard<ConnData>,
		log_vec: &mut Vec<RequestLogItem>,
		config: &HttpConfig,
		mappings: &HashSet<String>,
		extensions: &HashSet<String>,
		wh: &WriteHandle,
		sha1: Sha1,
	) -> Result<bool, Error> {
		let mut page_processed = false;
		let mut end_buf;
		let start_buf;
		let len = conn_data.buffer.len();
		let buffer = conn_data.buffer[0..len].to_vec();
		let end_headers = index_of(&END_HEADERS.to_vec(), &buffer);

		if len < 6 {
			// not enough content
			return Ok(false);
		}

		match end_headers {
			None => {} // do nothing and return, more data needed
			Some(end_headers) => {
				start_buf = end_headers + 4;
				end_buf = end_headers + 3;

				let header_info = Self::parse_headers(conn_data, wh, buffer, config, &mut end_buf)?;

				let header_info = match header_info {
					Some(header_info) => header_info,
					None => {
						return Ok(false);
					}
				};

				if header_info.is_websocket {
					// return false. no page processing follows.
					// and mark the conn_data as websocket
					conn_data.is_websocket = true;
					conn_data.buffer.drain(0..len);

					match header_info.websocket_key {
						Some(ref key) => {
							let key = key.to_string();
							match (config.ws_handler)(
								conn_data,
								WebSocketMessage {
									mtype: WebSocketMessageType::Accept,
									payload: vec![],
									mask: false,
									header_info: Some(header_info),
								},
							)? {
								true => {
									Self::send_websocket_handshake_response(&wh, key, sha1)?;
									// now that it's accepted, send open

									let _ = (config.ws_handler)(
										conn_data,
										WebSocketMessage {
											mtype: WebSocketMessageType::Open,
											payload: vec![],
											mask: false,
											header_info: None,
										},
									);
								}
								false => {
									// if handler returns false, close connection.
									send_websocket_message(
										conn_data,
										&WebSocketMessage {
											mtype: WebSocketMessageType::Close,
											payload: vec![],
											mask: false,
											header_info: None,
										},
									)?;
									Self::send_forbidden(&wh)?;
									conn_data.wh.close()?;
								}
							}
						}
						None => Self::send_bad_request_error(
							&wh,
							&format!("Websocket request had no key"),
						)?,
					}
					return Ok(false);
				}

				// headers process complete we know we have a full page
				page_processed = true;

				if config.debug {
					log_multi!(
						INFO,
						MAIN_LOG,
						"method={:?},uri={},query={}",
						header_info.method,
						header_info.uri,
						header_info.query
					);
				}

				if config.print_headers {
					for header in &header_info.sep_headers_vec {
						let header_name = std::str::from_utf8(&header.0)?;
						let header_value = std::str::from_utf8(&header.1)?;
						log_multi!(INFO, MAIN_LOG, "header[{}] = {}", header_name, header_value,);
					}
				}

				let last_dot = header_info.uri.rfind('.');
				let extension = match last_dot {
					Some(pos) => &header_info.uri[(pos + 1)..],
					None => "",
				}
				.to_lowercase();

				let start_time = *START_TIME;
				let since_start = Instant::now().duration_since(start_time);
				(*conn_data).begin_request_time = since_start.as_nanos();
				if mappings.get(&header_info.uri).is_some() || extensions.get(&extension).is_some()
				{
					{
						let mut callback_state = nioruntime_util::lockw!(wh.callback_state)?;
						*callback_state = State::Init;
					}
					(config.callback)(
						conn_data.is_async.clone(),
						conn_data,
						header_info.content_len != 0,
						start_buf,
						end_buf + 1,
						header_info.method.clone(),
						config.clone(),
						wh.clone(),
						header_info.http_version,
						&header_info.uri,
						&header_info.query,
						header_info.sep_headers_vec.clone(),
						header_info.keep_alive,
					)?;
				} else {
					Self::send_response(
						&config,
						&wh,
						header_info.http_version,
						&header_info.uri,
						header_info.keep_alive,
					)?;
				}

				let elapsed = {
					let is_async = *nioruntime_util::lockr!(conn_data.is_async)?;
					if !is_async {
						let start_time = *START_TIME;
						let since_start = Instant::now().duration_since(start_time).as_nanos();
						let diff = since_start - (*conn_data).begin_request_time;
						(*conn_data).begin_request_time = 0;
						diff
					} else {
						0
					}
				};

				log_vec.push(RequestLogItem::new(
					header_info.uri,
					header_info.query,
					header_info.sep_headers_vec,
					header_info.method,
					elapsed,
					false,
				));

				conn_data.buffer.drain(0..end_buf + 1);
			}
		}

		Ok(page_processed)
	}

	fn process_request(
		config: HttpConfig,
		conn_data: &mut RwLockWriteGuard<ConnData>,
		wh: WriteHandle,
		mappings: HashSet<String>,
		extensions: HashSet<String>,
		ws_handler: &WsHandler,
		sha1: Sha1,
	) -> Result<Vec<RequestLogItem>, Error> {
		if conn_data.is_websocket {
			let is_close = match process_websocket_data(conn_data, ws_handler) {
				Ok(is_closed) => is_closed,
				Err(e) => {
					log_multi!(
						WARN,
						MAIN_LOG,
						"Processing websocket messages generated error: {}",
						e,
					);

					Self::close_conn_data(conn_data, &config)?;

					let close_message = WebSocketMessage {
						mtype: WebSocketMessageType::Close,
						payload: vec![],
						mask: false,
						header_info: None,
					};
					let _ = send_websocket_message(conn_data, &close_message);
					let _ = conn_data.get_wh().close();
					true
				}
			};

			if is_close {
				conn_data.is_closed_websocket = true;
			}

			return Ok(vec![]);
		}

		let mut log_vec = vec![];
		if (*conn_data).begin_request_time != 0 {
			// async request completing
			let start_time = *START_TIME;
			let since_start = Instant::now().duration_since(start_time).as_nanos();
			let diff = since_start - (*conn_data).begin_request_time;
			log_vec.push(RequestLogItem::new(
				"".to_string(),
				"".to_string(),
				vec![],
				HttpMethod::Get,
				diff,
				true,
			));

			(*conn_data).begin_request_time = 0;
		}

		{
			let is_async = *nioruntime_util::lockr!(conn_data.is_async)?;
			if is_async {
				return Ok(log_vec);
			}
		}
		if conn_data.needed_len != 0 && conn_data.buffer.len() < conn_data.needed_len {
			// data not sufficient return and wait for more data
			return Ok(log_vec);
		} else {
			conn_data.needed_len = 0;
		}
		// keep trying to process as many pages as we can with this data.
		loop {
			match Self::try_process_page(
				conn_data,
				&mut log_vec,
				&config,
				&mappings,
				&extensions,
				&wh,
				sha1.clone(),
			) {
				Ok(processed) => {
					if !processed {
						break;
					}
				}
				Err(e) => {
					warn!("An error occurred while processing page: {}", e);
					Self::send_bad_request_error(
						&wh,
						&format!("An error occurred while processing request. See Logs."),
					)?;
					break;
				}
			}

			if *nioruntime_util::lockr!(conn_data.is_async)? {
				break;
			}
		}

		Ok(log_vec)
	}

	fn send_forbidden(wh: &WriteHandle) -> Result<(), Error> {
		let msg = format!("HTTP/1.1 403 Forbidden\r\n\r\n",);
		let response = msg.as_bytes();
		wh.write(response)?;
		Ok(())
	}

	fn send_websocket_handshake_response(
		wh: &WriteHandle,
		key: String,
		mut sha1: Sha1,
	) -> Result<(), Error> {
		let hash = format!("{}{}", key, WEBSOCKET_GUID);
		sha1.update(hash.as_bytes());
		let msg = format!(
			"HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Accept: {}\r\n\r\n",
			base64::encode(&sha1.finalize()[..]),
		);
		let response = msg.as_bytes();
		wh.write(response)?;
		Ok(())
	}

	fn send_bad_request_error(wh: &WriteHandle, message: &str) -> Result<(), Error> {
		let msg = format!(
			"HTTP/1.1 400 Bad Request\r\n\r\nInvalid Request {}.\r\n\r\n",
			message,
		);
		let response = msg.as_bytes();
		wh.write(response)?;
		wh.close()?;
		Ok(())
	}

	fn send_response(
		config: &HttpConfig,
		wh: &WriteHandle,
		_version: HttpVersion,
		uri: &str,
		keep_alive: bool,
	) -> Result<(), Error> {
		let mut path = Self::get_path(config, uri)?;
		let mut is_404 = false;
		let mut found_404_content = true;
		let mut flen = match metadata(path.clone()) {
			Ok(md) => {
				if md.is_dir() {
					path = format!("{}/www{}/index.html", config.root_dir, uri);
					match metadata(path.clone()) {
						Ok(md) => md.len(),
						Err(_) => {
							is_404 = true;
							path = format!("{}/www/404.html", config.root_dir);
							match metadata(path.clone()) {
								Ok(md) => md.len(),
								Err(_) => 0,
							}
						}
					}
				} else {
					md.len()
				}
			}
			Err(_) => {
				// try to return the 404 page.
				is_404 = true;
				path = format!("{}/www/404.html", config.root_dir);
				match metadata(path.clone()) {
					Ok(md) => md.len(),
					Err(_) => {
						found_404_content = false;
						0
					}
				}
			}
		};

		let file = File::open(path.clone());

		match file {
			Ok(mut file) => {
				let buflen = if flen > MAX_CHUNK_SIZE {
					MAX_CHUNK_SIZE
				} else {
					flen
				};

				let mut buf = vec![0; buflen as usize];
				let mut first_loop = true;
				loop {
					let res = file.read(&mut buf);
					match res {
						Ok(amt) => {
							if first_loop {
								Self::write_headers(
									wh,
									config,
									!is_404,
									found_404_content,
									keep_alive,
									vec![],
									None,
								)?;
							}
							if keep_alive {
								let msg_len_bytes = format!("{:X}\r\n", amt);
								let msg_len_bytes = msg_len_bytes.as_bytes();
								wh.write(msg_len_bytes)?;
								wh.write(&buf[0..amt])?;
								if flen <= amt.try_into().unwrap_or(0) {
									wh.write("\r\n0\r\n\r\n".as_bytes())?;
									if !keep_alive {
										wh.close()?;
									}
								} else {
									wh.write("\r\n".as_bytes())?;
								}
							} else {
								if flen <= amt.try_into().unwrap_or(0) {
									wh.write(&buf[0..amt])?;
									if !keep_alive {
										wh.close()?;
									}
								} else {
									wh.write(&buf[0..amt])?;
								}
							}
							flen -= amt.try_into().unwrap_or(0);
						}
						Err(_) => {
							// directory
							Self::write_headers(
								wh,
								config,
								false,
								found_404_content,
								keep_alive,
								vec![],
								None,
							)?;
							break;
						}
					}

					if flen <= 0 {
						break;
					}
					first_loop = false;
				}
			}
			Err(_) => {
				// file not found
				Self::write_headers(
					wh,
					config,
					false,
					found_404_content,
					keep_alive,
					vec![],
					None,
				)?;
			}
		}

		Ok(())
	}

	fn process_close(
		http_context: Arc<RwLock<HttpContext>>,
		http_config: HttpConfig,
		id: u128,
	) -> Result<(), Error> {
		let conn_data = {
			let mut http_context = nioruntime_util::lockw!(http_context)?;
			http_context.stats.conns -= 1;
			let mut map = nioruntime_util::lockw!(http_context.map)?;
			map.remove(&id)
		};

		match conn_data {
			Some(conn_data) => {
				Self::close_conn_data(&mut *nioruntime_util::lockw!(conn_data)?, &http_config)?;
			}
			None => {}
		}

		Ok(())
	}

	fn close_conn_data(conn_data: &mut ConnData, config: &HttpConfig) -> Result<(), Error> {
		if conn_data.is_websocket && !conn_data.is_closed_websocket {
			let close_message = WebSocketMessage {
				mtype: WebSocketMessageType::Close,
				payload: vec![],
				mask: false,
				header_info: None,
			};
			(config.ws_handler)(conn_data, close_message)?;
			conn_data.is_closed_websocket = true;
		}

		Ok(())
	}

	fn build_webroot(root_dir: String) -> Result<(), Error> {
		fsutils::mkdir(&root_dir);
		fsutils::mkdir(&format!("{}/www", root_dir));
		fsutils::mkdir(&format!("{}/logs", root_dir));

		let bytes = include_bytes!("resources/DERP.jpeg");
		match Self::create_file_from_bytes("DERP.jpeg".to_string(), root_dir.clone(), bytes) {
			Ok(_) => {}
			Err(e) => {
				log_multi!(
					ERROR,
					MAIN_LOG,
					"Creating file resulted in error: {}",
					e.to_string()
				);
			}
		}

		let bytes = include_bytes!("resources/index.html");
		match Self::create_file_from_bytes("index.html".to_string(), root_dir.clone(), bytes) {
			Ok(_) => {}
			Err(e) => {
				log_multi!(
					ERROR,
					MAIN_LOG,
					"Creating file resulted in error: {}",
					e.to_string()
				);
			}
		}

		let bytes = include_bytes!("resources/404.html");
		match Self::create_file_from_bytes("404.html".to_string(), root_dir.clone(), bytes) {
			Ok(_) => {}
			Err(e) => {
				log_multi!(
					ERROR,
					MAIN_LOG,
					"Creating file resulted in error: {}",
					e.to_string()
				);
			}
		}

		let bytes = include_bytes!("resources/favicon.ico");
		match Self::create_file_from_bytes("favicon.ico".to_string(), root_dir.clone(), bytes) {
			Ok(_) => {}
			Err(e) => {
				log_multi!(
					ERROR,
					MAIN_LOG,
					"Creating file resulted in error: {}",
					e.to_string()
				);
			}
		}

		let bytes = include_bytes!("resources/favicon-16x16.png");
		match Self::create_file_from_bytes("favicon-16x16.png".to_string(), root_dir.clone(), bytes)
		{
			Ok(_) => {}
			Err(e) => {
				log_multi!(
					ERROR,
					MAIN_LOG,
					"Creating file resulted in error: {}",
					e.to_string()
				);
			}
		}

		let bytes = include_bytes!("resources/favicon-32x32.png");
		match Self::create_file_from_bytes("favicon-32x32.png".to_string(), root_dir.clone(), bytes)
		{
			Ok(_) => {}
			Err(e) => {
				log_multi!(
					ERROR,
					MAIN_LOG,
					"Creating file resulted in error: {}",
					e.to_string()
				);
			}
		}

		let bytes = include_bytes!("resources/about.txt");
		match Self::create_file_from_bytes("about.txt".to_string(), root_dir.clone(), bytes) {
			Ok(_) => {}
			Err(e) => {
				log_multi!(
					ERROR,
					MAIN_LOG,
					"Creating file resulted in error: {}",
					e.to_string()
				);
			}
		}

		let bytes = include_bytes!("resources/android-chrome-192x192.png");
		match Self::create_file_from_bytes(
			"android-chrome-192x192.png".to_string(),
			root_dir.clone(),
			bytes,
		) {
			Ok(_) => {}
			Err(e) => {
				log_multi!(
					ERROR,
					MAIN_LOG,
					"Creating file resulted in error: {}",
					e.to_string()
				);
			}
		}

		let bytes = include_bytes!("resources/android-chrome-512x512.png");
		match Self::create_file_from_bytes(
			"android-chrome-512x512.png".to_string(),
			root_dir.clone(),
			bytes,
		) {
			Ok(_) => {}
			Err(e) => {
				log_multi!(
					ERROR,
					MAIN_LOG,
					"Creating file resulted in error: {}",
					e.to_string()
				);
			}
		}

		let bytes = include_bytes!("resources/apple-touch-icon.png");
		match Self::create_file_from_bytes(
			"apple-touch-icon.png".to_string(),
			root_dir.clone(),
			bytes,
		) {
			Ok(_) => {}
			Err(e) => {
				log_multi!(
					ERROR,
					MAIN_LOG,
					"Creating file resulted in error: {}",
					e.to_string()
				);
			}
		}

		let bytes = include_bytes!("resources/lettherebebitcom.png");
		match Self::create_file_from_bytes(
			"lettherebebitcom.png".to_string(),
			root_dir.clone(),
			bytes,
		) {
			Ok(_) => {}
			Err(e) => {
				log_multi!(
					ERROR,
					MAIN_LOG,
					"Creating file resulted in error: {}",
					e.to_string()
				);
			}
		}

		Ok(())
	}
}

#[test]
fn test_index_of() -> Result<(), Error> {
	assert_eq!(index_of(&vec![2, 3, 4], &vec![0, 1, 2, 3, 4, 5]), Some(2));
	assert_eq!(
		index_of(&vec![9, 9], &vec![0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10]),
		None
	);
	assert_eq!(
		index_of(
			&vec![99, 23, 28, 4, 3, 2, 1, 0, 1, 2, 3, 4],
			&vec![0, 1, 2, 3, 99, 23, 28, 4, 3, 2, 1, 0, 1, 2, 3, 4, 2, 2, 2, 3, 4]
		),
		Some(4)
	);
	Ok(())
}
