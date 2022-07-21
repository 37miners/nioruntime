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

use crate::data::HttpData;
use crate::data::STAT_RECORD_PREFIX;
use crate::data::USER_RECORD_PREFIX;
use crate::types::LogEvent;
use crate::types::{HttpMethod, HttpVersion};
use nioruntime_deps::dirs;
use nioruntime_deps::jemalloc_ctl::{epoch, stats};
use nioruntime_deps::path_clean::clean as path_clean;
use nioruntime_derive::Serializable;
use nioruntime_err::Error;
use nioruntime_err::ErrorKind;
use nioruntime_log::*;
use nioruntime_util::lmdb::Store;
use nioruntime_util::misc::invert_timestamp128;
use nioruntime_util::ser::BinReader;
use nioruntime_util::ser::Serializable;
use nioruntime_util::ser::{Reader, Writer};
use nioruntime_util::StaticQueue;
use std::collections::HashMap;
use std::convert::TryInto;
use std::fmt::Debug;
use std::fmt::Formatter;
use std::io::Cursor;
use std::path::PathBuf;
use std::sync::Arc;
use std::sync::RwLock;
use std::time::Instant;
use std::time::{SystemTime, UNIX_EPOCH};

info!();

pub const MAX_LOG_STR_LEN: usize = 128;
pub const MAX_USER_MATCHES: usize = 10;
pub const LOG_ITEM_SIZE: usize = MAX_LOG_STR_LEN * 5 + (1 + MAX_USER_MATCHES) * 8 + 28;

#[derive(Clone, Debug, Copy)]
pub struct LogItem {
	pub http_method: HttpMethod,
	pub http_version: HttpVersion,
	pub uri_requested: [u8; MAX_LOG_STR_LEN],
	pub uri: [u8; MAX_LOG_STR_LEN],
	pub query: [u8; MAX_LOG_STR_LEN],
	pub user_agent: [u8; MAX_LOG_STR_LEN],
	pub referer: [u8; MAX_LOG_STR_LEN],
	pub content_len: u64,
	pub start_micros: u64,
	pub end_micros: u64,
	pub response_code: u16,
	pub match_count: usize,
	pub matches: [u64; MAX_USER_MATCHES],
}

impl Default for LogItem {
	fn default() -> Self {
		Self {
			http_method: HttpMethod::Get,
			http_version: HttpVersion::V11,
			uri_requested: [0u8; MAX_LOG_STR_LEN],
			uri: [0u8; MAX_LOG_STR_LEN],
			query: [0u8; MAX_LOG_STR_LEN],
			user_agent: [0u8; MAX_LOG_STR_LEN],
			referer: [0u8; MAX_LOG_STR_LEN],
			content_len: 0,
			start_micros: 0,
			end_micros: 0,
			response_code: 0,
			match_count: 0,
			matches: [0u64; MAX_USER_MATCHES],
		}
	}
}

impl Serializable for LogItem {
	fn read<R>(reader: &mut R) -> Result<Self, Error>
	where
		R: Reader,
	{
		let http_method = match reader.read_u8()? {
			0 => HttpMethod::Get,
			1 => HttpMethod::Post,
			2 => HttpMethod::Put,
			3 => HttpMethod::Delete,
			4 => HttpMethod::Head,
			5 => HttpMethod::Options,
			6 => HttpMethod::Connect,
			7 => HttpMethod::Patch,
			_ => HttpMethod::Trace,
		};

		let http_version = match reader.read_u8()? {
			1 => HttpVersion::V10,
			2 => HttpVersion::V11,
			3 => HttpVersion::V20,
			_ => HttpVersion::Unknown,
		};

		let content_len = reader.read_u64()?;
		let start_micros = reader.read_u64()?;
		let end_micros = reader.read_u64()?;
		let response_code = reader.read_u16()?;

		let mut uri = [0u8; MAX_LOG_STR_LEN];
		for i in 0..MAX_LOG_STR_LEN {
			uri[i] = reader.read_u8()?;
		}

		let mut query = [0u8; MAX_LOG_STR_LEN];
		for i in 0..MAX_LOG_STR_LEN {
			query[i] = reader.read_u8()?;
		}

		let mut user_agent = [0u8; MAX_LOG_STR_LEN];
		for i in 0..MAX_LOG_STR_LEN {
			user_agent[i] = reader.read_u8()?;
		}

		let mut referer = [0u8; MAX_LOG_STR_LEN];
		for i in 0..MAX_LOG_STR_LEN {
			referer[i] = reader.read_u8()?;
		}

		let mut uri_requested = [0u8; MAX_LOG_STR_LEN];
		for i in 0..MAX_LOG_STR_LEN {
			uri_requested[i] = reader.read_u8()?;
		}

		let match_count = reader.read_u64()? as usize;
		let mut matches = [064; MAX_USER_MATCHES];
		for i in 0..MAX_USER_MATCHES {
			matches[i] = reader.read_u64()?;
		}

		Ok(Self {
			http_method,
			http_version,
			content_len,
			start_micros,
			end_micros,
			query,
			uri,
			user_agent,
			referer,
			uri_requested,
			response_code,
			match_count,
			matches,
		})
	}
	fn write<W>(&self, writer: &mut W) -> Result<(), Error>
	where
		W: Writer,
	{
		match self.http_method {
			HttpMethod::Get => writer.write_u8(0)?,
			HttpMethod::Post => writer.write_u8(1)?,
			HttpMethod::Put => writer.write_u8(2)?,
			HttpMethod::Delete => writer.write_u8(3)?,
			HttpMethod::Head => writer.write_u8(4)?,
			HttpMethod::Options => writer.write_u8(5)?,
			HttpMethod::Connect => writer.write_u8(6)?,
			HttpMethod::Patch => writer.write_u8(7)?,
			HttpMethod::Trace => writer.write_u8(8)?,
		}
		match self.http_version {
			HttpVersion::Unknown => writer.write_u8(0)?,
			HttpVersion::V10 => writer.write_u8(1)?,
			HttpVersion::V11 => writer.write_u8(2)?,
			HttpVersion::V20 => writer.write_u8(3)?,
		}

		writer.write_u64(self.content_len)?;
		writer.write_u64(self.start_micros)?;
		writer.write_u64(self.end_micros)?;
		writer.write_u16(self.response_code)?;

		for i in 0..MAX_LOG_STR_LEN {
			writer.write_u8(self.uri[i])?;
		}

		for i in 0..MAX_LOG_STR_LEN {
			writer.write_u8(self.query[i])?;
		}

		for i in 0..MAX_LOG_STR_LEN {
			writer.write_u8(self.user_agent[i])?;
		}

		for i in 0..MAX_LOG_STR_LEN {
			writer.write_u8(self.referer[i])?;
		}

		for i in 0..MAX_LOG_STR_LEN {
			writer.write_u8(self.uri_requested[i])?;
		}

		writer.write_u64(self.match_count.try_into()?)?;

		for i in 0..MAX_USER_MATCHES {
			writer.write_u64(self.matches[i])?;
		}

		Ok(())
	}
}

impl LogItem {
	pub fn overwrite(
		&mut self,
		http_method: HttpMethod,
		http_version: HttpVersion,
		uri_requested: [u8; MAX_LOG_STR_LEN],
		uri: [u8; MAX_LOG_STR_LEN],
		query: [u8; MAX_LOG_STR_LEN],
		user_agent: [u8; MAX_LOG_STR_LEN],
		referer: [u8; MAX_LOG_STR_LEN],
		content_len: u64,
		start_micros: u64,
		end_micros: u64,
		response_code: u16,
		match_count: usize,
		matches: [u64; MAX_USER_MATCHES],
	) -> Result<(), Error> {
		self.http_method = http_method;
		self.http_version = http_version;
		self.uri_requested = uri_requested;
		self.user_agent = user_agent;
		self.uri = uri;
		self.query = query;
		self.referer = referer;
		self.content_len = content_len;
		self.start_micros = start_micros;
		self.end_micros = end_micros;
		self.response_code = response_code;
		self.match_count = match_count;
		self.matches = matches;
		Ok(())
	}

	pub fn write(&self, buf: &mut [u8; LOG_ITEM_SIZE]) -> Result<(), Error> {
		match self.http_method {
			HttpMethod::Get => buf[0] = 0,
			HttpMethod::Post => buf[0] = 1,
			HttpMethod::Put => buf[0] = 2,
			HttpMethod::Delete => buf[0] = 3,
			HttpMethod::Head => buf[0] = 4,
			HttpMethod::Options => buf[0] = 5,
			HttpMethod::Connect => buf[0] = 6,
			HttpMethod::Patch => buf[0] = 7,
			HttpMethod::Trace => buf[0] = 8,
		}
		match self.http_version {
			HttpVersion::Unknown => buf[1] = 0,
			HttpVersion::V10 => buf[1] = 1,
			HttpVersion::V11 => buf[1] = 2,
			HttpVersion::V20 => buf[1] = 3,
		}
		buf[2..10].clone_from_slice(&self.content_len.to_be_bytes()[..]);
		buf[10..18].clone_from_slice(&self.start_micros.to_be_bytes()[..]);
		buf[18..26].clone_from_slice(&self.end_micros.to_be_bytes()[..]);
		buf[26..28].clone_from_slice(&self.response_code.to_be_bytes()[..]);
		buf[28..28 + MAX_LOG_STR_LEN].clone_from_slice(&self.uri[..]);
		buf[28 + MAX_LOG_STR_LEN..28 + MAX_LOG_STR_LEN * 2].clone_from_slice(&self.query[..]);
		buf[28 + MAX_LOG_STR_LEN * 2..28 + MAX_LOG_STR_LEN * 3]
			.clone_from_slice(&self.user_agent[..]);
		buf[28 + MAX_LOG_STR_LEN * 3..28 + MAX_LOG_STR_LEN * 4].clone_from_slice(&self.referer[..]);
		buf[28 + MAX_LOG_STR_LEN * 4..28 + MAX_LOG_STR_LEN * 5]
			.clone_from_slice(&self.uri_requested[..]);
		buf[28 + MAX_LOG_STR_LEN * 5..36 + MAX_LOG_STR_LEN * 5]
			.clone_from_slice(&self.match_count.to_be_bytes()[..]);
		let max = if self.match_count > MAX_USER_MATCHES {
			MAX_USER_MATCHES
		} else {
			self.match_count
		};
		for i in 0..max {
			buf[36 + MAX_LOG_STR_LEN * 5 + i * 8..44 + MAX_LOG_STR_LEN * 5 + i * 8]
				.clone_from_slice(&self.matches[i].to_be_bytes()[..]);
		}
		Ok(())
	}

	pub fn read(&mut self, buf: &[u8; LOG_ITEM_SIZE]) -> Result<(), Error> {
		self.http_method = match buf[0] {
			0 => HttpMethod::Get,
			1 => HttpMethod::Post,
			2 => HttpMethod::Put,
			3 => HttpMethod::Delete,
			4 => HttpMethod::Head,
			5 => HttpMethod::Options,
			6 => HttpMethod::Connect,
			7 => HttpMethod::Patch,
			_ => HttpMethod::Trace,
		};

		self.http_version = match buf[1] {
			1 => HttpVersion::V10,
			2 => HttpVersion::V11,
			3 => HttpVersion::V20,
			_ => HttpVersion::Unknown,
		};

		self.content_len = u64::from_be_bytes(buf[2..10].try_into()?);
		self.start_micros = u64::from_be_bytes(buf[10..18].try_into()?);
		self.end_micros = u64::from_be_bytes(buf[18..26].try_into()?);
		self.response_code = u16::from_be_bytes(buf[26..28].try_into()?);
		self.uri[..].clone_from_slice(&buf[28..28 + MAX_LOG_STR_LEN]);
		self.query[..].clone_from_slice(&buf[28 + MAX_LOG_STR_LEN..28 + MAX_LOG_STR_LEN * 2]);
		self.user_agent[..]
			.clone_from_slice(&buf[28 + MAX_LOG_STR_LEN * 2..28 + MAX_LOG_STR_LEN * 3]);
		self.referer[..].clone_from_slice(&buf[28 + MAX_LOG_STR_LEN * 3..28 + MAX_LOG_STR_LEN * 4]);
		self.uri_requested[..]
			.clone_from_slice(&buf[28 + MAX_LOG_STR_LEN * 4..28 + MAX_LOG_STR_LEN * 5]);
		self.match_count =
			u64::from_be_bytes(buf[28 + MAX_LOG_STR_LEN * 5..36 + MAX_LOG_STR_LEN * 5].try_into()?)
				as usize;
		for i in 0..self.match_count {
			self.matches[i] = u64::from_be_bytes(
				buf[36 + MAX_LOG_STR_LEN * 5 + i * 8..44 + MAX_LOG_STR_LEN * 5 + i * 8]
					.try_into()?,
			);
		}
		Ok(())
	}
}

#[derive(Clone)]
pub struct HttpStatsConfig {
	pub request_log_config: LogConfig,
	pub stats_frequency: u64,
	pub debug_log_queue: bool,
	pub debug_show_stats: bool,
}

#[derive(Clone, Debug, Serializable)]
pub struct StatRecord {
	pub requests: u64,
	pub dropped_log: u64,
	pub conns: u64,
	pub connects: u64,
	pub disconnects: u64,
	pub connect_timeouts: u64,
	pub read_timeouts: u64,
	pub timestamp: u128,
	pub prev_timestamp: u128,
	pub startup_time: u128,
	pub lat_sum_micros: u64,
	pub memory_bytes: u64,
}

impl StatRecord {
	fn new(startup_time: u128) -> Self {
		Self {
			requests: 0,
			dropped_log: 0,
			conns: 0,
			connects: 0,
			disconnects: 0,
			connect_timeouts: 0,
			read_timeouts: 0,
			timestamp: 0,
			prev_timestamp: 0,
			startup_time,
			lat_sum_micros: 0,
			memory_bytes: 0,
		}
	}

	fn reset(&mut self) -> Result<(), Error> {
		self.requests = 0;
		self.dropped_log = 0;
		self.connects = 0;
		self.disconnects = 0;
		self.connect_timeouts = 0;
		self.read_timeouts = 0;
		self.prev_timestamp = self.timestamp;
		self.lat_sum_micros = 0;
		self.memory_bytes = 0;
		Ok(())
	}

	pub fn get_bytes(&self) -> Vec<u8> {
		let mut ret = vec![];
		ret.append(&mut self.requests.to_be_bytes().to_vec());
		ret.append(&mut self.dropped_log.to_be_bytes().to_vec());
		ret.append(&mut self.conns.to_be_bytes().to_vec());
		ret.append(&mut self.connects.to_be_bytes().to_vec());
		ret.append(&mut self.disconnects.to_be_bytes().to_vec());
		ret.append(&mut self.connect_timeouts.to_be_bytes().to_vec());
		ret.append(&mut self.read_timeouts.to_be_bytes().to_vec());
		ret.append(&mut (self.timestamp as u64).to_be_bytes().to_vec());
		ret.append(&mut (self.prev_timestamp as u64).to_be_bytes().to_vec());
		ret.append(&mut (self.startup_time as u64).to_be_bytes().to_vec());
		ret.append(&mut (self.lat_sum_micros as u64).to_be_bytes().to_vec());
		ret.append(&mut (self.memory_bytes as u64).to_be_bytes().to_vec());
		ret
	}
}

#[derive(Clone)]
pub struct HttpStats {
	config: HttpStatsConfig,
	db: HttpData,
	request_log: Arc<RwLock<Log>>,
	_startup_time: u128,
	stat_record_accumulator: Arc<RwLock<StatRecord>>,
	user_match_accumulator: Arc<RwLock<HashMap<u64, u64>>>,
	recent_requests: Arc<RwLock<StaticQueue<LogItem>>>,
}

impl Debug for HttpStats {
	fn fmt(&self, _: &mut Formatter<'_>) -> Result<(), std::fmt::Error> {
		Ok(())
	}
}

// stats data schema:
// prefix of 0 - sever start timestamps
// prefix of 1 - stats entries (every 5 seconds (configurable)) requests, dropped log, conns
// starting, connects, disconnects, connect_timeout, read_timeouts, server start timestamp to
// link back, timestamp, prev_timestamp
impl HttpStats {
	pub fn new(config: HttpStatsConfig, db: HttpData) -> Result<Self, Error> {
		let mut request_log_config = config.request_log_config.clone();
		let home_dir = match dirs::home_dir() {
			Some(p) => p,
			None => PathBuf::new(),
		}
		.as_path()
		.display()
		.to_string();

		if request_log_config.file_path.is_none() {
			return Err(ErrorKind::LogConfigurationError(
				"filepath must be specified for request_log".to_string(),
			)
			.into());
		}

		request_log_config.file_path = Some(
			request_log_config
				.file_path
				.unwrap()
				.replace("~", &home_dir),
		);
		request_log_config.file_path = Some(path_clean(&request_log_config.file_path.unwrap()));

		let mut log = Log::new();

		log.init(request_log_config)?;
		let request_log = Arc::new(RwLock::new(log));

		let startup_time = SystemTime::now().duration_since(UNIX_EPOCH)?.as_millis();

		// insert our time into the db.
		{
			let db = lockw!(db.db())?;
			let batch = (*db).batch()?;
			let mut timestamp_bytes = vec![];
			timestamp_bytes.push(0);
			for b in startup_time.to_be_bytes() {
				timestamp_bytes.push(b);
			}

			batch.put(&timestamp_bytes, b"")?;

			batch.commit()?;
		}

		if config.debug_show_stats {
			let db = lockw!(db.db())?;
			let batch = (*db).batch()?;
			let mut itt = batch.iter(&([0u8])[..], |k, _v| {
				Ok(u128::from_be_bytes(k[1..17].try_into()?))
			})?;

			warn!("timestamps:")?;
			let mut count = 0;
			loop {
				match itt.next() {
					Some(timestamp) => warn!("timestamp[{}] = {}", count, timestamp)?,
					None => break,
				}
				count += 1;

				if count > 10 {
					// only show first 10
					break;
				}
			}
		}

		if config.debug_show_stats {
			let db = lockw!(db.db())?;
			let batch = (*db).batch()?;
			let mut itt = batch.iter(&([STAT_RECORD_PREFIX])[..], |_k, v| {
				let mut cursor = Cursor::new(v.to_vec());
				cursor.set_position(0);
				let mut reader = BinReader::new(&mut cursor);
				Ok(StatRecord::read(&mut reader)?)
			})?;

			let mut count = 0;
			warn!("records: ")?;
			loop {
				match itt.next() {
					Some(record) => warn!("record[{}] = {:?}", count, record)?,
					None => break,
				}
				count += 1;

				if count > 10 {
					// only show first 10
					break;
				}
			}
		}

		let stat_record_accumulator = Arc::new(RwLock::new(StatRecord::new(startup_time)));
		let user_match_accumulator = Arc::new(RwLock::new(HashMap::new()));

		Self::start_stats_thread(
			&stat_record_accumulator,
			&user_match_accumulator,
			&db.db(),
			&config,
		)?;

		let recent_requests = Arc::new(RwLock::new(StaticQueue::new(100)));

		Ok(Self {
			config,
			db,
			request_log,
			_startup_time: startup_time,
			stat_record_accumulator,
			user_match_accumulator,
			recent_requests,
		})
	}

	pub fn start_stats_thread(
		stat_record_accumulator: &Arc<RwLock<StatRecord>>,
		user_match_accumulator: &Arc<RwLock<HashMap<u64, u64>>>,
		db: &Arc<RwLock<Store>>,
		config: &HttpStatsConfig,
	) -> Result<(), Error> {
		let stat_record_accumulator = stat_record_accumulator.clone();
		let user_match_accumulator = user_match_accumulator.clone();
		let db = db.clone();
		let config = config.clone();

		std::thread::spawn(move || -> Result<(), Error> {
			let mut elapsed = 0u64;
			loop {
				std::thread::sleep(std::time::Duration::from_millis(
					config.stats_frequency.saturating_sub(elapsed),
				));
				let start = Instant::now();
				match Self::process_stats(
					&stat_record_accumulator,
					&user_match_accumulator,
					&db,
					&config,
				) {
					Ok(_) => {}
					Err(e) => {
						warn!("Stats processing generated error: {}", e)?;
					}
				}

				if false {
					break;
				}
				elapsed = start.elapsed().as_millis().try_into().unwrap_or(0);
			}
			Ok(())
		});

		Ok(())
	}

	pub fn process_stats(
		stat_record_accumulator: &Arc<RwLock<StatRecord>>,
		user_match_accumulator: &Arc<RwLock<HashMap<u64, u64>>>,
		db: &Arc<RwLock<Store>>,
		config: &HttpStatsConfig,
	) -> Result<(), Error> {
		let e = epoch::mib().unwrap();
		e.advance().unwrap();
		let allocated = stats::allocated::mib().unwrap();
		let bytes = allocated.read().unwrap() as u64;
		let stat_record_accumulator = {
			let mut stat_record_accumulator = lockw!(stat_record_accumulator)?;
			if (*stat_record_accumulator).timestamp == 0 {
				(*stat_record_accumulator).prev_timestamp = (*stat_record_accumulator).startup_time;
			}
			(*stat_record_accumulator).timestamp =
				SystemTime::now().duration_since(UNIX_EPOCH)?.as_millis();
			let mut ret = (*stat_record_accumulator).clone();
			ret.memory_bytes = bytes;
			(*stat_record_accumulator).reset()?;
			ret
		};

		let user_match_accumulator = {
			let mut user_match_accumulator = lockw!(user_match_accumulator)?;
			let ret = (*user_match_accumulator).clone();
			(*user_match_accumulator).clear();
			ret
		};

		if config.debug_show_stats {
			warn!(
				"stats = {:?}, user_matches = {:?}",
				stat_record_accumulator, user_match_accumulator
			)?;
		}

		let mut stat_record_key = vec![];
		stat_record_key.push(STAT_RECORD_PREFIX);
		let timestamp = invert_timestamp128(stat_record_accumulator.timestamp);
		stat_record_key.append(&mut timestamp.to_be_bytes().to_vec());

		{
			let db = lockw!(db)?;
			let batch = db.batch()?;
			batch.put_ser(&stat_record_key, &stat_record_accumulator)?;

			for (k, v) in user_match_accumulator {
				let mut user_record_key = vec![];
				user_record_key.push(USER_RECORD_PREFIX);
				user_record_key.append(&mut k.to_be_bytes().to_vec());
				user_record_key.append(&mut timestamp.to_be_bytes().to_vec());
				let user_record_value = v.to_be_bytes().to_vec();
				batch.put_ser(&user_record_key, &user_record_value)?;
			}

			batch.commit()?;
		}

		Ok(())
	}

	pub fn from_utf8(b: &[u8]) -> &str {
		let mut end = 0;
		for i in 0..b.len() {
			if b[i] == 0 {
				end = i;
				break;
			}
		}

		if end > 0 {
			match std::str::from_utf8(&b[0..end]) {
				Ok(b) => b,
				Err(_) => "Unknown - non-utf8",
			}
		} else {
			""
		}
	}

	pub fn store_log_items<I, J>(&mut self, log_items: I, log_events: J) -> Result<(), Error>
	where
		I: Iterator<Item = LogItem>,
		J: Iterator<Item = LogEvent>,
	{
		let mut logger = lockw!(self.request_log)?;
		if logger.rotation_status()? == RotationStatus::Needed {
			match logger.rotate()? {
				Some(rot_file) => {
					info!("Request log rotated. [{}]", rot_file)?;
				}
				None => {
					warn!("Request log rotation not needed, when expected to need.")?;
				}
			}
		}

		let mut requests: u64 = 0;
		let mut lat_sum_micros = 0;

		let mut recent_requests = lockw!(self.recent_requests)?;
		for log_item in log_items {
			if recent_requests.size() == recent_requests.capacity() {
				recent_requests.dequeue()?;
			}
			recent_requests.enqueue(log_item)?;
			requests += 1;
			let uri = Self::from_utf8(&log_item.uri);
			let query = Self::from_utf8(&log_item.query);
			let user_agent = Self::from_utf8(&log_item.user_agent);
			let referer = Self::from_utf8(&log_item.referer);
			let uri_requested = Self::from_utf8(&log_item.uri_requested);
			let micro_diff = log_item.end_micros.saturating_sub(log_item.start_micros);
			lat_sum_micros += micro_diff;
			let response_code = log_item.response_code;

			let mut match_string = String::new();
			for i in 0..log_item.match_count {
				let match_id = log_item.matches[i];
				match_string.push_str(&format!("{}", match_id).to_string());
				if i < log_item.match_count.saturating_sub(1) {
					match_string.push(',');
				}
			}

			logger.log(
				INFO,
				&format!(
					"{}|{}|{}|{}|{}|{}|{}|{}|{}",
					log_item.http_method,
					uri,
					uri_requested,
					query,
					user_agent,
					referer,
					micro_diff,
					response_code,
					match_string,
				)[..],
			)?;
		}

		let mut drop_count = 0;
		let mut connects = 0;
		let mut disconnects = 0;
		let mut read_timeouts = 0;
		let mut connect_timeouts = 0;
		{
			let mut user_match_accumulator = lockw!(self.user_match_accumulator)?;
			for log_event in log_events {
				drop_count += log_event.dropped_count;
				connects += log_event.connect_count;
				disconnects += log_event.disconnect_count;
				read_timeouts += log_event.read_timeout_count;
				connect_timeouts += log_event.connect_timeout_count;
				lat_sum_micros += log_event.dropped_lat_sum;
				for (id, count) in log_event.user_matches {
					let create_entry = match (*user_match_accumulator).get_mut(&id) {
						Some(match_count_cur) => {
							*match_count_cur += count;
							false
						}
						None => true,
					};

					if create_entry {
						(*user_match_accumulator).insert(id, count);
					}
				}
			}
		}

		if drop_count > 0 && self.config.debug_log_queue {
			warn!("Log drop {} items", drop_count)?;
		}

		requests += drop_count;

		{
			let mut stat_record_accumulator = lockw!(self.stat_record_accumulator)?;
			(*stat_record_accumulator).dropped_log += drop_count;
			(*stat_record_accumulator).connects += connects;
			(*stat_record_accumulator).disconnects += disconnects;
			(*stat_record_accumulator).read_timeouts += read_timeouts;
			(*stat_record_accumulator).connect_timeouts += connect_timeouts;
			(*stat_record_accumulator).requests += requests;
			(*stat_record_accumulator).conns += connects;
			(*stat_record_accumulator).conns =
				(*stat_record_accumulator).conns.saturating_sub(disconnects);
			(*stat_record_accumulator).lat_sum_micros += lat_sum_micros;
		}

		Ok(())
	}

	pub fn get_recent_requests(&self) -> Result<Vec<LogItem>, Error> {
		let mut ret = vec![];
		let recent_requests = lockw!(self.recent_requests)?;
		for request in &*recent_requests {
			ret.push(request);
		}
		Ok(ret)
	}

	pub fn get_stats_aggregation_after(
		&self,
		timestamp: u64,
		quantity: u64,
	) -> Result<Vec<StatRecord>, Error> {
		let db = lockw!(self.db.db())?;
		let batch = db.batch()?;

		let mut itt = batch.iter(&([STAT_RECORD_PREFIX])[..], |_k, v| {
			let mut cursor = Cursor::new(v.to_vec());
			cursor.set_position(0);
			let mut reader = BinReader::new(&mut cursor);
			Ok(StatRecord::read(&mut reader)?)
		})?;

		let mut count = 0;
		let mut ret = vec![];
		loop {
			match itt.next() {
				Some(record) => {
					if count >= quantity {
						break;
					}

					if record.timestamp < timestamp.into() {
						ret.push(record);
						count += 1;
					}
				}
				None => break,
			}
		}

		Ok(ret)
	}

	pub fn get_stats_aggregation(
		&self,
		offset_start: u64,
		offset_end: u64,
	) -> Result<Vec<StatRecord>, Error> {
		let db = lockw!(self.db.db())?;
		let batch = db.batch()?;

		let mut itt = batch.iter(&([STAT_RECORD_PREFIX])[..], |_k, v| {
			let mut cursor = Cursor::new(v.to_vec());
			cursor.set_position(0);
			let mut reader = BinReader::new(&mut cursor);
			Ok(StatRecord::read(&mut reader)?)
		})?;

		let mut count = 0;
		let mut ret = vec![];
		loop {
			match itt.next() {
				Some(record) => {
					if count > offset_end {
						break;
					}
					if count >= offset_start {
						ret.push(record);
					}
				}
				None => break,
			}
			count += 1;
		}
		Ok(ret)
	}
}
