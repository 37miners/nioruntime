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
use crate::data::RULE_PREFIX;
use crate::data::STAT_RECORD_PREFIX;
use crate::data::USER_RECORD_PREFIX;
use crate::stats::HttpStats;
use crate::stats::StatRecord;
use crate::stats::LOG_ITEM_SIZE;
use crate::websocket::{WebSocketMessage, WebSocketMessageType};
use nioruntime_deps::rand;
use nioruntime_derive::Serializable;
use nioruntime_err::{Error, ErrorKind};
use nioruntime_log::*;
use nioruntime_util::misc::invert_timestamp128;
use nioruntime_util::multi_match::Dictionary;
use nioruntime_util::multi_match::Pattern;
use nioruntime_util::ser::{serialize, BinReader, Serializable};
use nioruntime_util::ser::{Reader, Writer};
use nioruntime_util::StaticHash;
use std::cmp::Ordering;
use std::collections::{HashMap, HashSet};
use std::convert::TryInto;
use std::io::Cursor;
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

warn!();

const WS_ADMIN_GET_STATS_REQUEST: u8 = 0u8;
const WS_ADMIN_GET_STATS_RESPONSE: u8 = 0u8;
const WS_ADMIN_PING: u8 = 1u8;
const WS_ADMIN_PONG: u8 = 1u8;
const WS_ADMIN_GET_STATS_AFTER_TIMESTAMP_REQUEST: u8 = 2u8;
const WS_ADMIN_GET_RECENT_REQUESTS: u8 = 3u8;
const WS_ADMIN_RECENT_REQUESTS_RESPONSE: u8 = 3u8;
const WS_ADMIN_REQUEST_CHART_REQUEST: u8 = 4u8;
const WS_ADMIN_REQUEST_CHART_RESPONSE: u8 = 4u8;

const WS_ADMIN_CREATE_RULE: u8 = 9u8;
const WS_ADMIN_CREATE_RULE_RESPONSE: u8 = 9u8;
const WS_ADMIN_GET_RULES: u8 = 10u8;
const WS_ADMIN_GET_RULES_RESPONSE: u8 = 10u8;
const WS_ADMIN_SET_ACTIVE_RULES: u8 = 12u8;
const WS_ADMIN_SET_ACTIVE_RULES_RESPONSE: u8 = 12u8;
const WS_ADMIN_DELETE_RULE: u8 = 13u8;
const WS_ADMIN_DELETE_RULE_RESPONSE: u8 = 13u8;
const WS_ADMIN_GET_DATA: u8 = 14u8;
const WS_ADMIN_GET_DATA_RESPONSE: u8 = 14u8;
const WS_ADMIN_ERROR_REPLY: u8 = 15u8;

const RULE_TYPE_AND: u8 = 1;
const RULE_TYPE_OR: u8 = 2;
const RULE_TYPE_NOT: u8 = 3;
const RULE_TYPE_PATTERN: u8 = 4;

#[derive(Debug, Serializable, Clone)]
pub struct FunctionalRule {
	pub id: u64,
	pub rule: Rule,
	pub is_active: bool,
	pub label: String,
}

impl FunctionalRule {
	pub fn get_all_patterns(&self) -> Result<Vec<&Pattern>, Error> {
		self.rule.get_all_patterns()
	}

	pub fn evaluate(&self, patterns: &StaticHash<(), ()>) -> Result<bool, Error> {
		self.rule.evaluate(patterns)
	}

	pub fn id(&self) -> u64 {
		self.id
	}

	pub fn label(&self) -> &String {
		&self.label
	}
}

#[derive(Debug, PartialEq, Clone, Ord, Eq, PartialOrd)]
pub enum Rule {
	And(Vec<Rule>),
	Or(Vec<Rule>),
	Not(Arc<Rule>),
	Pattern(Pattern),
}

impl Serializable for Rule {
	fn read<R>(reader: &mut R) -> Result<Self, Error>
	where
		R: Reader,
	{
		match reader.read_u8()? {
			RULE_TYPE_AND => {
				let len = reader.read_u64()?;
				let mut v = vec![];
				for _ in 0..len {
					v.push(Rule::read(reader)?);
				}
				Ok(Self::And(v))
			}
			RULE_TYPE_OR => {
				let len = reader.read_u64()?;
				let mut v = vec![];
				for _ in 0..len {
					v.push(Rule::read(reader)?);
				}
				Ok(Self::Or(v))
			}
			RULE_TYPE_NOT => Ok(Self::Not(Arc::new(Rule::read(reader)?))),
			RULE_TYPE_PATTERN => Ok(Self::Pattern(Pattern::read(reader)?)),
			_ => Err(ErrorKind::CorruptedData("unexpected rule type".into()).into()),
		}
	}

	fn write<W>(&self, writer: &mut W) -> Result<(), Error>
	where
		W: Writer,
	{
		match self {
			Self::And(rules) => {
				writer.write_u8(RULE_TYPE_AND)?;
				writer.write_u64(rules.len().try_into()?)?;
				for rule in rules {
					Serializable::write(rule, writer)?;
				}
			}
			Self::Or(rules) => {
				writer.write_u8(RULE_TYPE_OR)?;
				writer.write_u64(rules.len().try_into()?)?;
				for rule in rules {
					Serializable::write(rule, writer)?;
				}
			}
			Self::Not(rule) => {
				writer.write_u8(RULE_TYPE_NOT)?;
				Serializable::write(rule, writer)?;
			}
			Self::Pattern(pattern) => {
				writer.write_u8(RULE_TYPE_PATTERN)?;
				Serializable::write(pattern, writer)?;
			}
		}
		Ok(())
	}
}

impl Rule {
	pub fn validate_patterns(&self) -> Result<(), Error> {
		match self {
			Self::And(rules) => {
				for rule in rules {
					rule.validate_patterns()?
				}
			}
			Self::Or(rules) => {
				for rule in rules {
					rule.validate_patterns()?
				}
			}
			Self::Not(rule) => unsafe {
				Arc::<Rule>::as_ptr(rule)
					.as_ref()
					.unwrap()
					.validate_patterns()?
			},
			Self::Pattern(pattern) => {
				let mut dictionary =
					Dictionary::new(pattern.regex.len() + 10, true, pattern.regex.len());
				dictionary.add(pattern.clone(), false)?;
			}
		}

		Ok(())
	}

	pub fn get_all_patterns(&self) -> Result<Vec<&Pattern>, Error> {
		Ok(match self {
			Self::Pattern(pattern) => vec![pattern],
			Self::Not(rule) => rule.get_all_patterns()?,
			Self::Or(rules) => {
				let mut ret = vec![];
				for rule in rules {
					ret.append(&mut rule.get_all_patterns()?);
				}
				ret
			}
			Self::And(rules) => {
				let mut ret = vec![];
				for rule in rules {
					ret.append(&mut rule.get_all_patterns()?);
				}
				ret
			}
		})
	}

	pub fn evaluate(&self, pattern_map: &StaticHash<(), ()>) -> Result<bool, Error> {
		Ok(match self {
			Self::Pattern(pattern) => pattern_map.get_raw(&pattern.id.to_be_bytes()).is_some(),
			Self::Not(rule) => rule.evaluate(pattern_map)? == false,
			Self::Or(rules) => {
				let mut ret = false;
				for rule in rules {
					if rule.evaluate(pattern_map)? == true {
						ret = true;
						break;
					}
				}

				ret
			}
			Self::And(rules) => {
				let mut ret = true;
				for rule in rules {
					if rule.evaluate(pattern_map)? == false {
						ret = false;
						break;
					}
				}

				ret
			}
		})
	}
}

#[derive(Clone, Debug, Hash)]
struct TimestampCountPair {
	timestamp: u64,
	count: u64,
}

impl PartialOrd for TimestampCountPair {
	fn partial_cmp(&self, x: &Self) -> Option<Ordering> {
		if x.timestamp > self.timestamp {
			Some(Ordering::Less)
		} else if x.timestamp < self.timestamp {
			Some(Ordering::Greater)
		} else {
			Some(Ordering::Equal)
		}
	}
}

impl PartialEq for TimestampCountPair {
	fn eq(&self, x: &Self) -> bool {
		x.timestamp == self.timestamp && x.count == self.count
	}
}

impl Eq for TimestampCountPair {}

impl Ord for TimestampCountPair {
	fn cmp(&self, x: &Self) -> Ordering {
		if x.timestamp > self.timestamp {
			Ordering::Less
		} else if x.timestamp < self.timestamp {
			Ordering::Greater
		} else {
			Ordering::Equal
		}
	}
}

impl TimestampCountPair {
	fn new(timestamp: u64, count: u64) -> Self {
		Self { timestamp, count }
	}
}

#[derive(Clone)]
pub struct HttpAdmin {
	db: HttpData,
}

impl HttpAdmin {
	pub fn new(db: HttpData) -> Result<Self, Error> {
		Ok(Self { db })
	}

	pub fn get_active_rules(&self) -> Result<Vec<FunctionalRule>, Error> {
		let mut ret = vec![];
		let db = lockw!(self.db.db())?;
		let batch = db.batch()?;
		let mut itt = batch.iter(&([RULE_PREFIX])[..], |_k, v| {
			let mut cursor = Cursor::new(v.to_vec());
			cursor.set_position(0);
			let mut reader = BinReader::new(&mut cursor);
			Ok(FunctionalRule::read(&mut reader)?)
		})?;
		loop {
			match itt.next() {
				Some(rule) => {
					if rule.is_active {
						ret.push(rule);
					}
				}
				None => break,
			}
		}
		Ok(ret)
	}

	pub fn create_rule(&self, rule: &Rule, label: String) -> Result<u64, Error> {
		rule.validate_patterns()?;
		let id = rand::random();
		let functional_rule = FunctionalRule {
			id,
			is_active: false,
			rule: rule.clone(),
			label,
		};
		let mut rule_key = vec![RULE_PREFIX];
		rule_key.append(&mut functional_rule.id.to_be_bytes().to_vec());

		let db = lockw!(self.db.db())?;
		let batch = db.batch()?;
		batch.put_ser(&rule_key, &functional_rule)?;
		batch.commit()?;

		Ok(id)
	}

	fn delete_rule(&self, id: u64) -> Result<(), Error> {
		let mut rule_key = vec![RULE_PREFIX];
		rule_key.append(&mut id.to_be_bytes().to_vec());

		let db = lockw!(self.db.db())?;
		let batch = db.batch()?;
		batch.delete(&rule_key)?;
		batch.commit()?;
		Ok(())
	}

	fn reply_error(msg: &str) -> Result<WebSocketMessage, Error> {
		let mut payload = vec![WS_ADMIN_ERROR_REPLY];
		payload.append(&mut ((msg.len() as u64).to_be_bytes()).to_vec());
		payload.append(&mut msg.as_bytes().to_vec());

		Ok(WebSocketMessage {
			payload,
			mtype: WebSocketMessageType::Binary,
			mask: false,
		})
	}

	fn get_rules(&self) -> Result<Vec<FunctionalRule>, Error> {
		let mut ret = vec![];
		let db = lockw!(self.db.db())?;
		let batch = db.batch()?;
		let mut itt = batch.iter(&([RULE_PREFIX])[..], |_k, v| {
			let mut cursor = Cursor::new(v.to_vec());
			cursor.set_position(0);
			let mut reader = BinReader::new(&mut cursor);
			Ok(FunctionalRule::read(&mut reader)?)
		})?;
		loop {
			match itt.next() {
				Some(rule) => {
					ret.push(rule);
				}
				None => break,
			}
		}
		Ok(ret)
	}

	fn set_active_rules(&self, rules: HashSet<u64>) -> Result<Vec<FunctionalRule>, Error> {
		let mut ret = vec![];
		let db = lockw!(self.db.db())?;
		let batch = db.batch()?;

		// get last timestamp for any new rules
		let search = vec![STAT_RECORD_PREFIX];
		let mut itt = batch.iter(&search, |k, _v| {
			Ok(u128::from_be_bytes(k[1..17].try_into()?))
		})?;

		let last = match itt.next() {
			Some(timestamp) => timestamp,
			None => invert_timestamp128(SystemTime::now().duration_since(UNIX_EPOCH)?.as_millis()),
		};

		for id in &rules {
			let mut search = vec![USER_RECORD_PREFIX];
			search.append(&mut id.to_be_bytes().to_vec());
			let mut itt = batch.iter(&search, |k, _v| {
				let timestamp = invert_timestamp128(u128::from_be_bytes(k[9..25].try_into()?));
				Ok(timestamp)
			})?;

			let found = match itt.next() {
				Some(_) => true,
				None => false,
			};

			if !found {
				let mut key = vec![USER_RECORD_PREFIX];
				key.append(&mut id.to_be_bytes().to_vec());
				key.append(&mut last.to_be_bytes().to_vec());
				let value = (0 as u64).to_be_bytes().to_vec();
				batch.put_ser(&key, &value)?;
			}
		}

		let mut itt = batch.iter(&([RULE_PREFIX])[..], |k, v| {
			let mut cursor = Cursor::new(v.to_vec());
			cursor.set_position(0);
			let mut reader = BinReader::new(&mut cursor);
			Ok((k.to_owned(), FunctionalRule::read(&mut reader)?))
		})?;
		loop {
			match itt.next() {
				Some((key, mut rule)) => {
					match rules.get(&rule.id) {
						Some(_) => {
							rule.is_active = true;
							ret.push(rule.clone());
						}
						None => {
							rule.is_active = false;
						}
					}
					batch.put_ser(&key, &rule)?;
				}
				None => break,
			}
		}
		batch.commit()?;
		Ok(ret)
	}

	pub fn process_admin_ws(
		&self,
		msg: WebSocketMessage,
		http_stats: &HttpStats,
	) -> Result<(bool, Option<WebSocketMessage>, Option<Vec<FunctionalRule>>), Error> {
		let mut active_functional_rules: Option<Vec<FunctionalRule>> = None;
		if msg.mtype == WebSocketMessageType::Close {
			Ok((false, None, None))
		} else {
			if msg.payload.len() == 0 {
				return Ok((false, None, None));
			}
			let response = match msg.payload[0] {
				WS_ADMIN_CREATE_RULE => {
					let mut cursor = Cursor::new(msg.payload[1..].to_vec());
					cursor.set_position(0);
					let mut reader = BinReader::new(&mut cursor);
					let rule = Rule::read(&mut reader)?;
					let label = String::read(&mut reader)?;
					match self.create_rule(&rule, label) {
						Ok(id) => {
							let mut payload = vec![WS_ADMIN_CREATE_RULE_RESPONSE];
							payload.append(&mut id.to_be_bytes().to_vec());
							Some(WebSocketMessage {
								payload,
								mtype: WebSocketMessageType::Binary,
								mask: false,
							})
						}
						Err(e) => {
							warn!("Creating rule generated error: {}", e)?;
							Some(Self::reply_error("CREATE_RULE resulted in error")?)
						}
					}
				}
				WS_ADMIN_GET_RULES => match self.get_rules() {
					Ok(rules) => {
						let mut payload = vec![WS_ADMIN_GET_RULES_RESPONSE];
						payload.append(
							&mut ((SystemTime::now().duration_since(UNIX_EPOCH)?.as_millis()
								as u64)
								.to_be_bytes())
							.to_vec(),
						);
						payload.append(&mut ((rules.len() as u64).to_be_bytes()).to_vec());
						for i in 0..rules.len() {
							let mut v = vec![];
							serialize(&mut v, &rules[i])?;
							payload.append(&mut v);
						}
						Some(WebSocketMessage {
							payload,
							mtype: WebSocketMessageType::Binary,
							mask: false,
						})
					}
					Err(e) => {
						error!("Error getting rules: {}", e)?;
						Some(Self::reply_error(
							&format!("GET_RULES resulted in error: {}", e)[..],
						)?)
					}
				},
				WS_ADMIN_DELETE_RULE => {
					if msg.payload.len() < 9 {
						error!(
							"invalid delete_rule message, msg len = {}",
							msg.payload.len()
						)?;
						return Ok((
							true,
							Some(Self::reply_error(
								&format!("WS_ADMIN_DELETE_RULE: invalid message length")[..],
							)?),
							None,
						));
					}
					let id = u64::from_be_bytes(msg.payload[1..9].try_into()?);
					match self.delete_rule(id) {
						Ok(_) => Some(WebSocketMessage {
							payload: vec![WS_ADMIN_DELETE_RULE_RESPONSE],
							mtype: WebSocketMessageType::Binary,
							mask: false,
						}),
						Err(e) => {
							warn!("delete rule generated error: {}", e)?;
							Some(Self::reply_error(
								&format!("WS_ADMIN_DELETE_RULE: delete rule generated error")[..],
							)?)
						}
					}
				}
				WS_ADMIN_SET_ACTIVE_RULES => {
					if msg.payload.len() < 9 {
						warn!(
							"invalid set_active_rules message, msg len = {}",
							msg.payload.len()
						)?;
						return Ok((
							true,
							Some(Self::reply_error(
								&format!("WS_ADMIN_SET_ACTIVE_RULES: invalid message length")[..],
							)?),
							None,
						));
					}
					let rule_count = u64::from_be_bytes(msg.payload[1..9].try_into()?);
					let mut rules = HashSet::new();
					for i in 0..rule_count {
						let i: usize = i as usize;
						if msg.payload.len() < (i * 8) + 17 {
							error!(
                                                            "invalid set_active_rules message. message len = {}, rule_count = {}",
                                                            msg.payload.len(),
                                                            rule_count
                                                        )?;
							error!("payload={:?}", msg.payload)?;
							return Ok((
								true,
								Some(Self::reply_error(
									&format!("WS_ADMIN_SET_ACTIVE_RULES: invalid message length")[..],
								)?),
								None,
							));
						}
						rules.insert(u64::from_be_bytes(
							msg.payload[(i * 8) + 9..(i * 8) + 17].try_into()?,
						));
					}
					match self.set_active_rules(rules) {
						Ok(nrules) => {
							active_functional_rules = Some(nrules);
							Some(WebSocketMessage {
								payload: vec![WS_ADMIN_SET_ACTIVE_RULES_RESPONSE],
								mtype: WebSocketMessageType::Binary,
								mask: false,
							})
						}
						Err(e) => Some(Self::reply_error(
							&format!("WS_ADMIN_SET_ACTIVE_RULES generated error: {}", e)[..],
						)?),
					}
				}
				WS_ADMIN_GET_DATA => {
					let start = u64::from_be_bytes(msg.payload[1..9].try_into()?);
					let end = u64::from_be_bytes(msg.payload[9..17].try_into()?);
					let count = u64::from_be_bytes(msg.payload[17..25].try_into()?);
					let mut payload = vec![WS_ADMIN_GET_DATA_RESPONSE];
					payload.append(&mut count.to_be_bytes().to_vec());

					let db = lockw!(self.db.db())?;
					let batch = db.batch()?;

					for i in 0..count {
						let id = u64::from_be_bytes(
							msg.payload[25 + i as usize * 8..33 + i as usize * 8].try_into()?,
						);

						// 0 a special case for total request count
						let search = if id == 0 {
							vec![STAT_RECORD_PREFIX]
						} else {
							let mut ret = vec![USER_RECORD_PREFIX];
							ret.append(&mut id.to_be_bytes().to_vec());
							ret
						};
						let mut first_timestamp = u64::MAX;
						let mut itt = batch.iter(&search, |k, v| {
							if id == 0 {
								let timestamp =
									invert_timestamp128(u128::from_be_bytes(k[1..17].try_into()?));
								let timestamp: u64 = timestamp.try_into()?;
								let mut cursor = Cursor::new(v.to_vec());
								cursor.set_position(0);
								let mut reader = BinReader::new(&mut cursor);
								let sr = StatRecord::read(&mut reader)?;

								let count = sr.requests;
								Ok(TimestampCountPair::new(timestamp, count))
							} else {
								let count = u64::from_be_bytes(v[8..16].try_into()?);
								let timestamp =
									invert_timestamp128(u128::from_be_bytes(k[9..25].try_into()?));
								let timestamp: u64 = timestamp.try_into()?;
								Ok(TimestampCountPair::new(timestamp, count))
							}
						})?;

						let mut itt2 = batch.iter(&([STAT_RECORD_PREFIX])[..], |k, _v| {
							let timestamp =
								invert_timestamp128(u128::from_be_bytes(k[1..17].try_into()?));
							Ok(TimestampCountPair::new(timestamp.try_into()?, 0))
						})?;

						let mut timestamp_count_pairs_value = HashMap::new();
						let mut timestamp_count_pairs_no_value = HashMap::new();
						let mut itt_complete = false;
						let mut itt2_complete = false;
						loop {
							if !itt_complete {
								match itt.next() {
									Some(pair) => {
										if pair.timestamp < first_timestamp {
											first_timestamp = pair.timestamp;
										}
										if pair.timestamp >= start && pair.timestamp <= end {
											timestamp_count_pairs_value
												.insert(pair.timestamp, pair);
										} else if pair.timestamp < start {
											itt_complete = true;
										}
									}
									None => itt_complete = true,
								}
							}

							if !itt2_complete {
								match itt2.next() {
									Some(pair) => {
										if pair.timestamp >= start && pair.timestamp <= end {
											timestamp_count_pairs_no_value
												.insert(pair.timestamp, pair);
										} else if pair.timestamp < start {
											itt2_complete = true;
										}
									}
									None => {
										itt2_complete = true;
									}
								}

								if itt_complete && itt2_complete {
									break;
								}
							}
						}

						let mut timestamp_count_pairs = vec![];
						for (k, v) in &timestamp_count_pairs_value {
							if k >= &first_timestamp {
								timestamp_count_pairs.push(v.clone());
							}
						}
						for (k, v) in timestamp_count_pairs_no_value {
							if k >= first_timestamp && timestamp_count_pairs_value.get(&k).is_none()
							{
								timestamp_count_pairs.push(v.clone());
							}
						}

						timestamp_count_pairs.sort();

						payload.append(&mut timestamp_count_pairs.len().to_be_bytes().to_vec());
						for j in 0..timestamp_count_pairs.len() {
							payload.append(
								&mut timestamp_count_pairs[j].timestamp.to_be_bytes().to_vec(),
							);
							payload
								.append(&mut timestamp_count_pairs[j].count.to_be_bytes().to_vec());
						}
					}

					Some(WebSocketMessage {
						payload,
						mtype: WebSocketMessageType::Binary,
						mask: false,
					})
				}
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

					Some(WebSocketMessage {
						payload,
						mtype: WebSocketMessageType::Binary,
						mask: false,
					})
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
					Some(WebSocketMessage {
						payload,
						mtype: WebSocketMessageType::Binary,
						mask: false,
					})
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

					Some(WebSocketMessage {
						payload,
						mtype: WebSocketMessageType::Binary,
						mask: false,
					})
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

					Some(WebSocketMessage {
						payload,
						mtype: WebSocketMessageType::Binary,
						mask: false,
					})
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

					Some(WebSocketMessage {
						payload,
						mtype: WebSocketMessageType::Binary,
						mask: false,
					})
				}
				_ => {
					warn!("unknown ws admin command. msg = {:?}", msg)?;
					None
				}
			};
			Ok((true, response, active_functional_rules))
		}
	}
}

#[cfg(test)]
mod test {
	use crate::admin::*;
	use crate::stats::{HttpStats, HttpStatsConfig};
	use crate::websocket::{WebSocketMessage, WebSocketMessageType};
	use nioruntime_err::Error;

	info!();

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

	fn check_ser(rule_in: &Rule) -> Result<(), Error> {
		let mut v = vec![];
		serialize(&mut v, &rule_in)?;
		let mut cursor = Cursor::new(v.to_vec());
		cursor.set_position(0);
		let mut reader = BinReader::new(&mut cursor);
		let rule_out = Rule::read(&mut reader)?;
		assert_eq!(rule_in, &rule_out);

		Ok(())
	}

	#[test]
	fn test_rule_serialize() -> Result<(), Error> {
		let rule1 = Rule::Pattern(Pattern {
			multi_line: false,
			regex: "ok".to_string(),
			id: 102,
		});
		check_ser(&rule1)?;
		let rule2 = Rule::Pattern(Pattern {
			multi_line: true,
			regex: "abc\nok".to_string(),
			id: 103,
		});
		check_ser(&rule2)?;
		let rule3 = Rule::Pattern(Pattern {
			multi_line: false,
			regex: "abcdef".to_string(),
			id: 104,
		});
		check_ser(&rule3)?;

		let rule_and_all = Rule::And(vec![rule1.clone(), rule2.clone(), rule3.clone()]);
		check_ser(&rule_and_all)?;
		let rule_or_all = Rule::Or(vec![rule1.clone(), rule2.clone(), rule3.clone()]);
		check_ser(&rule_or_all)?;

		let not_rule_and_all = Rule::Not(Arc::new(rule_and_all.clone()));
		check_ser(&not_rule_and_all)?;

		let rule1_and_rule2 = Rule::And(vec![rule1.clone(), rule2.clone()]);
		let not_rule3 = Rule::Not(Arc::new(rule3.clone()));
		let rule1_and_rule2_or_not_rule3 =
			Rule::Or(vec![rule1_and_rule2.clone(), not_rule3.clone()]);
		check_ser(&rule1_and_rule2_or_not_rule3)?;

		Ok(())
	}

	#[test]
	fn test_rules() -> Result<(), Error> {
		let root_dir = "./.test_admin_rules.nio";
		setup_test_dir(root_dir)?;
		let lmdb_dir = format!("{}/lmdb", root_dir);
		let config = HttpStatsConfig {
			request_log_config: LogConfig {
				file_path: Some(format!("{}/logs", root_dir)),
				..LogConfig::default()
			},
			stats_frequency: 10_000,
			debug_log_queue: false,
			debug_show_stats: false,
		};

		let db = HttpData::new(&lmdb_dir)?;
		let http_stats = HttpStats::new(config, db.clone())?;
		let http_admin = HttpAdmin::new(db)?;

		let mut payload = vec![WS_ADMIN_CREATE_RULE];
		let rule1 = Rule::Pattern(Pattern {
			multi_line: false,
			regex: "xyz".to_string(),
			id: 99,
		});
		let rule2 = Rule::Pattern(Pattern {
			multi_line: false,
			regex: "abc".to_string(),
			id: 98,
		});
		let rule3 = Rule::Pattern(Pattern {
			multi_line: false,
			regex: "def".to_string(),
			id: 97,
		});
		let mut v = vec![];
		serialize(&mut v, &rule1)?;
		payload.append(&mut v);
		let label1 = "mylabel1".to_string();
		let mut v = vec![];
		serialize(&mut v, &label1)?;
		payload.append(&mut v);

		let wsm = WebSocketMessage {
			payload,
			mtype: WebSocketMessageType::Binary,
			mask: false,
		};
		let res = http_admin.process_admin_ws(wsm, &http_stats)?;
		assert_eq!(
			res.1.as_ref().unwrap().payload[0],
			WS_ADMIN_CREATE_RULE_RESPONSE
		);

		let mut payload = vec![WS_ADMIN_CREATE_RULE];
		let mut v = vec![];
		serialize(&mut v, &rule2)?;
		payload.append(&mut v);
		let label2 = "mylabel2".to_string();
		let mut v = vec![];
		serialize(&mut v, &label2)?;
		payload.append(&mut v);

		let wsm = WebSocketMessage {
			payload,
			mtype: WebSocketMessageType::Binary,
			mask: false,
		};
		let res = http_admin.process_admin_ws(wsm, &http_stats)?;
		assert_eq!(
			res.1.as_ref().unwrap().payload[0],
			WS_ADMIN_CREATE_RULE_RESPONSE
		);

		let mut payload = vec![WS_ADMIN_CREATE_RULE];
		let mut v = vec![];
		serialize(&mut v, &rule3)?;
		payload.append(&mut v);
		let label3 = "mylabel3".to_string();
		let mut v = vec![];
		serialize(&mut v, &label3)?;
		payload.append(&mut v);

		let wsm = WebSocketMessage {
			payload,
			mtype: WebSocketMessageType::Binary,
			mask: false,
		};
		let res = http_admin.process_admin_ws(wsm, &http_stats)?;
		assert_eq!(
			res.1.as_ref().unwrap().payload[0],
			WS_ADMIN_CREATE_RULE_RESPONSE
		);

		let payload = vec![WS_ADMIN_GET_RULES];
		let wsm = WebSocketMessage {
			payload,
			mtype: WebSocketMessageType::Binary,
			mask: false,
		};
		let res = http_admin.process_admin_ws(wsm, &http_stats)?;
		let payload = &res.1.as_ref().unwrap().payload;
		assert_eq!(payload[0], WS_ADMIN_GET_RULES_RESPONSE);
		let len = u64::from_be_bytes(payload[9..17].try_into()?);
		assert_eq!(len, 3);
		let mut cursor = Cursor::new(payload[17..].to_vec());
		cursor.set_position(0);
		let mut reader = BinReader::new(&mut cursor);
		let rule_out1 = FunctionalRule::read(&mut reader)?;
		let rule_out2 = FunctionalRule::read(&mut reader)?;
		let rule_out3 = FunctionalRule::read(&mut reader)?;
		let mut rules_out = vec![];
		rules_out.push(rule_out1.rule.clone());
		rules_out.push(rule_out2.rule.clone());
		rules_out.push(rule_out3.rule.clone());
		rules_out.sort();
		let mut rules_in = vec![];
		rules_in.push(rule1.clone());
		rules_in.push(rule2.clone());
		rules_in.push(rule3.clone());
		rules_in.sort();
		assert_eq!(rules_out, rules_in);

		let mut frules = vec![];
		frules.push(rule_out1);
		frules.push(rule_out2);
		frules.push(rule_out3);

		let mut id1: u64 = 0;
		let mut id2: u64 = 0;
		for frule in frules {
			match frule.rule {
				Rule::Pattern(pattern) => {
					if pattern.id == 97 {
						id1 = frule.id;
					} else if pattern.id == 99 {
						id2 = frule.id;
					}
				}
				_ => {}
			}
		}

		assert!(id1 != 0);
		assert!(id2 != 0);

		let mut payload = vec![WS_ADMIN_SET_ACTIVE_RULES];
		payload.append(&mut ((2 as u64).to_be_bytes()).to_vec());
		payload.append(&mut (id1.to_be_bytes()).to_vec());
		payload.append(&mut (id2.to_be_bytes()).to_vec());
		let wsm = WebSocketMessage {
			payload,
			mtype: WebSocketMessageType::Binary,
			mask: false,
		};
		let res = http_admin.process_admin_ws(wsm, &http_stats)?;
		let frules = res.2.as_ref().unwrap();
		assert_eq!(frules.len(), 2);
		let mut active_list = vec![];
		for frule in frules {
			active_list.push(frule.rule.clone());
		}

		let mut active_list_expect = vec![];
		active_list_expect.push(rule1);
		active_list_expect.push(rule3);

		active_list.sort();
		active_list_expect.sort();

		assert_eq!(active_list, active_list_expect);

		assert_eq!(
			res.1.as_ref().unwrap().payload,
			vec![WS_ADMIN_SET_ACTIVE_RULES_RESPONSE]
		);
		assert_eq!(res.0, true);

		let active_cur = http_admin.get_active_rules()?;
		assert_eq!(active_cur.len(), 2);
		let mut active_cur_rules = vec![];
		for active in active_cur {
			active_cur_rules.push(active.rule);
		}
		active_cur_rules.sort();
		assert_eq!(active_cur_rules, active_list_expect);

		let mut payload = vec![WS_ADMIN_DELETE_RULE];
		payload.append(&mut (id1.to_be_bytes()).to_vec());
		let wsm = WebSocketMessage {
			payload,
			mtype: WebSocketMessageType::Binary,
			mask: false,
		};
		let res = http_admin.process_admin_ws(wsm, &http_stats)?;
		assert_eq!(res.0, true);
		assert_eq!(
			res.1.as_ref().unwrap().payload,
			vec![WS_ADMIN_DELETE_RULE_RESPONSE]
		);
		assert!(res.2.is_none());

		let active_cur = http_admin.get_active_rules()?;
		assert_eq!(active_cur.len(), 1);

		tear_down_test_dir(root_dir)?;

		Ok(())
	}
}
