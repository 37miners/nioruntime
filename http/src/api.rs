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

use crate::data::USER_RECORD_DAILY_PREFIX;
use crate::data::USER_RECORD_HOURLY_PREFIX;
use crate::data::USER_RECORD_MONTHLY_PREFIX;
use crate::data::USER_RECORD_PREFIX;
use crate::HttpStats;
use nioruntime_deps::chrono::naive::{NaiveDate, NaiveDateTime};
use nioruntime_err::{Error, ErrorKind};
use nioruntime_log::*;
use nioruntime_util::lmdb::Batch;
use nioruntime_util::lmdb::Store;
use nioruntime_util::lockw;
use nioruntime_util::misc::invert_timestamp128;
use std::convert::TryInto;
use std::sync::{Arc, RwLock};

info!();

const HOUR_MILLIS: u128 = 1000 * 60 * 60;
const DAY_MILLIS: u128 = HOUR_MILLIS * 24;

#[derive(Clone)]
pub struct Api {
	db: Arc<RwLock<Store>>,
	stats: HttpStats,
}

impl Api {
	pub fn new(db: Arc<RwLock<Store>>, stats: HttpStats) -> Result<Self, Error> {
		Ok(Self { db, stats })
	}

	pub fn insert_match(&mut self, id: u64) -> Result<(), Error> {
		self.stats.insert_match(id)?;
		Ok(())
	}

	pub fn get_timestamp_counts(
		&self,
		id: u64,
		start: u128,
		end: u128,
	) -> Result<Vec<(u128, u64)>, Error> {
		let mut ret = vec![];
		{
			let db = lockw!(self.db)?;
			let batch = db.batch()?;
			let itts = vec![
				self.get_iter(id, USER_RECORD_PREFIX, &batch)?,
				self.get_iter(id, USER_RECORD_HOURLY_PREFIX, &batch)?,
				self.get_iter(id, USER_RECORD_DAILY_PREFIX, &batch)?,
				self.get_iter(id, USER_RECORD_MONTHLY_PREFIX, &batch)?,
			];

			for mut itt in itts {
				loop {
					match itt.next() {
						Some((timestamp, count)) => {
							debug!("got t={},c={}", timestamp, count)?;

							if timestamp >= start && timestamp <= end {
								ret.push((timestamp, count));
							} else if timestamp < start {
								// we can break here because data is
								// ordered
								break;
							}
						}
						None => break,
					}
				}
			}
		}

		ret.sort();
		Ok(ret)
	}

	fn get_iter(
		&self,
		id: u64,
		iter_type: u8,
		batch: &Batch,
	) -> Result<impl Iterator<Item = (u128, u64)>, Error> {
		let mut search = vec![iter_type];
		search.append(&mut id.to_be_bytes().to_vec());
		batch.iter(&search, move |k, v| {
			let count = u64::from_be_bytes(v[0..8].try_into()?);
			let timestamp = u128::from_be_bytes(k[9..25].try_into()?);
			let timestamp = match iter_type {
				USER_RECORD_PREFIX => invert_timestamp128(timestamp),
				USER_RECORD_HOURLY_PREFIX => invert_timestamp128(timestamp * HOUR_MILLIS),
				USER_RECORD_DAILY_PREFIX => invert_timestamp128(timestamp * DAY_MILLIS),
				USER_RECORD_MONTHLY_PREFIX => {
					let timestamp = invert_timestamp128(timestamp);
					let year = (timestamp / 12) + 1970;
					let month = (timestamp % 12) + 1;
					let date: NaiveDateTime =
						NaiveDate::from_ymd(year.try_into()?, month.try_into()?, 1)
							.and_hms(0, 0, 0);
					let monthly_timestamp: u128 = date.timestamp().try_into()?;
					let monthly_timestamp = monthly_timestamp * 1_000;
					monthly_timestamp
				}
				_ => {
					return Err(
						ErrorKind::IllegalArgument("unexpected iter_type".to_string()).into(),
					);
				}
			};
			Ok((timestamp, count))
		})
	}
}

#[cfg(test)]
mod test {
	use crate::api::*;
	use crate::HttpData;
	use crate::{HttpStats, HttpStatsConfig};
	use std::time::{SystemTime, UNIX_EPOCH};

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
	fn test_db_api() -> Result<(), Error> {
		let test_dir = ".test_data_api.nio";
		setup_test_dir(test_dir)?;
		let db = Arc::new(RwLock::new(Store::new(&test_dir, None, None, None, true)?));

		// insert some records
		{
			let db = lockw!(db)?;
			let batch = db.batch()?;

			HttpStats::create_user_record(&batch, 123, 9_000, 30)?;
			HttpStats::create_user_record(&batch, 123, 5_000, 10)?;
			HttpStats::create_user_record(&batch, 123, 6_000, 20)?;
			HttpStats::create_user_record(&batch, 123, 3_000, 40)?;

			batch.commit()?;
		}

		let data = HttpData::new(&test_dir.to_string())?;
		let stats_config = HttpStatsConfig {
			request_log_config: LogConfig {
				file_path: Some(format!("{}/request.log", test_dir)),
				..Default::default()
			},
			..Default::default()
		};
		let stats = HttpStats::new(stats_config.clone(), data.clone())?;
		let mut data_api = Api::new(db, stats.clone())?;

		assert_eq!(
			data_api.get_timestamp_counts(123, 4_000, 8_000)?,
			[(5_000, 10), (6_000, 20)]
		);

		assert_eq!(
			data_api.get_timestamp_counts(123, 2_000, 8_000)?,
			[(3_000, 40), (5_000, 10), (6_000, 20)]
		);

		assert_eq!(data_api.get_timestamp_counts(1, 2_000, 8_000)?, []);

		assert_eq!(
			data_api.get_timestamp_counts(123, 8_000, 18_000)?,
			[(9_000, 30)]
		);
		assert_eq!(data_api.get_timestamp_counts(123, 18_000, 118_000)?, []);
		assert_eq!(data_api.get_timestamp_counts(123, 0, 100)?, []);

		data_api.insert_match(1000)?;
		data_api.insert_match(1000)?;
		data_api.insert_match(2000)?;
		data_api.insert_match(2000)?;
		data_api.insert_match(2000)?;
		data_api.insert_match(3000)?;

		let now = SystemTime::now().duration_since(UNIX_EPOCH)?.as_millis();
		HttpStats::process_stats(
			&stats.stat_record_accumulator,
			&stats.user_match_accumulator,
			data.db(),
			&stats_config,
			0,
			now,
		)?;

		let tcs1 = data_api.get_timestamp_counts(1000, now - 1000, now + 1000)?;
		let tcs2 = data_api.get_timestamp_counts(2000, now - 1000, now + 1000)?;
		let tcs3 = data_api.get_timestamp_counts(3000, now - 1000, now + 1000)?;

		info!("counts = {:?} {:?} {:?}", tcs1, tcs2, tcs3)?;

		assert_eq!(tcs1, [(now, 2)]);
		assert_eq!(tcs2, [(now, 3)]);
		assert_eq!(tcs3, [(now, 1)]);

		tear_down_test_dir(test_dir)?;
		Ok(())
	}
}
