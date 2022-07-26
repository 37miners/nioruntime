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

use clap::load_yaml;
use clap::App;
use nioruntime_deps::dirs;
use nioruntime_err::Error;
use nioruntime_http::admin::HttpAdmin;
use nioruntime_http::admin::Rule;
use nioruntime_http::data::HttpData;
use nioruntime_http::data::STAT_RECORD_PREFIX;
use nioruntime_http::data::USER_RECORD_PREFIX;
use nioruntime_http::stats::HttpStats;
use nioruntime_http::stats::HttpStatsConfig;
use nioruntime_http::stats::StatRecord;
use nioruntime_http::HttpConfig;
use nioruntime_log::*;
use nioruntime_util::lmdb::Batch;
use nioruntime_util::lmdb::Store;
use nioruntime_util::misc::invert_timestamp128;
use nioruntime_util::multi_match::Pattern;
use std::collections::HashSet;
use std::path::PathBuf;
use std::sync::{Arc, RwLock};
use std::time::{SystemTime, UNIX_EPOCH};

debug!();

// include build information
pub mod built_info {
	include!(concat!(env!("OUT_DIR"), "/built.rs"));
}

fn insert_ts(now: u128, ids: &Vec<u64>, max: u64, min: u64, batch: &Batch) -> Result<(), Error> {
	let mut qty_sum = 0;
	for id in ids {
		let qty: u64 = rand::random();
		let qty = (qty % (max - min)) + min;
		qty_sum += qty;
		let mut user_record_key = vec![];
		user_record_key.push(USER_RECORD_PREFIX);
		user_record_key.append(&mut id.to_be_bytes().to_vec());
		user_record_key.append(&mut invert_timestamp128(now).to_be_bytes().to_vec());
		batch.put_ser(&user_record_key, &qty)?;
	}

	let mut stat_record_key = vec![];
	stat_record_key.push(STAT_RECORD_PREFIX);
	stat_record_key.append(&mut invert_timestamp128(now).to_be_bytes().to_vec());
	let mut stat_record = StatRecord::new(now);
	stat_record.requests = qty_sum;
	batch.put_ser(&stat_record_key, &stat_record)?;

	Ok(())
}

fn main() -> Result<(), Error> {
	log_config!(LogConfig {
		show_bt: false,
		..Default::default()
	})?;

	let yml = load_yaml!("dbload.yml");
	let args = App::from_yaml(yml)
		.version(built_info::PKG_VERSION)
		.get_matches();

	let db_dir = match args.is_present("db") {
		true => args.value_of("db").unwrap(),
		false => "~/.niohttpd/lmdb",
	}
	.to_string();

	let request_log = match args.is_present("requestlog") {
		true => args.value_of("requestlog").unwrap(),
		false => "~/.niohttpd/logs/request.log",
	}
	.to_string();

	let randname: u16 = rand::random();
	let randname = &format!("r{}", randname)[..];
	let rulename = match args.is_present("rulename") {
		true => args.value_of("rulename").unwrap(),
		false => randname,
	}
	.to_string();

	let min = match args.is_present("min") {
		true => args.value_of("min").unwrap().parse()?,
		false => 50,
	};
	let max = match args.is_present("max") {
		true => args.value_of("max").unwrap().parse()?,
		false => 100,
	};
	let count = match args.is_present("count") {
		true => args.value_of("count").unwrap().parse()?,
		false => 100,
	};
	let diff = match args.is_present("diff") {
		true => args.value_of("diff").unwrap().parse()?,
		false => 10_000,
	};
	let id_count = match args.is_present("ids") {
		true => args.value_of("ids").unwrap().parse()?,
		false => 1,
	};

	info!("Starting dbload")?;

	let home_dir = match dirs::home_dir() {
		Some(p) => p,
		None => PathBuf::new(),
	}
	.as_path()
	.display()
	.to_string();
	let lmdb_dir = db_dir.replace("~", &home_dir);

	let db = Arc::new(RwLock::new(Store::new(&lmdb_dir, None, None, None, true)?));

	let config = HttpStatsConfig {
		request_log_config: LogConfig {
			file_path: Some(request_log),
			..Default::default()
		},
		stats_frequency: 0,
		debug_log_queue: true,
		debug_show_stats: true,
		debug_db_update: true,
	};

	let data = HttpData::new(&db_dir)?;

	let stats = HttpStats::new(config, data.clone())?;
	let admin = HttpAdmin::new(data.clone(), &HttpConfig::default())?;

	let mut ids = vec![];
	let mut rule_hashset = HashSet::new();

	for i in 0..id_count {
		let rulename = format!("{}v{}", rulename.clone(), i);
		let mut n = [0u8; 4];
		let x: u8 = rand::random();
		n[0] = 'a' as u8 + (x % 24);
		let x: u8 = rand::random();
		n[1] = 'a' as u8 + (x % 24);
		let x: u8 = rand::random();
		n[2] = 'a' as u8 + (x % 24);
		let x: u8 = rand::random();
		n[3] = 'a' as u8 + (x % 24);
		let rule = Rule::Pattern(Pattern {
			multi_line: false,
			regex: format!(
				"%$#Jfjadsfjljjok{}{}{}{}",
				n[0] as char, n[1] as char, n[2] as char, n[3] as char
			),
			id: rand::random(),
		});
		let id = admin.create_rule(&rule, rulename)?;
		ids.push(id);
		rule_hashset.insert(id);
	}

	admin.set_active_rules(rule_hashset)?;

	let mut now = SystemTime::now().duration_since(UNIX_EPOCH)?.as_millis();
	now = now.saturating_sub(count * diff);

	let mut i = 0;
	loop {
		{
			let db = lockw!(db)?;
			if db.needs_resize()? {
				db.do_resize()?
			}

			let batch = db.batch()?;
			for _ in 0..360 {
				insert_ts(now, &ids, max, min, &batch)?;
				now = now + diff;

				i += 1;
				if i == count {
					break;
				}
			}
			batch.commit()?;
		}
		if i == count {
			break;
		}
		HttpStats::process_stats(
			&stats.stat_record_accumulator,
			&stats.user_match_accumulator,
			&stats.db.db(),
			&stats.config,
			0,
			now,
		)?;
	}

	Ok(())
}
