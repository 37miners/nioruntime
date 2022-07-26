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

use nioruntime_deps::dirs;
use nioruntime_err::Error;
use nioruntime_util::lmdb::Store;
use std::path::PathBuf;
use std::sync::{Arc, RwLock};

pub const STAT_RECORD_PREFIX: u8 = 1u8;
pub const RULE_PREFIX: u8 = 2u8;
pub const USER_RECORD_PREFIX: u8 = 3u8;
pub const USER_RECORD_HOURLY_PREFIX: u8 = 4u8;
pub const USER_RECORD_DAILY_PREFIX: u8 = 5u8;
pub const USER_RECORD_MONTHLY_PREFIX: u8 = 6u8;
pub const STAT_RECORD_DAILY_PREFIX: u8 = 7u8;

#[derive(Clone)]
pub struct HttpData {
	db: Arc<RwLock<Store>>,
}

impl HttpData {
	pub fn new(lmdb_dir: &String) -> Result<Self, Error> {
		let home_dir = match dirs::home_dir() {
			Some(p) => p,
			None => PathBuf::new(),
		}
		.as_path()
		.display()
		.to_string();
		let lmdb_dir = lmdb_dir.replace("~", &home_dir);

		let db = Arc::new(RwLock::new(Store::new(&lmdb_dir, None, None, None, true)?));
		Ok(Self { db })
	}

	pub fn db(&self) -> &Arc<RwLock<Store>> {
		&self.db
	}
}
