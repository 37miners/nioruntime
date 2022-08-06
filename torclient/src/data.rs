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
use nioruntime_log::*;
use nioruntime_tor::TorDirectory;
use nioruntime_util::lmdb::Store;
use std::fs::create_dir_all;
use std::path::PathBuf;
use std::sync::{Arc, RwLock};

info!();

pub const NTOR_PUBKEY_PREFIX: u8 = 0u8;
pub const DIRECTORY_PREFIX: u8 = 1u8;

#[derive(Clone)]
pub struct TorData {
	db: Arc<RwLock<Store>>,
}

impl TorData {
	pub fn new(lmdb_dir: &String) -> Result<Self, Error> {
		let home_dir = match dirs::home_dir() {
			Some(p) => p,
			None => PathBuf::new(),
		}
		.as_path()
		.display()
		.to_string();
		let lmdb_dir = lmdb_dir.replace("~", &home_dir);
		create_dir_all(lmdb_dir.clone())?;

		let db = Arc::new(RwLock::new(Store::new(&lmdb_dir, None, None, None, true)?));
		Ok(Self { db })
	}

	pub fn write_directory(&self, directory: &TorDirectory) -> Result<(), Error> {
		let db = lockw!(self.db)?;
		let batch = db.batch()?;
		let key = vec![DIRECTORY_PREFIX];
		batch.put_ser(&key, &directory)?;
		batch.commit()?;
		Ok(())
	}

	pub fn read_directory(&self) -> Result<Option<TorDirectory>, Error> {
		let db = lockw!(self.db)?;
		let batch = db.batch()?;
		let key = vec![DIRECTORY_PREFIX];
		let directory = batch.get_ser(&key)?;
		Ok(match directory {
			Some(directory) => Some(directory),
			None => None,
		})
	}

	pub fn insert_ntor(&self, microdescriptor: &str, ntor_onion_pubkey: &str) -> Result<(), Error> {
		let db = lockw!(self.db)?;
		let batch = db.batch()?;
		let mut key = vec![NTOR_PUBKEY_PREFIX];
		key.extend(microdescriptor.as_bytes());
		debug!("insert ntor key = {:?},len={}", key, key.len())?;
		batch.put_ser(&key, &ntor_onion_pubkey.as_bytes().to_vec())?;
		batch.commit()?;
		Ok(())
	}

	pub fn get_ntor(&self, microdescriptor: &str) -> Result<Option<String>, Error> {
		let db = lockw!(self.db)?;
		let batch = db.batch()?;
		let mut key = vec![NTOR_PUBKEY_PREFIX];
		key.extend(microdescriptor.as_bytes());
		batch.get_ser(&key)
	}
}
