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
//

//! Storage of core types using LMDB.

use std::fs;
use std::sync::Arc;

use lmdb::traits::CreateCursor;
use lmdb::LmdbResultExt;
use nioruntime_deps::lmdb_zero as lmdb;
use nioruntime_log::*;

use nioruntime_err::{Error, ErrorKind};

use crate::lockr;
use crate::ser;
use nioruntime_deps::rand;
use std::sync::RwLock;

info!();

/// number of bytes to grow the database by when needed
pub const ALLOC_CHUNK_SIZE_DEFAULT: usize = 134_217_728; //128 MB
/// And for test mode, to avoid too much disk allocation on windows
pub const ALLOC_CHUNK_SIZE_DEFAULT_TEST: usize = 1_048_576; //1 MB
const RESIZE_PERCENT: f32 = 0.9;
/// Want to ensure that each resize gives us at least this %
/// of total space free
const RESIZE_MIN_TARGET_PERCENT: f32 = 0.65;

/// LMDB-backed store facilitating data access and serialization. All writes
/// are done through a Batch abstraction providing atomicity.
pub struct Store {
	env: Arc<lmdb::Environment>,
	db: Arc<RwLock<Option<Arc<lmdb::Database<'static>>>>>,
	name: String,
	alloc_chunk_size: usize,
}

impl Store {
	/// Create a new LMDB env under the provided directory.
	/// By default creates an environment named "lmdb".
	/// Be aware of transactional semantics in lmdb
	/// (transactions are per environment, not per database).
	pub fn new(
		root_path: &str,
		env_name: Option<&str>,
		db_name: Option<&str>,
		max_readers: Option<u32>,
		is_production_mode: bool,
	) -> Result<Store, Error> {
		let name = match env_name {
			Some(n) => n.to_owned(),
			None => "lmdb".to_owned(),
		};
		let db_name = match db_name {
			Some(n) => n.to_owned(),
			None => "lmdb".to_owned(),
		};
		let full_path = [root_path.to_owned(), name].join("/");
		fs::create_dir_all(&full_path).map_err(|e| {
			let error: Error =
				ErrorKind::LmdbError(format!("Unable to create directory to store data: {:?}", e))
					.into();
			error
		})?;

		let mut env_builder = lmdb::EnvBuilder::new()?;
		env_builder.set_maxdbs(8)?;

		if let Some(max_readers) = max_readers {
			env_builder.set_maxreaders(max_readers)?;
		}

		let alloc_chunk_size = match is_production_mode {
			true => ALLOC_CHUNK_SIZE_DEFAULT,
			false => ALLOC_CHUNK_SIZE_DEFAULT_TEST,
		};

		let env = unsafe { env_builder.open(&full_path, lmdb::open::NOTLS, 0o600)? };

		debug!("DB Mapsize for {} is {}", full_path, env.info()?.mapsize)?;
		let res = Store {
			env: Arc::new(env),
			db: Arc::new(RwLock::new(None)),
			name: db_name,
			alloc_chunk_size,
		};

		{
			let mut w = lockw!(res.db)?;
			*w = Some(Arc::new(lmdb::Database::open(
				res.env.clone(),
				Some(&res.name),
				&lmdb::DatabaseOptions::new(lmdb::db::CREATE),
			)?));
		}
		Ok(res)
	}

	/// Construct a new store from current params
	pub fn construct(&self, is_production_mode: bool) -> Store {
		let alloc_chunk_size = match is_production_mode {
			true => ALLOC_CHUNK_SIZE_DEFAULT,
			false => ALLOC_CHUNK_SIZE_DEFAULT_TEST,
		};
		Store {
			env: self.env.clone(),
			db: self.db.clone(),
			name: self.name.clone(),
			alloc_chunk_size,
		}
	}

	/// Opens the database environment
	pub fn open(&self) -> Result<(), Error> {
		let mut w = lockw!(self.db)?;
		*w = Some(Arc::new(lmdb::Database::open(
			self.env.clone(),
			Some(&self.name),
			&lmdb::DatabaseOptions::new(lmdb::db::CREATE),
		)?));
		Ok(())
	}

	/// Determines whether the environment needs a resize based on a simple percentage threshold
	pub fn needs_resize(&self) -> Result<bool, Error> {
		let env_info = self.env.info()?;
		let stat = self.env.stat()?;

		let size_used = stat.psize as usize * env_info.last_pgno;
		trace!("DB map size: {}", env_info.mapsize)?;
		trace!("Space used: {}", size_used)?;
		trace!("Space remaining: {}", env_info.mapsize - size_used)?;
		let resize_percent = RESIZE_PERCENT;
		trace!(
			"Percent used: {:.*}  Percent threshold: {:.*}",
			4,
			size_used as f64 / env_info.mapsize as f64,
			4,
			resize_percent
		)?;

		if size_used as f32 / env_info.mapsize as f32 > resize_percent
			|| env_info.mapsize < self.alloc_chunk_size
		{
			trace!("Resize threshold met (percent-based)")?;
			Ok(true)
		} else {
			trace!("Resize threshold not met (percent-based)")?;
			Ok(false)
		}
	}

	/// Increments the database size by as many ALLOC_CHUNK_SIZES
	/// to give a minimum threshold of free space
	pub fn do_resize(&self) -> Result<(), Error> {
		let env_info = self.env.info()?;
		let stat = self.env.stat()?;
		let size_used = stat.psize as usize * env_info.last_pgno;

		let new_mapsize = if env_info.mapsize < self.alloc_chunk_size {
			self.alloc_chunk_size
		} else {
			let mut tot = env_info.mapsize;
			while size_used as f32 / tot as f32 > RESIZE_MIN_TARGET_PERCENT {
				tot += self.alloc_chunk_size;
			}
			tot
		};

		// close
		let mut w = lockw!(self.db)?;
		*w = None;

		unsafe {
			self.env.set_mapsize(new_mapsize)?;
		}

		*w = Some(Arc::new(lmdb::Database::open(
			self.env.clone(),
			Some(&self.name),
			&lmdb::DatabaseOptions::new(lmdb::db::CREATE),
		)?));

		debug!(
			"Resized database from {} to {}",
			env_info.mapsize, new_mapsize
		)?;
		Ok(())
	}

	/// Gets a value from the db, provided its key.
	/// Deserializes the retrieved data using the provided function.
	pub fn get_with<F, T>(
		&self,
		key: &[u8],
		access: &lmdb::ConstAccessor<'_>,
		db: &lmdb::Database<'_>,
		deserialize: F,
	) -> Result<Option<T>, Error>
	where
		F: Fn(&[u8], &[u8]) -> Result<T, Error>,
	{
		let res: Option<&[u8]> = access.get(db, key).to_opt()?;
		match res {
			None => Ok(None),
			Some(res) => deserialize(key, res).map(Some),
		}
	}

	/// Gets a `Serializable` value from the db, provided its key.
	/// Note: Creates a new read transaction so will *not* see any uncommitted data.
	pub fn get_ser<T: ser::Serializable>(&self, key: &[u8]) -> Result<Option<T>, Error> {
		let lock = lockr!(self.db)?;
		let db = lock.as_ref().ok_or_else(|| {
			let error: Error = ErrorKind::LmdbError("db is None".to_string()).into();
			error
		})?;
		let txn = lmdb::ReadTransaction::new(self.env.clone())?;
		let access = txn.access();

		self.get_with(key, &access, &db, |_, mut data| {
			ser::deserialize(&mut data).map_err(From::from)
		})
	}

	/// Whether the provided key exists
	pub fn exists(&self, key: &[u8]) -> Result<bool, Error> {
		let db = lockr!(self.db)?;
		let txn = lmdb::ReadTransaction::new(self.env.clone())?;
		let access = txn.access();

		match &*db {
			Some(db) => {
				let res: Option<&lmdb::Ignore> = access.get(&db, key).to_opt()?;
				Ok(res.is_some())
			}
			None => Ok(false),
		}
	}

	/// Produces an iterator from the provided key prefix.
	pub fn iter<F, T>(&self, prefix: &[u8], deserialize: F) -> Result<PrefixIterator<F, T>, Error>
	where
		F: Fn(&[u8], &[u8]) -> Result<T, Error>,
	{
		let lock = lockr!(self.db)?;
		let db = lock.as_ref().ok_or_else(|| {
			let error: Error = ErrorKind::LmdbError("db is None".to_string()).into();
			error
		})?;
		let tx = Arc::new(lmdb::ReadTransaction::new(self.env.clone())?);
		let cursor = Arc::new(tx.cursor(db.clone())?);
		Ok(PrefixIterator::new(tx, cursor, prefix, deserialize, false))
	}

	/// Produces an iterator from the provided key prefix. Iteration occurs in reverse order.
	pub fn iter_rev<F, T>(
		&self,
		prefix: &[u8],
		deserialize: F,
	) -> Result<PrefixIterator<F, T>, Error>
	where
		F: Fn(&[u8], &[u8]) -> Result<T, Error>,
	{
		let lock = lockr!(self.db)?;
		let db = lock.as_ref().ok_or_else(|| {
			let error: Error = ErrorKind::LmdbError("db is None".to_string()).into();
			error
		})?;
		let tx = Arc::new(lmdb::ReadTransaction::new(self.env.clone())?);
		let cursor = tx.cursor(db.clone())?;
		let cursor = Arc::new(cursor);
		Ok(PrefixIterator::new(tx, cursor, prefix, deserialize, true))
	}

	/// Builds a new batch to be used with this store.
	pub fn batch(&self) -> Result<Batch<'_>, Error> {
		// check if the db needs resizing before returning the batch
		if self.needs_resize()? {
			self.do_resize()?;
		}
		let tx = lmdb::WriteTransaction::new(self.env.clone())?;
		Ok(Batch { store: self, tx })
	}
}

/// Batch to write multiple Writeables to db in an atomic manner.
pub struct Batch<'a> {
	store: &'a Store,
	tx: lmdb::WriteTransaction<'a>,
}

impl<'a> Batch<'a> {
	/// Writes a single key/value pair to the db
	pub fn put(&self, key: &[u8], value: &[u8]) -> Result<(), Error> {
		let db = lockr!(self.store.db)?;
		match &*db {
			Some(db) => {
				let tx = &self.tx;
				let mut access = tx.access();
				access.put(&db, key, value, lmdb::put::Flags::empty())?
			}
			None => {}
		}

		Ok(())
	}

	/// Writes a single key and its `Writeable` value to the db.
	/// Encapsulates serialization using the (default) version configured on the store instance.
	pub fn put_ser<W: ser::Serializable>(&self, key: &[u8], value: &W) -> Result<(), Error> {
		let mut v = vec![];
		ser::serialize(&mut v, value)?;
		self.put(key, &v)
	}

	/// Low-level access for retrieving data by key.
	/// Takes a function for flexible deserialization.
	pub fn get_with<F, T>(&self, key: &[u8], deserialize: F) -> Result<Option<T>, Error>
	where
		F: Fn(&[u8], &[u8]) -> Result<T, Error>,
	{
		let db = lockr!(self.store.db)?;
		let access = self.tx.access();

		match &*db {
			Some(db) => self.store.get_with(key, &access, &db, deserialize),
			None => Ok(None),
		}
	}

	/// Whether the provided key exists.
	/// This is in the context of the current write transaction.
	pub fn exists(&self, key: &[u8]) -> Result<bool, Error> {
		let db = lockr!(self.store.db)?;
		let access = self.tx.access();
		match &*db {
			Some(db) => {
				let res: Option<&lmdb::Ignore> = access.get(&db, key).to_opt()?;
				Ok(res.is_some())
			}
			None => Ok(false),
		}
	}

	/// Produces an iterator from the provided key prefix.
	pub fn iter<F, T>(&self, prefix: &[u8], deserialize: F) -> Result<PrefixIterator<F, T>, Error>
	where
		F: Fn(&[u8], &[u8]) -> Result<T, Error>,
	{
		self.store.iter(prefix, deserialize)
	}

	/// Produces an iterator from the provided key prefix. Iteration occurs in reverse order.
	pub fn iter_rev<F, T>(
		&self,
		prefix: &[u8],
		deserialize: F,
	) -> Result<PrefixIterator<F, T>, Error>
	where
		F: Fn(&[u8], &[u8]) -> Result<T, Error>,
	{
		self.store.iter_rev(prefix, deserialize)
	}

	/// Gets a `Serializable` value from the db by provided key and default deserialization strategy.
	pub fn get_ser<T: ser::Serializable>(&self, key: &[u8]) -> Result<Option<T>, Error> {
		self.get_with(key, |_, mut data| match ser::deserialize(&mut data) {
			Ok(res) => Ok(res),
			Err(e) => Err(From::from(e)),
		})
	}

	/// Deletes a key/value pair from the db
	pub fn delete(&self, key: &[u8]) -> Result<(), Error> {
		let db = lockr!(self.store.db)?;
		match &*db {
			Some(db) => self.tx.access().del_key(&db, key)?,
			None => {}
		}
		Ok(())
	}

	/// Writes the batch to db
	pub fn commit(self) -> Result<(), Error> {
		self.tx.commit()?;
		Ok(())
	}
}

/// An iterator based on key prefix.
/// Caller is responsible for deserialization of the data.
pub struct PrefixIterator<F, T>
where
	F: Fn(&[u8], &[u8]) -> Result<T, Error>,
{
	tx: Arc<lmdb::ReadTransaction<'static>>,
	cursor: Arc<lmdb::Cursor<'static, 'static>>,
	seek: bool,
	prefix: Vec<u8>,
	deserialize: F,
	reverse: bool,
}

impl<F, T> Iterator for PrefixIterator<F, T>
where
	F: Fn(&[u8], &[u8]) -> Result<T, Error>,
{
	type Item = T;

	fn next(&mut self) -> Option<Self::Item> {
		let access = self.tx.access();
		let cursor = Arc::get_mut(&mut self.cursor).expect("failed to get cursor");
		let kv: Result<(&[u8], &[u8]), _> = if self.seek {
			if self.reverse {
				cursor.prev(&access)
			} else {
				cursor.next(&access)
			}
		} else {
			self.seek = true;
			if self.reverse {
				cursor.last::<[u8], [u8]>(&access)
			} else {
				cursor.seek_range_k(&access, &self.prefix[..])
			}
		};
		kv.ok()
			.filter(|(k, _)| k.starts_with(self.prefix.as_slice()))
			.map(|(k, v)| match (self.deserialize)(k, v) {
				Ok(v) => Some(v),
				Err(_) => None,
			})
			.flatten()
	}
}

impl<F, T> PrefixIterator<F, T>
where
	F: Fn(&[u8], &[u8]) -> Result<T, Error>,
{
	/// Initialize a new prefix iterator.
	pub fn new(
		tx: Arc<lmdb::ReadTransaction<'static>>,
		cursor: Arc<lmdb::Cursor<'static, 'static>>,
		prefix: &[u8],
		deserialize: F,
		reverse: bool,
	) -> PrefixIterator<F, T> {
		PrefixIterator {
			tx,
			cursor,
			seek: false,
			prefix: prefix.to_vec(),
			deserialize,
			reverse,
		}
	}
}

#[cfg(test)]
mod test {
	use crate::lmdb::Store;
	use crate::ser::{BinReader, Reader, Serializable, Writer};
	use nioruntime_err::Error;
	use std::io::Cursor;

	#[derive(Debug, PartialEq, Eq, Clone)]
	struct TestData {
		f1: u8,
		f2: u128,
	}

	impl Serializable for TestData {
		fn read<R: Reader>(reader: &mut R) -> Result<Self, Error> {
			let f1 = reader.read_u8()?;
			let f2 = reader.read_u128()?;
			Ok(Self { f1, f2 })
		}
		fn write<W: Writer>(&self, writer: &mut W) -> Result<(), Error> {
			writer.write_u8(self.f1)?;
			writer.write_u128(self.f2)?;
			Ok(())
		}
	}

	#[derive(Debug)]
	struct BadData {
		f1: u128,
		f2: u128,
	}

	impl Serializable for BadData {
		fn read<R: Reader>(reader: &mut R) -> Result<Self, Error> {
			let f1 = reader.read_u128()?;
			let f2 = reader.read_u128()?;
			Ok(Self { f1, f2 })
		}
		fn write<W: Writer>(&self, writer: &mut W) -> Result<(), Error> {
			writer.write_u128(self.f1)?;
			writer.write_u128(self.f2)?;
			Ok(())
		}
	}

	#[test]
	fn test_reverse() -> Result<(), Error> {
		let store = Store::new(".lmdbrev.nio", None, Some("test"), None, true)?;
		let td1 = TestData { f1: 10, f2: 20 };
		let td2 = TestData { f1: 100, f2: 200 };
		let td3 = TestData { f1: 101, f2: 201 };
		{
			let batch = store.batch()?;
			batch.put_ser(b"ha", &td1)?;
			batch.put_ser(b"hb", &td2)?;
			batch.put_ser(b"hc", &td3)?;
			batch.commit()?;
		}

		{
			let batch = store.batch()?;

			let mut itt = batch.iter(&(b"h")[..], |_k, v| {
				let mut cursor = Cursor::new(v.to_vec());
				cursor.set_position(0);
				let mut reader = BinReader::new(&mut cursor);
				Ok(TestData::read(&mut reader)?)
			})?;

			assert!(itt.next() == Some(td1.clone()));
			assert!(itt.next() == Some(td2.clone()));
			assert!(itt.next() == Some(td3.clone()));
			assert!(itt.next() == None);

			let mut itt = batch.iter_rev(&(b"h")[..], |_k, v| {
				let mut cursor = Cursor::new(v.to_vec());
				cursor.set_position(0);
				let mut reader = BinReader::new(&mut cursor);
				Ok(TestData::read(&mut reader)?)
			})?;

			assert!(itt.next() == Some(td3));
			assert!(itt.next() == Some(td2));
			assert!(itt.next() == Some(td1));
			assert!(itt.next() == None);
		}

		std::fs::remove_dir_all(".lmdbrev.nio")?;

		Ok(())
	}

	#[test]
	fn test_store() -> Result<(), Error> {
		let store = Store::new(".lmdbtest.nio", None, Some("test"), None, true)?;
		let td1 = TestData { f1: 10, f2: 20 };
		let td2 = TestData { f1: 100, f2: 200 };
		let td3 = TestData { f1: 101, f2: 201 };
		{
			let batch = store.batch()?;
			batch.put_ser(b"hi", &td1)?;
			batch.put_ser(b"ho", &td2)?;
			batch.put_ser(b"xyz", &td3)?;
			assert!(batch.exists(b"xyz")?);
			batch.put_ser(b"zzz", &td3)?;
			batch.put_ser(b"vvv", &BadData { f1: 0, f2: 0 })?;
			batch.commit()?;
		}

		{
			let batch = store.batch()?;
			batch.delete(b"zzz")?;
			assert!(batch.exists(b"zzz")? == false);
			assert!(batch.get_ser::<BadData>(b"vvv")?.is_some());
			let data = batch.get_ser::<TestData>(b"hi")?;
			assert!(data.is_some());
			let data = data.unwrap();
			assert_eq!(data.f1, 10);
			assert_eq!(data.f2, 20);
			let data = batch.get_ser::<TestData>(b"x")?;
			assert!(data.is_none());
			assert!(batch.get_ser::<BadData>(b"hi").is_err());

			let mut itt = batch.iter(&(b"h")[..], |_k, v| {
				let mut cursor = Cursor::new(v.to_vec());
				cursor.set_position(0);
				let mut reader = BinReader::new(&mut cursor);
				Ok(TestData::read(&mut reader)?)
			})?;

			let mut count = 0;
			loop {
				match itt.next() {
					Some(test_data) => {
						count += 1;
						assert!(test_data != td3);
						assert!(test_data == td1 || test_data == td2);
					}
					None => break,
				}
			}
			assert_eq!(count, 2);

			let mut itt = batch.iter(&(b"h")[..], |_k, v| {
				let mut cursor = Cursor::new(v.to_vec());
				cursor.set_position(0);
				let mut reader = BinReader::new(&mut cursor);
				Ok(BadData::read(&mut reader)?)
			})?;

			assert!(itt.next().is_none());
		}

		std::fs::remove_dir_all(".lmdbtest.nio")?;

		Ok(())
	}
}
