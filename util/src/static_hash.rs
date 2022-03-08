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

use crate::ser::{deserialize, serialize, BinReader, Serializable};
use nioruntime_deps::byte_tools::copy;
use nioruntime_err::{Error, ErrorKind};
use nioruntime_log::*;
use std::collections::hash_map::DefaultHasher;
use std::convert::TryInto;
use std::hash::{Hash, Hasher};
use std::io::Cursor;
use std::marker::PhantomData;

const EMPTY: u8 = 0;
const OCCUPIED: u8 = 1;
const DELETED: u8 = 2;

debug!();

/// Statistics for this static hash
#[derive(Debug, Clone)]
pub struct StaticHashStats {
	/// Max elements that have ever been in this table at one given time
	pub max_elements: usize,
	/// Current number of elements in the table
	pub cur_elements: usize,
	/// Total of times the 'get' function is called
	pub access_count: usize,
	/// Total of node visits on a get (collision results in at least two node visits)
	/// Note that if errors are returned the get is not counted.
	pub total_node_reads: usize,
	/// Worst case visits
	pub worst_case_visits: usize,
}

impl StaticHashStats {
	fn new() -> Self {
		Self {
			max_elements: 0,
			cur_elements: 0,
			access_count: 0,
			total_node_reads: 0,
			worst_case_visits: 0,
		}
	}

	fn reset(&mut self) {
		self.max_elements = self.cur_elements;
		self.access_count = 0;
		self.total_node_reads = 0;
		self.worst_case_visits = 0;
	}
}

#[derive(Clone)]
pub struct StaticHashConfig {
	pub max_entries: usize,
	pub key_len: usize,
	pub entry_len: usize,
	pub max_load_factor: f64,
	pub iterator: bool,
}

impl Default for StaticHashConfig {
	fn default() -> Self {
		Self {
			max_entries: 1_000,
			key_len: 8,
			entry_len: 8,
			max_load_factor: 0.9999999,
			iterator: true,
		}
	}
}

/// Static hash object. A hashtable with fixed size.
/// format of the hashtable:
/// [overhead byte: 0 - empty, 1 - occupied, 2 - deleted][key - key_len bytes][value - entry_len bytes]
#[derive(Clone)]
pub struct StaticHash<K: Serializable, V: Serializable> {
	data: Vec<u8>,
	config: StaticHashConfig,
	stats: StaticHashStats,
	first: u64,
	last: u64,
	pos: u64,
	_phantom_data1: PhantomData<K>,
	_phantom_data2: PhantomData<V>,
}

#[derive(Hash)]
struct Key {
	data: Vec<u8>,
}

impl<K: Serializable, V: Serializable> Drop for StaticHash<K, V> {
	fn drop(&mut self) {
		// explicitly drain to free memory
		self.data.drain(..);
	}
}

impl<K: Serializable, V: Serializable> Iterator for &mut StaticHash<K, V> {
	type Item = (K, V);

	fn next(&mut self) -> Option<Self::Item> {
		if self.pos == u64::MAX {
			self.pos = self.last;
			None
		} else {
			let offset = self.get_iterator_prev_offset(self.pos.try_into().ok()?);
			let k_offset = self.get_key_offset(self.pos.try_into().ok()?);
			let v_offset = self.get_value_offset(self.pos.try_into().ok()?);
			self.pos = u64::from_be_bytes(self.data[offset..offset + 8].try_into().ok()?);

			let vec1 = self.data[k_offset..k_offset + self.config.key_len].to_vec();
			let vec2 = self.data[v_offset..v_offset + self.config.entry_len].to_vec();

			let mut cursor1 = Cursor::new(vec1);
			let mut cursor2 = Cursor::new(vec2);
			let mut reader1 = BinReader::new(&mut cursor1);
			let mut reader2 = BinReader::new(&mut cursor2);

			let elem1 = Serializable::read(&mut reader1).ok()?;
			let elem2 = Serializable::read(&mut reader2).ok()?;
			let ret = (elem1, elem2);

			Some(ret)
		}
	}
}

impl<K: Serializable, V: Serializable> StaticHash<K, V> {
	/// Create a new instance of StaticHash
	pub fn new(config: StaticHashConfig) -> Result<StaticHash<K, V>, Error> {
		if config.max_load_factor > 1 as f64 || config.max_load_factor <= 0 as f64 {
			return Err(ErrorKind::InvalidMaxLoadCapacity.into());
		}
		let mut data = Vec::new();

		let iterator_size = if config.iterator { 16 } else { 0 };
		let max_entries = config.max_entries;
		let key_len = config.key_len;
		let entry_len = config.entry_len;

		let entry_count = max_entries * (1 + key_len + entry_len + iterator_size) as usize;
		data.resize(entry_count, 0u8);

		let ret = StaticHash {
			data,
			config,
			first: u64::MAX,
			last: u64::MAX,
			pos: u64::MAX,
			stats: StaticHashStats::new(),
			_phantom_data1: PhantomData,
			_phantom_data2: PhantomData,
		};

		Ok(ret)
	}

	/// Return the current size of this static_hash
	pub fn size(&self) -> usize {
		self.stats.cur_elements
	}

	pub fn get(&mut self, key: &K) -> Option<V> {
		let mut key_buf = vec![];
		serialize(&mut key_buf, key).ok()?;
		Self::ensure_length(&mut key_buf, self.config.key_len);
		match self.get_raw(&key_buf) {
			Some(mut o) => {
				let res: Result<V, Error> = deserialize(&mut o);
				match res {
					Ok(res) => Some(res),
					Err(e) => {
						warn!("deserialization error: {}", e).ok();
						None
					}
				}
			}
			None => None,
		}
	}

	/// Get this key
	pub fn get_raw(&mut self, key: &[u8]) -> Option<&[u8]> {
		if key.len() != self.config.key_len as usize {
			return None;
		}
		let hash = self.get_hash(key);

		for count in 0..self.config.max_entries {
			let n = hash + count;
			let entry = n % self.config.max_entries;
			let ohb = self.get_overhead_byte(entry);
			if ohb == EMPTY {
				return None;
			} else if ohb == OCCUPIED {
				if self.cmp_key(key, entry) {
					let offset = self.get_value_offset(entry);
					let ret = self.data.as_slice();
					let start = offset;
					let end = offset + self.config.entry_len;
					let ret = &ret[start..end];
					return Some(ret);
				}
			}
			if count + 1 > self.stats.worst_case_visits {
				self.stats.worst_case_visits = count + 1;
			}
		}

		// not found
		return None;
	}

	fn ensure_length(buf: &mut Vec<u8>, len: usize) {
		for _ in buf.len()..len {
			buf.push(0);
		}
	}

	pub fn put(&mut self, key: &K, value: &V) -> Result<(), Error> {
		let mut key_buf = vec![];
		let mut value_buf = vec![];
		serialize(&mut key_buf, key)?;
		serialize(&mut value_buf, value)?;
		Self::ensure_length(&mut key_buf, self.config.key_len);
		Self::ensure_length(&mut value_buf, self.config.entry_len);
		self.put_raw(&key_buf, &value_buf)?;
		Ok(())
	}

	/// Put this value for specified key
	pub fn put_raw(&mut self, key: &[u8], value: &[u8]) -> Result<(), Error> {
		if key.len() != self.config.key_len as usize {
			let actual = key.len();
			let expect = self.config.key_len;
			let error: Error = ErrorKind::BadKeyLen(actual, expect).into();
			return Err(error);
		}
		if value.len() != self.config.entry_len as usize {
			let actual = value.len();
			let expect = self.config.entry_len;
			let error: Error = ErrorKind::BadValueLen(actual, expect).into();
			return Err(error);
		}
		let hash = self.get_hash(key);

		for count in 0..self.config.max_entries {
			let entry = (hash + count) % self.config.max_entries;
			let ohb = self.get_overhead_byte(entry);
			if ohb == EMPTY || ohb == DELETED {
				let cur_elements = (self.stats.cur_elements + 1) as f64;
				let cur_load_factor = cur_elements / self.config.max_entries as f64;
				if cur_load_factor > self.config.max_load_factor {
					return Err(ErrorKind::MaxLoadCapacityExceeded.into());
				}

				// empty spot
				self.set_overhead_byte(entry, OCCUPIED);
				self.set_key(entry, key);
				self.set_value(entry, value);
				if self.config.iterator {
					self.put_iterator(entry)?;
				}
				self.stats.cur_elements += 1;
				if self.stats.cur_elements > self.stats.max_elements {
					self.stats.max_elements = self.stats.cur_elements;
				}
				return Ok(());
			}

			if ohb == OCCUPIED && self.cmp_key(key, entry) {
				// already present, overwrite value
				self.set_value(entry, value);
				return Ok(());
			}

			if count + 1 > self.stats.worst_case_visits {
				self.stats.worst_case_visits = count + 1;
			}
		}

		return Err(ErrorKind::MaxLoadCapacityExceeded.into());
	}

	fn put_iterator(&mut self, entry: usize) -> Result<(), Error> {
		if self.last == u64::MAX {
			self.last = entry.try_into()?;
			self.pos = self.last;
		}

		// set next entry to the current first
		let offset = self.get_iterator_next_offset(entry);
		let ebytes = self.first.to_be_bytes();
		self.data[offset..offset + 8].clone_from_slice(&ebytes);

		// set the prev pointer to u64::MAX (end of chain)
		let offset = self.get_iterator_prev_offset(entry);
		let ebytes = u64::MAX.to_be_bytes();
		self.data[offset..offset + 8].clone_from_slice(&ebytes);

		// update the prev pointer of the current first to point to
		// the new entry
		if self.first != u64::MAX {
			let offset = self.get_iterator_prev_offset(self.first.try_into()?);
			let ebytes = entry.to_be_bytes();
			self.data[offset..offset + 8].clone_from_slice(&ebytes);
		}

		// set first to this new entry
		self.first = entry.try_into()?;

		Ok(())
	}

	fn remove_iterator(&mut self, entry: usize) -> Result<(), Error> {
		let offset = self.get_iterator_next_offset(entry);
		let next = u64::from_be_bytes(self.data[offset..offset + 8].try_into()?);

		let offset = self.get_iterator_prev_offset(entry);
		let prev = u64::from_be_bytes(self.data[offset..offset + 8].try_into()?);

		if prev == u64::MAX {
			self.first = next;
		} else {
			let offset = self.get_iterator_next_offset(prev.try_into()?);
			let ebytes = next.to_be_bytes();
			self.data[offset..offset + 8].clone_from_slice(&ebytes);
		}

		if next == u64::MAX {
			self.last = prev;
			self.pos = prev;
		} else {
			let offset = self.get_iterator_prev_offset(next.try_into()?);
			let ebytes = prev.to_be_bytes();
			self.data[offset..offset + 8].clone_from_slice(&ebytes);
		}

		Ok(())
	}

	pub fn remove(&mut self, key: &K) -> Option<V> {
		let mut key_buf = vec![];
		serialize(&mut key_buf, key).ok()?;
		Self::ensure_length(&mut key_buf, self.config.key_len);
		match self.remove_raw(&key_buf) {
			Some(mut o) => {
				let res: Result<V, Error> = deserialize(&mut o);
				match res {
					Ok(res) => Some(res),
					Err(e) => {
						warn!("deserialization error: {}", e).ok();
						None
					}
				}
			}
			None => None,
		}
	}

	/// Remove the speicifed key
	pub fn remove_raw(&mut self, key: &[u8]) -> Option<&[u8]> {
		if key.len() != self.config.key_len as usize {
			return None;
		}
		let hash = self.get_hash(key);

		for count in 0..self.config.max_entries {
			let entry = (hash + count) % self.config.max_entries;
			let ohb = self.get_overhead_byte(entry);
			if ohb == OCCUPIED {
				if self.cmp_key(key, entry) {
					// this is us, flag entry as deleted.
					self.set_overhead_byte(entry, DELETED);

					if self.config.iterator {
						self.remove_iterator(entry).ok()?;
					}

					self.stats.cur_elements -= 1;
					let offset = self.get_value_offset(entry);
					return Some(&self.data[offset..offset + self.config.entry_len]);
				}
			// otherwise, this is not us, we continue
			} else if ohb == EMPTY {
				// we didn't find this entry.
				return None;
			} // otherwise, it's another deleted entry, we need to continue
			if count + 1 > self.stats.worst_case_visits {
				self.stats.worst_case_visits = count + 1;
			}
		}

		None
	}

	/// Reset the stats fields
	pub fn reset_stats(&mut self) {
		self.stats.reset();
	}

	fn get_overhead_byte(&mut self, entry: usize) -> u8 {
		self.stats.total_node_reads += 1;
		let offset = self.get_overhead_offset(entry);
		self.data[offset]
	}

	fn set_overhead_byte(&mut self, entry: usize, value: u8) {
		let offset = self.get_overhead_offset(entry);
		self.data[offset] = value;
	}

	fn get_hash(&mut self, key: &[u8]) -> usize {
		self.stats.access_count += 1;
		let mut hasher = DefaultHasher::new();
		Key { data: key.to_vec() }.hash(&mut hasher);

		let max: u64 = usize::MAX.try_into().unwrap_or(u64::MAX);
		let hasher_usize: usize = (hasher.finish() % max).try_into().unwrap();
		hasher_usize % self.config.max_entries
	}

	fn cmp_key(&mut self, key: &[u8], entry: usize) -> bool {
		let len = key.len();
		let offset = self.get_key_offset(entry);
		for i in 0..len {
			if self.data[offset + i] != key[i] {
				return false;
			}
		}
		return true;
	}

	fn set_value(&mut self, entry: usize, value: &[u8]) {
		let offset = self.get_value_offset(entry);
		copy(value, &mut self.data.as_mut_slice()[offset..]);
	}

	fn set_key(&mut self, entry: usize, key: &[u8]) {
		let offset = self.get_key_offset(entry);
		copy(key, &mut self.data.as_mut_slice()[offset..]);
	}

	fn get_key_offset(&self, entry: usize) -> usize {
		self.get_offset(entry) + 1 + if self.config.iterator { 16 } else { 0 }
	}

	fn get_value_offset(&self, entry: usize) -> usize {
		self.get_offset(entry) + 1 + if self.config.iterator { 16 } else { 0 } + self.config.key_len
	}

	fn get_iterator_next_offset(&self, entry: usize) -> usize {
		self.get_offset(entry) + 1
	}

	fn get_iterator_prev_offset(&self, entry: usize) -> usize {
		self.get_offset(entry) + 9
	}

	fn get_overhead_offset(&self, entry: usize) -> usize {
		self.get_offset(entry)
	}

	fn get_offset(&self, entry: usize) -> usize {
		let config = &self.config;
		let key_len = config.key_len;
		let entry_len = config.entry_len;
		let iterator = if self.config.iterator { 16 } else { 0 };
		(1 + key_len + entry_len + iterator) * entry
	}
}

#[cfg(test)]
mod test {
	use super::*;
	use crate::ser::{Reader, Writer};
	use nioruntime_deps::rand::{thread_rng, Rng};

	#[test]
	fn test_default() -> Result<(), Error> {
		let mut hashtable = StaticHash::new(StaticHashConfig::default())?;
		let i: u64 = 1;
		let j: u64 = 2;
		let k: u64 = 3;
		assert!(hashtable.put(&i, &j).is_ok());
		assert!(hashtable.put(&i, &k).is_ok());
		assert_eq!(hashtable.size(), 1);

		Ok(())
	}

	#[test]
	fn test_static_hash1() {
		let mut hashtable = StaticHash::new(StaticHashConfig {
			max_entries: 10,
			key_len: 9,
			entry_len: 9,
			max_load_factor: 0.9,
			..Default::default()
		})
		.unwrap();

		// lower sizes are ok
		let value1: [u8; 8] = [1, 1, 1, 1, 1, 1, 1, 1];
		let value2: [u8; 8] = [2, 2, 2, 2, 2, 2, 2, 2];

		let i: u64 = 1;
		let j: u64 = 7;
		let k: u64 = 100;
		hashtable.put(&i, &value1).unwrap();
		hashtable.put(&j, &value2).unwrap();

		assert_eq!(hashtable.get(&i), Some(value1));
		assert_eq!(hashtable.get(&j), Some(value2));

		// greater sizes fail
		let mut hashtable = StaticHash::new(StaticHashConfig {
			max_entries: 10,
			key_len: 1,
			entry_len: 9,
			max_load_factor: 0.9,
			..Default::default()
		})
		.unwrap();

		assert!(hashtable.put(&i, &[1 as u8, 2 as u8]).is_err());

		// overwrite
		let mut hashtable = StaticHash::new(StaticHashConfig {
			max_entries: 10,
			key_len: 9,
			entry_len: 9,
			max_load_factor: 0.9,
			..Default::default()
		})
		.unwrap();

		hashtable.put(&i, &j).unwrap();
		assert_eq!(hashtable.get(&i), Some(j));
		hashtable.put(&i, &k).unwrap();
		assert_eq!(hashtable.get(&i), Some(k));
	}

	#[test]
	fn test_static_hash_advanced() {
		let mut hashtable = StaticHash::new(StaticHashConfig {
			max_entries: 100000,
			key_len: 16,
			entry_len: 32,
			max_load_factor: 0.9,
			..Default::default()
		})
		.unwrap();
		let mut rng = thread_rng();
		let mut kvec: Vec<[u8; 16]> = Vec::new();
		let mut vvec: Vec<[u8; 32]> = Vec::new();
		let mut vreadvec: Vec<[u8; 32]> = Vec::new();

		for i in 0..76000 {
			let k1: [u8; 16] = rng.gen();
			let v1: [u8; 32] = rng.gen();
			let ret = hashtable.put(&k1, &v1);
			assert_eq!(ret.is_err(), false);
			kvec.insert(i, k1);
			vvec.insert(i, v1);
		}
		// remove several entries

		let res = hashtable.remove(&kvec[45]);
		assert_eq!(res.is_some(), true);
		assert_eq!(res.unwrap(), vvec[45]);
		assert_eq!(hashtable.remove(&kvec[45]), None);
		kvec.remove(45);
		vvec.remove(45);

		let res = hashtable.remove(&kvec[37]);
		assert_eq!(res.is_some(), true);
		assert_eq!(res.unwrap(), vvec[37]);
		assert_eq!(hashtable.remove(&kvec[37]), None);
		kvec.remove(37);
		vvec.remove(37);

		let res = hashtable.remove(&kvec[13]);
		assert_eq!(res.is_some(), true);
		assert_eq!(res.unwrap(), vvec[13]);
		assert_eq!(hashtable.remove(&kvec[13]), None);
		kvec.remove(13);
		vvec.remove(13);
		for i in 0..75997 {
			let res = hashtable.get(&kvec[i]);
			assert_eq!(res.is_some(), true);
			let vread = res.unwrap();
			vreadvec.insert(i, vread.try_into().unwrap());
		}
		assert_eq!(vreadvec, vvec);
	}

	#[test]
	fn test_static_hash_stats() {
		let mut hashtable = StaticHash::new(StaticHashConfig {
			max_entries: 10,
			key_len: 1,
			entry_len: 2,
			max_load_factor: 0.9,
			..Default::default()
		})
		.unwrap();
		let k1: [u8; 1] = [1];
		let v1: [u8; 2] = [1, 1];
		let ret = hashtable.put(&k1, &v1);
		assert_eq!(ret.is_ok(), true);

		let k2: [u8; 1] = [2];
		let v2: [u8; 2] = [2, 2];
		let ret = hashtable.put(&k2, &v2);
		assert_eq!(ret.is_ok(), true);

		let k3: [u8; 1] = [3];
		let v3: [u8; 2] = [3, 3];
		let ret = hashtable.put(&k3, &v3);
		assert_eq!(ret.is_ok(), true);

		let k4: [u8; 1] = [4];
		let v4: [u8; 2] = [4, 4];
		let ret = hashtable.put(&k4, &v4);
		assert_eq!(ret.is_ok(), true);

		let res = hashtable.remove(&k2);
		assert_eq!(res.unwrap(), v2);

		assert_eq!(hashtable.stats.cur_elements, 3);
		assert_eq!(hashtable.stats.max_elements, 4);
		assert_eq!(hashtable.stats.access_count, 5);
		// this table has one collision
		assert_eq!(hashtable.stats.total_node_reads, 6);
		assert_eq!(hashtable.stats.worst_case_visits, 1);

		let mut hashtable = StaticHash::new(StaticHashConfig {
			max_entries: 10000,
			key_len: 1,
			entry_len: 2,
			max_load_factor: 0.9,
			..Default::default()
		})
		.unwrap();
		let k1: [u8; 1] = [1];
		let v1: [u8; 2] = [1, 1];
		let ret = hashtable.put(&k1, &v1);
		assert_eq!(ret.is_ok(), true);

		let k2: [u8; 1] = [2];
		let v2: [u8; 2] = [2, 2];
		let ret = hashtable.put(&k2, &v2);
		assert_eq!(ret.is_ok(), true);

		let k3: [u8; 1] = [3];
		let v3: [u8; 2] = [3, 3];
		let ret = hashtable.put(&k3, &v3);
		assert_eq!(ret.is_ok(), true);

		let k4: [u8; 1] = [4];
		let v4: [u8; 2] = [4, 4];
		let ret = hashtable.put(&k4, &v4);
		assert_eq!(ret.is_ok(), true);

		let res = hashtable.remove(&k2);
		assert_eq!(res.unwrap(), v2);

		assert_eq!(hashtable.stats.cur_elements, 3);
		assert_eq!(hashtable.stats.max_elements, 4);
		assert_eq!(hashtable.stats.access_count, 5);
		// this table has no collisions
		assert_eq!(hashtable.stats.total_node_reads, 5);
		assert_eq!(hashtable.stats.worst_case_visits, 0);

		// reset
		hashtable.reset_stats();
		assert_eq!(hashtable.stats.cur_elements, 3);
		assert_eq!(hashtable.stats.max_elements, 3);
		assert_eq!(hashtable.stats.access_count, 0);
		assert_eq!(hashtable.stats.total_node_reads, 0);
		assert_eq!(hashtable.stats.worst_case_visits, 0);
	}

	#[test]
	fn test_static_hash_load_factor() {
		let mut rng = thread_rng();

		let mut hashtable = StaticHash::new(StaticHashConfig {
			max_entries: 9,
			key_len: 16,
			entry_len: 32,
			max_load_factor: 0.9,
			..Default::default()
		})
		.unwrap();

		for _ in 0..7 {
			let k: [u8; 16] = rng.gen();
			let v: [u8; 32] = rng.gen();
			let res = hashtable.put(&k, &v);
			assert_eq!(res.is_ok(), true);
		}

		let k1: [u8; 16] = rng.gen();
		let v1: [u8; 32] = rng.gen();

		let k2: [u8; 16] = rng.gen();
		let v2: [u8; 32] = rng.gen();

		let res = hashtable.put(&k1, &v1);
		assert_eq!(res.is_ok(), true);

		let res = hashtable.put(&k2, &v2);
		assert_eq!(res.is_ok(), false);

		let res = hashtable.remove(&k1);
		assert_eq!(res.is_some(), true);
		assert_eq!(res.unwrap(), v1);

		let res = hashtable.put(&k2, &v2);
		assert_eq!(res.is_ok(), true);
	}

	#[test]
	fn test_static_hash_iterator() {
		let mut rng = thread_rng();

		let mut hashtable = StaticHash::new(StaticHashConfig {
			max_entries: 9,
			key_len: 16,
			entry_len: 32,
			max_load_factor: 0.9,
			iterator: true,
		})
		.unwrap();

		let k1: [u8; 16] = rng.gen();
		let v1: [u8; 32] = rng.gen();

		let k2: [u8; 16] = rng.gen();
		let v2: [u8; 32] = rng.gen();

		let k3: [u8; 16] = rng.gen();
		let v3: [u8; 32] = rng.gen();

		let k4: [u8; 16] = rng.gen();
		let v4: [u8; 32] = rng.gen();

		let k5: [u8; 16] = rng.gen();
		let v5: [u8; 32] = rng.gen();

		let res = hashtable.put(&k1, &v1);
		assert_eq!(res.is_ok(), true);

		let res = hashtable.put(&k2, &v2);
		assert_eq!(res.is_ok(), true);

		let res = hashtable.put(&k3, &v3);
		assert_eq!(res.is_ok(), true);

		let res = hashtable.put(&k4, &v4);
		assert_eq!(res.is_ok(), true);

		let res = hashtable.put(&k5, &v5);
		assert_eq!(res.is_ok(), true);

		let mut k_v = vec![];
		k_v.push((k1, v1));
		k_v.push((k2, v2));
		k_v.push((k3, v3));
		k_v.push((k4, v4));
		k_v.push((k5, v5));

		let mut counter = 0;
		for (k, v) in &mut hashtable {
			assert_eq!(k, k_v[counter].0);
			assert_eq!(v, k_v[counter].1);
			counter += 1;
		}
		assert_eq!(counter, 5);

		let res = hashtable.remove(&k2);
		assert_eq!(res.is_some(), true);
		assert_eq!(res.unwrap(), v2);

		let mut k_v = vec![];
		k_v.push((k1, v1));
		k_v.push((k3, v3));
		k_v.push((k4, v4));
		k_v.push((k5, v5));

		let mut counter = 0;
		for (k, v) in &mut hashtable {
			assert_eq!(k, k_v[counter].0);
			assert_eq!(v, k_v[counter].1);
			counter += 1;
		}
		assert_eq!(counter, 4);

		let res = hashtable.remove(&k1);
		assert_eq!(res.is_some(), true);
		assert_eq!(res.unwrap(), v1);

		let mut k_v = vec![];
		k_v.push((k3, v3));
		k_v.push((k4, v4));
		k_v.push((k5, v5));

		let mut counter = 0;
		for (k, v) in &mut hashtable {
			assert_eq!(k, k_v[counter].0);
			assert_eq!(v, k_v[counter].1);
			counter += 1;
		}
		assert_eq!(counter, 3);

		let res = hashtable.remove(&k5);
		assert_eq!(res.is_some(), true);
		assert_eq!(res.unwrap(), v5);

		let mut k_v = vec![];
		k_v.push((k3, v3));
		k_v.push((k4, v4));

		let mut counter = 0;
		for (k, v) in &mut hashtable {
			assert_eq!(k, k_v[counter].0);
			assert_eq!(v, k_v[counter].1);
			counter += 1;
		}
		assert_eq!(counter, 2);

		let res = hashtable.remove(&k3);
		assert_eq!(res.is_some(), true);
		assert_eq!(res.unwrap(), v3);

		let mut k_v = vec![];
		k_v.push((k4, v4));

		let mut counter = 0;
		for (k, v) in &mut hashtable {
			assert_eq!(k, k_v[counter].0);
			assert_eq!(v, k_v[counter].1);
			counter += 1;
		}
		assert_eq!(counter, 1);

		let res = hashtable.remove(&k4);
		assert_eq!(res.is_some(), true);
		assert_eq!(res.unwrap(), v4);

		assert!((&mut hashtable).next().is_none());
	}

	#[derive(Debug, PartialEq, Clone)]
	struct S {
		flags: u8,
		data: Vec<u8>,
	}

	impl Serializable for S {
		fn read<R: Reader>(reader: &mut R) -> Result<Self, Error> {
			let flags = reader.read_u8()?;
			let data = Serializable::read(reader)?;
			Ok(Self { flags, data })
		}

		fn write<W: Writer>(&self, writer: &mut W) -> Result<(), Error> {
			writer.write_u8(self.flags)?;
			Serializable::write(&self.data, writer)?;
			Ok(())
		}
	}

	#[derive(Debug, PartialEq)]
	struct Key {
		x: u128,
	}

	impl Serializable for Key {
		fn read<R: Reader>(reader: &mut R) -> Result<Self, Error> {
			let x = reader.read_u128()?;
			Ok(Self { x })
		}

		fn write<W: Writer>(&self, writer: &mut W) -> Result<(), Error> {
			writer.write_u128(self.x)?;
			Ok(())
		}
	}

	#[test]
	fn test_serialize() -> Result<(), Error> {
		let mut hashtable = StaticHash::new(StaticHashConfig {
			max_entries: 100,
			key_len: 16,
			entry_len: 12,
			max_load_factor: 0.9,
			..Default::default()
		})
		.unwrap();
		let v1 = vec![1, 2, 3];
		let v2 = vec![4, 5, 6];
		let v3 = vec![7, 8, 9];

		let s1 = S { data: v1, flags: 0 };
		let s2 = S { data: v2, flags: 1 };
		let s3 = S { data: v3, flags: 4 };

		let k1 = Key { x: 123 };
		let k2 = Key { x: 456 };
		let k3 = Key { x: 789 };

		let mut key_buf = vec![];
		serialize(&mut key_buf, &k1)?;
		let res: Result<Key, Error> = deserialize(&mut &key_buf[..]);
		assert_eq!(res.unwrap(), k1);

		hashtable.put(&k1, &s1)?;
		hashtable.put(&k2, &s2)?;
		hashtable.put(&k3, &s3)?;

		let r1: Option<S> = hashtable.get(&k1);
		assert_eq!(r1, Some(s1.clone()));
		let r2: Option<S> = hashtable.get(&k2);
		assert_eq!(r2, Some(s2.clone()));
		let r3: Option<S> = hashtable.get(&k3);
		assert_eq!(r3, Some(s3.clone()));

		let r2: Option<S> = hashtable.remove(&k2);
		assert_eq!(r2, Some(s2.clone()));

		let r3: Option<S> = hashtable.get(&k3);
		assert_eq!(r3, Some(s3.clone()));

		let r3: Option<S> = hashtable.remove(&k3);
		assert_eq!(r3, Some(s3.clone()));

		let r3: Option<S> = hashtable.get(&k3);
		assert_eq!(r3, None);

		let r1: Option<S> = hashtable.get(&k1);
		assert_eq!(r1, Some(s1.clone()));

		let r1: Option<S> = hashtable.remove(&k1);
		assert_eq!(r1, Some(s1.clone()));

		let r1: Option<S> = hashtable.get(&k1);
		assert_eq!(r1, None);

		let r2: Option<S> = hashtable.remove(&k2);
		assert_eq!(r2, None);

		Ok(())
	}

	#[derive(Debug)]
	struct VarSize {
		a: u8,
		b: u8,
	}

	impl Serializable for VarSize {
		fn read<R: Reader>(reader: &mut R) -> Result<Self, Error> {
			let a = reader.read_u8()?;
			let b = if a == 0 { 0 } else { reader.read_u8()? };
			Ok(Self { a, b })
		}

		fn write<W: Writer>(&self, writer: &mut W) -> Result<(), Error> {
			Serializable::write(&self.a, writer)?;
			if self.a == 0 {
				Serializable::write(&self.b, writer)?;
			}
			Ok(())
		}
	}

	#[test]
	fn test_config() -> Result<(), Error> {
		let config = StaticHashConfig {
			max_entries: 3,
			key_len: 2,
			entry_len: 2,
			max_load_factor: 0.999999,
			iterator: true,
		};

		let mut sh: StaticHash<VarSize, VarSize> = StaticHash::new(config)?;
		assert!(sh.put_raw(&[0, 1, 2], &[1, 2]).is_err());
		assert!(sh.put_raw(&[1, 1], &[1, 2, 3]).is_err());
		assert!(sh
			.put(&VarSize { a: 1, b: 2 }, &VarSize { a: 1, b: 2 })
			.is_ok());
		assert!(sh
			.put(&VarSize { a: 0, b: 2 }, &VarSize { a: 0, b: 2 })
			.is_ok());

		// full but overwrite
		assert!(sh
			.put(&VarSize { a: 0, b: 2 }, &VarSize { a: 0, b: 2 })
			.is_ok());

		// full new value, can't add
		assert!(sh
			.put(&VarSize { a: 0, b: 20 }, &VarSize { a: 0, b: 2 })
			.is_err());

		// low load factor

		let config = StaticHashConfig {
			max_entries: 3,
			key_len: 2,
			entry_len: 2,
			max_load_factor: 0.01,
			iterator: true,
		};

		let mut sh: StaticHash<VarSize, VarSize> = StaticHash::new(config)?;
		assert!(sh
			.put(&VarSize { a: 1, b: 2 }, &VarSize { a: 1, b: 2 })
			.is_err());

		// no iterator
		let mut config = StaticHashConfig {
			max_entries: 3,
			key_len: 2,
			entry_len: 2,
			max_load_factor: 0.99,
			iterator: false,
		};

		let mut sh: StaticHash<VarSize, VarSize> = StaticHash::new(config.clone())?;
		assert!(sh
			.put(&VarSize { a: 1, b: 2 }, &VarSize { a: 1, b: 2 })
			.is_ok());
		assert!(sh
			.put(&VarSize { a: 0, b: 2 }, &VarSize { a: 0, b: 2 })
			.is_ok());

		assert!((&mut sh).next().is_none());

		// with iterator
		config.iterator = true;
		let mut sh: StaticHash<VarSize, VarSize> = StaticHash::new(config.clone())?;
		assert!(sh
			.put(&VarSize { a: 1, b: 2 }, &VarSize { a: 1, b: 2 })
			.is_ok());
		assert!(sh
			.put(&VarSize { a: 0, b: 2 }, &VarSize { a: 0, b: 2 })
			.is_ok());

		let mut count = 0;
		for _ in &mut sh {
			count += 1;
		}
		assert_eq!(count, 2);

		config.max_load_factor = 1.1;
		let sh: Result<StaticHash<(), ()>, Error> = StaticHash::new(config);
		assert!(sh.is_err());

		Ok(())
	}

	#[derive(Debug)]
	struct DeserError {
		a: u8,
		b: u8,
	}

	impl Serializable for DeserError {
		fn read<R: Reader>(reader: &mut R) -> Result<Self, Error> {
			let a = reader.read_u8()?;
			let b = reader.read_u8()?;
			if a == 0 {
				Err(ErrorKind::ApplicationError("blah".into()).into())
			} else {
				Ok(Self { a, b })
			}
		}

		fn write<W: Writer>(&self, writer: &mut W) -> Result<(), Error> {
			Serializable::write(&self.a, writer)?;
			Serializable::write(&self.b, writer)?;
			Ok(())
		}
	}

	#[test]
	fn test_deser_error() -> Result<(), Error> {
		let mut sh: StaticHash<DeserError, DeserError> =
			StaticHash::new(StaticHashConfig::default())?;
		assert!(sh
			.put(&DeserError { a: 0, b: 0 }, &DeserError { a: 0, b: 0 })
			.is_ok());
		assert!(sh.get(&DeserError { a: 0, b: 0 }).is_none());
		assert!(sh.remove(&DeserError { a: 0, b: 0 }).is_none());
		assert!(sh.get_raw(&[]).is_none());
		assert!(sh
			.put(&DeserError { a: 1, b: 0 }, &DeserError { a: 1, b: 0 })
			.is_ok());
		assert!(sh.get(&DeserError { a: 1, b: 0 }).is_some());

		Ok(())
	}

	#[test]
	fn test_full() -> Result<(), Error> {
		let mut sh: StaticHash<(), ()> = StaticHash::new(StaticHashConfig {
			max_entries: 3,
			key_len: 1,
			entry_len: 1,
			max_load_factor: 1.0,
			..Default::default()
		})?;

		sh.put_raw(&[0], &[0])?;
		sh.put_raw(&[1], &[1])?;
		sh.put_raw(&[2], &[2])?;

		assert!(sh.get_raw(&[3]).is_none());
		assert!(sh.remove_raw(&[3]).is_none());
		assert!(sh.remove_raw(&[]).is_none());

		let mut sh: StaticHash<(), ()> = StaticHash::new(StaticHashConfig {
			max_entries: 3,
			key_len: 1,
			entry_len: 1,
			max_load_factor: 1.0,
			..Default::default()
		})?;

		sh.put_raw(&[0], &[0])?;
		sh.put_raw(&[1], &[1])?;
		sh.put_raw(&[2], &[2])?;

		assert!(sh.remove_raw(&[3]).is_none());
		assert!(sh.get_raw(&[3]).is_none());
		assert!(sh.remove_raw(&[]).is_none());

		let mut sh: StaticHash<(), ()> = StaticHash::new(StaticHashConfig {
			max_entries: 3,
			key_len: 1,
			entry_len: 1,
			max_load_factor: 1.0,
			..Default::default()
		})?;

		sh.put_raw(&[0], &[0])?;
		sh.put_raw(&[1], &[1])?;
		sh.put_raw(&[2], &[2])?;
		assert!(sh.put_raw(&[3], &[3]).is_err());

		Ok(())
	}
}
