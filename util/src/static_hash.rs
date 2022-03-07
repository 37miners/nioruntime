// Copyright 2021 The BitcoinMW Developers
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

use crate::ser::{deserialize, serialize, Serializable};
use nioruntime_deps::byte_tools::copy;
use nioruntime_err::{Error, ErrorKind};
use nioruntime_log::*;
use std::collections::hash_map::DefaultHasher;
use std::convert::TryInto;
use std::hash::{Hash, Hasher};

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
	fn reset(&mut self) {
		self.max_elements = self.cur_elements;
		self.access_count = 0;
		self.total_node_reads = 0;
		self.worst_case_visits = 0;
	}
}

/// Iterator
pub struct StaticHashIterator<'a> {
	pos: usize,
	reverse: bool,
	static_hash: &'a StaticHash,
}

impl<'a> StaticHashIterator<'a> {
	/// Create a new StaticHashIterator
	pub fn new(static_hash: &StaticHash) -> Result<StaticHashIterator, Error> {
		Ok(StaticHashIterator {
			pos: static_hash.first,
			static_hash,
			reverse: false,
		})
	}

	pub fn reverse(static_hash: &StaticHash) -> Result<StaticHashIterator, Error> {
		Ok(StaticHashIterator {
			pos: static_hash.last,
			static_hash,
			reverse: true,
		})
	}

	pub fn next(&mut self) -> Result<Option<(&[u8], &[u8])>, Error> {
		if self.pos == usize::MAX {
			Ok(None)
		} else {
			let offset = if self.reverse {
				self.static_hash.get_iterator_prev_offset(self.pos)
			} else {
				self.static_hash.get_iterator_next_offset(self.pos)
			};
			let k_offset = self.static_hash.get_key_offset(self.pos);
			let v_offset = self.static_hash.get_value_offset(self.pos);
			self.pos = usize::from_be_bytes(self.static_hash.data[offset..offset + 8].try_into()?);
			Ok(Some((
				&self.static_hash.data[k_offset..k_offset + self.static_hash.config.key_len],
				&self.static_hash.data[v_offset..v_offset + self.static_hash.config.entry_len],
			)))
		}
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
			max_entries: 1_000_000,
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
pub struct StaticHash {
	data: Vec<u8>,
	config: StaticHashConfig,
	stats: StaticHashStats,
	first: usize,
	last: usize,
}

#[derive(Hash)]
struct Key {
	data: Vec<u8>,
}

impl Drop for StaticHash {
	fn drop(&mut self) {
		// explicitly drain to free memory
		self.data.drain(..);
	}
}

impl StaticHash {
	/// Create a new instance of StaticHash
	pub fn new(config: StaticHashConfig) -> Result<StaticHash, Error> {
		if config.max_load_factor >= 1 as f64 || config.max_load_factor <= 0 as f64 {
			return Err(ErrorKind::InvalidMaxLoadCapacity.into());
		}
		let mut data = Vec::new();

		let iterator_size = if config.iterator { 16 } else { 0 };

		data.resize(
			config.max_entries * (1 + config.key_len + config.entry_len + iterator_size) as usize,
			0u8,
		);
		Ok(StaticHash {
			data,
			config,
			first: usize::MAX,
			last: usize::MAX,
			stats: StaticHashStats {
				max_elements: 0,
				cur_elements: 0,
				access_count: 0,
				total_node_reads: 0,
				worst_case_visits: 0,
			},
		})
	}

	/// Return the current size of this static_hash
	pub fn size(&self) -> usize {
		self.stats.cur_elements
	}

	pub fn get<K: Serializable, V: Serializable>(&mut self, key: &K) -> Option<V> {
		let mut key_buf = vec![];
		serialize(&mut key_buf, key).ok()?;
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
		let mut count = 0;
		loop {
			let entry = (hash + count) % self.config.max_entries;
			let ohb = self.get_overhead_byte(entry);
			if ohb == EMPTY {
				return None;
			} else if ohb == OCCUPIED && self.cmp_key(key, entry) {
				let offset = self.get_value_offset(entry);

				return Some(&self.data.as_slice()[offset..(offset + self.config.entry_len)]);
			}
			count += 1;
			if count > self.stats.worst_case_visits {
				self.stats.worst_case_visits = count;
			}
		}
	}

	pub fn put<K: Serializable, V: Serializable>(
		&mut self,
		key: &K,
		value: &V,
	) -> Result<(), Error> {
		let mut key_buf = vec![];
		let mut value_buf = vec![];
		serialize(&mut key_buf, key)?;
		serialize(&mut value_buf, value)?;
		self.put_raw(&key_buf, &value_buf)?;
		Ok(())
	}

	/// Put this value for specified key
	pub fn put_raw(&mut self, key: &[u8], value: &[u8]) -> Result<(), Error> {
		if key.len() != self.config.key_len as usize {
			return Err(ErrorKind::BadKeyLen(key.len(), self.config.key_len).into());
		}
		if value.len() != self.config.entry_len as usize {
			return Err(ErrorKind::BadValueLen(value.len(), self.config.entry_len).into());
		}
		if (self.stats.cur_elements + 1) as f64 / self.config.max_entries as f64
			> self.config.max_load_factor
		{
			return Err(ErrorKind::MaxLoadCapacityExceeded.into());
		}
		let hash = self.get_hash(key);
		let mut count = 0;
		loop {
			let entry = (hash + count) % self.config.max_entries;
			let ohb = self.get_overhead_byte(entry);
			if ohb == EMPTY || ohb == DELETED {
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
				break;
			}

			if ohb == OCCUPIED && self.cmp_key(key, entry) {
				// already present, overwrite value
				self.set_value(entry, value);
				break;
			}

			count += 1;
			if count > self.stats.worst_case_visits {
				self.stats.worst_case_visits = count;
			}
		}
		Ok(())
	}

	fn put_iterator(&mut self, entry: usize) -> Result<(), Error> {
		if self.last == usize::MAX {
			self.last = entry;
		}

		// set next entry to the current first
		let offset = self.get_iterator_next_offset(entry);
		let ebytes = self.first.to_be_bytes();
		self.data[offset..offset + 8].clone_from_slice(&ebytes);

		// set the prev pointer to usize::MAX (end of chain)
		let offset = self.get_iterator_prev_offset(entry);
		let ebytes = usize::MAX.to_be_bytes();
		self.data[offset..offset + 8].clone_from_slice(&ebytes);

		// update the prev pointer of the current first to point to
		// the new entry
		if self.first != usize::MAX {
			let offset = self.get_iterator_prev_offset(self.first);
			let ebytes = entry.to_be_bytes();
			self.data[offset..offset + 8].clone_from_slice(&ebytes);
		}

		// set first to this new entry
		self.first = entry;

		Ok(())
	}

	fn remove_iterator(&mut self, entry: usize) -> Result<(), Error> {
		let offset = self.get_iterator_next_offset(entry);
		let next = usize::from_be_bytes(self.data[offset..offset + 8].try_into()?);

		let offset = self.get_iterator_prev_offset(entry);
		let prev = usize::from_be_bytes(self.data[offset..offset + 8].try_into()?);

		if prev == usize::MAX {
			self.first = next;
		} else {
			let offset = self.get_iterator_next_offset(prev);
			let ebytes = next.to_be_bytes();
			self.data[offset..offset + 8].clone_from_slice(&ebytes);
		}

		if next == usize::MAX {
			self.last = prev;
		} else {
			let offset = self.get_iterator_prev_offset(next);
			let ebytes = prev.to_be_bytes();
			self.data[offset..offset + 8].clone_from_slice(&ebytes);
		}

		Ok(())
	}

	pub fn remove<K: Serializable, V: Serializable>(&mut self, key: &K) -> Option<V> {
		let mut key_buf = vec![];
		serialize(&mut key_buf, key).ok()?;
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
		let mut count = 0;
		loop {
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
			count += 1;
			if count > self.stats.worst_case_visits {
				self.stats.worst_case_visits = count;
			}
		}
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

		// u32 is good enough. Nothing less than 32 bit platforms right?
		let u32_max: u64 = u32::MAX.into();
		let hasher_usize: usize = (hasher.finish() % u32_max).try_into().unwrap();
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
		(1 + self.config.key_len
			+ self.config.entry_len
			+ if self.config.iterator { 16 } else { 0 })
			* entry
	}
}

#[cfg(test)]
mod test {
	use super::*;
	use crate::ser::{Reader, Writer};
	use nioruntime_deps::rand::{thread_rng, Rng};

	#[test]
	fn test_static_hash1() {
		let mut hashtable = StaticHash::new(StaticHashConfig {
			max_entries: 10,
			key_len: 8,
			entry_len: 8,
			max_load_factor: 0.9,
			..Default::default()
		})
		.unwrap();
		let key1 = [1, 2, 3, 4, 5, 6, 7, 8];
		let key2 = [8, 7, 6, 5, 4, 3, 2, 1];

		let value1 = [1, 1, 1, 1, 1, 1, 1, 1];
		let value2 = [2, 2, 2, 2, 2, 2, 2, 2];
		let res1 = hashtable.put_raw(&key1, &value1);
		let res2 = hashtable.put_raw(&key2, &value2);
		assert_eq!(res1.is_err(), false);
		assert_eq!(res2.is_err(), false);

		let get1 = hashtable.get_raw(&key1);
		assert!(get1.is_some());
		assert_eq!(value1, get1.unwrap());

		let get2 = hashtable.get_raw(&key2);
		assert!(get2.is_some());
		assert_eq!(value2, get2.unwrap());

		// test wrong sizes
		let badkey = [1, 2, 3];
		let bad_put = hashtable.put_raw(&badkey, &value1);
		assert_eq!(bad_put.is_err(), true);

		let badvalue = [4, 5, 6];
		let bad_put = hashtable.put_raw(&key1, &badvalue);
		assert_eq!(bad_put.is_err(), true);

		// overwrite value

		let mut hashtable = StaticHash::new(StaticHashConfig {
			max_entries: 30,
			key_len: 3,
			entry_len: 3,
			max_load_factor: 0.9,
			..Default::default()
		})
		.unwrap();

		let key1 = [3, 3, 3];
		let value1 = [4, 4, 4];
		let value2 = [5, 5, 5];

		let res1 = hashtable.put_raw(&key1, &value1);
		let res2 = hashtable.put_raw(&key1, &value2);
		assert_eq!(res1.is_err(), false);
		assert_eq!(res2.is_err(), false);

		let res = hashtable.get_raw(&key1);
		assert_eq!(res.is_some(), true);

		let res = res.unwrap();
		assert_eq!(res, [5, 5, 5]);
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
			let ret = hashtable.put_raw(&k1, &v1);
			assert_eq!(ret.is_err(), false);
			kvec.insert(i, k1);
			vvec.insert(i, v1);
		}

		// remove several entries

		let res = hashtable.remove_raw(&kvec[45]);
		assert_eq!(res.is_some(), true);
		assert_eq!(res.unwrap(), vvec[45]);
		assert_eq!(hashtable.remove_raw(&kvec[45]), None);
		kvec.remove(45);
		vvec.remove(45);

		let res = hashtable.remove_raw(&kvec[37]);
		assert_eq!(res.is_some(), true);
		assert_eq!(res.unwrap(), vvec[37]);
		assert_eq!(hashtable.remove_raw(&kvec[37]), None);
		kvec.remove(37);
		vvec.remove(37);

		let res = hashtable.remove_raw(&kvec[13]);
		assert_eq!(res.is_some(), true);
		assert_eq!(res.unwrap(), vvec[13]);
		assert_eq!(hashtable.remove_raw(&kvec[13]), None);
		kvec.remove(13);
		vvec.remove(13);

		for i in 0..75997 {
			//let mut vread = [0 as u8; 32];
			let res = hashtable.get_raw(&kvec[i]);
			assert_eq!(res.is_some(), true);
			let vread = res.unwrap();
			vreadvec.insert(i, vread.try_into().unwrap());
		}
		assert_eq!(vreadvec, vvec);
	}

	#[test]
	fn test_static_hash_stats() {
		let mut rng = thread_rng();
		let mut hashtable = StaticHash::new(StaticHashConfig {
			max_entries: 100000,
			key_len: 16,
			entry_len: 32,
			max_load_factor: 0.9,
			..Default::default()
		})
		.unwrap();
		let k1: [u8; 16] = rng.gen();
		let v1: [u8; 32] = rng.gen();
		let ret = hashtable.put_raw(&k1, &v1);
		assert_eq!(ret.is_ok(), true);

		let k2: [u8; 16] = rng.gen();
		let v2: [u8; 32] = rng.gen();
		let ret = hashtable.put_raw(&k2, &v2);
		assert_eq!(ret.is_ok(), true);

		let k3: [u8; 16] = rng.gen();
		let v3: [u8; 32] = rng.gen();
		let ret = hashtable.put_raw(&k3, &v3);
		assert_eq!(ret.is_ok(), true);

		let k4: [u8; 16] = rng.gen();
		let v4: [u8; 32] = rng.gen();
		let ret = hashtable.put_raw(&k4, &v4);
		assert_eq!(ret.is_ok(), true);

		let res = hashtable.remove_raw(&k2);
		assert_eq!(res.unwrap(), v2);
		assert_eq!(hashtable.stats.cur_elements, 3);
		assert_eq!(hashtable.stats.max_elements, 4);
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
			let res = hashtable.put_raw(&k, &v);
			assert_eq!(res.is_ok(), true);
		}

		let k1: [u8; 16] = rng.gen();
		let v1: [u8; 32] = rng.gen();

		let k2: [u8; 16] = rng.gen();
		let v2: [u8; 32] = rng.gen();

		let res = hashtable.put_raw(&k1, &v1);
		assert_eq!(res.is_ok(), true);

		let res = hashtable.put_raw(&k2, &v2);
		assert_eq!(res.is_ok(), false);

		let res = hashtable.remove_raw(&k1);
		assert_eq!(res.is_some(), true);
		assert_eq!(res.unwrap(), v1);

		let res = hashtable.put_raw(&k2, &v2);
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

		let res = hashtable.put_raw(&k1, &v1);
		assert_eq!(res.is_ok(), true);

		let res = hashtable.put_raw(&k2, &v2);
		assert_eq!(res.is_ok(), true);

		let res = hashtable.put_raw(&k3, &v3);
		assert_eq!(res.is_ok(), true);

		let res = hashtable.put_raw(&k4, &v4);
		assert_eq!(res.is_ok(), true);

		let res = hashtable.put_raw(&k5, &v5);
		assert_eq!(res.is_ok(), true);
		let res = hashtable.remove_raw(&k2);
		assert_eq!(res.is_some(), true);
		assert_eq!(res.unwrap(), v2);

		let iterator = StaticHashIterator::new(&hashtable);
		assert_eq!(iterator.is_err(), false);
		let mut iterator = iterator.unwrap();

		let next = iterator.next();
		let (k_out, v_out) = next.unwrap().unwrap();
		assert_eq!(k_out, k5);
		assert_eq!(v_out, v5);

		let next = iterator.next();
		let (k_out, v_out) = next.unwrap().unwrap();
		assert_eq!(k_out, k4);
		assert_eq!(v_out, v4);

		let next = iterator.next();
		let (k_out, v_out) = next.unwrap().unwrap();
		assert_eq!(k_out, k3);
		assert_eq!(v_out, v3);

		let next = iterator.next();
		let (k_out, v_out) = next.unwrap().unwrap();
		assert_eq!(k_out, k1);
		assert_eq!(v_out, v1);

		let next = iterator.next();
		assert!(next.unwrap().is_none());

		// try reverse a iterator
		let iterator = StaticHashIterator::reverse(&hashtable);
		assert_eq!(iterator.is_err(), false);
		let mut iterator = iterator.unwrap();

		let next = iterator.next();
		let (k_out, v_out) = next.unwrap().unwrap();
		assert_eq!(k_out, k1);
		assert_eq!(v_out, v1);

		let next = iterator.next();
		let (k_out, v_out) = next.unwrap().unwrap();
		assert_eq!(k_out, k3);
		assert_eq!(v_out, v3);

		let next = iterator.next();
		let (k_out, v_out) = next.unwrap().unwrap();
		assert_eq!(k_out, k4);
		assert_eq!(v_out, v4);

		let next = iterator.next();
		let (k_out, v_out) = next.unwrap().unwrap();
		assert_eq!(k_out, k5);
		assert_eq!(v_out, v5);

		let next = iterator.next();
		assert!(next.unwrap().is_none());

		let res = hashtable.remove_raw(&k1);
		assert_eq!(res.is_some(), true);
		assert_eq!(res.unwrap(), v1);

		let iterator = StaticHashIterator::new(&hashtable);
		assert_eq!(iterator.is_err(), false);
		let mut iterator = iterator.unwrap();

		let next = iterator.next();
		let (k_out, v_out) = next.unwrap().unwrap();
		assert_eq!(k_out, k5);
		assert_eq!(v_out, v5);

		let next = iterator.next();
		let (k_out, v_out) = next.unwrap().unwrap();
		assert_eq!(k_out, k4);
		assert_eq!(v_out, v4);

		let next = iterator.next();
		let (k_out, v_out) = next.unwrap().unwrap();
		assert_eq!(k_out, k3);
		assert_eq!(v_out, v3);

		let next = iterator.next();
		assert!(next.unwrap().is_none());

		let res = hashtable.remove_raw(&k5);
		assert_eq!(res.is_some(), true);
		assert_eq!(res.unwrap(), v5);

		let iterator = StaticHashIterator::new(&hashtable);
		assert_eq!(iterator.is_err(), false);
		let mut iterator = iterator.unwrap();

		let next = iterator.next();
		let (k_out, v_out) = next.unwrap().unwrap();
		assert_eq!(k_out, k4);
		assert_eq!(v_out, v4);

		let next = iterator.next();
		let (k_out, v_out) = next.unwrap().unwrap();
		assert_eq!(k_out, k3);
		assert_eq!(v_out, v3);

		let next = iterator.next();
		assert!(next.unwrap().is_none());

		let res = hashtable.remove_raw(&k3);
		assert_eq!(res.is_some(), true);
		assert_eq!(res.unwrap(), v3);

		let iterator = StaticHashIterator::new(&hashtable);
		assert_eq!(iterator.is_err(), false);
		let mut iterator = iterator.unwrap();

		let next = iterator.next();
		let (k_out, v_out) = next.unwrap().unwrap();
		assert_eq!(k_out, k4);
		assert_eq!(v_out, v4);

		let next = iterator.next();
		assert!(next.unwrap().is_none());

		let res = hashtable.remove_raw(&k4);
		assert_eq!(res.is_some(), true);
		assert_eq!(res.unwrap(), v4);

		let iterator = StaticHashIterator::new(&hashtable);
		assert_eq!(iterator.is_err(), false);
		let mut iterator = iterator.unwrap();

		let next = iterator.next();
		assert!(next.unwrap().is_none());
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

	struct K {
		x: u128,
	}

	impl Serializable for K {
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

		let k1 = K { x: 123 };
		let k2 = K { x: 456 };
		let k3 = K { x: 789 };

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
}
