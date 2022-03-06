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

/// Basic statistics for this static hash
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
		// can't reset other fields.
		self.access_count = 0;
		self.total_node_reads = 0;
		self.worst_case_visits = 0;
	}
}

/// Iterator
pub struct StaticHashIterator {
	pos: usize,
	hashtable: StaticHash,
}

impl StaticHashIterator {
	/// Create a new StaticHashIterator
	pub fn new(hashtable: StaticHash) -> Result<StaticHashIterator, Error> {
		Ok(StaticHashIterator { pos: 0, hashtable })
	}

	/// Get the next element in the iterator
	pub fn next(&mut self, key: &mut [u8], value: &mut [u8]) -> Result<bool, Error> {
		loop {
			if self.pos >= self.hashtable.max_entries {
				break;
			}
			let overhead_byte = self.hashtable.get_overhead_byte(self.pos);
			if overhead_byte == OCCUPIED {
				let res = self.hashtable.copy_key(key, self.pos);
				if res.is_ok() {
					let res = self.hashtable.copy_value(value, self.pos);
					if res.is_ok() {
						self.pos += 1;
						return Ok(true);
					} else {
						return Err(ErrorKind::OtherError("error copying value".to_string()).into());
					}
				} else {
					return Err(ErrorKind::OtherError("error copying key".to_string()).into());
				}
			}

			self.pos += 1;
		}

		Ok(false)
	}
}

/// Static hash object. A hashtable with fixed size.
/// format of the hashtable:
/// [overhead byte: 0 - empty, 1 - occupied, 2 - deleted][key - key_len bytes][value - entry_len bytes]
#[derive(Clone)]
pub struct StaticHash {
	data: Vec<u8>,
	/// Max entries in this table
	pub max_entries: usize,
	key_len: usize,
	entry_len: usize,
	/// Maximum load factor allowed
	max_load_factor: f64,
	/// Basic statistics for this static hash
	pub stats: StaticHashStats,
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
	pub fn new(
		max_entries: usize,
		key_len: usize,
		entry_len: usize,
		max_load_factor: f64,
	) -> Result<StaticHash, Error> {
		if max_load_factor >= 1 as f64 || max_load_factor <= 0 as f64 {
			return Err(ErrorKind::InvalidMaxLoadCapacity.into());
		}
		let mut data = Vec::new();
		data.resize(max_entries * (1 + key_len + entry_len) as usize, 0);
		let max_entries = max_entries.try_into().unwrap_or(0);
		Ok(StaticHash {
			data,
			max_entries,
			key_len,
			entry_len,
			max_load_factor,
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
		if key.len() != self.key_len as usize {
			return None;
		}
		let hash = self.get_hash(key);
		let mut count = 0;
		loop {
			let entry = (hash + count) % self.max_entries;
			let ohb = self.get_overhead_byte(entry);
			if ohb == EMPTY {
				return None;
			} else if ohb == OCCUPIED && self.cmp_key(key, entry) {
				let offset = (1 + self.key_len + self.entry_len) * entry + 1 + self.key_len;

				return Some(&self.data.as_slice()[offset..(offset + self.entry_len)]);
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
		if key.len() != self.key_len as usize {
			return Err(ErrorKind::BadKeyLen(key.len(), self.key_len).into());
		}
		if value.len() != self.entry_len as usize {
			return Err(ErrorKind::BadValueLen(value.len(), self.entry_len).into());
		}
		if (self.stats.cur_elements + 1) as f64 / self.max_entries as f64 > self.max_load_factor {
			return Err(ErrorKind::MaxLoadCapacityExceeded.into());
		}
		let hash = self.get_hash(key);
		let mut count = 0;
		loop {
			let entry = (hash + count) % self.max_entries;
			let ohb = self.get_overhead_byte(entry);
			if ohb == EMPTY || ohb == DELETED {
				// empty spot
				self.set_overhead_byte(entry, OCCUPIED);
				self.set_key(entry, key);
				self.set_value(entry, value);
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
		if key.len() != self.key_len as usize {
			return None;
		}
		let hash = self.get_hash(key);
		let mut count = 0;
		loop {
			let entry = (hash + count) % self.max_entries;
			let ohb = self.get_overhead_byte(entry);
			if ohb == OCCUPIED {
				if self.cmp_key(key, entry) {
					// this is us, flag entry as deleted.
					self.set_overhead_byte(entry, DELETED);
					self.stats.cur_elements -= 1;
					let start: usize =
						((1 + self.key_len + self.entry_len) * entry) + 1 + self.key_len;
					let end: usize = start + self.entry_len;
					return Some(&self.data[start..end]);
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
		let offset = (1 + self.key_len + self.entry_len) * entry;
		self.data[offset]
	}

	fn set_overhead_byte(&mut self, entry: usize, value: u8) {
		let offset = (1 + self.key_len + self.entry_len) * entry;
		self.data[offset] = value;
	}

	fn get_hash(&mut self, key: &[u8]) -> usize {
		self.stats.access_count += 1;
		let mut hasher = DefaultHasher::new();
		Key { data: key.to_vec() }.hash(&mut hasher);

		// u32 is good enough. Nothing less than 32 bit platforms right?
		let u32_max: u64 = u32::MAX.into();
		let hasher_usize: usize = (hasher.finish() % u32_max).try_into().unwrap();
		hasher_usize % self.max_entries
	}

	fn copy_key(&mut self, key: &mut [u8], entry: usize) -> Result<(), Error> {
		let offset = ((1 + self.key_len + self.entry_len) * entry) + 1;
		copy(&self.data.as_slice()[offset..(offset + self.key_len)], key);
		Ok(())
	}

	fn copy_value(&mut self, value: &mut [u8], entry: usize) -> Result<(), Error> {
		let offset = (1 + self.key_len + self.entry_len) * entry + (1 + self.key_len);
		copy(
			&self.data.as_slice()[offset..(offset + self.entry_len)],
			value,
		);
		Ok(())
	}

	fn cmp_key(&mut self, key: &[u8], entry: usize) -> bool {
		let len = key.len();
		let offset = (1 + self.key_len + self.entry_len) * entry + 1;
		for i in 0..len {
			if self.data[offset + i] != key[i] {
				return false;
			}
		}
		return true;
	}

	fn set_value(&mut self, entry: usize, value: &[u8]) {
		let offset = (1 + self.key_len + self.entry_len) * entry + 1 + self.key_len;
		copy(value, &mut self.data.as_mut_slice()[offset..]);
	}

	fn set_key(&mut self, entry: usize, key: &[u8]) {
		let offset = (1 + self.key_len + self.entry_len) * entry + 1;
		copy(key, &mut self.data.as_mut_slice()[offset..]);
	}
}

#[cfg(test)]
mod test {
	use super::*;
	use crate::ser::{Reader, Writer};
	use nioruntime_deps::rand::{thread_rng, Rng};

	#[test]
	fn test_static_hash() {
		let mut hashtable = StaticHash::new(10, 8, 8, 0.9).unwrap();
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

		let mut hashtable = StaticHash::new(30, 3, 3, 0.9).unwrap();

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
		let mut hashtable = StaticHash::new(100000, 16, 32, 0.9).unwrap();
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
		let mut hashtable = StaticHash::new(100000, 16, 32, 0.9).unwrap();
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

		let mut hashtable = StaticHash::new(9, 16, 32, 0.9).unwrap();

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

		let mut hashtable = StaticHash::new(9, 16, 32, 0.9).unwrap();

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

		let mut input = Vec::new();
		input.insert(0, k1);
		input.insert(1, k3);
		input.insert(2, k4);
		input.insert(3, k5);
		input.sort();
		let mut vinput = Vec::new();
		vinput.insert(0, v1);
		vinput.insert(1, v3);
		vinput.insert(2, v4);
		vinput.insert(3, v5);
		vinput.sort();

		let iterator = StaticHashIterator::new(hashtable);
		assert_eq!(iterator.is_err(), false);
		let mut iterator = iterator.unwrap();

		let mut k1: [u8; 16] = rng.gen();
		let mut k2: [u8; 16] = rng.gen();
		let mut k3: [u8; 16] = rng.gen();
		let mut k4: [u8; 16] = rng.gen();
		let mut k5: [u8; 16] = rng.gen();

		let mut v1: [u8; 32] = rng.gen();
		let mut v2: [u8; 32] = rng.gen();
		let mut v3: [u8; 32] = rng.gen();
		let mut v4: [u8; 32] = rng.gen();
		let mut v5: [u8; 32] = rng.gen();

		let res = iterator.next(&mut k1, &mut v1);
		assert_eq!(res.is_ok(), true);
		assert_eq!(res.unwrap(), true);

		let res = iterator.next(&mut k2, &mut v2);
		assert_eq!(res.is_ok(), true);
		assert_eq!(res.unwrap(), true);

		let res = iterator.next(&mut k3, &mut v3);
		assert_eq!(res.is_ok(), true);
		assert_eq!(res.unwrap(), true);

		let res = iterator.next(&mut k4, &mut v4);
		assert_eq!(res.is_ok(), true);
		assert_eq!(res.unwrap(), true);

		let res = iterator.next(&mut k5, &mut v5);
		assert_eq!(res.is_ok(), true);
		assert_eq!(res.unwrap(), false);

		let mut output = Vec::new();
		output.insert(0, k1);
		output.insert(0, k2);
		output.insert(0, k3);
		output.insert(0, k4);
		output.sort();

		let mut voutput = Vec::new();
		voutput.insert(0, v1);
		voutput.insert(0, v2);
		voutput.insert(0, v3);
		voutput.insert(0, v4);
		voutput.sort();

		assert_eq!(input, output);
		assert_eq!(vinput, voutput);
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
		let mut hashtable = StaticHash::new(100, 16, 12, 0.9).unwrap();
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
