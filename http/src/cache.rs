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

use nioruntime_deps::sha2::{Digest, Sha256};
use nioruntime_err::{Error, ErrorKind};
use nioruntime_log::*;
use nioruntime_util::slabs::{Slab, SlabAllocator};
use nioruntime_util::{StaticHash, StaticHashConfig};
use std::convert::TryInto;
use std::io::Write;

debug!();

#[derive(Debug)]
pub struct Iter<'a> {
	cur: u64,
	cache: &'a HttpCache,
}

impl<'a> Iterator for Iter<'a> {
	type Item = &'a [u8];

	fn next(&mut self) -> Option<Self::Item> {
		if self.cur == u64::MAX {
			None
		} else {
			match self.cache.slabs.get(self.cur) {
				Ok(slab) => {
					self.cur = u64::from_be_bytes(slab.data[0..8].try_into().unwrap());
					Some(&slab.data[25..])
				}
				Err(e) => {
					let _ = error!("couldn't get slab due to: {}", e);
					None
				}
			}
		}
	}
}

// key is 256 byte sha256 hash of the cleaned file path.
// value are the chunk id (u64) from slab allocator. StaticHash's iterator starts with the oldest entry
// so we delete based on the iterator.
// each chunk looks like this
// first chunk has [8 bytes next chunk][8 bytes file_len][8 bytes last chunk] -> chunk_id[1 byte is complete if done saving]
// all subsequent chunks have
// [8 bytes next chunk] -> chunk_id. Until the end of the list which is u64::MAX
// followed by file data.
#[derive(Debug)]
pub struct HttpCache {
	map: StaticHash<(), ()>,
	slabs: SlabAllocator,
	chunk_size: u64,
	cur_slabs: u64,
	cur_entries: u64,
	max_slabs: u64,
	max_entries: u64,
}

impl HttpCache {
	pub fn new(
		max_entries: usize,
		max_slabs: u64,
		chunk_size: u64,
		max_load_factor: f64,
	) -> Result<Self, Error> {
		if chunk_size < 16 {
			Err(ErrorKind::IllegalArgument(format!(
				"Invalid chunk_size {}. Must be greater than or equal to 16.",
				chunk_size
			))
			.into())
		} else {
			Ok(Self {
				map: StaticHash::new(StaticHashConfig {
					max_entries,
					iterator: true,
					key_len: 32,
					entry_len: 8,
					max_load_factor,
				})?,
				slabs: SlabAllocator::new(max_slabs, chunk_size + 25),
				chunk_size,
				cur_slabs: 0,
				cur_entries: 0,
				max_slabs,
				max_entries: (max_entries as f64 * max_load_factor).floor() as u64,
			})
		}
	}

	pub fn iter(&self, file: &String) -> Result<(Iter, u64), Error> {
		let mut hasher = Sha256::new();
		hasher.update(file.as_bytes());
		let key: [u8; 32] = hasher.finalize()[..].try_into()?;
		Ok(match self.map.get_raw(&key) {
			Some(entry) => {
				let cur = u64::from_be_bytes(entry.try_into()?);
				let slab = self.slabs.get(cur)?;
				match slab.data[24] {
					0 => (
						Iter {
							cur: u64::MAX,
							cache: self,
						},
						0,
					),
					_ => {
						let len = u64::from_be_bytes(slab.data[8..16].try_into()?);
						debug!("entry = {}", cur)?;
						(Iter { cur, cache: self }, len)
					}
				}
			}
			None => (
				Iter {
					cur: u64::MAX,
					cache: self,
				},
				0,
			),
		})
	}

	pub fn append_file_chunk(
		&mut self,
		file: &String,
		value: &[u8],
		len: Option<u64>,
		complete: bool,
	) -> Result<(), Error> {
		let value_len = value.len();
		let chunk_size = self.chunk_size.try_into()?;

		if value_len > chunk_size {
			return Err(ErrorKind::IllegalArgument(format!(
				"Invalid length '{}'. Chunk size is {}.",
				value.len(),
				self.chunk_size
			))
			.into());
		}

		let mut hasher = Sha256::new();
		hasher.write(file.as_bytes())?;
		let key: [u8; 32] = hasher.finalize()[..].try_into()?;
		if self.cur_slabs >= self.max_slabs || self.cur_entries >= self.max_entries {
			self.free_oldest()?;
		}

		let new_entry = match self.map.get_raw(&key) {
			Some(entry) => {
				let nchunk_id = {
					self.cur_slabs += 1;
					let slab = self.slabs.allocate()?;
					slab.data[25..25 + value_len].clone_from_slice(&value);
					slab.data[0..8].clone_from_slice(&u64::MAX.to_be_bytes());
					slab.id
				};

				let entry = u64::from_be_bytes(entry.try_into()?);
				let first = self.slabs.get_mut(entry)?;
				if complete {
					first.data[24] = 1;
				}
				let last = u64::from_be_bytes(first.data[16..24].try_into()?);

				first.data[16..24].clone_from_slice(&nchunk_id.to_be_bytes());
				let last_chunk = self.slabs.get_mut(last)?;
				last_chunk.data[0..8].clone_from_slice(&nchunk_id.to_be_bytes());

				None
			}
			None => match len {
				Some(len) => {
					self.cur_slabs += 1;
					let entry = self.slabs.allocate()?;
					entry.data[25..25 + value_len].clone_from_slice(&value);
					entry.data[0..8].clone_from_slice(&u64::MAX.to_be_bytes());
					entry.data[8..16].clone_from_slice(&len.to_be_bytes());
					entry.data[16..24].clone_from_slice(&entry.id.to_be_bytes());
					if complete {
						entry.data[24] = 1;
					} else {
						entry.data[24] = 0;
					}
					Some(entry.id)
				}
				None => {
					return Err(ErrorKind::IllegalArgument(
						"Expected len to be specified for first chunk.".into(),
					)
					.into());
				}
			},
		};

		match new_entry {
			Some(entry) => {
				self.cur_entries += 1;
				self.map.insert_raw(&key, &entry.to_be_bytes())?;
			}
			None => {}
		}

		Ok(())
	}

	pub fn exists(&self, file: &String) -> Result<bool, Error> {
		let mut hasher = Sha256::new();
		hasher.update(file.as_bytes());
		let key: [u8; 32] = hasher.finalize()[..].try_into()?;
		Ok(self.map.get_raw(&key).is_some())
	}

	fn free_oldest(&mut self) -> Result<(), Error> {
		let k = match self.map.iter_raw().next() {
			Some((k, _v)) => k.to_owned(),
			None => {
				error!("Inconsistent state! No slab to remove!")?;
				return Err(ErrorKind::NoMoreSlabs.into());
			}
		};

		debug!("removing k={:?}", k)?;
		let mut entry = match self.map.remove_raw(&k) {
			Some(oldest) => {
				let oldest = u64::from_be_bytes(oldest.try_into()?);
				debug!("oldest = {}", oldest)?;
				oldest
			}
			None => {
				error!("Inconsistent state! No slab to remove!")?;
				return Err(ErrorKind::NoMoreSlabs.into());
			}
		};

		loop {
			if entry == u64::MAX {
				break;
			}

			let (id, next) = {
				let slab = self.slabs.get(entry)?;
				let next = u64::from_be_bytes(slab.data[0..8].try_into()?);
				(slab.id, next)
			};
			debug!("freeing id = {}", id)?;
			self.slabs.free(&Slab { id, data: &[] })?;

			entry = next;
		}
		Ok(())
	}
}

#[cfg(test)]
mod test {
	use crate::cache::HttpCache;
	use nioruntime_err::Error;
	use nioruntime_log::*;

	debug!();

	#[test]
	fn test_cache() -> Result<(), Error> {
		debug!("calling new")?;
		let mut cache = HttpCache::new(30, 5, 16, 0.99)?;
		let file1 = "/abc.html".to_string();
		let file2 = "/a/def.html".to_string();

		debug!("calling append")?;
		cache.append_file_chunk(
			&file1,
			&[0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15],
			Some(16),
			true,
		)?;

		cache.append_file_chunk(
			&file2,
			&[1, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15],
			Some(32),
			false,
		)?;
		cache.append_file_chunk(
			&file2,
			&[2, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15],
			None,
			true,
		)?;

		let (mut iter, len) = cache.iter(&file1)?;
		assert_eq!(len, 16);
		assert_eq!(
			iter.next().unwrap(),
			&[0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15]
		);
		assert!(iter.next().is_none());

		let (mut iter, len) = cache.iter(&file2)?;
		assert_eq!(len, 32);
		assert_eq!(
			iter.next().unwrap(),
			&[1, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15]
		);
		assert_eq!(
			iter.next().unwrap(),
			&[2, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15]
		);
		assert!(iter.next().is_none());

		Ok(())
	}

	#[test]
	fn test_cache_remove_file_slabs() -> Result<(), Error> {
		let mut cache = HttpCache::new(30, 3, 16, 0.99)?;

		let file1 = "/abc.html".to_string();
		let file2 = "/def.html".to_string();
		let file3 = "/ghi.html".to_string();

		cache.append_file_chunk(
			&file1,
			&[0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15],
			Some(16),
			true,
		)?;

		let (mut iter, len) = cache.iter(&file1)?;
		assert_eq!(len, 16);
		assert_eq!(
			iter.next().unwrap(),
			&[0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15]
		);
		assert!(iter.next().is_none());

		// now append a 3 chunk file
		cache.append_file_chunk(
			&file2,
			&[1, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15],
			Some(48),
			false,
		)?;
		cache.append_file_chunk(
			&file2,
			&[2, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15],
			Some(48),
			false,
		)?;
		cache.append_file_chunk(
			&file2,
			&[3, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15],
			Some(48),
			true,
		)?;

		let (mut iter, len) = cache.iter(&file2)?;
		assert_eq!(len, 48);
		assert_eq!(
			iter.next().unwrap(),
			&[1, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15]
		);
		assert_eq!(
			iter.next().unwrap(),
			&[2, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15]
		);
		assert_eq!(
			iter.next().unwrap(),
			&[3, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15]
		);
		assert!(iter.next().is_none());

		let (mut iter, _len) = cache.iter(&file1)?;
		assert!(iter.next().is_none());

		cache.append_file_chunk(
			&file3,
			&[4, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15],
			Some(16),
			true,
		)?;

		let (mut iter, _len) = cache.iter(&file1)?;
		assert!(iter.next().is_none());

		let (mut iter, _len) = cache.iter(&file2)?;
		assert!(iter.next().is_none());

		let (mut iter, len) = cache.iter(&file3)?;
		assert_eq!(len, 16);
		assert_eq!(
			iter.next().unwrap(),
			&[4, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15]
		);
		assert!(iter.next().is_none());

		Ok(())
	}

	#[test]
	fn test_cache_remove_file_hash() -> Result<(), Error> {
		let mut cache = HttpCache::new(3, 10, 16, 0.99)?;
		let file1 = "/abc.html".to_string();
		let file2 = "/def.html".to_string();
		let file3 = "/ghi.html".to_string();

		cache.append_file_chunk(&file1, &[200], Some(1), true)?;

		cache.append_file_chunk(&file2, &[201], Some(1), true)?;

		let (mut iter, len) = cache.iter(&file1)?;
		assert_eq!(len, 1);
		assert_eq!(iter.next().unwrap()[0], 200);

		let (mut iter, len) = cache.iter(&file2)?;
		assert_eq!(len, 1);
		assert_eq!(iter.next().unwrap()[0], 201);

		cache.append_file_chunk(&file3, &[202], Some(1), true)?;

		let (mut iter, _len) = cache.iter(&file1)?;
		assert!(iter.next().is_none());

		let (mut iter, len) = cache.iter(&file2)?;
		assert_eq!(len, 1);
		assert_eq!(iter.next().unwrap()[0], 201);

		let (mut iter, len) = cache.iter(&file3)?;
		assert_eq!(len, 1);
		assert_eq!(iter.next().unwrap()[0], 202);

		Ok(())
	}

	#[test]
	fn test_partial() -> Result<(), Error> {
		let mut cache = HttpCache::new(3, 3, 16, 0.99)?;

		let file1 = "/abc.html".to_string();

		cache.append_file_chunk(&file1, &[10], Some(1), true)?;

		let (mut iter, len) = cache.iter(&file1)?;
		let next = iter.next().unwrap();
		assert_eq!(next[0], 10);
		assert_eq!(len, 1);

		Ok(())
	}

	#[test]
	fn test_incomplete() -> Result<(), Error> {
		let mut cache = HttpCache::new(10, 10, 16, 0.99)?;
		let file1 = "/abc.html".to_string();
		cache.append_file_chunk(
			&file1,
			&[0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15],
			Some(32),
			false,
		)?;

		let (mut iter, _len) = cache.iter(&file1)?;
		assert!(iter.next().is_none());

		cache.append_file_chunk(
			&file1,
			&[1, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15],
			None,
			true,
		)?;

		let (mut iter, len) = cache.iter(&file1)?;
		assert_eq!(len, 32);
		assert_eq!(
			iter.next().unwrap(),
			&[0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15]
		);
		assert_eq!(
			iter.next().unwrap(),
			&[1, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15]
		);
		assert!(iter.next().is_none());

		Ok(())
	}
}
