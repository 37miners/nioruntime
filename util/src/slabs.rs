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

use nioruntime_err::{Error, ErrorKind};
use nioruntime_log::*;
use std::convert::TryInto;

debug!();

#[derive(Debug)]
pub struct Chunk<'a> {
	pub data: &'a mut [u8],
	pub id: u64,
}

pub struct SlabAllocator {
	data: Vec<u8>,
	chunk_size: u64,
	first_free: u64,
}

// Format
// [free_list_next 8 bytes][chunk bytes]...
// u64::MAX indicates end of list
impl SlabAllocator {
	pub fn new(chunks: u64, chunk_size: u64) -> Self {
		let mut data = vec![];
		data.resize((chunks * (chunk_size + 8)).try_into().unwrap(), 0u8);
		Self::build_free(&mut data, chunks, chunk_size);
		Self {
			data,
			chunk_size,
			first_free: 0,
		}
	}

	pub fn allocate_chunk(&mut self) -> Result<Chunk, Error> {
		if self.first_free == u64::MAX {
			Err(ErrorKind::NoMoreChunks.into())
		} else {
			let id = self.first_free;
			let offset = ((8 + self.chunk_size) * id).try_into()?;
			self.first_free =
				u64::from_be_bytes(self.data[offset..offset + 8].try_into()?).try_into()?;

			let offset = (offset + 8).try_into()?;
			let data = &mut self.data[offset..offset + self.chunk_size as usize];
			Ok(Chunk { data, id })
		}
	}

	pub fn free_chunk(&mut self, chunk: &Chunk) -> Result<(), Error> {
		let offset = ((8 + self.chunk_size) * chunk.id).try_into()?;
		self.data[offset..offset + 8].clone_from_slice(&self.first_free.to_be_bytes());
		self.first_free = chunk.id;
		Ok(())
	}

	fn build_free(data: &mut Vec<u8>, chunks: u64, chunk_size: u64) {
		for i in 0..chunks {
			let next_bytes = if i < chunks - 1 {
				(i + 1).to_be_bytes()
			} else {
				u64::MAX.to_be_bytes()
			};

			let prev_bytes = if i > 0 {
				(i - 1).to_be_bytes()
			} else {
				u64::MAX.to_be_bytes()
			};

			let offset_next: usize = (i * (8 + chunk_size)).try_into().unwrap();
			let offset_prev: usize = (offset_next + 8).try_into().unwrap();
			data[offset_next..offset_next + 8].clone_from_slice(&next_bytes);
			data[offset_prev..offset_prev + 8].clone_from_slice(&prev_bytes);
		}
	}
}

#[cfg(test)]
mod test {
	use crate::slabs::{Chunk, SlabAllocator};
	use nioruntime_err::Error;
	use nioruntime_log::*;

	debug!();

	#[test]
	fn test_slab_allocator() -> Result<(), Error> {
		let mut x = SlabAllocator::new(3, 10);
		for i in 0..3 {
			let chunk = x.allocate_chunk()?;
			chunk.data[0] = i + 10;
		}

		let chunk = x.allocate_chunk();
		assert!(chunk.is_err());

		x.free_chunk(&Chunk {
			id: 0,
			data: &mut [],
		})?;
		x.free_chunk(&Chunk {
			id: 1,
			data: &mut [],
		})?;

		let chunk = x.allocate_chunk()?;
		assert_eq!(chunk.id, 1);
		assert_eq!(chunk.data[0], 11);

		let chunk = x.allocate_chunk()?;
		assert_eq!(chunk.id, 0);
		assert_eq!(chunk.data[0], 10);

		let chunk = x.allocate_chunk();
		assert!(chunk.is_err());

		Ok(())
	}
}
