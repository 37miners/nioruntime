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

pub struct SlabMut<'a> {
	pub data: &'a mut [u8],
	pub id: u64,
}

#[derive(Debug)]
pub struct Slab<'a> {
	pub data: &'a [u8],
	pub id: u64,
}

#[derive(Debug)]
pub struct SlabAllocator {
	data: Vec<u8>,
	slab_size: u64,
	first_free: u64,
	free_count: u64,
}

// Format
// [free_list_next 8 bytes][slab bytes]...
// u64::MAX indicates end of list
impl SlabAllocator {
	pub fn new(slabs: u64, slab_size: u64) -> Self {
		let mut data = vec![];
		data.resize((slabs * (slab_size + 8)).try_into().unwrap(), 0u8);
		Self::build_free(&mut data, slabs, slab_size);
		Self {
			data,
			slab_size,
			first_free: 0,
			free_count: slabs,
		}
	}

	pub fn allocate(&mut self) -> Result<SlabMut, Error> {
		if self.first_free == u64::MAX {
			Err(ErrorKind::NoMoreSlabs.into())
		} else {
			let id = self.first_free;
			let offset = ((8 + self.slab_size) * id).try_into()?;
			self.first_free =
				u64::from_be_bytes(self.data[offset..offset + 8].try_into()?).try_into()?;

			let offset = (offset + 8).try_into()?;
			let data = &mut self.data[offset..offset + self.slab_size as usize];
			self.free_count = self.free_count.saturating_sub(1);
			Ok(SlabMut { data, id })
		}
	}

	pub fn free(&mut self, slab: &Slab) -> Result<(), Error> {
		self.free_id(slab.id)
	}

	pub fn free_id(&mut self, slab_id: u64) -> Result<(), Error> {
		let offset = ((8 + self.slab_size) * slab_id).try_into()?;
		self.data[offset..offset + 8].clone_from_slice(&self.first_free.to_be_bytes());
		self.first_free = slab_id;
		self.free_count += 1;
		Ok(())
	}

	pub fn slab_size(&self) -> u64 {
		self.slab_size
	}

	pub fn free_count(&self) -> u64 {
		self.free_count
	}

	pub fn get(&self, id: u64) -> Result<Slab, Error> {
		let offset = (8 + ((8 + self.slab_size) * id)).try_into()?;
		let data = &self.data[offset..offset + self.slab_size as usize];
		Ok(Slab { data, id })
	}

	pub fn get_mut(&mut self, id: u64) -> Result<SlabMut, Error> {
		let offset = (8 + ((8 + self.slab_size) * id)).try_into()?;
		let data = &mut self.data[offset..offset + self.slab_size as usize];
		Ok(SlabMut { data, id })
	}

	fn build_free(data: &mut Vec<u8>, slabs: u64, slab_size: u64) {
		for i in 0..slabs {
			let next_bytes = if i < slabs - 1 {
				(i + 1).to_be_bytes()
			} else {
				u64::MAX.to_be_bytes()
			};

			let offset_next: usize = (i * (8 + slab_size)).try_into().unwrap();
			data[offset_next..offset_next + 8].clone_from_slice(&next_bytes);
		}
	}
}

#[cfg(test)]
mod test {
	use crate::slabs::{Slab, SlabAllocator};
	use nioruntime_err::Error;
	use nioruntime_log::*;

	debug!();

	#[test]
	fn test_slab_allocator() -> Result<(), Error> {
		let mut x = SlabAllocator::new(3, 10);
		for i in 0..3 {
			let slab = x.allocate()?;
			slab.data[0] = i + 10;
		}

		let slab = x.allocate();
		assert!(slab.is_err());

		x.free(&Slab {
			id: 0,
			data: &mut [],
		})?;
		x.free(&Slab {
			id: 1,
			data: &mut [],
		})?;

		let slab = x.allocate()?;
		assert_eq!(slab.id, 1);
		assert_eq!(slab.data[0], 11);

		let slab = x.allocate()?;
		assert_eq!(slab.id, 0);
		assert_eq!(slab.data[0], 10);

		let slab = x.allocate();
		assert!(slab.is_err());

		Ok(())
	}
}
