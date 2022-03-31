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
use std::any::Any;

info!();

pub struct DataHolder {
	index: usize,
	next: usize,
	data: Box<dyn Any>,
}

// note clone implemented for resize. It's ok if data is none for those purposes
// The DataHolders should not be cloned for other uses
impl Clone for DataHolder {
	fn clone(&self) -> Self {
		Self {
			index: self.index,
			next: self.next,
			data: Box::new(false),
		}
	}
}

impl<'a> DataHolder {
	pub fn new() -> Self {
		Self {
			index: 0,
			next: usize::MAX,
			data: Box::new(false),
		}
	}

	pub fn data(&self) -> &Box<dyn Any> {
		&self.data
	}

	pub fn data_mut(&mut self) -> &mut Box<dyn Any> {
		&mut self.data
	}

	pub fn index(&self) -> usize {
		self.index
	}

	pub fn data_as<T: 'static>(&'a self) -> Option<&'a T> {
		self.data().downcast_ref::<T>()
	}

	pub fn data_as_mut<T: 'static>(&'a mut self) -> Option<&'a mut T> {
		self.data_mut().downcast_mut::<T>()
	}
}

pub struct StepAllocatorConfig {
	pub step_size: usize,
}

impl Default for StepAllocatorConfig {
	fn default() -> Self {
		Self { step_size: 100 }
	}
}

pub struct StepAllocator {
	data: Vec<DataHolder>,
	first: usize,
	config: StepAllocatorConfig,
}

impl<'a> StepAllocator {
	pub fn new(config: StepAllocatorConfig) -> Self {
		let data = vec![];
		let first = usize::MAX;
		Self {
			data,
			first,
			config,
		}
	}

	pub fn next(&'a mut self) -> &'a mut DataHolder {
		if self.first == usize::MAX {
			// reallocate
			let data_len = self.data.len();
			self.data
				.resize(data_len + self.config.step_size, DataHolder::new());
			self.first = data_len;
			self.build_free_list(data_len, data_len + self.config.step_size);
		}

		let first = self.first;
		self.first = self.data[first].next;
		&mut self.data[first]
	}

	pub fn get(&'a self, index: usize) -> Result<&'a DataHolder, Error> {
		if index >= self.data.len() {
			Err(
				ErrorKind::ArrayIndexOutofBounds(format!("{} >= {}", index, self.data.len()))
					.into(),
			)
		} else {
			Ok(&self.data[index])
		}
	}

	pub fn get_mut(&'a mut self, index: usize) -> Result<&'a mut DataHolder, Error> {
		if index >= self.data.len() {
			Err(
				ErrorKind::ArrayIndexOutofBounds(format!("{} >= {}", index, self.data.len()))
					.into(),
			)
		} else {
			Ok(&mut self.data[index])
		}
	}

	pub fn free_index(&mut self, index: usize) -> Result<(), Error> {
		self.data[index].next = self.first;
		self.data[index].data = Box::new(false);
		self.first = index;
		Ok(())
	}

	fn build_free_list(&mut self, first: usize, last: usize) {
		for i in first..(last - 1) {
			self.data[i].index = i;
			self.data[i].next = i + 1;
		}
		self.data[last - 1].index = last - 1;
		self.data[last - 1].next = usize::MAX;
	}
}

#[cfg(test)]
mod test {
	use crate::step_allocator::{StepAllocator, StepAllocatorConfig};
	use nioruntime_err::Error;
	use nioruntime_log::*;

	info!();

	#[test]
	fn test_step_allocator1() -> Result<(), Error> {
		let mut step_allocator = StepAllocator::new(StepAllocatorConfig { step_size: 3 });
		for i in 0..5 {
			let next = step_allocator.next();
			let index = next.index();
			assert_eq!(index, i);
			debug!("next.index={}", index)?;

			let data = next.data_mut();
			match data.downcast_ref::<u128>() {
				Some(x) => {
					debug!("cur value for index = {} is {}", index, x)?;
				}
				None => {
					debug!("no value for {}", index)?;
					let value: u128 = 10 + index as u128;
					*data = Box::new(value);
				}
			}
		}
		step_allocator.free_index(3)?;
		let next = step_allocator.next();
		assert_eq!(next.index(), 3);
		debug!("next.index={}", next.index())?;
		let next = step_allocator.next();
		assert_eq!(next.index(), 5);
		debug!("next.index={}", next.index())?;
		let next = step_allocator.next();
		assert_eq!(next.index(), 6);
		debug!("next.index={}", next.index())?;

		let x = step_allocator.get(0)?;
		assert_eq!(x.data().downcast_ref::<u128>().unwrap(), &10);

		let x = step_allocator.get(1)?;
		assert_eq!(x.data().downcast_ref::<u128>().unwrap(), &11);

		let x = step_allocator.get(2)?;
		assert_eq!(x.data().downcast_ref::<u128>().unwrap(), &12);

		let x = step_allocator.get(3)?;
		assert!(x.data().downcast_ref::<u128>().is_none());

		assert_eq!(step_allocator.get(4)?.data_as::<u128>().unwrap(), &14);
		let v = step_allocator.get_mut(4)?.data_as_mut::<u128>().unwrap();
		*v = 15;
		assert_eq!(step_allocator.get(4)?.data_as::<u128>().unwrap(), &15);
		assert!(step_allocator.get_mut(4)?.data_as_mut::<u64>().is_none());

		Ok(())
	}

	#[test]
	fn test_step_allocator2() -> Result<(), Error> {
		let mut step_allocator = StepAllocator::new(StepAllocatorConfig { step_size: 30 });

		for i in 0..100 {
			let next = step_allocator.next();
			let index = next.index();
			assert_eq!(index, i);
			debug!("next.index={}", index)?;

			let data = next.data_mut();
			match data.downcast_ref::<u128>() {
				Some(_) => {}
				None => {
					let value: u128 = 10 + index as u128;
					*data = Box::new(value);
				}
			}
		}

		for i in 20..40 {
			step_allocator.free_index(i)?;
		}

		let mut itt = 1;
		for _ in 20..40 {
			assert_eq!(step_allocator.next().index(), 40 - itt);
			itt += 1;
		}
		assert_eq!(step_allocator.next().index(), 100);

		for i in 0..20 {
			assert_eq!(
				step_allocator.get(i)?.data_as::<u128>().unwrap(),
				&((10 + i) as u128)
			);
		}

		for i in 20..40 {
			assert!(step_allocator.get(i)?.data_as::<u128>().is_none());
		}

		for i in 40..100 {
			assert_eq!(
				step_allocator.get(i)?.data_as::<u128>().unwrap(),
				&((10 + i) as u128)
			);
		}

		Ok(())
	}
}
