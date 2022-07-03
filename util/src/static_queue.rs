// Copyright (c) 2022, 37 Miners, LLC
// //
// // Licensed under the Apache License, Version 2.0 (the "License");
// // you may not use this file except in compliance with the License.
// // You may obtain a copy of the License at
// //
// //     http://www.apache.org/licenses/LICENSE-2.0
// //
// // Unless required by applicable law or agreed to in writing, software
// // distributed under the License is distributed on an "AS IS" BASIS,
// // WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// // See the License for the specific language governing permissions and
// // limitations under the License.

use nioruntime_err::{Error, ErrorKind};
use nioruntime_log::*;
use std::fmt::Debug;

info!();

#[derive(Clone, Debug)]
pub struct StaticQueue<T>
where
	T: Clone + Copy + Default + Debug,
{
	data: Vec<T>,
	first: usize,
	last: usize,
	size: usize,
}

impl<'a, T> IntoIterator for &'a StaticQueue<T>
where
	T: Debug + Default + Copy,
{
	type Item = T;
	type IntoIter = StaticQueueIterator<'a, T>;

	fn into_iter(self) -> Self::IntoIter {
		StaticQueueIterator {
			static_queue: &self,
			index: 0,
		}
	}
}

pub struct StaticQueueIterator<'a, T>
where
	T: Debug + Default + Copy,
{
	static_queue: &'a StaticQueue<T>,
	index: usize,
}

impl<'a, T> Iterator for StaticQueueIterator<'a, T>
where
	T: Debug + Default + Copy,
{
	type Item = T;
	fn next(&mut self) -> Option<Self::Item> {
		match self.static_queue.peek(self.index) {
			Ok(item) => {
				self.index += 1;
				item
			}
			Err(_) => None,
		}
	}
}

impl<T> StaticQueue<T>
where
	T: Clone + Copy + Default + Debug,
{
	pub fn new(capacity: usize) -> Self {
		let mut data = vec![];
		data.resize(capacity, T::default());
		Self {
			data,
			first: 0,
			last: 0,
			size: 0,
		}
	}

	pub fn enqueue(&mut self, item: T) -> Result<(), Error> {
		if self.size == self.capacity() {
			return Err(ErrorKind::CapacityExceeded(format!(
				"Queue capacity exceeded: {}",
				self.capacity()
			))
			.into());
		}
		self.size += 1;
		self.data[self.first] = item;
		debug!("enqueue insert item {:?} into slot {}", item, self.first)?;
		self.first += 1;
		if self.first >= self.capacity() {
			self.first = 0;
		}
		Ok(())
	}

	pub fn dequeue(&mut self) -> Result<Option<T>, Error> {
		if self.size == 0 {
			return Ok(None);
		}
		self.size -= 1;
		let ret = self.data[self.last];
		self.last += 1;
		if self.last >= self.capacity() {
			self.last = 0;
		}
		Ok(Some(ret))
	}

	pub fn capacity(&self) -> usize {
		self.data.len()
	}

	pub fn size(&self) -> usize {
		self.size
	}

	pub fn peek(&self, index: usize) -> Result<Option<T>, Error> {
		if index >= self.size {
			return Err(ErrorKind::ArrayIndexOutofBounds(format!(
				"peek requested index {}. Size = {}.",
				index, self.size
			))
			.into());
		}
		let mut offset = self.last + index;
		if offset >= self.capacity() {
			offset -= self.capacity();
		}
		debug!("ret offset={}, last={}", offset, self.last)?;
		Ok(Some(self.data[offset]))
	}

	pub fn clear(&mut self) -> Result<(), Error> {
		self.last = 0;
		self.first = 0;
		self.size = 0;
		Ok(())
	}
}

#[cfg(test)]
mod test {
	use crate::StaticQueue;
	use nioruntime_err::Error;
	use nioruntime_log::*;

	debug!();

	#[derive(Copy, Clone, Default, PartialEq, Eq, Debug)]
	struct MyItem {
		f1: u8,
		f2: u64,
	}

	#[test]
	fn test_queue_iterator() -> Result<(), Error> {
		let my_item1 = MyItem { f1: 1, f2: 1 };
		let my_item2 = MyItem { f1: 2, f2: 2 };
		let my_item3 = MyItem { f1: 3, f2: 3 };
		let my_item4 = MyItem { f1: 4, f2: 4 };
		let my_item5 = MyItem { f1: 5, f2: 5 };

		let mut queue = StaticQueue::new(10);
		assert_eq!(queue.capacity(), 10);
		queue.enqueue(my_item1)?;
		queue.enqueue(my_item2)?;
		queue.enqueue(my_item3)?;
		queue.enqueue(my_item4)?;
		queue.enqueue(my_item5)?;

		let mut v = vec![];
		for item in &queue {
			v.push(item);
		}

		assert_eq!(v, vec![my_item1, my_item2, my_item3, my_item4, my_item5]);

		Ok(())
	}

	#[test]
	fn test_queue() -> Result<(), Error> {
		let my_item1 = MyItem { f1: 1, f2: 1 };
		let my_item2 = MyItem { f1: 2, f2: 2 };
		let my_item3 = MyItem { f1: 3, f2: 3 };
		let my_item4 = MyItem { f1: 4, f2: 4 };
		let my_item5 = MyItem { f1: 5, f2: 5 };

		let mut queue = StaticQueue::new(10);
		assert_eq!(queue.capacity(), 10);
		queue.enqueue(my_item1)?;
		queue.enqueue(my_item2)?;
		let item_read1 = queue.dequeue()?.unwrap();
		let item_read2 = queue.dequeue()?.unwrap();
		assert!(queue.dequeue()?.is_none());

		assert_eq!(item_read1.f1, 1);
		assert_eq!(item_read1.f2, 1);

		assert_eq!(item_read2.f1, 2);
		assert_eq!(item_read2.f2, 2);

		// test wrapping around
		let mut queue = StaticQueue::new(3);
		queue.enqueue(my_item1)?;
		assert_eq!(queue.peek(0)?, Some(my_item1));
		assert!(queue.peek(1).is_err());
		assert_eq!(queue.size(), 1);
		assert_eq!(queue.capacity(), 3);
		queue.enqueue(my_item2)?;
		assert_eq!(queue.size(), 2);
		assert_eq!(queue.capacity(), 3);
		queue.enqueue(my_item3)?;
		assert_eq!(queue.size(), 3);
		assert_eq!(queue.capacity(), 3);
		assert_eq!(queue.peek(0)?, Some(my_item1));
		assert_eq!(queue.peek(1)?, Some(my_item2));
		assert_eq!(queue.peek(2)?, Some(my_item3));
		assert!(queue.peek(3).is_err());
		assert!(queue.enqueue(my_item4).is_err());
		let item_read1 = queue.dequeue()?.unwrap();
		assert_eq!(queue.size(), 2);
		assert_eq!(queue.capacity(), 3);
		assert_eq!(my_item1, item_read1);
		queue.enqueue(my_item4)?;
		let item_read2 = queue.dequeue()?.unwrap();
		assert_eq!(my_item2, item_read2);
		queue.enqueue(my_item5)?;

		assert_eq!(queue.peek(0)?, Some(my_item3));
		assert_eq!(queue.peek(1)?, Some(my_item4));
		assert_eq!(queue.peek(2)?, Some(my_item5));

		assert!(queue.enqueue(my_item4).is_err());
		let item_read3 = queue.dequeue()?.unwrap();
		let item_read4 = queue.dequeue()?.unwrap();
		let item_read5 = queue.dequeue()?.unwrap();
		assert!(queue.dequeue()?.is_none());
		assert_eq!(item_read3, my_item3);
		assert_eq!(item_read4, my_item4);
		assert_eq!(item_read5, my_item5);

		Ok(())
	}
}
