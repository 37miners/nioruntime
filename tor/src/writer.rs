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

//! Internal: Declare the Writer type for tor-bytes

pub trait Writeable {
	/// Encode this object into the writer `b`.
	fn write_onto<B: Writer + ?Sized>(&self, b: &mut B);
}

/// Trait for an object that can be encoded and consumed by a Writer.
///
/// Implement this trait in order to make an object that can be
/// written more efficiently by absorbing it into the writer.
///
/// Most code won't need to call this directly, but will instead use
/// it implicitly via the Writer::write_and_consume() method.
pub trait WriteableOnce {
	/// Encode this object into the writer `b`, and consume it.
	fn write_into<B: Writer + ?Sized>(self, b: &mut B);
}

impl<W: Writeable> WriteableOnce for W {
	fn write_into<B: Writer + ?Sized>(self, b: &mut B) {
		self.write_onto(b);
	}
}

/// A byte-oriented trait for writing to small arrays.
///
/// Unlike std::io::Write, this trait's methods are not allowed to
/// fail.  It's not for IO.
///
/// Most code will want to use the fact that Vec<u8> implements this trait.
/// To define a new implementation, just define the write_all method.
///
/// # Examples
///
/// You can use a Writer to add bytes explicitly:
/// ```
/// use nioruntime_tor::writer::Writer;
/// let mut w: Vec<u8> = Vec::new(); // Vec<u8> implements Writer.
/// w.write_u32(0x12345);
/// w.write_u8(0x22);
/// w.write_zeros(3);
/// assert_eq!(w, &[0x00, 0x01, 0x23, 0x45, 0x22, 0x00, 0x00, 0x00]);
/// ```
///
/// You can also use a Writer to encode things that implement the
/// Writeable trait:
///
/// ```
/// use nioruntime_tor::writer::{Writer,Writeable};
/// let mut w: Vec<u8> = Vec::new();
/// w.write(&4_u16); // The unsigned types all implement Writeable.
///
/// // We also provide Writeable implementations for several important types.
/// use std::net::Ipv4Addr;
/// let ip = Ipv4Addr::new(127, 0, 0, 1);
///
/// ```
pub trait Writer {
	/// Append a slice to the end of this writer.
	fn write_all(&mut self, b: &[u8]);

	/// Append a single u8 to this writer.
	fn write_u8(&mut self, x: u8) {
		self.write_all(&[x]);
	}
	/// Append a single u16 to this writer, encoded in big-endian order.
	fn write_u16(&mut self, x: u16) {
		self.write_all(&x.to_be_bytes());
	}
	/// Append a single u32 to this writer, encoded in big-endian order.
	fn write_u32(&mut self, x: u32) {
		self.write_all(&x.to_be_bytes());
	}
	/// Append a single u64 to this writer, encoded in big-endian order.
	fn write_u64(&mut self, x: u64) {
		self.write_all(&x.to_be_bytes());
	}
	/// Append a single u128 to this writer, encoded in big-endian order.
	fn write_u128(&mut self, x: u128) {
		self.write_all(&x.to_be_bytes());
	}
	/// Write n bytes to this writer, all with the value zero.
	///
	/// NOTE: This implementation is somewhat inefficient, since it allocates
	/// a vector.  You should probably replace it if you can.
	fn write_zeros(&mut self, n: usize) {
		let v = vec![0_u8; n];
		self.write_all(&v[..]);
	}
	/// Encode a Writeable object onto this writer, using its
	/// write_onto method.
	fn write<E: Writeable + ?Sized>(&mut self, e: &E) {
		e.write_onto(self);
	}
	/// Encode a WriteableOnce object onto this writer, using its
	/// write_into method.
	fn write_and_consume<E: WriteableOnce>(&mut self, e: E) {
		e.write_into(self);
	}
}

#[cfg(test)]
mod tests {
	use super::*;
	use crate::writer::Writer;
	use nioruntime_deps::bytes;
	#[test]
	fn write_ints() {
		let mut b = bytes::BytesMut::new();
		b.write_u8(1);
		b.write_u16(2);
		b.write_u32(3);
		b.write_u64(4);
		b.write_u128(5);

		assert_eq!(
			&b[..],
			&[
				1, 0, 2, 0, 0, 0, 3, 0, 0, 0, 0, 0, 0, 0, 4, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
				0, 0, 5
			]
		);
	}

	#[test]
	fn write_slice() {
		let mut v = Vec::new();
		v.write_u16(0x5468);
		v.write(&b"ey're good dogs, Bront"[..]);

		assert_eq!(&v[..], &b"They're good dogs, Bront"[..]);
	}

	#[test]
	fn writeable() {
		struct Sequence(u8);
		impl Writeable for Sequence {
			fn write_onto<B: Writer + ?Sized>(&self, b: &mut B) {
				for i in 0..self.0 {
					b.write_u8(i);
				}
			}
		}

		let mut v = Vec::new();
		v.write(&Sequence(6));
		assert_eq!(&v[..], &[0, 1, 2, 3, 4, 5]);

		v.write_and_consume(Sequence(3));
		assert_eq!(&v[..], &[0, 1, 2, 3, 4, 5, 0, 1, 2]);
	}
}
