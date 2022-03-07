// Copyright 2021 The Grin Developers
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

//! Serialization and deserialization layer specialized for binary encoding.
//! Ensures consistency and safety. Basically a minimal subset or
//! rustc_serialize.
//!
//! To use it simply implement `Serializable` and then use the
//! `serialize` or `deserialize` functions on them as appropriate.

use nioruntime_deps::byteorder::{BigEndian, ByteOrder, ReadBytesExt};
use nioruntime_deps::bytes::Buf;
use nioruntime_err::{Error, ErrorKind};
use std::convert::TryInto;
use std::fmt::Debug;
use std::io::{self, Read, Write};
use std::marker;

/// Implementations defined how different numbers and binary structures are
/// written to an underlying stream or container (depending on implementation).
pub trait Writer {
	/// Writes a u8 as bytes
	fn write_u8(&mut self, n: u8) -> Result<(), Error> {
		self.write_fixed_bytes(&[n])
	}

	/// Writes a i8 as bytes
	fn write_i8(&mut self, n: i8) -> Result<(), Error> {
		self.write_fixed_bytes(&[n as u8])
	}

	/// Writes a u16 as bytes
	fn write_u16(&mut self, n: u16) -> Result<(), Error> {
		let mut bytes = [0; 2];
		BigEndian::write_u16(&mut bytes, n);
		self.write_fixed_bytes(&bytes)
	}

	/// Writes a i16 as bytes
	fn write_i16(&mut self, n: i16) -> Result<(), Error> {
		let mut bytes = [0; 2];
		BigEndian::write_i16(&mut bytes, n);
		self.write_fixed_bytes(&bytes)
	}

	/// Writes a u32 as bytes
	fn write_u32(&mut self, n: u32) -> Result<(), Error> {
		let mut bytes = [0; 4];
		BigEndian::write_u32(&mut bytes, n);
		self.write_fixed_bytes(&bytes)
	}

	/// Writes a u32 as bytes
	fn write_i32(&mut self, n: i32) -> Result<(), Error> {
		let mut bytes = [0; 4];
		BigEndian::write_i32(&mut bytes, n);
		self.write_fixed_bytes(&bytes)
	}

	/// Writes a u64 as bytes
	fn write_u64(&mut self, n: u64) -> Result<(), Error> {
		let mut bytes = [0; 8];
		BigEndian::write_u64(&mut bytes, n);
		self.write_fixed_bytes(&bytes)
	}

	/// Writes a i128 as bytes
	fn write_i128(&mut self, n: i128) -> Result<(), Error> {
		let mut bytes = [0; 16];
		BigEndian::write_i128(&mut bytes, n);
		self.write_fixed_bytes(&bytes)
	}

	/// Writes a u128 as bytes
	fn write_u128(&mut self, n: u128) -> Result<(), Error> {
		let mut bytes = [0; 16];
		BigEndian::write_u128(&mut bytes, n);
		self.write_fixed_bytes(&bytes)
	}

	/// Writes a i64 as bytes
	fn write_i64(&mut self, n: i64) -> Result<(), Error> {
		let mut bytes = [0; 8];
		BigEndian::write_i64(&mut bytes, n);
		self.write_fixed_bytes(&bytes)
	}

	/// Writes a variable number of bytes. The length is encoded as a 64-bit
	/// prefix.
	fn write_bytes<T: AsRef<[u8]>>(&mut self, bytes: T) -> Result<(), Error> {
		self.write_u64(bytes.as_ref().len() as u64)?;
		self.write_fixed_bytes(bytes)
	}

	/// Writes a fixed number of bytes. The reader is expected to know the actual length on read.
	fn write_fixed_bytes<T: AsRef<[u8]>>(&mut self, bytes: T) -> Result<(), Error>;

	/// Writes a fixed length of "empty" bytes.
	fn write_empty_bytes(&mut self, length: usize) -> Result<(), Error> {
		self.write_fixed_bytes(vec![0u8; length])
	}
}

/// Implementations defined how different numbers and binary structures are
/// read from an underlying stream or container (depending on implementation).
pub trait Reader {
	/// Read a u8 from the underlying Read
	fn read_u8(&mut self) -> Result<u8, Error>;
	/// Read a i8 from the underlying Read
	fn read_i8(&mut self) -> Result<i8, Error>;
	/// Read a i16 from the underlying Read
	fn read_i16(&mut self) -> Result<i16, Error>;
	/// Read a u16 from the underlying Read
	fn read_u16(&mut self) -> Result<u16, Error>;
	/// Read a u32 from the underlying Read
	fn read_u32(&mut self) -> Result<u32, Error>;
	/// Read a u64 from the underlying Read
	fn read_u64(&mut self) -> Result<u64, Error>;
	/// Read a u128 from the underlying Read
	fn read_u128(&mut self) -> Result<u128, Error>;
	/// Read a i128 from the underlying Read
	fn read_i128(&mut self) -> Result<i128, Error>;
	/// Read a i32 from the underlying Read
	fn read_i32(&mut self) -> Result<i32, Error>;
	/// Read a i64 from the underlying Read
	fn read_i64(&mut self) -> Result<i64, Error>;
	/// Read a u64 len prefix followed by that number of exact bytes.
	fn read_bytes_len_prefix(&mut self) -> Result<Vec<u8>, Error>;
	/// Read a fixed number of bytes from the underlying reader.
	fn read_fixed_bytes(&mut self, length: usize) -> Result<Vec<u8>, Error>;
	/// Consumes a byte from the reader, producing an error if it doesn't have
	/// the expected value
	fn expect_u8(&mut self, val: u8) -> Result<u8, Error>;

	/// Read a fixed number of "empty" bytes from the underlying reader.
	/// It is an error if any non-empty bytes encountered.
	fn read_empty_bytes(&mut self, length: usize) -> Result<(), Error> {
		for _ in 0..length {
			if self.read_u8()? != 0u8 {
				return Err(ErrorKind::CorruptedData("expected 0u8".to_string()).into());
			}
		}
		Ok(())
	}
}

/// Reader that exposes an Iterator interface.
pub struct IteratingReader<'a, T, R: Reader> {
	count: u64,
	curr: u64,
	reader: &'a mut R,
	_marker: marker::PhantomData<T>,
}

impl<'a, T, R: Reader> IteratingReader<'a, T, R> {
	/// Constructor to create a new iterating reader for the provided underlying reader.
	/// Takes a count so we know how many to iterate over.
	pub fn new(reader: &'a mut R, count: u64) -> Self {
		let curr = 0;
		IteratingReader {
			count,
			curr,
			reader,
			_marker: marker::PhantomData,
		}
	}
}

impl<'a, T, R> Iterator for IteratingReader<'a, T, R>
where
	T: Serializable,
	R: Reader,
{
	type Item = T;

	fn next(&mut self) -> Option<T> {
		if self.curr >= self.count {
			return None;
		}
		self.curr += 1;
		T::read(self.reader).ok()
	}
}

pub trait Serializable
where
	Self: Sized + Debug,
{
	fn read<R: Reader>(reader: &mut R) -> Result<Self, Error>;
	fn write<W: Writer>(&self, writer: &mut W) -> Result<(), Error>;
}

/// Deserializes a Serializable from any std::io::Read implementation.
pub fn deserialize<T: Serializable, R: Read>(source: &mut R) -> Result<T, Error> {
	let mut reader = BinReader::new(source);
	T::read(&mut reader)
}

/// Serializes a Serializable into any std::io::Write implementation.
pub fn serialize<W: Serializable>(sink: &mut dyn Write, thing: &W) -> Result<(), Error> {
	let mut writer = BinWriter::new(sink);
	thing.write(&mut writer)
}

/// Utility to read from a binary source
pub struct BinReader<'a, R: Read> {
	source: &'a mut R,
}

impl<'a, R: Read> BinReader<'a, R> {
	/// Constructor for a new BinReader for the provided source
	pub fn new(source: &'a mut R) -> Self {
		BinReader { source }
	}
}

fn map_io_err(err: io::Error) -> Error {
	ErrorKind::IOError(format!("{}", err)).into()
}

/// Utility wrapper for an underlying byte Reader. Defines higher level methods
/// to read numbers, byte vectors, hashes, etc.
impl<'a, R: Read> Reader for BinReader<'a, R> {
	fn read_u8(&mut self) -> Result<u8, Error> {
		self.source.read_u8().map_err(map_io_err)
	}
	fn read_i8(&mut self) -> Result<i8, Error> {
		self.source.read_i8().map_err(map_io_err)
	}
	fn read_i16(&mut self) -> Result<i16, Error> {
		self.source.read_i16::<BigEndian>().map_err(map_io_err)
	}
	fn read_u16(&mut self) -> Result<u16, Error> {
		self.source.read_u16::<BigEndian>().map_err(map_io_err)
	}
	fn read_u32(&mut self) -> Result<u32, Error> {
		self.source.read_u32::<BigEndian>().map_err(map_io_err)
	}
	fn read_i32(&mut self) -> Result<i32, Error> {
		self.source.read_i32::<BigEndian>().map_err(map_io_err)
	}
	fn read_u64(&mut self) -> Result<u64, Error> {
		self.source.read_u64::<BigEndian>().map_err(map_io_err)
	}
	fn read_i128(&mut self) -> Result<i128, Error> {
		self.source.read_i128::<BigEndian>().map_err(map_io_err)
	}

	fn read_u128(&mut self) -> Result<u128, Error> {
		self.source.read_u128::<BigEndian>().map_err(map_io_err)
	}
	fn read_i64(&mut self) -> Result<i64, Error> {
		self.source.read_i64::<BigEndian>().map_err(map_io_err)
	}
	/// Read a variable size vector from the underlying Read. Expects a usize
	fn read_bytes_len_prefix(&mut self) -> Result<Vec<u8>, Error> {
		let len = self.read_u64()?;
		self.read_fixed_bytes(len as usize)
	}

	/// Read a fixed number of bytes.
	fn read_fixed_bytes(&mut self, len: usize) -> Result<Vec<u8>, Error> {
		// not reading more than 100k bytes in a single read
		if len > 100_000 {
			return Err(ErrorKind::TooLargeReadErr("too large read".to_string()).into());
		}
		let mut buf = vec![0; len];
		self.source.read_exact(&mut buf).map_err(map_io_err)?;
		Ok(buf)
	}

	fn expect_u8(&mut self, val: u8) -> Result<u8, Error> {
		let b = self.read_u8()?;
		if b == val {
			Ok(b)
		} else {
			Err(ErrorKind::UnexpectedData(format!(
				"expected: {:?}, received: {:?}",
				vec![val],
				vec![b]
			))
			.into())
		}
	}
}

/// A reader that reads straight off a stream.
/// Tracks total bytes read so we can verify we read the right number afterwards.
pub struct StreamingReader<'a> {
	total_bytes_read: u64,
	stream: &'a mut dyn Read,
}

impl<'a> StreamingReader<'a> {
	/// Create a new streaming reader with the provided underlying stream.
	/// Also takes a duration to be used for each individual read_exact call.
	pub fn new(stream: &'a mut dyn Read) -> StreamingReader<'a> {
		StreamingReader {
			total_bytes_read: 0,
			stream,
		}
	}

	/// Returns the total bytes read via this streaming reader.
	pub fn total_bytes_read(&self) -> u64 {
		self.total_bytes_read
	}
}

/// Note: We use read_fixed_bytes() here to ensure our "async" I/O behaves as expected.
impl<'a> Reader for StreamingReader<'a> {
	fn read_u8(&mut self) -> Result<u8, Error> {
		let buf = self.read_fixed_bytes(1)?;
		Ok(buf[0])
	}
	fn read_i8(&mut self) -> Result<i8, Error> {
		let buf = self.read_fixed_bytes(1)?;
		Ok(buf[0] as i8)
	}
	fn read_i16(&mut self) -> Result<i16, Error> {
		let buf = self.read_fixed_bytes(2)?;
		Ok(BigEndian::read_i16(&buf[..]))
	}
	fn read_u16(&mut self) -> Result<u16, Error> {
		let buf = self.read_fixed_bytes(2)?;
		Ok(BigEndian::read_u16(&buf[..]))
	}
	fn read_u32(&mut self) -> Result<u32, Error> {
		let buf = self.read_fixed_bytes(4)?;
		Ok(BigEndian::read_u32(&buf[..]))
	}
	fn read_i32(&mut self) -> Result<i32, Error> {
		let buf = self.read_fixed_bytes(4)?;
		Ok(BigEndian::read_i32(&buf[..]))
	}
	fn read_u64(&mut self) -> Result<u64, Error> {
		let buf = self.read_fixed_bytes(8)?;
		Ok(BigEndian::read_u64(&buf[..]))
	}
	fn read_u128(&mut self) -> Result<u128, Error> {
		let buf = self.read_fixed_bytes(8)?;
		Ok(BigEndian::read_u128(&buf[..]))
	}
	fn read_i128(&mut self) -> Result<i128, Error> {
		let buf = self.read_fixed_bytes(8)?;
		Ok(BigEndian::read_i128(&buf[..]))
	}
	fn read_i64(&mut self) -> Result<i64, Error> {
		let buf = self.read_fixed_bytes(8)?;
		Ok(BigEndian::read_i64(&buf[..]))
	}

	/// Read a variable size vector from the underlying stream. Expects a usize
	fn read_bytes_len_prefix(&mut self) -> Result<Vec<u8>, Error> {
		let len = self.read_u64()?;
		self.total_bytes_read += 8;
		self.read_fixed_bytes(len as usize)
	}

	/// Read a fixed number of bytes.
	fn read_fixed_bytes(&mut self, len: usize) -> Result<Vec<u8>, Error> {
		if len > 100_000 {
			return Err(ErrorKind::TooLargeReadErr("too large read".to_string()).into());
		}
		let mut buf = vec![0u8; len];
		self.stream.read_exact(&mut buf)?;
		self.total_bytes_read += len as u64;
		Ok(buf)
	}

	fn expect_u8(&mut self, val: u8) -> Result<u8, Error> {
		let b = self.read_u8()?;
		if b == val {
			Ok(b)
		} else {
			Err(ErrorKind::UnexpectedData(format!(
				"expected: {:?}, received: {:?}",
				vec![val],
				vec![b],
			))
			.into())
		}
	}
}

/// Protocol wrapper around a `Buf` impl
pub struct BufReader<'a, B: Buf> {
	inner: &'a mut B,
	bytes_read: usize,
}

impl<'a, B: Buf> BufReader<'a, B> {
	/// Construct a new BufReader
	pub fn new(buf: &'a mut B) -> Self {
		Self {
			inner: buf,
			bytes_read: 0,
		}
	}

	/// Check whether the buffer has enough bytes remaining to perform a read
	fn has_remaining(&mut self, len: usize) -> Result<(), Error> {
		if self.inner.remaining() >= len {
			self.bytes_read += len;
			Ok(())
		} else {
			Err(ErrorKind::UnexpectedEof("unexpectedEOF".to_string()).into())
		}
	}

	/// The total bytes read
	pub fn bytes_read(&self) -> u64 {
		self.bytes_read as u64
	}

	/// Convenience function to read from the buffer and deserialize
	pub fn body<T: Serializable>(&mut self) -> Result<T, Error> {
		T::read(self)
	}
}

impl<'a, B: Buf> Reader for BufReader<'a, B> {
	fn read_u8(&mut self) -> Result<u8, Error> {
		self.has_remaining(1)?;
		Ok(self.inner.get_u8())
	}

	fn read_i8(&mut self) -> Result<i8, Error> {
		self.has_remaining(1)?;
		Ok(self.inner.get_i8())
	}

	fn read_i16(&mut self) -> Result<i16, Error> {
		self.has_remaining(2)?;
		Ok(self.inner.get_i16())
	}

	fn read_u16(&mut self) -> Result<u16, Error> {
		self.has_remaining(2)?;
		Ok(self.inner.get_u16())
	}

	fn read_u32(&mut self) -> Result<u32, Error> {
		self.has_remaining(4)?;
		Ok(self.inner.get_u32())
	}

	fn read_u64(&mut self) -> Result<u64, Error> {
		self.has_remaining(8)?;
		Ok(self.inner.get_u64())
	}

	fn read_u128(&mut self) -> Result<u128, Error> {
		self.has_remaining(16)?;
		Ok(self.inner.get_u128())
	}

	fn read_i128(&mut self) -> Result<i128, Error> {
		self.has_remaining(16)?;
		Ok(self.inner.get_i128())
	}

	fn read_i32(&mut self) -> Result<i32, Error> {
		self.has_remaining(4)?;
		Ok(self.inner.get_i32())
	}

	fn read_i64(&mut self) -> Result<i64, Error> {
		self.has_remaining(8)?;
		Ok(self.inner.get_i64())
	}

	fn read_bytes_len_prefix(&mut self) -> Result<Vec<u8>, Error> {
		let len = self.read_u64()?;
		self.read_fixed_bytes(len as usize)
	}

	fn read_fixed_bytes(&mut self, len: usize) -> Result<Vec<u8>, Error> {
		// not reading more than 100k bytes in a single read
		if len > 100_000 {
			return Err(ErrorKind::TooLargeReadErr("too large read".to_string()).into());
		}
		self.has_remaining(len)?;

		let mut buf = vec![0; len];
		self.inner.copy_to_slice(&mut buf[..]);
		Ok(buf)
	}

	fn expect_u8(&mut self, val: u8) -> Result<u8, Error> {
		let b = self.read_u8()?;
		if b == val {
			Ok(b)
		} else {
			Err(ErrorKind::UnexpectedData(format!(
				"expected: {:?}, received: {:?}",
				vec![val],
				vec![b]
			))
			.into())
		}
	}
}

/// Utility wrapper for an underlying byte Writer. Defines higher level methods
/// to write numbers, byte vectors, hashes, etc.
pub struct BinWriter<'a> {
	sink: &'a mut dyn Write,
}

impl<'a> BinWriter<'a> {
	/// Wraps a standard Write in a new BinWriter
	pub fn new(sink: &'a mut dyn Write) -> BinWriter<'a> {
		BinWriter { sink }
	}
}

impl<'a> Writer for BinWriter<'a> {
	fn write_fixed_bytes<T: AsRef<[u8]>>(&mut self, bytes: T) -> Result<(), Error> {
		let bytes_as_ref = bytes.as_ref();
		// not writing more than 100k bytes in a single read
		if bytes_as_ref.len() > 100_000 {
			return Err(ErrorKind::TooLargeWriteErr("too large write".to_string()).into());
		}
		self.sink.write_all(bytes.as_ref())?;
		Ok(())
	}
}

macro_rules! impl_array {
	($count:expr) => {
		impl<S: Serializable> Serializable for [S; $count] {
			fn write<W: Writer>(&self, writer: &mut W) -> Result<(), Error> {
				for item in self {
					Serializable::write(item, writer)?;
				}
				Ok(())
			}
			fn read<R: Reader>(reader: &mut R) -> Result<[S; $count], Error> {
				let mut ret = vec![];
				for _ in 0..$count {
					ret.push(Serializable::read(reader)?);
				}
				Ok(ret.try_into().unwrap())
			}
		}
	};
}

impl_array!(1);
impl_array!(2);
impl_array!(3);
impl_array!(4);
impl_array!(5);
impl_array!(6);
impl_array!(7);
impl_array!(8);
impl_array!(9);
impl_array!(10);
impl_array!(11);
impl_array!(12);
impl_array!(13);
impl_array!(14);
impl_array!(15);
impl_array!(16);
impl_array!(17);
impl_array!(18);
impl_array!(19);
impl_array!(20);
impl_array!(21);
impl_array!(22);
impl_array!(23);
impl_array!(24);
impl_array!(25);
impl_array!(26);
impl_array!(27);
impl_array!(28);
impl_array!(29);
impl_array!(30);
impl_array!(31);
impl_array!(32);

macro_rules! impl_int {
	($int:ty, $w_fn:ident, $r_fn:ident) => {
		impl Serializable for $int {
			fn write<W: Writer>(&self, writer: &mut W) -> Result<(), Error> {
				writer.$w_fn(*self)
			}
			fn read<R: Reader>(reader: &mut R) -> Result<$int, Error> {
				reader.$r_fn()
			}
		}
	};
}

impl_int!(u8, write_u8, read_u8);
impl_int!(u16, write_u16, read_u16);
impl_int!(u32, write_u32, read_u32);
impl_int!(i32, write_i32, read_i32);
impl_int!(u64, write_u64, read_u64);
impl_int!(i64, write_i64, read_i64);
impl_int!(i8, write_i8, read_i8);
impl_int!(i16, write_i16, read_i16);
impl_int!(u128, write_u128, read_u128);
impl_int!(i128, write_i128, read_i128);

impl Serializable for () {
	fn read<R: Reader>(_reader: &mut R) -> Result<(), Error> {
		Ok(())
	}

	fn write<W: Writer>(&self, _writer: &mut W) -> Result<(), Error> {
		Ok(())
	}
}

impl Serializable for bool {
	fn read<R: Reader>(reader: &mut R) -> Result<bool, Error> {
		Ok(reader.read_u8()? != 0)
	}

	fn write<W: Writer>(&self, writer: &mut W) -> Result<(), Error> {
		writer.write_u8(match self {
			true => 1,
			false => 0,
		})?;
		Ok(())
	}
}

impl<T> Serializable for Option<T>
where
	T: Serializable,
{
	fn read<R: Reader>(reader: &mut R) -> Result<Option<T>, Error> {
		match reader.read_u8()? {
			0 => Ok(None),
			_ => Ok(Some(T::read(reader)?)),
		}
	}
	fn write<W: Writer>(&self, writer: &mut W) -> Result<(), Error> {
		match self {
			Some(o) => {
				writer.write_u8(1)?;
				Serializable::write(o, writer)?;
			}
			None => writer.write_u8(0)?,
		}
		Ok(())
	}
}

impl<T> Serializable for Vec<T>
where
	T: Serializable,
{
	fn write<W: Writer>(&self, writer: &mut W) -> Result<(), Error> {
		writer.write_u64(self.len().try_into()?)?;
		for elmt in self {
			elmt.write(writer)?;
		}
		Ok(())
	}

	fn read<R: Reader>(reader: &mut R) -> Result<Vec<T>, Error> {
		let mut buf = Vec::new();
		let len = reader.read_u64()?;
		for _ in 0..len {
			buf.push(T::read(reader)?);
		}
		Ok(buf)
	}
}

impl<'a, A: Serializable> Serializable for &'a A {
	fn write<W: Writer>(&self, writer: &mut W) -> Result<(), Error> {
		Serializable::write(*self, writer)
	}
	fn read<R: Reader>(_reader: &mut R) -> Result<&'a A, Error> {
		unimplemented!()
	}
}

impl<A: Serializable, B: Serializable> Serializable for (A, B) {
	fn write<W: Writer>(&self, writer: &mut W) -> Result<(), Error> {
		Serializable::write(&self.0, writer)?;
		Serializable::write(&self.1, writer)
	}
	fn read<R: Reader>(reader: &mut R) -> Result<(A, B), Error> {
		Ok((Serializable::read(reader)?, Serializable::read(reader)?))
	}
}

impl<A: Serializable, B: Serializable, C: Serializable> Serializable for (A, B, C) {
	fn write<W: Writer>(&self, writer: &mut W) -> Result<(), Error> {
		Serializable::write(&self.0, writer)?;
		Serializable::write(&self.1, writer)?;
		Serializable::write(&self.2, writer)
	}
	fn read<R: Reader>(reader: &mut R) -> Result<(A, B, C), Error> {
		Ok((
			Serializable::read(reader)?,
			Serializable::read(reader)?,
			Serializable::read(reader)?,
		))
	}
}

impl<A: Serializable, B: Serializable, C: Serializable, D: Serializable> Serializable
	for (A, B, C, D)
{
	fn write<W: Writer>(&self, writer: &mut W) -> Result<(), Error> {
		Serializable::write(&self.0, writer)?;
		Serializable::write(&self.1, writer)?;
		Serializable::write(&self.2, writer)?;
		Serializable::write(&self.3, writer)
	}
	fn read<R: Reader>(reader: &mut R) -> Result<(A, B, C, D), Error> {
		Ok((
			Serializable::read(reader)?,
			Serializable::read(reader)?,
			Serializable::read(reader)?,
			Serializable::read(reader)?,
		))
	}
}

#[cfg(test)]
mod test {
	use crate::ser::{serialize, BinReader, Reader, Serializable, Writer};
	use nioruntime_err::Error;
	use nioruntime_log::*;
	use std::io::Cursor;

	debug!();

	#[derive(PartialEq, Debug)]
	struct TestSer {
		f1: u8,
		f2: u16,
	}

	impl Serializable for TestSer {
		fn write<W: Writer>(&self, writer: &mut W) -> Result<(), Error> {
			writer.write_u8(self.f1)?;
			writer.write_u16(self.f2)?;
			Ok(())
		}

		fn read<R: Reader>(reader: &mut R) -> Result<Self, Error> {
			let f1 = reader.read_u8()?;
			let f2 = reader.read_u16()?;
			Ok(Self { f1, f2 })
		}
	}

	#[test]
	fn test_ser() -> Result<(), Error> {
		info!("testing ser")?;

		let ser_in = TestSer { f1: 1, f2: 2 };
		let mut ser_vec = vec![];
		serialize(&mut ser_vec, &ser_in)?;

		let mut cursor = Cursor::new(ser_vec);
		cursor.set_position(0);
		let mut reader = BinReader::new(&mut cursor);

		let ser_out = TestSer::read(&mut reader)?;
		assert_eq!(ser_out, ser_in);
		Ok(())
	}
}
