//! Implementations of Writeable and Readable for several items that
//! we use in Tor.
//!

use crate::ed25519::Signature;
use crate::reader::Readable;
use crate::reader::Reader;
use crate::reader::Result;
use crate::writer::Writeable;
use crate::writer::WriteableOnce;
use crate::writer::Writer;
use nioruntime_deps::arrayref::array_ref;
use nioruntime_err::ErrorKind;

impl Readable for crate::ed25519::PublicKey {
	fn take_from(b: &mut Reader<'_>) -> Result<Self> {
		let bytes = b.take(32)?;
		Self::from_bytes(array_ref![bytes, 0, 32])
			.map_err(|_| ErrorKind::Tor("Couldn't decode Ed25519 public key".to_string()).into())
	}
}

impl Writeable for crate::ed25519::PublicKey {
	fn write_onto<B: Writer + ?Sized>(&self, b: &mut B) {
		b.write_all(self.as_bytes());
	}
}

impl<const N: usize> Readable for [u8; N] {
	fn take_from(r: &mut Reader<'_>) -> Result<Self> {
		// note: Conceivably this should use MaybeUninit, but let's
		// avoid that unless there is some measurable benefit.
		let mut array = [0_u8; N];
		r.take_into(&mut array[..])?;
		Ok(array)
	}
}

impl Readable for Signature {
	fn take_from(b: &mut Reader<'_>) -> Result<Self> {
		let bytes = b.take(64)?;
		Self::from_bytes(array_ref![bytes, 0, 64])
			.map_err(|_| ErrorKind::Tor("Couldn't decode Ed25519 signature.".to_string()).into())
	}
}

use nioruntime_deps::generic_array::GenericArray;

// ----------------------------------------------------------------------

/// Vec<u8> is the main type that implements Writer.
impl Writer for Vec<u8> {
	fn write_all(&mut self, bytes: &[u8]) {
		self.extend_from_slice(bytes);
	}
	fn write_u8(&mut self, byte: u8) {
		// specialize for performance
		self.push(byte);
	}
	fn write_zeros(&mut self, n: usize) {
		// specialize for performance
		let new_len = self.len() + n;
		self.resize(new_len, 0);
	}
}

impl Writer for nioruntime_deps::bytes::BytesMut {
	fn write_all(&mut self, bytes: &[u8]) {
		self.extend_from_slice(bytes);
	}
}

// ----------------------------------------------------------------------

impl<'a> Writeable for [u8] {
	fn write_onto<B: Writer + ?Sized>(&self, b: &mut B) {
		b.write_all(self);
	}
}

impl Writeable for Vec<u8> {
	fn write_onto<B: Writer + ?Sized>(&self, b: &mut B) {
		b.write_all(&self[..]);
	}
}

// The GenericArray type is defined to work around a limitation in Rust's
// type system.  Ideally we can get rid of GenericArray entirely at some
// point down the line.
//
// For now, we only use GenericArray<u8>, so that's all we'll declare, since
// it permits a faster implementation.
impl<N> Readable for GenericArray<u8, N>
where
	N: nioruntime_deps::generic_array::ArrayLength<u8>,
{
	fn take_from(b: &mut Reader<'_>) -> Result<Self> {
		// safety -- "take" returns the requested bytes or error.
		Ok(Self::clone_from_slice(b.take(N::to_usize())?))
	}
}

impl<N> Writeable for GenericArray<u8, N>
where
	N: nioruntime_deps::generic_array::ArrayLength<u8>,
{
	fn write_onto<B: Writer + ?Sized>(&self, b: &mut B) {
		b.write_all(self.as_slice());
	}
}

/*
// We could add these as well as our implementations over GenericArray<u8>,
// except that we don't actually need them, and Rust doesn't support
// specialization.

impl<T, N> Readable for GenericArray<T, N>
where
	T: Readable + Clone,
	N: generic_array::ArrayLength<T>,
{
	fn take_from(b: &mut Reader<'_>) -> Result<Self> {
		let mut v: Vec<T> = Vec::new();
		for _ in 0..N::to_usize() {
			v.push(T::take_from(b)?);
		}
		// TODO(nickm) I wish I didn't have to clone this.
		Ok(Self::from_slice(v.as_slice()).clone())
	}
}

impl<T, N> Writeable for GenericArray<T, N>
where
	T: Writeable,
	N: generic_array::ArrayLength<T>,
{
	fn write_onto<B: Writer + ?Sized>(&self, b: &mut B) {
		for item in self {
			item.write_onto(b)
		}
	}
}
*/

/// Make Readable and Writeable implementations for a provided
/// unsigned type, delegating to the `read_uNN` and `write_uNN` functions.
macro_rules! impl_u {
	( $t:ty, $wrfn:ident, $rdfn:ident ) => {
		impl Writeable for $t {
			fn write_onto<B: Writer + ?Sized>(&self, b: &mut B) {
				b.$wrfn(*self)
			}
		}
		impl Readable for $t {
			fn take_from(b: &mut Reader<'_>) -> Result<Self> {
				b.$rdfn()
			}
		}
	};
}

impl_u!(u8, write_u8, take_u8);
impl_u!(u16, write_u16, take_u16);
impl_u!(u32, write_u32, take_u32);
impl_u!(u64, write_u64, take_u64);
impl_u!(u128, write_u128, take_u128);

// ----------------------------------------------------------------------

mod rsa_impls {
	use super::*;
	use crate::constants::*;
	use crate::rsa::RsaIdentity;

	impl Writeable for RsaIdentity {
		fn write_onto<B: Writer + ?Sized>(&self, b: &mut B) {
			b.write_all(self.as_bytes());
		}
	}
	impl Readable for RsaIdentity {
		fn take_from(b: &mut Reader<'_>) -> Result<Self> {
			let m = b.take(RSA_ID_LEN)?;
			RsaIdentity::from_bytes(m)
				.ok_or_else(|| ErrorKind::Tor("wrong number of bytes from take".to_string()).into())
		}
	}
}

mod curve25519_impls {
	use super::*;
	use nioruntime_deps::x25519_dalek::{PublicKey, SharedSecret};

	impl Writeable for PublicKey {
		fn write_onto<B: Writer + ?Sized>(&self, b: &mut B) {
			b.write_all(self.as_bytes());
		}
	}
	impl Readable for PublicKey {
		fn take_from(b: &mut Reader<'_>) -> Result<Self> {
			let bytes = b.take(32)?;
			Ok((*array_ref![bytes, 0, 32]).into())
		}
	}
	impl Writeable for SharedSecret {
		fn write_onto<B: Writer + ?Sized>(&self, b: &mut B) {
			b.write_all(self.as_bytes());
		}
	}
}

mod digest_impls {
	use super::*;
	use nioruntime_deps::digest::{CtOutput, OutputSizeUser};
	impl<T: OutputSizeUser> WriteableOnce for CtOutput<T> {
		fn write_into<B: Writer + ?Sized>(self, b: &mut B) {
			let code = self.into_bytes();
			b.write(&code[..]);
		}
	}
	impl<T: OutputSizeUser> Readable for CtOutput<T> {
		fn take_from(b: &mut Reader<'_>) -> Result<Self> {
			let array = GenericArray::take_from(b)?;
			Ok(CtOutput::new(array))
		}
	}
}
