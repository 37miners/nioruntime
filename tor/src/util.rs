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

use crate::ed25519;
use crate::rsa::PublicKey;
use crate::util::tor1::InboundClientLayer;
use crate::util::tor1::OutboundClientLayer;
use crate::util::tor1::RelayCellBody;
use nioruntime_deps::generic_array::GenericArray;
use nioruntime_deps::old_rand_core::{
	CryptoRng as OldCryptoRng, Error as OldError, RngCore as OldRngCore,
};
use nioruntime_deps::simple_asn1::{from_der, oid, ASN1Block};
use nioruntime_deps::subtle::Choice;
use nioruntime_deps::subtle::ConditionallySelectable;
use nioruntime_deps::subtle::ConstantTimeEq;
use nioruntime_err::{Error, ErrorKind};
use std::convert::TryInto;

/// Convenience implementation of a TimeBound object.
use std::ops::{Bound, RangeBounds};
use std::time;

use nioruntime_deps::rand_core::{CryptoRng, RngCore};

/// A Timebound object is one that is only valid for a given range of time.
///
/// It's better to wrap things in a TimeBound than to give them an is_valid()
/// valid method, so that you can make sure that nobody uses the object before
/// checking it.
pub trait Timebound<T>: Sized {
	/// An error type that's returned when the object is _not_ timely.
	type Error;

	/// Check whether this object is valid at a given time.
	///
	/// Return Ok if the object is valid, and an error if the object is not.
	fn is_valid_at(&self, t: &time::SystemTime) -> Result<(), Self::Error>;

	/// Return the underlying object without checking whether it's valid.
	fn dangerously_assume_timely(self) -> T;

	/// Unwrap this Timebound object if it is valid at a given time.
	fn check_valid_at(self, t: &time::SystemTime) -> Result<T, Self::Error> {
		self.is_valid_at(t)?;
		Ok(self.dangerously_assume_timely())
	}

	/// Unwrap this Timebound object if it is valid now.
	fn check_valid_now(self) -> Result<T, Self::Error> {
		self.check_valid_at(&time::SystemTime::now())
	}

	/// Unwrap this object if it is valid at the provided time t.
	/// If no time is provided, check the object at the current time.
	fn check_valid_at_opt(self, t: Option<time::SystemTime>) -> Result<T, Self::Error> {
		match t {
			Some(when) => self.check_valid_at(&when),
			None => self.check_valid_now(),
		}
	}
}

/// A TimeBound object that is valid for a specified range of time.
///
/// The range is given as an argument, as in `t1..t2`.
///
///
pub struct TimerangeBound<T> {
	/// The underlying object, which we only want to expose if it is
	/// currently timely.
	obj: T,
	/// If present, when the object first became valid.
	start: Option<time::SystemTime>,
	/// If present, when the object will no longer be valid.
	end: Option<time::SystemTime>,
}

/// Helper: convert a Bound to its underlying value, if any.
///
/// This helper discards information about whether the bound was
/// inclusive or exclusive.  However, since SystemTime has sub-second
/// precision, we really don't care about what happens when the
/// nanoseconds are equal to exactly 0.

fn unwrap_bound(b: Bound<&'_ time::SystemTime>) -> Option<time::SystemTime> {
	match b {
		Bound::Included(x) => Some(*x),
		Bound::Excluded(x) => Some(*x),
		_ => None,
	}
}

impl<T> TimerangeBound<T> {
	/// Construct a new TimerangeBound object from a given object and range.
	///
	/// Note that we do not distinguish between inclusive and
	/// exclusive bounds: `x..y` and `x..=y` are treated the same
	/// here.
	pub fn new<U>(obj: T, range: U) -> Self
	where
		U: RangeBounds<time::SystemTime>,
	{
		let start = unwrap_bound(range.start_bound());
		let end = unwrap_bound(range.end_bound());
		Self { obj, start, end }
	}
}

impl<T> Timebound<T> for TimerangeBound<T> {
	type Error = Error;

	fn is_valid_at(&self, t: &time::SystemTime) -> Result<(), Self::Error> {
		if let Some(start) = self.start {
			if let Ok(d) = start.duration_since(*t) {
				return Err(ErrorKind::Tor(format!("not yet valid: {:?}", d)).into());
			}
		}

		if let Some(end) = self.end {
			if let Ok(d) = t.duration_since(end) {
				return Err(ErrorKind::Tor(format!("not yet valid: {:?}", d)).into());
			}
		}

		Ok(())
	}

	fn dangerously_assume_timely(self) -> T {
		self.obj
	}
}

/// A cryptographically signed object that needs an external public
/// key to validate it.
pub trait ExternallySigned<T>: Sized {
	/// The type of the public key object.
	///
	/// You can use a tuple or a vector here if the object is signed
	/// with multiple keys.
	type Key: ?Sized;

	/// A type that describes what keys are missing for this object.
	type KeyHint;

	/// An error type that's returned when the object is _not_ well-signed.
	type Error;

	/// Check whether k is the right key for this object.  If not, return
	/// an error describing what key would be right.
	///
	/// This function is allowed to return 'true' for a bad key, but never
	/// 'false' for a good key.
	fn key_is_correct(&self, k: &Self::Key) -> Result<(), Self::KeyHint>;

	/// Check the signature on this object
	fn is_well_signed(&self, k: &Self::Key) -> Result<(), Self::Error>;

	/// Unwrap this object without checking any signatures on it.
	fn dangerously_assume_wellsigned(self) -> T;

	/// Unwrap this object if it's correctly signed by a provided key.
	fn check_signature(self, k: &Self::Key) -> Result<T, Self::Error> {
		self.is_well_signed(k)?;
		Ok(self.dangerously_assume_wellsigned())
	}
}

pub trait ValidatableSignature {
	/// Check whether this signature is a correct signature for the document.
	fn is_valid(&self) -> bool;

	/// Return this value as a validatable Ed25519 signature, if it is one.
	fn as_ed25519(&self) -> Option<&ed25519::ValidatableEd25519Signature> {
		None
	}
}

/// Given an X.509 certificate in DER, return its SubjectPublicKey if that key
/// is an RSA key.
///
/// WARNING: Does not validate the X.509 certificate at all!
///
/// TODO(nickm): This is a massive kludge.
pub fn x509_extract_rsa_subject_kludge(der: &[u8]) -> Option<PublicKey> {
	//use ASN1Block::*;
	let blocks = from_der(der).ok()?;
	let block = Asn1(blocks.get(0)?);
	// TBSCertificate
	let tbs_cert: Asn1<'_> = block.into_seq()?.get(0)?.into();
	// SubjectPublicKeyInfo
	let spki: Asn1<'_> = tbs_cert.into_seq()?.get(6)?.into();
	let spki_members = spki.into_seq()?;
	// Is it an RSA key?
	let algid: Asn1<'_> = spki_members.get(0)?.into();
	let oid: Asn1<'_> = algid.into_seq()?.get(0)?.into();
	oid.must_be_rsa_oid()?;

	// try to get the RSA key.
	let key: Asn1<'_> = spki_members.get(1)?.into();
	PublicKey::from_der(key.to_bitstr()?)
}

/// Helper to wrap a simple_asn1::Asn1Block and add more methods to it.
struct Asn1<'a>(&'a ASN1Block);
impl<'a> From<&'a ASN1Block> for Asn1<'a> {
	fn from(b: &'a ASN1Block) -> Asn1<'a> {
		Asn1(b)
	}
}
impl<'a> Asn1<'a> {
	/// If this block is a sequence, return a reference to its members.
	fn into_seq(self) -> Option<&'a [ASN1Block]> {
		match self.0 {
			ASN1Block::Sequence(_, ref s) => Some(s),
			_ => None,
		}
	}
	/// If this block is the OID for the RSA cipher, return Some(()); else
	/// return None.
	///
	/// (It's not a great API, but it lets us use the ? operator
	/// easily above.)
	fn must_be_rsa_oid(self) -> Option<()> {
		// Current and nightly rust disagree about whether these imports
		// are unused.
		let oid = match self.0 {
			ASN1Block::ObjectIdentifier(_, ref oid) => Some(oid),
			_ => None,
		}?;
		if oid == oid!(1, 2, 840, 113549, 1, 1, 1) {
			Some(())
		} else {
			None
		}
	}
	/// If this block is a BitString, return its bitstring value as a
	/// slice of bytes.
	fn to_bitstr(&self) -> Option<&[u8]> {
		match self.0 {
			ASN1Block::BitString(_, _, ref v) => Some(&v[..]),
			_ => None,
		}
	}
}

/// Convert a boolean into a Choice.
///
/// This isn't necessarily a good idea or constant-time.
pub fn bool_to_choice(v: bool) -> Choice {
	Choice::from(u8::from(v))
}

/// Return true if two slices are equal.  Performs its operation in constant
/// time, but returns a bool instead of a subtle::Choice.
pub fn bytes_eq(a: &[u8], b: &[u8]) -> bool {
	let choice = a.ct_eq(b);
	choice.unwrap_u8() == 1
}

/// Try to find an item in a slice without leaking where and whether the
/// item was found.
///
/// If there is any item `x` in the `array` for which `matches(x)`
/// is true, this function will return a reference to one such
/// item.  (We don't specify which.)
///
/// Otherwise, this function returns none.
///
/// We evaluate `matches` on every item of the array, and try not to
/// leak by timing which element (if any) matched.
///
/// Note that this doesn't necessarily do a constant-time comparison,
/// and that it is not constant-time for found/not-found case.
pub fn lookup<T, F>(array: &[T], matches: F) -> Option<&T>
where
	F: Fn(&T) -> Choice,
{
	// ConditionallySelectable isn't implemented for usize, so we need
	// to use u64.
	let mut idx: u64 = 0;
	let mut found: Choice = 0.into();

	for (i, x) in array.iter().enumerate() {
		let equal = matches(x);
		idx.conditional_assign(&(i as u64), equal);
		found.conditional_assign(&equal, equal);
	}

	if found.into() {
		Some(&array[idx as usize])
	} else {
		None
	}
}

/// Extension trait for the _current_ versions of [`RngCore`]; adds a
/// compatibility-wrapper function.
pub trait RngCompatExt: RngCore {
	/// Wrapper type returned by this trait.
	type Wrapper: RngCore + OldRngCore;
	/// Return a version of this Rng that can be used with older versions
	/// of the rand_core and rand libraries, as well as the current
	/// version.
	fn rng_compat(self) -> Self::Wrapper;
}

impl<T: RngCore + Sized> RngCompatExt for T {
	type Wrapper = RngWrapper<T>;
	fn rng_compat(self) -> RngWrapper<Self> {
		self.into()
	}
}

/// A new-style Rng, wrapped for backward compatibility.
///
/// This object implements both the current (0.6.2) version of [`RngCore`],
/// as well as the version from 0.5.1 that the dalek-crypto functions expect.
///
/// To get an RngWrapper, use the [`RngCompatExt`] extension trait:
/// ```
/// use crate::nioruntime_tor::util::RngCompatExt;
///
/// let mut wrapped_rng = nioruntime_deps::rand::thread_rng().rng_compat();
/// ```
pub struct RngWrapper<T>(T);

impl<T: RngCore> From<T> for RngWrapper<T> {
	fn from(rng: T) -> RngWrapper<T> {
		RngWrapper(rng)
	}
}

impl<T: RngCore> OldRngCore for RngWrapper<T> {
	fn next_u32(&mut self) -> u32 {
		self.0.next_u32()
	}
	fn next_u64(&mut self) -> u64 {
		self.0.next_u64()
	}
	fn fill_bytes(&mut self, dest: &mut [u8]) {
		self.0.fill_bytes(dest);
	}
	fn try_fill_bytes(&mut self, dest: &mut [u8]) -> Result<(), OldError> {
		self.0.try_fill_bytes(dest).map_err(|e| err_to_old(&e))
	}
}

impl<T: RngCore> RngCore for RngWrapper<T> {
	fn next_u32(&mut self) -> u32 {
		self.0.next_u32()
	}
	fn next_u64(&mut self) -> u64 {
		self.0.next_u64()
	}
	fn fill_bytes(&mut self, dest: &mut [u8]) {
		self.0.fill_bytes(dest);
	}
	fn try_fill_bytes(&mut self, dest: &mut [u8]) -> Result<(), nioruntime_deps::rand::Error> {
		self.0.try_fill_bytes(dest)
	}
}

impl<T: CryptoRng> OldCryptoRng for RngWrapper<T> {}
impl<T: CryptoRng> CryptoRng for RngWrapper<T> {}

fn err_to_old(e: &nioruntime_deps::rand::Error) -> OldError {
	use std::num::NonZeroU32;
	if let Some(code) = e.code() {
		code.into()
	} else {
		// CUSTOM_START is defined to be a nonzero value in rand_core,
		// so this conversion will succeed, so this unwrap can't panic.
		#[allow(clippy::unwrap_used)]
		let nz: NonZeroU32 = OldError::CUSTOM_START.try_into().unwrap();
		nz.into()
	}
}

// Hops on the circuit.
#[derive(Copy, Clone, Eq, PartialEq, Debug)]
pub struct HopNum(u8);

impl From<HopNum> for u8 {
	fn from(hop: HopNum) -> u8 {
		hop.0
	}
}

impl From<u8> for HopNum {
	fn from(v: u8) -> HopNum {
		HopNum(v)
	}
}

impl From<HopNum> for usize {
	fn from(hop: HopNum) -> usize {
		hop.0 as usize
	}
}

impl std::fmt::Display for HopNum {
	fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::result::Result<(), std::fmt::Error> {
		self.0.fmt(f)
	}
}

/// A client's view of the cryptographic state for an entire
/// constructed circuit, as used for sending cells.
pub struct OutboundClientCrypt {
	/// Vector of layers, one for each hop on the circuit, ordered from the
	/// closest hop to the farthest.
	layers: Vec<Box<dyn OutboundClientLayer + Send>>,
}

impl std::fmt::Debug for OutboundClientCrypt {
	fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
		write!(f, "[outboundclientcrypt,layers={}]", self.layers.len())
	}
}

unsafe impl Sync for OutboundClientCrypt {}

/// A client's view of the cryptographic state for an entire
/// constructed circuit, as used for receiving cells.
pub struct InboundClientCrypt {
	/// Vector of layers, one for each hop on the circuit, ordered from the
	/// closest hop to the farthest.
	layers: Vec<Box<dyn InboundClientLayer + Send>>,
}

impl std::fmt::Debug for InboundClientCrypt {
	fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
		write!(f, "[inboundclientcrypt,layers={}]", self.layers.len())
	}
}

unsafe impl Sync for InboundClientCrypt {}

impl OutboundClientCrypt {
	/// Return a new (empty) OutboundClientCrypt.
	pub fn new() -> Self {
		OutboundClientCrypt { layers: Vec::new() }
	}
	/// Prepare a cell body to sent away from the client.
	///
	/// The cell is prepared for the `hop`th hop, and then encrypted with
	/// the appropriate keys.
	///
	/// On success, returns a reference to tag that should be expected
	/// for an authenticated SENDME sent in response to this cell.
	pub fn encrypt(&mut self, cell: &mut RelayCellBody, hop: HopNum) -> Result<&[u8; 20], Error> {
		let hop: usize = hop.into();
		if hop >= self.layers.len() {
			return Err(ErrorKind::Tor("NoSuchHop".into()).into());
		}

		let mut layers = self.layers.iter_mut().take(hop + 1).rev();
		let first_layer = layers.next().ok_or({
			let error: Error = ErrorKind::Tor("NoSuchHop".into()).into();
			error
		})?;
		let tag = first_layer.originate_for(cell);
		for layer in layers {
			layer.encrypt_outbound(cell);
		}
		Ok(tag.try_into().expect("wrong SENDME digest size"))
	}

	/// Add a new layer to this OutboundClientCrypt
	pub fn add_layer(&mut self, layer: Box<dyn OutboundClientLayer + Send>) {
		assert!(self.layers.len() < std::u8::MAX as usize);
		self.layers.push(layer);
	}

	/// Return the number of layers configured on this OutboundClientCrypt.
	pub fn n_layers(&self) -> usize {
		self.layers.len()
	}
}

impl InboundClientCrypt {
	/// Return a new (empty) InboundClientCrypt.
	pub fn new() -> Self {
		InboundClientCrypt { layers: Vec::new() }
	}
	/// Decrypt an incoming cell that is coming to the client.
	///
	/// On success, return which hop was the originator of the cell.
	// TODO(nickm): Use a real type for the tag, not just `&[u8]`.
	pub fn decrypt(&mut self, cell: &mut RelayCellBody) -> Result<(HopNum, &[u8]), Error> {
		for (hopnum, layer) in self.layers.iter_mut().enumerate() {
			if let Some(tag) = layer.decrypt_inbound(cell) {
				assert!(hopnum <= std::u8::MAX as usize);
				return Ok(((hopnum as u8).into(), tag));
			}
		}
		Err(ErrorKind::Tor("BadCellAuth".into()).into())
	}
	/// Add a new layer to this InboundClientCrypt
	pub fn add_layer(&mut self, layer: Box<dyn InboundClientLayer + Send>) {
		assert!(self.layers.len() < std::u8::MAX as usize);
		self.layers.push(layer);
	}

	/// Return the number of layers configured on this InboundClientCrypt.
	///
	/// TODO: use HopNum
	#[allow(dead_code)]
	pub fn n_layers(&self) -> usize {
		self.layers.len()
	}
}

/// Standard Tor relay crypto, as instantiated for RELAY cells.
pub type Tor1RelayCrypto =
	tor1::CryptStatePair<nioruntime_deps::aes::Aes128Ctr, nioruntime_deps::sha1::Sha1>;

/// Incomplete untested implementation of Tor's current cell crypto.
pub mod tor1 {
	use super::*;
	use nioruntime_deps::cipher::{NewCipher, StreamCipher};
	use nioruntime_deps::digest::Digest;
	use nioruntime_deps::typenum::Unsigned;
	use std::convert::TryInto;

	/// A CryptState is part of a RelayCrypt or a ClientLayer.
	///
	/// It is parameterized on a stream cipher and a digest type: most
	/// circuits will use AES-128-CTR and SHA1, but v3 onion services
	/// use AES-256-CTR and SHA-3.
	pub struct CryptState<SC: StreamCipher, D: Digest + Clone> {
		/// Stream cipher for en/decrypting cell bodies.
		cipher: SC,
		/// Digest for authenticating cells to/from this hop.
		digest: D,
		/// Most recent digest value generated by this crypto.
		last_digest_val: GenericArray<u8, D::OutputSize>,
	}

	/// A pair of CryptStates, one for the forward (away from client)
	/// direction, and one for the reverse (towards client) direction.
	pub struct CryptStatePair<SC: StreamCipher, D: Digest + Clone> {
		/// State for en/decrypting cells sent away from the client.
		fwd: CryptState<SC, D>,
		/// State for en/decrypting cells sent towards the client.
		back: CryptState<SC, D>,
	}

	impl<SC: StreamCipher + NewCipher, D: Digest + Clone> CryptInit for CryptStatePair<SC, D> {
		fn seed_len() -> usize {
			SC::KeySize::to_usize() * 2 + D::OutputSize::to_usize() * 2
		}
		fn initialize(seed: &[u8]) -> Result<Self, Error> {
			if seed.len() != Self::seed_len() {
				return Err(
					ErrorKind::Tor(format!("seed length {} was invalid", seed.len())).into(),
				);
			}
			let keylen = SC::KeySize::to_usize();
			let dlen = D::OutputSize::to_usize();
			let fdinit = &seed[0..dlen];
			let bdinit = &seed[dlen..dlen * 2];
			let fckey = &seed[dlen * 2..dlen * 2 + keylen];
			let bckey = &seed[dlen * 2 + keylen..dlen * 2 + keylen * 2];
			let fwd = CryptState {
				cipher: SC::new(fckey.try_into().expect("Wrong length"), &Default::default()),
				digest: D::new().chain_update(fdinit),
				last_digest_val: GenericArray::default(),
			};
			let back = CryptState {
				cipher: SC::new(bckey.try_into().expect("Wrong length"), &Default::default()),
				digest: D::new().chain_update(bdinit),
				last_digest_val: GenericArray::default(),
			};
			Ok(CryptStatePair { fwd, back })
		}
	}

	impl<SC, D> ClientLayer<CryptState<SC, D>, CryptState<SC, D>> for CryptStatePair<SC, D>
	where
		SC: StreamCipher,
		D: Digest + Clone,
	{
		fn split(self) -> (CryptState<SC, D>, CryptState<SC, D>) {
			(self.fwd, self.back)
		}
	}

	impl<SC: StreamCipher, D: Digest + Clone> RelayCrypt for CryptStatePair<SC, D> {
		fn originate(&mut self, cell: &mut RelayCellBody) {
			let mut d_ignored = GenericArray::default();
			cell.set_digest(&mut self.back.digest, &mut d_ignored);
		}
		fn encrypt_inbound(&mut self, cell: &mut RelayCellBody) {
			self.back.cipher.apply_keystream(cell.as_mut());
		}
		fn decrypt_outbound(&mut self, cell: &mut RelayCellBody) -> bool {
			self.fwd.cipher.apply_keystream(cell.as_mut());
			let mut d_ignored = GenericArray::default();
			cell.recognized(&mut self.fwd.digest, &mut d_ignored)
		}
	}

	impl<SC: StreamCipher, D: Digest + Clone> OutboundClientLayer for CryptState<SC, D> {
		fn originate_for(&mut self, cell: &mut RelayCellBody) -> &[u8] {
			cell.set_digest(&mut self.digest, &mut self.last_digest_val);
			self.encrypt_outbound(cell);
			&self.last_digest_val
		}
		fn encrypt_outbound(&mut self, cell: &mut RelayCellBody) {
			self.cipher.apply_keystream(&mut cell.0[..]);
		}
	}

	impl<SC: StreamCipher, D: Digest + Clone> InboundClientLayer for CryptState<SC, D> {
		fn decrypt_inbound(&mut self, cell: &mut RelayCellBody) -> Option<&[u8]> {
			self.cipher.apply_keystream(&mut cell.0[..]);
			if cell.recognized(&mut self.digest, &mut self.last_digest_val) {
				Some(&self.last_digest_val)
			} else {
				None
			}
		}
	}

	pub const CELL_DATA_LEN: usize = 509;
	pub type RawCellBody = [u8; CELL_DATA_LEN];

	/// Type for the body of a relay cell.
	#[derive(Clone)]
	pub struct RelayCellBody(pub RawCellBody);

	impl From<RawCellBody> for RelayCellBody {
		fn from(body: RawCellBody) -> Self {
			RelayCellBody(body)
		}
	}
	impl From<RelayCellBody> for RawCellBody {
		fn from(cell: RelayCellBody) -> Self {
			cell.0
		}
	}
	impl AsRef<[u8]> for RelayCellBody {
		fn as_ref(&self) -> &[u8] {
			&self.0[..]
		}
	}
	impl AsMut<[u8]> for RelayCellBody {
		fn as_mut(&mut self) -> &mut [u8] {
			&mut self.0[..]
		}
	}

	/// A paired object containing an inbound client layer and an outbound
	/// client layer.
	///
	/// TODO: Maybe we should fold this into CryptInit.
	pub trait ClientLayer<F, B>
	where
		F: OutboundClientLayer,
		B: InboundClientLayer,
	{
		/// Consume this ClientLayer and return a paired forward and reverse
		/// crypto layer.
		fn split(self) -> (F, B);
	}

	pub trait CryptInit: Sized {
		/// Return the number of bytes that this state will require.
		fn seed_len() -> usize;
		/// Construct this state from a seed of the appropriate length.
		fn initialize(seed: &[u8]) -> Result<Self, Error>;
		/// Initialize this object from a key generator.
		fn construct<K: crate::handshake::KeyGenerator>(keygen: K) -> Result<Self, Error> {
			let seed = keygen.expand(Self::seed_len())?;
			Self::initialize(&seed)
		}
	}

	/// A client's view of the crypto state shared with a single relay, as
	/// used for outbound cells.
	pub trait OutboundClientLayer {
		/// Prepare a RelayCellBody to be sent to the relay at this layer, and
		/// encrypt it.
		///
		/// Return the authentication tag.
		fn originate_for(&mut self, cell: &mut RelayCellBody) -> &[u8];
		/// Encrypt a RelayCellBody to be decrypted by this layer.
		fn encrypt_outbound(&mut self, cell: &mut RelayCellBody);
	}
	pub trait RelayCrypt {
		/// Prepare a RelayCellBody to be sent towards the client.
		fn originate(&mut self, cell: &mut RelayCellBody);
		/// Encrypt a RelayCellBody that is moving towards the client.
		fn encrypt_inbound(&mut self, cell: &mut RelayCellBody);
		/// Decrypt a RelayCellBody that is moving towards
		/// the client.  Return true if it is addressed to us.
		fn decrypt_outbound(&mut self, cell: &mut RelayCellBody) -> bool;
	}

	/// A client's view of the crypto state shared with a single relay, as
	/// used for inbound cells.
	pub trait InboundClientLayer {
		/// Decrypt a CellBody that passed through this layer.
		/// Return an authentication tag if this layer is the originator.
		fn decrypt_inbound(&mut self, cell: &mut RelayCellBody) -> Option<&[u8]>;
	}

	impl RelayCellBody {
		/// Prepare a cell body by setting its digest and recognized field.
		fn set_digest<D: Digest + Clone>(
			&mut self,
			d: &mut D,
			used_digest: &mut GenericArray<u8, D::OutputSize>,
		) {
			self.0[1] = 0;
			self.0[2] = 0;
			self.0[5] = 0;
			self.0[6] = 0;
			self.0[7] = 0;
			self.0[8] = 0;

			d.update(&self.0[..]);
			// TODO(nickm) can we avoid this clone?  Probably not.
			*used_digest = d.clone().finalize();
			self.0[5..9].copy_from_slice(&used_digest[0..4]);
		}
		/// Check a cell to see whether its recognized field is set.
		fn recognized<D: Digest + Clone>(
			&self,
			d: &mut D,
			rcvd: &mut GenericArray<u8, D::OutputSize>,
		) -> bool {
			use nioruntime_deps::arrayref::array_ref;

			// Validate 'Recognized' field
			let recognized = u16::from_be_bytes(*array_ref![self.0, 1, 2]);
			if recognized != 0 {
				return false;
			}

			// Now also validate the 'Digest' field:

			let mut dtmp = d.clone();
			// Add bytes up to the 'Digest' field
			dtmp.update(&self.0[..5]);
			// Add zeroes where the 'Digest' field is
			dtmp.update([0_u8; 4]);
			// Add the rest of the bytes
			dtmp.update(&self.0[9..]);
			// Clone the digest before finalize destroys it because we will use
			// it in the future
			let dtmp_clone = dtmp.clone();
			let result = dtmp.finalize();

			if bytes_eq(&self.0[5..9], &result[0..4]) {
				// Copy useful things out of this cell (we keep running digest)
				*d = dtmp_clone;
				*rcvd = result;
				return true;
			}

			false
		}
	}
}
