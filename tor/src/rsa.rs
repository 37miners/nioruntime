// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
// http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

//! Re-exporting RSA implementations.
//!
//! This module can currently handle public keys and signature
//! verification used in the Tor directory protocol and
//! similar places.
//!
//! Currently, that means validating PKCSv1 signatures, and encoding
//! and decoding RSA public keys from DER.
//!
//! # Limitations:
//!
//! Currently missing are support for signing and RSA-OEAP.  In Tor,
//! RSA signing is only needed for relays and authorities, and
//! RSA-OAEP padding is only needed for the (obsolete) TAP protocol.
//!
//! This module should expose RustCrypto trait-based wrappers,
//! but the [`rsa`] crate didn't support them as of initial writing.

use crate::constants::*;
use crate::reader::Reader;
use crate::util::ExternallySigned;
use crate::util::TimerangeBound;
use crate::util::ValidatableSignature;
use nioruntime_deps::arrayref::array_ref;
use nioruntime_deps::base64;
use nioruntime_deps::hex;
use nioruntime_deps::rsa::pkcs1::{FromRsaPrivateKey, FromRsaPublicKey};
use nioruntime_deps::serde;
use nioruntime_deps::sha2::{Digest, Sha256};
use nioruntime_deps::signature;
use nioruntime_deps::subtle::{Choice, ConstantTimeEq};
use nioruntime_err::{Error, ErrorKind};
use std::fmt;
use zeroize::Zeroize;

/// A RSA->Ed25519 cross-certificate
///
/// This kind of certificate is used in the channel handshake to prove
/// that the Ed25519 identity key speaks on behalf of the RSA identity key.
///
/// (There is no converse type for certifying Ed25519 identity keys with
/// RSA identity keys, since the RSA identity keys are too weak to trust.)
#[must_use]
pub struct RsaCrosscert {
	/// The key that is being certified
	subject_key: crate::ed25519::PublicKey,
	/// The expiration time of this certificate, in hours since the
	/// unix epoch.
	exp_hours: u32,
	/// The digest of the signed part of the certificate (for checking)
	digest: [u8; 32],
	/// The (alleged) signature on the certificate.
	signature: Vec<u8>,
}

impl RsaCrosscert {
	/// Return the time at which this certificate becomes expired
	pub fn expiry(&self) -> std::time::SystemTime {
		let d = std::time::Duration::new(u64::from(self.exp_hours) * 3600, 0);
		std::time::SystemTime::UNIX_EPOCH + d
	}

	/// Return true if the subject key in this certificate matches `other`
	pub fn subject_key_matches(&self, other: &crate::ed25519::PublicKey) -> bool {
		self.subject_key == *other
	}

	/// Decode a slice of bytes into an RSA crosscert.
	pub fn decode(bytes: &[u8]) -> Result<UncheckedRsaCrosscert, Error> {
		let mut r = Reader::from_slice(bytes);
		let signed_portion = r.peek(36)?; // TODO(nickm): a bit ugly.
		let subject_key = r.extract()?;
		let exp_hours = r.take_u32()?;
		let siglen = r.take_u8()?;
		let signature = r.take(siglen as usize)?.into();

		let mut d = Sha256::new();
		d.update(&b"Tor TLS RSA/Ed25519 cross-certificate"[..]);
		d.update(signed_portion);
		let digest = d.finalize().into();

		let cc = RsaCrosscert {
			subject_key,
			exp_hours,
			digest,
			signature,
		};

		Ok(UncheckedRsaCrosscert(cc))
	}
}

/// An RsaCrosscert whose signature has not been checked.
pub struct UncheckedRsaCrosscert(RsaCrosscert);

impl ExternallySigned<TimerangeBound<RsaCrosscert>> for UncheckedRsaCrosscert {
	type Key = PublicKey;
	type KeyHint = ();
	type Error = Error;

	fn key_is_correct(&self, _k: &Self::Key) -> Result<(), Self::KeyHint> {
		// there is no way to check except for trying to verify the signature
		Ok(())
	}

	fn is_well_signed(&self, k: &Self::Key) -> Result<(), Self::Error> {
		k.verify(&self.0.digest[..], &self.0.signature[..])
			.map_err(|_| {
				let error: Error =
					ErrorKind::Tor("Invalid signature on RSA->Ed identity crosscert".to_string())
						.into();
				error
			})?;
		Ok(())
	}

	fn dangerously_assume_wellsigned(self) -> TimerangeBound<RsaCrosscert> {
		let expiration = self.0.expiry();
		TimerangeBound::new(self.0, ..expiration)
	}
}

/// An identifier for a Tor relay, based on its legacy RSA identity
/// key.  These are used all over the Tor protocol.
///
/// Note that for modern purposes, you should almost always identify a
/// relay by its [`Ed25519Identity`](crate::pk::ed25519::Ed25519Identity)
/// instead of by this kind of identity key.
#[derive(Clone, Copy, Hash, Zeroize, Ord, PartialOrd)]
#[allow(clippy::derive_hash_xor_eq)]
pub struct RsaIdentity {
	/// SHA1 digest of a DER encoded public key.
	id: [u8; RSA_ID_LEN],
}

impl ConstantTimeEq for RsaIdentity {
	fn ct_eq(&self, other: &Self) -> Choice {
		self.id.ct_eq(&other.id)
	}
}

impl PartialEq<RsaIdentity> for RsaIdentity {
	fn eq(&self, rhs: &RsaIdentity) -> bool {
		self.ct_eq(rhs).unwrap_u8() == 1
	}
}

impl Eq for RsaIdentity {}

impl fmt::Display for RsaIdentity {
	fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
		write!(f, "${}", hex::encode(&self.id[..]))
	}
}
impl fmt::Debug for RsaIdentity {
	fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
		write!(f, "RsaIdentity {{ ${} }}", hex::encode(&self.id[..]))
	}
}

impl serde::Serialize for RsaIdentity {
	fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
	where
		S: serde::Serializer,
	{
		if serializer.is_human_readable() {
			serializer.serialize_str(&hex::encode(&self.id[..]))
		} else {
			serializer.serialize_bytes(&self.id[..])
		}
	}
}

impl<'de> serde::Deserialize<'de> for RsaIdentity {
	fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
	where
		D: serde::Deserializer<'de>,
	{
		if deserializer.is_human_readable() {
			/// Deserialization helper
			struct RsaIdentityVisitor;
			impl<'de> serde::de::Visitor<'de> for RsaIdentityVisitor {
				type Value = RsaIdentity;
				fn expecting(&self, fmt: &mut std::fmt::Formatter<'_>) -> fmt::Result {
					fmt.write_str("hex-encoded RSA identity")
				}
				fn visit_str<E>(self, s: &str) -> Result<Self::Value, E>
				where
					E: serde::de::Error,
				{
					let bytes = hex::decode(s).map_err(E::custom)?;
					RsaIdentity::from_bytes(&bytes)
						.ok_or_else(|| E::custom("wrong length for RSA identity"))
				}
			}

			deserializer.deserialize_str(RsaIdentityVisitor)
		} else {
			/// Deserialization helper
			struct RsaIdentityVisitor;
			impl<'de> serde::de::Visitor<'de> for RsaIdentityVisitor {
				type Value = RsaIdentity;
				fn expecting(&self, fmt: &mut std::fmt::Formatter<'_>) -> fmt::Result {
					fmt.write_str("RSA identity")
				}
				fn visit_bytes<E>(self, bytes: &[u8]) -> Result<Self::Value, E>
				where
					E: serde::de::Error,
				{
					RsaIdentity::from_bytes(&bytes)
						.ok_or_else(|| E::custom("wrong length for RSA identity"))
				}
			}
			deserializer.deserialize_bytes(RsaIdentityVisitor)
		}
	}
}

impl RsaIdentity {
	/// Expose an RsaIdentity as a slice of bytes.
	pub fn as_bytes(&self) -> &[u8] {
		&self.id[..]
	}
	/// Construct an RsaIdentity from a slice of bytes.
	///
	/// Returns None if the input is not of the correct length.
	///
	/// ```
	/// use nioruntime_tor::rsa::RsaIdentity;
	///
	/// let bytes = b"xyzzyxyzzyxyzzyxyzzy";
	/// let id = RsaIdentity::from_bytes(bytes);
	/// assert_eq!(id.unwrap().as_bytes(), bytes);
	///
	/// let truncated = b"xyzzy";
	/// let id = RsaIdentity::from_bytes(truncated);
	/// assert_eq!(id, None);
	/// ```
	pub fn from_bytes(bytes: &[u8]) -> Option<Self> {
		if bytes.len() == RSA_ID_LEN {
			Some(RsaIdentity {
				id: *array_ref![bytes, 0, RSA_ID_LEN],
			})
		} else {
			None
		}
	}

	pub fn from_hex(id: &str) -> Option<Self> {
		match hex::decode(id) {
			Ok(b) => Self::from_bytes(&b),
			Err(_) => None,
		}
	}

	pub fn from_base64(id: &str) -> Option<Self> {
		match base64::decode(id) {
			Ok(b) => Self::from_bytes(&b),
			Err(_) => None,
		}
	}

	/// Return a base64 representation of this rsa id
	pub fn to_stripped_base64(&self) -> String {
		let mut res = &base64::encode(self.id)[..];
		if res.ends_with("=") {
			res = &res[..res.len() - 1];
		}

		res.to_string()
	}
}

impl From<[u8; 20]> for RsaIdentity {
	fn from(id: [u8; 20]) -> RsaIdentity {
		RsaIdentity { id }
	}
}

/// An RSA public key.
///
/// This implementation is a simple wrapper so that we can define new
/// methods and traits on the type.
#[derive(Clone, Debug, PartialEq)]
pub struct PublicKey(nioruntime_deps::rsa::RsaPublicKey);

/// An RSA private key.
///
/// This is not so useful at present, since Arti currently only has
/// client support, and Tor clients never actually need RSA private
/// keys.
pub struct PrivateKey(nioruntime_deps::rsa::RsaPrivateKey);

impl PrivateKey {
	/// Return the public component of this key.
	pub fn to_public_key(&self) -> PublicKey {
		PublicKey(self.0.to_public_key())
	}
	/// Construct a PrivateKey from DER pkcs1 encoding.
	pub fn from_der(der: &[u8]) -> Option<Self> {
		Some(PrivateKey(
			nioruntime_deps::rsa::RsaPrivateKey::from_pkcs1_der(der).ok()?,
		))
	}
	// ....
}
impl PublicKey {
	/// Return true iff the exponent for this key is the same
	/// number as 'e'.
	pub fn exponent_is(&self, e: u32) -> bool {
		use nioruntime_deps::rsa::PublicKeyParts;
		*self.0.e() == nioruntime_deps::rsa::BigUint::new(vec![e])
	}
	/// Return the number of bits in the modulus for this key.
	pub fn bits(&self) -> usize {
		use nioruntime_deps::rsa::PublicKeyParts;
		self.0.n().bits()
	}
	/// Try to check a signature (as used in Tor.)  The signed hash
	/// should be in 'hashed', and the alleged signature in 'sig'.
	///
	/// Tor uses RSA-PKCSv1 signatures, with hash algorithm OIDs
	/// omitted.
	pub fn verify(&self, hashed: &[u8], sig: &[u8]) -> Result<(), signature::Error> {
		use nioruntime_deps::rsa::PublicKey;
		let padding = nioruntime_deps::rsa::PaddingScheme::new_pkcs1v15_sign(None);
		self.0
			.verify(padding, hashed, sig)
			.map_err(|_| signature::Error::new())
	}
	/// Decode an alleged DER byte string into a PublicKey.
	///
	/// Return None  if the DER string does not have a valid PublicKey.
	///
	/// (This function expects an RsaPublicKey, as used by Tor.  It
	/// does not expect or accept a PublicKeyInfo.)
	pub fn from_der(der: &[u8]) -> Option<Self> {
		Some(PublicKey(
			nioruntime_deps::rsa::RsaPublicKey::from_pkcs1_der(der).ok()?,
		))
	}
	/// Encode this public key into the DER format as used by Tor.
	///
	/// The result is an RsaPublicKey, not a PublicKeyInfo.
	pub fn to_der(&self) -> Vec<u8> {
		// There seem to be version issues with these two
		// versions of bigint: yuck!
		use nioruntime_deps::rsa::BigUint; // not the same as the one in simple_asn1.
		use nioruntime_deps::rsa::PublicKeyParts;
		use nioruntime_deps::simple_asn1::{ASN1Block, BigInt};
		/// Helper: convert a BigUInt to signed asn1.
		fn to_asn1_int(x: &BigUint) -> ASN1Block {
			// We stick a "0" on the front so that we can used
			// from_signed_bytes_be.  The 0 guarantees that we'll
			// have a positive value.
			let mut bytes = vec![0];
			bytes.extend(x.to_bytes_be());
			// We use from_signed_bytes_be() here because simple_asn1
			// exposes BigInt but not Sign, so we can't call
			// its version of from_signed_bytes().
			let bigint = BigInt::from_signed_bytes_be(&bytes);
			ASN1Block::Integer(0, bigint)
		}

		let asn1 = ASN1Block::Sequence(0, vec![to_asn1_int(self.0.n()), to_asn1_int(self.0.e())]);
		nioruntime_deps::simple_asn1::to_der(&asn1).expect("RSA key not encodable as DER")
	}

	/// Compute the RsaIdentity for this public key.
	pub fn to_rsa_identity(&self) -> RsaIdentity {
		use nioruntime_deps::sha1::Sha1;
		let id = Sha1::digest(&self.to_der()).into();

		RsaIdentity { id }
	}
}

/// An RSA signature plus all the information needed to validate it.
pub struct ValidatableRsaSignature {
	/// The key that allegedly signed this signature
	key: PublicKey,
	/// The signature in question
	sig: Vec<u8>,
	/// The value we expect to find that the signature is a signature of.
	expected_hash: Vec<u8>,
}

impl ValidatableRsaSignature {
	/// Construct a new ValidatableRsaSignature.
	pub fn _new(key: &PublicKey, sig: &[u8], expected_hash: &[u8]) -> Self {
		ValidatableRsaSignature {
			key: key.clone(),
			sig: sig.into(),
			expected_hash: expected_hash.into(),
		}
	}
}

impl ValidatableSignature for ValidatableRsaSignature {
	fn is_valid(&self) -> bool {
		self.key
			.verify(&self.expected_hash[..], &self.sig[..])
			.is_ok()
	}
}
