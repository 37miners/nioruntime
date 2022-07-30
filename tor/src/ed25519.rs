//! Re-exporting Ed25519 implementations, and related utilities.
//!
//! Here we re-export types from [`ed25519_dalek`] that implement the
//! Ed25519 signature algorithm.  (TODO: Eventually, this module
//! should probably be replaced with a wrapper that uses the ed25519
//! trait and the Signature trait.)
//!
//! We additionally provide an `Ed25519Identity` type to represent the
//! unvalidated Ed25519 "identity keys" that we use throughout the Tor
//! protocol to uniquely identify a relay.

use crate::reader::Readable;
use crate::reader::Reader;
use crate::util::Timebound;
use crate::util::ValidatableSignature;
use nioruntime_deps::arrayref::array_ref;
use nioruntime_deps::base58::ToBase58;
use nioruntime_deps::base64;
use nioruntime_deps::caret::caret_int;
use nioruntime_deps::ed25519_dalek::Verifier;
use nioruntime_deps::serde;
use nioruntime_deps::subtle::{Choice, ConstantTimeEq};
pub use nioruntime_deps::x25519_dalek::PublicKey as XDalekPublicKey;
use nioruntime_err::{Error, ErrorKind};
use std::convert::{TryFrom, TryInto};
use std::fmt::{self, Debug, Display, Formatter};

/// Extension indicating that a key that signed a given certificate.
struct SignedWithEd25519Ext {
	/// The key that signed the certificate including this extension.
	pk: PublicKey,
}

/// Any unrecognized extension on a Tor certificate.
#[allow(unused)]
struct UnrecognizedExt {
	/// True iff this extension must be understand in order to validate the
	/// certificate.
	affects_validation: bool,
	/// The type of the extension
	ext_type: ExtType,
	/// The body of the extension.
	body: Vec<u8>,
}

/// A key whose type we didn't recognize.
pub struct UnrecognizedKey {
	/// Actual type of the key.
	key_type: KeyType,
	/// digest of the key, or the key itself.
	key_digest: [u8; 32],
}

/// An extension in a Tor certificate.
enum CertExt {
	/// Indicates which Ed25519 public key signed this cert.
	SignedWithEd25519(SignedWithEd25519Ext),
	/// An extension whose identity we don't recognize.
	Unrecognized(UnrecognizedExt),
}

impl Readable for CertExt {
	fn take_from(b: &mut Reader<'_>) -> Result<Self, Error> {
		let len = b.take_u16()?;
		let ext_type: ExtType = b.take_u8()?.into();
		let flags = b.take_u8()?;
		let body = b.take(len as usize)?;

		Ok(match ext_type {
			ExtType::SIGNED_WITH_ED25519_KEY => {
				if body.len() != 32 {
					return Err(ErrorKind::Tor("wrong length on Ed25519 key".to_string()).into());
				}
				CertExt::SignedWithEd25519(SignedWithEd25519Ext {
					pk: PublicKey::from_bytes(body).map_err(|_| {
						let error: Error =
							ErrorKind::Tor("invalid Ed25519 public key".to_string()).into();
						error
					})?,
				})
			}
			_ => {
				if (flags & 1) != 0 {
					return Err(ErrorKind::Tor(
						"unrecognized certificate extension, with 'affects_validation' flag set."
							.to_string(),
					)
					.into());
				}
				CertExt::Unrecognized(UnrecognizedExt {
					affects_validation: false,
					ext_type,
					body: body.into(),
				})
			}
		})
	}
}

impl CertExt {
	/// Return the identifier code for this Extension.
	fn ext_id(&self) -> ExtType {
		match self {
			CertExt::SignedWithEd25519(_) => ExtType::SIGNED_WITH_ED25519_KEY,
			CertExt::Unrecognized(u) => u.ext_type,
		}
	}
}

/// One of the data types that can be certified by an Ed25519Cert.
#[non_exhaustive]
pub enum CertifiedKey {
	/// An Ed25519 public key, signed directly.
	Ed25519(PublicKey),
	/// The SHA256 digest of a DER-encoded RsaPublicKey
	RsaSha256Digest([u8; 32]),
	/// The SHA256 digest of an X.509 certificate.
	X509Sha256Digest([u8; 32]),
	/// Some unrecognized key type.
	Unrecognized(UnrecognizedKey),
}

impl CertifiedKey {
	/// Return the byte that identifies the type of this key.
	pub fn key_type(&self) -> KeyType {
		match self {
			CertifiedKey::Ed25519(_) => KeyType::ED25519_KEY,
			CertifiedKey::RsaSha256Digest(_) => KeyType::SHA256_OF_RSA,
			CertifiedKey::X509Sha256Digest(_) => KeyType::SHA256_OF_X509,

			CertifiedKey::Unrecognized(u) => u.key_type,
		}
	}
	/// Return the bytes that are used for the body of this certified
	/// key or object.
	pub fn as_bytes(&self) -> &[u8] {
		match self {
			CertifiedKey::Ed25519(k) => k.as_bytes(),
			CertifiedKey::RsaSha256Digest(k) => &k[..],
			CertifiedKey::X509Sha256Digest(k) => &k[..],
			CertifiedKey::Unrecognized(u) => &u.key_digest[..],
		}
	}
	/// If this is an Ed25519 public key, return Some(key).
	/// Otherwise, return None.
	pub fn as_ed25519(&self) -> Option<&PublicKey> {
		match self {
			CertifiedKey::Ed25519(k) => Some(k),
			_ => None,
		}
	}
	/// Try to extract a CertifiedKey from a Reader, given that we have
	/// already read its type as `key_type`.
	fn from_reader(key_type: KeyType, r: &mut Reader<'_>) -> Result<Self, Error> {
		Ok(match key_type {
			KeyType::ED25519_KEY => CertifiedKey::Ed25519(r.extract()?),
			KeyType::SHA256_OF_RSA => CertifiedKey::RsaSha256Digest(r.extract()?),
			KeyType::SHA256_OF_X509 => CertifiedKey::X509Sha256Digest(r.extract()?),
			_ => CertifiedKey::Unrecognized(UnrecognizedKey {
				key_type,
				key_digest: r.extract()?,
			}),
		})
	}
}

caret_int! {
	/// Extension identifiers for extensions in certificates.
	pub struct ExtType(u8) {
		/// Extension indicating an Ed25519 key that signed this certificate.
		///
		/// Certificates do not always contain the key that signed them.
		SIGNED_WITH_ED25519_KEY = 0x04,
	}
}

caret_int! {
	/// Identifiers for the type of key or object getting signed.
	pub struct KeyType(u8) {
		/// Identifier for an Ed25519 key.
		ED25519_KEY = 0x01,
		/// Identifier for the SHA256 of an DER-encoded RSA key.
		SHA256_OF_RSA = 0x02,
		/// Identifies the SHA256 of an X.509 certificate.
		SHA256_OF_X509 = 0x03,

		// 08 through 09 and 0B are used for onion services.  They
		// probably shouldn't be, but that's what Tor does.
	}
}

caret_int! {
	/// Recognized values for Tor's certificate type field.
	///
	/// In the names used here, "X_V_Y" means "key X verifying key Y",
	/// whereas "X_CC_Y" means "key X cross-certifying key Y".  In both
	/// cases, X is the key that is doing the signing, and Y is the key
	/// or object that is getting signed.
	///
	/// Not every one of these types is valid for an Ed25519
	/// certificate.  Some are for X.509 certs in a CERTS cell; some
	/// are for RSA->Ed crosscerts in a CERTS cell.
	pub struct CertType(u8) {
		/// TLS link key, signed with RSA identity. X.509 format. (Obsolete)
		TLS_LINK_X509 = 0x01,
		/// Self-signed RSA identity certificate. X.509 format. (Legacy)
		RSA_ID_X509 = 0x02,
		/// RSA lnk authentication key signed with RSA identity
		/// key. X.509 format. (Obsolete)
		LINK_AUTH_X509 = 0x03,

		/// Identity verifying a signing key, directly.
		IDENTITY_V_SIGNING = 0x04,

		/// Signing key verifying a TLS certificate by digest.
		SIGNING_V_TLS_CERT = 0x05,

		/// Signing key verifying a link authentication key.
		SIGNING_V_LINK_AUTH = 0x06,

		/// RSA identity key certifying an Ed25519 identity key. RSA
		/// crosscert format. (Legacy)
		RSA_ID_V_IDENTITY = 0x07,

		/// For onion services: short-term signing key authenticated with
		/// blinded service identity.
		HS_BLINDED_ID_V_SIGNING = 0x08,

		/// For onion services: to be documented.
		HS_IP_V_SIGNING = 0x09,

		/// An ntor key converted to a ed25519 key, cross-certifying an
		/// identity key.
		NTOR_CC_IDENTITY = 0x0A,

		/// For onion services: to be documented.
		HS_IP_CC_SIGNING = 0x0B,
	}
}

/// Structure for an Ed25519-signed certificate as described in Tor's
/// cert-spec.txt.
pub struct Ed25519Cert {
	/// How many _hours_ after the epoch will this certificate expire?
	exp_hours: u32,
	/// Type of the certificate; recognized values are in certtype::*
	_cert_type: CertType,
	/// The key or object being certified.
	cert_key: CertifiedKey,
	/// A list of extensions.
	#[allow(unused)]
	extensions: Vec<CertExt>,
	/// The key that signed this cert.
	///
	/// Once the cert has been unwrapped from an KeyUnknownCert, this
	/// field will be set.
	signed_with: Option<PublicKey>,
}

impl Ed25519Cert {
	/*
		/// Helper: Assert that there is nothing wrong with the
		/// internal structure of this certificate.
		fn assert_rep_ok(&self) {
			assert!(self.extensions.len() <= std::u8::MAX as usize);
		}

		/// Encode a certificate into a new vector, signing the result
		/// with `keypair`.
		pub fn encode_and_sign(&self, skey: &ed25519::Keypair) -> Vec<u8> {
			self.assert_rep_ok();
			let mut w = Vec::new();
			w.write_u8(1); // Version
			w.write_u8(self.cert_type.into());
			w.write_u32(self.exp_hours);
			w.write_u8(self.cert_key.key_type().into());
			w.write_all(self.cert_key.as_bytes());

			for e in self.extensions.iter() {
				w.write(e);
			}

			let signature = skey.sign(&w[..]);
			w.write(&signature);
			w
		}
	*/

	/// Try to decode a certificate from a byte slice.
	///
	/// This function returns an error if the byte slice is not
	/// completely exhausted.
	///
	/// Note that the resulting KeyUnknownCertificate is not checked
	/// for validity at all: you will need to provide it with an expected
	/// signing key, then check it for timeliness and well-signedness.
	pub fn decode(cert: &[u8]) -> Result<KeyUnknownCert, Error> {
		let mut r = Reader::from_slice(cert);
		let v = r.take_u8()?;
		if v != 1 {
			// This would be something other than a "v1" certificate. We don't
			// understand those.
			return Err(ErrorKind::Tor("Unrecognized certificate version".to_string()).into());
		}
		let _cert_type = r.take_u8()?.into();
		let exp_hours = r.take_u32()?;
		let mut cert_key_type = r.take_u8()?.into();

		// This is a workaround for a tor bug: the key type is
		// wrong. It was fixed in tor#40124, which got merged into Tor
		// 0.4.5.x and later.
		if _cert_type == CertType::SIGNING_V_TLS_CERT && cert_key_type == KeyType::ED25519_KEY {
			cert_key_type = KeyType::SHA256_OF_X509;
		}

		let cert_key = CertifiedKey::from_reader(cert_key_type, &mut r)?;
		let n_exts = r.take_u8()?;
		let mut extensions = Vec::new();
		for _ in 0..n_exts {
			let e: CertExt = r.extract()?;
			extensions.push(e);
		}

		let sig_offset = r.consumed();
		let signature: Signature = r.extract()?;
		r.should_be_exhausted()?;

		let keyext = extensions
			.iter()
			.find(|e| e.ext_id() == ExtType::SIGNED_WITH_ED25519_KEY);

		let included_pkey = match keyext {
			Some(CertExt::SignedWithEd25519(s)) => Some(s.pk),
			_ => None,
		};

		Ok(KeyUnknownCert {
			cert: UncheckedCert {
				cert: Ed25519Cert {
					exp_hours,
					_cert_type,
					cert_key,
					extensions,

					signed_with: included_pkey,
				},
				text: cert[0..sig_offset].into(),
				signature,
			},
		})
	}

	/// Return the time at which this certificate becomes expired
	pub fn expiry(&self) -> std::time::SystemTime {
		let d = std::time::Duration::new(u64::from(self.exp_hours) * 3600, 0);
		std::time::SystemTime::UNIX_EPOCH + d
	}

	/// Return true iff this certificate will be expired at the time `when`.
	pub fn is_expired_at(&self, when: std::time::SystemTime) -> bool {
		when >= self.expiry()
	}

	/// Return the signed key or object that is authenticated by this
	/// certificate.
	pub fn subject_key(&self) -> &CertifiedKey {
		&self.cert_key
	}

	/// Return the ed25519 key that signed this certificate.
	pub fn signing_key(&self) -> Option<&PublicKey> {
		self.signed_with.as_ref()
	}

	/// Return the type of this certificate.
	pub fn _cert_type(&self) -> CertType {
		self._cert_type
	}
}

/// A parsed Ed25519 certificate. Maybe it includes its signing key;
/// maybe it doesn't.
pub struct KeyUnknownCert {
	/// The certificate whose signing key might not be known.
	cert: UncheckedCert,
}

impl KeyUnknownCert {
	/// Return the certificate type of the underling cert.
	pub fn _peek_cert_type(&self) -> CertType {
		self.cert.cert._cert_type
	}
	/// Return subject key of the underlying cert.
	pub fn _peek_subject_key(&self) -> &CertifiedKey {
		&self.cert.cert.cert_key
	}

	/// Check whether a given pkey is (or might be) a key that has correctly
	/// signed this certificate.
	///
	/// On success, we can check whether the certificate is well-signed;
	/// otherwise, we can't check the certificate.
	pub fn check_key(self, pkey: &Option<PublicKey>) -> Result<UncheckedCert, Error> {
		let real_key = match (pkey, self.cert.cert.signed_with) {
			(Some(a), Some(b)) if a == &b => b,
			(Some(_), Some(_)) => {
				return Err(ErrorKind::Tor("Mismatched public key on cert".to_string()).into())
			}
			(Some(a), None) => *a,
			(None, Some(b)) => b,
			(None, None) => {
				return Err(ErrorKind::Tor("Missing public key on cert".to_string()).into())
			}
		};
		Ok(UncheckedCert {
			cert: Ed25519Cert {
				signed_with: Some(real_key),
				..self.cert.cert
			},
			..self.cert
		})
	}
}

/// A certificate that has been parsed, but whose signature and
/// timeliness have not been checked.
pub struct UncheckedCert {
	/// The parsed certificate, possibly modified by inserting an externally
	/// supplied key as its signing key.
	cert: Ed25519Cert,

	/// The signed text of the certificate. (Checking ed25519 signatures
	/// forces us to store this.
	// TODO(nickm)  It would be better to store a hash here, but we
	// don't have the right Ed25519 API.
	text: Vec<u8>,

	/// The alleged signature
	signature: Signature,
}

/// A certificate that has been parsed and signature-checked, but whose
/// timeliness has not been checked.
pub struct SigCheckedCert {
	/// The certificate that might or might not be timely
	cert: Ed25519Cert,
}

impl UncheckedCert {
	/// Split this unchecked cert into a component that assumes it has
	/// been checked, and a signature to validate.
	pub fn dangerously_split(self) -> Result<(SigCheckedCert, ValidatableEd25519Signature), Error> {
		let signing_key = self.cert.signed_with.ok_or({
			let error: Error = ErrorKind::Tor("Missing public key on cert".to_string()).into();
			error
		})?;
		let signature =
			ValidatableEd25519Signature::new(signing_key, self.signature, &self.text[..]);
		Ok((self.dangerously_assume_wellsigned(), signature))
	}

	/// Return subject key of the underlying cert.
	pub fn _peek_subject_key(&self) -> &CertifiedKey {
		&self.cert.cert_key
	}
	/// Return signing key of the underlying cert.
	pub fn _peek_signing_key(&self) -> &PublicKey {
		self.cert
			.signed_with
			.as_ref()
			.expect("Made an UncheckedCert without a signing key")
	}
}

/// A cryptographically signed object that can be validated without
/// additional public keys.
///
/// It's better to wrap things in a SelfSigned than to give them an is_valid()
/// method, so that you can make sure that nobody uses the object before
/// checking it.  It's better to wrap things in a SelfSigned than to check
/// them immediately, since you might want to defer the signature checking
/// operation to another thread.
pub trait SelfSigned<T>: Sized {
	/// An error type that's returned when the object is _not_ well-signed.
	type Error;
	/// Check the signature on this object
	fn is_well_signed(&self) -> Result<(), Self::Error>;
	/// Return the underlying object without checking its signature.
	fn dangerously_assume_wellsigned(self) -> T;

	/// Unwrap this object if the signature is valid
	fn check_signature(self) -> Result<T, Self::Error> {
		self.is_well_signed()?;
		Ok(self.dangerously_assume_wellsigned())
	}
}

impl SelfSigned<SigCheckedCert> for UncheckedCert {
	type Error = Error;

	fn is_well_signed(&self) -> Result<(), Error> {
		let pubkey = &self.cert.signed_with.ok_or({
			let error: Error =
				ErrorKind::Tor("Certificate was not in fact self-signed".to_string()).into();
			error
		})?;

		pubkey
			.verify(&self.text[..], &self.signature)
			.map_err(|_| {
				let error: Error =
					ErrorKind::Tor("Invalid certificate signature".to_string()).into();
				error
			})?;

		Ok(())
	}

	fn dangerously_assume_wellsigned(self) -> SigCheckedCert {
		SigCheckedCert { cert: self.cert }
	}
}

impl Timebound<Ed25519Cert> for SigCheckedCert {
	type Error = Error;
	fn is_valid_at(&self, t: &std::time::SystemTime) -> std::result::Result<(), Self::Error> {
		if self.cert.is_expired_at(*t) {
			let expiry = self.cert.expiry();
			Err(ErrorKind::Tor(
				format!("Expired: {}ms ago.", t.duration_since(expiry)?.as_millis()).into(),
			)
			.into())
		} else {
			Ok(())
		}
	}

	fn dangerously_assume_timely(self) -> Ed25519Cert {
		self.cert
	}
}

pub use nioruntime_deps::ed25519_dalek::{
	ExpandedSecretKey, Keypair, PublicKey, SecretKey, Signature,
};

/// A relay's identity, as an unchecked, unvalidated Ed25519 key.
///
/// This type is distinct from an Ed25519 [`PublicKey`] for several reasons:
///  * We're storing it in a compact format, whereas the public key
///    implementation might want an expanded form for more efficient key
///    validation.
///  * This type hasn't checked whether the bytes here actually _are_ a
///    valid Ed25519 public key.
#[derive(Clone, Copy, Hash)]
#[allow(clippy::derive_hash_xor_eq)]
pub struct Ed25519Identity {
	/// A raw unchecked Ed25519 public key.
	id: [u8; 32],
}

impl Ed25519Identity {
	/// Construct a new Ed25519 identity from a 32-byte sequence.
	///
	/// This might or might not actually be a valid Ed25519 public key.
	///
	/// ```
	/// use nioruntime_tor::ed25519::{Ed25519Identity, PublicKey};
	/// use std::convert::TryInto;
	///
	/// let bytes = b"klsadjfkladsfjklsdafkljasdfsdsd!";
	/// let id = Ed25519Identity::new(*bytes);
	/// let pk: Result<PublicKey,_> = (&id).try_into();
	/// assert!(pk.is_ok());
	///
	/// let bytes = b"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
	/// let id = Ed25519Identity::new(*bytes);
	/// let pk: Result<PublicKey,_> = (&id).try_into();
	/// assert!(pk.is_err());
	/// ```
	pub fn new(id: [u8; 32]) -> Self {
		Ed25519Identity { id }
	}
	/// If `id` is of the correct length, wrap it in an Ed25519Identity.
	pub fn from_bytes(id: &[u8]) -> Option<Self> {
		if id.len() == 32 {
			Some(Ed25519Identity::new(*array_ref!(id, 0, 32)))
		} else {
			None
		}
	}
	/// Return a reference to the bytes in this key.
	pub fn as_bytes(&self) -> &[u8] {
		&self.id[..]
	}

	/// Return a base58 String representation of this key.
	pub fn to_base58(&self) -> String {
		self.id.to_base58()
	}
}

impl From<[u8; 32]> for Ed25519Identity {
	fn from(id: [u8; 32]) -> Self {
		Ed25519Identity::new(id)
	}
}

impl From<PublicKey> for Ed25519Identity {
	fn from(pk: PublicKey) -> Self {
		(&pk).into()
	}
}

impl From<&PublicKey> for Ed25519Identity {
	fn from(pk: &PublicKey) -> Self {
		// This unwrap is safe because the public key is always 32 bytes
		// long.
		Ed25519Identity::from_bytes(pk.as_bytes()).expect("Ed25519 public key had wrong length?")
	}
}

impl TryFrom<&Ed25519Identity> for PublicKey {
	type Error = nioruntime_deps::ed25519_dalek::SignatureError;
	fn try_from(id: &Ed25519Identity) -> Result<PublicKey, Self::Error> {
		PublicKey::from_bytes(&id.id[..])
	}
}

impl TryFrom<Ed25519Identity> for PublicKey {
	type Error = nioruntime_deps::ed25519_dalek::SignatureError;
	fn try_from(id: Ed25519Identity) -> Result<PublicKey, Self::Error> {
		(&id).try_into()
	}
}

impl ConstantTimeEq for Ed25519Identity {
	fn ct_eq(&self, other: &Self) -> Choice {
		self.id.ct_eq(&other.id)
	}
}

impl PartialEq<Ed25519Identity> for Ed25519Identity {
	fn eq(&self, rhs: &Ed25519Identity) -> bool {
		self.ct_eq(rhs).unwrap_u8() == 1
	}
}

impl Eq for Ed25519Identity {}

impl Display for Ed25519Identity {
	fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
		write!(
			f,
			"{}",
			base64::encode_config(self.id, base64::STANDARD_NO_PAD)
		)
	}
}

impl Debug for Ed25519Identity {
	fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
		write!(f, "Ed25519Identity {{ {} }}", self)
	}
}

impl serde::Serialize for Ed25519Identity {
	fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
	where
		S: serde::Serializer,
	{
		if serializer.is_human_readable() {
			serializer.serialize_str(&base64::encode_config(self.id, base64::STANDARD_NO_PAD))
		} else {
			serializer.serialize_bytes(&self.id[..])
		}
	}
}

impl<'de> serde::Deserialize<'de> for Ed25519Identity {
	fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
	where
		D: serde::Deserializer<'de>,
	{
		if deserializer.is_human_readable() {
			/// Helper for deserialization
			struct EdIdentityVisitor;
			impl<'de> serde::de::Visitor<'de> for EdIdentityVisitor {
				type Value = Ed25519Identity;
				fn expecting(&self, fmt: &mut std::fmt::Formatter<'_>) -> fmt::Result {
					fmt.write_str("base64-encoded Ed25519 public key")
				}
				fn visit_str<E>(self, s: &str) -> Result<Self::Value, E>
				where
					E: serde::de::Error,
				{
					let bytes =
						base64::decode_config(s, base64::STANDARD_NO_PAD).map_err(E::custom)?;
					Ed25519Identity::from_bytes(&bytes)
						.ok_or_else(|| E::custom("wrong length for Ed25519 public key"))
				}
			}

			deserializer.deserialize_str(EdIdentityVisitor)
		} else {
			/// Helper for deserialization
			struct EdIdentityVisitor;
			impl<'de> serde::de::Visitor<'de> for EdIdentityVisitor {
				type Value = Ed25519Identity;
				fn expecting(&self, fmt: &mut std::fmt::Formatter<'_>) -> fmt::Result {
					fmt.write_str("ed25519 public key")
				}
				fn visit_bytes<E>(self, bytes: &[u8]) -> Result<Self::Value, E>
				where
					E: serde::de::Error,
				{
					Ed25519Identity::from_bytes(bytes)
						.ok_or_else(|| E::custom("wrong length for ed25519 public key"))
				}
			}
			deserializer.deserialize_bytes(EdIdentityVisitor)
		}
	}
}

/// An ed25519 signature, plus the document that it signs and its
/// public key.
pub struct ValidatableEd25519Signature {
	/// The key that allegedly produced the signature
	key: PublicKey,
	/// The alleged signature
	sig: Signature,
	/// The entire body of text that is allegedly signed here.
	///
	/// TODO: It's not so good to have this included here; it
	/// would be better to have a patch to ed25519_dalek to allow
	/// us to pre-hash the signed thing, and just store a digest.
	/// We can't use that with the 'prehash' variant of ed25519,
	/// since that has different constants.
	entire_text_of_signed_thing: Vec<u8>,
}

impl ValidatableEd25519Signature {
	/// Create a new ValidatableEd25519Signature
	pub fn new(key: PublicKey, sig: Signature, text: &[u8]) -> Self {
		ValidatableEd25519Signature {
			key,
			sig,
			entire_text_of_signed_thing: text.into(),
		}
	}

	/// View the interior of this signature object.
	pub(crate) fn as_parts(&self) -> (&PublicKey, &Signature, &[u8]) {
		(&self.key, &self.sig, &self.entire_text_of_signed_thing[..])
	}
}

impl ValidatableSignature for ValidatableEd25519Signature {
	fn is_valid(&self) -> bool {
		self.key
			.verify(&self.entire_text_of_signed_thing[..], &self.sig)
			.is_ok()
	}

	fn as_ed25519(&self) -> Option<&ValidatableEd25519Signature> {
		Some(self)
	}
}

/// Perform a batch verification operation on the provided signatures
///
/// Return `true` if _every_ signature is valid; otherwise return `false`.
///
/// Note that the mathematics for batch validation are slightly
/// different than those for normal one-signature validation.  Because
/// of this, it is possible for an ostensible signature that passes
/// one validation algorithm might fail the other.  (Well-formed
/// signatures generated by a correct Ed25519 implementation will
/// always pass both kinds of validation, and an attacker should not
/// be able to forge a signature that passes either kind.)
pub fn validate_batch(sigs: &[&ValidatableEd25519Signature]) -> bool {
	if sigs.is_empty() {
		// ed25519_dalek has nonzero cost for a batch-verification of
		// zero sigs.
		true
	} else if sigs.len() == 1 {
		// Validating one signature in the traditional way is faster.
		sigs[0].is_valid()
	} else {
		let mut ed_msgs = Vec::new();
		let mut ed_sigs = Vec::new();
		let mut ed_pks = Vec::new();
		for ed_sig in sigs {
			let (pk, sig, msg) = ed_sig.as_parts();
			ed_sigs.push(*sig);
			ed_pks.push(*pk);
			ed_msgs.push(msg);
		}
		nioruntime_deps::ed25519_dalek::verify_batch(&ed_msgs[..], &ed_sigs[..], &ed_pks[..])
			.is_ok()
	}
}
