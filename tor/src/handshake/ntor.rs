//! Implements the ntor handshake, as used in modern Tor.

use super::KeyGenerator;
use crate::reader::Reader;
use crate::rsa::RsaIdentity;
use crate::util::RngCompatExt;
use crate::util::{bool_to_choice, lookup};
use crate::writer::Writer;
use crate::SecretBytes;
use nioruntime_deps::base64;
use nioruntime_deps::digest::Mac;
use nioruntime_deps::rand_core::{CryptoRng, RngCore};
use nioruntime_deps::sha2::Sha256;
use nioruntime_deps::x25519_dalek::{EphemeralSecret, PublicKey, SharedSecret, StaticSecret};
use nioruntime_deps::zeroize::Zeroizing;
use nioruntime_err::{Error, ErrorKind};
use nioruntime_log::*;

debug!();

/// Client side of the Ntor handshake.
pub struct NtorClient;

impl super::ClientHandshake for NtorClient {
	type KeyType = NtorPublicKey;
	type StateType = NtorHandshakeState;
	type KeyGen = NtorHkdfKeyGenerator;

	fn client1<R: RngCore + CryptoRng>(
		rng: &mut R,
		key: &Self::KeyType,
	) -> Result<(Self::StateType, Vec<u8>), Error> {
		Ok(client_handshake_ntor_v1(rng, key))
	}

	fn client2<T: AsRef<[u8]>>(state: Self::StateType, msg: T) -> Result<Self::KeyGen, Error> {
		client_handshake2_ntor_v1(msg, &state)
	}
}

/// Server side of the ntor handshake.
pub(crate) struct NtorServer;

impl super::ServerHandshake for NtorServer {
	type KeyType = NtorSecretKey;
	type KeyGen = NtorHkdfKeyGenerator;

	fn server<R: RngCore + CryptoRng, T: AsRef<[u8]>>(
		rng: &mut R,
		key: &[Self::KeyType],
		msg: T,
	) -> Result<(Self::KeyGen, Vec<u8>), Error> {
		server_handshake_ntor_v1(rng, msg, key)
	}
}

/// A set of public keys used by a client to initiate an ntor handshake.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct NtorPublicKey {
	/// Public RSA identity fingerprint for the relay; used in authentication
	/// calculation.
	pub(crate) id: RsaIdentity,
	/// Public curve25519 ntor key for the relay.
	pub(crate) pk: PublicKey,
}

impl NtorPublicKey {
	pub fn from_base64(b64: &str) -> Option<PublicKey> {
		match base64::decode(b64) {
			Ok(b) => {
				let mut bytes: [u8; 32] = [0u8; 32];
				if b.len() == 32 {
					bytes.clone_from_slice(&b[0..32]);
					Some(PublicKey::from(bytes))
				} else {
					None
				}
			}
			Err(_) => None,
		}
	}
}

/// A secret key used by a relay to answer an ntor request
pub(crate) struct NtorSecretKey {
	/// Public key components; must match those held by the client.
	pk: NtorPublicKey,
	/// Secret curve25519 ntor key for the relay; must correspond to
	/// the public key in pk.pk.
	sk: StaticSecret,
}

use nioruntime_deps::subtle::{Choice, ConstantTimeEq};
impl NtorSecretKey {
	/// Construct a new NtorSecretKey from its components.
	#[allow(unused)]
	pub(crate) fn new(sk: StaticSecret, pk: PublicKey, id: RsaIdentity) -> Self {
		NtorSecretKey {
			pk: NtorPublicKey { id, pk },
			sk,
		}
	}
	/// Return true if the curve25519 public key in `self` matches `pk`.
	///
	/// Used for looking up keys in an array.
	fn matches_pk(&self, pk: &PublicKey) -> Choice {
		self.pk.pk.as_bytes().ct_eq(pk.as_bytes())
	}
}

/// Client state for an ntor handshake.
#[derive(Clone)]
pub struct NtorHandshakeState {
	/// The relay's public key.  We need to remember this since it is
	/// used to finish the handshake.
	relay_public: NtorPublicKey,
	/// The temporary curve25519 secret (x) that we've generated for
	/// this handshake.
	// We'd like to EphemeralSecret here, but we can't since we need
	// to use it twice.
	my_sk: StaticSecret,
	/// The public key `X` corresponding to my_sk.
	my_public: PublicKey,
}

impl std::fmt::Debug for NtorHandshakeState {
	fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
		write!(
			f,
			"NtorHandshakeState=[relay_public={:?},my_public={:?},]",
			self.relay_public, self.my_public
		)
	}
}

/// KeyGenerator for use with ntor circuit handshake.
pub struct NtorHkdfKeyGenerator {
	/// Secret key information derived from the handshake, used as input
	/// to HKDF
	seed: SecretBytes,
}

impl NtorHkdfKeyGenerator {
	/// Create a new key generator to expand a given seed
	pub(crate) fn new(seed: SecretBytes) -> Self {
		NtorHkdfKeyGenerator { seed }
	}
}

impl KeyGenerator for NtorHkdfKeyGenerator {
	fn expand(self, keylen: usize) -> Result<SecretBytes, Error> {
		let ntor1_key = &b"ntor-curve25519-sha256-1:key_extract"[..];
		let ntor1_expand = &b"ntor-curve25519-sha256-1:key_expand"[..];
		use crate::kdf::{Kdf, Ntor1Kdf};
		Ntor1Kdf::new(ntor1_key, ntor1_expand).derive(&self.seed[..], keylen)
	}
}

/// Alias for an HMAC output, used to validate correctness of a handshake.
type Authcode = nioruntime_deps::digest::CtOutput<nioruntime_deps::hmac::Hmac<Sha256>>;

/// Perform a client handshake, generating an onionskin and a state object
fn client_handshake_ntor_v1<R>(
	rng: &mut R,
	relay_public: &NtorPublicKey,
) -> (NtorHandshakeState, Vec<u8>)
where
	R: RngCore + CryptoRng,
{
	let my_sk = StaticSecret::new(rng.rng_compat());
	let my_public = PublicKey::from(&my_sk);

	client_handshake_ntor_v1_no_keygen(my_public, my_sk, relay_public)
}

/// Helper: client handshake _without_ generating  new keys.
fn client_handshake_ntor_v1_no_keygen(
	my_public: PublicKey,
	my_sk: StaticSecret,
	relay_public: &NtorPublicKey,
) -> (NtorHandshakeState, Vec<u8>) {
	let mut v: Vec<u8> = Vec::new();

	v.write(&relay_public.id);
	v.write(&relay_public.pk);
	v.write(&my_public);

	assert_eq!(v.len(), 20 + 32 + 32);

	let state = NtorHandshakeState {
		relay_public: relay_public.clone(),
		my_public,
		my_sk,
	};

	(state, v)
}

/// Complete a client handshake, returning a key generator on success.
fn client_handshake2_ntor_v1<T>(
	msg: T,
	state: &NtorHandshakeState,
) -> Result<NtorHkdfKeyGenerator, Error>
where
	T: AsRef<[u8]>,
{
	let mut cur = Reader::from_slice(msg.as_ref());
	let their_pk: PublicKey = cur.extract()?;
	let auth: Authcode = cur.extract()?;
	let xy = state.my_sk.diffie_hellman(&their_pk);
	let xb = state.my_sk.diffie_hellman(&state.relay_public.pk);
	let (keygen, authcode) =
		ntor_derive(&xy, &xb, &state.relay_public, &state.my_public, &their_pk);
	let okay = authcode.ct_eq(&auth)
		& bool_to_choice(xy.was_contributory())
		& bool_to_choice(xb.was_contributory());
	if okay.into() {
		Ok(keygen)
	} else {
		Err(ErrorKind::Tor(format!("BadCircHandshake: {:?}", okay)).into())
	}
}

/// helper: compute a key generator and an authentication code from a set
/// of ntor parameters.
///
/// These parameter names are as described in tor-spec.txt
fn ntor_derive(
	xy: &SharedSecret,
	xb: &SharedSecret,
	server_pk: &NtorPublicKey,
	x: &PublicKey,
	y: &PublicKey,
) -> (NtorHkdfKeyGenerator, Authcode) {
	let ntor1_protoid = &b"ntor-curve25519-sha256-1"[..];
	let ntor1_mac = &b"ntor-curve25519-sha256-1:mac"[..];
	let ntor1_verify = &b"ntor-curve25519-sha256-1:verify"[..];
	let server_string = &b"Server"[..];

	let mut secret_input = Zeroizing::new(Vec::new());
	secret_input.write(xy); // EXP(X,y)
	secret_input.write(xb); // EXP(X,b)
	secret_input.write(&server_pk.id); // ID
	secret_input.write(&server_pk.pk); // B
	secret_input.write(x); // X
	secret_input.write(y); // Y
	secret_input.write(ntor1_protoid); // PROTOID

	use nioruntime_deps::hmac::Hmac;
	let verify = {
		let mut m =
			Hmac::<Sha256>::new_from_slice(ntor1_verify).expect("Hmac allows keys of any size");
		m.update(&secret_input[..]);
		m.finalize()
	};
	let mut auth_input: SecretBytes = Zeroizing::new(Vec::new());
	auth_input.write_and_consume(verify); // verify
	auth_input.write(&server_pk.id); // ID
	auth_input.write(&server_pk.pk); // B
	auth_input.write(y); // Y
	auth_input.write(x); // X
	auth_input.write(ntor1_protoid); // PROTOID
	auth_input.write(server_string); // "Server"

	let auth_mac = {
		let mut m =
			Hmac::<Sha256>::new_from_slice(ntor1_mac).expect("Hmac allows keys of any size");
		m.update(&auth_input[..]);
		m.finalize()
	};

	let keygen = NtorHkdfKeyGenerator::new(secret_input);
	(keygen, auth_mac)
}

/// Perform a server-side ntor handshake.
///
/// On success returns a key generator and a server onionskin.
fn server_handshake_ntor_v1<R, T>(
	rng: &mut R,
	msg: T,
	keys: &[NtorSecretKey],
) -> Result<(NtorHkdfKeyGenerator, Vec<u8>), Error>
where
	R: RngCore + CryptoRng,
	T: AsRef<[u8]>,
{
	// TODO(nickm): we generate this key whether or not we are
	// actually going to find our nodeid or keyid. Perhaps we should
	// delay that till later?  It shouldn't matter for most cases,
	// though.
	let ephem = EphemeralSecret::new(rng.rng_compat());
	let ephem_pub = PublicKey::from(&ephem);

	server_handshake_ntor_v1_no_keygen(ephem_pub, ephem, msg, keys)
}

/// Helper: perform a server handshake without generating any new keys.
fn server_handshake_ntor_v1_no_keygen<T>(
	ephem_pub: PublicKey,
	ephem: EphemeralSecret,
	msg: T,
	keys: &[NtorSecretKey],
) -> Result<(NtorHkdfKeyGenerator, Vec<u8>), Error>
where
	T: AsRef<[u8]>,
{
	let mut cur = Reader::from_slice(msg.as_ref());

	let my_id: RsaIdentity = cur.extract()?;
	let my_key: PublicKey = cur.extract()?;
	let their_pk: PublicKey = cur.extract()?;

	let keypair = lookup(keys, |key| key.matches_pk(&my_key));
	let keypair = match keypair {
		Some(k) => k,
		None => return Err(ErrorKind::Tor("MissingKey".into()).into()),
	};

	if my_id != keypair.pk.id {
		return Err(ErrorKind::Tor("MissingKey".into()).into());
	}

	let xy = ephem.diffie_hellman(&their_pk);
	let xb = keypair.sk.diffie_hellman(&their_pk);

	let okay = bool_to_choice(xy.was_contributory()) & bool_to_choice(xb.was_contributory());

	let (keygen, authcode) = ntor_derive(&xy, &xb, &keypair.pk, &their_pk, &ephem_pub);

	let mut reply: Vec<u8> = Vec::new();
	reply.write(&ephem_pub);
	reply.write_and_consume(authcode);

	if okay.into() {
		Ok((keygen, reply))
	} else {
		Err(ErrorKind::Tor("BadHandshake".into()).into())
	}
}

#[cfg(test)]
mod tests {
	#![allow(clippy::unwrap_used)]
	use super::*;
	use crate::handshake::ClientHandshake;
	use crate::handshake::ServerHandshake;
	use nioruntime_deps::rand_core;

	pub(crate) struct FakePRNG<'a> {
		bytes: &'a [u8],
	}
	impl<'a> FakePRNG<'a> {
		pub(crate) fn new(bytes: &'a [u8]) -> Self {
			Self { bytes }
		}
	}
	impl<'a> rand_core::RngCore for FakePRNG<'a> {
		fn next_u32(&mut self) -> u32 {
			rand_core::impls::next_u32_via_fill(self)
		}
		fn next_u64(&mut self) -> u64 {
			rand_core::impls::next_u64_via_fill(self)
		}
		fn try_fill_bytes(&mut self, dest: &mut [u8]) -> std::result::Result<(), rand_core::Error> {
			self.fill_bytes(dest);
			Ok(())
		}
		fn fill_bytes(&mut self, dest: &mut [u8]) {
			assert!(dest.len() <= self.bytes.len());

			dest.copy_from_slice(&self.bytes[0..dest.len()]);
			self.bytes = &self.bytes[dest.len()..];
		}
	}
	impl rand_core::CryptoRng for FakePRNG<'_> {}

	#[test]
	fn simple() -> Result<(), Error> {
		let mut rng = nioruntime_deps::rand::thread_rng().rng_compat();
		let relay_secret = StaticSecret::new(&mut rng);
		let relay_public = PublicKey::from(&relay_secret);
		let relay_identity = RsaIdentity::from_bytes(&[12; 20]).unwrap();
		let relay_ntpk = NtorPublicKey {
			id: relay_identity,
			pk: relay_public,
		};
		let (state, cmsg) = NtorClient::client1(&mut rng, &relay_ntpk)?;

		let relay_ntsk = NtorSecretKey {
			pk: relay_ntpk,
			sk: relay_secret,
		};
		let relay_ntsks = [relay_ntsk];

		let (skeygen, smsg) = NtorServer::server(&mut rng, &relay_ntsks, &cmsg).unwrap();

		let ckeygen = NtorClient::client2(state, smsg)?;

		let skeys = skeygen.expand(55)?;
		let ckeys = ckeygen.expand(55)?;

		assert_eq!(skeys, ckeys);

		Ok(())
	}

	fn make_fake_ephem_key(bytes: &[u8]) -> EphemeralSecret {
		assert_eq!(bytes.len(), 32);
		let mut rng = FakePRNG::new(bytes).rng_compat();
		EphemeralSecret::new(&mut rng)
	}

	#[test]
	fn testvec() -> Result<(), Error> {
		use nioruntime_deps::hex_literal::hex;

		let b_sk = hex!("4820544f4c4420594f5520444f474954204b454550532048415050454e494e47");
		let b_pk = hex!("ccbc8541904d18af08753eae967874749e6149f873de937f57f8fd903a21c471");
		let x_sk = hex!("706f6461792069207075742e2e2e2e2e2e2e2e4a454c4c59206f6e2074686973");
		let x_pk = hex!("e65dfdbef8b2635837fe2cebc086a8096eae3213e6830dc407516083d412b078");
		let y_sk = hex!("70686520737175697272656c2e2e2e2e2e2e2e2e686173206869732067616d65");
		let y_pk = hex!("390480a14362761d6aec1fea840f6e9e928fb2adb7b25c670be1045e35133a37");
		let id = hex!("69546f6c64596f7541626f75745374616972732e");
		let client_handshake = hex!("69546f6c64596f7541626f75745374616972732eccbc8541904d18af08753eae967874749e6149f873de937f57f8fd903a21c471e65dfdbef8b2635837fe2cebc086a8096eae3213e6830dc407516083d412b078");
		let server_handshake = hex!("390480a14362761d6aec1fea840f6e9e928fb2adb7b25c670be1045e35133a371cbdf68b89923e1f85e8e18ee6e805ea333fe4849c790ffd2670bd80fec95cc8");
		let keys = hex!("0c62dee7f48893370d0ef896758d35729867beef1a5121df80e00f79ed349af39b51cae125719182f19d932a667dae1afbf2e336e6910e7822223e763afad0a13342157969dc6b79");

		let relay_pk = NtorPublicKey {
			id: RsaIdentity::from_bytes(&id).unwrap(),
			pk: b_pk.into(),
		};
		let relay_sk = NtorSecretKey {
			pk: relay_pk.clone(),
			sk: b_sk.into(),
		};

		let (state, create_msg) =
			client_handshake_ntor_v1_no_keygen(x_pk.into(), x_sk.into(), &relay_pk);
		assert_eq!(&create_msg[..], &client_handshake[..]);

		let ephem = make_fake_ephem_key(&y_sk[..]);
		let ephem_pub = y_pk.into();
		let (s_keygen, created_msg) =
			server_handshake_ntor_v1_no_keygen(ephem_pub, ephem, &create_msg[..], &[relay_sk])
				.unwrap();
		assert_eq!(&created_msg[..], &server_handshake[..]);

		let c_keygen = client_handshake2_ntor_v1(created_msg, &state)?;

		let c_keys = c_keygen.expand(keys.len())?;
		let s_keys = s_keygen.expand(keys.len())?;
		assert_eq!(&c_keys[..], &keys[..]);
		assert_eq!(&s_keys[..], &keys[..]);

		Ok(())
	}

	#[test]
	fn failing_handshakes() {
		let mut rng = nioruntime_deps::rand::thread_rng().rng_compat();

		// Set up keys.
		let relay_secret = StaticSecret::new(&mut rng);
		let relay_public = PublicKey::from(&relay_secret);
		let wrong_public = PublicKey::from([16_u8; 32]);
		let relay_identity = RsaIdentity::from_bytes(&[12; 20]).unwrap();
		let wrong_identity = RsaIdentity::from_bytes(&[13; 20]).unwrap();
		let relay_ntpk = NtorPublicKey {
			id: relay_identity,
			pk: relay_public,
		};
		let relay_ntsk = NtorSecretKey {
			pk: relay_ntpk.clone(),
			sk: relay_secret,
		};
		let relay_ntsks = &[relay_ntsk];
		let wrong_ntpk1 = NtorPublicKey {
			id: wrong_identity,
			pk: relay_public,
		};
		let wrong_ntpk2 = NtorPublicKey {
			id: relay_identity,
			pk: wrong_public,
		};

		// If the client uses the wrong keys, the relay should reject the
		// handshake.
		let (_, handshake1) = NtorClient::client1(&mut rng, &wrong_ntpk1).unwrap();
		let (_, handshake2) = NtorClient::client1(&mut rng, &wrong_ntpk2).unwrap();
		let (st3, handshake3) = NtorClient::client1(&mut rng, &relay_ntpk).unwrap();

		let ans1 = NtorServer::server(&mut rng, relay_ntsks, &handshake1);
		let ans2 = NtorServer::server(&mut rng, relay_ntsks, &handshake2);
		let ans3 = NtorServer::server(&mut rng, relay_ntsks, &handshake3);

		assert!(ans1.is_err());
		assert!(ans2.is_err());
		assert!(ans3.is_ok());

		// If the relay's message is tampered with, the client will
		// reject the handshake.
		let (_, mut smsg) = NtorServer::server(&mut rng, relay_ntsks, &handshake3).unwrap();
		let smsg_orig = smsg.clone();
		smsg[60] ^= 7;
		let ans3 = NtorClient::client2(st3.clone(), smsg);
		assert!(ans3.is_err());
		let ans4 = NtorClient::client2(st3, smsg_orig);
		assert!(ans4.is_ok());
	}
}
