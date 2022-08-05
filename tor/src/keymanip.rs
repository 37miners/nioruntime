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

//! Key manipulation functions for use with public keys.
//!
//! Tor does some interesting and not-standard things with its
//! curve25519 and ed25519 keys, for several reasons.
//!
//! In order to prove ownership of a curve25519 private key, Tor
//! converts it into an ed25519 key, and then uses that ed25519 key to
//! sign its identity key.  We implement this conversion with
//! [`convert_curve25519_to_ed25519_public`] and
//! [`convert_curve25519_to_ed25519_private`].
//!
//! In Tor's v3 onion service design, Tor uses a _key blinding_
//! algorithm to derive a publicly known Ed25519 key from a different
//! Ed25519 key used as the .onion address.  This algorithm allows
//! directories to validate the signatures on onion service
//! descriptors, without knowing which services they represent.  We
//! implement this blinding operation via [`blind_pubkey`].
//!
//! ## TODO
//!
//! Recommend more standardized ways to do these things.

use crate::ed25519::Ed25519Identity;
use nioruntime_deps::digest::Digest;
use nioruntime_deps::sha3::Sha3_256;
pub use nioruntime_deps::x25519_dalek;
use nioruntime_err::{Error, ErrorKind};
use nioruntime_log::*;
use std::convert::TryInto;

info!();

const STR_ED25519_BASEPOINT: &[u8] =
	b"(15112221349535400772501151409588531511454012693041857206046113283949847762202, \
46316835694926478169428394003475163141307993866256225615783033603165251855960)";
const HS_KEYBLIND_NONCE_PREFIX: &[u8] = b"key-blind";
const HS_INDEX_PREFIX: &[u8] = b"store-at-idx";
const HS_DIR_INDEX_PREFIX: &[u8] = b"node-idx";

/// Convert a curve25519 public key (with sign bit) to an ed25519
/// public key, for use in ntor key cross-certification.
///
/// Note that this formula is not standardized; don't use
/// it for anything besides cross-certification.
#[cfg(test)]
pub fn convert_curve25519_to_ed25519_public(
	pubkey: &x25519_dalek::PublicKey,
	signbit: u8,
) -> Option<crate::ed25519::PublicKey> {
	use nioruntime_deps::curve25519_dalek::montgomery::MontgomeryPoint;

	let point = MontgomeryPoint(*pubkey.as_bytes());
	let edpoint = point.to_edwards(signbit)?;

	// TODO: This is inefficient; we shouldn't have to re-compress
	// this point to get the public key we wanted.  But there's no way
	// with the current API that I can to construct an ed25519 public
	// key from a compressed point.
	let compressed_y = edpoint.compress();
	crate::ed25519::PublicKey::from_bytes(compressed_y.as_bytes()).ok()
}

/// Convert a curve25519 private key to an ed25519 public key (and
/// give a sign bit) to use with it, for use in ntor key cross-certification.
///
/// Note that this formula is not standardized; don't use
/// it for anything besides cross-certification.
///
/// *NEVER* use these keys to sign inputs that may be generated by an
/// attacker.
///
/// # Panics
///
/// If the `debug_assertions` feature is enabled, this function will
/// double-check that the key it is about to return is the right
/// private key for the public key returned by
/// `convert_curve25519_to_ed25519_public`.
///
/// This panic should be impossible unless there are implementation
/// bugs.
///
/// # Availability
///
/// This function is only available when the `relay` feature is enabled.
#[cfg(any(test, feature = "relay"))]
pub fn convert_curve25519_to_ed25519_private(
	privkey: &x25519_dalek::StaticSecret,
) -> Option<(crate::ed25519::ExpandedSecretKey, u8)> {
	use nioruntime_deps::sha2::Sha512;
	use nioruntime_deps::zeroize::Zeroizing;

	let h = Sha512::new()
		.chain_update(privkey.to_bytes())
		.chain_update(&b"Derive high part of ed25519 key from curve25519 key\0"[..])
		.finalize();

	let mut bytes = Zeroizing::new([0_u8; 64]);
	bytes[0..32].clone_from_slice(&privkey.to_bytes());
	bytes[32..64].clone_from_slice(&h[0..32]);

	let result = crate::ed25519::ExpandedSecretKey::from_bytes(&bytes[..]).ok()?;
	let pubkey: crate::ed25519::PublicKey = (&result).into();
	let signbit = pubkey.as_bytes()[31] >> 7;

	#[cfg(debug_assertions)]
	{
		let curve_pubkey1 = x25519_dalek::PublicKey::from(privkey);
		let ed_pubkey1 = convert_curve25519_to_ed25519_public(&curve_pubkey1, signbit)?;
		assert_eq!(ed_pubkey1, pubkey);
	}

	Some((result, signbit))
}

/// Blind the ed25519 public key `pk` using the blinding parameter
/// `param`, and return the blinded public key.
///
/// This algorithm is described in `rend-spec-v3.txt`, section A.2.
/// In the terminology of that section, the value `pk` corresponds to
/// `A`, and the value `param` corresponds to `h`.
///
/// Note that the approach used to clamp `param` to a scalar means
/// that different possible values for `param` may yield the same
/// output for a given `pk`.  This and other limitations make this
/// function unsuitable for use outside the context of
/// `rend-spec-v3.txt` without careful analysis.
///
/// # Errors
///
/// This function can fail if the input is not actually a valid
/// Ed25519 public key.
///
/// # Availability
///
/// This function is only available when the `hsv3-client` feature is enabled.
pub fn blind_pubkey(
	pk: &crate::ed25519::PublicKey,
	mut param: [u8; 32],
) -> Result<crate::ed25519::PublicKey, Error> {
	use nioruntime_deps::curve25519_dalek::edwards::CompressedEdwardsY;
	use nioruntime_deps::curve25519_dalek::scalar::Scalar;

	// Clamp the blinding parameter
	param[0] &= 248;
	param[31] &= 63;
	param[31] |= 64;

	// Transform it into a scalar so that we can do scalar mult
	let blinding_factor = Scalar::from_bytes_mod_order(param);

	// Convert the public key to a point on the curve
	let pubkey_point = match CompressedEdwardsY(pk.to_bytes()).decompress() {
		Some(p) => p,
		None => {
			return Err(ErrorKind::Tor("BadPubkey".to_string()).into());
		}
	};

	// Do the scalar multiplication and get a point back
	let blinded_pubkey_point = (blinding_factor * pubkey_point).compress();
	// Turn the point back into bytes and return it
	Ok(crate::ed25519::PublicKey::from_bytes(
		&blinded_pubkey_point.0,
	)?)
}

pub fn build_hs_index(
	replica: u64,
	blinded_pk: &crate::ed25519::PublicKey,
	time_period: u64,
	period_length: u64,
) -> Result<[u8; 32], Error> {
	let hash: [u8; 32] = Sha3_256::new()
		.chain_update(HS_INDEX_PREFIX)
		.chain_update(blinded_pk.to_bytes())
		.chain_update(replica.to_be_bytes())
		.chain_update(period_length.to_be_bytes())
		.chain_update(time_period.to_be_bytes())
		.finalize()
		.try_into()?;
	Ok(hash)
}

pub fn build_hs_dir_index(
	identity: Ed25519Identity,
	srv_value: &[u8],
	time_period: u64,
	period_length: u64,
) -> Result<[u8; 32], Error> {
	let hash: [u8; 32] = Sha3_256::new()
		.chain_update(HS_DIR_INDEX_PREFIX)
		.chain_update(identity.as_bytes())
		.chain_update(srv_value)
		.chain_update(time_period.to_be_bytes())
		.chain_update(period_length.to_be_bytes())
		.finalize()
		.try_into()?;
	Ok(hash)
}

/// Calculate the param for blinding in tor
pub fn calc_param(
	pk_bytes: [u8; 32],
	secret: Option<Vec<u8>>,
	time_period: u64,
	period_length: u64,
) -> Result<[u8; 32], Error> {
	let blind_str: &[u8] = &b"Derive temporary signing key\0"[..];
	let mut nonce = vec![];
	nonce.extend(HS_KEYBLIND_NONCE_PREFIX);
	nonce.extend(time_period.to_be_bytes());
	nonce.extend(period_length.to_be_bytes());

	Ok(match secret {
		Some(secret) => Sha3_256::new()
			.chain_update(blind_str)
			.chain_update(pk_bytes)
			.chain_update(secret)
			.chain_update(STR_ED25519_BASEPOINT)
			.chain_update(nonce)
			.finalize()
			.try_into()?,
		None => Sha3_256::new()
			.chain_update(blind_str)
			.chain_update(pk_bytes)
			.chain_update(STR_ED25519_BASEPOINT)
			.chain_update(nonce)
			.finalize()
			.try_into()?,
	})
}

#[cfg(test)]
mod tests {
	#![allow(clippy::unwrap_used)]
	use super::*;
	use crate::TorDirectory;
	use nioruntime_deps::data_encoding::BASE32;
	use nioruntime_deps::hex;

	info!();

	#[test]
	fn test_with_param() -> Result<(), Error> {
		let b32 = BASE32
			.decode(
				"gxgn6ix6pzk6kk7luad2n7sdvzha6upz7jyj53k3wkuh5ykspjwpwyid"
					.to_uppercase()
					.as_bytes(),
			)
			.unwrap();
		let mut pkbytes = [0u8; 32];
		pkbytes.copy_from_slice(&b32[0..32]);
		let pk = crate::ed25519::PublicKey::from_bytes(&pkbytes).unwrap();
		let param = calc_param(pkbytes, None, 1, 1440)?;
		let blinded_pk = blind_pubkey(&pk, param)?;

		assert_eq!(
			"IJy6pqyIGJ1s56YTpGFg3gNpTi4XyHVgLK24ZHTcqpI=",
			nioruntime_deps::base64::encode(blinded_pk.to_bytes())
		);

		// build hsindex for this
		for i in 0..2 {
			let hs_index = build_hs_index(i + 1, &blinded_pk, 1, 1440)?;
			info!("hs_index={:?}", hs_index)?;
		}
		let directory = TorDirectory::from_file("./test/resources/authority".to_string())?;
		let hsdirs = directory.hsdirs();
		let srv_value = directory.srv_value()?;
		info!("srv_value={:?}", srv_value)?;
		for hsdir in hsdirs {
			let index = build_hs_dir_index(hsdir.ed25519_identity, srv_value, 1, 1440)?;
			info!("dir={:?}", index)?;
		}

		// display current
		let time_in_minutes = std::time::SystemTime::now()
			.duration_since(std::time::UNIX_EPOCH)?
			.as_secs() / 60;
		// subtract 12 hours
		let time_in_minutes = time_in_minutes.saturating_sub(12 * 60);
		let time_period = time_in_minutes / 1440; // consensus, but where do we get it?
		let param = calc_param(pkbytes, None, time_period, 1440)?;
		let blinded_pk = blind_pubkey(&pk, param)?;
		info!(
			"blinded_pk={}",
			nioruntime_deps::base64::encode(blinded_pk.to_bytes())
		)?;

		Ok(())
	}

	#[test]
	fn curve_to_ed_compatible() {
		use crate::util::RngCompatExt;
		use nioruntime_deps::rand::thread_rng;
		use nioruntime_deps::signature::Verifier;

		let rng = thread_rng().rng_compat();

		let curve_sk = x25519_dalek::StaticSecret::new(rng);
		let curve_pk = x25519_dalek::PublicKey::from(&curve_sk);

		let (ed_sk, signbit) = convert_curve25519_to_ed25519_private(&curve_sk).unwrap();
		let ed_pk1: crate::ed25519::PublicKey = (&ed_sk).into();
		let ed_pk2 = convert_curve25519_to_ed25519_public(&curve_pk, signbit).unwrap();

		let msg = b"tis the gift to be simple";
		let sig1 = ed_sk.sign(&msg[..], &ed_pk1);
		assert!(ed_pk1.verify(&msg[..], &sig1).is_ok());
		assert!(ed_pk2.verify(&msg[..], &sig1).is_ok());

		assert_eq!(ed_pk1, ed_pk2);
	}

	#[test]
	fn blinding() {
		use std::convert::TryInto;

		// Test the ed25519 blinding function.
		//
		// These test vectors are from our ed25519 implementation and related
		// functions. These were automatically generated by the
		// ed25519_exts_ref.py script in little-t-tor and they are also used by
		// little-t-tor and onionbalance:
		let pubkeys = vec![
			b"c2247870536a192d142d056abefca68d6193158e7c1a59c1654c954eccaff894",
			b"1519a3b15816a1aafab0b213892026ebf5c0dc232c58b21088d88cb90e9b940d",
			b"081faa81992e360ea22c06af1aba096e7a73f1c665bc8b3e4e531c46455fd1dd",
			b"73cfa1189a723aad7966137cbffa35140bb40d7e16eae4c40b79b5f0360dd65a",
			b"66c1a77104d86461b6f98f73acf3cd229c80624495d2d74d6fda1e940080a96b",
			b"d21c294db0e64cb2d8976625786ede1d9754186ae8197a64d72f68c792eecc19",
			b"c4d58b4cf85a348ff3d410dd936fa460c4f18da962c01b1963792b9dcc8a6ea6",
			b"95126f14d86494020665face03f2d42ee2b312a85bc729903eb17522954a1c4a",
			b"95126f14d86494020665face03f2d42ee2b312a85bc729903eb17522954a1c4a",
			b"95126f14d86494020665face03f2d42ee2b312a85bc729903eb17522954a1c4a",
		];
		let params = vec![
			"54a513898b471d1d448a2f3c55c1de2c0ef718c447b04497eeb999ed32027823",
			"831e9b5325b5d31b7ae6197e9c7a7baf2ec361e08248bce055908971047a2347",
			"ac78a1d46faf3bfbbdc5af5f053dc6dc9023ed78236bec1760dadfd0b2603760",
			"f9c84dc0ac31571507993df94da1b3d28684a12ad14e67d0a068aba5c53019fc",
			"b1fe79d1dec9bc108df69f6612c72812755751f21ecc5af99663b30be8b9081f",
			"81f1512b63ab5fb5c1711a4ec83d379c420574aedffa8c3368e1c3989a3a0084",
			"97f45142597c473a4b0e9a12d64561133ad9e1155fe5a9807fe6af8a93557818",
			"3f44f6a5a92cde816635dfc12ade70539871078d2ff097278be2a555c9859cd0",
			"0000000000000000000000000000000000000000000000000000000000000000",
			"1111111111111111111111111111111111111111111111111111111111111111",
		];
		let blinded_pubkeys = vec![
			"1fc1fa4465bd9d4956fdbdc9d3acb3c7019bb8d5606b951c2e1dfe0b42eaeb41",
			"1cbbd4a88ce8f165447f159d9f628ada18674158c4f7c5ead44ce8eb0fa6eb7e",
			"c5419ad133ffde7e0ac882055d942f582054132b092de377d587435722deb028",
			"3e08d0dc291066272e313014bfac4d39ad84aa93c038478a58011f431648105f",
			"59381f06acb6bf1389ba305f70874eed3e0f2ab57cdb7bc69ed59a9b8899ff4d",
			"2b946a484344eb1c17c89dd8b04196a84f3b7222c876a07a4cece85f676f87d9",
			"c6b585129b135f8769df2eba987e76e089e80ba3a2a6729134d3b28008ac098e",
			"0eefdc795b59cabbc194c6174e34ba9451e8355108520554ec285acabebb34ac",
			"312404d06a0a9de489904b18d5233e83a50b225977fa8734f2c897a73c067952",
			"952a908a4a9e0e5176a2549f8f328955aca6817a9fdc59e3acec5dec50838108",
		];

		for i in 0..pubkeys.len() {
			let pk =
				crate::ed25519::PublicKey::from_bytes(&hex::decode(pubkeys[i]).unwrap()).unwrap();

			let blinded_pk = blind_pubkey(&pk, hex::decode(params[i]).unwrap().try_into().unwrap());

			assert_eq!(
				hex::encode(blinded_pk.unwrap().to_bytes()),
				blinded_pubkeys[i]
			);
		}
	}
}
