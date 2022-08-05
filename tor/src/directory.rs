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

use crate::ed25519::Ed25519Identity;
use crate::ed25519::PublicKey;
use crate::keymanip::{build_hs_dir_index, build_hs_index};
use crate::rsa::RsaIdentity;
use crate::util::RngCompatExt;
use nioruntime_deps::rand::Rng;
use nioruntime_err::{Error, ErrorKind};
use nioruntime_log::*;
use nioruntime_util::bytes_eq;
use nioruntime_util::bytes_find;
use std::cmp::Ordering;
use std::collections::HashMap;
use std::collections::HashSet;
use std::fs;
use std::hash::Hash;
use std::hash::Hasher;

const BACK_N: &[u8] = &['\n' as u8];
const R_LINE: &[u8] = &['r' as u8, ' ' as u8];
const M_LINE: &[u8] = &['m' as u8, ' ' as u8, '2' as u8];
const ID_LINE: &[u8] = &['i' as u8, 'd' as u8, ' ' as u8];
const PR_LINE: &[u8] = &['p' as u8, 'r' as u8, ' ' as u8];
const S_LINE: &[u8] = &['s' as u8, ' ' as u8];
const HSDIR: &[u8] = "HSDir".as_bytes();
const DIRCACHE: &[u8] = "DirCache=2".as_bytes();
const GUARD: &[u8] = "Guard".as_bytes();
const EXIT: &[u8] = "Exit".as_bytes();
const BADEXIT: &[u8] = "BadExit".as_bytes();
const SHARED_RANDOM_LINE: &[u8] = "shared-rand-previous-value ".as_bytes();

debug!();

/// Tor Host. Holds information about a tor relay.
#[derive(Debug, Clone, Eq, PartialEq)]
pub struct TorRelay {
	pub nickname: String,
	pub microdesc: String,
	pub socket_addr: String,
	pub ntor_onion: Option<PublicKey>,
	pub ed25519_identity: Ed25519Identity,
	pub rsa_identity: RsaIdentity,
	pub is_exit: bool,
	pub is_guard: bool,
	pub is_hsdir: bool,
	pub is_dir_cache: bool,
}

impl Hash for TorRelay {
	// socket_addrs should be unique
	fn hash<H>(&self, hasher: &mut H)
	where
		H: Hasher,
	{
		self.socket_addr.hash(hasher)
	}
}

#[derive(Eq, PartialEq)]
struct RelaySorter {
	pub relay: TorRelay,
	pub v: [u8; 32],
}

impl PartialOrd for RelaySorter {
	fn partial_cmp(&self, rhs: &Self) -> Option<Ordering> {
		if self.v < rhs.v {
			Some(Ordering::Less)
		} else if self.v > rhs.v {
			Some(Ordering::Greater)
		} else {
			Some(Ordering::Equal)
		}
	}
}

impl Ord for RelaySorter {
	fn cmp(&self, rhs: &Self) -> Ordering {
		if self.v < rhs.v {
			Ordering::Less
		} else if self.v > rhs.v {
			Ordering::Greater
		} else {
			Ordering::Equal
		}
	}
}

/// Tor directory. Holds information about the tor directory.
pub struct TorDirectory {
	guards: Vec<TorRelay>,
	relays: Vec<TorRelay>,
	exits: Vec<TorRelay>,
	hs_dirs: Vec<TorRelay>,
	micro_map: HashMap<String, TorRelay>,
	srv: Vec<u8>,
}

impl TorDirectory {
	pub fn from_file(filename: String) -> Result<Self, Error> {
		let file_as_string = fs::read_to_string(filename)?;
		Self::from_bytes(file_as_string.as_bytes())
	}

	pub fn from_bytes(b: &[u8]) -> Result<Self, Error> {
		let len = b.len();
		let mut i = 0;
		let mut nickname = "".to_string();
		let mut rsa_identity = "".to_string();
		let mut socket_addr = "".to_string();
		let mut r_line_valid = false;
		let mut m_line_valid = false;
		let mut is_dir_cache = false;
		let mut is_hsdir = false;
		let mut is_exit = false;
		let mut is_guard = false;
		let mut is_bad_exit = false;
		let mut ed25519_identity = "".to_string();
		let mut relays = vec![];
		let mut exits = vec![];
		let mut guards = vec![];
		let mut hs_dirs = vec![];
		let mut micro_map = HashMap::new();

		// TODO: implemnet shared random disaster recovery here
		let mut srv = vec![0, 0, 0, 0, 0, 0, 0, 0];

		loop {
			if i >= len {
				break;
			}

			let x = match bytes_find(&b[i..], BACK_N) {
				Some(x) => x,
				None => len,
			};

			if x != len {
				// r line
				if i + 2 < len && bytes_eq(&b[i..i + 2], R_LINE) {
					let line = std::str::from_utf8(&b[i..i + x])?;
					let arr: Vec<&str> = line.trim().split_whitespace().collect();
					if arr.len() > 7 {
						nickname = arr[1].to_string();
						rsa_identity = arr[2].to_string();
						socket_addr = format!("{}:{}", arr[6], arr[7]);
						r_line_valid = true;
					} else {
						r_line_valid = false;
					}
				} else if i + 2 < len && bytes_eq(&b[i..i + 2], S_LINE) {
					is_exit = bytes_find(&b[i..i + x], EXIT).is_some();
					is_guard = bytes_find(&b[i..i + x], GUARD).is_some();
					is_bad_exit = bytes_find(&b[i..i + x], BADEXIT).is_some();
					is_hsdir = bytes_find(&b[i..i + x], HSDIR).is_some();
				} else if i + 3 < len && bytes_eq(&b[i..i + 3], ID_LINE) {
					let line = std::str::from_utf8(&b[i..i + x])?;
					let arr: Vec<&str> = line.trim().split_whitespace().collect();
					if arr.len() > 2 {
						ed25519_identity = arr[2].to_string();
						m_line_valid = true;
					} else {
						m_line_valid = false;
					}
				} else if i + 3 < len && bytes_eq(&b[i..i + 3], PR_LINE) {
					is_dir_cache = bytes_find(&b[i..i + x], DIRCACHE).is_some();
				} else if i + SHARED_RANDOM_LINE.len() + 1 < len
					&& bytes_eq(&b[i..i + SHARED_RANDOM_LINE.len()], SHARED_RANDOM_LINE)
				{
					let line = std::str::from_utf8(&b[i..i + x])?;
					let arr: Vec<&str> = line.trim().split_whitespace().collect();
					if arr.len() > 2 {
						srv = nioruntime_deps::base64::decode(arr[2])?;
					}
				} else if i + 3 < len && bytes_eq(&b[i..i + 3], M_LINE) {
					let line = std::str::from_utf8(&b[i..i + x])?;
					let arr: Vec<&str> = line.trim().split_whitespace().collect();
					if arr.len() > 2 {
						match arr[2].split('=').last() {
							Some(microdesc_value) => {
								let microdesc = microdesc_value.to_string();
								if r_line_valid && m_line_valid {
									match Ed25519Identity::from_base64(&ed25519_identity) {
										Some(ed25519_identity) => {
											match RsaIdentity::from_base64(&rsa_identity) {
												Some(rsa_identity) => {
													let socket_addr = socket_addr.clone();
													let nickname = nickname.clone();
													let tor_relay = TorRelay {
														nickname,
														microdesc: microdesc.clone(),
														socket_addr,
														ntor_onion: None,
														ed25519_identity,
														rsa_identity,
														is_exit,
														is_guard,
														is_hsdir,
														is_dir_cache,
													};

													if !is_bad_exit {
														relays.push(tor_relay.clone());
													}
													if is_exit && !is_bad_exit {
														exits.push(tor_relay.clone());
													}
													if is_guard && !is_bad_exit {
														guards.push(tor_relay.clone());
													}
													if is_hsdir {
														hs_dirs.push(tor_relay.clone());
													}
													micro_map.insert(microdesc, tor_relay);
													is_hsdir = false; // reset
													is_dir_cache = false; // reset
													is_exit = false; // reset
													is_guard = false; // reset
												}
												None => {}
											}
										}
										None => {}
									}
								}
							}
							None => {
								// something wrong look for the next r line.
							}
						}
					} else {
						// something wrong look for the next r line.
					}
				}
				i += x;
			}

			i += 1;
		}
		Ok(Self {
			guards,
			relays,
			exits,
			hs_dirs,
			micro_map,
			srv,
		})
	}

	pub fn hs_dirs_for(
		&self,
		blinded_pk: &crate::ed25519::PublicKey,
		time_period: u64,
		time_length: u64,
		n_replicas: u64,
		n_spread: u64,
	) -> Result<Vec<TorRelay>, Error> {
		let mut ret = vec![];
		let mut hs_sorters = vec![];
		let srv_value = self.srv_value()?;
		for r in &self.hs_dirs {
			let v = build_hs_dir_index(r.ed25519_identity, srv_value, time_period, time_length)?;
			hs_sorters.push(RelaySorter {
				v,
				relay: r.clone(),
			});
		}

		hs_sorters.sort();
		let mut ret_set = HashSet::new();

		for x in 1..n_replicas + 1 {
			let mut insert_count = 0;
			let hs_index = build_hs_index(x, blinded_pk, time_period, time_length)?;
			for hs_dir in &hs_sorters {
				if hs_dir.v > hs_index && insert_count < n_spread {
					match ret_set.get(&hs_dir.relay) {
						Some(_) => {} // skip over because we already have this one.
						None => {
							ret_set.insert(hs_dir.relay.clone());
							insert_count += 1;
						}
					}
				}
			}
		}
		for ret_i in ret_set {
			ret.push(ret_i);
		}
		Ok(ret)
	}

	pub fn srv_value(&self) -> Result<&[u8], Error> {
		Ok(&self.srv)
	}

	pub fn add_ntor(&mut self, microdesc: String, ntor_onion: PublicKey) -> Result<(), Error> {
		match self.micro_map.get_mut(&microdesc) {
			Some(relay) => {
				relay.ntor_onion = Some(ntor_onion);
			}
			None => {
				return Err(ErrorKind::Tor(format!(
					"microdesc: {} not found in directory",
					microdesc
				))
				.into())
			}
		}
		Ok(())
	}

	pub fn random_guard(&self) -> Option<&TorRelay> {
		let mut rng = nioruntime_deps::rand::thread_rng().rng_compat();
		let len = self.guards.len();
		if len == 0 {
			return None;
		}
		let r: usize = rng.gen();
		Some(&self.guards[r % len])
	}

	pub fn random_relay(&self) -> Option<&TorRelay> {
		let mut rng = nioruntime_deps::rand::thread_rng().rng_compat();
		let len = self.relays.len();
		if len == 0 {
			return None;
		}
		let r: usize = rng.gen();
		Some(&self.relays[r % len])
	}

	pub fn random_exit(&self) -> Option<&TorRelay> {
		let mut rng = nioruntime_deps::rand::thread_rng().rng_compat();
		let len = self.exits.len();
		if len == 0 {
			return None;
		}
		let r: usize = rng.gen();
		Some(&self.exits[r % len])
	}

	pub fn guards(&self) -> &Vec<TorRelay> {
		&self.guards
	}

	pub fn relays(&self) -> &Vec<TorRelay> {
		&self.relays
	}

	pub fn exits(&self) -> &Vec<TorRelay> {
		&self.exits
	}

	pub fn hsdirs(&self) -> &Vec<TorRelay> {
		&self.hs_dirs
	}
}

#[cfg(test)]
mod test {
	use crate::keymanip::blind_pubkey;
	use crate::keymanip::calc_param;
	use crate::TorDirectory;
	use nioruntime_deps::data_encoding::BASE32;
	use nioruntime_err::Error;
	use nioruntime_log::*;
	use std::time::Instant;

	debug!();

	#[test]
	fn test_dir_file() -> Result<(), Error> {
		let directory = TorDirectory::from_file("./test/resources/authority".to_string())?;
		let guard = directory.random_guard().unwrap();
		let relay = directory.random_relay().unwrap();
		let exit = directory.random_exit().unwrap();
		info!("g={:?},r={:?},e={:?}", guard, relay, exit)?;

		assert_eq!(directory.exits().len(), 1668);
		assert_eq!(directory.guards().len(), 3432);
		assert_eq!(directory.relays().len(), 7071);
		assert_eq!(directory.hsdirs().len(), 2844);

		Ok(())
	}

	#[test]
	fn test_hsdir_for() -> Result<(), Error> {
		let directory = TorDirectory::from_file("./test/resources/authority".to_string())?;
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

		let start = Instant::now();
		let time_in_minutes = std::time::SystemTime::now()
			.duration_since(std::time::UNIX_EPOCH)?
			.as_secs() / 60;
		// subtract 12 hours
		let time_in_minutes = time_in_minutes.saturating_sub(12 * 60);
		let time_period = time_in_minutes / 1440; // consensus, but where do we get it?
		let param = calc_param(pkbytes, None, time_period, 1440)?;
		let blinded_pk = blind_pubkey(&pk, param)?;
		info!(
			"blinded_pk b64={}",
			nioruntime_deps::base64::encode(blinded_pk)
		)?;
		let dirs = directory.hs_dirs_for(&blinded_pk, time_period, 1440, 2, 3)?;
		info!(
			"elapsed={}sec",
			start.elapsed().as_millis() as f64 / 1000 as f64
		)?;
		info!("timep={}", time_period)?;
		for dir in dirs {
			info!("{:?}", dir)?;
		}
		Ok(())
	}
}
