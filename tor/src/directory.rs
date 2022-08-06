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
use crate::handshake::ntor::NtorPublicKey;
use crate::keymanip::{build_hs_dir_index, build_hs_index};
use crate::rsa::RsaIdentity;
use crate::util::RngCompatExt;
use nioruntime_deps::base64;
use nioruntime_deps::chrono::NaiveDateTime;
use nioruntime_deps::chrono::Utc;
use nioruntime_deps::rand::Rng;
use nioruntime_deps::x25519_dalek::PublicKey as DalekPublicKey;
use nioruntime_err::{Error, ErrorKind};
use nioruntime_log::*;
use nioruntime_util::bytes_eq;
use nioruntime_util::bytes_find;
use nioruntime_util::ser::Serializable;
use std::cmp::Ordering;
use std::collections::HashMap;
use std::collections::HashSet;
use std::convert::TryInto;
use std::fs;
use std::hash::Hash;
use std::hash::Hasher;

const BACK_N: &[u8] = &['\n' as u8];
const R_LINE: &[u8] = &['r' as u8, ' ' as u8];
const M_LINE: &[u8] = &['m' as u8, ' ' as u8, '2' as u8];
const ID_LINE: &[u8] = &['i' as u8, 'd' as u8, ' ' as u8];
const PR_LINE: &[u8] = &['p' as u8, 'r' as u8, ' ' as u8];
const S_LINE: &[u8] = &['s' as u8, ' ' as u8];
const VALID_UNTIL_LINE: &[u8] = b"valid-until ";
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
	pub ntor_onion: Option<DalekPublicKey>,
	pub ed25519_identity: Ed25519Identity,
	pub rsa_identity: RsaIdentity,
	pub is_exit: bool,
	pub is_guard: bool,
	pub is_hsdir: bool,
	pub is_dir_cache: bool,
	pub is_bad_exit: bool,
}

impl PartialOrd for TorRelay {
	fn partial_cmp(&self, other: &TorRelay) -> std::option::Option<std::cmp::Ordering> {
		if self.rsa_identity < other.rsa_identity {
			Some(Ordering::Less)
		} else if self.rsa_identity > other.rsa_identity {
			Some(Ordering::Greater)
		} else {
			Some(Ordering::Equal)
		}
	}
}

impl Ord for TorRelay {
	fn cmp(&self, other: &TorRelay) -> std::cmp::Ordering {
		if self.rsa_identity < other.rsa_identity {
			Ordering::Less
		} else if self.rsa_identity > other.rsa_identity {
			Ordering::Greater
		} else {
			Ordering::Equal
		}
	}
}

impl Serializable for TorRelay {
	fn read<R>(reader: &mut R) -> Result<Self, Error>
	where
		R: nioruntime_util::ser::Reader,
	{
		let nickname = String::read(reader)?;
		let microdesc = String::read(reader)?;
		let socket_addr = String::read(reader)?;
		let ntor_onion = match reader.read_u8()? != 0 {
			true => {
				let mut ntor_onion = [0u8; 32];
				for i in 0..32 {
					ntor_onion[i] = reader.read_u8()?;
				}
				Some(DalekPublicKey::from(ntor_onion))
			}
			false => None,
		};
		let mut ed25519_identity = [0u8; 32];
		for i in 0..32 {
			ed25519_identity[i] = reader.read_u8()?;
		}
		let ed25519_identity = match Ed25519Identity::from_bytes(&ed25519_identity) {
			Some(x) => x,
			None => {
				return Err(
					ErrorKind::CorruptedData("Expected valid ed25519_identity key".into()).into(),
				)
			}
		};

		let mut rsa_identity = [0u8; 20];
		for i in 0..20 {
			rsa_identity[i] = reader.read_u8()?;
		}
		let rsa_identity = match RsaIdentity::from_bytes(&rsa_identity) {
			Some(x) => x,
			None => {
				return Err(
					ErrorKind::CorruptedData("Expected valid rsa_identity key".into()).into(),
				)
			}
		};
		let is_exit = reader.read_u8()? != 0;
		let is_guard = reader.read_u8()? != 0;
		let is_hsdir = reader.read_u8()? != 0;
		let is_dir_cache = reader.read_u8()? != 0;
		let is_bad_exit = reader.read_u8()? != 0;

		Ok(Self {
			nickname,
			microdesc,
			socket_addr,
			ntor_onion,
			ed25519_identity,
			rsa_identity,
			is_exit,
			is_guard,
			is_hsdir,
			is_dir_cache,
			is_bad_exit,
		})
	}
	fn write<W>(&self, writer: &mut W) -> Result<(), Error>
	where
		W: nioruntime_util::ser::Writer,
	{
		String::write(&self.nickname, writer)?;
		String::write(&self.microdesc, writer)?;
		String::write(&self.socket_addr, writer)?;
		match self.ntor_onion {
			Some(ntor_onion) => {
				writer.write_u8(1)?;
				let ntor_bytes = ntor_onion.to_bytes();
				for b in ntor_bytes {
					writer.write_u8(b)?;
				}
			}
			None => {
				writer.write_u8(0)?;
			}
		}

		for b in self.ed25519_identity.as_bytes() {
			writer.write_u8(*b)?;
		}

		for b in self.rsa_identity.as_bytes() {
			writer.write_u8(*b)?;
		}

		if self.is_exit {
			writer.write_u8(1)?;
		} else {
			writer.write_u8(0)?;
		}
		if self.is_guard {
			writer.write_u8(1)?;
		} else {
			writer.write_u8(0)?;
		}
		if self.is_hsdir {
			writer.write_u8(1)?;
		} else {
			writer.write_u8(0)?;
		}
		if self.is_dir_cache {
			writer.write_u8(1)?;
		} else {
			writer.write_u8(0)?;
		}
		if self.is_bad_exit {
			writer.write_u8(1)?;
		} else {
			writer.write_u8(0)?;
		}

		Ok(())
	}
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
#[derive(Debug, PartialEq)]
pub struct TorDirectory {
	guards: Vec<TorRelay>,
	relays: Vec<TorRelay>,
	exits: Vec<TorRelay>,
	hs_dirs: Vec<TorRelay>,
	micro_map: HashMap<String, TorRelay>,
	ed25519_id_map: HashMap<String, TorRelay>,
	srv: Vec<u8>,
	valid_until: i64,
}

impl Serializable for TorDirectory {
	fn read<R>(reader: &mut R) -> Result<Self, Error>
	where
		R: nioruntime_util::ser::Reader,
	{
		let mut guards = vec![];
		let mut relays = vec![];
		let mut exits = vec![];
		let mut hs_dirs = vec![];
		let mut micro_map = HashMap::new();
		let mut ed25519_id_map = HashMap::new();
		let mut srv = vec![];
		srv.resize(32, 0u8);

		let valid_until = reader.read_i64()?;
		for i in 0..32 {
			srv[i] = reader.read_u8()?;
		}

		let count = reader.read_u64()?;
		for _i in 0..count {
			let r = TorRelay::read(reader)?;
			let relay = r.clone();
			micro_map.insert(r.microdesc, relay.clone());

			ed25519_id_map.insert(base64::encode(r.ed25519_identity.as_bytes()), relay.clone());

			if !relay.is_bad_exit {
				relays.push(relay.clone());
			}
			if relay.is_exit && !relay.is_bad_exit {
				exits.push(relay.clone());
			}
			if relay.is_guard && !relay.is_bad_exit {
				guards.push(relay.clone());
			}
			if relay.is_hsdir {
				hs_dirs.push(relay.clone());
			}
		}

		Ok(Self {
			valid_until,
			guards,
			relays,
			exits,
			hs_dirs,
			micro_map,
			ed25519_id_map,
			srv,
		})
	}

	fn write<W>(&self, writer: &mut W) -> Result<(), Error>
	where
		W: nioruntime_util::ser::Writer,
	{
		writer.write_i64(self.valid_until)?;
		for i in 0..32 {
			writer.write_u8(self.srv[i])?;
		}
		writer.write_u64(self.micro_map.len().try_into()?)?;
		for (_k, v) in &self.micro_map {
			TorRelay::write(&v, writer)?;
		}

		Ok(())
	}
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
		let mut valid_until = Utc::now().naive_utc().timestamp();
		let mut ed25519_id_map = HashMap::new();

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
				} else if i + VALID_UNTIL_LINE.len() + 1 < len
					&& bytes_eq(&b[i..i + VALID_UNTIL_LINE.len()], VALID_UNTIL_LINE)
				{
					let line = std::str::from_utf8(&b[i..i + x])?;
					let arr: Vec<&str> = line.trim().split_whitespace().collect();
					valid_until = NaiveDateTime::parse_from_str(
						&format!("{} {}", arr[1], arr[2])[..],
						"%Y-%m-%d %H:%M:%S",
					)
					.map_err(|e| {
						let error: Error = ErrorKind::IllegalArgument(format!(
							"date_time '{}' could not be parsed: {}",
							format!("{} {}", arr[1], arr[2]),
							e
						))
						.into();
						error
					})?
					.timestamp();
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
														is_bad_exit,
													};
													micro_map.insert(microdesc, tor_relay.clone());
													ed25519_id_map.insert(
														base64::encode(ed25519_identity.as_bytes()),
														tor_relay.clone(),
													);

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

													is_hsdir = false; // reset
													is_dir_cache = false; // reset
													is_exit = false; // reset
													is_guard = false; // reset
													is_bad_exit = false; // reset
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
			ed25519_id_map,
			srv,
			valid_until,
		})
	}

	pub fn valid_until(&self) -> i64 {
		self.valid_until
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

	pub fn get_ed25519_id_map(&self) -> &HashMap<String, TorRelay> {
		&self.ed25519_id_map
	}

	pub fn srv_value(&self) -> Result<&[u8], Error> {
		Ok(&self.srv)
	}

	pub fn unknown_ntor_relays(&self) -> Vec<TorRelay> {
		let mut ret = vec![];

		for (_k, v) in &self.micro_map {
			if v.ntor_onion.is_none() {
				ret.push(v.to_owned());
			}
		}

		ret
	}

	pub fn repopulate_ntor(&mut self) -> Result<(), Error> {
		let mut relays = vec![];
		let mut guards = vec![];
		let mut hs_dirs = vec![];
		let mut exits = vec![];
		for (_k, v) in &self.micro_map {
			if !v.is_bad_exit {
				relays.push(v.clone());
			}
			if v.is_exit && !v.is_bad_exit {
				exits.push(v.clone());
			}
			if v.is_guard && !v.is_bad_exit {
				guards.push(v.clone());
			}
			if v.is_hsdir {
				hs_dirs.push(v.clone());
			}
		}

		self.guards = guards;
		self.hs_dirs = hs_dirs;
		self.exits = exits;
		self.relays = relays;
		Ok(())
	}

	pub fn add_ntor(
		&mut self,
		microdesc: &String,
		ntor_onion_pubkey_b64: &str,
	) -> Result<(), Error> {
		let ntor_onion_pubkey = match NtorPublicKey::from_base64(ntor_onion_pubkey_b64) {
			Some(id) => id,
			None => return Err(ErrorKind::Tor("invalid ntor pubkey base64".to_string()).into()),
		};
		match self.micro_map.get_mut(microdesc) {
			Some(relay) => {
				relay.ntor_onion = Some(ntor_onion_pubkey);
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
	use crate::directory::TorRelay;
	use crate::keymanip::blind_pubkey;
	use crate::keymanip::calc_param;
	use crate::TorDirectory;
	use nioruntime_deps::chrono::Utc;
	use nioruntime_deps::data_encoding::BASE32;
	use nioruntime_err::Error;
	use nioruntime_log::*;
	use nioruntime_util::ser::serialize;
	use nioruntime_util::ser::BinReader;
	use nioruntime_util::ser::Serializable;
	use std::io::Cursor;
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

	#[test]
	fn test_serializable() -> Result<(), Error> {
		let mut directory = TorDirectory::from_file("./test/resources/authority".to_string())?;

		info!("valid until = {}", directory.valid_until)?;
		info!("now = {}", Utc::now().naive_utc().timestamp())?;
		let guard = directory.random_guard().unwrap();
		info!("guard={:?}", guard)?;

		let exit = loop {
			let ret = directory.random_exit().unwrap();
			if ret != guard {
				break ret;
			}
		};

		info!("exit={:?}", exit)?;

		assert!(guard != exit);

		let mut ser_vec = vec![];
		serialize(&mut ser_vec, guard)?;
		let mut cursor = Cursor::new(ser_vec);
		cursor.set_position(0);
		let mut reader = BinReader::new(&mut cursor);
		let ser_out = TorRelay::read(&mut reader)?;

		info!("serout(guard)={:?}", ser_out)?;

		assert_eq!(&ser_out, guard);

		let mut ser_vec = vec![];
		serialize(&mut ser_vec, exit)?;
		let mut cursor = Cursor::new(ser_vec);
		cursor.set_position(0);
		let mut reader = BinReader::new(&mut cursor);
		let ser_out = TorRelay::read(&mut reader)?;

		info!("serout(exit)={:?}", ser_out)?;
		assert_eq!(&ser_out, exit);

		let mut ser_vec = vec![];
		serialize(&mut ser_vec, &directory)?;
		let mut cursor = Cursor::new(ser_vec);
		cursor.set_position(0);
		let mut reader = BinReader::new(&mut cursor);
		let mut ser_out = TorDirectory::read(&mut reader)?;
		ser_out.relays.sort();
		directory.relays.sort();
		assert_eq!(ser_out.relays, directory.relays);

		ser_out.guards.sort();
		directory.guards.sort();
		assert_eq!(ser_out.guards, directory.guards);

		ser_out.hs_dirs.sort();
		directory.hs_dirs.sort();
		assert_eq!(ser_out.hs_dirs, directory.hs_dirs);

		ser_out.exits.sort();
		directory.exits.sort();
		assert_eq!(ser_out.exits, directory.exits);

		assert_eq!(ser_out.srv, directory.srv);

		assert_eq!(ser_out.ed25519_id_map.len(), directory.ed25519_id_map.len());
		assert_eq!(ser_out.micro_map.len(), directory.micro_map.len());
		assert_eq!(ser_out.valid_until, directory.valid_until);
		assert_eq!(ser_out, directory);

		Ok(())
	}

	#[test]
	fn test_repopulate_ntor() -> Result<(), Error> {
		let mut directory = TorDirectory::from_file("./test/resources/authority".to_string())?;
		let mut found = false;
		let relays = directory.relays();
		for relay in relays {
			if relay.microdesc == "JjnpeYaHvjK3++17y0uNCJQcsuc98aVRPXVmxyvv/ZI" {
				info!("relay = {:?}", relay)?;
				found = true;
				assert!(relay.ntor_onion.is_none());
			}
		}

		assert!(found);
		directory.add_ntor(
			&"JjnpeYaHvjK3++17y0uNCJQcsuc98aVRPXVmxyvv/ZI".to_string(),
			"z/k+9h73AUcYzRSOuke9Ee+pD4vx7HUXSq1w7hFD6no=",
		)?;
		directory.add_ntor(
			&"tUd+zv64LEHmcM1/ovk7fYjh6Ke9mWrswx5dnQMcR+A".to_string(),
			"dtDQ497XG1PRbtodI2gdQVKB8f2+SyrPBpWTjmRPn24=",
		)?;
		directory.repopulate_ntor()?;

		let relays = directory.relays();
		let mut found = false;
		for relay in relays {
			if relay.microdesc == "JjnpeYaHvjK3++17y0uNCJQcsuc98aVRPXVmxyvv/ZI" {
				info!("relay = {:?}", relay)?;
				found = true;
				assert!(relay.ntor_onion.is_some());
			}
		}
		assert!(found);

		let mut found = false;
		let hs_dirs = directory.hs_dirs.clone();
		for hs_dir in hs_dirs {
			if hs_dir.microdesc == "JjnpeYaHvjK3++17y0uNCJQcsuc98aVRPXVmxyvv/ZI" {
				info!("hs_dir = {:?}", hs_dir)?;
				found = true;
				assert!(hs_dir.ntor_onion.is_some());
			}
		}
		assert!(found);

		let mut found = false;
		let guards = directory.guards();
		for guard in guards {
			if guard.microdesc == "tUd+zv64LEHmcM1/ovk7fYjh6Ke9mWrswx5dnQMcR+A" {
				info!("guard = {:?}", guard)?;
				found = true;
				assert!(guard.ntor_onion.is_some());
			}
		}
		assert!(found);
		Ok(())
	}
}
