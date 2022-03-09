// Copyright (c) 2022, 37 Miners, LLC
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

//! Tests for static_hash with derive macros

#[cfg(test)]
mod test {

	use nioruntime_deps::rand;
	use nioruntime_derive::Serializable;
	use nioruntime_err::Error;
	use nioruntime_log::*;
	use nioruntime_util::{StaticHash, StaticHashConfig};

	debug!();

	#[derive(Debug, PartialEq, Serializable)]
	struct Elem {
		id: u64,
		name: [u8; 10],
		count: i128,
	}
	#[derive(Debug, PartialEq, Serializable)]
	struct Key {
		id: u128,
		data: [u8; 20],
	}

	#[test]
	fn test_static_hash() -> Result<(), Error> {
		let mut static_hash = StaticHash::new(StaticHashConfig {
			key_len: 36,
			entry_len: 34,
			..StaticHashConfig::default()
		})?;

		let k1 = Key {
			id: 101,
			data: rand::random(),
		};
		let v1 = Elem {
			id: 1,
			name: rand::random(),
			count: 1,
		};

		let k2 = Key {
			id: 102,
			data: rand::random(),
		};
		let v2 = Elem {
			id: 1,
			name: rand::random(),
			count: 2,
		};

		let k3 = Key {
			id: 103,
			data: rand::random(),
		};
		let v3 = Elem {
			id: 1,
			name: rand::random(),
			count: 3,
		};

		let k4 = Key {
			id: 104,
			data: rand::random(),
		};
		let v4 = Elem {
			id: 1,
			name: rand::random(),
			count: 4,
		};

		let k5 = Key {
			id: 105,
			data: rand::random(),
		};
		let v5 = Elem {
			id: 1,
			name: rand::random(),
			count: 5,
		};

		static_hash.insert(&k1, &v1)?;
		static_hash.insert(&k2, &v2)?;
		static_hash.insert(&k3, &v3)?;
		static_hash.insert(&k4, &v4)?;
		static_hash.insert(&k5, &v5)?;

		let v_out: Option<Elem> = static_hash.get(&k1);
		assert_eq!(v_out, Some(v1));

		let v_out: Option<Elem> = static_hash.get(&k2);
		assert_eq!(v_out, Some(v2));

		let v_out: Option<Elem> = static_hash.get(&k3);
		assert_eq!(v_out, Some(v3));

		let v_out: Option<Elem> = static_hash.get(&k4);
		assert_eq!(v_out, Some(v4));

		let v_out: Option<Elem> = static_hash.get(&k5);
		assert_eq!(v_out, Some(v5));

		for (k, v) in static_hash.iter() {
			info!("k={:?}, v={:?}", k, v)?;
		}

		Ok(())
	}
}
