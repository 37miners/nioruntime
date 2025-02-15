// Copyright 2018 The Grin Developers
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

use nioruntime_err::{Error, ErrorKind};
use secp256k1zkp::rand::thread_rng;
use std::sync::{Arc, Mutex};

#[macro_use]
extern crate serde_derive;
#[macro_use]
extern crate log;
pub use secp256k1zkp as secp;

pub mod config;
pub mod hex;
pub mod ov3;
pub mod process;

lazy_static::lazy_static! {
		/// Static reference to secp instance
		pub static ref SECP256K1:Arc<Mutex<secp::Secp256k1>>
				= Arc::new(Mutex::new(secp::Secp256k1::with_caps(secp::ContextFlag::Commit)));
}

/// Returns the static instance, but calls randomize on it as well
/// (Recommended to avoid side channel attacks
pub fn static_secp_instance() -> Arc<Mutex<secp::Secp256k1>> {
	let mut secp_inst = SECP256K1.lock().unwrap();
	secp_inst.randomize(&mut thread_rng());
	SECP256K1.clone()
}
