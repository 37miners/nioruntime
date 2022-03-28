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

#[cfg(any(
	target_os = "macos",
	target_os = "dragonfly",
	target_os = "netbsd",
	target_os = "openbsd",
	target_os = "freebsd"
))]
pub use kqueue_sys;

#[cfg(windows)]
pub use wepoll_sys;
#[cfg(windows)]
pub use winapi;
#[cfg(windows)]
pub use ws2_32;

pub use arrayref;
pub use backtrace;
pub use base58;
pub use base64;
pub use bitvec;
pub use blake2;
pub use byte_tools;
pub use bytefmt;
pub use byteorder;
pub use bytes;
pub use caret;
pub use chrono;
pub use cipher;
pub use colored;
pub use digest;
pub use dirs;
pub use ed25519_dalek;
pub use errno;
pub use failure;
pub use fsutils;
pub use futures;
pub use generic_array;
pub use hex;
pub use hex_literal;
pub use hkdf;
pub use hmac;
pub use lazy_static;
pub use libc;
pub use native_tls;
pub use nix;
pub use num_enum;
pub use num_format;
pub use path_clean;
pub use portpicker;
pub use rand;
pub use rand_core;
pub use rustls;
pub use rustls_pemfile;
pub use serde;
pub use serde_derive;
pub use sha2;
pub use signature;
pub use subtle;
pub use typenum;
pub use webpki_roots;
pub use x509_signature;
pub use zeroize;

// we put this here because util has macros so it needs to be external to the crate
use std::collections::HashMap;
use std::sync::{Arc, RwLock};

lazy_static::lazy_static! {
	pub static ref LOCK_MONITOR: Arc<RwLock<HashMap<u128, LockInfo>>> =
		Arc::new(RwLock::new(HashMap::new()));
}

#[derive(Debug)]
pub struct LockInfo {
	pub bt: backtrace::Backtrace,
	pub time: u128,
	pub id: u128,
}
