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

//! Wrapper around the getrandom crate which uses urandom for entropy on linux and
//! equivelent on other platforms. https://docs.rs/getrandom/latest/getrandom/index.html

use nioruntime_deps::getrandom::getrandom;
use nioruntime_err::Error;

pub fn get_rand_u128() -> Result<u128, Error> {
	let mut b = [0u8; 16];
	getrandom(&mut b)?;
	Ok(u128::from_be_bytes(b))
}
