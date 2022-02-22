// Copyright 2021 37 Miners, LLC
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

use crate::config::TorClientConfig;
use crate::io::{Reader, Writer};
use nioruntime_err::Error;
use std::io::{Read, Write};

pub struct TorClient {}

impl TorClient {
	pub fn new(config: TorClientConfig) -> Self {
		Self {}
	}

	pub fn start() -> Result<(), Error> {
		Ok(())
	}
}
