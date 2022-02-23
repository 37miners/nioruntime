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

use crate::common::{IoState, TorCommon};
use crate::config::TorServerConfig;
use crate::io::{Reader, Writer};
use nioruntime_err::Error;
use std::io::{Read, Write};

pub struct TorServer {}

impl TorServer {
	pub fn new(_config: TorServerConfig) -> Self {
		Self {}
	}

	pub fn start() -> Result<(), Error> {
		Ok(())
	}
}

impl TorCommon for TorServer {
	fn reader(&mut self) -> Reader {
		todo!()
	}

	fn writer(&mut self) -> Writer {
		todo!()
	}

	fn process_new_packets(&mut self) -> Result<IoState, Error> {
		todo!()
	}

	fn read_tls(&mut self, _rd: &mut dyn Read) -> Result<usize, Error> {
		todo!()
	}

	fn write_tls(&mut self, _wr: &mut dyn Write) -> Result<usize, Error> {
		todo!()
	}
}
