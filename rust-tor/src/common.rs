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

use crate::io::{Reader, Writer};
use nioruntime_err::Error;
use std::io::{Read, Write};

pub struct IoState {
	tls_bytes_to_write: usize,
	plaintext_bytes_to_read: usize,
	peer_has_closed: bool,
}

impl IoState {
	fn new(
		tls_bytes_to_write: usize,
		plaintext_bytes_to_read: usize,
		peer_has_closed: bool,
	) -> Self {
		Self {
			tls_bytes_to_write,
			plaintext_bytes_to_read,
			peer_has_closed,
		}
	}

	pub fn tls_bytes_to_write(&self) -> usize {
		self.tls_bytes_to_write
	}

	pub fn plaintext_bytes_to_read(&self) -> usize {
		self.plaintext_bytes_to_read
	}

	pub fn peer_has_closed(&self) -> bool {
		self.peer_has_closed
	}
}

pub trait TorCommon {
	fn reader(&mut self) -> Reader;
	fn writer(&mut self) -> Writer;
	fn process_new_packets(&mut self) -> Result<IoState, Error>;
	fn read_tls(&mut self, rd: &mut dyn Read) -> Result<usize, Error>;
	fn write_tls(&mut self, wr: &mut dyn Write) -> Result<usize, Error>;
}
