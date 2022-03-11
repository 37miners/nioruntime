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

use nioruntime_err::Error;
use std::collections::HashMap;

pub struct HttpCache {
	map: HashMap<String, Vec<u8>>,
}

impl HttpCache {
	pub fn new() -> Self {
		Self {
			map: HashMap::new(),
		}
	}

	pub fn get_file_chunk(
		&self,
		file: &String,
		_chunk_num: u32,
	) -> Result<Option<&Vec<u8>>, Error> {
		Ok(self.map.get(file))
	}

	pub fn set_file_chunk(
		&mut self,
		file: String,
		_chunk_num: u32,
		value: Vec<u8>,
	) -> Result<(), Error> {
		self.map.insert(file, value);
		Ok(())
	}
}
