// Copyright 2022 37 Miners, LLC
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

//! Tests for the macros

#[cfg(test)]
mod test {

	use nioruntime_err::Error;
	use nioruntime_log::*;
	use nioruntime_macros::Ser;
	use nioruntime_util::ser::{serialize, BinReader, Readable};
	use std::io::Cursor;

	debug!();

	#[derive(PartialEq, Debug, Ser)]
	struct TestSer {
		f1: u8,
		f2: u16,
		f3: u32,
		f4: u64,
		f5: u128,
		f6: i8,
		f7: i16,
		f8: i32,
		f9: i64,
		f10: i128,
	}

	#[test]
	fn test_ser() -> Result<(), Error> {
		info!("testing ser")?;

		let ser_in = TestSer {
			f1: 1,
			f2: 2,
			f3: 3,
			f4: 4,
			f5: 5,
			f6: -128,
			f7: -200,
			f8: 1,
			f9: 10,
			f10: 10,
		};
		let mut ser_vec = vec![];
		serialize(&mut ser_vec, &ser_in)?;

		let mut cursor = Cursor::new(ser_vec);
		cursor.set_position(0);
		let mut reader = BinReader::new(&mut cursor);

		let ser_out = TestSer::read(&mut reader)?;
		assert_eq!(ser_out, ser_in);
		Ok(())
	}
}
