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
	use nioruntime_macros::Serializable;
	use nioruntime_util::ser::{serialize, BinReader, Serializable};
	use std::io::Cursor;

	debug!();

	macro_rules! test_ser {
		($ser_in:expr, $ser_fn:expr) => {{
			debug!("Checking $ser_in={:?}", $ser_in)?;
			let mut buf = vec![];
			serialize(&mut buf, &$ser_in)?;
			debug!("ser = {:?}", buf)?;
			let mut cursor = Cursor::new(buf);
			cursor.set_position(0);
			let mut reader = BinReader::new(&mut cursor);
			let ser_out = $ser_fn(&mut reader)?;
			debug!("ser_in='{:?}',ser_out='{:?}'", $ser_in, ser_out)?;
			assert_eq!(ser_out, $ser_in);
		}};
	}

	#[derive(PartialEq, Debug, Serializable)]
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

	#[derive(PartialEq, Debug, Serializable)]
	struct TestSer2 {
		f1: u8,
	}

	#[derive(PartialEq, Debug, Serializable)]
	struct TestSer3 {
		f1: i8,
		t2: TestSer2,
	}

	#[derive(PartialEq, Debug, Serializable)]
	struct TestSer4 {
		pub f1: i8,
		t2: Vec<u8>,
	}

	#[derive(PartialEq, Debug, Serializable)]
	pub struct TestSer5 {
		f1: i128,
		arr: Vec<i128>,
	}

	#[derive(PartialEq, Debug, Serializable)]
	pub struct TestSer6 {
		f1: u64,
		arr: Vec<TestSer2>,
	}

	#[derive(PartialEq, Debug, Serializable)]
	struct TestSer7 {
		z0: Vec<u32>,
		z1: u8,
		f1: Option<u8>,
		f2: Option<u32>,
	}

	#[derive(PartialEq, Debug, Serializable)]
	struct TestSer8 {
		b1: u8,
		b2: u8,
	}

	#[derive(PartialEq, Debug, Serializable)]
	struct TestSer9 {
		x: Option<Vec<u8>>,
	}

	#[derive(PartialEq, Debug, Serializable)]
	pub struct TestSer10 {
		x: Vec<Option<u8>>,
	}

	#[derive(PartialEq, Debug, Serializable)]
	struct TestSer11 {
		x: Vec<Vec<u128>>,
		y: Option<Option<u8>>,
	}

	#[derive(PartialEq, Debug, Serializable)]
	struct TestSer12 {
		x: Vec<Option<Vec<Option<Vec<Option<Vec<Vec<TestSer8>>>>>>>>,
		y: TestSer8,
	}

	#[derive(PartialEq, Debug, Serializable)]
	struct TestSer13(u8);

	#[derive(PartialEq, Debug, Serializable)]
	struct TestSer14((u8, u64));

	#[derive(PartialEq, Debug, Serializable)]
	struct TestSer15 {
		x: [u8; 4],
	}

	#[derive(PartialEq, Debug, Serializable)]
	struct TestSer16 {
		x: bool,
		y: u8,
	}

	#[derive(PartialEq, Debug, Serializable)]
	struct TestSer17 {
		x: [bool; 3],
	}

	#[test]
	fn test_ser() -> Result<(), Error> {
		info!("testing ser")?;
		test_ser!(
			TestSer {
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
			},
			TestSer::read
		);

		test_ser!(TestSer2 { f1: 8 }, TestSer2::read);
		test_ser!(
			TestSer3 {
				f1: -8,
				t2: TestSer2 { f1: 0 },
			},
			TestSer3::read
		);

		test_ser!(
			TestSer4 {
				f1: -1,
				t2: vec![0, 1, 2, 3],
			},
			TestSer4::read
		);

		test_ser!(
			TestSer5 {
				f1: 1234,
				arr: vec![9, 10, 11],
			},
			TestSer5::read
		);
		test_ser!(
			TestSer6 {
				f1: 1,
				arr: vec![TestSer2 { f1: 2 }]
			},
			TestSer6::read
		);

		test_ser!(
			TestSer7 {
				z0: vec![0, 7],
				z1: 0,
				f1: Some(10),
				f2: None,
			},
			TestSer7::read
		);

		test_ser!(TestSer8 { b2: 1, b1: 2 }, TestSer8::read);

		test_ser!(
			TestSer9 {
				x: Some(vec![0, 1, 2]),
			},
			TestSer9::read
		);

		test_ser!(TestSer10 { x: vec!(Some(1)) }, TestSer10::read);

		test_ser!(
			TestSer10 {
				x: vec!(Some(1), None, Some(2))
			},
			TestSer10::read
		);

		test_ser!(
			TestSer11 {
				x: vec![vec![1, 2, 3], vec![4, 5, 6]],
				y: Some(Some(1))
			},
			TestSer11::read
		);

		test_ser!(
			TestSer11 {
				x: vec![vec![1, 2, 3], vec![4, 5, 6]],
				y: Some(None)
			},
			TestSer11::read
		);

		test_ser!(
			TestSer11 {
				x: vec![vec![1, 2, 3], vec![4, 5, 6]],
				y: None
			},
			TestSer11::read
		);

		test_ser!(
			TestSer12 {
				x: vec![Some(vec![Some(vec![Some(vec![
					vec![TestSer8 { b1: 0, b2: 2 }, TestSer8 { b1: 2, b2: 3 }],
					vec![],
					vec![TestSer8 { b1: 4, b2: 5 }]
				])])])],
				y: TestSer8 { b1: 9, b2: 10 },
			},
			TestSer12::read
		);

		test_ser!(TestSer13(1), TestSer13::read);

		test_ser!(TestSer13(10), TestSer13::read);

		test_ser!(TestSer14((1, 10000)), TestSer14::read);

		test_ser!(TestSer15 { x: [1, 2, 3, 4] }, TestSer15::read);

		test_ser!(TestSer16 { x: false, y: 1 }, TestSer16::read);

		test_ser!(
			TestSer17 {
				x: [true, false, true],
			},
			TestSer17::read
		);

		Ok(())
	}
}
