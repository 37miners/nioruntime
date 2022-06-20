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

use nioruntime_err::{Error, ErrorKind};

const COLON_SPACE: &[u8] = ": ".as_bytes();
const BACK_R: &[u8] = "\r".as_bytes();

pub fn bytes_eq(bytes1: &[u8], bytes2: &[u8]) -> bool {
	let b1_len = bytes1.len();
	let b2_len = bytes2.len();
	if b1_len != b2_len {
		false
	} else {
		let mut ret = true;
		for i in 0..b1_len {
			if bytes1[i] != bytes2[i] {
				ret = false;
				break;
			}
		}

		ret
	}
}

pub fn bytes_find(bytes: &[u8], pattern: &[u8]) -> Option<usize> {
	let pattern_len = pattern.len();
	let bytes_len = bytes.len();
	if pattern_len > bytes_len {
		None
	} else {
		for i in 0..(bytes_len - pattern_len) + 1 {
			let mut is_equal = true;
			for j in 0..pattern_len {
				if bytes[i + j] != pattern[j] {
					is_equal = false;
					break;
				}
			}

			if is_equal {
				return Some(i);
			}
		}
		None
	}
}

pub fn bytes_to_usize_hex(bytes: &[u8]) -> Result<usize, Error> {
	let mut bytes_len = bytes.len();
	let mut ret = 0;
	let mut mul = 1;
	let mut itt = 0;
	for _ in 0..(bytes_len.saturating_sub(1)) {
		mul *= 16;
	}
	loop {
		if bytes_len == 0 {
			break;
		}
		bytes_len -= 1;

		if !((bytes[itt] >= '0' as u8 && bytes[itt] <= '9' as u8)
			|| (bytes[itt] >= 'a' as u8 && bytes[itt] <= 'f' as u8))
		{
			return Err(ErrorKind::UnexpectedData(format!(
				"Illegal character in number: '{}'",
				bytes[itt] as char,
			))
			.into());
		}
		if bytes[itt] >= 'a' as u8 {
			ret += mul * (10 + bytes[itt] as usize - ('a' as usize));
		} else {
			ret += mul * (bytes[itt] as usize - ('0' as usize));
		}

		itt += 1;
		mul /= 16;
	}

	Ok(ret)
}

pub fn bytes_to_usize(bytes: &[u8]) -> Result<usize, Error> {
	let mut bytes_len = bytes.len();
	let mut ret = 0;
	let mut mul = 1;
	let mut itt = 0;
	for _ in 0..(bytes_len.saturating_sub(1)) {
		mul *= 10;
	}

	loop {
		if bytes_len == 0 {
			break;
		}
		bytes_len -= 1;

		if bytes[itt] < '0' as u8 || bytes[itt] > '9' as u8 {
			return Err(ErrorKind::UnexpectedData(format!(
				"Illegal character in number: {}",
				bytes[itt],
			))
			.into());
		}
		ret += mul * (bytes[itt] as usize - ('0' as usize));

		itt += 1;
		mul /= 10;
	}

	Ok(ret)
}

pub fn bytes_parse_number_hex(bytes: &[u8]) -> Option<usize> {
	let end = bytes_find(bytes, BACK_R);
	match end {
		Some(end) => match bytes_to_usize_hex(&bytes[0..end]) {
			Ok(v) => Some(v),
			Err(_e) => None,
		},
		None => None,
	}
}

pub fn bytes_parse_number(bytes: &[u8]) -> Option<usize> {
	let end = bytes_find(bytes, BACK_R);
	match end {
		Some(end) => match bytes_to_usize(&bytes[0..end]) {
			Ok(v) => Some(v),
			Err(_e) => None,
		},
		None => None,
	}
}

pub fn bytes_parse_number_header(bytes: &[u8], index: usize) -> Option<usize> {
	let start = bytes_find(&bytes[index..], COLON_SPACE);
	match start {
		Some(start) => bytes_parse_number(&bytes[index + start + 2..]),
		None => None,
	}
}

#[cfg(test)]
mod test {
	use crate::byte_utils::{
		bytes_find, bytes_parse_number, bytes_parse_number_header, bytes_parse_number_hex,
		bytes_to_usize, bytes_to_usize_hex,
	};
	use nioruntime_err::Error;

	#[test]
	fn test_bytes_find() -> Result<(), Error> {
		assert!(bytes_find("abc".as_bytes(), "def".as_bytes()).is_none());
		assert_eq!(bytes_find("abc".as_bytes(), "abc".as_bytes()), Some(0));
		assert!(bytes_find("abc".as_bytes(), "abcd".as_bytes()).is_none());
		assert_eq!(bytes_find("abcd".as_bytes(), "abc".as_bytes()), Some(0));
		assert_eq!(bytes_find("abcd".as_bytes(), "bcd".as_bytes()), Some(1));
		assert_eq!(bytes_find("abcde".as_bytes(), "bcd".as_bytes()), Some(1));
		Ok(())
	}

	#[test]
	fn test_bytes_to_usize_hex() -> Result<(), Error> {
		assert_eq!(bytes_to_usize_hex(b"012").unwrap(), 18);
		assert!(bytes_to_usize_hex(b"012g").is_err());
		assert_eq!(bytes_to_usize_hex(b"012f").unwrap(), 303);
		assert_eq!(bytes_to_usize_hex(b"f").unwrap(), 15);
		assert_eq!(bytes_to_usize_hex(b"e").unwrap(), 14);
		assert_eq!(bytes_to_usize_hex(b"ff").unwrap(), 255);
		assert!(bytes_parse_number_hex(b"012g").is_none());
		assert!(bytes_parse_number_hex(b"012\r").is_some());
		Ok(())
	}

	#[test]
	fn test_other() -> Result<(), Error> {
		assert!(bytes_to_usize(b"012a").is_err());
		assert_eq!(bytes_to_usize(b"012").unwrap(), 12);
		assert!(bytes_parse_number_hex(b"x\r").is_none());
		assert!(bytes_parse_number_hex(b"0\r").is_some());
		assert!(bytes_parse_number(b"V\r").is_none());
		assert!(bytes_parse_number(b"0\r").is_some());
		assert!(bytes_parse_number(b"00").is_none());
		assert!(bytes_parse_number_header(b"abc", 0).is_none());
		assert!(bytes_parse_number_header(b"x: 1\r", 0).is_some());
		Ok(())
	}
}
