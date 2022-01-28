// Copyright 2021 The BMW Developers
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

use crate::ConnData;
use byteorder::{BigEndian, ByteOrder};
use nioruntime_err::{Error, ErrorKind};
use nioruntime_log::*;
use std::convert::TryInto;

info!();

// constant bit flags
const FIN_BIT: u8 = 0x1 << 7;
const MASK_BIT: u8 = 0x1 << 7;
const OP_CODE_MASK1: u8 = 0x1 << 3;
const OP_CODE_MASK2: u8 = 0x1 << 2;
const OP_CODE_MASK3: u8 = 0x1 << 1;
const OP_CODE_MASK4: u8 = 0x1 << 0;

#[derive(Debug, PartialEq)]
enum FrameType {
	Continuation,
	Text,
	Binary,
	Close,
	Ping,
	Pong,
}

#[derive(Debug, PartialEq)]
struct FrameHeaderInfo {
	ftype: FrameType,     // which type of frame is this?
	mask: bool,           // is this frame masked?
	fin: bool,            // is this the last piece of data in the frame?
	payload_len: usize,   // size of the payload
	masking_key: u32,     // masking key
	start_content: usize, // start of the content of the message
}

// build the FrameHeader for this data. If data is not sufficient
// to return the frame None is returned.
fn get_frame_header_info(buffer: &mut Vec<u8>) -> Result<Option<FrameHeaderInfo>, Error> {
	let len = buffer.len();
	let start_content;
	if len < 2 {
		// not enough to even start parsing
		debug!("return ok 1");
		return Ok(None);
	}

	// get basic bits from the first byte
	let fin = (buffer[0] & FIN_BIT) != 0;
	let op1 = (buffer[0] & OP_CODE_MASK1) != 0;
	let op2 = (buffer[0] & OP_CODE_MASK2) != 0;
	let op3 = (buffer[0] & OP_CODE_MASK3) != 0;
	let op4 = (buffer[0] & OP_CODE_MASK4) != 0;

	debug!("op1={},op2={},op3={},op4={}", op1, op2, op3, op4);

	// get type based on op_codes
	let ftype = if !op1 && !op2 && !op3 && !op4 {
		FrameType::Continuation
	} else if !op1 && !op2 && !op3 && op4 {
		FrameType::Text
	} else if !op1 && !op2 && op3 && !op4 {
		FrameType::Binary
	} else if op1 && !op2 && !op3 && !op4 {
		FrameType::Close
	} else if op1 && !op2 && !op3 && op4 {
		FrameType::Ping
	} else if op1 && !op2 && op3 && !op4 {
		FrameType::Pong
	} else {
		// other op codes not supported
		return Err(ErrorKind::InvalidWebSocketOpCode("Unknown payload type".to_string()).into());
	};

	// get bit indicating masking.
	let mask = (buffer[1] & MASK_BIT) != 0;
	// get 7 bit size, then 16 bit, then 64. See rfc:
	// https://datatracker.ietf.org/doc/html/rfc6455
	let first_payload_bits = buffer[1] & !MASK_BIT;

	let payload_len: usize = if first_payload_bits == 126 {
		if len < 4 {
			debug!("return ok 2");
			return Ok(None);
		}
		BigEndian::read_u16(&buffer[2..4]).try_into()?
	} else if first_payload_bits == 127 {
		if len < 10 {
			debug!("return ok 3");
			return Ok(None);
		}
		BigEndian::read_u64(&buffer[2..10]).try_into()?
	} else {
		let payload_len: usize = first_payload_bits.into();
		payload_len
	}
	.into();

	let masking_key = if !mask {
		if first_payload_bits == 126 {
			start_content = 4;
			if len < 4 + payload_len {
				debug!("return ok 4");
				return Ok(None);
			}
		} else if first_payload_bits == 127 {
			start_content = 10;
			if len < 10 + payload_len {
				debug!("return ok 5");
				return Ok(None);
			}
		} else {
			start_content = 2;
			if len < 2 + payload_len {
				debug!("return ok 6");
				return Ok(None);
			}
		}
		0
	} else if first_payload_bits == 126 {
		start_content = 8;
		if len < 8 + payload_len {
			debug!("return ok 7");
			return Ok(None);
		}
		BigEndian::read_u32(&buffer[4..8])
	} else if first_payload_bits == 127 {
		start_content = 14;
		if len < 14 + payload_len {
			debug!("return ok 8");
			return Ok(None);
		}
		BigEndian::read_u32(&buffer[10..14])
	} else {
		start_content = 6;
		if len < 6 + payload_len {
			debug!("return ok 9");
			return Ok(None);
		}
		BigEndian::read_u32(&buffer[2..6])
	};

	Ok(Some(FrameHeaderInfo {
		ftype,
		mask,
		fin,
		payload_len,
		masking_key,
		start_content,
	}))
}

fn build_messages(buffer: &mut Vec<u8>) -> Result<Vec<Vec<u8>>, Error> {
	let mut ret = vec![];
	let mut headers = vec![];
	let mut offset = 0;

	loop {
		let header = get_frame_header_info(&mut buffer[offset..].to_vec())?;

		match header {
			Some(header) => {
				let fin = header.fin;
				let payload_len = header.payload_len;
				let start_content = header.start_content;

				// add this header to our framed headers
				headers.push((header, offset));

				let end_content = start_content + payload_len;
				offset += end_content;

				// if it's the final buffer, we drain
				if fin {
					// process the existing frames
					let message = build_message(headers, buffer.to_vec())?;
					ret.push(message);
					headers = vec![];

					buffer.drain(0..(end_content + offset));
				}
			}
			None => {
				// we don't have enough data to continue, so break
				break;
			}
		}
	}
	Ok(ret)
}

fn build_message(frames: Vec<(FrameHeaderInfo, usize)>, buffer: Vec<u8>) -> Result<Vec<u8>, Error> {
	// append each frame of the message content into a single message for processing
	let mut ret = vec![];

	let mut masking_bytes = [0u8; 4];

	for (header, offset) in frames {
		let start = header.start_content + offset;
		let end = header.payload_len + start;
		let data = &buffer[start..end];
		let mut ndata = vec![];
		let mut i = 0;

		BigEndian::write_u32(&mut masking_bytes, header.masking_key);
		for d in data {
			let j = i % 4;
			let nbyte = d ^ masking_bytes[j];
			ndata.push(nbyte);
			i += 1;
		}
		ret.append(&mut data.to_vec());
	}

	Ok(ret)
}

pub fn process_websocket_data(conn_data: &mut ConnData) -> Result<(), Error> {
	let buffer = conn_data.get_buffer();
	let len = buffer.len();
	info!("websocket.rs data[{}] = {:?}", len, buffer);
	let _messages = build_messages(buffer)?;
	// next send the messages to the callback.

	Ok(())
}

#[test]
fn test_get_frame_header_info() -> Result<(), Error> {
	use crate::websocket::FrameType::*;

	// too little data
	assert_eq!(get_frame_header_info(&mut [0u8; 0].to_vec()).unwrap(), None);

	// again too little data
	assert_eq!(get_frame_header_info(&mut [0u8; 1].to_vec()).unwrap(), None);

	// sufficient data this time
	assert_eq!(
		get_frame_header_info(&mut [0u8; 2].to_vec()).unwrap(),
		Some(FrameHeaderInfo {
			ftype: Continuation,
			mask: false,
			fin: false,
			payload_len: 0,
			masking_key: 0,
			start_content: 2,
		})
	);

	// set final true this time
	assert_eq!(
		get_frame_header_info(&mut [128, 0].to_vec()).unwrap(),
		Some(FrameHeaderInfo {
			ftype: Continuation,
			mask: false,
			fin: true,
			payload_len: 0,
			masking_key: 0,
			start_content: 2,
		})
	);

	// text type
	assert_eq!(
		get_frame_header_info(&mut [1, 0].to_vec()).unwrap(),
		Some(FrameHeaderInfo {
			ftype: Text,
			mask: false,
			fin: false,
			payload_len: 0,
			masking_key: 0,
			start_content: 2,
		})
	);

	// binary type
	assert_eq!(
		get_frame_header_info(&mut [2, 0].to_vec()).unwrap(),
		Some(FrameHeaderInfo {
			ftype: Binary,
			mask: false,
			fin: false,
			payload_len: 0,
			masking_key: 0,
			start_content: 2,
		})
	);

	// close type
	assert_eq!(
		get_frame_header_info(&mut [8, 0].to_vec()).unwrap(),
		Some(FrameHeaderInfo {
			ftype: Close,
			mask: false,
			fin: false,
			payload_len: 0,
			masking_key: 0,
			start_content: 2,
		})
	);

	// Ping
	assert_eq!(
		get_frame_header_info(&mut [9, 0].to_vec()).unwrap(),
		Some(FrameHeaderInfo {
			ftype: Ping,
			mask: false,
			fin: false,
			payload_len: 0,
			masking_key: 0,
			start_content: 2,
		})
	);

	// Pong
	assert_eq!(
		get_frame_header_info(&mut [10, 0].to_vec()).unwrap(),
		Some(FrameHeaderInfo {
			ftype: Pong,
			mask: false,
			fin: false,
			payload_len: 0,
			masking_key: 0,
			start_content: 2,
		})
	);

	// test a masking_key
	assert_eq!(
		get_frame_header_info(&mut [10, 128, 0, 0, 0, 1].to_vec()).unwrap(),
		Some(FrameHeaderInfo {
			ftype: Pong,
			mask: true,
			fin: false,
			payload_len: 0,
			masking_key: 1,
			start_content: 6,
		})
	);

	// different masking key value
	assert_eq!(
		get_frame_header_info(&mut [10, 128, 0, 0, 0, 111].to_vec()).unwrap(),
		Some(FrameHeaderInfo {
			ftype: Pong,
			mask: true,
			fin: false,
			payload_len: 0,
			masking_key: 111,
			start_content: 6,
		})
	);

	// set payload len to 1 but don't send a payload. Return None to wait for more
	// data
	assert_eq!(
		get_frame_header_info(&mut [10, 129, 0, 0, 0, 111].to_vec()).unwrap(),
		None
	);

	// now send enough data
	assert_eq!(
		get_frame_header_info(&mut [10, 129, 0, 0, 0, 111, 1].to_vec()).unwrap(),
		Some(FrameHeaderInfo {
			ftype: Pong,
			mask: true,
			fin: false,
			payload_len: 1,
			masking_key: 111,
			start_content: 6,
		})
	);

	// use the 16 bit payload
	let mut data = [0u8; 1000];
	data[0] = 10;
	data[1] = 254;
	data[2] = 0;
	data[3] = 150;
	data[4] = 0;
	data[5] = 0;
	data[6] = 0;
	data[7] = 111;

	assert_eq!(
		get_frame_header_info(&mut data.to_vec()).unwrap(),
		Some(FrameHeaderInfo {
			ftype: Pong,
			mask: true,
			fin: false,
			payload_len: 150,
			masking_key: 111,
			start_content: 8,
		})
	);

	// bigger value
	let mut data = [0u8; 1000];
	data[0] = 10;
	data[1] = 254;
	data[2] = 1;
	data[3] = 150;
	data[4] = 0;
	data[5] = 0;
	data[6] = 0;
	data[7] = 111;

	assert_eq!(
		get_frame_header_info(&mut data.to_vec()).unwrap(),
		Some(FrameHeaderInfo {
			ftype: Pong,
			mask: true,
			fin: false,
			payload_len: 406,
			masking_key: 111,
			start_content: 8,
		})
	);

	// use the 64 bit value
	let mut data = [0u8; 1000];
	data[0] = 10;
	data[1] = 255;
	data[2] = 0;
	data[3] = 0;
	data[4] = 0;
	data[5] = 0;
	data[6] = 0;
	data[7] = 0;
	data[8] = 1;
	data[9] = 150;
	data[10] = 0;
	data[11] = 0;
	data[12] = 0;
	data[13] = 111;

	assert_eq!(
		get_frame_header_info(&mut data.to_vec()).unwrap(),
		Some(FrameHeaderInfo {
			ftype: Pong,
			mask: true,
			fin: false,
			payload_len: 406,
			masking_key: 111,
			start_content: 14,
		})
	);

	// with a larger value so we don't have enough data
	let mut data = [0u8; 1000];
	data[0] = 10;
	data[1] = 255;
	data[2] = 0;
	data[3] = 0;
	data[4] = 0;
	data[5] = 0;
	data[6] = 0;
	data[7] = 0;
	data[8] = 4;
	data[9] = 150;
	data[10] = 0;
	data[11] = 0;
	data[12] = 0;
	data[13] = 111;

	assert_eq!(get_frame_header_info(&mut data.to_vec()).unwrap(), None,);

	// almost enough, but not quite
	let mut data = [0u8; 1187];
	data[0] = 10;
	data[1] = 255;
	data[2] = 0;
	data[3] = 0;
	data[4] = 0;
	data[5] = 0;
	data[6] = 0;
	data[7] = 0;
	data[8] = 4;
	data[9] = 150;
	data[10] = 0;
	data[11] = 0;
	data[12] = 0;
	data[13] = 111;

	assert_eq!(get_frame_header_info(&mut data.to_vec()).unwrap(), None,);

	// finally enough
	let mut data = [0u8; 1188];
	data[0] = 10;
	data[1] = 255;
	data[2] = 0;
	data[3] = 0;
	data[4] = 0;
	data[5] = 0;
	data[6] = 0;
	data[7] = 0;
	data[8] = 4;
	data[9] = 150;
	data[10] = 0;
	data[11] = 0;
	data[12] = 0;
	data[13] = 111;

	assert_eq!(
		get_frame_header_info(&mut data.to_vec()).unwrap(),
		Some(FrameHeaderInfo {
			ftype: Pong,
			mask: true,
			fin: false,
			payload_len: 1174,
			masking_key: 111,
			start_content: 14,
		})
	);

	// check content
	let mut data = [0u8; 1900];
	data[0] = 10;
	data[1] = 255;
	data[2] = 0;
	data[3] = 0;
	data[4] = 0;
	data[5] = 0;
	data[6] = 0;
	data[7] = 0;
	data[8] = 4;
	data[9] = 150;
	data[10] = 0;
	data[11] = 0;
	data[12] = 0;
	data[13] = 111;
	data[14] = 1;
	data[15] = 2;

	let mut message_expected = [0u8; 1174];
	message_expected[0] = 1;
	message_expected[1] = 2;

	let header = get_frame_header_info(&mut data.to_vec()).unwrap().unwrap();
	let message_found = &data[header.start_content..(header.start_content + 1174)];
	assert_eq!(message_expected, message_found);

	Ok(())
}
