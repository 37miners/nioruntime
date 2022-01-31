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

use crate::http::HeaderInfo;
use crate::ConnData;
use crate::WsHandler;
use byteorder::{BigEndian, ByteOrder};
use nioruntime_err::{Error, ErrorKind};
use nioruntime_log::*;
use std::convert::TryInto;

info!();

#[derive(Debug, PartialEq, Clone)]
pub enum WebSocketMessageType {
	Text,
	Binary,
	Close,
	Ping,
	Pong,
	Open,
	Accept,
}

#[derive(Debug, PartialEq, Clone)]
pub struct WebSocketMessage {
	pub mtype: WebSocketMessageType,
	pub payload: Vec<u8>,
	pub mask: bool,
	pub header_info: Option<HeaderInfo>,
}

impl From<WebSocketMessage> for Vec<u8> {
	fn from(ws: WebSocketMessage) -> Vec<u8> {
		(&ws).into()
	}
}

impl From<&WebSocketMessage> for Vec<u8> {
	fn from(ws: &WebSocketMessage) -> Vec<u8> {
		let mut ret: Vec<u8> = vec![];
		ret.resize(2, 0u8);

		// always set fin bit for now. No fragmentation.
		ret[0] = match ws.mtype {
			WebSocketMessageType::Text => 0x80 | 0x1,
			WebSocketMessageType::Binary => 0x80 | 0x2,
			WebSocketMessageType::Close => 0x80 | 0x8,
			WebSocketMessageType::Ping => 0x80 | 0x9,
			WebSocketMessageType::Pong => 0x80 | 0xA,
			_ => 0x80 | 0x1, // should not happen
		};

		ret[1] = if ws.mask { 0x80 } else { 0x00 };

		let mut masking_bytes = [0u8; 4];
		let payload_len = ws.payload.len();
		let start_content = if payload_len < 126 {
			ret[1] |= payload_len as u8;
			if ws.mask {
				ret.resize(6 + payload_len, 0u8);
				let masking_key = rand::random();
				BigEndian::write_u32(&mut ret[2..6], masking_key);
				masking_bytes.clone_from_slice(&ret[2..6]);
				6
			} else {
				ret.resize(2 + payload_len, 0u8);
				2
			}
		} else if payload_len <= u16::MAX.into() {
			ret[1] |= 126;
			if ws.mask {
				ret.resize(8 + payload_len, 0u8);
			} else {
				ret.resize(4 + payload_len, 0u8);
			}
			BigEndian::write_u16(&mut ret[2..4], payload_len.try_into().unwrap_or(0));
			if ws.mask {
				BigEndian::write_u32(&mut ret[4..8], rand::random());
				masking_bytes.clone_from_slice(&ret[4..8]);
				8
			} else {
				4
			}
		} else {
			ret[1] |= 127;
			if ws.mask {
				ret.resize(14 + payload_len, 0u8);
			} else {
				ret.resize(10 + payload_len, 0u8);
			}
			BigEndian::write_u64(&mut ret[2..10], payload_len.try_into().unwrap_or(0));
			if ws.mask {
				BigEndian::write_u32(&mut ret[10..14], rand::random());
				masking_bytes.clone_from_slice(&ret[10..14]);
				14
			} else {
				10
			}
		};

		ret[start_content..].clone_from_slice(&ws.payload);

		if ws.mask {
			let mut i = 0;
			let ret_len = ret.len();
			loop {
				if i + start_content >= ret_len {
					break;
				}

				let j = i % 4;
				ret[i + start_content] = ret[i + start_content] ^ masking_bytes[j];
				i += 1;
			}
		}

		ret
	}
}

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
		debug!("return none 1");
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
		return Err(ErrorKind::WebSocketError("invalid opcode".to_string()).into());
	};

	// get bit indicating masking.
	let mask = (buffer[1] & MASK_BIT) != 0;
	// get 7 bit size, then 16 bit, then 64. See rfc:
	// https://datatracker.ietf.org/doc/html/rfc6455
	let first_payload_bits = buffer[1] & !MASK_BIT;

	let payload_len: usize = if first_payload_bits == 126 {
		if len < 4 {
			debug!("return none 2");
			return Ok(None);
		}
		BigEndian::read_u16(&buffer[2..4]).try_into()?
	} else if first_payload_bits == 127 {
		if len < 10 {
			debug!("return none 3");
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
				debug!("return none 4");
				return Ok(None);
			}
		} else if first_payload_bits == 127 {
			start_content = 10;
			if len < 10 + payload_len {
				debug!("return none 5");
				return Ok(None);
			}
		} else {
			start_content = 2;
			if len < 2 + payload_len {
				debug!("return none 6");
				return Ok(None);
			}
		}
		0
	} else if first_payload_bits == 126 {
		start_content = 8;
		if len < 8 + payload_len {
			debug!("return none 7");
			return Ok(None);
		}
		BigEndian::read_u32(&buffer[4..8])
	} else if first_payload_bits == 127 {
		start_content = 14;
		if len < 14 + payload_len {
			debug!("return none 8");
			return Ok(None);
		}
		BigEndian::read_u32(&buffer[10..14])
	} else {
		start_content = 6;
		if len < 6 + payload_len {
			debug!("return none 9");
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

fn build_messages(buffer: &mut Vec<u8>) -> Result<Vec<WebSocketMessage>, Error> {
	let mut ret = vec![];
	let mut headers = vec![];
	let mut offset = 0;

	loop {
		let header = get_frame_header_info(&mut buffer[offset..].to_vec())?;

		debug!("found a header: {:?}", header);

		match header {
			Some(header) => {
				let fin = header.fin;
				let payload_len = header.payload_len;
				let start_content = header.start_content;

				let end_content = start_content + payload_len;

				// if it's the final buffer, we drain
				if fin {
					// add this header to our framed headers
					headers.push((header, offset));
					offset += end_content;
					// process the existing frames
					let message = build_message(headers, buffer.to_vec())?;
					ret.push(message);
					headers = vec![];

					buffer.drain(0..offset);
					offset = 0;
				} else {
					match header.ftype {
						FrameType::Ping => {
							return Err(ErrorKind::WebSocketError(format!(
								"frametype '{:?}' must set fin = true.",
								header.ftype
							))
							.into());
						}
						_ => {}
					}
					// add this header to our framed headers
					headers.push((header, offset));
					offset += end_content;
				}
			}
			None => {
				debug!("not enough data. Returning none");

				// we don't have enough data to continue, so break
				break;
			}
		}
	}
	Ok(ret)
}

fn build_message(
	frames: Vec<(FrameHeaderInfo, usize)>,
	buffer: Vec<u8>,
) -> Result<WebSocketMessage, Error> {
	// append each frame of the message content into a single message for processing
	let mut payload = vec![];

	let mut masking_bytes = [0u8; 4];
	let mut mtype = WebSocketMessageType::Text;
	let mut mask = false;

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
		payload.append(&mut ndata.to_vec());

		// take the type of the last frame
		mtype = match header.ftype {
			FrameType::Text => WebSocketMessageType::Text,
			FrameType::Binary => WebSocketMessageType::Binary,
			FrameType::Ping => WebSocketMessageType::Ping,
			FrameType::Pong => WebSocketMessageType::Pong,
			FrameType::Close => WebSocketMessageType::Close,
			_ => WebSocketMessageType::Text,
		};

		// same for mask
		mask = header.mask;
	}

	Ok(WebSocketMessage {
		mtype,
		payload,
		mask,
		header_info: None,
	})
}

pub fn send_websocket_message(
	conn_data: &ConnData,
	message: &WebSocketMessage,
) -> Result<(), Error> {
	let message: Vec<u8> = message.into();
	conn_data.get_wh().write(&message)?;
	Ok(())
}

// returns true on close, otherwise, false
pub fn process_websocket_data(
	conn_data: &mut ConnData,
	ws_handler: &WsHandler,
) -> Result<bool, Error> {
	let mut ret = false;
	let buffer = conn_data.get_buffer();
	let len = buffer.len();
	debug!("websocket.rs data[{}] = {:?}", len, buffer);
	let messages = build_messages(buffer)?;

	// send the messages to the callback.
	for message in messages {
		if message.mtype == WebSocketMessageType::Close {
			ret = true;
		}
		match ws_handler(conn_data, message)? {
			true => {}
			false => {
				// close connection
				send_websocket_message(
					conn_data,
					&WebSocketMessage {
						mtype: WebSocketMessageType::Close,
						payload: vec![],
						mask: false,
						header_info: None,
					},
				)?;
				conn_data.get_wh().close()?;

				break;
			}
		}
	}

	Ok(ret)
}

#[cfg(test)]
mod tests {
	use crate::websocket::FrameType::*;
	use crate::websocket::*;

	#[test]
	fn test_get_frame_header_info() -> Result<(), Error> {
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

	#[test]
	fn test_get_message() -> Result<(), Error> {
		// get two separate finished messages
		let mut data = [0u8; 26];
		data[0] = 129;
		data[1] = 255;
		data[2] = 0;
		data[3] = 0;
		data[4] = 0;
		data[5] = 0;
		data[6] = 0;
		data[7] = 0;
		data[8] = 0;
		data[9] = 5;
		data[10] = 0;
		data[11] = 0;
		data[12] = 0;
		data[13] = 0;
		data[14] = 1;
		data[15] = 2;
		data[16] = 3;
		data[17] = 4;
		data[18] = 5;
		data[19] = 129;
		data[20] = 129;
		data[21] = 0;
		data[22] = 0;
		data[23] = 0;
		data[24] = 0;
		data[25] = 100;

		let header = get_frame_header_info(&mut data.to_vec()).unwrap();
		assert_eq!(
			header,
			Some(FrameHeaderInfo {
				ftype: Text,
				mask: true,
				fin: true,
				payload_len: 5,
				masking_key: 0,
				start_content: 14,
			})
		);

		let messages = build_messages(&mut data[..].to_vec())?;
		assert_eq!(
			messages,
			vec![
				WebSocketMessage {
					payload: vec![1, 2, 3, 4, 5],
					mtype: WebSocketMessageType::Text,
					mask: true,
					header_info: None,
				},
				WebSocketMessage {
					payload: vec![100],
					mtype: WebSocketMessageType::Text,
					mask: true,
					header_info: None,
				},
			],
		);

		// get two combined messages
		let mut data = [0u8; 26];
		data[0] = 1;
		data[1] = 255;
		data[2] = 0;
		data[3] = 0;
		data[4] = 0;
		data[5] = 0;
		data[6] = 0;
		data[7] = 0;
		data[8] = 0;
		data[9] = 5;
		data[10] = 0;
		data[11] = 0;
		data[12] = 0;
		data[13] = 0;
		data[14] = 1;
		data[15] = 2;
		data[16] = 3;
		data[17] = 4;
		data[18] = 5;
		data[19] = 129;
		data[20] = 129;
		data[21] = 0;
		data[22] = 0;
		data[23] = 0;
		data[24] = 0;
		data[25] = 100;

		let header = get_frame_header_info(&mut data.to_vec()).unwrap();
		assert_eq!(
			header,
			Some(FrameHeaderInfo {
				ftype: Text,
				mask: true,
				fin: false,
				payload_len: 5,
				masking_key: 0,
				start_content: 14,
			})
		);

		let messages = build_messages(&mut data[..].to_vec())?;
		assert_eq!(
			messages,
			vec![WebSocketMessage {
				payload: vec![1, 2, 3, 4, 5, 100],
				mtype: WebSocketMessageType::Text,
				mask: true,
				header_info: None,
			},],
		);

		// get unfinished messages
		let mut data = [0u8; 26];
		data[0] = 1;
		data[1] = 255;
		data[2] = 0;
		data[3] = 0;
		data[4] = 0;
		data[5] = 0;
		data[6] = 0;
		data[7] = 0;
		data[8] = 0;
		data[9] = 5;
		data[10] = 0;
		data[11] = 0;
		data[12] = 0;
		data[13] = 0;
		data[14] = 1;
		data[15] = 2;
		data[16] = 3;
		data[17] = 4;
		data[18] = 5;
		data[19] = 1;
		data[20] = 129;
		data[21] = 0;
		data[22] = 0;
		data[23] = 0;
		data[24] = 0;
		data[25] = 100;

		let header = get_frame_header_info(&mut data.to_vec()).unwrap();
		assert_eq!(
			header,
			Some(FrameHeaderInfo {
				ftype: Text,
				mask: true,
				fin: false,
				payload_len: 5,
				masking_key: 0,
				start_content: 14,
			})
		);

		let messages = build_messages(&mut data[..].to_vec())?;
		assert_eq!(messages.len(), 0);

		// test masking key
		let mut data = [0u8; 19];
		data[0] = 129;
		data[1] = 255;
		data[2] = 0;
		data[3] = 0;
		data[4] = 0;
		data[5] = 0;
		data[6] = 0;
		data[7] = 0;
		data[8] = 0;
		data[9] = 5;
		data[10] = 1;
		data[11] = 1;
		data[12] = 1;
		data[13] = 1;
		data[14] = 1;
		data[15] = 2;
		data[16] = 3;
		data[17] = 4;
		data[18] = 5;

		let header = get_frame_header_info(&mut data.to_vec()).unwrap();
		assert_eq!(
			header,
			Some(FrameHeaderInfo {
				ftype: Text,
				mask: true,
				fin: true,
				payload_len: 5,
				masking_key: 16843009,
				start_content: 14,
			})
		);

		let messages = build_messages(&mut data[..].to_vec())?;
		assert_eq!(
			messages,
			vec![WebSocketMessage {
				payload: vec![0, 3, 2, 5, 4],
				mtype: WebSocketMessageType::Text,
				mask: true,
				header_info: None,
			},],
		);

		// send other message types
		let mut data = [0u8; 19];
		data[0] = 130;
		data[1] = 255;
		data[2] = 0;
		data[3] = 0;
		data[4] = 0;
		data[5] = 0;
		data[6] = 0;
		data[7] = 0;
		data[8] = 0;
		data[9] = 5;
		data[10] = 1;
		data[11] = 1;
		data[12] = 1;
		data[13] = 1;
		data[14] = 1;
		data[15] = 2;
		data[16] = 3;
		data[17] = 4;
		data[18] = 5;

		let header = get_frame_header_info(&mut data.to_vec()).unwrap();
		assert_eq!(
			header,
			Some(FrameHeaderInfo {
				ftype: Binary,
				mask: true,
				fin: true,
				payload_len: 5,
				masking_key: 16843009,
				start_content: 14,
			}),
		);

		let messages = build_messages(&mut data[..].to_vec())?;
		assert_eq!(
			messages,
			vec![WebSocketMessage {
				payload: vec![0, 3, 2, 5, 4],
				mtype: WebSocketMessageType::Binary,
				mask: true,
				header_info: None,
			},],
		);

		// send Ping without a payload
		let mut data = [0u8; 6];
		data[0] = 137;
		data[1] = 128;
		data[2] = 0;
		data[3] = 0;
		data[4] = 0;
		data[5] = 0;

		let header = get_frame_header_info(&mut data.to_vec()).unwrap();
		assert_eq!(
			header,
			Some(FrameHeaderInfo {
				ftype: Ping,
				mask: true,
				fin: true,
				payload_len: 0,
				masking_key: 0,
				start_content: 6,
			})
		);

		let messages = build_messages(&mut data[..].to_vec())?;
		assert_eq!(
			messages,
			vec![WebSocketMessage {
				payload: vec![],
				mtype: WebSocketMessageType::Ping,
				mask: true,
				header_info: None,
			}],
		);

		// pong
		let mut data = [0u8; 6];
		data[0] = 138;
		data[1] = 128;
		data[2] = 0;
		data[3] = 0;
		data[4] = 0;
		data[5] = 0;

		let header = get_frame_header_info(&mut data.to_vec()).unwrap();
		assert_eq!(
			header,
			Some(FrameHeaderInfo {
				ftype: Pong,
				mask: true,
				fin: true,
				payload_len: 0,
				masking_key: 0,
				start_content: 6,
			})
		);

		let messages = build_messages(&mut data[..].to_vec())?;
		assert_eq!(
			messages,
			vec![WebSocketMessage {
				payload: vec![],
				mtype: WebSocketMessageType::Pong,
				mask: true,
				header_info: None,
			}],
		);

		// close
		let mut data = [0u8; 6];
		data[0] = 136;
		data[1] = 128;
		data[2] = 0;
		data[3] = 0;
		data[4] = 0;
		data[5] = 0;

		let header = get_frame_header_info(&mut data.to_vec()).unwrap();
		assert_eq!(
			header,
			Some(FrameHeaderInfo {
				ftype: Close,
				mask: true,
				fin: true,
				payload_len: 0,
				masking_key: 0,
				start_content: 6,
			})
		);

		let messages = build_messages(&mut data[..].to_vec())?;
		assert_eq!(
			messages,
			vec![WebSocketMessage {
				payload: vec![],
				mtype: WebSocketMessageType::Close,
				mask: true,
				header_info: None,
			}],
		);

		// multiple messages
		let mut data = [0u8; 37];

		// ping
		data[0] = 137;
		data[1] = 128;
		data[2] = 0;
		data[3] = 0;
		data[4] = 0;
		data[5] = 0;

		// two combined messages
		data[6] = 1;
		data[7] = 1;
		data[8] = 42;
		data[9] = 129;
		data[10] = 1;
		data[11] = 43;

		// Pong
		data[12] = 138;
		data[13] = 128;
		data[14] = 0;
		data[15] = 0;
		data[16] = 0;
		data[17] = 0;

		// binary message
		data[18] = 130;
		data[19] = 1;
		data[20] = 37;

		// close
		data[21] = 136;
		data[22] = 0;

		// another partial message that should not be processed
		data[23] = 130;
		data[24] = 100;
		data[25] = 0;
		data[26] = 0;
		data[27] = 0;
		data[28] = 0;
		data[29] = 0;
		data[30] = 0;
		data[31] = 0;
		data[32] = 0;
		data[33] = 0;
		data[34] = 0;
		data[35] = 0;
		data[36] = 0; // need 100, provided 12.

		let messages = build_messages(&mut data[..].to_vec())?;
		assert_eq!(
			messages,
			vec![
				WebSocketMessage {
					payload: vec![],
					mtype: WebSocketMessageType::Ping,
					mask: true,
					header_info: None,
				},
				WebSocketMessage {
					payload: vec![42, 43],
					mtype: WebSocketMessageType::Text,
					mask: false,
					header_info: None,
				},
				WebSocketMessage {
					payload: vec![],
					mtype: WebSocketMessageType::Pong,
					mask: true,
					header_info: None,
				},
				WebSocketMessage {
					payload: vec![37],
					mtype: WebSocketMessageType::Binary,
					mask: false,
					header_info: None,
				},
				WebSocketMessage {
					payload: vec![],
					mtype: WebSocketMessageType::Close,
					mask: false,
					header_info: None,
				},
			],
		);

		Ok(())
	}

	fn check_message(message: WebSocketMessage) -> Result<(), Error> {
		let data: Vec<u8> = (&message).into();
		let messages = build_messages(&mut data[..].to_vec())?;
		assert!(messages.len() == 1);

		assert_eq!(message, messages[0]);
		Ok(())
	}

	#[test]
	fn test_message_ser() -> Result<(), Error> {
		check_message(WebSocketMessage {
			mtype: WebSocketMessageType::Text,
			payload: vec![1, 0],
			mask: true,
			header_info: None,
		})?;

		check_message(WebSocketMessage {
			mtype: WebSocketMessageType::Binary,
			payload: vec![1, 0, 99, 5],
			mask: true,
			header_info: None,
		})?;

		check_message(WebSocketMessage {
			mtype: WebSocketMessageType::Close,
			payload: vec![],
			mask: false,
			header_info: None,
		})?;

		check_message(WebSocketMessage {
			mtype: WebSocketMessageType::Ping,
			payload: vec![],
			mask: true,
			header_info: None,
		})?;

		check_message(WebSocketMessage {
			mtype: WebSocketMessageType::Ping,
			payload: vec![],
			mask: true,
			header_info: None,
		})?;

		let payload = [1u8; 500].to_vec();
		check_message(WebSocketMessage {
			mtype: WebSocketMessageType::Text,
			payload,
			mask: true,
			header_info: None,
		})?;

		let payload = [2u8; 65534].to_vec();
		check_message(WebSocketMessage {
			mtype: WebSocketMessageType::Text,
			payload,
			mask: true,
			header_info: None,
		})?;

		let payload = [3u8; 65535].to_vec();
		check_message(WebSocketMessage {
			mtype: WebSocketMessageType::Text,
			payload,
			mask: true,
			header_info: None,
		})?;

		let payload = [4u8; 65536].to_vec();
		check_message(WebSocketMessage {
			mtype: WebSocketMessageType::Text,
			payload,
			mask: true,
			header_info: None,
		})?;

		let payload = [5u8; 65537].to_vec();
		check_message(WebSocketMessage {
			mtype: WebSocketMessageType::Text,
			payload,
			mask: true,
			header_info: None,
		})?;

		for i in 0..300 {
			let mut payload = vec![];
			for _ in 0..i {
				let x: u8 = i as u8 % 255;
				payload.push(x);
			}

			check_message(WebSocketMessage {
				mtype: WebSocketMessageType::Binary,
				payload,
				mask: true,
				header_info: None,
			})?;
		}

		Ok(())
	}

	#[test]
	fn test_ser() -> Result<(), Error> {
		let serialized_wsm: Vec<u8> = WebSocketMessage {
			mtype: WebSocketMessageType::Binary,
			payload: vec![1, 2, 3],
			mask: false,
			header_info: None,
		}
		.into();
		assert_eq!(serialized_wsm, [130, 3, 1, 2, 3]);

		Ok(())
	}
}
