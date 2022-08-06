// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
// http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

use crate::cell::CellBody;
use crate::cell::Relay;
use crate::circuit::Circuit;
use crate::types::Stream;
use crate::types::StreamEventType;
use nioruntime_err::Error;
use nioruntime_log::*;

info!();

pub struct StreamImpl<'a> {
	sid: u16,
	cid: u32,
	etype: StreamEventType,
	data: Vec<u8>,
	circuit: &'a mut Circuit,
}

impl<'a> StreamImpl<'a> {
	pub fn new(
		sid: u16,
		cid: u32,
		etype: StreamEventType,
		data: Vec<u8>,
		circuit: &'a mut Circuit,
	) -> Self {
		Self {
			sid,
			cid,
			etype,
			data,
			circuit,
		}
	}

	pub fn data(&mut self) -> &mut Vec<u8> {
		&mut self.data
	}

	pub fn sid(&self) -> u16 {
		self.sid
	}
	pub fn cid(&self) -> u32 {
		self.cid
	}
}

impl<'a> Stream for StreamImpl<'a> {
	fn event_type(&self) -> StreamEventType {
		self.etype
	}
	fn write(&mut self, b: &[u8]) -> Result<(), Error> {
		let body = CellBody::Relay(Relay::new_data(
			b.to_vec(),
			self.circuit.channel_context().crypt_state.clone(),
			self.sid,
		)?);
		self.circuit.send_cell(body)?;
		Ok(())
	}
	fn get_data(&self) -> Result<&Vec<u8>, Error> {
		Ok(&self.data)
	}
	fn available(&self) -> Result<usize, Error> {
		Ok(self.data.len())
	}
	fn close(&mut self, reason: u8) -> Result<(), Error> {
		self.circuit.close(self.sid, reason)?;

		Ok(())
	}

	fn id(&self) -> u16 {
		self.sid
	}
}
