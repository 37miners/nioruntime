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

use crate::native_tls::TlsStream;
use crate::num_enum::IntoPrimitive;
use nioruntime_err::Error;
use nioruntime_log::*;
use std::io::{Read, Write};
use std::net::TcpStream;

debug!();

#[derive(IntoPrimitive)]
#[repr(u8)]
/// We don't support everything for now. Just what we need to use
enum ChanCmd {
	/// Variable-length cell, despite its number: negotiate versions
	Versions = 7,
}

pub struct Channel {}

impl Channel {
	pub fn connect(&self, stream: &mut TlsStream<TcpStream>) -> Result<(), Error> {
		// advertise version 4.
		let versions_msg: &[u8] = &[0, 0, ChanCmd::Versions.into(), 0, 2, 0, 4];
		stream.write(versions_msg)?;
		stream.flush()?;

		let mut hdr = [0_u8; 5];
		stream.read(&mut hdr)?;
		warn!("hdr={:?}", hdr)?;
		Ok(())
	}
}

#[cfg(test)]
mod test {
	use crate::channel::Channel;
	use crate::native_tls::TlsConnector;
	use nioruntime_err::Error;
	use nioruntime_log::*;
	use std::net::TcpStream;

	debug!();

	#[test]
	fn test_channel() -> Result<(), Error> {
		let addr = "45.66.33.45:443";
		let channel = Channel {};

		let mut builder = TlsConnector::builder();
		builder
			.danger_accept_invalid_certs(true)
			.danger_accept_invalid_hostnames(true);

		let connector = builder.build().unwrap();

		let mut tls_stream = connector
			.connect("", TcpStream::connect(addr).unwrap())
			.unwrap();
		info!("stream connected")?;
		//let (reader, writer) = &mut (&tls_stream, &tls_stream);

		//"http://45.66.33.45:443"
		channel.connect(&mut tls_stream).unwrap();

		Ok(())
	}
}
