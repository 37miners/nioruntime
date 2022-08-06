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

use crate::types::TorStreamHandlers;
use crate::types::{TorStream, TorStreamConfig};
use nioruntime_err::Error;
use nioruntime_log::*;
use nioruntime_tor::circuit::Circuit;
use nioruntime_tor::types::Stream;
use std::io::Write;
use std::net::TcpStream;
use std::sync::{Arc, RwLock};

info!();

pub struct TorStreamImpl<OnRead, OnConnect, OnClose>
where
	OnRead: Fn(u16, &[u8]) -> Result<(), Error> + Send + 'static + Clone + Sync + Unpin,
	OnConnect: Fn(u16) -> Result<(), Error> + Send + 'static + Clone + Sync + Unpin,
	OnClose: Fn(u16, u8) -> Result<(), Error> + Send + 'static + Clone + Sync + Unpin,
{
	_config: TorStreamConfig,
	_handlers: TorStreamHandlers<OnRead, OnConnect, OnClose>,
	circuit: Arc<RwLock<Circuit>>,
	id: u16,
	tcpstream: TcpStream,
}

impl<OnRead, OnConnect, OnClose> TorStreamImpl<OnRead, OnConnect, OnClose>
where
	OnRead: Fn(u16, &[u8]) -> Result<(), Error> + Send + 'static + Clone + Sync + Unpin,
	OnConnect: Fn(u16) -> Result<(), Error> + Send + 'static + Clone + Sync + Unpin,
	OnClose: Fn(u16, u8) -> Result<(), Error> + Send + 'static + Clone + Sync + Unpin,
{
	pub fn new(
		config: TorStreamConfig,
		handlers: TorStreamHandlers<OnRead, OnConnect, OnClose>,
		circuit: Arc<RwLock<Circuit>>,
		mut tcpstream: TcpStream,
	) -> Result<Self, Error> {
		let id = {
			let mut circuit = lockw!(circuit)?;
			let host_port = format!("{}:{}", config.host, config.port);
			debug!("opening stream to {}", host_port)?;
			let stream = circuit.open_stream(&host_port)?;
			stream.id()
		};

		{
			let mut circuit = lockw!(circuit)?;
			let mut wbuf = vec![];
			circuit.write_tor(&mut wbuf)?;
			tcpstream.write(&wbuf)?;
		}

		Ok(Self {
			_handlers: handlers,
			_config: config,
			circuit,
			id,
			tcpstream,
		})
	}
}

impl<OnRead, OnConnect, OnClose> TorStream<OnRead, OnConnect, OnClose>
	for TorStreamImpl<OnRead, OnConnect, OnClose>
where
	OnRead: Fn(u16, &[u8]) -> Result<(), Error> + Send + 'static + Clone + Sync + Unpin,
	OnConnect: Fn(u16) -> Result<(), Error> + Send + 'static + Clone + Sync + Unpin,
	OnClose: Fn(u16, u8) -> Result<(), Error> + Send + 'static + Clone + Sync + Unpin,
{
	fn write(&mut self, data: &[u8]) -> Result<(), Error> {
		let mut circuit = lockw!(self.circuit)?;
		debug!("writing data to stream")?;
		circuit.get_stream(self.id)?.write(data)?;
		let mut wbuf = vec![];
		circuit.write_tor(&mut wbuf)?;
		debug!("wrote len = {}", wbuf.len())?;
		self.tcpstream.write(&wbuf)?;
		Ok(())
	}
}

#[cfg(test)]
mod test {
	/*
	use crate::manager::StreamManagerBuilder;
	use crate::stream::TorStreamHandlers;
	use crate::types::StreamManager;
	use crate::types::{StreamManagerConfig, TorStreamConfig};
	*/
	use nioruntime_err::Error;
	use nioruntime_log::*;

	info!();

	#[test]
	fn test_torclient() -> Result<(), Error> {
		/*
		let mut manager = StreamManagerBuilder::build(StreamManagerConfig::default())?;
		let mut client1_handlers = TorStreamHandlers::default();
		client1_handlers.set_on_read(move |id, data| {
			debug!("got data = {:?} on client1: {}", data, id)?;
			Ok(())
		})?;

		client1_handlers.set_on_connect(move |id| {
			debug!("client1 connected: {}", id)?;
			Ok(())
		})?;

		client1_handlers.set_on_close(move |id, reason| {
			debug!("client1 closed: {},reason={}", id, reason)?;
			Ok(())
		})?;
		let client1_config = TorStreamConfig {
			host: "example.com".to_string(),
			port: 80,
			..Default::default()
		};

		let mut client1 = manager.open_stream(client1_config, client1_handlers)?;
		client1.write(b"GET / HTTP/1.0\r\n\r\n")?;

		let mut client2_handlers = TorStreamHandlers::default();
		client2_handlers.set_on_read(move |id, data| {
			debug!("got data = {:?} on client2 = {}", data, id)?;
			Ok(())
		})?;

		client2_handlers.set_on_connect(move |id| {
			debug!("client2 connected: {}", id)?;
			Ok(())
		})?;

		client2_handlers.set_on_close(move |id, reason| {
			debug!("client2 closed: {}, reason={}", id, reason)?;
			Ok(())
		})?;
		let client2_config = TorStreamConfig {
			host: "example.com".to_string(),
			port: 80,
			..Default::default()
		};

		let mut client2 = manager.open_stream(client2_config, client2_handlers)?;
		client2.write(b"GET / HTTP/1.0\r\n\r\n")?;
			*/

		Ok(())
	}
}
