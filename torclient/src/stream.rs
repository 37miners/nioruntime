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

debug!();

pub struct TorStreamImpl<OnRead, OnConnect, OnClose>
where
	OnRead: Fn(&[u8]) -> Result<(), Error> + Send + 'static + Clone + Sync + Unpin,
	OnConnect: Fn() -> Result<(), Error> + Send + 'static + Clone + Sync + Unpin,
	OnClose: Fn() -> Result<(), Error> + Send + 'static + Clone + Sync + Unpin,
{
	config: TorStreamConfig,
	handlers: TorStreamHandlers<OnRead, OnConnect, OnClose>,
}

impl<OnRead, OnConnect, OnClose> TorStreamImpl<OnRead, OnConnect, OnClose>
where
	OnRead: Fn(&[u8]) -> Result<(), Error> + Send + 'static + Clone + Sync + Unpin,
	OnConnect: Fn() -> Result<(), Error> + Send + 'static + Clone + Sync + Unpin,
	OnClose: Fn() -> Result<(), Error> + Send + 'static + Clone + Sync + Unpin,
{
	pub fn new(
		config: TorStreamConfig,
		handlers: TorStreamHandlers<OnRead, OnConnect, OnClose>,
		circuit: Circuit,
	) -> Self {
		Self { handlers, config }
	}
}

impl<OnRead, OnConnect, OnClose> TorStream<OnRead, OnConnect, OnClose>
	for TorStreamImpl<OnRead, OnConnect, OnClose>
where
	OnRead: Fn(&[u8]) -> Result<(), Error> + Send + 'static + Clone + Sync + Unpin,
	OnConnect: Fn() -> Result<(), Error> + Send + 'static + Clone + Sync + Unpin,
	OnClose: Fn() -> Result<(), Error> + Send + 'static + Clone + Sync + Unpin,
{
	fn write(&mut self, _: &[u8]) -> Result<(), Error> {
		Ok(())
	}
}

#[cfg(test)]
mod test {
	use crate::manager::StreamManagerBuilder;
	use crate::stream::TorStreamHandlers;
	use crate::types::StreamManager;
	use crate::types::{StreamManagerConfig, TorStreamConfig};
	use nioruntime_err::Error;
	use nioruntime_log::*;

	info!();

	#[test]
	fn test_torclient() -> Result<(), Error> {
		let mut manager = StreamManagerBuilder::build(StreamManagerConfig::default())?;
		let mut client1_handlers = TorStreamHandlers::default();
		client1_handlers.set_on_read(move |data| {
			info!("got data = {:?} on client1", data)?;
			Ok(())
		})?;

		client1_handlers.set_on_connect(move || {
			info!("client1 connected")?;
			Ok(())
		})?;

		client1_handlers.set_on_close(move || {
			info!("client1 closed")?;
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
		client2_handlers.set_on_read(move |data| {
			info!("got data = {:?} on client2", data)?;
			Ok(())
		})?;

		client2_handlers.set_on_connect(move || {
			info!("client2 connected")?;
			Ok(())
		})?;

		client2_handlers.set_on_close(move || {
			info!("client2 closed")?;
			Ok(())
		})?;
		let client2_config = TorStreamConfig {
			host: "example.com".to_string(),
			port: 80,
			..Default::default()
		};

		let mut client2 = manager.open_stream(client2_config, client2_handlers)?;
		client2.write(b"GET / HTTP/1.0\r\n\r\n")?;

		Ok(())
	}
}
