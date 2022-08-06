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

use crate::dirmanager::DirManager;
use crate::stream::TorStreamImpl;
use crate::types::TorStreamHandlers;
use crate::types::{StreamManager, StreamManagerConfig, TorStream, TorStreamConfig};
use nioruntime_err::Error;
use nioruntime_err::ErrorKind;
use nioruntime_log::*;
use nioruntime_tor::circuit::Circuit;
use nioruntime_tor::types::{CircuitPlan, Node, Stream, StreamEventType};
use nioruntime_util::threadpool::StaticThreadPool;
use std::convert::TryInto;
use std::io::{Read, Write};
use std::net::TcpStream;
use std::sync::mpsc::sync_channel;
use std::sync::{Arc, RwLock};
use std::time::Instant;

info!();

struct StreamManagerImpl {
	config: StreamManagerConfig,
	tp: StaticThreadPool,
}

impl StreamManagerImpl {
	fn new(config: StreamManagerConfig) -> Result<Self, Error> {
		let mut tp = StaticThreadPool::new()?;
		tp.set_on_panic(move || Ok(()))?;
		tp.start(10)?;
		Ok(Self { config, tp })
	}

	fn get_healthy_circuit<OnRead, OnConnect, OnClose>(
		&mut self,
		handlers: TorStreamHandlers<OnRead, OnConnect, OnClose>,
	) -> Result<(Arc<RwLock<Circuit>>, TcpStream), Error>
	where
		OnRead: Fn(u16, &[u8]) -> Result<(), Error> + Send + 'static + Clone + Sync + Unpin,
		OnConnect: Fn(u16) -> Result<(), Error> + Send + 'static + Clone + Sync + Unpin,
		OnClose: Fn(u16, u8) -> Result<(), Error> + Send + 'static + Clone + Sync + Unpin,
	{
		let now = Instant::now();
		// get the directory
		let directory = DirManager::new(self.config.data_dir.clone())?;
		info!(
			"directory ready in {} seconds.",
			now.elapsed().as_millis() as f64 / 1000 as f64
		)?;

		// for now just build a circuit
		let node1: Node = match directory.random_guard() {
			Some(node) => node,
			None => return Err(ErrorKind::Tor("no guards available".to_string()).into()),
		}
		.try_into()?;

		let node2: Node = match directory.random_relay() {
			Some(node) => node,
			None => return Err(ErrorKind::Tor("no relays available".to_string()).into()),
		}
		.try_into()?;

		let node3: Node = match directory.random_exit() {
			Some(node) => node,
			None => return Err(ErrorKind::Tor("no exits available".to_string()).into()),
		}
		.try_into()?;

		let plan = CircuitPlan::new(vec![node1.clone(), node2, node3]);
		let mut circuit = Circuit::new(plan)?;

		circuit.start()?;

		let circuit = Arc::new(RwLock::new(circuit));
		let circuit_clone = circuit.clone();

		let (tx, rx) = sync_channel(1);

		//let mut stream = TcpStream::connect("104.53.221.159:9001")?;
		let mut stream = TcpStream::connect(node1.sockaddr.clone())?;
		let stream_clone = stream.try_clone()?;

		self.tp.execute(async move {
			let mut wbuf = vec![];

			{
				let mut circuit = lockw!(circuit)?;
				circuit.write_tor(&mut wbuf)?;
			}

			stream.write(&wbuf)?;

			let mut buffer = vec![];
			const BUFFER_SIZE: usize = 8 * 1024;
			buffer.resize(BUFFER_SIZE, 0u8);
			let mut tx_sent = false;

			loop {
				wbuf.clear();
				debug!("about to read")?;
				let len = stream.read(&mut buffer[0..BUFFER_SIZE])?;
				debug!("read len = {} bytes", len)?;

				{
					let mut circuit = lockw!(circuit)?;
					circuit.read_tor(&mut &buffer[0..len])?;

					match circuit.process_new_packets() {
						Ok(mut state) => {
							let handlers = handlers.clone();
							state.process_stream_events(move |stream| {
								debug!("processing stream event for stream = {}", stream.id())?;
								match stream.event_type() {
									StreamEventType::Readable => match &handlers.on_read {
										Some(on_read) => {
											debug!("read event")?;
											(on_read)(stream.id(), stream.data())?
										}
										None => {}
									},
									StreamEventType::Close(reason) => {
										debug!("close event reason = {}", reason)?;
										match &handlers.on_close {
											Some(on_close) => (on_close)(stream.id(), reason)?,
											None => {}
										}
									}
									StreamEventType::Connected => {
										debug!("conn event")?;
										match &handlers.on_connect {
											Some(on_connect) => (on_connect)(stream.id())?,
											None => {}
										}
									}
									_ => {
										warn!("unexpected event type!")?;
									}
								}

								Ok(())
							})?;
						}
						Err(e) => {
							error!("process_new_packets generated error: {}", e)?;
						}
					}

					circuit.write_tor(&mut wbuf)?;

					if wbuf.len() > 0 {
						debug!("writing {} bytes to the channel", wbuf.len(),)?;
						stream.write(&wbuf)?;
					}

					if circuit.is_built() && !tx_sent {
						tx_sent = true;
						tx.send(true)?;
					}
					debug!("circuit.built={}", circuit.is_built())?;
				}
			}
		})?;

		debug!("waiting for recv")?;
		rx.recv()?;
		debug!("recv")?;

		Ok((circuit_clone, stream_clone))
	}
}

impl StreamManager for StreamManagerImpl {
	fn open_stream<OnRead, OnConnect, OnClose>(
		&mut self,
		config: TorStreamConfig,
		handlers: TorStreamHandlers<OnRead, OnConnect, OnClose>,
	) -> Result<Box<dyn TorStream<OnRead, OnConnect, OnClose>>, Error>
	where
		OnRead: Fn(u16, &[u8]) -> Result<(), Error> + Send + 'static + Clone + Sync + Unpin,
		OnConnect: Fn(u16) -> Result<(), Error> + Send + 'static + Clone + Sync + Unpin,
		OnClose: Fn(u16, u8) -> Result<(), Error> + Send + 'static + Clone + Sync + Unpin,
	{
		debug!("opening a stream: {:?}", config)?;
		let (circuit, tcpstream) = self.get_healthy_circuit(handlers.clone())?;
		Ok(Box::new(TorStreamImpl::new(
			config, handlers, circuit, tcpstream,
		)?))
	}
}

pub struct StreamManagerBuilder {}

impl StreamManagerBuilder {
	pub fn build(config: StreamManagerConfig) -> Result<Box<impl StreamManager>, Error> {
		Ok(Box::new(StreamManagerImpl::new(config)?))
	}
}

#[cfg(test)]
mod test {
	use crate::manager::{StreamManagerBuilder, StreamManagerConfig};
	use crate::types::StreamManager;
	use crate::types::TorStreamHandlers;
	use crate::TorStreamConfig;
	use std::sync::mpsc::sync_channel;
	use std::time::Instant;

	use nioruntime_err::Error;
	use nioruntime_log::*;

	info!();

	#[test]
	fn test_manager() -> Result<(), Error> {
		/*
		let now = Instant::now();
		let mut manager = StreamManagerBuilder::build(StreamManagerConfig::default())?;
		let mut handlers = TorStreamHandlers::default();
		let (tx, rx) = sync_channel(1);

		handlers.set_on_read(move |id, data| {
			let data = std::str::from_utf8(data).unwrap_or("non-utf8 data");
			info!(
				"read data [sid={},elapsed={}s] data = '{}'",
				id,
				now.elapsed().as_millis() as f64 / 1000 as f64,
				data
			)?;
			Ok(())
		})?;
		handlers.set_on_connect(move |id| {
			info!(
				"on connect [sid={},elapsed={}s]",
				id,
				now.elapsed().as_millis() as f64 / 1000 as f64
			)?;
			tx.send(true)?;
			Ok(())
		})?;

		handlers.set_on_close(move |id, reason| {
			info!(
				"on close [sid={},elapsed={}s] reason={}",
				id,
				now.elapsed().as_millis() as f64 / 1000 as f64,
				reason
			)?;
			Ok(())
		})?;

		let mut stream = manager.open_stream(
			TorStreamConfig {
				host: "example.com".to_string(),
				port: 80,
				..Default::default()
			},
			handlers,
		)?;

		debug!("pre conn")?;
		rx.recv()?;
		debug!("write GET HTTP")?;
		stream.write(b"GET / HTTP/1.0\r\n\r\n")?;
		std::thread::park();
			*/

		Ok(())
	}
}
