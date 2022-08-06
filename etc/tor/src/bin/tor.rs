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

use nioruntime_torclient::{
	StreamManager, StreamManagerBuilder, StreamManagerConfig, TorStreamConfig, TorStreamHandlers,
};
use std::sync::mpsc::sync_channel;
use std::time::Instant;

use nioruntime_err::Error;
use nioruntime_log::*;

debug!();

fn main() -> Result<(), Error> {
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
	Ok(())
}
