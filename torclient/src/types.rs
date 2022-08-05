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

use nioruntime_err::Error;
use std::pin::Pin;

pub struct TorStreamHandlers<OnRead, OnConnect, OnClose>
where
	OnRead: Fn(&[u8]) -> Result<(), Error> + Send + 'static + Clone + Sync + Unpin,
	OnConnect: Fn() -> Result<(), Error> + Send + 'static + Clone + Sync + Unpin,
	OnClose: Fn() -> Result<(), Error> + Send + 'static + Clone + Sync + Unpin,
{
	on_read: Option<Pin<Box<OnRead>>>,
	on_close: Option<Pin<Box<OnClose>>>,
	on_connect: Option<Pin<Box<OnConnect>>>,
}

impl<OnRead, OnConnect, OnClose> TorStreamHandlers<OnRead, OnConnect, OnClose>
where
	OnRead: Fn(&[u8]) -> Result<(), Error> + Send + 'static + Clone + Sync + Unpin,
	OnConnect: Fn() -> Result<(), Error> + Send + 'static + Clone + Sync + Unpin,
	OnClose: Fn() -> Result<(), Error> + Send + 'static + Clone + Sync + Unpin,
{
	pub fn set_on_read(&mut self, on_read: OnRead) -> Result<(), Error> {
		self.on_read = Some(Box::pin(on_read));
		Ok(())
	}
	pub fn set_on_connect(&mut self, on_connect: OnConnect) -> Result<(), Error> {
		self.on_connect = Some(Box::pin(on_connect));
		Ok(())
	}
	pub fn set_on_close(&mut self, on_close: OnClose) -> Result<(), Error> {
		self.on_close = Some(Box::pin(on_close));
		Ok(())
	}
}

impl<OnRead, OnConnect, OnClose> Default for TorStreamHandlers<OnRead, OnConnect, OnClose>
where
	OnRead: Fn(&[u8]) -> Result<(), Error> + Send + 'static + Clone + Sync + Unpin,
	OnConnect: Fn() -> Result<(), Error> + Send + 'static + Clone + Sync + Unpin,
	OnClose: Fn() -> Result<(), Error> + Send + 'static + Clone + Sync + Unpin,
{
	fn default() -> Self {
		Self {
			on_read: None,
			on_connect: None,
			on_close: None,
		}
	}
}

#[derive(Debug)]
pub struct TorStreamConfig {
	pub host: String,
	pub port: u16,
	pub connect_timeout: u128,
}

impl Default for TorStreamConfig {
	fn default() -> Self {
		Self {
			host: "".to_string(),
			port: 80,
			connect_timeout: 10_000,
		}
	}
}

pub trait TorStream<OnRead, OnConnect, OnClose>
where
	OnRead: Fn(&[u8]) -> Result<(), Error> + Send + 'static + Clone + Sync + Unpin,
	OnConnect: Fn() -> Result<(), Error> + Send + 'static + Clone + Sync + Unpin,
	OnClose: Fn() -> Result<(), Error> + Send + 'static + Clone + Sync + Unpin,
{
	fn write(&mut self, _: &[u8]) -> Result<(), Error>;
}

pub struct StreamManagerConfig {}

impl Default for StreamManagerConfig {
	fn default() -> Self {
		Self {}
	}
}

pub trait StreamManager {
	fn open_stream<OnRead, OnConnect, OnClose>(
		&mut self,
		config: TorStreamConfig,
		handlers: TorStreamHandlers<OnRead, OnConnect, OnClose>,
	) -> Result<Box<dyn TorStream<OnRead, OnConnect, OnClose>>, Error>
	where
		OnRead: Fn(&[u8]) -> Result<(), Error> + Send + 'static + Clone + Sync + Unpin,
		OnConnect: Fn() -> Result<(), Error> + Send + 'static + Clone + Sync + Unpin,
		OnClose: Fn() -> Result<(), Error> + Send + 'static + Clone + Sync + Unpin;
}
