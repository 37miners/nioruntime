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

use crate::stream::TorStreamImpl;
use crate::types::TorStreamHandlers;
use crate::types::{StreamManager, StreamManagerConfig, TorStream, TorStreamConfig};
use nioruntime_err::Error;
use nioruntime_log::*;
use nioruntime_tor::circuit::Circuit;
use nioruntime_tor::types::{CircuitPlan, Node};

debug!();

struct StreamManagerImpl {
	config: StreamManagerConfig,
}

impl StreamManagerImpl {
	fn new(config: StreamManagerConfig) -> Self {
		Self { config }
	}

	fn get_healthy_circuit(&mut self) -> Result<Circuit, Error> {
		// for now just build a circuit
		let node1 = Node::new(
			"104.53.221.159:9001",                          // router1
			"ZtzhbIWHJpGQG+5N7hbRTtenyzq2RNJrx0QegtoY+bY=", // ed25519Identity
			"03dOCy/Dud/kPwIzD+cbpIR+K8BxJoHIKmGsrXvJiFY=", // ntor pubkey
			"AAoQ1DAR6kkoo19hBAX5K0QztNw=",                 // rsa identity
		)?;

		let node2 = Node::new(
			"154.35.175.225:443",                           // router2
			"r/mzLbFVinqX14PW091o3jM14ifPiEO4zdVxr8BQrsI=", // ed25519Identity
			"SVcLOUxfauyHtZ08gp1SbxKPlGyhbO6oUBZBv0bYpDw=", // ntor pubkey
			"z20Kr7OFvnG44RH8XP9LR5I3M7w=",                 // rsa identity
		)?;

		let node3 = Node::new(
			"5.255.101.131:9001",
			"fKy8py24dUeTinJgQ78OW0c7BV2Q3gX24OMIDZCZQ+4=",
			"MmMf88cx87yaT1/psofamaKdEmRg07x0NStFhbOr0yc=",
			"CLSIimVm9rxTY0I4YvSFKUIKufc=",
		)?;
		let plan = CircuitPlan::new(vec![node1, node2, node3]);
		Circuit::new(plan)
	}
}

impl StreamManager for StreamManagerImpl {
	fn open_stream<OnRead, OnConnect, OnClose>(
		&mut self,
		config: TorStreamConfig,
		handlers: TorStreamHandlers<OnRead, OnConnect, OnClose>,
	) -> Result<Box<dyn TorStream<OnRead, OnConnect, OnClose>>, Error>
	where
		OnRead: Fn(&[u8]) -> Result<(), Error> + Send + 'static + Clone + Sync + Unpin,
		OnConnect: Fn() -> Result<(), Error> + Send + 'static + Clone + Sync + Unpin,
		OnClose: Fn() -> Result<(), Error> + Send + 'static + Clone + Sync + Unpin,
	{
		debug!("opening a stream: {:?}", config)?;
		let circuit = self.get_healthy_circuit()?;
		Ok(Box::new(TorStreamImpl::new(config, handlers, circuit)))
	}
}

pub struct StreamManagerBuilder {}

impl StreamManagerBuilder {
	pub fn build(config: StreamManagerConfig) -> Result<Box<impl StreamManager>, Error> {
		Ok(Box::new(StreamManagerImpl::new(config)))
	}
}
