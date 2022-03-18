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
use nioruntime_http::{HttpConfig, HttpServer};
use nioruntime_log::*;
use std::net::SocketAddr;
use std::str::FromStr;

trace!();

fn main() -> Result<(), Error> {
	let config = HttpConfig {
		addrs: vec![
			SocketAddr::from_str("127.0.0.1:8080")?,
			SocketAddr::from_str("0.0.0.0:8081")?,
		],
		..Default::default()
	};

	let mut http = HttpServer::new(config);
	http.set_api_handler(move |_, _, _| Ok(()))?;
	http.start()?;
	std::thread::park();
	Ok(())
}
