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

use nioruntime_deps::caret::caret_int;
use nioruntime_deps::x509_signature;

mod cell;
pub mod channel;
mod client;
mod common;
mod config;
pub mod directory;
mod ed25519;
mod io;
mod rsa;
mod server;

pub const CELL_LEN: usize = 514;

caret_int! {
				/// A ChanCmd is the type of a channel cell.  The value of the ChanCmd
				/// indicates the meaning of the cell, and (possibly) its length.
				pub struct ChanCmd(u8) {
								/// A fixed-length cell that will be dropped.
								PADDING = 0,
								/// Create a new circuit (obsolete format)
								CREATE = 1,
								/// Finish circuit-creation handshake (obsolete format)
								CREATED = 2,
								/// Relay cell, transmitted over a circuit.
								RELAY = 3,
								/// Destroy a circuit
								DESTROY = 4,
								/// Create a new circuit (no public-key)
								CREATE_FAST = 5,
								/// Finish a circuit-creation handshake (no public-key)
								CREATED_FAST = 6,
								// note gap in numbering: 7 is grouped with the variable-length cells
								/// Finish a channel handshake with time and address information
								NETINFO = 8,
								/// Relay cell, transmitted over a circuit.  Limited.
								RELAY_EARLY = 9,
								/// Create a new circuit (current format)
								CREATE2 = 10,
								/// Finish a circuit-creation handshake (current format)
								CREATED2 = 11,
								/// Adjust channel-padding settings
								PADDING_NEGOTIATE = 12,

								/// Variable-length cell, despite its number: negotiate versions
								VERSIONS = 7,
								/// Variable-length channel-padding cell
								VPADDING = 128,
								/// Provide additional certificates beyond those given in the TLS
								/// handshake
								CERTS = 129,
								/// Challenge material used in relay-to-relay handshake.
								AUTH_CHALLENGE = 130,
								/// Response material used in relay-to-relay handshake.
								AUTHENTICATE = 131,
								/// Indicates client permission to use relay.  Not currently used.
								AUTHORIZE = 132,
				}
}

/*
#[derive(IntoPrimitive)]
#[repr(u8)]
/// We don't support everything for now. Just what we need to use
enum ChanCmd {
		/// Create Fast used because we've already verified as part of the initial handshake
		CreateFast = 5,

		/// Variable-length cell, despite its number: negotiate versions
		Versions = 7,
	NetInfo = 8,

	Certs = 129,
	AuthChallenge = 128,
}
*/

pub use crate::client::TorClient;
pub use crate::config::{TorClientConfig, TorServerConfig};
pub use crate::ed25519::Ed25519Cert;
pub use crate::server::TorServer;
