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

pub const CELL_LEN: usize = 514;

/// A ChanCmd is the type of a channel cell.  The value of the ChanCmd
/// indicates the meaning of the cell, and (possibly) its length.

/// A fixed-length cell that will be dropped.
pub const CHAN_CMD_PADDING: u8 = 0;
/// Create a new circuit (obsolete format)
pub const CHAN_CMD_CREATE: u8 = 1;
/// Finish circuit-creation handshake (obsolete format)
pub const CHAN_CMD_CREATED: u8 = 2;
/// Relay cell, transmitted over a circuit.
pub const CHAN_CMD_RELAY: u8 = 3;
/// Destroy a circuit
pub const CHAN_CMD_DESTROY: u8 = 4;
/// Create a new circuit (no public-key)
pub const CHAN_CMD_CREATE_FAST: u8 = 5;
/// Finish a circuit-creation handshake (no public-key)
pub const CHAN_CMD_CREATED_FAST: u8 = 6;
// note gap in numbering: 7 is grouped with the variable-length cells
/// Finish a channel handshake with time and address information
pub const CHAN_CMD_NETINFO: u8 = 8;
/// Relay cell, transmitted over a circuit.  Limited.
pub const CHAN_CMD_RELAY_EARLY: u8 = 9;
/// Create a new circuit (current format)
pub const CHAN_CMD_CREATE2: u8 = 10;
/// Finish a circuit-creation handshake (current format)
pub const CHAN_CMD_CREATED2: u8 = 11;
/// Adjust channel-padding settings
pub const CHAN_CMD_PADDING_NEGOTIATE: u8 = 12;
/// Variable-length cell, despite its number: negotiate versions
pub const CHAN_CMD_VERSIONS: u8 = 7;
/// Variable-length channel-padding cell
pub const CHAN_CMD_VPADDING: u8 = 128;
/// Provide additional certificates beyond those given in the TLS
/// handshake
pub const CHAN_CMD_CERTS: u8 = 129;
/// Challenge material used in relay-to-relay handshake.
pub const CHAN_CMD_AUTH_CHALLENGE: u8 = 130;
/// Response material used in relay-to-relay handshake.
pub const CHAN_CMD_AUTHENTICATE: u8 = 131;
/// Indicates client permission to use relay.  Not currently used.
pub const CHAN_CMD_AUTHORIZE: u8 = 132;

/// Relay command for extended2
pub const RELAY_CMD_BEGIN: u8 = 1;
pub const RELAY_CMD_DATA: u8 = 2;
pub const RELAY_CMD_END: u8 = 3;
pub const RELAY_CMD_EXTEND2: u8 = 14;
pub const RELAY_CMD_EXTENDED2: u8 = 15;

/// How many bytes are in an "RSA ID"?  (This is a legacy tor
/// concept, and refers to identifying a relay by a SHA1 digest
/// of its RSA public identity key.)
pub const RSA_ID_LEN: usize = 20;

/// length of the ntor onion key.
pub const ED25519_LEN: usize = 32;

pub const HANDSHAKE_TYPE_NTOR: [u8; 2] = [0, 2];
