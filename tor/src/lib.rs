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

mod byte_impls;
pub mod cell;
pub mod channel;
pub mod circuit;
pub mod constants;
pub mod directory;
pub mod ed25519;
pub mod handshake;
mod kdf;
pub mod keymanip;
mod process;
pub mod reader;
pub mod rsa;
pub mod stream;
pub mod types;
pub mod util;
pub mod writer;

// public
pub use crate::directory::TorDirectory;
pub use crate::ed25519::CertifiedKey;
pub use crate::rsa::{PrivateKey, PublicKey};
pub use crate::types::TorState;

/// A vector of bytes that gets cleared when it's dropped.
type SecretBytes = nioruntime_deps::zeroize::Zeroizing<Vec<u8>>;
