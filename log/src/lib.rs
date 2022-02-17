// Copyright 2021 The BMW Developers
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

use nioruntime_deps::backtrace;
use nioruntime_deps::chrono;
use nioruntime_deps::lazy_static;
use nioruntime_deps::rand;
use nioruntime_err;

mod logger;
mod macros;

pub use crate::logger::{do_log, Log, LogConfig, RotationStatus, Settings};
pub use crate::logger::{DEBUG, ERROR, FATAL, INFO, TRACE, WARN};
pub use crate::macros::{DEFAULT_LOG_NAME, STATIC_LOG};
