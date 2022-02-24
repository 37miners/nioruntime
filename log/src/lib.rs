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

//! Logging crate used with nioruntime. The crate has an extensive macro
//! library that allows for logging at the standard 5 levels and also
//! allows for specifying a log file and various options. All options can
//! be seen in the [`crate::LogConfig`] struct. This crate is largely compatible
//! with the [log](https://docs.rs/log/latest/log/) crate. So any code
//! that was written to work with that crate will work with this crate.
//! In addition to the [`trace`], [`debug`], [`info`], [`warn`], [`error`]
//! and [`fatal`] log levels, this crate provides an all version and no_ts
//! version of each macro. For example: [`info_all`] and [`info_no_ts`].
//! These macros allow for logging to standard out, no matter how the log is
//! configured and log without the timestamp respectively. The main difference
//! is that this crate returns errors so you will have to add the error handling
//! which can be as simple as using the question mark operator.
//!
//! # Examples
//!
//! ```
//! // This is a basic example showing configuration and a single logged line.
//! use nioruntime_log::*;
//! use nioruntime_err::Error;
//!
//! debug!(); // each file must set the log level before calling the macro.
//!           // this can be done at the top of the file and changed at any
//!           // scope level throughout the file.
//!
//! fn test() -> Result<(), Error> {
//!     // if the log_config! macro is not called, a default logger will be used.
//!     log_config!(nioruntime_log::LogConfig {
//!         file_path: Some("/path/to/mylog.log".to_string()),
//!         max_age_millis: 300_0000, // set log rotations to every 300 seconds (5 minutes)
//!         max_size: 100_000, // set log rotations to every 100,000 bytes
//!         ..Default::default() // use defaults for the rest of the options
//!     });
//!
//!     let value = 1;
//!     info!("This will be logged. Value: {}", value)?;
//!     Ok(())
//! }
//! ```
//!
//! ```
//! //
//! ```
//! # Using in Cargo.toml
//! To use the crate in a project add the following two line to Cargo.toml:
//! ```toml
//! [dependencies]
//! nioruntime_log = { git = "https://github.com/37miners/nioruntime" }
//! ```
//!
//! Optionally you may want to add the nioruntime_err crate to the project:
//! ```toml
//! [dependencies]
//! nioruntime_err = { git = "https://github.com/37miners/nioruntime" }
//! ```

use nioruntime_deps::backtrace;
use nioruntime_deps::chrono;
use nioruntime_deps::colored;
use nioruntime_deps::lazy_static;
use nioruntime_deps::rand;

mod logger;
mod macros;

pub use crate::logger::{do_log, Log, LogConfig, RotationStatus, Settings};
pub use crate::logger::{DEBUG, ERROR, FATAL, INFO, TRACE, WARN};
pub use crate::macros::{DEFAULT_LOG_NAME, STATIC_LOG};

#[doc(hidden)]
pub use nioruntime_deps;
#[doc(hidden)]
pub use nioruntime_err;
#[doc(hidden)]
pub use nioruntime_util;
