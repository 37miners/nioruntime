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

use crate::lazy_static::lazy_static;
use crate::Log;
use std::collections::HashMap;
use std::sync::{Arc, RwLock};

lazy_static! {
	/// This is the static holder of all log objects. Generally this
	/// should not be called directly. See [`log`] instead.
	#[doc(hidden)]
	pub static ref STATIC_LOG: Arc<RwLock<HashMap<String, Log>>> = Arc::new(RwLock::new(HashMap::new()));
	#[doc(hidden)]
	pub static ref DEFAULT_LOG_NAME: Arc<RwLock<String>> = Arc::new(RwLock::new("default".to_string()));
}

#[macro_export]
/// This macro is used to get/set the default log name. If no parameters are specified, the current default
/// log name is returned. If a &str is specified, the default log name is set to that value.
///
/// # Examples
/// ```
///
/// use nioruntime_log::*;
/// use nioruntime_err::Error;
/// trace!();
///
/// fn test() -> Result<(), Error> {
///     const LOGA: &str = "loga";
///     const LOGB: &str = "logb";
///     log_config_multi!(LOGA, LogConfig {
///         show_timestamp: false,
///         ..Default::default()
///     })?;
///
///     log_config_multi!(LOGB, LogConfig {
///         show_log_level: false,
///         ..Default::default()
///     })?;
///
///     log_multi!(INFO, LOGA, "a0123456789")?;
///     log_multi!(INFO, LOGB, "b0123456789")?;
///
///     default_log_name!(LOGA);
///     debug!("a")?; // logged to log a.
///
///     Ok(())
/// }
///
/// ```
macro_rules! default_log_name {
	() => {{
		match nioruntime_log::lockw!(nioruntime_log::DEFAULT_LOG_NAME) {
			Ok(default_log_name) => (*default_log_name).clone(),
			Err(_e) => "default".to_string(),
		}
	}};
	($name:expr) => {{
		match nioruntime_log::lockw!(nioruntime_log::DEFAULT_LOG_NAME) {
			Ok(mut default_log_name) => {
				*default_log_name = $name.to_string();
			}
			Err(_e) => {}
		}
	}};
}

/// Log at the 'fatal' (5) log level. This macro calls the default logger. To configure this
/// logger, see [`log_config`]. It is used like the println/format macros.
/// Also see [`trace`] [`debug`], [`info`], [`warn`], or [`error`].
/// # Examples
/// ```
/// use nioruntime_log::*;
/// use nioruntime_err::Error;
/// // log level must be set before calling any logging function.
/// // typically it is done at the top of a file so that it's easy to change.
/// // but it can be done at any level or scope. The inner scope prevails.
/// fatal!(); // set log level to fatal "5"
///
/// fn test() -> Result<(), Error> {
///     let abc = 123;
///     fatal!("my value = {}", abc);
///     fatal_all!("hi");
///     fatal_no_ts!("no timestamp shown");
///     Ok(())
/// }
///
/// // The output will look something like this:
/// // [2022-02-16 19:37:48]: (FATAL) [..c/perf/src/bin/perf.rs:85]: my value = 123
/// // [2022-02-16 19:37:48]: (FATAL) [..c/perf/src/bin/perf.rs:86]: hi
/// // no timestamp shown
/// ```
#[macro_export]
macro_rules! fatal {
	() => {
		nioruntime_log::do_log!(nioruntime_log::FATAL);
	};
	($a:expr) => {
		{
			match LOG_LEVEL <= nioruntime_log::FATAL {
				true => {
					let default = nioruntime_log::default_log_name!();
					nioruntime_log::log_multi!(nioruntime_log::FATAL, &default, $a)
				},
				false => Ok(()),
			}
		}
	};
	($a:expr,$($b:tt)*)=>{
		{
                        match LOG_LEVEL <= nioruntime_log::FATAL {
                                true => {
                                        let default = nioruntime_log::default_log_name!();
                                        nioruntime_log::log_multi!(nioruntime_log::FATAL, &default, $a, $($b)*)
                                },
                                false => Ok(()),
                        }
		}
	};
}

/// Just like [`fatal`], but with no timestamp or other information. Just the raw line.
#[macro_export]
macro_rules! fatal_no_ts {
	($a:expr) => {
		{
                        match LOG_LEVEL <= nioruntime_log::FATAL {
                                true => {
					let default = nioruntime_log::default_log_name!();
					nioruntime_log::log_multi_no_ts!(nioruntime_log::FATAL, &default, $a)
                                },
                                false => Ok(()),
                        }
		}
	};
	($a:expr,$($b:tt)*)=>{
		{
                        match LOG_LEVEL <= nioruntime_log::FATAL {
                                true => {
					let default = nioruntime_log::default_log_name!();
					nioruntime_log::log_multi_no_ts!(nioruntime_log::FATAL, &default, $a, $($b)*)
                                },
                                false => Ok(()),
                        }
		}
	};
}

/// Just like [`fatal`], but the line is also logged to stdout regardless of the current
/// configuration.
#[macro_export]
macro_rules! fatal_all {
	($a:expr) => {
		{
                        match LOG_LEVEL <= nioruntime_log::FATAL {
                                true => {
					let default = nioruntime_log::default_log_name!();
					nioruntime_log::log_multi_all!(nioruntime_log::FATAL, &default, $a)
                                },
                                false => Ok(()),
                        }
		}
	};
	($a:expr,$($b:tt)*)=>{
		{
                        match LOG_LEVEL <= nioruntime_log::FATAL {
                                true => {
					let default = nioruntime_log::default_log_name!();
					nioruntime_log::log_multi_all!(nioruntime_log::FATAL, &default, $a, $($b)*)
                                },
                                false => Ok(()),
                        }
		}
	};
}

/// Log at the 'error' (4) log level. This macro calls the default logger. To configure this
/// logger, see [`log_config`]. It is used like the println/format macros.
/// Also see [`trace`], [`debug`], [`info`], [`warn`], or [`fatal`].
/// # Examples
/// ```
/// use nioruntime_log::*;
/// use nioruntime_err::Error;
/// // log level must be set before calling any logging function.
/// // typically it is done at the top of a file so that it's easy to change.
/// // but it can be done at any level or scope. The inner scope prevails.
/// error!(); // set log level to error "4"
///
///
/// fn test() -> Result<(), Error> {
///     let abc = 123;
///     error!("my value = {}", abc);
///     error_all!("hi");
///     error_no_ts!("no timestamp shown");
///     Ok(())
/// }
///
/// // The output will look something like this:
/// // [2022-02-16 19:37:48]: (ERROR) [..c/perf/src/bin/perf.rs:85]: my value = 123
/// // [2022-02-16 19:37:48]: (ERROR) [..c/perf/src/bin/perf.rs:86]: hi
/// // no timestamp shown
/// ```
#[macro_export]
macro_rules! error {
	() => {
		nioruntime_log::do_log!(nioruntime_log::ERROR);
	};
	($a:expr) => {
		{
                        match LOG_LEVEL <= nioruntime_log::ERROR {
                                true => {
					let default = nioruntime_log::default_log_name!();
					nioruntime_log::log_multi!(nioruntime_log::ERROR, &default, $a)
                                },
                                false => Ok(()),
                        }
		}
	};
	($a:expr,$($b:tt)*)=>{
		{
                        match LOG_LEVEL <= nioruntime_log::ERROR {
                                true => {
					let default = nioruntime_log::default_log_name!();
					nioruntime_log::log_multi!(nioruntime_log::ERROR, &default, $a, $($b)*)
                                },
                                false => Ok(()),
                        }
		}
	};
}

/// Just like [`error`], but with no timestamp or other information. Just the raw line.
#[macro_export]
macro_rules! error_no_ts {
	($a:expr) => {
		{
                        match LOG_LEVEL <= nioruntime_log::ERROR {
                                true => {
					let default = nioruntime_log::default_log_name!();
					nioruntime_log::log_multi_no_ts!(nioruntime_log::ERROR, &default, $a)
                                },
                                false => Ok(()),
                        }
		}
	};
	($a:expr,$($b:tt)*)=>{
		{
                        match LOG_LEVEL <= nioruntime_log::ERROR {
                                true => {
					let default = nioruntime_log::default_log_name!();
					nioruntime_log::log_multi_no_ts!(nioruntime_log::ERROR, &default, $a, $($b)*)
                                },
                                false => Ok(()),
                        }
		}
	};
}

/// Just like [`error`], but the line is also logged to stdout regardless of the current
/// configuration.
#[macro_export]
macro_rules! error_all {
	($a:expr) => {
		{
                        match LOG_LEVEL <= nioruntime_log::ERROR {
                                true => {
					let default = nioruntime_log::default_log_name!();
					nioruntime_log::log_multi_all!(nioruntime_log::ERROR, &default, $a)
                                },
                                false => Ok(()),
                        }
		}
	};
	($a:expr,$($b:tt)*)=>{
		{
                        match LOG_LEVEL <= nioruntime_log::ERROR {
                                true => {
					let default = nioruntime_log::default_log_name!();
					nioruntime_log::log_multi_all!(nioruntime_log::ERROR, &default, $a, $($b)*)
                                },
                                false => Ok(()),
                        }
		}
	};
}

/// Log at the 'warn' (3) log level. This macro calls the default logger. To configure this
/// logger, see [`log_config`]. It is used like the println/format macros.
/// Also see [`trace`], [`debug`], [`info`], [`error`], or [`fatal`].
/// # Examples
/// ```
/// use nioruntime_log::*;
/// use nioruntime_err::Error;
/// // log level must be set before calling any logging function.
/// // typically it is done at the top of a file so that it's easy to change.
/// // but it can be done at any level or scope. The inner scope prevails.
/// warn!(); // set log level to warn "3"
///
///
/// fn test() -> Result<(), Error> {
///     let abc = 123;
///     warn!("my value = {}", abc);
///     warn_all!("hi");
///     warn_no_ts!("no timestamp shown");
///     Ok(())
/// }
///
/// // The output will look something like this:
/// // [2022-02-16 19:37:48]: (WARN) [..c/perf/src/bin/perf.rs:85]: my value = 123
/// // [2022-02-16 19:37:48]: (WARN) [..c/perf/src/bin/perf.rs:86]: hi
/// // no timestamp shown
/// ```
#[macro_export]
macro_rules! warn {
	() => {
		nioruntime_log::do_log!(nioruntime_log::WARN);
	};
	($a:expr) => {
		{
                        match LOG_LEVEL <= nioruntime_log::WARN {
                                true => {
					let default = nioruntime_log::default_log_name!();
					nioruntime_log::log_multi!(nioruntime_log::WARN, &default, $a)
                                },
                                false => Ok(()),
                        }
		}
	};
	($a:expr,$($b:tt)*)=>{
		{
                        match LOG_LEVEL <= nioruntime_log::WARN {
                                true => {
					let default = nioruntime_log::default_log_name!();
					nioruntime_log::log_multi!(nioruntime_log::WARN, &default, $a, $($b)*)
                                },
                                false => Ok(()),
                        }
		}
	};
}

/// Just like [`warn`], but with no timestamp or other information. Just the raw line.
#[macro_export]
macro_rules! warn_no_ts {
	($a:expr) => {
		{
                        match LOG_LEVEL <= nioruntime_log::WARN {
                                true => {
					let default = nioruntime_log::default_log_name!();
					nioruntime_log::log_multi_no_ts!(nioruntime_log::WARN, &default, $a)
                                },
                                false => Ok(()),
                        }
		}
	};
	($a:expr,$($b:tt)*)=>{
		{
                        match LOG_LEVEL <= nioruntime_log::WARN {
                                true => {
					let default = nioruntime_log::default_log_name!();
					nioruntime_log::log_multi_no_ts!(nioruntime_log::WARN, &default, $a, $($b)*)
                                },
                                false => Ok(()),
                        }
		}
	};
}

/// Just like [`warn`], but the line is also logged to stdout regardless of the current
/// configuration.
#[macro_export]
macro_rules! warn_all {
	($a:expr) => {
		{
                        match LOG_LEVEL <= nioruntime_log::WARN {
                                true => {
					let default = nioruntime_log::default_log_name!();
					nioruntime_log::log_multi_all!(nioruntime_log::WARN, &default, $a)
                                },
                                false => Ok(()),
                        }
		}
	};
	($a:expr,$($b:tt)*)=>{
		{
                        match LOG_LEVEL <= nioruntime_log::WARN {
                                true => {
					let default = nioruntime_log::default_log_name!();
					nioruntime_log::log_multi_all!(nioruntime_log::WARN, &default, $a, $($b)*)
                                },
                                false => Ok(()),
                        }
		}
	};
}

/// Log at the 'info' (2) log level. This macro calls the default logger. To configure this
/// logger, see [`log_config`]. It is used like the println/format macros.
/// Also see [`trace`], [`debug`], [`warn`], [`error`], or [`fatal`].
/// # Examples
/// ```
/// use nioruntime_log::*;
/// use nioruntime_err::Error;
/// // log level must be set before calling any logging function.
/// // typically it is done at the top of a file so that it's easy to change.
/// // but it can be done at any level or scope. The inner scope prevails.
/// info!(); // set log level to info "2"
///
/// fn test() -> Result<(), Error> {
///     let abc = 123;
///     info!("my value = {}", abc);
///     info_all!("hi");
///     info_no_ts!("no timestamp shown");
///     Ok(())
/// }
/// // The output will look something like this:
/// // [2022-02-16 19:37:48]: (INFO) [..c/perf/src/bin/perf.rs:85]: my value = 123
/// // [2022-02-16 19:37:48]: (INFO) [..c/perf/src/bin/perf.rs:86]: hi
/// // no timestamp shown
/// ```
#[macro_export]
macro_rules! info {
	() => {
		nioruntime_log::do_log!(nioruntime_log::INFO);
	};
	($a:expr) => {
		{
                        match LOG_LEVEL <= nioruntime_log::INFO {
                                true => {
					let default = nioruntime_log::default_log_name!();
					nioruntime_log::log_multi!(nioruntime_log::INFO, &default, $a)
                                },
                                false => Ok(()),
                        }
		}
	};
	($a:expr,$($b:tt)*)=>{
		{
                        match LOG_LEVEL <= nioruntime_log::INFO {
                                true => {
					let default = nioruntime_log::default_log_name!();
					nioruntime_log::log_multi!(nioruntime_log::INFO, &default, $a, $($b)*)
                                },
                                false => Ok(()),
                        }
		}
	};
}

/// Just like [`info`], but with no timestamp or other information. Just the raw line.
#[macro_export]
macro_rules! info_no_ts {
	($a:expr) => {
		{
                        match LOG_LEVEL <= nioruntime_log::INFO {
                                true => {
					let default = nioruntime_log::default_log_name!();
					nioruntime_log::log_multi_no_ts!(nioruntime_log::INFO, &default, $a)
                                },
                                false => Ok(()),
                        }
		}
	};
	($a:expr,$($b:tt)*)=>{
		{
                        match LOG_LEVEL <= nioruntime_log::INFO {
                                true => {
					let default = nioruntime_log::default_log_name!();
					nioruntime_log::log_multi_no_ts!(nioruntime_log::INFO, &default, $a, $($b)*)
                                },
                                false => Ok(()),
                        }
		}
	};
}

/// Just like [`info`], but the line is also logged to stdout regardless of the current
/// configuration.
#[macro_export]
macro_rules! info_all {
	($a:expr) => {
		{
                        match LOG_LEVEL <= nioruntime_log::INFO {
                                true => {
					let default = nioruntime_log::default_log_name!();
					nioruntime_log::log_multi_all!(nioruntime_log::INFO, &default, $a)
                                },
                                false => Ok(()),
                        }
		}
	};
	($a:expr,$($b:tt)*)=>{
		{
                        match LOG_LEVEL <= nioruntime_log::INFO {
                                true => {
					let default = nioruntime_log::default_log_name!();
					nioruntime_log::log_multi_all!(nioruntime_log::INFO, &default, $a, $($b)*)
                                },
                                false => Ok(()),
                        }
		}
	};
}

/// Log at the 'debug' (1) log level. This macro calls the default logger. To configure this
/// logger, see [`log_config`]. It is used like the println/format macros.
/// Also see [`trace`], [`info`], [`warn`], [`error`], or [`fatal`].
/// # Examples
/// ```
/// use nioruntime_log::*;
/// use nioruntime_err::Error;
/// // log level must be set before calling any logging function.
/// // typically it is done at the top of a file so that it's easy to change.
/// // but it can be done at any level or scope. The inner scope prevails.
/// debug!(); // set log level to debug "1"
///
///
/// fn test() -> Result<(), Error> {
///     let abc = 123;
///     debug!("my value = {}", abc)?;
///     debug_all!("hi")?;
///     debug_no_ts!("no timestamp shown")?;
///     Ok(())
/// }
///
/// // The output will look something like this:
/// // [2022-02-16 19:37:48]: (DEBUG) [..c/perf/src/bin/perf.rs:85]: my value = 123
/// // [2022-02-16 19:37:48]: (DEBUG) [..c/perf/src/bin/perf.rs:86]: hi
/// // no timestamp shown
/// ```

#[macro_export]
macro_rules! debug {
	() => {
		nioruntime_log::do_log!(nioruntime_log::DEBUG);
	};
	($a:expr) => {
		{
                        match LOG_LEVEL <= nioruntime_log::DEBUG {
                                true => {
					let default = nioruntime_log::default_log_name!();
					nioruntime_log::log_multi!(nioruntime_log::DEBUG, &default, $a)
                                },
                                false => Ok(()),
                        }
		}
	};
	($a:expr,$($b:tt)*)=>{
		{
                        match LOG_LEVEL <= nioruntime_log::DEBUG {
                                true => {
					let default = nioruntime_log::default_log_name!();
					nioruntime_log::log_multi!(nioruntime_log::DEBUG, &default, $a, $($b)*)
                                },
                                false => Ok(()),
                        }
		}
	};
}

/// Just like [`debug`], but with no timestamp or other information. Just the raw line.
#[macro_export]
macro_rules! debug_no_ts {
	($a:expr) => {
		{
                        match LOG_LEVEL <= nioruntime_log::DEBUG {
                                true => {
					let default = nioruntime_log::default_log_name!();
					nioruntime_log::log_multi_no_ts!(nioruntime_log::DEBUG, &default, $a)
                                },
                                false => Ok(()),
                        }
		}
	};
	($a:expr,$($b:tt)*)=>{
		{
                        match LOG_LEVEL <= nioruntime_log::DEBUG {
                                true => {
					let default = nioruntime_log::default_log_name!();
					nioruntime_log::log_multi_no_ts!(nioruntime_log::DEBUG, &default, $a, $($b)*)
                                },
                                false => Ok(()),
                        }
		}
	};
}

/// Just like [`debug`], but the line is also logged to stdout regardless of the current
/// configuration.
#[macro_export]
macro_rules! debug_all {
	($a:expr) => {
		{
                        match LOG_LEVEL <= nioruntime_log::DEBUG {
                                true => {
					let default = nioruntime_log::default_log_name!();
					nioruntime_log::log_multi_all!(nioruntime_log::DEBUG, &default, $a)
                                },
                                false => Ok(()),
                        }
		}
	};
	($a:expr,$($b:tt)*)=>{
		{
                        match LOG_LEVEL <= nioruntime_log::DEBUG {
                                true => {
					let default = nioruntime_log::default_log_name!();
					nioruntime_log::log_multi_all!(nioruntime_log::DEBUG, &default, $a, $($b)*)
                                },
                                false => Ok(()),
                        }
		}
	};
}

/// Log at the 'trace' (0) log level. This macro calls the default logger. To configure this
/// logger, see [`log_config`]. It is used like the println/format macros.
/// Also see [`debug`], [`info`], [`warn`], [`error`], or [`fatal`].
/// # Examples
/// ```
/// use nioruntime_log::*;
/// use nioruntime_err::Error;
/// // log level must be set before calling any logging function.
/// // typically it is done at the top of a file so that it's easy to change.
/// // but it can be done at any level or scope. The inner scope prevails.
/// trace!(); // set log level to trace "0"
///
///
/// fn test() -> Result<(), Error> {
///     let abc = 123;
///     trace!("my value = {}", abc);
///     trace_all!("hi");
///     trace_no_ts!("no timestamp shown");
///     Ok(())
/// }
///
/// // The output will look something like this:
/// // [2022-02-16 19:37:48]: (TRACE) [..c/perf/src/bin/perf.rs:85]: my value = 123
/// // [2022-02-16 19:37:48]: (TRACE) [..c/perf/src/bin/perf.rs:86]: hi
/// // no timestamp shown
/// ```
#[macro_export]
macro_rules! trace {
	() => {
		nioruntime_log::do_log!(nioruntime_log::TRACE);
	};
	($a:expr) => {
		{
                        match LOG_LEVEL <= nioruntime_log::TRACE {
                                true => {
					let default = nioruntime_log::default_log_name!();
					nioruntime_log::log_multi!(nioruntime_log::TRACE, &default, $a)
				},
				false => Ok(()),
			}
		}
	};
	($a:expr,$($b:tt)*)=>{
		{
                        match LOG_LEVEL <= nioruntime_log::TRACE {
                                true => {
					let default = nioruntime_log::default_log_name!();
					nioruntime_log::log_multi!(nioruntime_log::TRACE, &default, $a, $($b)*)
				},
				false => Ok(()),
			}

		}
	};
}

/// Just like [`trace`], but with no timestamp or other information. Just the raw line.
#[macro_export]
macro_rules! trace_no_ts {
	($a:expr) => {
		{
                        match LOG_LEVEL <= nioruntime_log::TRACE {
                                true => {
					let default = nioruntime_log::default_log_name!();
					nioruntime_log::log_multi_no_ts!(nioruntime_log::TRACE, &default, $a)
                                },
                                false => Ok(()),
                        }
		}
	};
	($a:expr,$($b:tt)*)=>{
		{
                        match LOG_LEVEL <= nioruntime_log::TRACE {
                                true => {
					let default = nioruntime_log::default_log_name!();
					nioruntime_log::log_multi_no_ts!(nioruntime_log::TRACE, &default, $a, $($b)*)
                                },
                                false => Ok(()),
                        }
		}
	};
}

/// Just like [`trace`], but the line is also logged to stdout regardless of the current
/// configuration.
#[macro_export]
macro_rules! trace_all {
	($a:expr) => {
		{
                        match LOG_LEVEL <= nioruntime_log::TRACE {
                                true => {
					let default = nioruntime_log::default_log_name!();
					nioruntime_log::log_multi_all!(nioruntime_log::TRACE, &default, $a)
                                },
                                false => Ok(()),
                        }
		}
	};
	($a:expr,$($b:tt)*)=>{
		{
                        match LOG_LEVEL <= nioruntime_log::TRACE {
                                true => {
					let default = nioruntime_log::default_log_name!();
					nioruntime_log::log_multi_all!(nioruntime_log::TRACE, &default, $a, $($b)*)
                                },
                                false => Ok(()),
                        }
		}
	};
}

/// Same as [`log_multi`] except that the log line is logged to stdout as well, no matter
/// what the existing configuration is. To configure this
/// logger, see [`log_config_multi`]. It is used like the println/format macros. The first
/// parameter is the log level. To avoid specifying level, see [`trace_all`], [`debug_all`],
/// [`info_all`], [`warn_all`], [`error_all`], or [`fatal_all`].
/// # Examples
/// ```
/// use nioruntime_log::*;
/// use nioruntime_err::Error;
/// // log level must be set before calling any logging function.
/// // typically it is done at the top of a file so that it's easy to change.
/// // but it can be done at any level or scope. The inner scope prevails.
/// info!(); // set log level to info "2"
///
/// const MAIN_LOG: &str = "mainlog";
///
/// fn test() -> Result<(), Error> {
///     let abc = 123;
///     log_multi_all!(INFO, MAIN_LOG, "my value = {}", abc);
///     log_multi_all!(WARN, MAIN_LOG, "hi");
///     Ok(())
/// }
///
/// // The output will look something like this:
/// // [2022-02-16 19:37:48]: (INFO) [..c/perf/src/bin/perf.rs:85]: my value = 123
/// // [2022-02-16 19:37:48]: (WARN) [..c/perf/src/bin/perf.rs:86]: hi
/// ```
#[macro_export]
macro_rules! log_multi_all {
	($level:expr, $a:expr, $b:expr) => {{
                match LOG_LEVEL <= $level {
                	true => {
				// TODO: there's a possiblity that two threads could log at the same time
				// and set this option on one another. Make it use a single lock.
				let stdout_cur = nioruntime_log::get_config_option!(
					nioruntime_log::Settings::Stdout
				).unwrap_or(true);

				nioruntime_log::set_config_option!(
					nioruntime_log::Settings::Stdout, true
				).ok();

				let res: Result<(), nioruntime_err::Error> =
					nioruntime_log::log_multi!($level, $a, $b);

				nioruntime_log::set_config_option!(
					nioruntime_log::Settings::Stdout, stdout_cur
				).ok();

				res
			},
			false => Ok(()),
		}

	}};
	($level:expr, $a:expr,$b:expr,$($c:tt)*)=> {{
                match LOG_LEVEL <= $level {
                        true => {
				let mut res: Result<(), nioruntime_err::Error>;

				let stdout_cur = nioruntime_log::get_config_option!(
					nioruntime_log::Settings::Stdout
				).unwrap_or(true);

				res = nioruntime_log::set_config_option!(
					nioruntime_log::Settings::Stdout, true
				);

				if res.is_ok() {
					res = nioruntime_log::log_multi!($level, $a, $b, $($c)*);
				}

				if res.is_ok() {
					res = nioruntime_log::set_config_option!(
						nioruntime_log::Settings::Stdout, stdout_cur
					);
				}

				res
                        },
                        false => Ok(()),
                }
	}};
}

/// The main logging macro for use with multiple loggers. To configure this
/// logger, see [`log_config_multi`]. It is used like the println/format macros. The first
/// parameter is the log level. To avoid specifying level, see [`trace`], [`debug`],
/// [`info`], [`warn`], [`error`], or [`fatal`].
/// # Examples
/// ```
/// use nioruntime_log::*;
/// use nioruntime_err::Error;
/// // log level must be set before calling any logging function.
/// // typically it is done at the top of a file so that it's easy to change.
/// // but it can be done at any level or scope. The inner scope prevails.
/// info!(); // set log level to info "2"
///
/// const MAIN_LOG: &str = "mainlog";
///
/// fn test() -> Result<(), Error> {
///     let abc = 123;
///     log_multi!(INFO, MAIN_LOG, "my value = {}", abc);
///     log_multi!(WARN, MAIN_LOG, "hi");
///     Ok(())
/// }
///
/// // The output will look something like this:
/// // [2022-02-16 19:37:48]: (INFO) [..c/perf/src/bin/perf.rs:85]: my value = 123
/// // [2022-02-16 19:37:48]: (WARN) [..c/perf/src/bin/perf.rs:86]: hi
/// ```
#[macro_export]
macro_rules! log_multi {
	($level:expr, $a:expr, $b:expr) => {{
                match LOG_LEVEL <= $level {
                        true => {
				let res: Result<(), nioruntime_err::Error>;
				match nioruntime_log::lockw!(nioruntime_log::STATIC_LOG) {
					Ok(mut log_map) => {
						let mut log = log_map.get_mut($a);
						match log {
			       				Some(ref mut log) => {
			       					res = nioruntime_log::do_log!($level, true, log, $b);
			       				},
			       				None => {
			       					let mut log = nioruntime_log::Log::new();
			       					res = nioruntime_log::do_log!($level, true, &mut log, $b);
			       					log_map.insert($a.to_string(), log);
			       				}
						}
					}
					Err(e) => {
						res = Err(
							nioruntime_err::ErrorKind::LogError(
								format!(
									"couldn't obtain lock due to: {}",
									e
								)
							).into()
						);
					}
				}
				res
                        },
                        false => Ok(()),
                }
	}};
	($level:expr, $a:expr,$b:expr,$($c:tt)*)=> {{
		match LOG_LEVEL <= $level {
                        true => {
				let res: Result<(), nioruntime_err::Error>;
				match nioruntime_log::lockw!(nioruntime_log::STATIC_LOG) {
					Ok(mut log_map) => {
						let mut log = log_map.get_mut($a);
						match log {
							Some(ref mut log) => {
								res = nioruntime_log::do_log!($level, true, log, $b, $($c)*);
							},
							None => {
								let mut log = nioruntime_log::Log::new();
								res = nioruntime_log::do_log!($level, true, &mut log, $b, $($c)*);
								log_map.insert($a.to_string(), log);
							}
						}
					}
					Err(e) => {
						res = Err(
							nioruntime_err::ErrorKind::LogError(
								format!(
									"couldn't obtain lock due to: {}",
									e
								)
							).into()
						);
					}
				}
				res
                        },
                        false => Ok(()),
                }
	}};
}

/// The main logging macro. This macro calls the default logger. To configure this
/// logger, see [`log_config`]. It is used like the println/format macros. The first
/// parameter is the log level. To avoid specifying level, see [`trace`], [`debug`],
/// [`info`], [`warn`], [`error`], or [`fatal`].
/// # Examples
/// ```
/// use nioruntime_log::*;
/// use nioruntime_err::Error;
/// // log level must be set before calling any logging function.
/// // typically it is done at the top of a file so that it's easy to change.
/// // but it can be done at any level or scope. The inner scope prevails.
/// info!(); // set log level to info "2"
///
/// fn test() -> Result<(), Error> {
///     let abc = 123;
///     log!(INFO, "my value = {}", abc);
///     log!(WARN, "hi");
///     Ok(())
/// }
///
/// // The output will look something like this:
/// // [2022-02-16 19:37:48]: (INFO) [..c/perf/src/bin/perf.rs:85]: my value = 123
/// // [2022-02-16 19:37:48]: (WARN) [..c/perf/src/bin/perf.rs:86]: hi
/// ```
#[macro_export]
macro_rules! log {
       ($level:expr, $a:expr)=>{
		{
			match LOG_LEVEL <= $level {
                        	true => {
					let default = nioruntime_log::default_log_name!();
					nioruntime_log::log_multi!($level, &default, $a)
                	        },
                        	false => Ok(()),
                	}
		}
	};
	($level:expr, $a:expr, $($b:tt)*)=>{
		{
                	match LOG_LEVEL <= $level {
                        	true => {
					let default = nioruntime_log::default_log_name!();
					nioruntime_log::log_multi!($level, &default, $a, $($b)*)
                	        },
                        	false => Ok(()),
                	}
		}
	};
}

/// Just like [`log`], but the line is also logged to stdout regardless of the current
/// configuration.
#[macro_export]
macro_rules! log_all {
	($level:expr, $a:expr) => {
		{
                	match LOG_LEVEL <= $level {
                        	true => {
					let default = nioruntime_log::default_log_name!();
					nioruntime_log::log_multi_all!($level, &default, $a)
                        	},
                        	false => Ok(()),
                	}
		}
	};
	($level:expr, $a:expr,$($b:tt)*)=>{
		{
                	match LOG_LEVEL <= $level {
                        	true => {
					let default = nioruntime_log::default_log_name!();
					nioruntime_log::log_multi_all!($level, &default, $a, $($b)*)
                	        },
                        	false => Ok(()),
                	}
		}
	};
}

/// Set various options for the logger after initialization.
/// The settings supported are specified in the [`crate::logger::Settings`] enumeration.
///
/// # Examples
/// ```
/// use nioruntime_log::*;
/// use nioruntime_err::Error;
///
/// const MAIN_LOG: &str = "mainlog";
/// info!(); // set log level to info "2"
///
/// fn test() -> Result<(), Error> {
///     let original_stdout_setting = get_config_option!(Settings::Stdout)?;
///     let original_timestamp_setting = get_config_option!(Settings::Timestamp)?;
///     let original_log_level_setting = get_config_option!(Settings::Level)?;
///     let original_line_num_setting = get_config_option!(Settings::LineNum)?;
///
///     set_config_option!(Settings::Stdout, true);
///     set_config_option!(Settings::Timestamp, true);
///     set_config_option!(Settings::Level, true);
///     set_config_option!(Settings::LineNum, true);
///
///     log!(INFO, "some data");
///     set_config_option!(Settings::Stdout, original_stdout_setting);
///     set_config_option!(Settings::Stdout, original_timestamp_setting);
///     set_config_option!(Settings::Stdout, original_log_level_setting);
///     set_config_option!(Settings::Stdout, original_line_num_setting);
///     log!(INFO, "hi");
///
///
///     // this macro may also specify a particular logger instead of the default logger. To
///     // do that, specify the first parameter as the name of the logger.
///
///     set_config_option!(MAIN_LOG, Settings::Timestamp, true);
///     log_multi!(WARN, MAIN_LOG, "test");
///     set_config_option!(MAIN_LOG, Settings::Timestamp, false);
///     log_multi!(WARN, MAIN_LOG, "test");
///     Ok(())
/// }
///
/// ```
#[macro_export]
macro_rules! get_config_option {
	($get_type:expr) => {{
		nioruntime_log::get_config_option!("default", $get_type)
	}};
	($log:expr,$get_type:expr) => {{
		match nioruntime_log::lockw!(nioruntime_log::STATIC_LOG) {
			Ok(mut log_map) => {
				let log = log_map.get_mut($log);
				match log {
					Some(log) => match $get_type {
						nioruntime_log::Settings::Stdout => log.get_show_stdout(),
						nioruntime_log::Settings::LineNum => log.get_show_line_num(),
						nioruntime_log::Settings::Level => log.get_show_log_level(),
						nioruntime_log::Settings::Timestamp => log.get_show_timestamp(),
					},
					None => {
						let error: nioruntime_err::Error =
							nioruntime_err::ErrorKind::LogConfigurationError(
								"no config found".to_string(),
							)
							.into();
						Err(error)
					}
				}
			}
			Err(e) => Err(e),
		}
	}};
}

/// Set various options for the logger after initialization.
/// The settings supported are specified in the [`crate::logger::Settings`] enumeration.
///
/// # Examples
/// ```
/// use nioruntime_log::*;
/// use nioruntime_err::Error;
///
/// const MAIN_LOG: &str = "mainlog";
/// info!(); // set log level to info "2"
///
/// fn test() -> Result<(), Error> {
///
///     let abc = 123;
///     set_config_option!(Settings::Stdout, false);
///     log!(INFO, "my value = {}", abc);
///     set_config_option!(Settings::Stdout, true);
///     log!(INFO, "hi");
///
///     set_config_option!(Settings::LineNum, true);
///     log!(INFO, "my value = {}", abc);
///     set_config_option!(Settings::LineNum, false);
///     log!(INFO, "hi");
///
///     set_config_option!(Settings::Level, true);
///     log!(INFO, "my value = {}", abc);
///     set_config_option!(Settings::Level, false);
///     log!(INFO, "hi");
///
///     set_config_option!(Settings::Timestamp, true);
///     log!(INFO, "my value = {}", abc);
///     set_config_option!(Settings::Timestamp, false);
///     log!(INFO, "hi");
///
///     // this macro may also specify a particular logger instead of the default logger. To
///     // do that, specify the first parameter as the name of the logger.
///
///     set_config_option!(MAIN_LOG, Settings::Timestamp, true);
///     log_multi!(WARN, MAIN_LOG, "test");
///     set_config_option!(MAIN_LOG, Settings::Timestamp, false);
///     log_multi!(WARN, MAIN_LOG, "test");
///
///     Ok(())
/// }
///
/// ```
#[macro_export]
macro_rules! set_config_option {
	($set_type:expr,$value:expr) => {{
		nioruntime_log::set_config_option!("default", $set_type, $value)
	}};
	($log:expr,$set_type:expr,$value:expr) => {{
		match nioruntime_log::lockw!(nioruntime_log::STATIC_LOG) {
			Ok(mut log_map) => {
				let log = log_map.get_mut($log);
				match log {
					Some(log) => match $set_type {
						nioruntime_log::Settings::Stdout => log.update_show_stdout($value),
						nioruntime_log::Settings::LineNum => log.update_show_line_num($value),
						nioruntime_log::Settings::Level => log.update_show_log_level($value),
						nioruntime_log::Settings::Timestamp => log.update_show_timestamp($value),
					},
					None => {
						let error: nioruntime_err::Error =
							nioruntime_err::ErrorKind::LogConfigurationError(
								"no config found".to_string(),
							)
							.into();
						Err(error)
					}
				}
			}
			Err(e) => Err(e),
		}
	}};
}

/// Identical to [`log_no_ts`] except that the name of the logger is specified instead of using
/// the default logger.
/// # Examples ///
/// ```
/// use nioruntime_log::*;
/// use nioruntime_err::Error;
///
/// info!();
///
/// fn test() -> Result<(), Error> {
///     log_multi_no_ts!(INFO, "nondefaultlogger", "hi");
///     log_multi_no_ts!(INFO, "nondefaultlogger", "value = {}", 123);
///     Ok(())
/// }
/// ```
///
#[macro_export]
macro_rules! log_multi_no_ts {
($level:expr, $a:expr, $b:expr) => {{
                match LOG_LEVEL <= $level {
                        true => {
				let res: Result<(), nioruntime_err::Error>;
				match nioruntime_log::lockw!(nioruntime_log::STATIC_LOG) {
					Ok(mut log_map) => {
						let mut log = log_map.get_mut($a);
						match log {
							Some(ref mut log) => {
								res = nioruntime_log::do_log!($level, false, log, $b);
							},
							None => {
								let mut log = nioruntime_log::Log::new();
								res = nioruntime_log::do_log!($level, false, &mut log, $b);
								log_map.insert($a.to_string(), log);
							}
						}
					}
					Err(e) => {
						res = Err(
							nioruntime_err::ErrorKind::LogError(
								format!(
									"couldn't obtain lock due to: {}",
									e
								)
							).into()
						);
					}
				}
				res
                        },
                        false => Ok(()),
                }
	}};
	($level:expr, $a:expr,$b:expr,$($c:tt)*)=> {{
		match LOG_LEVEL <= $level {
			true => {
				let res: Result<(), nioruntime_err::Error>; match nioruntime_log::lockw!(nioruntime_log::STATIC_LOG) {
					Ok(mut log_map) => {
						let mut log = log_map.get_mut($a);
						match log {
							Some(ref mut log) => {
								res = nioruntime_log::do_log!($level, false, log, $b, $($c)*);
							},
							None => {
								let mut log = nioruntime_log::Log::new();
								res = nioruntime_log::do_log!($level, false, &mut log, $b, $($c)*);
								log_map.insert($a.to_string(), log);
							}
						}
					}
					Err(e) => {
						res = Err(
							nioruntime_err::ErrorKind::LogError(
								format!(
									"couldn't obtain lock due to: {}",
									e
								)
							).into()
						);
					}
				}
				res
                        },
                        false => Ok(()),
                }
	}};
}

/// Log using the default logger and don't print a timestamp. See [`log`] for more details on logging.
/// # Examples
///
/// ```
/// use nioruntime_log::*;
/// use nioruntime_err::Error;
/// debug!(); // set log level to debug
///
/// fn test() -> Result<(), Error> {
///     log!(INFO, "hi");
///     log_no_ts!(INFO, "message here");
///     log_no_ts!(WARN, "my value = {}", 1);
///     log!(WARN, "more data");
///     Ok(())
/// }
///
/// // The output will look something like this:
/// // [2021-08-09 19:41:37]: (INFO) [..e/src/ops/function.rs:227]: hi
/// // message here
/// // my value = 1
/// // [2021-08-09 19:41:37]: (WARN) [..e/src/ops/function.rs:227]: more data
/// ```
#[macro_export]
macro_rules! log_no_ts {
	($level:expr, $a:expr) => {
		{
                	match LOG_LEVEL <= $level {
                        	true => {
					let default = nioruntime_log::default_log_name!();
					nioruntime_log::log_multi_no_ts!($level, &default, $a)
                        	},
                        	false => Ok(()),
                	}
		}
	};
	($level:expr, $a:expr,$($b:tt)*)=>{
		{
                	match LOG_LEVEL <= $level {
                        	true => {
					let default = nioruntime_log::default_log_name!();
					nioruntime_log::log_multi_no_ts!($level, &default, $a, $($b)*)
                	        },
                        	false => Ok(()),
                	}
		}
	};
}

/// Generally, this macro should not be used directly. It is used by the other macros. See [`log`] or [`info`] instead.
#[macro_export]
#[doc(hidden)]
macro_rules! do_log {
	($level:expr)=>{
		const LOG_LEVEL: i32 = $level;
	};
	($level:expr, $show_ts:expr, $log:expr, $a:expr)=>{
		{
                	match LOG_LEVEL <= $level {
                        	true => {
					let res: Result<(), nioruntime_err::Error> = nioruntime_log::do_log(
						$level, $show_ts, $log, format!($a), LOG_LEVEL
					);
					res
                        	},
                        	false => Ok(()),
                	}
		}
	};
	($level:expr, $show_ts:expr, $log:expr, $a:expr, $($b:tt)*)=>{
		{
                	match LOG_LEVEL <= $level {
                        	true => {
					let res: Result<(), nioruntime_err::Error> = nioruntime_log::do_log(
						$level, $show_ts, $log, format!($a, $($b)*), LOG_LEVEL
					);
					res
                 	       },
                        	false => Ok(()),
                	}
		}
	};
}

/// get_config returns the [`crate::LogConfig`] structure for the specified logger.
/// If no logger is specified, the default logger's [`crate::LogConfig`] will be returned.
///
/// # Examples
/// ```
/// use nioruntime_log::*;
/// use nioruntime_err::Error;
///
/// info!();
/// const MAIN_LOG: &str = "mainlog";
///
/// fn test() -> Result<(), Error> {
///     log_multi!(INFO, MAIN_LOG, "test");
///     let config = get_config!(MAIN_LOG)?;
///     info!("The mainlog's config is {:?}", config);
///     let config = get_config!();
///     info!("The default config is {:?}", config);
///
///     Ok(())
/// }
/// ```
///
/// For full details on all parameters see [`crate::LogConfig`].
#[macro_export]
macro_rules! get_config {
	() => {{
		let default = nioruntime_log::default_log_name!();
		nioruntime_log::get_config!(&default)
	}};
	($a:expr) => {{
		let res: Result<LogConfig, nioruntime_err::Error>;
		match nioruntime_log::lockw!(nioruntime_log::STATIC_LOG) {
			Ok(mut log_map) => match log_map.get_mut($a) {
				Some(log) => {
					res = log.get_config();
				}
				None => {
					res = Err(nioruntime_err::ErrorKind::LogConfigurationError(
						"no config found".to_string(),
					)
					.into());
				}
			},
			Err(e) => {
				res = Err(nioruntime_err::ErrorKind::LogError(format!(
					"error obtaining lock: {}",
					e
				))
				.into());
			}
		}
		res
	}};
}

/// log_config_multi is identical to [`log_config`] except that the name of the logger is specified instead of using
/// the default logger. Please note that this macro must be called before any logging occurs. After logging has
/// started options may only be set via the [`set_config_option`] macro.
///
/// A sample log_config_multi! call might look something like this:
///
/// ```
/// use nioruntime_log::*;
/// use nioruntime_err::*;
///
/// info!();
///
/// fn test() -> Result<(), Error> {
///     log_config_multi!(
///	 "nondefaultlogger",
///	 LogConfig {
///		max_age_millis: 10000, // set log rotations to every 10 seconds
///		max_size: 10000, // set log rotations to every 10,000 bytes
///		..Default::default()
///	 }
///     );
///     Ok(())
/// }
/// ```
///
/// For full details on all parameters see [`crate::LogConfig`].
#[macro_export]
macro_rules! log_config_multi {
	($a:expr, $b:expr) => {{
		let res: Result<(), nioruntime_err::Error>;
		match nioruntime_log::lockw!(nioruntime_log::STATIC_LOG) {
			Ok(mut log_map) => match log_map.get_mut($a) {
				Some(log) => res = log.init($b),
				None => {
					let mut log = nioruntime_log::Log::new();
					res = log.init($b);
					log_map.insert($a.to_string(), log);
				}
			},
			Err(e) => res = Err(e),
		};
		res
	}};
}

/// This macro may be used to configure logging. If it is not called, the default LogConfig is used.
/// By default logging is only done to stdout.
/// A sample log_config! call is shown below in examples.
///
/// # Examples
/// ```
/// use nioruntime_log::*;
/// use nioruntime_err::Error;
///
/// info!();
///
/// fn test() -> Result<(), Error> {
///     log_config!(nioruntime_log::LogConfig {
/// 	    max_age_millis: 10000, // set log rotations to every 10 seconds
/// 	    max_size: 10000, // set log rotations to every 10,000 bytes
/// 	    ..Default::default()
///     });
///     Ok(())
/// }
/// ```
/// For full details on all parameters see [`crate::LogConfig`].
#[macro_export]
macro_rules! log_config {
	($a:expr) => {{
		let default = nioruntime_log::default_log_name!();
		let res: Result<(), nioruntime_err::Error> =
			nioruntime_log::log_config_multi!(&default, $a);
		res
	}};
}

/// This macro rotates the log. Optionally, the name of the log may be specified. If no
/// name is specified, the default log is rotated. Also see [`rotation_status`].
///
/// # Examples
/// ```
/// use nioruntime_log::*;
/// use nioruntime_err::Error;
///
/// const MAIN_LOG: &str = "mainlog";
///
/// info!();
///
/// fn test() -> Result<(), Error> {
///     log_config!(nioruntime_log::LogConfig {
///	 max_age_millis: 10000, // set log rotations to every 10 seconds
///	 max_size: 10000, // set log rotations to every 10,000 bytes
///	 ..Default::default()
///     });
///
///     info!("some data...");
///     rotate!();
///
///     info!("other data...");
///     rotate!(MAIN_LOG);
///
///     Ok(())
/// }
/// ```
#[macro_export]
macro_rules! rotate {
	() => {{
		let default = nioruntime_log::default_log_name!();
		rotate!(&default)
	}};
	($log:expr) => {{
		//let res: Result<nioruntime_log::RotationStatus, nioruntime_err::Error>;
		let res: Result<(), nioruntime_err::Error>;
		match nioruntime_log::lockw!(nioruntime_log::STATIC_LOG) {
			Ok(mut log_map) => match log_map.get_mut($log) {
				Some(log) => {
					res = log.rotate();
				}
				None => {
					res = Err(nioruntime_err::ErrorKind::LogConfigurationError(
						"error log not configured".to_string(),
					)
					.into());
				}
			},
			Err(e) => {
				res = Err(e);
			}
		};
		res
	}};
}

/// This macro returns the rotation status of the log. Optionally, the name of the log
/// may be specified. If no name is specified, the default log is rotated. The return
/// value is of the [`crate::RotationStatus`] enum. See its documentation for further details.
/// Also see [`rotate`].
///
/// # Examples
/// ```
/// use nioruntime_log::*;
/// use nioruntime_err::Error;
///
/// const MAIN_LOG: &str = "mainlog";
///
/// info!();
///
/// fn test() -> Result<(), Error> {
///     log_config!(nioruntime_log::LogConfig {
///	 max_age_millis: 10000, // set log rotations to every 10 seconds
///	 max_size: 10000, // set log rotations to every 10,000 bytes
///	 ..Default::default()
///     });
///
///     info!("some data...")?;
///     rotate!()?;
///
///     info!("other data...")?;
///     rotate!(MAIN_LOG)?;
///
///     let status_main = rotation_status!(MAIN_LOG)?;
///     let status_default = rotation_status!()?;
///
///     info!("rotation status main = {:?}, default = {:?}", status_main, status_default);
///
///     Ok(())
/// }
/// ```
#[macro_export]
macro_rules! rotation_status {
	() => {{
		let default = nioruntime_log::default_log_name!();
		rotation_status!(&default)
	}};
	($log:expr) => {{
		let res: Result<nioruntime_log::RotationStatus, nioruntime_err::Error>;
		match nioruntime_log::lockw!(nioruntime_log::STATIC_LOG) {
			Ok(mut log_map) => match log_map.get_mut($log) {
				Some(log) => {
					res = log.rotation_status();
				}
				None => {
					res = Err(nioruntime_err::ErrorKind::LogConfigurationError(
						"error log not configured".to_string(),
					)
					.into());
				}
			},
			Err(e) => {
				res = Err(e);
			}
		};
		res
	}};
}

#[cfg(test)]
mod tests {
	use crate as nioruntime_log;
	use crate::*;
	use nioruntime_err::Error;

	trace!();

	fn setup_test_dir(dir: &str) -> Result<(), Error> {
		let _ = std::fs::remove_dir_all(dir);
		std::fs::create_dir_all(dir)?;
		Ok(())
	}

	fn tear_down_test_dir(dir: &str) -> Result<(), Error> {
		std::fs::remove_dir_all(dir)?;
		Ok(())
	}

	#[test]
	fn test_macros() {
		const TEST_DIR: &str = ".test_macros.nio";

		setup_test_dir(TEST_DIR).unwrap();

		log_config!(LogConfig {
			show_bt: false,
			show_stdout: false,
			auto_rotate: false,
			show_line_num: false,
			show_timestamp: false,
			max_size: 10,
			file_path: Some(format!("{}/test1.log", TEST_DIR)),
			..Default::default()
		})
		.expect("log config");

		fatal!("fatal").expect("fatal");
		fatal_no_ts!("fatal no ts").expect("fatal no ts");
		fatal_all!("fatal all").expect("fatal all");

		error!("error").expect("error");
		error_no_ts!("error no ts").expect("error no ts");
		error_all!("error all").expect("error all");

		warn!("warn").expect("warn");
		warn_no_ts!("warn no ts").expect("warn no ts");
		warn_all!("warn all").expect("warn all");

		info!("info").expect("info");
		info_no_ts!("info no ts").expect("info no ts");
		info_all!("info all").expect("info all");

		debug!("debug").expect("debug");
		debug_no_ts!("debug no ts").expect("debug no ts");
		debug_all!("debug all").expect("debug all");

		trace!("trace").expect("trace");
		trace_no_ts!("trace no ts").expect("trace no ts");
		trace_all!("trace all").expect("trace all");

		log!(INFO, "info from log").expect("log");
		log_no_ts!(INFO, "info from log no ts").expect("log no ts");
		log_all!(INFO, "log all").expect("log all");

		log_multi_all!(INFO, "notmainlog", "log multi all").expect("log multi all");
		log_multi_no_ts!(INFO, "notmainlog", "log multi no ts").expect("log multi no ts");

		let config = get_config!().unwrap();
		info_all!("config.show_timestamp={:?}", config.show_timestamp).expect("config");

		// main log not configured yet
		assert_eq!(get_config!("mainlog").is_err(), true);
		log_multi!(INFO, "mainlog", "test").expect("log_multi");
		assert_eq!(get_config!("mainlog").is_err(), false);

		let config_option = get_config_option!(Settings::Level).expect("level");
		info_all!("level={}", config_option).expect("infoall");
		set_config_option!(Settings::Level, false).expect("set");

		let rs = rotation_status!().expect("rotation_status");
		rotate!().expect("rotate");
		let rs2 = rotation_status!().expect("rotation_status");
		info_all!("rs={:?},rs2={:?}", rs, rs2).expect("info");

		// there should be two files.
		let paths = std::fs::read_dir(TEST_DIR).unwrap();
		let mut count = 0;
		for path in paths {
			let path = path.unwrap().path().display().to_string();
			if path.find(".test_macros.nio/test1.log") == Some(0) {
				let len = std::fs::metadata(path).unwrap().len();
				assert_eq!(len, 24);
				count += 1;
			} else if path.find(".test_macros.nio/test1.r") == Some(0) {
				let len = std::fs::metadata(path).unwrap().len();
				assert_eq!(len, 363);
				count += 1;
			}
		}

		assert_eq!(count, 2);
		// for now checking length and number of files should be ok.
		// with the specified options, files are deterministic.
		// any bugs at this level would likely result in different file
		// lengths. More thorough testing is done in logger.rs

		// test different default name

		const LOGA: &str = "logA";
		const LOGB: &str = "logB";

		let path_a = format!("{}/{}", TEST_DIR, LOGA);
		let path_b = format!("{}/{}", TEST_DIR, LOGB);

		log_config_multi!(
			LOGA,
			LogConfig {
				file_path: Some(path_a.clone()),
				show_bt: false,
				show_stdout: false,
				auto_rotate: false,
				show_line_num: false,
				show_timestamp: false,
				..Default::default()
			}
		)
		.expect("loga");

		log_config_multi!(
			LOGB,
			LogConfig {
				file_path: Some(path_b.clone()),
				show_bt: false,
				show_stdout: false,
				auto_rotate: false,
				show_line_num: false,
				show_timestamp: false,
				..Default::default()
			}
		)
		.expect("logb");

		log_multi!(INFO, LOGA, "a0123456789").expect("loga");
		log_multi!(INFO, LOGB, "b0123456789").expect("logb");

		default_log_name!(LOGA);
		debug!("a").expect("to log a");

		let len_a = std::fs::metadata(path_a).unwrap().len();
		let len_b = std::fs::metadata(path_b).unwrap().len();

		assert_eq!(len_b, 19);
		assert_eq!(len_a, 29);

		tear_down_test_dir(TEST_DIR).unwrap();
	}
}

/// A macro that is used to lock a rwlock in write mode and return the appropriate error if the lock is poisoned.
/// This code was used in many places, and this macro simplifies it.
#[macro_export]
macro_rules! lockw {
	($a:expr) => {{
		let do_try_lock = if cfg!(debug_assertions) { true } else { false };
		let mut is_locked = false;
		let id: u128 = std::time::SystemTime::now()
			.duration_since(std::time::UNIX_EPOCH)
			.unwrap()
			.as_nanos(); // use time in nanos as random enough number here

		if do_try_lock {
			match $a.try_write() {
				Ok(_) => {}
				Err(_) => {
					is_locked = true;
					let bt = nioruntime_deps::backtrace::Backtrace::new();
					let time = std::time::SystemTime::now()
						.duration_since(std::time::UNIX_EPOCH)
						.unwrap()
						.as_millis();
					let mut lock_monitor = nioruntime_deps::LOCK_MONITOR
						.write()
						.map_err(|e| {
							let error: nioruntime_err::Error =
								nioruntime_err::ErrorKind::PoisonError(format!(
									"Poison Error: {}",
									e.to_string()
								))
								.into();
							error
						})
						.unwrap();
					lock_monitor.insert(id, nioruntime_deps::LockInfo { id, bt, time });
					match lock_monitor.get(&0) {
						Some(_) => {}
						None => {
							let bt = nioruntime_deps::backtrace::Backtrace::new();
							lock_monitor.insert(0, nioruntime_deps::LockInfo { id, bt, time });
							std::thread::spawn(move || loop {
								std::thread::sleep(std::time::Duration::from_millis(10000));
								let lock_monitor = match nioruntime_deps::LOCK_MONITOR.read() {
									Ok(lock_monitor) => lock_monitor,
									Err(e) => {
										println!("Warning error obtaining read lock: {}", e);
										continue;
									}
								};
								for (k, v) in &*lock_monitor {
									if *k != 0 {
										let time_now = std::time::SystemTime::now()
											.duration_since(std::time::UNIX_EPOCH)
											.unwrap_or(std::time::Duration::from_millis(0))
											.as_millis();
										let e = time_now - v.time;
										if e > 1000 {
											println!(
												"potential deadlock detected. k={:?},e={},v={:?}",
												k, e, v,
											);
										}
									}
								}
							});
						}
					};
				}
			}
		}
		let res = $a.write().map_err(|e| {
			let error: nioruntime_err::Error =
				nioruntime_err::ErrorKind::PoisonError(format!("Poison Error: {}", e.to_string()))
					.into();
			error
		});

		if is_locked {
			let mut lock_monitor = nioruntime_deps::LOCK_MONITOR
				.write()
				.map_err(|e| {
					let error: nioruntime_err::Error = nioruntime_err::ErrorKind::PoisonError(
						format!("Poison Error: {}", e.to_string()),
					)
					.into();
					error
				})
				.unwrap();

			(*lock_monitor).remove(&id);
		}

		res
	}};
}
