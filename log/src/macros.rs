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
	pub static ref STATIC_LOG: Arc<RwLock<HashMap<String, Log>>> = Arc::new(RwLock::new(HashMap::new()));
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
			const DEFAULT_LOG: &str = "default";
			nioruntime_log::log_multi!(nioruntime_log::FATAL, DEFAULT_LOG, $a)
		}
	};
	($a:expr,$($b:tt)*)=>{
		{
			const DEFAULT_LOG: &str = "default";
			nioruntime_log::log_multi!(nioruntime_log::FATAL, DEFAULT_LOG, $a, $($b)*)
		}
	};
}

/// Just like [`fatal`], but with no timestamp.
#[macro_export]
macro_rules! fatal_no_ts {
        ($a:expr) => {
                {
                        const DEFAULT_LOG: &str = "default";
                        nioruntime_log::log_no_ts_multi!(nioruntime_log::FATAL, DEFAULT_LOG, $a)
                }
        };
        ($a:expr,$($b:tt)*)=>{
                {
                        const DEFAULT_LOG: &str = "default";
                        nioruntime_log::log_no_ts_multi!(nioruntime_log::FATAL, DEFAULT_LOG, $a, $($b)*)
                }
        };
}

/// Just like [`fatal`], but the line is also logged to stdout regardless of the current
/// configuration.
#[macro_export]
macro_rules! fatal_all {
        ($a:expr) => {
                {
                        const DEFAULT_LOG: &str = "default";
                        nioruntime_log::log_multi_all!(nioruntime_log::FATAL, DEFAULT_LOG, $a)
                }
        };
        ($a:expr,$($b:tt)*)=>{
                {
                        const DEFAULT_LOG: &str = "default";
                        nioruntime_log::log_multi_all!(nioruntime_log::FATAL, DEFAULT_LOG, $a, $($b)*)
                }
        };
}

/// Log at the 'error' (4) log level. This macro calls the default logger. To configure this
/// logger, see [`log_config`]. It is used like the pritln/format macros.
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
                        const DEFAULT_LOG: &str = "default";
                        nioruntime_log::log_multi!(nioruntime_log::ERROR, DEFAULT_LOG, $a)
                }
        };
        ($a:expr,$($b:tt)*)=>{
                {
                        const DEFAULT_LOG: &str = "default";
                        nioruntime_log::log_multi!(nioruntime_log::ERROR, DEFAULT_LOG, $a, $($b)*)
                }
        };
}

/// Just like [`error`], but with no timestamp.
#[macro_export]
macro_rules! error_no_ts {
        ($a:expr) => {
                {
                        const DEFAULT_LOG: &str = "default";
                        nioruntime_log::log_no_ts_multi!(nioruntime_log::ERROR, DEFAULT_LOG, $a)
                }
        };
        ($a:expr,$($b:tt)*)=>{
                {
                        const DEFAULT_LOG: &str = "default";
                        nioruntime_log::log_no_ts_multi!(nioruntime_log::ERROR, DEFAULT_LOG, $a, $($b)*)
                }
        };
}

/// Just like [`error`], but the line is also logged to stdout regardless of the current
/// configuration.
#[macro_export]
macro_rules! error_all {
        ($a:expr) => {
                {
                        const DEFAULT_LOG: &str = "default";
                        nioruntime_log::log_multi_all!(nioruntime_log::ERROR, DEFAULT_LOG, $a)
                }
        };
        ($a:expr,$($b:tt)*)=>{
                {
                        const DEFAULT_LOG: &str = "default";
                        nioruntime_log::log_multi_all!(nioruntime_log::ERROR, DEFAULT_LOG, $a, $($b)*)
                }
        };
}

/// Log at the 'warn' (3) log level. This macro calls the default logger. To configure this
/// logger, see [`log_config`]. It is used like the pritln/format macros.
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
		nioruntime_log::do_log!(nioruntime_log::WARN)
	};
        ($a:expr) => {
                {
                        const DEFAULT_LOG: &str = "default";
                        nioruntime_log::log_multi!(nioruntime_log::WARN, DEFAULT_LOG, $a)
                }
        };
        ($a:expr,$($b:tt)*)=>{
                {
                        const DEFAULT_LOG: &str = "default";
                        nioruntime_log::log_multi!(nioruntime_log::WARN, DEFAULT_LOG, $a, $($b)*)
                }
        };
}

/// Just like [`warn`], but with no timestamp.
#[macro_export]
macro_rules! warn_no_ts {
        ($a:expr) => {
                {
                        const DEFAULT_LOG: &str = "default";
                        nioruntime_log::log_no_ts_multi!(nioruntime_log::WARN, DEFAULT_LOG, $a)
                }
        };
        ($a:expr,$($b:tt)*)=>{
                {
                        const DEFAULT_LOG: &str = "default";
                        nioruntime_log::log_no_ts_multi!(nioruntime_log::WARN, DEFAULT_LOG, $a, $($b)*)
                }
        };
}

/// Just like [`warn`], but the line is also logged to stdout regardless of the current
/// configuration.
#[macro_export]
macro_rules! warn_all {
        ($a:expr) => {
                {
                        const DEFAULT_LOG: &str = "default";
                        nioruntime_log::log_multi_all!(nioruntime_log::WARN, DEFAULT_LOG, $a)
                }
        };
        ($a:expr,$($b:tt)*)=>{
                {
                        const DEFAULT_LOG: &str = "default";
                        nioruntime_log::log_multi_all!(nioruntime_log::WARN, DEFAULT_LOG, $a, $($b)*)
                }
        };
}

/// Log at the 'info' (2) log level. This macro calls the default logger. To configure this
/// logger, see [`log_config`]. It is used like the pritln/format macros.
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
                        const DEFAULT_LOG: &str = "default";
                        nioruntime_log::log_multi!(nioruntime_log::INFO, DEFAULT_LOG, $a)
                }
        };
        ($a:expr,$($b:tt)*)=>{
                {
                        const DEFAULT_LOG: &str = "default";
                        nioruntime_log::log_multi!(nioruntime_log::INFO, DEFAULT_LOG, $a, $($b)*)
                }
        };
}

/// Just like [`info`], but with no timestamp.
#[macro_export]
macro_rules! info_no_ts {
        ($a:expr) => {
                {
                        const DEFAULT_LOG: &str = "default";
                        nioruntime_log::log_no_ts_multi!(nioruntime_log::INFO, DEFAULT_LOG, $a)
                }
        };
        ($a:expr,$($b:tt)*)=>{
                {
                        const DEFAULT_LOG: &str = "default";
                        nioruntime_log::log_no_ts_multi!(nioruntime_log::INFO, DEFAULT_LOG, $a, $($b)*)
                }
        };
}

/// Just like [`info`], but the line is also logged to stdout regardless of the current
/// configuration.
#[macro_export]
macro_rules! info_all {
        ($a:expr) => {
                {
                        const DEFAULT_LOG: &str = "default";
                        nioruntime_log::log_multi_all!(nioruntime_log::INFO, DEFAULT_LOG, $a)
                }
        };
        ($a:expr,$($b:tt)*)=>{
                {
                        const DEFAULT_LOG: &str = "default";
                        nioruntime_log::log_multi_all!(nioruntime_log::INFO, DEFAULT_LOG, $a, $($b)*)
                }
        };
}

/// Log at the 'debug' (1) log level. This macro calls the default logger. To configure this
/// logger, see [`log_config`]. It is used like the pritln/format macros.
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
                        const DEFAULT_LOG: &str = "default";
                        nioruntime_log::log_multi!(nioruntime_log::DEBUG, DEFAULT_LOG, $a)
		}
	};
	($a:expr,$($b:tt)*)=>{
		{
                        const DEFAULT_LOG: &str = "default";
			nioruntime_log::log_multi!(nioruntime_log::DEBUG, DEFAULT_LOG, $a, $($b)*)
		}
	};
}

/// Just like [`debug`], but with no timestamp.
#[macro_export]
macro_rules! debug_no_ts {
        ($a:expr) => {
                {
                        const DEFAULT_LOG: &str = "default";
                        nioruntime_log::log_no_ts_multi!(nioruntime_log::DEBUG, DEFAULT_LOG, $a)
                }
        };
        ($a:expr,$($b:tt)*)=>{
                {
                        const DEFAULT_LOG: &str = "default";
                        nioruntime_log::log_no_ts_multi!(nioruntime_log::DEBUG, DEFAULT_LOG, $a, $($b)*)
                }
        };
}

/// Just like [`debug`], but the line is also logged to stdout regardless of the current
/// configuration.
#[macro_export]
macro_rules! debug_all {
        ($a:expr) => {
                {
                        const DEFAULT_LOG: &str = "default";
                        nioruntime_log::log_multi_all!(nioruntime_log::DEBUG, DEFAULT_LOG, $a)
                }
        };
        ($a:expr,$($b:tt)*)=>{
                {
                        const DEFAULT_LOG: &str = "default";
                        nioruntime_log::log_multi_all!(nioruntime_log::DEBUG, DEFAULT_LOG, $a, $($b)*)
                }
        };
}

/// Log at the 'trace' (0) log level. This macro calls the default logger. To configure this
/// logger, see [`log_config`]. It is used like the pritln/format macros.
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
                        const DEFAULT_LOG: &str = "default";
                        nioruntime_log::log_multi!(nioruntime_log::TRACE, DEFAULT_LOG, $a)
                }
        };
        ($a:expr,$($b:tt)*)=>{
                {
                        const DEFAULT_LOG: &str = "default";
                        nioruntime_log::log_multi!(nioruntime_log::TRACE, DEFAULT_LOG, $a, $($b)*)
                }
        };
}

/// Just like [`trace`], but with no timestamp.
#[macro_export]
macro_rules! trace_no_ts {
	($a:expr) => {
		{
			const DEFAULT_LOG: &str = "default";
			nioruntime_log::log_no_ts_multi!(nioruntime_log::TRACE, DEFAULT_LOG, $a)
		}
	};
	($a:expr,$($b:tt)*)=>{
		{
			const DEFAULT_LOG: &str = "default";
			nioruntime_log::log_no_ts_multi!(nioruntime_log::TRACE, DEFAULT_LOG, $a, $($b)*)
		}
	};
}

/// Just like [`trace`], but the line is also logged to stdout regardless of the current
/// configuration.
#[macro_export]
macro_rules! trace_all {
        ($a:expr) => {
                {
                        const DEFAULT_LOG: &str = "default";
                        nioruntime_log::log_multi_all!(nioruntime_log::TRACE, DEFAULT_LOG, $a)
                }
        };
        ($a:expr,$($b:tt)*)=>{
                {
                        const DEFAULT_LOG: &str = "default";
                        nioruntime_log::log_multi_all!(nioruntime_log::TRACE, DEFAULT_LOG, $a, $($b)*)
                }
        };
}

/// Same as [`log_multi`] except that the log line is logged to stdout as well, no matter
/// what the existing configuration is. To configure this
/// logger, see [`log_multi_config`]. It is used like the pritln/format macros. The first
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
/// // [2021-08-09 19:41:37]: my value = 123
/// // [2021-08-09 19:41:37]: hi
/// ```
#[macro_export]
macro_rules! log_multi_all {
        ($level:expr, $a:expr, $b:expr) => {{
		let stdout_cur = nioruntime_log::get_config_option!(
			nioruntime_log::Settings::Stdout
		).unwrap_or(true);

                nioruntime_log::set_config_option!(
                        nioruntime_log::Settings::Stdout, true
                ).ok();

		let res: Result<(), nioruntime_err::Error>  = nioruntime_log::log_multi!($level, $a, $b);

		nioruntime_log::set_config_option!(
			nioruntime_log::Settings::Stdout, stdout_cur
		).ok();

		res
	}};
	($level:expr, $a:expr,$b:expr,$($c:tt)*)=> {{
		let mut res: Result<(), nioruntime_err::Error> = Ok(());

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
	}};
}

/// The main logging macro for use with multiple loggers. To configure this
/// logger, see [`log_multi_config`]. It is used like the pritln/format macros. The first
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
/// // [2021-08-09 19:41:37]: my value = 123
/// // [2021-08-09 19:41:37]: hi
/// ```
#[macro_export]
macro_rules! log_multi {
	($level:expr, $a:expr, $b:expr) => {{
		let res: Result<(), nioruntime_err::Error>;
		match nioruntime_util::lockw!(nioruntime_log::STATIC_LOG) {
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
	}};
	($level:expr, $a:expr,$b:expr,$($c:tt)*)=> {{
                let res: Result<(), nioruntime_err::Error>;
                match nioruntime_util::lockw!(nioruntime_log::STATIC_LOG) {
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
	}};
}

/// The main logging macro. This macro calls the default logger. To configure this
/// logger, see [`log_config`]. It is used like the pritln/format macros. The first
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
/// // [2021-08-09 19:41:37]: my value = 123
/// // [2021-08-09 19:41:37]: hi
/// ```
#[macro_export]
macro_rules! log {
       ($level:expr, $a:expr)=>{
                {
                        const DEFAULT_LOG: &str = "default";
                        nioruntime_log::log_multi!($level, DEFAULT_LOG, $a)
                }
        };
        ($level:expr, $a:expr, $($b:tt)*)=>{
                {
                        const DEFAULT_LOG: &str = "default";
                        nioruntime_log::log_multi!($level, DEFAULT_LOG, $a, $($b)*)
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
		match nioruntime_util::lockw!(nioruntime_log::STATIC_LOG) {
			Ok(mut log_map) => {
				let mut log = log_map.get_mut($log);
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
		match nioruntime_util::lockw!(nioruntime_log::STATIC_LOG) {
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
/// # Examples
///
/// ```
/// use nioruntime_log::*;
/// use nioruntime_err::Error;
///
/// info!();
///
/// fn test() -> Result<(), Error> {
///     log_no_ts_multi!(2, "nondefaultlogger", "hi");
///     log_no_ts_multi!(2, "nondefaultlogger", "value = {}", 123);
///     Ok(())
/// }
/// ```
///
#[macro_export]
macro_rules! log_no_ts_multi {
($level:expr, $a:expr, $b:expr) => {{
                let res: Result<(), nioruntime_err::Error>;
                match nioruntime_util::lockw!(nioruntime_log::STATIC_LOG) {
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
        }};
        ($level:expr, $a:expr,$b:expr,$($c:tt)*)=> {{
                let res: Result<(), nioruntime_err::Error>;
                match nioruntime_util::lockw!(nioruntime_log::STATIC_LOG) {
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
                        const DEFAULT_LOG: &str = "default";
                        nioruntime_log::log_no_ts_multi!($level, DEFAULT_LOG, $a)
                }
        };
        ($level:expr, $a:expr,$($b:tt)*)=>{
                {
                        const DEFAULT_LOG: &str = "default";
                        nioruntime_log::log_no_ts_multi!($level, DEFAULT_LOG, $a, $($b)*)
                }
        };
}

/// Generally, this macro should not be used directly. It is used by the other macros. See [`log`] or [`info`] instead.
#[macro_export]
macro_rules! do_log {
	($level:expr)=>{
		const LOG_LEVEL: i32 = $level;
	};
	($level:expr, $show_ts:expr, $log:expr, $a:expr)=>{
		{
			let res: Result<(), nioruntime_err::Error> = nioruntime_log::do_log(

				$level, $show_ts, $log, format!($a), LOG_LEVEL
			);
			res
		}
	};
	($level:expr, $show_ts:expr, $log:expr, $a:expr, $($b:tt)*)=>{
		{
			let res: Result<(), nioruntime_err::Error> = nioruntime_log::do_log(
				$level, $show_ts, $log, format!($a, $($b)*), LOG_LEVEL
			);
			res
		}
	};
}

/// get_config_multi get's the LogConfig structure for the specified logger
///
/// A sample get_config_multi! call might look something like this:
///
/// ```
/// use nioruntime_log::*;
/// use nioruntime_err::Error;
///
/// info!();
/// const MAIN_LOG: &str = "mainlog";
///
/// fn test() -> Result<(), Error> {
///     log_multi!(INFO, MAIN_LOG, "test");
///     let config = get_config_multi!(MAIN_LOG)?;
///     info!("The mainlog's config is {:?}", config);
///
///     Ok(())
/// }
/// ```
///
/// For full details on all parameters see [`crate::LogConfig`].
#[macro_export]
macro_rules! get_config_multi {
	($a:expr) => {{
		let mut log_map = nioruntime_util::lockw!(nioruntime_log::STATIC_LOG)?;
		let log = log_map.get_mut($a);
		match log {
			Some(log) => log.get_config(),
			None => Err(nioruntime_err::ErrorKind::LogConfigurationError(
				"no config found".to_string(),
			)
			.into()),
		}
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
///         "nondefaultlogger",
///         LogConfig {
///	        max_age_millis: 10000, // set log rotations to every 10 seconds
///	        max_size: 10000, // set log rotations to every 10,000 bytes
///	        ..Default::default()
///         }
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
		match nioruntime_util::lockw!(nioruntime_log::STATIC_LOG) {
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
		const DEFAULT_LOG: &str = "default";
		let res: Result<(), nioruntime_err::Error> =
			nioruntime_log::log_config_multi!(DEFAULT_LOG, $a);
		res
	}};
}
