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
/// logger, see [`log_config`]. It is used like the pritln/format macros.
/// Also see [`trace`] [`debug`], [`info`], [`warn`], or [`error`].
/// # Examples
/// ```
/// use nioruntime_log::*;
/// // log level must be set before calling any logging function.
/// // typically it is done at the top of a file so that it's easy to change.
/// // but it can be done at any level or scope. The inner scope prevails.
/// fatal!(); // set log level to fatal "5"
///
/// let abc = 123;
/// fatal!("my value = {}", abc);
/// fatal!("hi");
///
/// // The output will look like this:
/// // [2021-08-09 19:41:37]: my value = 123
/// // [2021-08-09 19:41:37]: hi
/// ```
#[macro_export]
macro_rules! fatal {
        () => {
                nioruntime_log::do_log!(nioruntime_log::FATAL);
        };
        ($a:expr) => {
                {
                        nioruntime_log::log!(nioruntime_log::FATAL, $a);
                }
        };
        ($a:expr,$($b:tt)*)=>{
                {
                        nioruntime_log::log!(nioruntime_log::FATAL, $a, $($b)*);
                }
        };
}

/// Just like [`fatal`], but with no timestamp.
#[macro_export]
macro_rules! fatal_no_ts {
        ($a:expr) => {
                {
                        nioruntime_log::log_no_ts!(nioruntime_log::FATAL, $a);
                }
        };
        ($a:expr,$($b:tt)*)=>{
                {
                        nioruntime_log::log_no_ts!(nioruntime_log::FATAL, $a, $($b)*);
                }
        };
}

/// Log at the 'error' (4) log level. This macro calls the default logger. To configure this
/// logger, see [`log_config`]. It is used like the pritln/format macros.
/// Also see [`trace`], [`debug`], [`info`], [`warn`], or [`fatal`].
/// # Examples
/// ```
/// use nioruntime_log::*;
/// // log level must be set before calling any logging function.
/// // typically it is done at the top of a file so that it's easy to change.
/// // but it can be done at any level or scope. The inner scope prevails.
/// error!(); // set log level to error "4"
///
/// let abc = 123;
/// error!("my value = {}", abc);
/// error!("hi");
///
/// // The output will look like this:
/// // [2021-08-09 19:41:37]: my value = 123
/// // [2021-08-09 19:41:37]: hi
/// ```
#[macro_export]
macro_rules! error {
        () => {
                nioruntime_log::do_log!(nioruntime_log::ERROR);
        };
        ($a:expr) => {
                {
                        nioruntime_log::log!(nioruntime_log::ERROR, $a);
                }
        };
        ($a:expr,$($b:tt)*)=>{
                {
                        nioruntime_log::log!(nioruntime_log::ERROR, $a, $($b)*);
                }
        };
}

/// Just like [`error`], but with no timestamp.
#[macro_export]
macro_rules! error_no_ts {
        ($a:expr) => {
                {
                        nioruntime_log::log_no_ts!(nioruntime_log::ERROR, $a);
                }
        };
        ($a:expr,$($b:tt)*)=>{
                {
                        nioruntime_log::log_no_ts!(nioruntime_log::ERROR, $a, $($b)*);
                }
        };
}

/// Log at the 'warn' (3) log level. This macro calls the default logger. To configure this
/// logger, see [`log_config`]. It is used like the pritln/format macros.
/// Also see [`trace`], [`debug`], [`info`], [`error`], or [`fatal`].
/// # Examples
/// ```
/// use nioruntime_log::*;
/// // log level must be set before calling any logging function.
/// // typically it is done at the top of a file so that it's easy to change.
/// // but it can be done at any level or scope. The inner scope prevails.
/// warn!(); // set log level to warn "3"
///
/// let abc = 123;
/// warn!("my value = {}", abc);
/// warn!("hi");
///
/// // The output will look like this:
/// // [2021-08-09 19:41:37]: my value = 123
/// // [2021-08-09 19:41:37]: hi
/// ```
#[macro_export]
macro_rules! warn {
        () => {
                nioruntime_log::do_log!(nioruntime_log::WARN);
        };
        ($a:expr) => {
		{
                	nioruntime_log::log!(nioruntime_log::WARN, $a);
		}
        };
        ($a:expr,$($b:tt)*)=>{
                {
                	nioruntime_log::log!(nioruntime_log::WARN, $a, $($b)*);
		}
        };
}

/// Just like [`warn`], but with no timestamp.
#[macro_export]
macro_rules! warn_no_ts {
        ($a:expr) => {
                {
                	nioruntime_log::log_no_ts!(nioruntime_log::WARN, $a);
		}
        };
        ($a:expr,$($b:tt)*)=>{
                {
                	nioruntime_log::log_no_ts!(nioruntime_log::WARN, $a, $($b)*);
		}
        };
}

/// Log at the 'info' (2) log level. This macro calls the default logger. To configure this
/// logger, see [`log_config`]. It is used like the pritln/format macros.
/// Also see [`trace`], [`debug`], [`warn`], [`error`], or [`fatal`].
/// # Examples
/// ```
/// use nioruntime_log::*;
/// // log level must be set before calling any logging function.
/// // typically it is done at the top of a file so that it's easy to change.
/// // but it can be done at any level or scope. The inner scope prevails.
/// info!(); // set log level to info "2"
///
/// let abc = 123;
/// info!("my value = {}", abc);
/// info!("hi");
///
/// // The output will look like this:
/// // [2021-08-09 19:41:37]: my value = 123
/// // [2021-08-09 19:41:37]: hi
/// ```
#[macro_export]
macro_rules! info {
	() => {
		nioruntime_log::do_log!(nioruntime_log::INFO);
	};
        ($a:expr) => {
                {
                	nioruntime_log::log!(nioruntime_log::INFO, $a);
		}
        };
        ($a:expr,$($b:tt)*)=>{
                {
                	nioruntime_log::log!(nioruntime_log::INFO, $a, $($b)*);
		}
        };
}

/// Just like [`info`], but with no timestamp.
#[macro_export]
macro_rules! info_no_ts {
        ($a:expr) => {
                {
                	nioruntime_log::log_no_ts!(nioruntime_log::INFO, $a);
		}
        };
        ($a:expr,$($b:tt)*)=>{
                {
                	nioruntime_log::log_no_ts!(nioruntime_log::INFO, $a, $($b)*);
		}
        };
}

/// Log at the 'debug' (1) log level. This macro calls the default logger. To configure this
/// logger, see [`log_config`]. It is used like the pritln/format macros.
/// Also see [`trace`], [`info`], [`warn`], [`error`], or [`fatal`].
/// # Examples
/// ```
/// use nioruntime_log::*;
/// // log level must be set before calling any logging function.
/// // typically it is done at the top of a file so that it's easy to change.
/// // but it can be done at any level or scope. The inner scope prevails.
/// debug!(); // set log level to debug "1"
///
/// let abc = 123;
/// debug!("my value = {}", abc);
/// debug!("hi");
///
/// // The output will look like this:
/// // [2021-08-09 19:41:37]: my value = 123
/// // [2021-08-09 19:41:37]: hi
/// ```
#[macro_export]
macro_rules! debug {
	() => {
		nioruntime_log::do_log!(nioruntime_log::DEBUG);
	};
        ($a:expr) => {
                {
                	log!(nioruntime_log::DEBUG, $a);
		}
        };
        ($a:expr,$($b:tt)*)=>{
                {
                	log!(nioruntime_log::DEBUG, $a, $($b)*);
		}
        };
}

/// Just like [`debug`], but with no timestamp.
#[macro_export]
macro_rules! debug_no_ts {
        ($a:expr) => {
                {
                	nioruntime_log::log_no_ts!(nioruntime_log::DEBUG, $a);
		}
        };
        ($a:expr,$($b:tt)*)=>{
                {
                	nioruntime_log::log_no_ts!(nioruntime_log::DEBUG, $a, $($b)*);
		}
        };
}

/// Log at the 'trace' (0) log level. This macro calls the default logger. To configure this
/// logger, see [`log_config`]. It is used like the pritln/format macros.
/// Also see [`debug`], [`info`], [`warn`], [`error`], or [`fatal`].
/// # Examples
/// ```
/// use nioruntime_log::*;
/// // log level must be set before calling any logging function.
/// // typically it is done at the top of a file so that it's easy to change.
/// // but it can be done at any level or scope. The inner scope prevails.
/// trace!(); // set log level to trace "0"
///
/// let abc = 123;
/// trace!("my value = {}", abc);
/// trace!("hi");
///
/// // The output will look like this:
/// // [2021-08-09 19:41:37]: my value = 123
/// // [2021-08-09 19:41:37]: hi
/// ```
#[macro_export]
macro_rules! trace {
        () => {
                nioruntime_log::do_log!(nioruntime_log::TRACE);
        };
        ($a:expr) => {
                {
                        nioruntime_log::log!(nioruntime_log::TRACE, $a);
                }
        };
        ($a:expr,$($b:tt)*)=>{
                {
                        nioruntime_log::log!(nioruntime_log::TRACE, $a, $($b)*);
                }
        };
}

/// Just like [`trace`], but with no timestamp.
#[macro_export]
macro_rules! trace_no_ts {
        ($a:expr) => {
                {
                        nioruntime_log::log_no_ts!(nioruntime_log::TRACE, $a);
                }
        };
        ($a:expr,$($b:tt)*)=>{
                {
                        nioruntime_log::log_no_ts!(nioruntime_log::TRACE, $a, $($b)*);
                }
        };
}

/// log_multi is identical to [`log`] except that the name of the logger is specified instead of using
/// the default logger.
/// # Examples
/// ```
/// use nioruntime_log::*;
/// // log level must be set before calling any logging function.
/// // typically it is done at the top of a file so that it's easy to change.
/// // but it can be done at any level or scope. The inner scope prevails.
/// info!();
///
/// let abc = 123;
/// log_multi!(nioruntime_log::WARN, "logger2", "hi");
/// log_multi!(nioruntime_log::WARN, "logger2", "value = {}", abc);
///
/// ```
#[macro_export]
macro_rules! log_multi {
	($level:expr, $a:expr, $b:expr) => {
		let static_log = &nioruntime_log::STATIC_LOG;
		let mut log_map = static_log.write();
		match log_map {
			Ok(mut log_map) => {
				let log = log_map.get_mut($a);
				match log {
					Some(log) => {
						nioruntime_log::do_log!($level, true, log, $b);
					},
					None => {
						let mut log = nioruntime_log::Log::new();
						nioruntime_log::do_log!($level, true, log, $b);
						log_map.insert($a.to_string(), log);
					}
				}
			},
			Err(e) => {
				println!(
					"Error: could not log '{}' due to PoisonError: {}",
					format!($b),
					e.to_string()
				);
			}
		}
	};
	($level:expr, $a:expr,$b:expr,$($c:tt)*)=>{
		let static_log = &nioruntime_log::STATIC_LOG;
		let mut log_map = static_log.write();
		match log_map {
			Ok(mut log_map) => {
				let log = log_map.get_mut($a);
				match log {
					Some(log) => {
						nioruntime_log::do_log!($level, true, log, $b, $($c)*);
					},
					None => {
						let mut log = nioruntime_log::Log::new();
						nioruntime_log::do_log!($level, true, log, $b, $($c)*);
						log_map.insert($a.to_string(), log);
					}
				}
			},
			Err(e) => {
				println!(
					"Error: could not log '{}' due to PoisonError: {}",
					format!($b, $($c)*),
					e.to_string()
				);
			},
		}
	};
}

/// The main logging macro. This macro calls the default logger. To configure this
/// logger, see [`log_config`]. It is used like the pritln/format macros. The first
/// parameter is the log level. To avoid specifying level, see [`trace`], [`debug`],
/// [`info`], [`warn`], [`error`], or [`fatal`].
/// # Examples
/// ```
/// use nioruntime_log::*;
///
/// info!(); // set log level to info "2"
///
/// let abc = 123;
/// log!(nioruntime_log::INFO, "my value = {}", abc);
/// log!(nioruntime_log::INFO, "hi");
///
/// // The output will look like this:
/// // [2021-08-09 19:41:37]: my value = 123
/// // [2021-08-09 19:41:37]: hi
/// ```
#[macro_export]
macro_rules! log {
	($level:expr, $a:expr)=>{
		{
                	const DEFAULT_LOG: &str = "default";
                	let static_log = &nioruntime_log::STATIC_LOG;
                	let mut log_map = static_log.write();
			match log_map {
				Ok(mut log_map) => {
                	let log = log_map.get_mut(&DEFAULT_LOG.to_string());
                	match log {
                        	Some(log) => {
                                	nioruntime_log::do_log!($level, true, log, $a);
                        	},
                        	None => {
                                	let mut log = nioruntime_log::Log::new();
                                	nioruntime_log::do_log!($level, true, log, $a);
                                	log_map.insert(DEFAULT_LOG.to_string(), log);
                        	}
                	}
				},
				Err(e) => {
                                        println!(
                                                "Error: could not log '{}' due to PoisonError: {}",
                                                format!($a),
                                                e.to_string()
                                        );
				},
			}
		}
    	};
	($level:expr, $a:expr,$($b:tt)*)=>{
		{
                        const DEFAULT_LOG: &str = "default";
                        let static_log = &nioruntime_log::STATIC_LOG;
                        let mut log_map = static_log.write().unwrap();
                        let log = log_map.get_mut(&DEFAULT_LOG.to_string());
                        match log {
                                Some(log) => {
                                        nioruntime_log::do_log!($level, true, log, $a, $($b)*);
                                },
                                None => {
                                        let mut log = nioruntime_log::Log::new();
                                        nioruntime_log::do_log!($level, true, log, $a, $($b)*);
                                        log_map.insert(DEFAULT_LOG.to_string(), log);
                                }
                        }
		}
	}
}

/// Identical to [`log_no_ts`] except that the name of the logger is specified instead of using
/// the default logger.
/// # Examples
///
/// ```
/// use nioruntime_log::*;
///
/// info!();
///
/// log_no_ts_multi!(2, "nondefaultlogger", "hi");
/// log_no_ts_multi!(2, "nondefaultlogger", "value = {}", 123);
/// ```
///
#[macro_export]
macro_rules! log_no_ts_multi {
        ($level:expr, $a:expr, $b:expr)=>{
                {
                        let static_log = &nioruntime_log::STATIC_LOG;
                        let mut log_map = static_log.write().unwrap();
                        let log = log_map.get_mut($a);
                        match log {
                                Some(log) => {
                                        { nioruntime_log::do_log!($level, false, log, $b); }
                                },
                                None => {
                                        let mut log = nioruntime_log::Log::new();
                                        { nioruntime_log::do_log!($level, false, log, $b); }
                                        log_map.insert($a.to_string(), log);
                                }
                        }
                }
        };
        ($level:expr, $a:expr,$b:expr,$($c:tt)*)=>{
                {
                        let static_log = &nioruntime_log::STATIC_LOG;
                        let mut log_map = static_log.write().unwrap();
                        let log = log_map.get_mut($a);
                        match log {
                                Some(log) => {
                                        { nioruntime_log::do_log!($level, false, log, $b, $($c)*) }
                                },
                                None => {
                                        let mut log = nioruntime_log::Log::new();
                                        { nioruntime_log::do_log!($level, false, log, $b, $($c)*) }
                                        log_map.insert($a.to_string(), log);
                                }
                        }
                }
        };
}

/// Log using the default logger and don't print a timestamp. See [`log`] for more details on logging.
/// # Examples
///
/// ```
/// use nioruntime_log::*;
///
/// debug!();
///
/// log!(2, "hi");
/// log_no_ts!(2, "message here");
/// log_no_ts!(3, "my value = {}", 1);
/// log!(2, "more data");
///
/// // The output will look like this:
/// // [2021-08-09 19:41:37]: hi
/// // message here
/// // my value = 1
/// // [2021-08-09 19:41:37]: more data
/// ```
#[macro_export]
macro_rules! log_no_ts {
	($level:expr, $a:expr)=>{
                {
                        const DEFAULT_LOG: &str = "default";
                        let static_log = &nioruntime_log::STATIC_LOG;
                        let mut log_map = static_log.write().unwrap();
                        let log = log_map.get_mut(&DEFAULT_LOG.to_string());
                        match log {
                                Some(log) => {
                                        { nioruntime_log::do_log!($level, false, log, $a); }
                                },
                                None => {
                                        let mut log = nioruntime_log::Log::new();
                                        { nioruntime_log::do_log!($level, false, log, $a); }
                                        log_map.insert(DEFAULT_LOG.to_string(), log);
                                }
                        }
                }
	};
	($level:expr, $a:expr,$($b:tt)*)=>{
		{

                        const DEFAULT_LOG: &str = "default";
                        let static_log = &nioruntime_log::STATIC_LOG;
                        let mut log_map = static_log.write().unwrap();
                        let log = log_map.get_mut(&DEFAULT_LOG.to_string());
                        match log {
                                Some(log) => {
                                        { nioruntime_log::do_log!($level, false, log, $a, $($b)*) }
                                },
                                None => {
                                        let mut log = nioruntime_log::Log::new();
                                        { nioruntime_log::do_log!($level, false, log, $a, $($b)*) }
                                        log_map.insert(DEFAULT_LOG.to_string(), log);
                                }
                        }
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
                                        // if not configured, use defaults
                                        if !$log.is_configured() {
                                                $log.config_with_object(nioruntime_log::LogConfig::default()).unwrap();
                                        }

					let cur_show_log_level = $log.get_show_log_level().unwrap_or(true);

					if $show_ts == false {
						let _ = $log.update_show_timestamp($show_ts);
						let _ = $log.update_show_log_level($show_ts);
					}

					if $level >= LOG_LEVEL {
                                       		match $log.log_level(&format!($a), $level) {
                                               		Ok(_) => {},
                                               		Err(e) => {
                                                       		println!(
                                                               		"Logging of '{}' resulted in Error: {}",
                                                               		format!($a),
                                                               		e.to_string(),
                                                       		);
                                               		}
                                       		}
					}

					let _ = $log.update_show_log_level(cur_show_log_level);
					// always set to showing timestamp (as default)
					let _ = $log.update_show_timestamp(true);

			}
        };
        ($level:expr, $show_ts:expr, $log:expr, $a:expr, $($b:tt)*)=>{
			{
                                        // if not configured, use defaults
                                        if !$log.is_configured() {
                                                $log.config_with_object(nioruntime_log::LogConfig::default()).unwrap();
                                        }

					let cur_show_log_level = $log.get_show_log_level().unwrap_or(true);
					if $show_ts == false {
						let _ = $log.update_show_timestamp($show_ts);
						let _ = $log.update_show_log_level($show_ts);
					}

					if $level >= LOG_LEVEL {
                                        	match $log.log_level(&format!($a, $($b)*), $level) {
                                                	Ok(_) => {},
                                                	Err(e) => {
                                                        	println!(
                                                                	"Logging of '{}' resulted in Error: {}",
                                                                	format!($a, $($b)*),
                                                                	e.to_string(),
                                                        	);
                                                	}
                                        	}
					}

                                        let _ = $log.update_show_log_level(cur_show_log_level);
                                        // always set to showing timestamp (as default)
                                        let _ = $log.update_show_timestamp(true);
			}
        };
}

/// get_config_multi get's the LogConfig structure for the specified logger
///
/// A sample get_config_multi! call might look something like this:
///
/// ```
/// use nioruntime_log::*;
///
/// info!();
/// const MAIN_LOG: &str = "mainlog";
///
/// log_multi!(INFO, MAIN_LOG, "test");
/// let mut config = get_config_multi!(MAIN_LOG).unwrap();
///
/// // print to stdout as well as log
/// config.show_stdout = true;
/// log_config_multi!(MAIN_LOG, config.clone());
///
///
/// log_multi!(
/// 	INFO,
/// 	MAIN_LOG,
/// 	"print to stdout as well",
/// );
///
/// config.show_stdout = false;
/// log_config_multi!(MAIN_LOG, config);
///
/// log_multi!(
/// 	INFO,
///	MAIN_LOG,
/// 	"print only to log file",
/// );
/// ```
///
/// For full details on all parameters of LogConfig see [`LogConfig`].
#[macro_export]
macro_rules! get_config_multi {
	($a:expr) => {{
		let static_log = &nioruntime_log::STATIC_LOG;
		let mut log_map = static_log.write();
		match log_map {
			Ok(mut log_map) => {
				let log = log_map.get_mut($a);
				match log {
					Some(log) => match &log.params {
						Some(params) => Ok(params.config.clone()),
						None => Err(nioruntime_err::ErrorKind::LogNotConfigured(
							"no params found".to_string(),
						)),
					},
					None => Err(nioruntime_err::ErrorKind::LogNotConfigured(
						"no config found".to_string(),
					)),
				}
			}
			Err(e) => Err(nioruntime_err::ErrorKind::PoisonError(format!(
				"log generated poison error: {}",
				e
			))
			.into()),
		}
	}};
}

/// log_config_multi is identical to [`log_config`] except that the name of the logger is specified instead of using
/// the default logger.
///
/// A sample log_config_multi! call might look something like this:
///
/// ```
/// use nioruntime_log::*;
///
/// info!();
///
/// log_config_multi!(
///     "nondefaultlogger",
///     LogConfig {
///         max_age_millis: 10000, // set log rotations to every 10 seconds
///         max_size: 10000, // set log rotations to every 10,000 bytes
///         ..Default::default()
///     }
/// );
/// ```
///
/// For full details on all parameters of LogConfig see [`LogConfig`].
#[macro_export]
macro_rules! log_config_multi {
	($a:expr, $b:expr) => {{
		let static_log = &nioruntime_log::STATIC_LOG;
		let mut log_map = static_log.write();
		match log_map {
			Ok(mut log_map) => {
				let log = log_map.get_mut($a);
				match log {
					Some(log) => log.config_with_object($b),
					None => {
						let mut log = nioruntime_log::Log::new();
						let ret = log.config_with_object($b);
						log_map.insert($a.to_string(), log);
						ret
					}
				}
			}
			Err(e) => Err(nioruntime_err::ErrorKind::PoisonError(format!(
				"log generated poison error: {}",
				e
			))
			.into()),
		}
	}};
}

/// This macro may be used to configure logging. If it is not called. The default LogConfig is used.
/// By default logging is only done to stdout.
/// A sample log_config! call might look something like this:
///
/// ```
/// use nioruntime_log::*;
///
/// info!();
///
/// log_config!(nioruntime_log::LogConfig {
/// 	max_age_millis: 10000, // set log rotations to every 10 seconds
/// 	max_size: 10000, // set log rotations to every 10,000 bytes
/// 	..Default::default()
/// });
/// ```
/// For full details on all parameters of LogConfig see [`LogConfig`].
#[macro_export]
macro_rules! log_config {
	($a:expr) => {{
		const DEFAULT_LOG: &str = "default";
		let static_log = &nioruntime_log::STATIC_LOG;
		let mut log_map = static_log.write();
		match log_map {
			Ok(mut log_map) => {
				let log = log_map.get_mut(&DEFAULT_LOG.to_string());
				match log {
					Some(log) => log.config_with_object($a),
					None => {
						let mut log = nioruntime_log::Log::new();
						let ret = log.config_with_object($a);
						log_map.insert(DEFAULT_LOG.to_string(), log);
						ret
					}
				}
			}
			Err(e) => Err(nioruntime_err::ErrorKind::PoisonError(format!(
				"log generated poison error: {}",
				e
			))
			.into()),
		}
	}};
}
