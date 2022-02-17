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

#![macro_use]

//! A logging library.

use crate::backtrace::Backtrace;
use crate::chrono::{DateTime, Local, Utc};
use crate::nioruntime_err::{Error, ErrorKind};
use crate::rand::random;
use std::convert::TryInto;
use std::fs::{canonicalize, metadata, File, OpenOptions};
use std::io::Write;
use std::path::PathBuf;
use std::time::Instant;

/// This enumeration is used to get/set properties of the log. These settings are generally set through
/// the [`set_config_option`] macro and the current settings for these properties can be obtained
/// via the [`get_config_option`] macro.
pub enum Settings {
	/// Setting as to whether the logger will print to standard out. (true/false).
	Stdout,
	/// Setting as to whether the logger will print a timestamp for each line. (true/false).
	Timestamp,
	/// Setting as to whether the logger will print the log level for each line. (true/false).
	Level,
	/// Setting as to whether the logger will print the line number for each line. (true/false).
	LineNum,
}

/// Trace level of logging. Should be used for very frequent logging that is only used to debug.
pub const TRACE: i32 = 0;
/// Debug level of logging. Should only be used for debugging information.
pub const DEBUG: i32 = 1;
/// Info level of logging. For displaying information that is generally useful to the user.
pub const INFO: i32 = 2;
/// Warn level of logging. Used to warn of a possible problem.
pub const WARN: i32 = 3;
/// Error level of logging. Used to indicate an error has occured that the user should know about.
pub const ERROR: i32 = 4;
/// Fatal level of logging. Used to indicate a fatal error has occured and that the program might
/// have halted.
pub const FATAL: i32 = 5;

const DISPLAY_ARRAY: [&str; 6] = ["TRACE", "DEBUG", "INFO", "WARN", "ERROR", "FATAL"];

/// The main logging object. Usually this is used through macros.
pub struct Log {
	log_impl: Option<LogImpl>,
}

/// The data that is held by the Log object.
struct LogImpl {
	file: Option<File>,
	cur_size: u64,
	last_rotation: Instant,
	config: LogConfig,
	has_rotated: bool,
}

/// Result of a [`Log::rotation_status`] function call.
#[derive(Debug, PartialEq)]
pub enum RotationStatus {
	/// A rotation is not needed.
	NotNeeded,
	/// A rotation is needed.
	Needed,
	/// A rotation has occurred automatically.
	AutoRotated,
}

/// Log Config object. Passed into the [`Log::init`] function. Also may be set via the
/// [`log_config`] and [`log_config_multi`] macros.
#[derive(Debug, Clone)]
pub struct LogConfig {
	/// The path to the log file. By default, logging is only printed to standard output.
	/// This default behaviour is acheived by setting file_path to None.
	/// If you wish to log to a file, this parameter must be set to a valid path.
	pub file_path: Option<String>,
	/// The maximum size in bytes of the log file before a log rotation occurs. By default,
	/// this is set to 10485760 bytes (10 mb). After a log rotation, a new file named:
	/// <log_name>.r_<month>_<day>_<year>_<hour>-<minute>-<second>_<random_number>.log
	/// For example, something like this: mainlog.r_08_10_2021_03-12-23_12701992901411981750.log
	/// is created.
	pub max_size: u64,
	/// The maximum age in milliseconds before a log rotation occurs. By default, this is set to
	/// 3600000 ms (1 hour). After a log rotation, a new file named:
	/// <log_name>.r_<month>_<day>_<year>_<hour>-<minute>-<second>_<random_number>.log
	/// For example, something like this: mainlog.r_08_10_2021_03-12-23_12701992901411981750.log
	/// is created.
	pub max_age_millis: u128,
	/// The header (first line) of a log file. By default the header is not printed.
	pub file_header: String,
	/// Whether or not to show the timestamp. By default, this is set to true.
	pub show_timestamp: bool,
	/// Whether or not to print the log lines to standard output. Default is true.
	pub show_stdout: bool,
	/// delete the rotated log immidiately (only used for testing). Default is false.
	pub delete_rotation: bool,
	/// display the log level. Default is true.
	pub show_log_level: bool,
	/// display the line number and file name that the log request came from. Default is true.
	pub show_line_num: bool,
	/// automatically rotate the log file. Default is true.
	pub auto_rotate: bool,
	/// The maximum length of a file name when printing it to the log. The default value is 25.
	pub max_file_name_len: usize,
	/// Show the backtrace when log level is set to ERROR or FATAL. The default value is true.
	pub show_bt: bool,
}

/// Return a default logging object.
impl Default for LogConfig {
	fn default() -> Self {
		LogConfig {
			file_path: None,
			max_size: 1024 * 1024 * 10,     // 10 mb
			max_age_millis: 60 * 60 * 1000, // 1 hr
			file_header: "".to_string(),
			show_timestamp: true,
			show_stdout: true,
			delete_rotation: false,
			show_log_level: true,
			show_line_num: true,
			auto_rotate: true,
			show_bt: true,
			max_file_name_len: 25,
		}
	}
}

impl LogImpl {
	/// This function rotates logs
	pub fn rotate(&mut self) -> Result<(), Error> {
		// get date and create a custom rotation file name.
		let now: DateTime<Utc> = Utc::now();
		let rotation_string = now.format(".r_%m_%d_%Y_%T").to_string().replace(":", "-");
		let original_file_path = match &self.config.file_path {
			Some(file_path) => file_path,
			None => {
				// not logging to disk. No need to rotate
				return Ok(());
			}
		};
		let new_file_path = match original_file_path.rfind(".") {
			Some(pos) => &original_file_path[0..pos],
			_ => &original_file_path,
		};

		let new_file_path = format!(
			"{}{}_{}.log",
			new_file_path,
			rotation_string,
			random::<u64>(),
		);

		// if delete rotation is set (testing) the log rotation is deleted.
		if self.config.delete_rotation {
			std::fs::remove_file(&original_file_path)?;
		} else {
			std::fs::rename(&original_file_path, new_file_path.clone())?;
		}

		// open the original log file location which has been renamed and continue logging.
		self.file = Some(
			OpenOptions::new()
				.append(true)
				.create(true)
				.open(&original_file_path)?,
		);

		// we know it exists because we returned earlir if file_path is none.
		let mut file = self.file.as_ref().unwrap();
		let line_bytes = self.config.file_header.as_bytes();
		if line_bytes.len() > 0 {
			file.write(line_bytes)?;
			file.write(&[10u8])?; // new line
			self.cur_size = line_bytes.len() as u64 + 1;
		} else {
			self.cur_size = 0;
		}
		self.last_rotation = Instant::now();

		Ok(())
	}

	/// Get the [`RotationStatus`] of the log.
	pub fn rotation_status(&mut self) -> Result<RotationStatus, Error> {
		// get current time
		let instant_now = Instant::now();
		if self.file.is_some()
			&& (self.cur_size >= self.config.max_size
				|| instant_now.duration_since(self.last_rotation).as_millis()
					> self.config.max_age_millis)
		{
			self.has_rotated = false;
			Ok(RotationStatus::Needed)
		} else if self.has_rotated {
			self.has_rotated = false;
			Ok(RotationStatus::AutoRotated)
		} else {
			Ok(RotationStatus::NotNeeded)
		}
	}

	/// The actual logging function, handles rotation if needed
	pub fn log(&mut self, line: &str, level: i32) -> Result<(), Error> {
		// get current time
		let instant_now = Instant::now();
		let time_since_rotation = instant_now.duration_since(self.last_rotation).as_millis();

		// check if rotation is needed
		if self.config.auto_rotate
			&& self.file.is_some()
			&& (self.cur_size >= self.config.max_size
				|| time_since_rotation > self.config.max_age_millis)
		{
			self.has_rotated = true;
			self.rotate()?;
		}

		let line_bytes = line.as_bytes(); // get line as bytes
		self.cur_size += line_bytes.len() as u64 + 1; // increment cur_size
		if self.config.show_timestamp {
			// timestamp is an additional 23 bytes
			self.cur_size += 23;
		}
		if self.config.show_log_level
			&& level <= DISPLAY_ARRAY.len().try_into().unwrap_or(0)
			&& level >= 0
		{
			self.cur_size += DISPLAY_ARRAY[level.try_into().unwrap_or(0)]
				.len()
				.try_into()
				.unwrap_or(0) + 3;
		}

		let line_num_text = if self.config.show_line_num {
			let mut found_logger = false;
			let mut found_frame = false;
			let mut logged_from_file = "unknown".to_string();
			nioruntime_deps::backtrace::trace(|frame| {
				nioruntime_deps::backtrace::resolve_frame(frame, |symbol| {
					if let Some(filename) = symbol.filename() {
						let filename = filename.display().to_string();
						let lineno = match symbol.lineno() {
							Some(lineno) => lineno.to_string(),
							None => "".to_string(),
						};
						if filename.find("nioruntime/log/src/logger.rs").is_some() {
							found_logger = true;
						}
						if filename.find("nioruntime/log/src/logger.rs").is_none() && found_logger {
							logged_from_file = format!("{}:{}", filename, lineno);
							found_frame = true;
						}
					}
				});
				!found_frame
			});

			let len = logged_from_file.len();
			if len > self.config.max_file_name_len {
				let start = len - self.config.max_file_name_len;
				logged_from_file = format!("..{}", &logged_from_file[start..]);
			}
			format!("[{}]: ", logged_from_file)
		} else {
			"".to_string()
		};
		self.cur_size += line_num_text.len().try_into().unwrap_or(0);

		// if we're showing the timestamp, print it
		if self.config.show_timestamp {
			let date = Local::now();
			let formatted_ts = date.format("%Y-%m-%d %H:%M:%S");
			if self.file.is_some() {
				self.file
					.as_ref()
					.unwrap()
					.write(format!("[{}]: ", formatted_ts).as_bytes())?;
			}
			if self.config.show_stdout {
				print!("[{}]: ", formatted_ts);
			}
		}

		if self.config.show_log_level
			&& level < DISPLAY_ARRAY.len().try_into().unwrap_or(0)
			&& level >= 0
		{
			if self.file.is_some() {
				self.file.as_ref().unwrap().write(
					format!("({}) ", DISPLAY_ARRAY[level.try_into().unwrap_or(0)]).as_bytes(),
				)?;
			}
			if self.config.show_stdout {
				print!("({}) ", DISPLAY_ARRAY[level.try_into().unwrap_or(0)]);
			}
		}

		if line_num_text.len() > 0 {
			match &mut self.file {
				Some(file) => {
					file.write(line_num_text.as_bytes())?;
				}
				None => {}
			}
			if self.config.show_stdout {
				print!("{}", line_num_text);
			}
		}

		// finally log the line followed by a newline.
		if self.file.is_some() {
			let mut file = self.file.as_ref().unwrap();
			file.write(line_bytes)?;
			file.write(&[10u8])?; // newline
			if self.config.show_bt && level >= ERROR {
				let bt = Backtrace::new();
				let bt_text = format!("{:?}", bt);
				let bt_bytes: &[u8] = bt_text.as_bytes();
				file.write(bt_bytes)?;
				self.cur_size += bt_bytes.len() as u64;
			}
		}

		// if stdout is specified log to stdout too
		if self.config.show_stdout {
			println!("{}", line);
			if self.config.show_bt && level >= ERROR {
				let bt = Backtrace::new();
				let bt_text = format!("{:?}", bt);
				print!("{}", bt_text);
				self.cur_size += bt_text.len() as u64;
			}
		}

		Ok(())
	}
}

impl Log {
	/// create a new Log object
	pub fn new() -> Log {
		Log { log_impl: None }
	}

	/// Check if the log is configured
	pub fn is_configured(&self) -> bool {
		self.log_impl.is_some()
	}

	pub fn get_config(&self) -> Result<LogConfig, Error> {
		match &self.log_impl {
			Some(log_impl) => Ok(log_impl.config.clone()),
			None => Err(ErrorKind::LogConfigurationError("log_impl None".to_string()).into()),
		}
	}

	/// Initialize the log file with the parameters in [`LogConfig`].
	pub fn init(&mut self, mut config: LogConfig) -> Result<(), Error> {
		if self.is_configured() {
			return Err(
				ErrorKind::LogConfigurationError("Log already configured".to_string()).into(),
			);
		}

		let has_rotated = false;

		let file = match config.file_path.clone() {
			Some(file_path) => Some(
				OpenOptions::new()
					.append(true)
					.create(true)
					.open(file_path)?,
			),
			None => None,
		};

		config.file_path = match config.file_path {
			Some(file_path) => Some(
				canonicalize(PathBuf::from(file_path))?
					.into_os_string()
					.into_string()?,
			),
			None => None,
		};

		// get current size of the file
		let mut cur_size = match config.file_path.clone() {
			Some(file_path) => metadata(file_path)?.len(),
			None => 0,
		};

		let file_header = config.file_header.to_string();
		if cur_size == 0 && config.file_path.is_some() {
			// add the header if the file is new
			let line_bytes = file_header.as_bytes();
			if line_bytes.len() > 0 {
				let mut file = file.as_ref().unwrap();
				file.write(line_bytes)?;
				file.write(&[10u8])?; // new line
				cur_size = file_header.len() as u64 + 1;
			}
		}

		let last_rotation = Instant::now();

		self.log_impl = Some(LogImpl {
			config,
			file,
			cur_size,
			last_rotation,
			has_rotated,
		});

		Ok(())
	}

	/// Rotate the log
	pub fn rotate(&mut self) -> Result<(), Error> {
		match self.log_impl.as_mut() {
			Some(log_impl) => log_impl.rotate(),
			None => Err(ErrorKind::LogConfigurationError("log_impl None".to_string()).into()),
		}
	}

	/// Check if a rotation is needed
	pub fn rotation_status(&mut self) -> Result<RotationStatus, Error> {
		match self.log_impl.as_mut() {
			Some(log_impl) => log_impl.rotation_status(),
			None => Err(ErrorKind::LogConfigurationError("log_impl None".to_string()).into()),
		}
	}

	/// Entry point for logging
	pub fn log(&mut self, level: i32, line: &str) -> Result<(), Error> {
		match self.log_impl.as_mut() {
			Some(log_impl) => {
				log_impl.log(line, level)?;
				Ok(())
			}
			None => Err(ErrorKind::LogConfigurationError("log_impl None".to_string()).into()),
		}
	}

	/// Change the show_line_num setting to the show value.
	pub fn update_show_line_num(&mut self, show: bool) -> Result<(), Error> {
		match self.log_impl.as_mut() {
			Some(log_impl) => {
				log_impl.config.show_line_num = show;
				Ok(())
			}
			None => Err(ErrorKind::LogConfigurationError("log_impl None".to_string()).into()),
		}
	}

	/// Get the show_line_num setting value.
	pub fn get_show_line_num(&mut self) -> Result<bool, Error> {
		match self.log_impl.as_mut() {
			Some(log_impl) => Ok(log_impl.config.show_line_num),
			None => Err(ErrorKind::LogConfigurationError("log_impl None".to_string()).into()),
		}
	}

	/// Change the show_log_level setting to the show value.
	pub fn update_show_log_level(&mut self, show: bool) -> Result<(), Error> {
		match self.log_impl.as_mut() {
			Some(log_impl) => {
				log_impl.config.show_log_level = show;
				Ok(())
			}
			None => Err(ErrorKind::LogConfigurationError("log_impl None".to_string()).into()),
		}
	}

	/// Get the show_log_level setting value.
	pub fn get_show_log_level(&mut self) -> Result<bool, Error> {
		match self.log_impl.as_mut() {
			Some(log_impl) => Ok(log_impl.config.show_log_level),
			None => Err(ErrorKind::LogConfigurationError("log_impl None".to_string()).into()),
		}
	}

	/// Change the show_timestamp setting to the show value.
	pub fn update_show_timestamp(&mut self, show: bool) -> Result<(), Error> {
		match self.log_impl.as_mut() {
			Some(log_impl) => {
				log_impl.config.show_timestamp = show;
				Ok(())
			}
			None => Err(ErrorKind::LogConfigurationError("log_impl None".to_string()).into()),
		}
	}

	/// Get the show_timestamp setting value.
	pub fn get_show_timestamp(&mut self) -> Result<bool, Error> {
		match self.log_impl.as_mut() {
			Some(log_impl) => Ok(log_impl.config.show_timestamp),
			None => Err(ErrorKind::LogConfigurationError("log_impl None".to_string()).into()),
		}
	}

	/// Change the show_stdout setting to the show value.
	pub fn update_show_stdout(&mut self, show: bool) -> Result<(), Error> {
		match self.log_impl.as_mut() {
			Some(log_impl) => {
				log_impl.config.show_stdout = show;
				Ok(())
			}
			None => Err(ErrorKind::LogConfigurationError("log_impl None".to_string()).into()),
		}
	}

	/// Get the show_stdout setting value.
	pub fn get_show_stdout(&mut self) -> Result<bool, Error> {
		match self.log_impl.as_mut() {
			Some(log_impl) => Ok(log_impl.config.show_stdout),
			None => Err(ErrorKind::LogConfigurationError("log_impl None".to_string()).into()),
		}
	}
}

// helper function for macros
pub fn do_log(
	level: i32,
	show_ts: bool,
	log: &mut Log,
	line: String,
	config_level: i32,
) -> Result<(), Error> {
	if !log.is_configured() {
		log.init(LogConfig::default())?;
	}

	let cur_show_log_level = log.get_show_log_level()?;
	let cur_show_line_num = log.get_show_line_num()?;
	let cur_show_timestamp = log.get_show_timestamp()?;

	if show_ts == false {
		log.update_show_timestamp(show_ts)?;
		log.update_show_log_level(show_ts)?;
		log.update_show_line_num(show_ts)?;
	}

	if level >= config_level {
		log.log(level, &line)?;
	}

	log.update_show_log_level(cur_show_log_level)?;
	log.update_show_line_num(cur_show_line_num)?;
	log.update_show_timestamp(cur_show_timestamp)?;

	Ok(())
}

#[cfg(test)]
mod tests {
	use crate::logger::LogImpl;
	use crate::*;
	use nioruntime_err::{Error, ErrorKind};
	use std::time::Instant;

	fn setup_test_dir() -> Result<(), Error> {
		let _ = std::fs::remove_dir_all(".test_log.nio");
		std::fs::create_dir_all(".test_log.nio")?;
		Ok(())
	}

	fn tear_down_test_dir() -> Result<(), Error> {
		std::fs::remove_dir_all(".test_log.nio")?;
		Ok(())
	}

	#[test]
	fn test_log() -> Result<(), Error> {
		setup_test_dir()?;

		// default settings - no line num
		let mut log = Log::new();
		let config = LogConfig {
			file_path: Some(".test_log.nio/test1.log".to_string()),
			show_line_num: false,
			delete_rotation: true,
			show_stdout: false,
			..Default::default()
		};

		// check inputs
		assert!(!log.is_configured());

		assert_eq!(
			log.rotate().err().unwrap().kind(),
			ErrorKind::LogConfigurationError("log_impl None".to_string())
		);
		assert!(log.update_show_line_num(true).is_err());
		assert_eq!(
			log.update_show_line_num(true).err().unwrap().kind(),
			ErrorKind::LogConfigurationError("log_impl None".to_string())
		);
		assert!(log.get_show_line_num().is_err());
		assert_eq!(
			log.get_show_line_num().err().unwrap().kind(),
			ErrorKind::LogConfigurationError("log_impl None".to_string())
		);
		assert!(log.update_show_log_level(true).is_err());
		assert_eq!(
			log.update_show_log_level(false).err().unwrap().kind(),
			ErrorKind::LogConfigurationError("log_impl None".to_string())
		);
		assert!(log.get_show_log_level().is_err());
		assert_eq!(
			log.get_show_log_level().err().unwrap().kind(),
			ErrorKind::LogConfigurationError("log_impl None".to_string())
		);
		assert!(log.update_show_timestamp(true).is_err());
		assert_eq!(
			log.update_show_timestamp(false).err().unwrap().kind(),
			ErrorKind::LogConfigurationError("log_impl None".to_string())
		);
		assert!(log.get_show_timestamp().is_err());
		assert_eq!(
			log.get_show_timestamp().err().unwrap().kind(),
			ErrorKind::LogConfigurationError("log_impl None".to_string())
		);
		assert_eq!(
			log.update_show_stdout(false).err().unwrap().kind(),
			ErrorKind::LogConfigurationError("log_impl None".to_string())
		);
		assert!(log.update_show_stdout(true).is_err());
		assert_eq!(
			log.get_show_stdout().err().unwrap().kind(),
			ErrorKind::LogConfigurationError("log_impl None".to_string())
		);
		assert!(log.get_show_stdout().is_err());
		assert_eq!(
			log.rotation_status().err().unwrap().kind(),
			ErrorKind::LogConfigurationError("log_impl None".to_string())
		);
		assert!(log.rotation_status().is_err());

		log.init(config)?;
		assert!(log.is_configured());
		log.log(DEBUG, "with_level")?;
		let text = std::fs::read_to_string(".test_log.nio/test1.log")?;
		assert_eq!(text.chars().nth(23).unwrap(), '(');
		assert_eq!(text.chars().nth(24).unwrap(), 'D');
		assert_eq!(text.chars().nth(25).unwrap(), 'E');
		assert_eq!(text.chars().nth(26).unwrap(), 'B');
		assert_eq!(text.chars().nth(27).unwrap(), 'U');
		assert_eq!(text.chars().nth(28).unwrap(), 'G');
		assert_eq!(text.chars().nth(29).unwrap(), ')');
		assert_eq!(text.chars().nth(30).unwrap(), ' ');
		assert_eq!(text.chars().nth(31).unwrap(), 'w');

		// no log level
		let mut log = Log::new();
		let config = LogConfig {
			show_log_level: false,
			file_path: Some(".test_log.nio/test2.log".to_string()),
			show_line_num: false,
			..Default::default()
		};
		log.init(config)?;
		log.log(INFO, "test")?;
		let text = std::fs::read_to_string(".test_log.nio/test2.log")?;

		assert_eq!(text.chars().nth(23).unwrap(), 't');
		assert_eq!(text.chars().nth(24).unwrap(), 'e');
		assert_eq!(text.chars().nth(25).unwrap(), 's');
		assert_eq!(text.chars().nth(26).unwrap(), 't');

		// no timestamp/log level
		let mut log = Log::new();
		let config = LogConfig {
			show_timestamp: false,
			show_log_level: false,
			show_line_num: false,
			file_path: Some(".test_log.nio/test3.log".to_string()),
			..Default::default()
		};
		log.init(config)?;
		log.log(INFO, "test")?;
		let text = std::fs::read_to_string(".test_log.nio/test3.log")?;

		assert_eq!(text.chars().nth(0).unwrap(), 't');
		assert_eq!(text.chars().nth(1).unwrap(), 'e');
		assert_eq!(text.chars().nth(2).unwrap(), 's');
		assert_eq!(text.chars().nth(3).unwrap(), 't');

		// test rotation
		let mut log = Log::new();
		let config = LogConfig {
			show_timestamp: false,
			show_log_level: false,
			show_line_num: false,
			max_size: 65,
			file_path: Some(".test_log.nio/test4.log".to_string()),
			..Default::default()
		};
		log.init(config)?;
		for _ in 0..10 {
			log.log(INFO, "01234567")?;
		}

		// there should be two files.
		let paths = std::fs::read_dir(".test_log.nio").unwrap();
		let mut count = 0;
		for path in paths {
			let path = path.unwrap().path().display().to_string();
			if path.find(".test_log.nio/test4.log") == Some(0) {
				let len = std::fs::metadata(path)?.len();
				assert_eq!(len, 18);
				count += 1;
			} else if path.find(".test_log.nio/test4.r") == Some(0) {
				let len = std::fs::metadata(path)?.len();
				assert_eq!(len, 72);
				count += 1;
			}
		}

		assert_eq!(count, 2);

		// test time based rotation
		let mut log = Log::new();
		let config = LogConfig {
			show_timestamp: false,
			show_log_level: false,
			show_line_num: false,
			max_age_millis: 65,
			file_path: Some(".test_log.nio/test5.log".to_string()),
			..Default::default()
		};
		log.init(config)?;
		log.log(INFO, "0123")?;
		log.log(DEBUG, "45678")?;
		std::thread::sleep(std::time::Duration::from_millis(100));
		log.log(INFO, "9012345678")?;

		// there should be two files.
		let paths = std::fs::read_dir(".test_log.nio").unwrap();
		let mut count = 0;
		for path in paths {
			let path = path.unwrap().path().display().to_string();
			if path.find(".test_log.nio/test5.log") == Some(0) {
				let len = std::fs::metadata(path)?.len();
				assert_eq!(len, 11);
				count += 1;
			} else if path.find(".test_log.nio/test5.r") == Some(0) {
				let len = std::fs::metadata(path)?.len();
				assert_eq!(len, 11);
				count += 1;
			}
		}
		assert_eq!(count, 2);

		// test with show line num
		// test time based rotation
		let mut log = Log::new();
		let config = LogConfig {
			show_timestamp: true,
			show_log_level: false,
			show_line_num: true,
			file_path: Some(".test_log.nio/test6.log".to_string()),
			..Default::default()
		};
		log.init(config)?;
		log.log(INFO, "0123")?;

		let text = std::fs::read_to_string(".test_log.nio/test6.log")?;
		assert_eq!(text.find("]: 0").unwrap() > 20, true);

		// with show_log_level too
		let mut log = Log::new();
		let config = LogConfig {
			show_timestamp: true,
			show_log_level: true,
			show_line_num: true,
			file_path: Some(".test_log.nio/test7.log".to_string()),
			..Default::default()
		};
		log.init(config)?;
		log.log(INFO, "0123")?;

		let text = std::fs::read_to_string(".test_log.nio/test7.log")?;
		assert_eq!(text.find("]: 0").unwrap() > 20, true);

		// update format
		let mut log = Log::new();
		let config = LogConfig {
			show_timestamp: true,
			show_log_level: true,
			show_line_num: true,
			file_path: Some(".test_log.nio/test8.log".to_string()),
			..Default::default()
		};
		log.init(config)?;

		assert_eq!(log.get_show_timestamp()?, true);
		assert_eq!(log.get_show_log_level()?, true);
		assert_eq!(log.get_show_line_num()?, true);
		log.log(INFO, "1line")?;
		log.update_show_line_num(false)?;
		assert_eq!(log.get_show_timestamp()?, true);
		assert_eq!(log.get_show_log_level()?, true);
		assert_eq!(log.get_show_line_num()?, false);
		log.log(INFO, "2line")?;
		log.update_show_log_level(false)?;
		assert_eq!(log.get_show_timestamp()?, true);
		assert_eq!(log.get_show_log_level()?, false);
		assert_eq!(log.get_show_line_num()?, false);
		log.log(INFO, "3line")?;
		log.update_show_timestamp(false)?;
		assert_eq!(log.get_show_timestamp()?, false);
		assert_eq!(log.get_show_log_level()?, false);
		assert_eq!(log.get_show_line_num()?, false);
		log.log(INFO, "4line")?;
		log.update_show_log_level(true)?;
		assert_eq!(log.get_show_timestamp()?, false);
		assert_eq!(log.get_show_log_level()?, true);
		assert_eq!(log.get_show_line_num()?, false);
		log.log(INFO, "5line")?;
		log.update_show_timestamp(true)?;
		assert_eq!(log.get_show_timestamp()?, true);
		assert_eq!(log.get_show_log_level()?, true);
		assert_eq!(log.get_show_line_num()?, false);
		log.log(INFO, "6line")?;
		log.update_show_line_num(true)?;
		assert_eq!(log.get_show_timestamp()?, true);
		assert_eq!(log.get_show_log_level()?, true);
		assert_eq!(log.get_show_line_num()?, true);
		assert_eq!(log.get_show_stdout()?, true);
		log.update_show_stdout(false)?;
		assert_eq!(log.get_show_stdout()?, false);
		log.log(INFO, "7line")?;
		log.update_show_stdout(true)?;
		assert_eq!(log.get_show_stdout()?, true);

		let text = std::fs::read_to_string(".test_log.nio/test8.log")?;
		let split: Vec<&str> = text.split("\n").collect();

		assert_eq!(split.len(), 8);
		assert_eq!(split[0].find("1line").unwrap() > 55, true);
		assert_eq!(split[1].find("2line"), Some(30));
		assert_eq!(split[2].find("3line"), Some(23));
		assert_eq!(split[3].find("4line"), Some(0));
		assert_eq!(split[4].find("5line"), Some(7));
		assert_eq!(split[5].find("6line"), Some(30));
		assert_eq!(split[6].find("7line").unwrap() > 55, true);
		assert_eq!(split[7].find("8line"), None); // empty last line

		// file header
		let mut log = Log::new();
		let config = LogConfig {
			show_timestamp: false,
			show_log_level: false,
			show_line_num: false,
			file_path: Some(".test_log.nio/test9.log".to_string()),
			file_header: "myheader".to_string(),
			..Default::default()
		};
		log.init(config)?;

		log.log(INFO, "1line")?;
		log.log(INFO, "2line")?;
		log.log(INFO, "3line")?;
		log.log(INFO, "4line")?;

		let text = std::fs::read_to_string(".test_log.nio/test9.log")?;
		assert_eq!(
			text,
			"myheader\n\
1line\n\
2line\n\
3line\n\
4line\n"
		);

		// test rotation status
		let mut log = Log::new();
		let config = LogConfig {
			show_timestamp: false,
			show_log_level: false,
			show_line_num: false,
			max_age_millis: 50,
			file_path: Some(".test_log.nio/test10.log".to_string()),
			file_header: "myheader".to_string(),
			..Default::default()
		};
		log.init(config)?;

		assert_eq!(log.rotation_status()?, RotationStatus::NotNeeded);
		log.log(INFO, "1line")?;
		std::thread::sleep(std::time::Duration::from_millis(100));
		assert_eq!(log.rotation_status()?, RotationStatus::Needed);
		assert_eq!(log.rotation_status()?, RotationStatus::Needed);
		log.log(INFO, "2line")?;
		assert_eq!(log.rotation_status()?, RotationStatus::AutoRotated);
		assert_eq!(log.rotation_status()?, RotationStatus::NotNeeded);
		std::thread::sleep(std::time::Duration::from_millis(100));
		assert_eq!(log.rotation_status()?, RotationStatus::Needed);
		log.rotate()?;
		assert_eq!(log.rotation_status()?, RotationStatus::NotNeeded);

		// with no auto-rotate
		let mut log = Log::new();
		let config = LogConfig {
			show_timestamp: false,
			show_log_level: false,
			show_line_num: false,
			auto_rotate: false,
			max_age_millis: 50,
			file_path: Some(".test_log.nio/test10.log".to_string()),
			file_header: "myheader".to_string(),
			..Default::default()
		};
		log.init(config)?;

		assert_eq!(log.rotation_status()?, RotationStatus::NotNeeded);
		log.log(INFO, "1line")?;
		std::thread::sleep(std::time::Duration::from_millis(100));
		assert_eq!(log.rotation_status()?, RotationStatus::Needed);
		assert_eq!(log.rotation_status()?, RotationStatus::Needed);
		log.log(INFO, "2line")?;
		assert_eq!(log.rotation_status()?, RotationStatus::Needed);
		assert_eq!(log.rotation_status()?, RotationStatus::Needed);
		std::thread::sleep(std::time::Duration::from_millis(100));
		assert_eq!(log.rotation_status()?, RotationStatus::Needed);
		log.rotate()?;
		assert_eq!(log.rotation_status()?, RotationStatus::NotNeeded);

		let mut log = Log::new();
		let config = LogConfig {
			show_timestamp: false,
			show_log_level: false,
			show_line_num: false,
			auto_rotate: false,
			max_size: 20,
			file_path: Some(".test_log.nio/test12.log".to_string()),
			file_header: "myheader".to_string(),
			..Default::default()
		};
		log.init(config)?;

		log.log(INFO, "01234567890")?;
		assert_eq!(log.rotation_status()?, RotationStatus::Needed);
		log.rotate()?;
		assert_eq!(log.rotation_status()?, RotationStatus::NotNeeded);
		log.log(INFO, "01234567890")?;
		assert_eq!(log.rotation_status()?, RotationStatus::Needed);
		log.log(INFO, "01234567890")?;
		assert_eq!(log.rotation_status()?, RotationStatus::Needed);

		let mut log = Log::new();
		let config = LogConfig {
			show_timestamp: false,
			show_log_level: false,
			show_line_num: false,
			auto_rotate: true,
			max_size: 5,
			file_path: Some(".test_log.nio/test13.log".to_string()),
			file_header: "".to_string(),
			..Default::default()
		};
		log.init(config)?;

		log.log(INFO, "0")?;
		assert_eq!(log.rotation_status()?, RotationStatus::NotNeeded);
		log.log(INFO, "01234567890")?;
		assert_eq!(log.rotation_status()?, RotationStatus::Needed);
		log.rotate()?;
		assert_eq!(log.rotation_status()?, RotationStatus::NotNeeded);
		log.log(INFO, "01234567890")?;
		assert_eq!(log.rotation_status()?, RotationStatus::Needed);
		log.log(INFO, "01234567890")?;
		assert_eq!(log.rotation_status()?, RotationStatus::Needed);
		log.log(INFO, "01234567890")?;
		assert_eq!(log.rotation_status()?, RotationStatus::Needed);
		log.rotate()?;
		assert_eq!(log.rotation_status()?, RotationStatus::NotNeeded);

		// more code coverage
		let mut log = Log::new();
		log.init(LogConfig::default())?;
		log.log(TRACE, "hello")?;
		log.log(DEBUG, "hello")?;
		log.log(INFO, "hello")?;
		log.log(WARN, "hello")?;
		log.log(ERROR, "hello")?;
		log.log(FATAL, "hello")?;

		let config = LogConfig {
			file_path: None,
			max_size: 1024 * 1024 * 10,     // 10 mb
			max_age_millis: 60 * 60 * 1000, // 1 hr
			file_header: "".to_string(),
			show_timestamp: true,
			show_stdout: true,
			delete_rotation: false,
			show_log_level: true,
			show_line_num: true,
			auto_rotate: true,
			max_file_name_len: 25,
			show_bt: true,
		};
		let mut log = Log::new();
		log.init(config)?;
		assert!(log.init(LogConfig::default()).is_err());

		let mut log = Log::new();
		let config = LogConfig {
			max_size: 10,
			..Default::default()
		};
		log.init(config)?;
		log.log(FATAL, "0123456789012345")?;
		let mut log = Log::new();
		let config = LogConfig {
			max_size: 10,
			..Default::default()
		};
		log.init(config)?;
		log.log(INFO, "abcdefghijklmnopqrs")?;

		let mut log = Log::new();
		let config = LogConfig {
			file_path: Some(".test_log.nio/test11.log".to_string()),
			max_size: 10,
			delete_rotation: true,
			..Default::default()
		};
		log.init(config)?;
		log.log(FATAL, "0123456789012345")?;
		log.log(FATAL, "0123456789012345")?;
		log.log(FATAL, "0123456789012345")?;

		let mut log = Log::new();
		let config = LogConfig {
			max_size: 10,
			delete_rotation: true,
			..Default::default()
		};
		let _config = config.clone();
		log.init(config)?;
		log.log(FATAL, "0123456789012345")?;
		log.log(FATAL, "0123456789012345")?;
		log.log(FATAL, "0123456789012345")?;
		log.rotate()?;

		let _log_impl = LogImpl {
			file: None,
			cur_size: 1,
			last_rotation: Instant::now(),
			config: LogConfig::default(),
			has_rotated: false,
		};

		tear_down_test_dir()?;
		Ok(())
	}
}
