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

use crate::failure::{Backtrace, Context, Fail};
#[cfg(unix)]
use crate::nix::errno::Errno;
use crate::rustls::client::InvalidDnsNameError;
use nioruntime_deps::hex::FromHexError;
use std::convert::Infallible;
use std::ffi::OsString;
use std::fmt;
use std::fmt::Display;
use std::net::AddrParseError;
use std::num::ParseIntError;
use std::num::TryFromIntError;
use std::str::Utf8Error;
use std::sync::mpsc::RecvError;
use std::sync::MutexGuard;

/// Base Error struct which is used throught this crate and other crates
#[derive(Debug, Fail)]
pub struct Error {
	inner: Context<ErrorKind>,
}

/// Kinds of errors that can occur
#[derive(Clone, Eq, PartialEq, Debug, Fail)]
pub enum ErrorKind {
	/// Application Error
	#[fail(display = "Application Error: {}", _0)]
	ApplicationError(String),
	/// IOError Error
	#[fail(display = "IOError Error: {}", _0)]
	IOError(String),
	/// Send Error
	#[fail(display = "Send Error: {}", _0)]
	SendError(String),
	/// Internal Error
	#[fail(display = "Internal Error: {}", _0)]
	InternalError(String),
	/// TLS Error
	#[fail(display = "TLS Error: {}", _0)]
	TLSError(String),
	/// Stale Fd
	#[fail(display = "Stale Fd Error: {}", _0)]
	StaleFdError(String),
	/// Array Index out of bounds
	#[fail(display = "ArrayIndexOutofBounds: {}", _0)]
	ArrayIndexOutofBounds(String),
	/// Setup Error
	#[fail(display = "Setup Error: {}", _0)]
	SetupError(String),
	/// EventHandlerConfigurationError
	#[fail(display = "Event Handler configuration Error: {}", _0)]
	EventHandlerConfigurationError(String),
	/// Log not configured
	#[fail(display = "Log configuration Error: {}", _0)]
	LogConfigurationError(String),
	/// OsString error
	#[fail(display = "OsString Error: {}", _0)]
	OsStringError(String),
	/// Poison error multiple locks
	#[fail(display = "Poison Error: {}", _0)]
	PoisonError(String),
	/// Connection close
	#[fail(display = "Connection Close Error: {}", _0)]
	ConnectionCloseError(String),
	/// Ordering Error
	#[fail(display = "Ordering Error: {}", _0)]
	OrderingError(String),
	/// Invalid RSP (Rust Server Page)
	#[fail(display = "Invalid RSP Error: {}", _0)]
	InvalidRSPError(String),
	/// UnexpectedData
	#[fail(display = "Unexpected Data Error: {}", _0)]
	UnexpectedData(String),
	/// TooLargeRead
	#[fail(display = "TooLargeRead Error: {}", _0)]
	TooLargeRead(String),
	/// CorruptedData
	#[fail(display = "Corrupted Data Error: {}", _0)]
	CorruptedData(String),
	/// CountError
	#[fail(display = "CountError: {}", _0)]
	CountError(String),
	/// ParseIntError
	#[fail(display = "ParseIntError: {}", _0)]
	ParseIntError(String),
	/// Tor Error
	#[fail(display = "Tor Error: {}", _0)]
	Tor(String),
	/// Process Error
	#[fail(display = "Process Error: {}", _0)]
	Process(String),
	/// Pid Error
	#[fail(display = "PID Error: {}", _0)]
	Pid(String),
	/// ProcessNotStarted
	#[fail(display = "Process not started: {}", _0)]
	ProcessNotStarted(String),
	/// InvalidBootstrapLine
	#[fail(display = "InvalidBootstrapLine: {}", _0)]
	InvalidBootstrapLine(String),
	/// Regex
	#[fail(display = "Regex: {}", _0)]
	Regex(String),
	/// InvalidLogLine
	#[fail(display = "InvalidLogLine: {}", _0)]
	InvalidLogLine(String),
	/// LogError
	#[fail(display = "Log Error: {}", _0)]
	LogError(String),
	/// Timeout
	#[fail(display = "Timeout: {}", _0)]
	Timeout(String),
	/// RecvError
	#[fail(display = "RecvError: {}", _0)]
	RecvError(String),
	/// NotOnion
	#[fail(display = "NotOnion: {}", _0)]
	NotOnion(String),
	/// ED25519Key
	#[fail(display = "ED25519Key: {}", _0)]
	ED25519Key(String),
	/// Configuration
	#[fail(display = "Configuration Error: {}", _0)]
	Configuration(String),
	/// WebsocketError
	#[fail(display = "WebSocket Error: {}", _0)]
	WebSocketError(String),
	/// TimespecError
	#[fail(display = "Kqueue timespec error: {}", _0)]
	TimespecError(String),
	/// KqueueError
	#[fail(display = "Kqueue error: {}", _0)]
	KqueueError(String),
	/// HandleNotFoundError
	#[fail(display = "Connection Handle was not found: {}", _0)]
	HandleNotFoundError(String),
	#[fail(display = "Wrong connection type: {}", _0)]
	WrongConnectionType(String),
	/// The connection is already closed
	#[fail(display = "Connection is closed: {}", _0)]
	ConnectionClosedError(String),
	/// Invalid Type
	#[fail(display = "Invalid Type error: {}", _0)]
	InvalidType(String),
	/// Too many handles have been added/accepted by this eventhandler
	#[fail(display = "Too many handles on this eventhandler: {}", _0)]
	MaxHandlesExceeded(String),
	/// AddrParseError
	#[fail(display = "AddrParseError: {}", _0)]
	AddrParseError(String),
	/// HexError
	#[fail(display = "HexError: {}", _0)]
	HexError(String),
	/// Bad key len
	#[fail(display = "Keylen not correct {} != {}", _0, _1)]
	BadKeyLen(usize, usize),
	/// Bad value len
	#[fail(display = "Valuelen not correct {} != {}", _0, _1)]
	BadValueLen(usize, usize),
	/// Other error
	#[fail(display = "Other error {}", _0)]
	OtherError(String),
	/// Max Load Capacity has been exceeded
	#[fail(display = "Max Load Capacity Exceeded")]
	MaxLoadCapacityExceeded,
	/// Invalid MaxLoadCapacity
	#[fail(display = "Invalid Max Load Capacity")]
	InvalidMaxLoadCapacity,
	/// Too large write for serialization
	#[fail(display = "TooLargeWrite: {}", _0)]
	TooLargeWriteErr(String),
	/// Too large read for serialization
	#[fail(display = "TooLargeRead: {}", _0)]
	TooLargeReadErr(String),
	/// UnexpectedEof error
	#[fail(display = "UnexpectedEOF: {}", _0)]
	UnexpectedEof(String),
	/// HttpError
	#[fail(display = "HttpError: {}", _0)]
	HttpError(String),
	/// HttpError 405
	#[fail(display = "HttpError 405: {}", _0)]
	HttpError405(String),
	/// HttpError 400
	#[fail(display = "HttpError 400: {}", _0)]
	HttpError400(String),
	/// HttpError 431
	#[fail(display = "HttpError 431: {}", _0)]
	HttpError431(String),
	/// HttpError 500
	#[fail(display = "HttpError 500: {}", _0)]
	HttpError500(String),
}

impl Display for Error {
	fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
		let cause = match self.cause() {
			Some(c) => format!("{}", c),
			None => String::from("Unknown"),
		};
		let backtrace = match self.backtrace() {
			Some(b) => format!("{}", b),
			None => String::from("Unknown"),
		};
		let output = format!(
			"{} \n Cause: {} \n Backtrace: {}",
			self.inner, cause, backtrace
		);
		Display::fmt(&output, f)
	}
}

impl Error {
	/// get kind
	pub fn kind(&self) -> ErrorKind {
		self.inner.get_context().clone()
	}
	/// get cause
	pub fn cause(&self) -> Option<&dyn Fail> {
		self.inner.cause()
	}
	/// get backtrace
	pub fn backtrace(&self) -> Option<&Backtrace> {
		self.inner.backtrace()
	}
}

impl From<ErrorKind> for Error {
	fn from(kind: ErrorKind) -> Error {
		Error {
			inner: Context::new(kind),
		}
	}
}

impl From<std::io::Error> for Error {
	fn from(e: std::io::Error) -> Error {
		Error {
			inner: Context::new(ErrorKind::IOError(format!("{}", e))),
		}
	}
}

#[cfg(unix)]
impl From<Errno> for Error {
	fn from(e: Errno) -> Error {
		Error {
			inner: Context::new(ErrorKind::IOError(format!("{}", e))),
		}
	}
}

impl From<Utf8Error> for Error {
	fn from(e: Utf8Error) -> Error {
		Error {
			inner: Context::new(ErrorKind::IOError(format!("{}", e))),
		}
	}
}

impl From<OsString> for Error {
	fn from(e: OsString) -> Error {
		Error {
			inner: Context::new(ErrorKind::OsStringError(format!("{:?}", e))),
		}
	}
}

impl From<ParseIntError> for Error {
	fn from(e: ParseIntError) -> Error {
		Error {
			inner: Context::new(ErrorKind::ParseIntError(format!("{}", e))),
		}
	}
}

impl From<crate::rustls::Error> for Error {
	fn from(e: crate::rustls::Error) -> Error {
		Error {
			inner: Context::new(ErrorKind::TLSError(format!("{}", e))),
		}
	}
}

impl From<RecvError> for Error {
	fn from(e: RecvError) -> Error {
		Error {
			inner: Context::new(ErrorKind::RecvError(format!("RecvError: {}", e))),
		}
	}
}

impl From<crate::failure::Context<ErrorKind>> for Error {
	fn from(e: crate::failure::Context<ErrorKind>) -> Error {
		Error {
			inner: Context::new(ErrorKind::InternalError(format!("InternalError: {}", e))),
		}
	}
}

impl From<std::sync::PoisonError<MutexGuard<'_, Vec<(String, String)>>>> for Error {
	fn from(e: std::sync::PoisonError<MutexGuard<'_, Vec<(String, String)>>>) -> Error {
		Error {
			inner: Context::new(ErrorKind::InternalError(format!("InternalError: {}", e))),
		}
	}
}

impl From<std::string::FromUtf8Error> for Error {
	fn from(e: std::string::FromUtf8Error) -> Error {
		Error {
			inner: Context::new(ErrorKind::InternalError(format!("UTF-8 error: {}", e))),
		}
	}
}

impl From<crate::base64::DecodeError> for Error {
	fn from(e: crate::base64::DecodeError) -> Error {
		Error {
			inner: Context::new(ErrorKind::InternalError(format!("Base64 error: {}", e))),
		}
	}
}

impl From<std::array::TryFromSliceError> for Error {
	fn from(e: std::array::TryFromSliceError) -> Error {
		Error {
			inner: Context::new(ErrorKind::InternalError(format!(
				"TryFromSlice error: {}",
				e
			))),
		}
	}
}

impl From<crate::ed25519_dalek::ed25519::Error> for Error {
	fn from(e: crate::ed25519_dalek::ed25519::Error) -> Error {
		Error {
			inner: Context::new(ErrorKind::InternalError(format!("dalek error: {}", e))),
		}
	}
}

impl From<std::time::SystemTimeError> for Error {
	fn from(e: std::time::SystemTimeError) -> Error {
		Error {
			inner: Context::new(ErrorKind::InternalError(format!(
				"system time error: {}",
				e
			))),
		}
	}
}

impl From<TryFromIntError> for Error {
	fn from(e: TryFromIntError) -> Error {
		Error {
			inner: Context::new(ErrorKind::InternalError(format!("TryFromIntError: {}", e))),
		}
	}
}

impl From<Infallible> for Error {
	fn from(e: Infallible) -> Error {
		Error {
			inner: Context::new(ErrorKind::InternalError(format!("Infallible: {}", e))),
		}
	}
}

impl From<InvalidDnsNameError> for Error {
	fn from(e: InvalidDnsNameError) -> Error {
		Error {
			inner: Context::new(ErrorKind::TLSError(format!("InvalidDNS: {}", e))),
		}
	}
}

impl From<AddrParseError> for Error {
	fn from(e: AddrParseError) -> Error {
		Error {
			inner: Context::new(ErrorKind::AddrParseError(format!(
				"Error parsing address: {}",
				e
			))),
		}
	}
}

impl From<FromHexError> for Error {
	fn from(e: FromHexError) -> Error {
		Error {
			inner: Context::new(ErrorKind::HexError(format!("Error parsing hex: {}", e))),
		}
	}
}
