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
use nioruntime_deps::hex::FromHexError;
use nioruntime_deps::nix::errno::Errno;
use nioruntime_deps::rustls::client::InvalidDnsNameError;
use std::convert::Infallible;
use std::ffi::OsString;
use std::fmt;
use std::fmt::Display;
use std::net::AddrParseError;
use std::num::ParseFloatError;
use std::num::ParseIntError;
use std::num::TryFromIntError;
use std::str::Utf8Error;

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
	/// UTF8Error
	#[fail(display = "UTF8 Error: {}", _0)]
	Utf8Error(String),
	/// ErrnoError
	#[fail(display = "Errno: {}", _0)]
	ErrnoError(String),
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
	#[fail(display = "OsString Error")]
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
	/// ParseFloatError
	#[fail(display = "ParseFloatError: {}", _0)]
	ParseFloatError(String),
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
	/// IllegalArgument
	#[fail(display = "IllegalArgument: {}", _0)]
	IllegalArgument(String),
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
	/// HttpError 403
	#[fail(display = "HttpError 403: {}", _0)]
	HttpError403(String),
	/// HttpError404
	#[fail(display = "HttpError 404: {}", _0)]
	HttpError404(String),
	#[fail(display = "No more slabs available")]
	NoMoreSlabs,
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

	/// get inner
	pub fn inner(&self) -> String {
		self.inner.to_string()
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
			inner: Context::new(ErrorKind::ErrnoError(format!("{}", e))),
		}
	}
}

impl From<Utf8Error> for Error {
	fn from(e: Utf8Error) -> Error {
		Error {
			inner: Context::new(ErrorKind::Utf8Error(format!("{}", e))),
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

impl From<std::string::FromUtf8Error> for Error {
	fn from(e: std::string::FromUtf8Error) -> Error {
		Error {
			inner: Context::new(ErrorKind::Utf8Error(format!("UTF-8 error: {}", e))),
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

// infallible cannot happen, so can't test for it.
#[cfg(not(tarpaulin_include))]
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

impl From<ParseFloatError> for Error {
	fn from(e: ParseFloatError) -> Error {
		Error {
			inner: Context::new(ErrorKind::ParseFloatError(format!(
				"Error parsing float: {}",
				e
			))),
		}
	}
}

#[cfg(test)]
mod test {
	use crate::base64;
	use crate::error::InvalidDnsNameError;
	use crate::error::OsString;
	use crate::error::ParseIntError;
	use crate::rustls;
	use crate::rustls::PrivateKey;
	use crate::rustls::ServerConfig;
	use crate::rustls::ServerName;
	use crate::{Error, ErrorKind};
	use nioruntime_deps::ed25519_dalek::PublicKey as DalekPublicKey;
	use nioruntime_deps::hex::FromHex;
	use nioruntime_deps::nix::errno::Errno;
	use nioruntime_deps::substring::Substring;
	use std::array::TryFromSliceError;
	use std::convert::TryFrom;
	use std::convert::TryInto;
	use std::env;
	use std::net::SocketAddr;
	use std::num::TryFromIntError;
	use std::str::FromStr;
	use std::thread::sleep;
	use std::time::{Duration, SystemTime};

	fn get_errno_error() -> Result<(), Error> {
		Err(Error::from(Errno::EPERM))
	}

	fn get_os_string() -> Result<(), Error> {
		Err(OsString::new().into())
	}

	fn check_error<T: Sized, Q>(r: Result<T, Q>, ematch: Error) -> Result<(), Error>
	where
		crate::Error: From<Q>,
	{
		if let Err(r) = r {
			let e: Error = r.into();
			assert_eq!(
				e.to_string().substring(0, e.inner().len()),
				ematch.to_string().substring(0, e.inner().len())
			);
			assert_eq!(
				e.kind().to_string(),
				ematch.to_string().substring(0, e.kind().to_string().len())
			);
			assert!(e.cause().is_none());
			assert!(e.backtrace().is_some());
			assert_eq!(e.inner(), ematch.to_string().substring(0, e.inner().len()),);
			println!("e.backtrace()={:?}", e.backtrace());
		}
		Ok(())
	}

	fn test_error_impl() -> Result<(), Error> {
		check_error(
			f64::from_str("a.12"),
			ErrorKind::ParseFloatError("Error parsing float: invalid float literal".to_string())
				.into(),
		)?;
		check_error(
			Vec::from_hex("48656c6c6f20776f726c6x21"),
			ErrorKind::HexError(
				"Error parsing hex: Invalid character 'x' at position 21".to_string(),
			)
			.into(),
		)?;
		check_error(
			SocketAddr::from_str(&format!("127.0.0.1:x")),
			ErrorKind::AddrParseError(
				"Error parsing address: invalid IP address syntax".to_string(),
			)
			.into(),
		)?;
		check_error(
			std::fs::File::open("/no/path/here"),
			ErrorKind::IOError("No such file or directory (os error 2)".to_string()).into(),
		)?;

		check_error(
			String::from_utf8(vec![0, 159]),
			ErrorKind::Utf8Error(
				"UTF-8 error: invalid utf-8 sequence of 1 bytes from index 1".to_string(),
			)
			.into(),
		)?;

		check_error(
			std::str::from_utf8(&vec![0u8, 159]),
			ErrorKind::Utf8Error("invalid utf-8 sequence of 1 bytes from index 1".to_string())
				.into(),
		)?;

		check_error(
			get_errno_error(),
			ErrorKind::ErrnoError("EPERM: Operation not permitted".to_string()).into(),
		)?;

		check_error(
			get_os_string(),
			ErrorKind::OsStringError("".to_string()).into(),
		)?;

		let x: Result<u16, ParseIntError> = "a".parse();
		check_error(
			x,
			ErrorKind::ParseIntError("invalid digit found in string".to_string()).into(),
		)?;

		check_error(
			base64::decode("aGVsbG8*gd29ybGQ="),
			ErrorKind::InternalError(
				"Base64 error: Encoded text cannot have a 6-bit remainder.".to_string(),
			)
			.into(),
		)?;

		let arr = [0u8; 20];
		let res: Result<[u8; 8], TryFromSliceError> = arr[0..5].try_into();
		check_error(
			res,
			ErrorKind::InternalError(
				"TryFromSlice error: could not convert slice to array".to_string(),
			)
			.into(),
		)?;

		let res: Result<u32, TryFromIntError> = u64::MAX.try_into();
		check_error(
			res,
			ErrorKind::InternalError(
				"TryFromIntError: out of range integral type conversion attempted".to_string(),
			)
			.into(),
		)?;

		let sys_time = SystemTime::now();
		sleep(Duration::from_secs(1));
		let new_sys_time = SystemTime::now();
		let res = sys_time.duration_since(new_sys_time);
		check_error(
			res,
			ErrorKind::InternalError(
				"system time error: second time provided was later than self".to_string(),
			)
			.into(),
		)?;

		let res: Result<ServerName, InvalidDnsNameError> = ServerName::try_from("example&^.com");
		check_error(
			res,
			ErrorKind::TLSError("InvalidDNS: invalid dns name".to_string()).into(),
		)?;

		let res: Result<ServerConfig, rustls::Error> = ServerConfig::builder()
			.with_safe_defaults()
			.with_no_client_auth()
			.with_single_cert(vec![], PrivateKey(vec![]));

		check_error(
			res,
			ErrorKind::TLSError("unexpected error: invalid private key".to_string()).into(),
		)?;

		let res: Result<DalekPublicKey, nioruntime_deps::signature::Error> =
			DalekPublicKey::from_bytes(&[0u8; 1]);

		check_error(
			res,
			ErrorKind::InternalError(
				"dalek error: signature error: PublicKey must be 32 bytes in length".to_string(),
			)
			.into(),
		)?;

		Ok(())
	}

	#[test]
	fn test_error_bt() -> Result<(), Error> {
		env::set_var("RUST_BACKTRACE", "1");
		test_error_impl()?;
		Ok(())
	}

	#[test]
	fn test_error_no_bt() -> Result<(), Error> {
		env::remove_var("RUST_BACKTRACE");
		test_error_impl()?;
		Ok(())
	}
}
