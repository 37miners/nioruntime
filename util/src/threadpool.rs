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

use crate::futures::executor::block_on;
use crate::lazy_static::lazy_static;
use crate::rand;
use nioruntime_err::{Error, ErrorKind};
use std::collections::HashMap;
use std::future::Future;
use std::pin::Pin;
use std::sync::mpsc;
use std::sync::Arc;
use std::sync::Mutex;
use std::sync::RwLock;
use std::thread;

lazy_static! {
	pub(crate) static ref STATIC_THREAD_POOL: Arc<RwLock<HashMap<u128, ThreadPoolImpl>>> =
		Arc::new(RwLock::new(HashMap::new()));
}

/// The static thread pool is a thread pool that can be used to execute futures. It is used
/// by the event handler and other structs to take advantage of the ability to run multiple
/// threads at the same time.
pub struct StaticThreadPool {
	id: u128,
}

impl StaticThreadPool {
	/// Build a new static thread pool or return an error if an error occurs.
	///
	/// This function builds a static thread pool. Note that it does not start
	/// the thread pool. [`StaticThreadPool.start`] must be called before using the thread pool.
	///
	/// Returns Ok(()) or Error if the static thread pool lock cannot be obtained.
	pub fn new() -> Result<Self, Error> {
		let tp = ThreadPoolImpl::new();
		let id: u128 = rand::random::<u128>();
		let mut stp = crate::lockw!(STATIC_THREAD_POOL)?;

		stp.insert(id, tp);

		Ok(StaticThreadPool { id })
	}

	pub fn set_on_panic(&mut self, on_panic: OnPanic) -> Result<(), Error> {
		let mut stp = crate::lockw!(STATIC_THREAD_POOL)?;

		let tp = stp.get_mut(&self.id);
		match tp {
			Some(tp) => tp.set_on_panic(on_panic),
			None => {
				return Err(ErrorKind::InternalError(format!(
					"static thread pool id = {} doesn't exist error",
					self.id
				))
				.into())
			}
		}
	}

	/// Start the static thread pool.
	///
	/// Start the thread pool with the specified size. After calling this function,
	/// [`StaticThreadPool.execute`] may be called to execute futures.
	///
	/// * `size` - The number of threads for this thread pool to start.
	pub fn start(&self, size: usize) -> Result<(), Error> {
		let mut stp = crate::lockw!(STATIC_THREAD_POOL)?;

		let tp = stp.get_mut(&self.id);
		match tp {
			Some(tp) => tp.start(size)?,
			None => {
				return Err(ErrorKind::InternalError(format!(
					"static thread pool id = {} doesn't exist error",
					self.id
				))
				.into())
			}
		}

		Ok(())
	}

	/// Stop this thread pool free all resources used by the thread pool and terminate
	/// all running threads.
	pub fn stop(&self) -> Result<(), Error> {
		let stp = crate::lockw!(STATIC_THREAD_POOL)?;

		let tp = stp.get(&self.id);
		match tp {
			Some(tp) => tp.stop()?,
			None => {
				return Err(ErrorKind::InternalError(format!(
					"static thread pool id = {} doesn't exist error",
					self.id
				))
				.into())
			}
		}
		Ok(())
	}

	/// Execute the specified future.
	///
	/// The specified future will be executed in one of the thread pool's threads.
	///
	/// * `f` - The future to execute.
	pub fn execute<F>(&self, f: F) -> Result<(), Error>
	where
		F: Future<Output = ()> + Send + Sync + 'static,
	{
		let stp = crate::lockr!(STATIC_THREAD_POOL)?;

		let tp = stp.get(&self.id);
		if tp.is_some() {
			tp.unwrap().execute(f)?;
		} else {
			let msg = format!("static thread pool id = {} doesn't exist error", self.id);
			let ekind = ErrorKind::InternalError(msg).into();
			return Err(ekind);
		}
		Ok(())
	}
}

pub(crate) struct FuturesHolder {
	inner: Pin<Box<dyn Future<Output = ()> + Send + Sync + 'static>>,
}

/// This type is a callback which may be set when creating a ThreadPool. It is called
/// if a thread that is executing the future panics.
pub type OnPanic = fn() -> Result<(), Error>;

pub(crate) struct ThreadPoolImpl {
	tx: Arc<Mutex<mpsc::Sender<(FuturesHolder, bool)>>>,
	rx: Arc<Mutex<mpsc::Receiver<(FuturesHolder, bool)>>>,
	size: Arc<Mutex<usize>>,
	on_panic: Option<OnPanic>,
}

impl ThreadPoolImpl {
	pub fn new() -> Self {
		let (tx, rx): (
			mpsc::Sender<(FuturesHolder, bool)>,
			mpsc::Receiver<(FuturesHolder, bool)>,
		) = mpsc::channel();
		let rx = Arc::new(Mutex::new(rx));
		let tx = Arc::new(Mutex::new(tx));
		ThreadPoolImpl {
			tx,
			rx,
			size: Arc::new(Mutex::new(0)),
			on_panic: None,
		}
	}

	pub fn set_on_panic(&mut self, on_panic: OnPanic) -> Result<(), Error> {
		self.on_panic = Some(on_panic);
		Ok(())
	}

	pub fn start(&mut self, size: usize) -> Result<(), Error> {
		let poison_err = |_e: std::sync::PoisonError<std::sync::MutexGuard<usize>>| -> Error {
			let error: Error = ErrorKind::PoisonError("size lock".to_string()).into();
			error
		};
		{
			let mut self_size = self.size.lock().map_err(poison_err)?;
			(*self_size) = size;
		}
		for _id in 0..size {
			let rx = self.rx.clone();
			let on_panic = self.on_panic.clone();
			thread::spawn(move || loop {
				let rx = rx.clone();
				let jh = thread::spawn(move || loop {
					let task = {
						let res = rx.lock();

						match res {
							Ok(rx) => match rx.recv() {
								Ok((task, stop)) => {
									if stop {
										break;
									}
									task
								}
								Err(e) => {
									println!("unexpected error in threadpool: {}", e.to_string());
									std::thread::sleep(std::time::Duration::from_millis(1000));
									break;
								}
							},
							Err(e) => {
								println!("unexpected error in threadpool: {}", e.to_string());
								std::thread::sleep(std::time::Duration::from_millis(1000));
								break;
							}
						}
					};

					block_on(task.inner);
				});

				let _ = jh.join();

				match on_panic {
					Some(on_panic) => match (on_panic)() {
						Ok(_) => {}
						Err(e) => {
							println!("on_panic callback generated error: '{}'", e.to_string())
						}
					},
					None => {}
				}
			});
		}

		Ok(())
	}

	pub fn stop(&self) -> Result<(), Error> {
		let poison_err = |_e: std::sync::PoisonError<std::sync::MutexGuard<usize>>| -> Error {
			let error: Error = ErrorKind::PoisonError("size lock".to_string()).into();
			error
		};
		let size = {
			let size = self.size.lock().map_err(poison_err)?;
			size
		};
		for _ in 0..*size {
			let f = async {};
			let f = FuturesHolder { inner: Box::pin(f) };
			let tx = self.tx.lock().map_err(|_e| {
				let error: Error = ErrorKind::PoisonError("size lock".to_string()).into();
				error
			})?;

			tx.send((f, true)).map_err(|_e| {
				let error: Error = ErrorKind::InternalError("send failed".to_string()).into();
				error
			})?;
		}
		Ok(())
	}

	pub fn execute<F>(&self, f: F) -> Result<(), Error>
	where
		F: Future<Output = ()> + Send + Sync + 'static,
	{
		let f = FuturesHolder { inner: Box::pin(f) };
		{
			let tx = self.tx.lock().map_err(|e| {
				let error: Error =
					ErrorKind::PoisonError(format!("tx.lock tp: {}", e.to_string())).into();
				error
			})?;
			tx.send((f, false)).map_err(|_e| {
				let error: Error = ErrorKind::InternalError("send failed".to_string()).into();
				error
			})?;
		}
		Ok(())
	}
}

#[test]
fn test_thread_pool() -> Result<(), Error> {
	let tp = StaticThreadPool::new()?;
	tp.start(10)?;
	let tp = Arc::new(Mutex::new(tp));
	let x = Arc::new(Mutex::new(0));
	let x1 = x.clone();
	let x2 = x.clone();
	let x3 = x.clone();
	let tp1 = tp.clone();
	let tp2 = tp.clone();
	let tp3 = tp.clone();

	thread::spawn(move || {
		let tp = tp1.clone();
		let tp = tp.lock().unwrap();
		tp.execute(async move {
			let mut x = x.lock().unwrap();
			*x += 1;
		})
		.unwrap();
	});

	thread::spawn(move || {
		let tp = tp2.clone();
		let tp = tp.lock().unwrap();
		tp.execute(async move {
			let mut x = x1.lock().unwrap();
			*x += 2;
		})
		.unwrap();
	});

	thread::spawn(move || {
		let tp = tp3.clone();
		let tp = tp.lock().unwrap();
		tp.execute(async move {
			let mut x = x2.lock().unwrap();
			*x += 3;
		})
		.unwrap();
	});

	let mut attempts = 0;
	loop {
		// wait for executors to complete
		std::thread::sleep(std::time::Duration::from_millis(300));
		let x = x3.lock().unwrap();
		attempts += 1;
		if *x < 6 && attempts <= 30 {
			continue;
		};
		assert_eq!(*x, 6);
		break;
	}

	Ok(())
}

#[test]
fn test_stop_thread_pool() -> Result<(), Error> {
	let mut tp = StaticThreadPool::new()?;
	tp.set_on_panic(move || Ok(()))?;
	tp.start(10)?;
	let tp = Arc::new(Mutex::new(tp));
	let x = Arc::new(Mutex::new(0));
	let x1 = x.clone();
	let x2 = x.clone();
	let x3 = x.clone();
	let tp1 = tp.clone();
	let tp2 = tp.clone();
	let tp3 = tp.clone();
	let tp4 = tp.clone();

	thread::spawn(move || {
		let tp = tp1.clone();
		let tp = tp.lock().unwrap();
		tp.execute(async move {
			let mut x = x.lock().unwrap();
			*x += 1;
		})
		.unwrap();
	});

	thread::spawn(move || {
		let tp = tp2.clone();
		let tp = tp.lock().unwrap();
		tp.execute(async move {
			let mut x = x1.lock().unwrap();
			*x += 2;
		})
		.unwrap();
	});

	std::thread::sleep(std::time::Duration::from_millis(1000));
	let tp4 = tp4.lock().unwrap();
	tp4.stop()?;
	std::thread::sleep(std::time::Duration::from_millis(1000));

	thread::spawn(move || {
		let tp = tp3.clone();
		let tp = tp.lock().unwrap();
		tp.execute(async move {
			let mut x = x2.lock().unwrap();
			*x += 313;
		})
		.unwrap();
	});

	let mut attempts = 0;
	loop {
		// wait for executors to complete
		std::thread::sleep(std::time::Duration::from_millis(300));
		let x = x3.lock().unwrap();
		attempts += 1;
		if *x < 3 && attempts <= 30 {
			continue;
		};
		assert_eq!(*x, 3);
		break;
	}

	Ok(())
}

#[test]
fn test_bad_static() -> Result<(), Error> {
	let mut tp = StaticThreadPool::new()?;
	tp.id = 1;
	assert!(tp.set_on_panic(move || Ok(())).is_err());
	assert!(tp.start(1).is_err());
	assert!(tp.stop().is_err());
	assert!(tp.execute(async move {}).is_err());
	Ok(())
}

#[test]
fn test_lock_poison() -> Result<(), Error> {
	let tp = StaticThreadPool::new()?;
	tp.start(1)?;
	tp.start(1)?;
	Ok(())
}
