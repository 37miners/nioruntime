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

/// A macro that is used to lock a mutex and return the appropriate error if the lock is poisoned.
/// This code was used in many places, and this macro simplifies it.
#[macro_export]
macro_rules! lock {
	($a:expr) => {
		$a.lock().map_err(|e| {
			let error: Error =
				ErrorKind::PoisonError(format!("Poison Error: {}", e.to_string())).into();
			error
		})?;
	};
}

/// A macro that is used to lock a rwlock in write mode and return the appropriate error if the lock is poisoned.
/// This code was used in many places, and this macro simplifies it.
#[macro_export]
macro_rules! lockw {
	($a:expr) => {{
		let do_try_lock = true;
		let mut is_locked = false;
		let id: u128 = rand::random();

		if do_try_lock {
			match $a.try_write() {
				Ok(_) => {}
				Err(_) => {
					is_locked = true;
					let bt = backtrace::Backtrace::new();
					let time = std::time::SystemTime::now()
						.duration_since(std::time::UNIX_EPOCH)
						.unwrap()
						.as_millis();
					let mut lock_monitor = nioruntime_err::LOCK_MONITOR
						.write()
						.map_err(|e| {
							let error: Error =
								ErrorKind::PoisonError(format!("Poison Error: {}", e.to_string()))
									.into();
							error
						})
						.unwrap();
					lock_monitor.insert(id, nioruntime_err::LockInfo { id, bt, time });
					match lock_monitor.get(&0) {
						Some(_) => {}
						None => {
							let bt = backtrace::Backtrace::new();
							lock_monitor.insert(0, nioruntime_err::LockInfo { id, bt, time });
							std::thread::spawn(move || loop {
								std::thread::sleep(std::time::Duration::from_millis(10000));
								let lock_monitor = match nioruntime_err::LOCK_MONITOR.read() {
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
			let error: Error =
				ErrorKind::PoisonError(format!("Poison Error: {}", e.to_string())).into();
			error
		});

		if is_locked {
			let mut lock_monitor = nioruntime_err::LOCK_MONITOR
				.write()
				.map_err(|e| {
					let error: Error =
						ErrorKind::PoisonError(format!("Poison Error: {}", e.to_string())).into();
					error
				})
				.unwrap();

			(*lock_monitor).remove(&id);
		}

		res
	}};
}

/// A macro that is used to lock a rwlock in read mode and return the appropriate error if the lock is poisoned.
/// This code was used in many places, and this macro simplifies it.
#[macro_export]
macro_rules! lockr {
	($a:expr) => {{
		let do_try_lock = true;
		let mut is_locked = false;
		let id: u128 = rand::random();

		if do_try_lock {
			match $a.try_read() {
				Ok(_) => {}
				Err(_) => {
					is_locked = true;
					let bt = backtrace::Backtrace::new();
					let time = std::time::SystemTime::now()
						.duration_since(std::time::UNIX_EPOCH)
						.unwrap()
						.as_millis();
					let mut lock_monitor = nioruntime_err::LOCK_MONITOR
						.write()
						.map_err(|e| {
							let error: Error =
								ErrorKind::PoisonError(format!("Poison Error: {}", e.to_string()))
									.into();
							error
						})
						.unwrap();
					lock_monitor.insert(id, nioruntime_err::LockInfo { id, bt, time });
					match lock_monitor.get(&0) {
						Some(_) => {}
						None => {
							let bt = backtrace::Backtrace::new();
							lock_monitor.insert(0, nioruntime_err::LockInfo { id, bt, time });
							std::thread::spawn(move || loop {
								std::thread::sleep(std::time::Duration::from_millis(10000));
								let lock_monitor = match nioruntime_err::LOCK_MONITOR.read() {
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
		let res = $a.read().map_err(|e| {
			let error: Error =
				ErrorKind::PoisonError(format!("Poison Error: {}", e.to_string())).into();
			error
		});

		if is_locked {
			let mut lock_monitor = nioruntime_err::LOCK_MONITOR
				.write()
				.map_err(|e| {
					let error: Error =
						ErrorKind::PoisonError(format!("Poison Error: {}", e.to_string())).into();
					error
				})
				.unwrap();

			(*lock_monitor).remove(&id);
		}

		res
	}};
}

/// A macro that is used to lock a rwlock in read mode ignoring poison locks
/// This code was used in many places, and this macro simplifies it.
#[macro_export]
macro_rules! lockrp {
	($a:expr) => {
		match $a.read() {
			Ok(data) => data,
			Err(e) => e.into_inner(),
		}
	};
}

/// A macro that is used to lock a rwlock in write mode ignoring poison locks
/// This code was used in many places, and this macro simplifies it.
#[macro_export]
macro_rules! lockwp {
	($a:expr) => {
		match $a.write() {
			Ok(data) => data,
			Err(e) => e.into_inner(),
		}
	};
}
