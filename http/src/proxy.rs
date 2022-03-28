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

use crate::types::ConnectionInfo;
use crate::types::*;
use nioruntime_deps::libc;
use nioruntime_deps::libc::fcntl;
use nioruntime_deps::nix::sys::socket::AddressFamily::Inet;
use nioruntime_deps::nix::sys::socket::SockType::Stream;
use nioruntime_deps::nix::sys::socket::{connect, socket, InetAddr, SockAddr, SockFlag};
use nioruntime_deps::rand;
use nioruntime_deps::sha2::{Digest, Sha256};
use nioruntime_err::{Error, ErrorKind};
use nioruntime_evh::ConnectionData;
use nioruntime_evh::EvhParams;
use nioruntime_log::*;
use nioruntime_util::slabs::SlabAllocator;
use nioruntime_util::{bytes_find, bytes_parse_number_header, bytes_parse_number_hex};
use std::collections::{HashMap, HashSet};
use std::convert::TryInto;
use std::io::Write;
use std::net::IpAddr;
use std::net::SocketAddr;
use std::str::from_utf8;
use std::sync::{Arc, RwLock};
use std::time::{SystemTime, UNIX_EPOCH};

warn!();

pub fn process_proxy_inbound(
	conn_data: &ConnectionData,
	nbuf: &[u8],
	proxy_connections: &mut HashMap<u128, ProxyInfo>,
	proxy_state: &mut HashMap<ProxyEntry, ProxyState>,
	idle_proxy_connections: &mut HashMap<ProxyEntry, HashMap<SocketAddr, HashSet<ProxyInfo>>>,
	now: SystemTime,
) -> Result<(), Error> {
	let proxy_info = proxy_connections.get_mut(&conn_data.get_connection_id());
	match proxy_info {
		Some(proxy_info) => {
			let (is_complete, is_close, _end_response) = if proxy_info.buffer.len() > 0 {
				proxy_info.buffer.extend_from_slice(nbuf);
				let (ret, close, end_response) = check_complete(&proxy_info.buffer)?;
				if ret {
					proxy_info.buffer.clear();
				}
				(ret, close, end_response)
			} else {
				let ret = check_complete(nbuf)?;
				ret
			};

			// we write whether we're done or not
			match &proxy_info.response_conn_data {
				Some(conn_data) => {
					match conn_data.write(nbuf) {
						Ok(_) => {}
						Err(e) => {
							warn!("proxy request generated error: {}", e)?;
						}
					}

					// if complete, call async complete
					if is_complete && !is_close {
						conn_data.async_complete()?;
					}
				}
				None => {
					warn!(
						"no proxy for id = {}, nbuf='{}'",
						conn_data.get_connection_id(),
						std::str::from_utf8(nbuf)?
					)?;
				}
			}
			if is_complete && !is_close {
				// update latency info
				let proxy_state = proxy_state.get_mut(&proxy_info.proxy_entry);
				match proxy_state {
					Some(proxy_state) => {
						let v = proxy_state.last_lat_micros.get_mut(&proxy_info.sock_addr);
						match v {
							Some(v) => {
								if v.1.len() > 0 {
									v.1[v.0] = now
										.duration_since(UNIX_EPOCH)?
										.as_micros()
										.saturating_sub(proxy_info.request_start_time);
									v.0 = (v.0 + 1) % v.1.len();
								}
							}
							None => {}
						}
					}
					None => {}
				}

				// put this connection into the idle pool
				proxy_info.response_conn_data = None;
				let added = match idle_proxy_connections.get_mut(&proxy_info.proxy_entry) {
					Some(conns) => match conns.get_mut(&proxy_info.sock_addr) {
						Some(ref mut conns) => {
							conns.insert(proxy_info.clone());
							true
						}
						None => false,
					},
					None => false,
				};

				if !added {
					let mut nhashset = HashSet::new();
					nhashset.insert(proxy_info.clone());
					match idle_proxy_connections.get_mut(&proxy_info.proxy_entry.clone()) {
						Some(map) => {
							map.insert(proxy_info.sock_addr, nhashset);
						}
						None => {
							let mut map = HashMap::new();
							map.insert(proxy_info.sock_addr, nhashset);
							idle_proxy_connections.insert(proxy_info.proxy_entry.clone(), map);
						}
					}
				}

			// update latency info
			} else if !is_close {
				proxy_info.buffer.extend_from_slice(nbuf);
			}
		}
		None => {
			error!("no proxy information found for this connection")?;
		}
	}

	Ok(())
}

pub fn set_last(
	now: u128,
	last_set: u128,
	sock_addr: &SocketAddr,
	proxy_entry: &ProxyEntry,
	proxy_state: &mut HashMap<ProxyEntry, ProxyState>,
) -> Result<(), Error> {
	match proxy_state.get_mut(proxy_entry) {
		Some(state) => match state.last_healthy_reply.get_mut(sock_addr) {
			Some(last) => {
				*last = last_set;
				update_healthy_socket_state(proxy_entry, proxy_state, now)?;
			}
			None => warn!("no last for our sockaddr: {:?}", sock_addr)?,
		},
		None => warn!("no state for proxy_entry: {:?}", proxy_entry)?,
	}
	Ok(())
}

pub fn process_health_check_response(
	conn_data: &ConnectionData,
	nbuf: &[u8],
	health_check_connections: &mut HashMap<u128, (ProxyEntry, SocketAddr)>,
	proxy_state: &mut HashMap<ProxyEntry, ProxyState>,
) -> Result<(), Error> {
	let now = SystemTime::now().duration_since(UNIX_EPOCH)?.as_millis();
	let proxy_entry = health_check_connections.get(&conn_data.get_connection_id());

	match proxy_entry {
		Some((proxy_entry, sock_addr)) => {
			match &proxy_entry.health_check {
				Some(health_check) => {
					// TODO: check cross boundry reply (unlikely, but possible)
					if bytes_find(nbuf, health_check.expect_text.as_bytes()).is_some() {
						match proxy_state.get_mut(proxy_entry) {
							Some(_state) => {
								set_last(now, now, sock_addr, proxy_entry, proxy_state)?;
							}
							None => {
								warn!("unexpected none")?;
							}
						}
						conn_data.close()?;
					}
				}
				None => {
					warn!("unexepected none2")?;
				}
			}
		}
		None => {
			warn!("unexpected none3")?;
		}
	}

	Ok(())
}

pub fn check_complete(buffer: &[u8]) -> Result<(bool, bool, usize), Error> {
	match bytes_find(buffer, END_HEADERS) {
		Some(end_headers) => {
			let clen = bytes_find(buffer, CONTENT_LENGTH);
			match clen {
				Some(clen) => {
					if clen < end_headers {
						let len = bytes_parse_number_header(buffer, clen);
						match len {
							Some(len) => {
								let complete = 4 + len + end_headers <= buffer.len();
								let close = if complete {
									bytes_find(buffer, CONNECTION_CLOSE).is_some()
								} else {
									false
								};

								let end = if complete { 6 + len + end_headers } else { 0 };
								return Ok((complete, close, end));
							}
							None => {
								return Ok((false, false, 0)); // TODO: how do we handle this?
							}
						}
					}
				}
				None => {}
			}
			let chunked = bytes_find(buffer, TRANSFER_ENCODING_CHUNKED).is_some();
			if !chunked {
				// if it's not chunked and no content-length, we return that it's not complete
				// HTTP/1.0
				// data is still sent and we must close the client connection
				// when upstream closes
				Ok((false, false, 0))
			} else {
				let mut offset = end_headers + 4;
				let buffer_len = buffer.len();
				loop {
					if offset > buffer_len {
						return Ok((false, false, 0));
					}
					let len = bytes_parse_number_hex(&buffer[offset..]);
					let len =
						match len {
							Some(len) => len,
							None => {
								warn!("invalid response from upstream. Could not parse Transfer-encoding")?;
								return Err(ErrorKind::HttpError500(format!(
											"Invalid response from upstream: could not parse transfer encoding"
											))
								.into());
							}
						};

					if len == 0 {
						break;
					}
					if offset > buffer_len {
						return Ok((false, false, 0));
					}
					let next_line = bytes_find(&buffer[offset..], BACK_R);
					match next_line {
						Some(next_line) => {
							offset += len + next_line + 5;
						}
						None => {
							return Err(
										ErrorKind::HttpError500(
                                                                                        format!(
                                                                                        "Invalid response from upstream: (2) could not parse transfer encoding"
                                                                                        )
                                                                                ).into()
									);
						}
					}
				}
				Ok((true, false, offset + 3))
			}
		}
		None => Ok((false, false, 0)), // headers not complete, we can't be done
	}
}

pub fn process_proxy_outbound(
	inbound: &ConnectionData,
	headers: &HttpHeaders,
	_config: &HttpConfig,
	proxy_entry: &ProxyEntry,
	buffer: &[u8],
	evh_params: &EvhParams,
	proxy_connections: &mut HashMap<u128, ProxyInfo>,
	active_connections: &mut HashMap<u128, ConnectionInfo>,
	idle_proxy_connections: &mut HashMap<ProxyEntry, HashMap<SocketAddr, HashSet<ProxyInfo>>>,
	proxy_state: &mut HashMap<ProxyEntry, ProxyState>,
	async_connections: &Arc<RwLock<HashSet<u128>>>,
	remote_peer: &Option<SocketAddr>,
	now: SystemTime,
	slabs: &Arc<RwLock<SlabAllocator>>,
) -> Result<usize, Error> {
	// select a random health socket
	let state = proxy_state.get(proxy_entry);
	let now_millis = now.duration_since(UNIX_EPOCH)?.as_millis();
	let healthy_sock_addr = match state {
		Some(state) => {
			let len = state.healthy_sockets.len();
			if len == 0 {
				// 503 service unavailable
				inbound.write(HTTP_ERROR_503)?;
				return Ok(buffer.len());
			} else {
				match &proxy_entry.proxy_rotation {
					ProxyRotation::Random => {
						let rand: usize = rand::random();
						state.healthy_sockets[rand % len]
					}
					ProxyRotation::LeastLatency => {
						let control_pct = proxy_entry.control_percent;
						let mut least_micros = u128::MAX;
						let mut fastest_addr = None;
						for (k, v) in &state.last_lat_micros {
							let mut sum = 0;
							for entry in &v.1 {
								sum += entry;
							}
							let avg = sum / v.1.len() as u128;
							if avg < least_micros {
								let last = state.last_healthy_reply.get(&k);
								match last {
									Some(last) => {
										let hc = proxy_entry.health_check.as_ref();
										let hc_millis = match hc {
											Some(hc) => hc.check_secs * 2_000,
											None => u128::MAX,
										};
										if now_millis.saturating_sub(*last) < hc_millis {
											least_micros = avg;
											fastest_addr = Some(k.clone());
										}
									}
									None => {}
								}
							}
						}
						let rand: usize = rand::random();
						if fastest_addr.is_some() && rand % 100 >= control_pct {
							fastest_addr.unwrap()
						} else {
							let rand: usize = rand::random();

							state.healthy_sockets[rand % len]
						}
					}
					ProxyRotation::StickyIp => match remote_peer {
						Some(remote_peer) => {
							let mut sha256 = Sha256::new();
							match remote_peer.ip() {
								IpAddr::V4(ip) => {
									sha256.write(&ip.octets())?;
								}
								IpAddr::V6(ip) => {
									sha256.write(&ip.octets())?;
								}
							}
							let hash = sha256.finalize();
							state.healthy_sockets
								[u32::from_be_bytes(hash.to_vec()[..4].try_into()?) as usize % len]
						}
						None => {
							let rand: usize = rand::random();
							state.healthy_sockets[rand % len]
						}
					},
					ProxyRotation::StickyCookie(cookie_target) => {
						match headers.get_header_value(&"Cookie".to_string())? {
							Some(cookies) => {
								let mut ret = None;
								for cookie in cookies {
									let cookie = cookie.as_bytes();
									let mut start = 0;
									loop {
										let mut end = cookie.len();
										if start >= end {
											break;
										}
										match bytes_find(&cookie[start..], b";") {
											Some(semi) => end = semi + start,
											None => {}
										}
										if start >= end {
											break;
										}

										match bytes_find(&cookie[start..], b"=") {
											Some(equal) => {
												if equal < end {
													if std::str::from_utf8(
														&cookie[start..(start + equal)],
													)? == cookie_target
													{
														ret = Some(
															from_utf8(
																&cookie[(start + equal + 1)..end],
															)?
															.to_string(),
														);
													}
												}
											}
											None => {}
										}

										start = end + 2;
									}
								}
								match ret {
									Some(ret) => {
										let mut sha256 = Sha256::new();
										sha256.write(&ret.as_bytes())?;
										let hash = sha256.finalize();
										state.healthy_sockets[u32::from_be_bytes(
											hash.to_vec()[..4].try_into()?,
										) as usize % len]
									}
									None => {
										let rand: usize = rand::random();
										state.healthy_sockets[rand % len]
									}
								}
							}
							None => {
								let rand: usize = rand::random();
								state.healthy_sockets[rand % len]
							}
						}
					}
				}
			}
		}
		None => {
			return Err(ErrorKind::InternalError(format!(
				"no state found for proxy: {:?}",
				proxy_entry
			))
			.into());
		}
	};

	let map = idle_proxy_connections.get_mut(proxy_entry).unwrap();
	let mut proxy_info = match map.get_mut(&healthy_sock_addr) {
		Some(hashset) => {
			let proxy_info = hashset.iter().last();
			match proxy_info {
				Some(proxy_info) => {
					let proxy_info = proxy_info.to_owned();
					hashset.retain(|k| k != &proxy_info);
					Some(proxy_info)
				}
				None => None,
			}
		}
		None => None,
	};

	let proxy_info = match proxy_info {
		Some(ref mut proxy_info) => {
			match proxy_connections.get_mut(&proxy_info.proxy_conn.get_connection_id()) {
				Some(proxy_info) => {
					proxy_info.response_conn_data = Some(inbound.clone());
					proxy_info.request_start_time = now.duration_since(UNIX_EPOCH)?.as_micros();
				}
				None => {
					return Err(
						ErrorKind::InternalError("proxy connection not found".into()).into(),
					)
				}
			}
			proxy_info.clone()
		}
		None => {
			let tid = inbound.tid();
			let state = proxy_state.get_mut(proxy_entry);
			let state = match state {
				Some(state) => state,
				None => return Err(ErrorKind::InternalError("No state found".into()).into()),
			};

			let (handle, conn_data) = match connect_outbound(&healthy_sock_addr, tid, evh_params) {
				Ok((handle, conn_data)) => {
					state.cur_connections += 1;
					(handle, conn_data)
				}
				Err(e) => {
					set_last(
						now.duration_since(UNIX_EPOCH)?.as_millis(),
						2,
						&healthy_sock_addr,
						&proxy_entry,
						proxy_state,
					)?;
					return Err(
						ErrorKind::IOError(format!("Error connecting to proxy: {}", e)).into(),
					);
				}
			};

			debug!(
				"proxy added handle = {}, conn_id = {}",
				handle,
				conn_data.get_connection_id()
			)?;

			let proxy_info = ProxyInfo {
				handle,
				response_conn_data: Some(inbound.clone()),
				buffer: vec![],
				sock_addr: healthy_sock_addr,
				proxy_conn: conn_data.clone(),
				proxy_entry: proxy_entry.clone(),
				request_start_time: now.duration_since(UNIX_EPOCH)?.as_micros(),
			};

			proxy_connections.insert(conn_data.get_connection_id(), proxy_info.clone());

			active_connections.insert(
				conn_data.get_connection_id(),
				ConnectionInfo::new(conn_data.clone()),
			);

			proxy_info
		}
	};

	let mut ctx = ApiContext::new(async_connections.clone(), inbound.clone(), slabs.clone());

	// set async
	ctx.set_async()?;

	// send the first request
	let end = send_first_request(headers, &proxy_info.proxy_conn, buffer)?;

	Ok(end)
}

fn send_first_request(
	headers: &HttpHeaders,
	conn_data: &ConnectionData,
	buffer: &[u8],
) -> Result<usize, Error> {
	let len = headers.len();
	// TODO: deal with Content-Length / Transfer-Encoding in request

	conn_data.write(&buffer[0..len])?;

	Ok(len)
}

pub fn connect_outbound(
	sock_addr: &SocketAddr,
	tid: usize,
	evh_params: &EvhParams,
) -> Result<(Handle, ConnectionData), Error> {
	let handle = socket_connect(sock_addr)?;
	let conn_data = evh_params.add_handle(handle, None, Some(tid))?;
	Ok((handle, conn_data))
}

fn update_healthy_socket_state(
	proxy_entry: &ProxyEntry,
	proxy_state: &mut HashMap<ProxyEntry, ProxyState>,
	now: u128,
) -> Result<(), Error> {
	let state = proxy_state.get_mut(proxy_entry);
	let mut healthy_sockets = vec![];
	match state {
		Some(state) => {
			for upstream in &proxy_entry.upstream {
				let last = state.last_healthy_reply.get(&upstream.sock_addr);
				match last {
					Some(last) => match &proxy_entry.health_check {
						Some(hc) => {
							if now.saturating_sub(*last) < hc.check_secs * 2_000 {
								for _ in 0..upstream.weight {
									healthy_sockets.push(upstream.sock_addr.clone());
								}
							}
						}
						None => {}
					},
					None => {}
				}
			}

			let v = proxy_state.get_mut(proxy_entry);
			match v {
				Some(v) => {
					v.healthy_sockets = healthy_sockets.clone();
				}
				None => warn!("expected to find a value for proxy_entry={:?}", proxy_entry)?,
			}
		}
		None => {}
	}

	Ok(())
}

pub fn socket_connect(socket_addr: &SocketAddr) -> Result<Handle, Error> {
	// TODO: support windows
	let handle = socket(Inet, Stream, SockFlag::empty(), None)?;

	let inet_addr = InetAddr::from_std(socket_addr);
	let sock_addr = SockAddr::new_inet(inet_addr);
	match connect(handle, &sock_addr) {
		Ok(_) => {}
		Err(e) => {
			#[cfg(unix)]
			unsafe {
				libc::close(handle);
			}
			#[cfg(windows)]
			unsafe {
				ws2_32::closesocket(handle);
			}
			debug!("error connecting to {}: {}", sock_addr, e)?;
			return Err(ErrorKind::IOError(format!("connect generated error: {}", e)).into());
		}
	};

	unsafe { fcntl(handle, libc::F_SETFL, libc::O_NONBLOCK) };

	Ok(handle)
}

pub fn process_health_check(
	thread_context: &mut ThreadContext,
	_config: &HttpConfig,
	evh_params: &EvhParams,
	tid: usize,
) -> Result<(), Error> {
	let now = SystemTime::now().duration_since(UNIX_EPOCH)?.as_millis();
	let mut update_vec = vec![];
	for (k, v) in &thread_context.proxy_state {
		match &k.health_check {
			Some(hc) => {
				if now.saturating_sub(v.last_health_check) > hc.check_secs * 1_000 {
					for upstream in &k.upstream {
						check(
							&upstream.sock_addr,
							tid,
							evh_params,
							&mut thread_context.health_check_connections,
							&mut thread_context.active_connections,
							k,
							&hc.path,
						)?;
					}
					update_vec.push(k.to_owned());
				}
			}
			None => {} // no health check specified
		}
	}

	for k in &update_vec {
		let v = thread_context.proxy_state.get_mut(k);
		match v {
			Some(v) => {
				v.last_health_check = now;
			}
			None => warn!("expected to find a value for k={:?}", k)?,
		}
	}

	Ok(())
}

fn check(
	sock_addr: &SocketAddr,
	tid: usize,
	evh_params: &EvhParams,
	health_check_connections: &mut HashMap<u128, (ProxyEntry, SocketAddr)>,
	active_connections: &mut HashMap<u128, ConnectionInfo>,
	proxy_entry: &ProxyEntry,
	path: &String,
) -> Result<bool, Error> {
	let (_handle, conn_data) = connect_outbound(sock_addr, tid, evh_params)?;
	let mut health_check = HEALTH_CHECK_VEC[0].clone();
	health_check.extend_from_slice(path.as_bytes());
	health_check.extend_from_slice(&HEALTH_CHECK_VEC[1]);
	health_check_connections.insert(
		conn_data.get_connection_id(),
		(proxy_entry.clone(), sock_addr.clone()),
	);
	conn_data.write(&health_check)?;

	active_connections.insert(
		conn_data.get_connection_id(),
		ConnectionInfo::new(conn_data.clone()),
	);

	Ok(true)
}

#[cfg(test)]
mod test {
	use crate::proxy::check_complete;
	use nioruntime_err::Error;
	use nioruntime_log::*;

	debug!();

	#[test]
	fn test_check_complete() -> Result<(), Error> {
		crate::test::test::init_logger()?;
		assert_eq!(check_complete(b"H")?, (false, false, 0));
		assert_eq!(
			check_complete(b"HTTP/1.1 200 OK\r\nServer: test\r\nContent-Length: 10\r\n")?,
			(false, false, 0)
		);
		assert_eq!(
			check_complete(
				b"HTTP/1.1 200 OK\r\nServer: test\r\nContent-Length: 10\r\n\r\n012345678"
			)?,
			(false, false, 0)
		);
		assert_eq!(
			check_complete(
				b"HTTP/1.1 200 OK\r\nServer: test\r\nContent-Length: 10\r\n\r\n0123456789"
			)?,
			(true, false, 65)
		);
		assert_eq!(
			check_complete(
				b"HTTP/1.1 200 OK\r\n\
Server: test\r\n\
Date: Thu, 24 Mar 2022 01:22:10 GMT\r\n\
Content-Type: text/html; charset=UTF-8\r\n\
Transfer-Encoding: chunked\r\n\
Connection: keep-alive\r\n\
\r\n\
10\r\n\
123456789abcdef\r\n\
\r\n\
0\r\n\
\r\n"
			)?,
			(true, false, 188)
		);
		assert_eq!(
			check_complete(
				b"HTTP/1.1 200 OK\r\n\
Server: test\r\n\
Date: Thu, 24 Mar 2022 01:22:10 GMT\r\n\
Content-Type: text/html; charset=UTF-8\r\n\
Transfer-Encoding: chunked\r\n\
Connection: keep-alive\r\n\
\r\n\
10\r\n\
123456789abcdef\r\n\
\r\n\
10\r\n\
\r\n"
			)?,
			(false, false, 0)
		);

		Ok(())
	}
}
