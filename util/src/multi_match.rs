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

use nioruntime_err::{Error, ErrorKind};
use nioruntime_log::*;
use std::marker::PhantomData;
use std::pin::Pin;

info!();

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub struct Match {
	pub start: usize,
	pub end: usize,
	pub id: u64,
}

impl Default for Match {
	fn default() -> Self {
		Self {
			start: usize::MAX,
			end: usize::MAX,
			id: 0,
		}
	}
}

pub struct Pattern {
	pub regex: String,
	pub id: u64,
}

#[derive(Clone)]
struct Node {
	next: [u32; 257],
	pattern_id: u64,
	is_multi: bool,
	is_term: bool,
	is_start_only: bool,
}

impl Default for Node {
	fn default() -> Self {
		Self {
			next: [u32::MAX; 257],
			pattern_id: u64::MAX,
			is_multi: false,
			is_term: false,
			is_start_only: false,
		}
	}
}

pub struct Dictionary<OnMatch> {
	nodes: Vec<Node>,
	next: u32,
	case_sensitive: bool,
	max_wildcard_len: usize,
	on_match: Option<Pin<Box<OnMatch>>>,
}

impl<OnMatch> Dictionary<OnMatch>
where
	OnMatch: Fn(&Match) -> Result<(), Error>,
{
	pub fn new(capacity: usize, case_sensitive: bool, max_wildcard_len: usize) -> Self {
		let mut nodes = vec![];
		nodes.resize(capacity, Node::default());
		Self {
			nodes,
			next: 0,
			case_sensitive,
			max_wildcard_len,
			on_match: None,
		}
	}

	pub fn set_on_match(&mut self, on_match: OnMatch) -> Result<(), Error> {
		self.on_match = Some(Box::pin(on_match));
		Ok(())
	}

	pub fn add(&mut self, pattern: Pattern, is_term: bool) -> Result<(), Error> {
		if pattern.regex.len() == 0 {
			return Err(ErrorKind::InvalidRegex(
				"Regex must be at least one byte long".to_string(),
			)
			.into());
		}

		let lower;
		let mut regex = if self.case_sensitive {
			pattern.regex.as_str().bytes().peekable()
		} else {
			lower = pattern.regex.to_lowercase();
			lower.as_str().bytes().peekable()
		};
		let mut cur_byte = regex.next().unwrap();
		let mut cur_node = &mut self.nodes[0];
		let mut is_start_only = false;

		if cur_byte == '^' as u8 {
			cur_byte = match regex.next() {
				Some(cur_byte) => {
					is_start_only = true;
					cur_byte
				}
				None => {
					return Err(ErrorKind::InvalidRegex(
						"Regex must be at least one byte long not including the ^ character"
							.to_string(),
					)
					.into());
				}
			}
		}

		loop {
			let (check_index, is_multi) = if cur_byte == '.' as u8 {
				let peek = regex.peek();
				let is_multi = match peek {
					Some(peek) => {
						if *peek == '*' as u8 {
							regex.next();
							true
						} else {
							false
						}
					}
					_ => false,
				};
				(256usize, is_multi) // wild card is 256
			} else if cur_byte == '\\' as u8 {
				let next = regex.next();
				match next {
					Some(next) => {
						if next == '\\' as u8 {
							(cur_byte as usize, false)
						} else if next == '.' as u8 {
							(next as usize, false)
						} else {
							return Err(ErrorKind::InvalidRegex(format!(
								"Illegal escape character '{}'",
								next as char
							))
							.into());
						}
					}
					None => {
						return Err(ErrorKind::InvalidRegex(format!(
							"Illegal escape character at termination of the string"
						))
						.into());
					}
				}
			} else {
				(cur_byte as usize, false)
			};
			let index = match cur_node.next[check_index] {
				u32::MAX => {
					cur_node.next[check_index] = self.next + 1;
					self.next += 1;
					self.next
				}
				_ => cur_node.next[check_index],
			};
			cur_node = &mut self.nodes[index as usize];
			cur_node.is_multi = is_multi;
			cur_byte = match regex.next() {
				Some(cur_byte) => cur_byte,
				None => {
					cur_node.pattern_id = pattern.id;
					cur_node.is_term = is_term;
					cur_node.is_start_only = is_start_only;
					break;
				}
			};
		}

		Ok(())
	}
}

pub struct MultiMatch<OnMatch> {
	matches: Vec<Match>,
	match_count: usize,
	dictionary: Dictionary<OnMatch>,
	branch_stack: Vec<(usize, usize)>,
	_on_match: PhantomData<OnMatch>,
}

impl<OnMatch> MultiMatch<OnMatch>
where
	OnMatch: Fn(&Match) -> Result<(), Error>,
{
	pub fn new(max_matches: usize, dictionary: Dictionary<OnMatch>) -> Self {
		let mut matches = vec![];
		let mut branch_stack = vec![];
		matches.resize(max_matches, Match::default());
		branch_stack.resize(dictionary.nodes.len(), (0, 0));
		Self {
			matches,
			match_count: 0,
			dictionary,
			branch_stack,
			_on_match: PhantomData,
		}
	}

	pub fn runmatch(&mut self, text: &[u8]) -> Result<(), Error> {
		self.match_count = 0;
		let mut itt = 0;
		let len = text.len();
		let mut cur_node = &self.dictionary.nodes[0];
		let mut start = 0;
		let mut multi_counter = 0;
		let mut branch_stack_counter = 0;
		let mut is_branch = false;

		loop {
			if start >= len {
				break;
			}
			if is_branch {
				is_branch = false;
			} else {
				itt = start;
			}
			loop {
				if itt >= len {
					break;
				}

				let byte = if self.dictionary.case_sensitive {
					text[itt]
				} else {
					if text[itt] >= 'A' as u8 && text[itt] <= 'Z' as u8 {
						text[itt] + 32
					} else {
						text[itt]
					}
				};

				if !cur_node.is_multi {
					multi_counter = 0;
				}

				match cur_node.next[byte as usize] {
					u32::MAX => {
						if cur_node.is_multi {
							multi_counter += 1;
							if multi_counter >= self.dictionary.max_wildcard_len {
								return Err(ErrorKind::InvalidRegex(format!(
									"Wildcard max length exceeded: {}",
									self.dictionary.max_wildcard_len
								))
								.into());
							}
							itt += 1;
							continue;
						}
						// check wildcard
						match cur_node.next[256] {
							u32::MAX => break,
							_ => cur_node = &self.dictionary.nodes[cur_node.next[256] as usize],
						}
					}
					_ => {
						match cur_node.next[256] {
							u32::MAX => {}
							_ => {
								// we have a branch here. Add it to the stack.
								self.branch_stack[branch_stack_counter].0 = itt;
								self.branch_stack[branch_stack_counter].1 =
									cur_node.next[256] as usize;
								branch_stack_counter += 1;
							}
						}
						cur_node = &self.dictionary.nodes[cur_node.next[byte as usize] as usize]
					}
				}

				match cur_node.pattern_id {
					u64::MAX => {}
					_ => {
						if !(cur_node.is_start_only && start != 0) {
							if self.match_count >= self.matches.len() {
								return Err(ErrorKind::CapacityExceeded(format!(
									"Too many matches found. Maximum is {}.",
									self.matches.len()
								))
								.into());
							}
							self.matches[self.match_count].id = cur_node.pattern_id;
							self.matches[self.match_count].end = itt + 1;
							self.matches[self.match_count].start = start;
							match &self.dictionary.on_match {
								Some(on_match) => {
									match (on_match)(&self.matches[self.match_count]) {
										Ok(_) => {}
										Err(e) => {
											error!("OnMatch callback generated error: {}", e)?
										}
									}
								}
								None => {}
							}
							self.match_count += 1;
							if cur_node.is_term {
								return Ok(());
							}
						}
					}
				}

				itt += 1;
			}
			if branch_stack_counter != 0 {
				branch_stack_counter -= 1;
				cur_node = &self.dictionary.nodes[self.branch_stack[branch_stack_counter].1];
				itt = self.branch_stack[branch_stack_counter].0;
				is_branch = true;
			} else {
				start += 1;
				cur_node = &self.dictionary.nodes[0];
				branch_stack_counter = 0;
			}
		}
		Ok(())
	}

	pub fn match_count(&self) -> usize {
		self.match_count
	}

	pub fn matches(&self) -> &Vec<Match> {
		&self.matches
	}
}

#[cfg(test)]
mod test {
	use crate::multi_match::*;
	use crate::{lockr, lockw};
	use nioruntime_deps::rand;
	use nioruntime_err::Error;
	use std::sync::Arc;
	use std::sync::RwLock;

	#[test]
	fn test_multi_match1() -> Result<(), Error> {
		let mut d = Dictionary::new(10_000, true, 100);
		d.set_on_match(move |_m| -> Result<(), Error> { Ok(()) })?;
		d.add(
			Pattern {
				regex: "test".to_string(),
				id: 1234,
			},
			false,
		)?;
		d.add(
			Pattern {
				regex: "ok123".to_string(),
				id: 5678,
			},
			false,
		)?;

		d.add(
			Pattern {
				regex: "tesla".to_string(),
				id: 9999,
			},
			false,
		)?;

		d.add(
			Pattern {
				regex: "teslaok".to_string(),
				id: 1000,
			},
			false,
		)?;

		d.add(
			Pattern {
				regex: "eyxxx".to_string(),
				id: 1111,
			},
			false,
		)?;

		let mut mm = MultiMatch::new(100, d);
		let bytes = b"abc123testxteslaokhitheretest";
		mm.runmatch(bytes)?;

		let mut matches_expected = vec![];
		matches_expected.push(Match {
			start: 6,
			end: 10,
			id: 1234,
		});
		matches_expected.push(Match {
			start: 11,
			end: 16,
			id: 9999,
		});
		matches_expected.push(Match {
			start: 25,
			end: 29,
			id: 1234,
		});
		matches_expected.push(Match {
			start: 11,
			end: 18,
			id: 1000,
		});
		matches_expected.sort();

		assert_eq!(mm.match_count(), 4);
		let matches_found = &mut mm.matches().clone();
		matches_found.sort();
		assert_eq!(&matches_found[0..4], &matches_expected[..]);

		mm.runmatch(b"tesla")?;
		for i in 0..mm.match_count() {
			info!("matches_found[{}]={:?}", i, mm.matches()[i])?;
		}

		let mut dictionary = Dictionary::new(10_000, true, 100);
		dictionary.set_on_match(move |_m| -> Result<(), Error> { Ok(()) })?;
		dictionary.add(
			Pattern {
				regex: "a".to_string(),
				id: 1,
			},
			false,
		)?;
		dictionary.add(
			Pattern {
				regex: "ab".to_string(),
				id: 2,
			},
			false,
		)?;
		dictionary.add(
			Pattern {
				regex: "abc".to_string(),
				id: 3,
			},
			false,
		)?;

		let mut mm = MultiMatch::new(100, dictionary);
		let bytes = b"abcd";
		mm.runmatch(bytes)?;
		for i in 0..mm.match_count() {
			info!("matches_found[{}]={:?}", i, mm.matches()[i])?;
		}
		assert_eq!(mm.match_count(), 3);
		let matches_found = &mut mm.matches().clone();
		matches_found.sort();
		let mut matches_expected = vec![];
		matches_expected.push(Match {
			start: 0,
			end: 1,
			id: 1,
		});
		matches_expected.push(Match {
			start: 0,
			end: 2,
			id: 2,
		});
		matches_expected.push(Match {
			start: 0,
			end: 3,
			id: 3,
		});
		matches_expected.sort();
		assert_eq!(&matches_found[0..3], &matches_expected[..]);

		let mut dictionary = Dictionary::new(10_000, true, 100);
		dictionary.set_on_match(move |_m| -> Result<(), Error> { Ok(()) })?;
		dictionary.add(
			Pattern {
				regex: "c".to_string(),
				id: 1,
			},
			false,
		)?;
		dictionary.add(
			Pattern {
				regex: "bc".to_string(),
				id: 2,
			},
			false,
		)?;
		dictionary.add(
			Pattern {
				regex: "abc".to_string(),
				id: 3,
			},
			false,
		)?;

		let mut mm = MultiMatch::new(100, dictionary);
		let bytes = b"abcd";
		mm.runmatch(bytes)?;
		for i in 0..mm.match_count() {
			info!("matches_found[{}]={:?}", i, mm.matches()[i])?;
		}
		assert_eq!(mm.match_count(), 3);
		let matches_found = &mut mm.matches().clone();
		matches_found.sort();
		let mut matches_expected = vec![];
		matches_expected.push(Match {
			start: 0,
			end: 3,
			id: 3,
		});
		matches_expected.push(Match {
			start: 1,
			end: 3,
			id: 2,
		});
		matches_expected.push(Match {
			start: 2,
			end: 3,
			id: 1,
		});
		matches_expected.sort();
		assert_eq!(&matches_found[0..3], &matches_expected[..]);

		let mut dictionary = Dictionary::new(10_000, true, 100);
		dictionary.set_on_match(move |_m| -> Result<(), Error> { Ok(()) })?;
		dictionary.add(
			Pattern {
				regex: "abcd".to_string(),
				id: 1,
			},
			false,
		)?;
		dictionary.add(
			Pattern {
				regex: "bc".to_string(),
				id: 2,
			},
			false,
		)?;

		let mut mm = MultiMatch::new(100, dictionary);
		let bytes = b"abcd";
		mm.runmatch(bytes)?;
		for i in 0..mm.match_count() {
			info!("matches_found[{}]={:?}", i, mm.matches()[i])?;
		}
		assert_eq!(mm.match_count(), 2);
		let matches_found = &mut mm.matches().clone();
		matches_found.sort();
		let mut matches_expected = vec![];
		matches_expected.push(Match {
			start: 0,
			end: 4,
			id: 1,
		});
		matches_expected.push(Match {
			start: 1,
			end: 3,
			id: 2,
		});
		matches_expected.sort();
		assert_eq!(&matches_found[0..2], &matches_expected[..]);

		Ok(())
	}

	#[test]
	fn test_multi_match2_case_insensitive() -> Result<(), Error> {
		let mut dictionary = Dictionary::new(10_000, false, 100);
		dictionary.set_on_match(move |_m| -> Result<(), Error> { Ok(()) })?;
		dictionary.add(
			Pattern {
				regex: "abcd".to_string(),
				id: 1,
			},
			false,
		)?;
		dictionary.add(
			Pattern {
				regex: "Bc".to_string(),
				id: 2,
			},
			false,
		)?;

		let mut mm = MultiMatch::new(100, dictionary);
		let bytes = b"abCd";
		mm.runmatch(bytes)?;
		for i in 0..mm.match_count() {
			info!("matches_found[{}]={:?}", i, mm.matches()[i])?;
		}
		assert_eq!(mm.match_count(), 2);
		let matches_found = &mut mm.matches().clone();
		matches_found.sort();
		let mut matches_expected = vec![];
		matches_expected.push(Match {
			start: 0,
			end: 4,
			id: 1,
		});
		matches_expected.push(Match {
			start: 1,
			end: 3,
			id: 2,
		});
		matches_expected.sort();
		assert_eq!(&matches_found[0..2], &matches_expected[..]);
		Ok(())
	}

	#[test]
	fn test_multi_match3_wild_card() -> Result<(), Error> {
		let mut dictionary = Dictionary::new(10_000, true, 100);
		dictionary.set_on_match(move |_m| -> Result<(), Error> { Ok(()) })?;
		dictionary.add(
			Pattern {
				regex: "ab.d".to_string(),
				id: 1,
			},
			false,
		)?;

		let mut mm = MultiMatch::new(100, dictionary);
		let bytes = b"abxd";
		mm.runmatch(bytes)?;
		for i in 0..mm.match_count() {
			info!("matches_found[{}]={:?}", i, mm.matches()[i])?;
		}
		assert_eq!(mm.match_count(), 1);
		let matches_found = &mut mm.matches().clone();
		matches_found.sort();
		let mut matches_expected = vec![];
		matches_expected.push(Match {
			start: 0,
			end: 4,
			id: 1,
		});
		matches_expected.sort();
		assert_eq!(&matches_found[0..1], &matches_expected[..]);

		let bytes = b"abxe";
		mm.runmatch(bytes)?;

		assert_eq!(mm.match_count(), 0);

		let bytes = b"abxxd";
		mm.runmatch(bytes)?;

		assert_eq!(mm.match_count(), 0);

		Ok(())
	}

	#[test]
	fn test_multi_match4_multi_wildcard() -> Result<(), Error> {
		let mut dictionary = Dictionary::new(10_000, true, 100);
		dictionary.set_on_match(move |_m| -> Result<(), Error> { Ok(()) })?;
		dictionary.add(
			Pattern {
				regex: "ab.*d".to_string(),
				id: 1,
			},
			false,
		)?;

		let mut mm = MultiMatch::new(100, dictionary);
		let bytes = b"abxd";
		mm.runmatch(bytes)?;
		for i in 0..mm.match_count() {
			info!("matches_found[{}]={:?}", i, mm.matches()[i])?;
		}
		assert_eq!(mm.match_count(), 1);
		let matches_found = &mut mm.matches().clone();
		matches_found.sort();
		let mut matches_expected = vec![];
		matches_expected.push(Match {
			start: 0,
			end: 4,
			id: 1,
		});
		matches_expected.sort();
		assert_eq!(&matches_found[0..1], &matches_expected[..]);

		let bytes = b"ababcd";
		mm.runmatch(bytes)?;
		assert_eq!(mm.match_count(), 2);
		let matches_found = &mut mm.matches().clone();
		for i in 0..mm.match_count() {
			info!("matches_found[{}]={:?}", i, mm.matches()[i])?;
		}
		matches_found.sort();
		let mut matches_expected = vec![];
		matches_expected.push(Match {
			start: 0,
			end: 6,
			id: 1,
		});
		matches_expected.push(Match {
			start: 2,
			end: 6,
			id: 1,
		});
		matches_expected.sort();
		assert_eq!(&matches_found[0..2], &matches_expected[..]);

		let bytes = b"abxe";
		mm.runmatch(bytes)?;

		assert_eq!(mm.match_count(), 0);
		Ok(())
	}

	#[test]
	fn test_multi_match5_escape_sequences() -> Result<(), Error> {
		let mut dictionary = Dictionary::new(10_000, true, 100);
		dictionary.set_on_match(move |_m| -> Result<(), Error> { Ok(()) })?;
		dictionary.add(
			Pattern {
				regex: "a\\.\\\\xyz".to_string(),
				id: 1,
			},
			false,
		)?;

		let mut mm = MultiMatch::new(100, dictionary);
		let bytes = b"a.\\xyz";
		mm.runmatch(bytes)?;
		for i in 0..mm.match_count() {
			info!("matches_found[{}]={:?}", i, mm.matches()[i])?;
		}
		assert_eq!(mm.match_count(), 1);
		let matches_found = &mut mm.matches().clone();
		matches_found.sort();
		let mut matches_expected = vec![];
		matches_expected.push(Match {
			start: 0,
			end: 6,
			id: 1,
		});
		matches_expected.sort();
		assert_eq!(&matches_found[0..1], &matches_expected[..]);

		let bytes = b"a\\.xyz";
		mm.runmatch(bytes)?;
		assert_eq!(mm.match_count(), 0);

		Ok(())
	}

	#[test]
	fn test_multi_match6_termination() -> Result<(), Error> {
		let mut dictionary = Dictionary::new(10_000, true, 100);
		dictionary.set_on_match(move |_m| -> Result<(), Error> { Ok(()) })?;
		dictionary.add(
			Pattern {
				regex: "a\\.\\\\xyz".to_string(),
				id: 1,
			},
			true,
		)?;

		dictionary.add(
			Pattern {
				regex: "111111".to_string(),
				id: 2,
			},
			false,
		)?;

		let mut mm = MultiMatch::new(100, dictionary);
		let bytes = b"a.\\xyzx111111";
		mm.runmatch(bytes)?;
		for i in 0..mm.match_count() {
			info!("matches_found[{}]={:?}", i, mm.matches()[i])?;
		}
		assert_eq!(mm.match_count(), 1);
		let matches_found = &mut mm.matches().clone();
		matches_found.sort();
		let mut matches_expected = vec![];
		matches_expected.push(Match {
			start: 0,
			end: 6,
			id: 1,
		});
		matches_expected.sort();
		assert_eq!(&matches_found[0..1], &matches_expected[..]);

		let bytes = b"111111xa.\\xyzx111111";
		mm.runmatch(bytes)?;
		assert_eq!(mm.match_count(), 2);

		Ok(())
	}

	#[test]
	fn test_multi_match7_max_wildcard_len() -> Result<(), Error> {
		let mut dictionary = Dictionary::new(10_000, true, 10);
		dictionary.set_on_match(move |_m| -> Result<(), Error> { Ok(()) })?;
		dictionary.add(
			Pattern {
				regex: "a.*b".to_string(),
				id: 1,
			},
			true,
		)?;

		let mut mm = MultiMatch::new(100, dictionary);
		let bytes = b"axxxxxxxxxxxb";
		assert!(mm.runmatch(bytes).is_err());
		let bytes = b"axxxxxxxxxxb";
		mm.runmatch(bytes)?;
		for i in 0..mm.match_count() {
			info!("matches_found[{}]={:?}", i, mm.matches()[i])?;
		}
		assert_eq!(mm.match_count(), 1);
		Ok(())
	}

	#[test]
	fn test_multi_match8_max_capacity() -> Result<(), Error> {
		let mut dictionary = Dictionary::new(10_000, true, 10);
		dictionary.set_on_match(move |_m| -> Result<(), Error> { Ok(()) })?;
		dictionary.add(
			Pattern {
				regex: "abc".to_string(),
				id: 1,
			},
			false,
		)?;

		let mut mm = MultiMatch::new(3, dictionary);
		let bytes = b"abcabcabcabc";
		assert!(mm.runmatch(bytes).is_err());
		let bytes = b"abcxxxxxxxxxxb";
		mm.runmatch(bytes)?;
		for i in 0..mm.match_count() {
			info!("matches_found[{}]={:?}", i, mm.matches()[i])?;
		}
		assert_eq!(mm.match_count(), 1);
		Ok(())
	}

	#[test]
	fn test_multi_match9_headers() -> Result<(), Error> {
		let mut dictionary = Dictionary::new(10_000, false, 512);
		dictionary.set_on_match(move |_m| -> Result<(), Error> { Ok(()) })?;
		dictionary.add(
			Pattern {
				regex: "\r\n\r\n".to_string(),
				id: 1,
			},
			true,
		)?;

		dictionary.add(
			Pattern {
				regex: "1234".to_string(),
				id: 2,
			},
			false,
		)?;

		dictionary.add(
			Pattern {
				regex: "\r\n.*: ".to_string(),
				id: 3,
			},
			false,
		)?;

		dictionary.add(
			Pattern {
				regex: "\r\nCONTENT-LENGTH: ".to_string(),
				id: 4,
			},
			false,
		)?;

		let mut mm = MultiMatch::new(300, dictionary);

		let bytes = b"POST /mypost HTTP/1.1\r\n\
Host: localhost\r\n\
Content-Length: 10\r\n\
User-Agent: myagent\r\n\
Range: 0-100\r\n\
CC: ok\r\n\
CO: ok\r\n\
CON: ok\r\n\
CONt: ok\r\n\
CONte: ok\r\n\
CONten: ok\r\n\
Random-Header: abc123\r\n\r\n
012345\r\n\r\n";

		mm.runmatch(bytes)?;

		info!("bytes.len={}", bytes.len())?;
		for i in 0..mm.match_count() {
			let bmatch = &mm.matches()[i];
			info!(
				"matches_found[{}]='{:?}',id={}",
				i,
				std::str::from_utf8(&bytes[bmatch.start..bmatch.end])?,
				bmatch.id
			)?;
		}

		assert_eq!(mm.match_count(), 13);

		Ok(())
	}

	#[test]
	fn test_multi_match10_lookback() -> Result<(), Error> {
		let mut dictionary = Dictionary::new(10_000, false, 512);
		dictionary.set_on_match(move |_m| -> Result<(), Error> { Ok(()) })?;
		dictionary.add(
			Pattern {
				regex: "abcdefghijklmnopqrstuvwxyz".to_string(),
				id: 1,
			},
			false,
		)?;
		dictionary.add(
			Pattern {
				regex: "abcdefghijklmnopqrstuvwxy".to_string(),
				id: 2,
			},
			false,
		)?;
		dictionary.add(
			Pattern {
				regex: "abcdefghijklmnopqrstuvwx".to_string(),
				id: 3,
			},
			false,
		)?;
		dictionary.add(
			Pattern {
				regex: "abcdefghijklmnopqrstuvw".to_string(),
				id: 4,
			},
			false,
		)?;
		dictionary.add(
			Pattern {
				regex: "abcdefghijklmnopqrstuv".to_string(),
				id: 5,
			},
			false,
		)?;
		dictionary.add(
			Pattern {
				regex: "abcdefghijklmnopqrstu".to_string(),
				id: 6,
			},
			false,
		)?;
		dictionary.add(
			Pattern {
				regex: "abcdefghijklmnopqrst".to_string(),
				id: 7,
			},
			false,
		)?;
		dictionary.add(
			Pattern {
				regex: "abcdefghijklmnopqrs".to_string(),
				id: 8,
			},
			false,
		)?;
		dictionary.add(
			Pattern {
				regex: "abcdefghijklmnopqr".to_string(),
				id: 9,
			},
			false,
		)?;

		let mut mm = MultiMatch::new(300, dictionary);

		let bytes = b"abcdefghijklmnopqrstuvwxyz";

		mm.runmatch(bytes)?;

		assert_eq!(mm.match_count(), 9);

		let mut matches_expected = vec![];
		matches_expected.push(Match {
			start: 0,
			end: 26,
			id: 1,
		});
		matches_expected.push(Match {
			start: 0,
			end: 25,
			id: 2,
		});
		matches_expected.push(Match {
			start: 0,
			end: 24,
			id: 3,
		});
		matches_expected.push(Match {
			start: 0,
			end: 23,
			id: 4,
		});
		matches_expected.push(Match {
			start: 0,
			end: 22,
			id: 5,
		});
		matches_expected.push(Match {
			start: 0,
			end: 21,
			id: 6,
		});
		matches_expected.push(Match {
			start: 0,
			end: 20,
			id: 7,
		});
		matches_expected.push(Match {
			start: 0,
			end: 19,
			id: 8,
		});
		matches_expected.push(Match {
			start: 0,
			end: 18,
			id: 9,
		});

		matches_expected.sort();
		let matches_found = &mut mm.matches().clone();
		matches_found.sort();
		assert_eq!(&matches_found[0..mm.match_count()], &matches_expected[..]);

		Ok(())
	}

	#[test]
	fn test_multi_match11_start_only() -> Result<(), Error> {
		let mut dictionary = Dictionary::new(10_000, false, 512);
		dictionary.set_on_match(move |_m| -> Result<(), Error> { Ok(()) })?;
		dictionary.add(
			Pattern {
				regex: "^abc".to_string(),
				id: 1,
			},
			false,
		)?;

		let mut mm = MultiMatch::new(300, dictionary);
		let bytes = b"abcdxxabcyy";
		mm.runmatch(bytes)?;

		for i in 0..mm.match_count() {
			let bmatch = &mm.matches()[i];
			info!(
				"matches_found[{}]='{:?}',id={}",
				i,
				std::str::from_utf8(&bytes[bmatch.start..bmatch.end])?,
				bmatch.id
			)?;
		}

		assert_eq!(mm.match_count(), 1);
		assert_eq!(mm.matches()[0].start, 0);
		assert_eq!(mm.matches()[0].end, 3);
		assert_eq!(mm.matches()[0].id, 1);

		Ok(())
	}

	#[test]
	fn test_multi_match12_on_match() -> Result<(), Error> {
		let mut dictionary = Dictionary::new(10_000, false, 512);
		let x = Arc::new(RwLock::new(0));
		let x_clone = x.clone();
		dictionary.set_on_match(move |m| -> Result<(), Error> {
			assert_eq!(
				m,
				&Match {
					start: 0,
					end: 3,
					id: 1
				}
			);
			let mut x_clone = lockw!(x_clone)?;
			(*x_clone) += 1;
			Ok(())
		})?;
		dictionary.add(
			Pattern {
				regex: "^abc".to_string(),
				id: 1,
			},
			false,
		)?;

		let mut mm = MultiMatch::new(300, dictionary);
		let bytes = b"abcdxxabcyy";
		mm.runmatch(bytes)?;

		for i in 0..mm.match_count() {
			let bmatch = &mm.matches()[i];
			info!(
				"matches_found[{}]='{:?}',id={}",
				i,
				std::str::from_utf8(&bytes[bmatch.start..bmatch.end])?,
				bmatch.id
			)?;
		}

		assert_eq!(mm.match_count(), 1);
		assert_eq!(mm.matches()[0].start, 0);
		assert_eq!(mm.matches()[0].end, 3);
		assert_eq!(mm.matches()[0].id, 1);

		assert_eq!(*(lockr!(x)?), 1);
		Ok(())
	}
}
