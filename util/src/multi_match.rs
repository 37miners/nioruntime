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
	next: [u32; 256],
	b: u8,
	pattern_id: u64,
}

impl Default for Node {
	fn default() -> Self {
		Self {
			next: [u32::MAX; 256],
			b: 0,
			pattern_id: u64::MAX,
		}
	}
}

pub struct Dictionary {
	nodes: Vec<Node>,
	next: u32,
	case_sensitive: bool,
}

impl Dictionary {
	pub fn new(capacity: usize, case_sensitive: bool) -> Self {
		let mut nodes = vec![];
		nodes.resize(capacity, Node::default());
		Self {
			nodes,
			next: 0,
			case_sensitive,
		}
	}

	pub fn add(&mut self, pattern: Pattern) -> Result<(), Error> {
		if pattern.regex.len() == 0 {
			return Err(ErrorKind::InvalidRegex(
				"Regex must be at least one byte long".to_string(),
			)
			.into());
		}

		let lower;
		let mut regex = if self.case_sensitive {
			pattern.regex.as_str().bytes()
		} else {
			lower = pattern.regex.to_lowercase();
			lower.as_str().bytes()
		};
		let mut cur_byte = regex.next().unwrap();
		let mut cur_node = &mut self.nodes[0];

		loop {
			debug!("cur_node.b = {}", cur_node.b as char)?;
			let index = match cur_node.next[cur_byte as usize] {
				u32::MAX => {
					cur_node.next[cur_byte as usize] = self.next + 1;
					self.next += 1;
					self.next
				}
				_ => cur_node.next[cur_byte as usize],
			};
			debug!("index={}", index)?;
			cur_node = &mut self.nodes[index as usize];
			cur_node.b = cur_byte;
			cur_byte = match regex.next() {
				Some(cur_byte) => cur_byte,
				None => {
					cur_node.pattern_id = pattern.id;
					break;
				}
			};
		}

		Ok(())
	}
}

pub struct MultiMatch {
	matches: Vec<Match>,
	match_count: usize,
	dictionary: Dictionary,
}

impl MultiMatch {
	pub fn new(max_matches: usize, dictionary: Dictionary) -> Self {
		let mut matches = vec![];
		matches.resize(max_matches, Match::default());
		Self {
			matches,
			match_count: 0,
			dictionary,
		}
	}

	pub fn runmatch(&mut self, text: &[u8]) -> Result<(), Error> {
		self.match_count = 0;
		let mut itt = 0;
		let len = text.len();
		let mut cur_node = &self.dictionary.nodes[0];
		let mut start = 0;

		loop {
			if itt >= len {
				start += 1;
				itt = start;
				cur_node = &self.dictionary.nodes[0];
				if start >= len {
					break;
				}
			}

			//let byte = text[itt];
			let byte = if self.dictionary.case_sensitive {
				text[itt]
			} else {
				if text[itt] >= 'A' as u8 && text[itt] <= 'Z' as u8 {
					text[itt] + 32
				} else {
					text[itt]
				}
			};

			match cur_node.next[byte as usize] {
				u32::MAX => {
					cur_node = &self.dictionary.nodes[0];
					itt = start + 1;
					start += 1;
					continue;
				}
				_ => cur_node = &self.dictionary.nodes[cur_node.next[byte as usize] as usize],
			}

			match cur_node.pattern_id {
				u64::MAX => {}
				_ => {
					self.matches[self.match_count].id = cur_node.pattern_id;
					self.matches[self.match_count].end = itt + 1;
					self.matches[self.match_count].start = start;
					self.match_count += 1;
				}
			}

			itt += 1;
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
	use nioruntime_err::Error;

	#[test]
	fn test_multi_match() -> Result<(), Error> {
		let mut d = Dictionary::new(10_000, true);
		d.add(Pattern {
			regex: "test".to_string(),
			id: 1234,
		})?;
		d.add(Pattern {
			regex: "ok123".to_string(),
			id: 5678,
		})?;

		d.add(Pattern {
			regex: "tesla".to_string(),
			id: 9999,
		})?;

		d.add(Pattern {
			regex: "teslaok".to_string(),
			id: 1000,
		})?;

		d.add(Pattern {
			regex: "eyxxx".to_string(),
			id: 1111,
		})?;

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

		let mut dictionary = Dictionary::new(10_000, true);
		dictionary.add(Pattern {
			regex: "a".to_string(),
			id: 1,
		})?;
		dictionary.add(Pattern {
			regex: "ab".to_string(),
			id: 2,
		})?;
		dictionary.add(Pattern {
			regex: "abc".to_string(),
			id: 3,
		})?;

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

		let mut dictionary = Dictionary::new(10_000, true);
		dictionary.add(Pattern {
			regex: "c".to_string(),
			id: 1,
		})?;
		dictionary.add(Pattern {
			regex: "bc".to_string(),
			id: 2,
		})?;
		dictionary.add(Pattern {
			regex: "abc".to_string(),
			id: 3,
		})?;

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

		let mut dictionary = Dictionary::new(10_000, true);
		dictionary.add(Pattern {
			regex: "abcd".to_string(),
			id: 1,
		})?;
		dictionary.add(Pattern {
			regex: "bc".to_string(),
			id: 2,
		})?;

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
	fn test_case_insensitive() -> Result<(), Error> {
		let mut dictionary = Dictionary::new(10_000, false);
		dictionary.add(Pattern {
			regex: "abcd".to_string(),
			id: 1,
		})?;
		dictionary.add(Pattern {
			regex: "Bc".to_string(),
			id: 2,
		})?;

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
}
