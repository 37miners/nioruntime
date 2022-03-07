// Copyright 2022 37 Miners, LLC
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

use clap::load_yaml;
use clap::App;
use nioruntime_err::Error;
use nioruntime_log::*;
use nioruntime_util::static_hash::{StaticHash, StaticHashConfig};
use std::alloc::{GlobalAlloc, Layout, System};
use std::collections::HashMap;
use std::time::Instant;

debug!();

// include build information
pub mod built_info {
	include!(concat!(env!("OUT_DIR"), "/built.rs"));
}

const KEY_LEN: usize = 8;
const VALUE_LEN: usize = 8;

struct MonAllocator;

static mut MEM_USED: usize = 0;

unsafe impl GlobalAlloc for MonAllocator {
	unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
		MEM_USED += layout.size();
		System.alloc(layout)
	}

	unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
		MEM_USED -= layout.size();
		System.dealloc(ptr, layout)
	}
}

#[global_allocator]
static GLOBAL: MonAllocator = MonAllocator;

fn main() -> Result<(), Error> {
	log_config!(LogConfig {
		show_bt: false,
		..Default::default()
	})?;

	let yml = load_yaml!("hash_perf.yml");
	let args = App::from_yaml(yml)
		.version(built_info::PKG_VERSION)
		.get_matches();

	let count = match args.is_present("count") {
		true => args.value_of("count").unwrap().parse()?,
		false => 1_000,
	};
	let static_hash_size = match args.is_present("size") {
		true => args.value_of("size").unwrap().parse()?,
		false => 2_000,
	};
	let no_gets = args.is_present("no_gets");
	let do_static = args.is_present("do_static");
	let do_hash = args.is_present("do_hash");
	let itt = match args.is_present("itt") {
		true => args.value_of("itt").unwrap().parse()?,
		false => 1,
	};

	let iterator = args.is_present("with_iterator");

	if do_static && do_hash {
		error!("You can only do either --do_static or --do_hash, not both")?;
		return Ok(());
	}

	info!("Starting tests")?;
	let mem_used_pre = unsafe { MEM_USED };
	if do_static {
		for _ in 0..itt {
			let now = Instant::now();
			{
				let mut static_hash = StaticHash::new(StaticHashConfig {
					max_entries: static_hash_size,
					key_len: KEY_LEN,
					entry_len: VALUE_LEN,
					max_load_factor: 0.99,
					iterator,
				})?;

				for _ in 0..count {
					let key: [u8; KEY_LEN] = rand::random();
					let value: [u8; VALUE_LEN] = rand::random();
					static_hash.put_raw(&key, &value)?;
					if !no_gets {
						static_hash.get_raw(&key);
					}
				}

				info!(
					"Memory used (pre_drop) = {}mb",
					(unsafe { MEM_USED } - mem_used_pre) as f64 / 1_000_000 as f64
				)?;
			}

			info!(
				"Memory used (post drop) = {}mb",
				(unsafe { MEM_USED } - mem_used_pre) as f64 / 1_000_000 as f64
			)?;
			info!(
				"(StaticHash) Elapsed time = {:.2}ms",
				now.elapsed().as_nanos() as f64 / 1_000_000 as f64
			)?;
		}
	}

	if do_hash {
		for _ in 0..itt {
			let now = Instant::now();
			{
				let mut hash_map = HashMap::new();
				let mut keys = vec![];
				let mut values = vec![];

				for _ in 0..count {
					let key: [u8; KEY_LEN] = rand::random();
					let value: [u8; VALUE_LEN] = rand::random();
					keys.push(key);
					values.push(value);
				}
				for i in 0..count {
					hash_map.insert(&keys[i], &values[i]);
					if !no_gets {
						hash_map.get(&keys[i]);
					}
				}

				info!(
					"Memory used (pre_drop) = {}mb",
					(unsafe { MEM_USED } - mem_used_pre) as f64 / 1_000_000 as f64
				)?;
			}

			info!(
				"Memory used (post drop) = {}mb",
				(unsafe { MEM_USED } - mem_used_pre) as f64 / 1_000_000 as f64
			)?;
			info!(
				"(HashMap) Elapsed time = {:.2}ms",
				now.elapsed().as_nanos() as f64 / 1_000_000 as f64
			)?;
		}
	}

	Ok(())
}
