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

use nioruntime_log::*;

trace!();

fn main() -> Result<(), std::io::Error> {
	log_config!(LogConfig {
		show_bt: false,
		show_stdout: false,
		file_path: Some("abc".to_string()),
		..Default::default()
	})
	.expect("log config");

	fatal!("fatal").expect("failed to log");
	fatal_no_ts!("fatal_no_ts").expect("failed to log");
	fatal_all!("fatal all").expect("failed to log");

	error!("error").expect("failed to log");
	error_no_ts!("error_no_ts").expect("failed to log");
	error_all!("error all").expect("failed to log");

	warn!("warn").expect("failed to log");
	warn_no_ts!("warn_no_ts").expect("failed to log");
	warn_all!("warn all").expect("failed to log");

	info!("info").expect("failed to log");
	info_no_ts!("info no ts").expect("failed to log");
	info_all!("info all").expect("failed to log");

	debug!("debug").expect("failed to log");
	debug_no_ts!("debug no ts").expect("failed to log");
	debug_all!("debug all").expect("failed to log");

	trace!("trace").expect("failed to log");
	trace_no_ts!("trace_no_ts").expect("failed to log");
	trace_all!("trace all").expect("failed to log");

	let config = get_config!("default");
	info!("config={:?}", config).expect("config");

	let config_option = get_config_option!(Settings::Stdout);
	set_config_option!(Settings::Timestamp, true).expect("set");
	info_all!("stdout={:?}", config_option).expect("info");
	rotate!().expect("rotate");
	let rotation_status = rotation_status!();
	info_all!("rot_status={:?}", rotation_status).expect("info");

	Ok(())
}
