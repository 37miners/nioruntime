#[cfg(test)]
pub(crate) mod test {
	use nioruntime_err::Error;
	use nioruntime_log::*;
	use std::sync::Once;

	static START: Once = Once::new();

	pub fn init_logger() -> Result<(), Error> {
		START.call_once(|| {
			let _ = std::fs::remove_dir_all(".log.nio");
			std::fs::create_dir_all(".log.nio").expect("failed to create log dir");
			let mainlog = format!(".log.nio/mainlog.log");
			log_config!(LogConfig {
				show_line_num: true,
				show_log_level: true,
				show_bt: false,
				file_path: Some(mainlog.to_string()),
				max_age_millis: 1000 * 60 * 60,
				max_size: 1024 * 1024,
				auto_rotate: false,
				..Default::default()
			})
			.expect("failed to init mainlog");
		});

		Ok(())
	}
}
