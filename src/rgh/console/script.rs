// SPDX-License-Identifier: MIT OR Apache-2.0
// Project: rustgenhash
// File: script.rs
// Author: Volker Schwaberow <volker@schwaberow.de>
// Copyright (c) 2022 Volker Schwaberow

use super::color::ConsoleLineRole;
use super::session::{ConsoleSession, Flow};
use super::ConsoleError;
use std::fs::File;
use std::io::{BufRead, BufReader};
use std::path::Path;

/// Executes commands from a script file in sequence.
pub fn run_script(
	session: &mut ConsoleSession,
	path: &Path,
	ignore_errors: bool,
) -> Result<i32, ConsoleError> {
	let file = File::open(path).map_err(ConsoleError::from)?;
	let reader = BufReader::new(file);
	for (idx, line) in reader.lines().enumerate() {
		let line = line.map_err(ConsoleError::from)?;
		let trimmed = line.trim();
		if trimmed.is_empty() || trimmed.starts_with('#') {
			continue;
		}
		let prompt_line = format!("rgh-console(script)# {}", trimmed);
		let colored_prompt = session
			.color_state()
			.format(ConsoleLineRole::Prompt, &prompt_line);
		println!("{}", colored_prompt);
		match session.execute_line(&line) {
			Ok(Flow::Continue) => continue,
			Ok(Flow::Exit(code)) => return Ok(code),
			Err(err) if ignore_errors => {
				let warning = format!(
					"script line {} failed but continuing: {}",
					idx + 1,
					err
				);
				let colored = session
					.color_state()
					.format(ConsoleLineRole::Warning, &warning);
				eprintln!("{}", colored);
			}
			Err(err) => return Err(err),
		}
	}
	Ok(0)
}
