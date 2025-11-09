// SPDX-License-Identifier: MIT OR Apache-2.0
// Project: rustgenhash
// File: dispatcher.rs
// Author: Volker Schwaberow <volker@schwaberow.de>
// Copyright (c) 2022 Volker Schwaberow

use super::ConsoleError;
use std::env;
use std::path::PathBuf;
use std::process::{Command, Stdio};

pub struct DispatchOutput {
	pub exit_code: i32,
	pub stdout: String,
	pub stderr: String,
}

fn current_binary() -> Result<PathBuf, ConsoleError> {
	env::current_exe().map_err(ConsoleError::from)
}

fn guard_command(tokens: &[String]) -> Result<(), ConsoleError> {
	if tokens
		.first()
		.map(|cmd| cmd.eq_ignore_ascii_case("console"))
		.unwrap_or(false)
	{
		return Err(ConsoleError::Message(
			"cannot invoke `console` from within console".into(),
		));
	}
	Ok(())
}

pub fn run_command(tokens: &[String]) -> Result<i32, ConsoleError> {
	guard_command(tokens)?;
	let binary = current_binary()?;
	let status = Command::new(binary)
		.args(tokens)
		.env("RGH_CONSOLE_CHILD", "1")
		.stdin(Stdio::inherit())
		.stdout(Stdio::inherit())
		.stderr(Stdio::inherit())
		.status()
		.map_err(ConsoleError::from)?;
	Ok(status.code().unwrap_or(1))
}

pub fn run_command_capture(
	tokens: &[String],
) -> Result<DispatchOutput, ConsoleError> {
	guard_command(tokens)?;
	let binary = current_binary()?;
	let output = Command::new(binary)
		.args(tokens)
		.env("RGH_CONSOLE_CHILD", "1")
		.stdout(Stdio::piped())
		.stderr(Stdio::piped())
		.output()
		.map_err(ConsoleError::from)?;
	let stdout = String::from_utf8_lossy(&output.stdout).to_string();
	let stderr = String::from_utf8_lossy(&output.stderr).to_string();
	let exit_code = output.status.code().unwrap_or(1);
	Ok(DispatchOutput {
		exit_code,
		stdout,
		stderr,
	})
}
