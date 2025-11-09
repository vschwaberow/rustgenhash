// SPDX-License-Identifier: MIT OR Apache-2.0
// Project: rustgenhash
// File: interactive_console.rs
// Author: Volker Schwaberow <volker@schwaberow.de>
// Copyright (c) 2022 Volker Schwaberow

use assert_cmd::prelude::*;
use predicates::prelude::*;
use rustgenhash::rgh::console::{
	parse_command, run_console, ConsoleError, ConsoleMode,
	ConsoleOptions, ConsoleValueType, ConsoleVariableStore,
};
use std::fs;
use std::path::Path;
use std::process::Command;
use tempfile::NamedTempFile;

#[test]
fn parser_detects_variable_assignment() {
	let parsed = parse_command(
		"set $alpha = digest string --alg blake3 \"alpha\"",
	);
	assert!(parsed.is_assignment());
	assert_eq!(parsed.assignment.as_deref(), Some("alpha"));
	assert_eq!(parsed.tokens[0], "set");
}

#[test]
fn variable_store_round_trip() {
	let mut store = ConsoleVariableStore::default();
	store.set(
		"token",
		"deadbeefcafebabe",
		ConsoleValueType::Digest,
		true,
	);
	let var = store.get("token").expect("variable stored");
	assert_eq!(var.name, "token");
	assert!(var.preview().contains("****"));
	assert!(store.clear("token"));
	assert!(store.get("token").is_none());
}

#[test]
fn script_runner_handles_missing_file() {
	let mut options = ConsoleOptions::interactive();
	options.tty_mode = ConsoleMode::Script;
	options.script_path =
		Some(std::path::PathBuf::from("does-not-exist.rgh"));
	let result = run_console(options);
	assert!(result.is_err());
}

#[test]
fn script_runner_executes_simple_script() {
	let mut file = NamedTempFile::new().expect("create temp script");
	std::io::Write::write_all(
		&mut file,
		b"# console smoke test\nshow vars\n",
	)
	.expect("write script");

	let mut options =
		ConsoleOptions::from_script(file.path().to_path_buf(), false);
	options.tty_mode = ConsoleMode::Script;
	let rc = run_console(options).expect("console run");
	assert_eq!(rc, 0);
}

#[test]
fn script_abort_exits_with_130() {
	let mut file = NamedTempFile::new().expect("create temp script");
	std::io::Write::write_all(&mut file, b"abort\n")
		.expect("write script");
	let options =
		ConsoleOptions::from_script(file.path().to_path_buf(), false);
	let rc = run_console(options).expect("console run");
	assert_eq!(rc, 130);
}

#[test]
fn console_digest_fixture_exists() {
	let content = std::fs::read_to_string(
		"tests/fixtures/interactive/console_digest_basic.txt",
	)
	.expect("fixture readable");
	assert!(content.contains("rgh-console# digest"));
}

#[test]
fn undefined_variable_in_script_returns_error() {
	let mut file = NamedTempFile::new().expect("create temp script");
	std::io::Write::write_all(
		&mut file,
		b"digest string --alg blake3 $missing\n",
	)
	.expect("write script");
	let options =
		ConsoleOptions::from_script(file.path().to_path_buf(), false);
	let err =
		run_console(options).expect_err("expect variable error");
	match err {
		ConsoleError::Variable(name) => assert_eq!(name, "missing"),
		other => panic!("unexpected error: {other:?}"),
	}
}

#[test]
fn script_success_matches_fixture() {
	let script_path = Path::new(
		"tests/fixtures/interactive/scripts/vars_chain.rgh",
	);
	let binary = assert_cmd::cargo::cargo_bin!("rgh");
	let assert = Command::new(binary)
		.args(["console", "--script", script_path.to_str().unwrap()])
		.assert()
		.success();
	let expected = fs::read_to_string(
		"tests/fixtures/interactive/console_variables_chain.txt",
	)
	.expect("read fixture");
	assert.stdout(predicate::eq(expected));
}

#[test]
fn script_error_matches_fixture_and_exit_code() {
	let script_path = Path::new(
		"tests/fixtures/interactive/scripts/script_error.rgh",
	);
	let expected_out = fs::read_to_string(
		"tests/fixtures/interactive/console_script_error.txt",
	)
	.expect("read fixture");
	let binary = assert_cmd::cargo::cargo_bin!("rgh");
	Command::new(binary)
		.args(["console", "--script", script_path.to_str().unwrap()])
		.assert()
		.code(65)
		.stdout(predicate::eq(expected_out))
		.stderr(predicate::eq(
			"error: undefined variable $missing\n",
		));
}

#[test]
fn console_completion_digest_fixture_matches() {
	let script_path = Path::new(
		"tests/fixtures/interactive/scripts/complete_digest.rgh",
	);
	let expected = fs::read_to_string(
		"tests/fixtures/interactive/console_completion_digest.txt",
	)
	.expect("read digest completion fixture");
	let binary = assert_cmd::cargo::cargo_bin!("rgh");
	Command::new(binary)
		.args(["console", "--script", script_path.to_str().unwrap()])
		.assert()
		.success()
		.stdout(predicate::eq(expected))
		.stderr(predicate::str::is_empty());
}

#[test]
fn console_completion_k_fixture_matches() {
	let script_path = Path::new(
		"tests/fixtures/interactive/scripts/complete_k.rgh",
	);
	let expected = fs::read_to_string(
		"tests/fixtures/interactive/console_completion_k.txt",
	)
	.expect("read k completion fixture");
	let binary = assert_cmd::cargo::cargo_bin!("rgh");
	Command::new(binary)
		.args(["console", "--script", script_path.to_str().unwrap()])
		.assert()
		.success()
		.stdout(predicate::eq(expected))
		.stderr(predicate::str::is_empty());
}

#[test]
fn console_completion_script_fixture_matches() {
	let script_path = Path::new(
		"tests/fixtures/interactive/scripts/complete_script.rgh",
	);
	let expected = fs::read_to_string(
		"tests/fixtures/interactive/console_completion_script.txt",
	)
	.expect("read completion script fixture");
	let binary = assert_cmd::cargo::cargo_bin!("rgh");
	Command::new(binary)
		.args(["console", "--script", script_path.to_str().unwrap()])
		.assert()
		.success()
		.stdout(predicate::eq(expected))
		.stderr(predicate::str::is_empty());
}

#[test]
fn console_help_digest_fixture_matches() {
	let script_path = Path::new(
		"tests/fixtures/interactive/scripts/help_digest.rgh",
	);
	let expected = fs::read_to_string(
		"tests/fixtures/interactive/console_help_digest.txt",
	)
	.expect("read help digest fixture");
	let binary = assert_cmd::cargo::cargo_bin!("rgh");
	Command::new(binary)
		.args(["console", "--script", script_path.to_str().unwrap()])
		.assert()
		.success()
		.stdout(predicate::eq(expected))
		.stderr(predicate::str::is_empty());
}

#[test]
fn console_help_unknown_fixture_matches() {
	let script_path = Path::new(
		"tests/fixtures/interactive/scripts/help_unknown.rgh",
	);
	let expected_out = fs::read_to_string(
		"tests/fixtures/interactive/console_help_unknown.txt",
	)
	.expect("read help unknown stdout");
	let expected_err = fs::read_to_string(
		"tests/fixtures/interactive/console_help_unknown.stderr.txt",
	)
	.expect("read help unknown stderr");
	let binary = assert_cmd::cargo::cargo_bin!("rgh");
	Command::new(binary)
		.args(["console", "--script", script_path.to_str().unwrap()])
		.assert()
		.code(64)
		.stdout(predicate::eq(expected_out))
		.stderr(predicate::eq(expected_err));
}

#[test]
fn console_help_script_fixture_matches() {
	let script_path = Path::new(
		"tests/fixtures/interactive/scripts/help_script.rgh",
	);
	let expected = fs::read_to_string(
		"tests/fixtures/interactive/console_help_script.txt",
	)
	.expect("read help script fixture");
	let binary = assert_cmd::cargo::cargo_bin!("rgh");
	Command::new(binary)
		.args(["console", "--script", script_path.to_str().unwrap()])
		.assert()
		.success()
		.stdout(predicate::eq(expected))
		.stderr(predicate::str::is_empty());
}

#[test]
fn child_streams_remain_plain_when_color_forced() {
	let script_path = Path::new(
		"tests/fixtures/interactive/scripts/child_streams_guard.rgh",
	);
	let binary = assert_cmd::cargo::cargo_bin!("rgh");
	let output = Command::new(binary)
		.args([
			"console",
			"--color",
			"always",
			"--ignore-errors",
			"--script",
			script_path.to_str().unwrap(),
		])
		.output()
		.expect("run console script with forced color");
	assert!(output.status.success());
	let stdout =
		String::from_utf8(output.stdout).expect("stdout utf8");
	let stderr =
		String::from_utf8(output.stderr).expect("stderr utf8");
	let digest_line = stdout
		.lines()
		.find(|line| {
			let mut parts = line.split_whitespace();
			if let Some(token) = parts.next() {
				token.len() == 64
					&& token.chars().all(|c| c.is_ascii_hexdigit())
			} else {
				false
			}
		})
		.expect("digest output line");
	assert!(
		!digest_line.contains('\u{1b}'),
		"child stdout must not include ANSI escapes: {digest_line}",
	);
	let error_line = stderr
		.lines()
		.find(|line| line.contains("error"))
		.expect("child stderr line");
	assert!(
		!error_line.contains('\u{1b}'),
		"child stderr must not include ANSI escapes: {error_line}",
	);
}

#[test]
fn console_color_auto_fixture_matches() {
	let script_path = Path::new(
		"tests/fixtures/interactive/scripts/color_auto.rgh",
	);
	let expected = fs::read_to_string(
		"tests/fixtures/interactive/console_color_auto.txt",
	)
	.expect("read color auto fixture");
	let binary = assert_cmd::cargo::cargo_bin!("rgh");
	let output = Command::new(binary)
		.env("TERM", "xterm-256color")
		.env("COLORTERM", "truecolor")
		.env_remove("NO_COLOR")
		.args([
			"console",
			"--color",
			"always",
			"--script",
			script_path.to_str().unwrap(),
		])
		.output()
		.expect("run console color auto script");
	assert!(output.status.success());
	let stdout =
		String::from_utf8(output.stdout).expect("stdout utf8");
	assert_eq!(stdout, expected);
	assert!(stdout.contains('\u{1b}'));
}

#[test]
fn console_color_forced_fixture_matches() {
	let script_path = Path::new(
		"tests/fixtures/interactive/scripts/color_always.rgh",
	);
	let expected = fs::read_to_string(
		"tests/fixtures/interactive/console_color_forced.txt",
	)
	.expect("read color forced fixture");
	let binary = assert_cmd::cargo::cargo_bin!("rgh");
	let output = Command::new(binary)
		.env("TERM", "xterm-256color")
		.env("COLORTERM", "truecolor")
		.env_remove("NO_COLOR")
		.args([
			"console",
			"--color",
			"always",
			"--script",
			script_path.to_str().unwrap(),
		])
		.output()
		.expect("run console color forced script");
	assert!(output.status.success());
	let stdout =
		String::from_utf8(output.stdout).expect("stdout utf8");
	assert_eq!(stdout, expected);
	assert!(stdout.contains('\u{1b}'));
	assert!(stdout.contains("high-contrast palette enabled"));
	assert!(stdout.contains("$alpha = 644a****"));
}

#[test]
fn console_color_disabled_fixture_matches() {
	let script_path = Path::new(
		"tests/fixtures/interactive/scripts/color_never.rgh",
	);
	let expected = fs::read_to_string(
		"tests/fixtures/interactive/console_color_disabled.txt",
	)
	.expect("read color disabled fixture");
	let binary = assert_cmd::cargo::cargo_bin!("rgh");
	let output = Command::new(binary)
		.env("TERM", "xterm-256color")
		.env("COLORTERM", "truecolor")
		.env("NO_COLOR", "1")
		.args(["console", "--script", script_path.to_str().unwrap()])
		.output()
		.expect("run console color disabled script");
	assert!(output.status.success());
	let stdout =
		String::from_utf8(output.stdout).expect("stdout utf8");
	assert_eq!(stdout, expected);
	assert!(
		!stdout.contains('\u{1b}'),
		"disabled fixture must remain monochrome",
	);
	assert!(stdout.contains("NO_COLOR is set"));
}
