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
use serde_json::Value as JsonValue;
use serde_yaml::Value as YamlValue;
use std::fs;
use std::io::Write;
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

#[test]
fn console_history_persist_fixture_matches() {
	let history_dir = tempfile::tempdir().expect("tempdir");
	let history_file = history_dir.path().join("history.json");
	let history_str = history_file.to_str().expect("history path");
	let seed_script = Path::new(
		"tests/fixtures/interactive/scripts/console_history_seed.rgh",
	);
	let expected_seed = fs::read_to_string(
		"tests/fixtures/interactive/console_history_seed.txt",
	)
	.expect("read history seed fixture");
	let binary = assert_cmd::cargo::cargo_bin!("rgh");
	let output = Command::new(&binary)
		.args([
			"console",
			"--color",
			"never",
			"--history-file",
			history_str,
			"--history-retention",
			"sanitized",
			"--force-script-history",
			"--script",
			seed_script.to_str().unwrap(),
		])
		.output()
		.expect("run console history seed script");
	assert!(output.status.success());
	let stdout =
		String::from_utf8(output.stdout).expect("stdout utf8");
	assert_eq!(stdout, expected_seed);

	let show_script = Path::new(
		"tests/fixtures/interactive/scripts/console_history_show.rgh",
	);
	let expected_show = fs::read_to_string(
		"tests/fixtures/interactive/console_history_show.txt",
	)
	.expect("read history show fixture");
	let output2 = Command::new(&binary)
		.args([
			"console",
			"--color",
			"never",
			"--history-file",
			history_str,
			"--history-retention",
			"sanitized",
			"--force-script-history",
			"--script",
			show_script.to_str().unwrap(),
		])
		.output()
		.expect("run console history show script");
	assert!(output2.status.success());
	let stdout2 =
		String::from_utf8(output2.stdout).expect("stdout utf8");
	assert_eq!(stdout2, expected_show);
}

#[test]
fn console_history_manual_builtins_work() {
	let history_dir = tempfile::tempdir().expect("history tempdir");
	let history_file = history_dir.path().join("manual.json");
	let script_source = format!(
		"digest string --algorithm blake3 \"beta\"\n\
history save \"{path}\"\n\
history clear\n\
history load \"{path}\"\n\
show history\n\
exit\n",
		path = history_file.display()
	);
	let mut script_file =
		NamedTempFile::new().expect("script temp file");
	script_file
		.write_all(script_source.as_bytes())
		.expect("write script");

	let binary = assert_cmd::cargo::cargo_bin!("rgh");
	let output = Command::new(&binary)
		.args([
			"console",
			"--color",
			"never",
			"--force-script-history",
			"--script",
			script_file.path().to_str().unwrap(),
		])
		.output()
		.expect("run console manual history script");
	assert!(
		output.status.success(),
		"stdout: {}\nstderr: {}",
		String::from_utf8_lossy(&output.stdout),
		String::from_utf8_lossy(&output.stderr)
	);
	let stdout =
		String::from_utf8(output.stdout).expect("stdout utf8");
	assert!(
		stdout.contains("saved history to"),
		"expected save confirmation"
	);
	assert!(
		stdout.contains("history cleared"),
		"expected clear confirmation"
	);
	assert!(
		stdout.contains("loaded 1 history entries"),
		"expected load confirmation"
	);
	assert!(
		stdout
			.contains("digest string --algorithm blake3 \"******\""),
		"history show should redact sensitive argument"
	);
	assert!(
		history_file.exists(),
		"manual history file should be created"
	);
}

#[test]
fn console_vars_export_json_masked_manifest_matches() {
	let manifest = NamedTempFile::new().expect("manifest temp file");
	let script_source = format!(
		"set $alpha = digest string --algorithm blake3 \"alpha\"\n\
export vars \"{path}\"\n\
exit\n",
		path = manifest.path().display()
	);
	let mut script_file =
		NamedTempFile::new().expect("script temp file");
	script_file
		.write_all(script_source.as_bytes())
		.expect("write script");
	let binary = assert_cmd::cargo::cargo_bin!("rgh");
	let output = Command::new(&binary)
		.args([
			"console",
			"--color",
			"never",
			"--script",
			script_file.path().to_str().unwrap(),
		])
		.output()
		.expect("run console export vars script");
	assert!(output.status.success());
	let stdout =
		String::from_utf8(output.stdout).expect("stdout utf8");
	assert!(
		stdout.contains("wrote 1 variables"),
		"expected success message"
	);
	let data =
		fs::read_to_string(manifest.path()).expect("read manifest");
	let manifest_json: JsonValue =
		serde_json::from_str(&data).expect("parse json manifest");
	assert!(!manifest_json["includes_secrets"]
		.as_bool()
		.unwrap_or(true));
	let records =
		manifest_json["records"].as_array().expect("records array");
	assert_eq!(records.len(), 1);
	let record = &records[0];
	assert!(record["preview"]
		.as_str()
		.unwrap_or("")
		.contains("****"));
	assert!(record["value"].is_null());
}

#[test]
fn console_vars_export_yaml_with_secrets_matches() {
	let manifest = NamedTempFile::new().expect("manifest temp file");
	let script_source = format!(
		"set $alpha = digest string --algorithm blake3 \"alpha\"\n\
export vars \"{path}\" --format yaml --include-secrets --yes\n\
exit\n",
		path = manifest.path().display()
	);
	let mut script_file =
		NamedTempFile::new().expect("script temp file");
	script_file
		.write_all(script_source.as_bytes())
		.expect("write script");
	let binary = assert_cmd::cargo::cargo_bin!("rgh");
	let output = Command::new(&binary)
		.args([
			"console",
			"--color",
			"never",
			"--script",
			script_file.path().to_str().unwrap(),
		])
		.output()
		.expect("run console export vars yaml script");
	assert!(output.status.success());
	let stdout =
		String::from_utf8(output.stdout).expect("stdout utf8");
	assert!(
		stdout.contains("includes secrets"),
		"expected secrets warning"
	);
	let data =
		fs::read_to_string(manifest.path()).expect("read manifest");
	let manifest_yaml: YamlValue =
		serde_yaml::from_str(&data).expect("parse yaml manifest");
	assert_eq!(
		manifest_yaml
			.get("includes_secrets")
			.and_then(YamlValue::as_bool),
		Some(true)
	);
	let records = manifest_yaml
		.get("records")
		.and_then(YamlValue::as_sequence)
		.expect("records sequence");
	assert_eq!(records.len(), 1);
	let record = &records[0];
	assert_eq!(
		record
			.get("value")
			.and_then(YamlValue::as_str)
			.unwrap_or(""),
		"644a9bc57c6063e2ba4028fa73ed585170ae7db8ac7723d32be49c021a0225f5"
	);
}
