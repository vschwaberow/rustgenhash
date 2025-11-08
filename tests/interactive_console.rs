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
