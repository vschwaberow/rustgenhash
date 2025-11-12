use assert_cmd::prelude::*;
use std::fs;
use std::io::Write;
use std::process::Command;
use tempfile::{tempdir, NamedTempFile};

#[test]
fn persisted_history_requires_secret_reentry_and_exports_csv() {
	let dir = tempdir().expect("tempdir");
	let history_path = dir.path().join("console-history.json");
	let export_path = dir.path().join("history.csv");

	let mut seed = NamedTempFile::new().expect("seed script");
	writeln!(&mut seed, "digest string -a sha256 \"royal secret\"")
		.expect("write seed script");

	let binary = assert_cmd::cargo::cargo_bin!("rgh");
	Command::new(binary.as_os_str())
		.args([
			"console",
			"--script",
			seed.path().to_str().unwrap(),
			"--history-file",
			history_path.to_str().unwrap(),
			"--history-retention",
			"sanitized",
			"--force-script-history",
		])
		.assert()
		.success();

	let mut replay = NamedTempFile::new().expect("replay script");
	writeln!(
		&mut replay,
		"replay 1\nhistory --export csv {}\nshow history\n",
		export_path.display()
	)
	.expect("write replay script");

	let output = Command::new(binary.as_os_str())
		.args([
			"console",
			"--script",
			replay.path().to_str().unwrap(),
			"--history-file",
			history_path.to_str().unwrap(),
			"--history-retention",
			"sanitized",
			"--force-script-history",
		])
		.output()
		.expect("run replay script");

	assert!(
		output.status.success(),
		"console replay run failed: {:?}",
		output
	);
	let stdout = String::from_utf8_lossy(&output.stdout);
	assert!(
		stdout.contains(
			"replay #1: digest string -a sha256 \"******\""
		),
		"sanitized replay preview missing:\n{}",
		stdout
	);
	assert!(
        stdout
            .contains("replay aborted: redacted literals require interactive input"),
        "redaction warning missing:\n{}",
        stdout
    );
	assert!(
		stdout.contains("[P]"),
		"persisted indicator missing:\n{}",
		stdout
	);

	let csv = fs::read_to_string(&export_path)
		.expect("history export csv readable");
	assert!(
		csv.contains("\"******\""),
		"export should contain sanitized placeholder:\n{}",
		csv
	);
}
