use std::io::Write;
use std::process::Command;
use tempfile::NamedTempFile;

#[test]
fn bang_bang_replays_most_recent_command() {
	let mut script = NamedTempFile::new().expect("script temp file");
	writeln!(
		&mut script,
		"digest string -a sha256 foo\n!!\nshow history\n"
	)
	.expect("write script");

	let binary = assert_cmd::cargo::cargo_bin!("rgh");
	let output = Command::new(binary)
		.args([
			"console",
			"--script",
			script.path().to_str().unwrap(),
		])
		.output()
		.expect("run console script");
	assert!(
		output.status.success(),
		"console run failed: {:?}",
		output
	);

	let stdout = String::from_utf8_lossy(&output.stdout);
	assert!(
		stdout.contains("replaying last command"),
		"replay banner missing:\n{}",
		stdout
	);
	let digest =
        "2c26b46b68ffc68ff99b453c1d30413413422d706483bfa0f98a5e886266e7ae foo";
	let digest_hits = stdout.matches(digest).count();
	assert!(
		digest_hits >= 2,
		"expected digest to appear twice, found {} hits in:\n{}",
		digest_hits,
		stdout
	);
}
