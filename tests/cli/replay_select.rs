use std::io::Write;
use std::process::Command;
use tempfile::NamedTempFile;

#[test]
fn replay_command_by_index_and_history_shortcut() {
	let mut script = NamedTempFile::new().expect("script temp file");
	writeln!(
        &mut script,
        "digest string -a sha256 alpha\ndigest string -a sha256 beta\nreplay 1\n!2\nreplay 42\nshow history\n"
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
		stdout.contains("replay #1: digest string -a sha256 alpha"),
		"replay preview missing:\n{}",
		stdout
	);
	assert!(
		stdout.contains("edit prompts unavailable in script mode")
	);
	let alpha_digest =
        "8ed3f6ad685b959ead7022518e1af76cd816f8e8ec7ccdda1ed4018e8f2223f8 alpha";
	assert!(
		stdout.matches(alpha_digest).count() >= 2,
		"alpha digest did not re-run:\n{}",
		stdout
	);
	assert!(stdout.contains("history index 42 is out of range"));
}
