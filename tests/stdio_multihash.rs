// SPDX-License-Identifier: MIT OR Apache-2.0
use assert_cmd::Command;

fn make_input(lines: usize) -> String {
	let mut data = String::new();
	for idx in 0..lines {
		data.push_str(&format!("line-{idx}\n"));
	}
	data
}

#[test]
#[allow(deprecated)]
fn multihash_stdio_streams_without_buffering() {
	let data = make_input(1000);
	let mut cmd =
		Command::cargo_bin("rgh").expect("binary rgh available");
	cmd.arg("digest")
		.arg("stdio")
		.arg("-a")
		.arg("sha256")
		.arg("--format")
		.arg("multihash")
		.arg("--hash-only");
	let assert = cmd.write_stdin(data).assert().success();
	let stdout =
		String::from_utf8(assert.get_output().stdout.clone())
			.expect("stdout should be UTF-8");
	let lines: Vec<&str> = stdout.lines().collect();
	assert_eq!(lines.len(), 1000);
	assert!(lines
		.iter()
		.all(|line| line.starts_with('z') && !line.contains(' ')));
}
