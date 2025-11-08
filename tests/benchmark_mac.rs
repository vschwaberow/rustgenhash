// SPDX-License-Identifier: MIT OR Apache-2.0
// Project: rustgenhash

use assert_cmd::cargo::cargo_bin_cmd;
use serde_json::Value;
use std::fs;
use std::path::Path;

#[test]
fn mac_benchmark_prints_table_and_writes_json() {
	let output_path =
		Path::new("target/benchmark/mac-integration.json");
	if let Some(parent) = output_path.parent() {
		fs::create_dir_all(parent).expect("create benchmark dir");
	}
	let _ = fs::remove_file(output_path);

	let mut cmd = cargo_bin_cmd!("rgh");
	let assert = cmd
		.args([
			"benchmark",
			"mac",
			"--alg",
			"poly1305",
			"--alg",
			"hmac-sha256",
			"--iterations",
			"40",
			"--message-bytes",
			"256",
			"--output",
			output_path.to_str().unwrap(),
			"--yes",
		])
		.assert()
		.success();

	let stdout =
		String::from_utf8(assert.get_output().stdout.clone())
			.expect("stdout utf8");
	assert!(stdout.contains("=== MAC Benchmarks (duration"));
	assert!(stdout.contains("payload 256 bytes"));
	assert!(stdout.contains("Algorithm"));
	assert!(stdout.contains("poly1305"));
	assert!(stdout.contains("hmac-sha256"));
	assert!(stdout.contains(output_path.to_str().unwrap()));

	let json_str = fs::read_to_string(output_path)
		.expect("benchmark json written");
	let payload: Value =
		serde_json::from_str(&json_str).expect("json payload");
	assert_eq!(payload["scenario"]["mode"], "mac");
	let cases = payload["cases"].as_array().expect("cases array");
	assert_eq!(cases.len(), 2);
	let mut algorithms = cases
		.iter()
		.map(|case| case["algorithm"].as_str().unwrap().to_string())
		.collect::<Vec<_>>();
	algorithms.sort();
	assert_eq!(
		algorithms,
		vec!["hmac-sha256".to_string(), "poly1305".to_string()]
	);
	for case in cases {
		let ops = case["avg_ops_per_sec"].as_f64().unwrap();
		assert!(ops > 0.0);
		let samples = case["samples_collected"].as_u64().unwrap();
		assert!(samples >= 1);
	}

	let json_only_path =
		Path::new("target/benchmark/mac-stdout.json");
	let _ = fs::remove_file(json_only_path);
	let mut json_cmd = cargo_bin_cmd!("rgh");
	let json_assert = json_cmd
		.args([
			"benchmark",
			"mac",
			"--alg",
			"poly1305",
			"--iterations",
			"5",
			"--json",
			"--output",
			json_only_path.to_str().unwrap(),
			"--yes",
		])
		.assert()
		.success();
	let json_stdout =
		String::from_utf8(json_assert.get_output().stdout.clone())
			.expect("stdout utf8");
	assert!(
		!json_stdout.contains("=== MAC Benchmarks"),
		"json flag must suppress banner"
	);
}
