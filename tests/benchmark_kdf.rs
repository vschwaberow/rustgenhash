// SPDX-License-Identifier: MIT OR Apache-2.0
// Project: rustgenhash

use assert_cmd::cargo::cargo_bin_cmd;
use serde_json::Value;
use std::fs;
use std::path::Path;

#[test]
fn kdf_benchmark_emits_json_with_profiles() {
	let output_path =
		Path::new("target/benchmark/kdf-integration.json");
	if let Some(parent) = output_path.parent() {
		fs::create_dir_all(parent).expect("create benchmark dir");
	}
	let _ = fs::remove_file(output_path);

	let mut cmd = cargo_bin_cmd!("rgh");
	let assert = cmd
		.args([
			"benchmark",
			"kdf",
			"--alg",
			"pbkdf2",
			"--alg",
			"scrypt",
			"--profile",
			"pbkdf2=nist-sp800-132-2023",
			"--profile",
			"scrypt=owasp-2024",
			"--iterations",
			"5",
			"--json",
			"--output",
			output_path.to_str().unwrap(),
			"--yes",
		])
		.assert()
		.success();

	let stdout =
		String::from_utf8(assert.get_output().stdout.clone())
			.expect("stdout utf8");
	assert!(stdout.contains(output_path.to_str().unwrap()));

	let json_str = fs::read_to_string(output_path)
		.expect("kdf benchmark json written");
	let payload: Value =
		serde_json::from_str(&json_str).expect("json payload");
	assert_eq!(payload["scenario"]["mode"], "kdf");
	assert!(payload["runtime_actual_seconds"].as_f64().is_some());
	let cases = payload["cases"].as_array().expect("cases array");
	assert_eq!(cases.len(), 2);
	for case in cases {
		assert!(case["median_latency_ms"].as_f64().unwrap() > 0.0);
		assert!(case["samples_collected"].as_u64().unwrap() >= 1);
		assert!(case["profile"].is_string());
	}

	let mut console_cmd = cargo_bin_cmd!("rgh");
	let console_assert = console_cmd
		.args([
			"benchmark",
			"kdf",
			"--alg",
			"pbkdf2",
			"--profile",
			"pbkdf2=nist-sp800-132-2023",
			"--duration",
			"3s",
			"--yes",
		])
		.assert()
		.success();
	let console_stdout =
		String::from_utf8(console_assert.get_output().stdout.clone())
			.expect("stdout utf8");
	assert!(
		console_stdout.contains("=== KDF Benchmarks (duration 3s")
	);
	assert!(console_stdout.contains("iterations auto"));
	assert!(console_stdout.contains("Planned"));
	assert!(console_stdout.contains("Actual"));
	assert!(console_stdout.contains("Ops/sec (kops)"));
	assert!(console_stdout.contains("kops/s"));
	assert!(console_stdout.contains(" ms"));
	assert!(console_stdout.contains("\nWarnings"));
	assert!(
		console_stdout.contains("- pbkdf2-sha256: Only"),
		"Warnings block must enumerate algorithms"
	);
	assert!(
		!console_stdout.contains("    warning:"),
		"Inline warning rows should be removed"
	);

	let json_stdout =
		String::from_utf8(assert.get_output().stdout.clone())
			.expect("stdout utf8");
	assert!(
		!json_stdout.contains("=== KDF Benchmarks"),
		"json flag must suppress banner"
	);
	assert!(
		!json_stdout.contains("kops/s"),
		"json flag must keep throughput numeric"
	);
	assert!(
		!json_stdout.contains("Planned"),
		"json flag must suppress runtime banner"
	);
	assert!(
		!json_stdout.contains(" ms"),
		"json flag must keep latency numeric"
	);
	assert!(
		!json_stdout.contains("Warnings"),
		"json mode must not print post-table warnings"
	);
}
