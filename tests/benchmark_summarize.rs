// SPDX-License-Identifier: MIT OR Apache-2.0
// Project: rustgenhash

use assert_cmd::cargo::cargo_bin_cmd;
use serde_json::json;
use std::fs;
use std::path::Path;

fn write_summary_fixture(path: &Path) {
	if let Some(parent) = path.parent() {
		fs::create_dir_all(parent).expect("create benchmark dir");
	}
	let payload = json!({
		"scenario": {
			"mode": "mac",
			"algorithms": ["poly1305", "hmac-sha256"],
			"duration_seconds": 5,
			"iterations": 40,
			"profiles": {},
			"output_path": "target/benchmark/mac-fixture.json",
			"stdin_required": false,
			"created_at": "2025-11-10T12:00:00Z"
		},
		"cases": [
			{
				"algorithm": "poly1305",
				"profile": null,
				"samples_collected": 35,
				"avg_ops_per_sec": 4123.77,
				"median_latency_ms": 0.24,
				"p95_latency_ms": 0.31,
				"compliance": true,
				"warnings": [],
				"notes": "payload 1KiB"
			},
			{
				"algorithm": "hmac-sha256",
				"profile": null,
				"samples_collected": 12,
				"avg_ops_per_sec": 1987.44,
				"median_latency_ms": 0.58,
				"p95_latency_ms": 0.73,
				"compliance": false,
				"warnings": ["Only 12 samples collected (< 30 target)"] ,
				"notes": "warning: increase duration"
			}
		],
		"environment": {
			"hostname": "ci",
			"os": "linux",
			"cpu": "amd64",
			"tool_version": "0.11.0"
		},
		"runtime_planned_seconds": 5.0,
		"runtime_planned_iterations": 40,
		"runtime_actual_seconds": 5.3
	});
	fs::write(path, serde_json::to_string_pretty(&payload).unwrap())
		.expect("write summary fixture");
}

#[test]
fn markdown_summary_table_emits_expected_rows() {
	let output_path =
		Path::new("target/benchmark/summary-fixture.json");
	write_summary_fixture(output_path);

	let assert = cargo_bin_cmd!("rgh")
		.args([
			"benchmark",
			"summarize",
			"--input",
			output_path.to_str().unwrap(),
			"--format",
			"markdown",
		])
		.assert()
		.success();

	let stdout =
		String::from_utf8(assert.get_output().stdout.clone())
			.expect("stdout utf8");
	assert!(stdout.contains("> === Benchmark Summary: MAC ==="));
	assert!(stdout.contains("> Planned 5.0s · Actual 5.3s"));
	assert!(stdout.contains("Ops/sec (kops)"));
	assert!(stdout.contains("kops/s"));
	assert!(stdout.contains(" ms"));
	assert!(stdout.contains("| Algorithm |"));
	assert!(stdout.contains("poly1305"));
	assert!(stdout.contains("hmac-sha256"));
	assert!(stdout.contains("✅ PASS"));
	assert!(stdout.contains("⚠ WARN"));
}

#[test]
fn console_summary_emits_banner_before_metadata() {
	let output_path =
		Path::new("target/benchmark/summary-console.json");
	write_summary_fixture(output_path);

	let assert = cargo_bin_cmd!("rgh")
		.args([
			"benchmark",
			"summarize",
			"--input",
			output_path.to_str().unwrap(),
		])
		.assert()
		.success();
	let stdout =
		String::from_utf8(assert.get_output().stdout.clone())
			.expect("stdout utf8");
	assert!(stdout.contains("=== Benchmark Summary: MAC ==="));
	assert!(
		stdout.contains("Benchmark summary from"),
		"metadata block should remain after the banner"
	);
	assert!(stdout.contains("Planned 5.0s · Actual 5.3s"));
	assert!(stdout.contains("Ops/sec (kops)"));
	assert!(stdout.contains("kops/s"));
	assert!(stdout.contains(" ms"));
}
