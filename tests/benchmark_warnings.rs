// SPDX-License-Identifier: MIT OR Apache-2.0

use rustgenhash::rgh::benchmark::warnings::{
	section_for_cases, section_for_summary, WarningRenderStyle,
	WarningSource,
};
use rustgenhash::rgh::benchmark::{
	BenchmarkMode, BenchmarkResult, BenchmarkScenario,
	BenchmarkSummary,
};

fn build_case(algorithm: &str, warnings: &[&str]) -> BenchmarkResult {
	BenchmarkResult {
		algorithm: algorithm.to_string(),
		profile: None,
		samples_collected: 10,
		avg_ops_per_sec: 1.0,
		median_latency_ms: 1.0,
		p95_latency_ms: 1.0,
		compliance: warnings.is_empty(),
		warnings: warnings.iter().map(|w| w.to_string()).collect(),
		notes: Some("test-case".into()),
	}
}

#[test]
fn deduplicates_by_algorithm_and_preserves_order() {
	let cases = vec![
		build_case(
			"hmac-sha1",
			&[
				"legacy warning",
				"Only 10 samples collected (< 30 target)",
			],
		),
		build_case("blake3", &[]),
		build_case(
			"hmac-sha1",
			&[
				"legacy warning",
				"Median latency 5.10 ms exceeds 4.00 ms guidance",
			],
		),
	];
	let section = section_for_cases(
		&cases,
		WarningRenderStyle::Console,
		"MAC Benchmark Run",
		WarningSource::Mac,
	);
	assert!(!section.is_empty());
	assert_eq!("Warnings", section.heading());
	assert_eq!(1, section.items().len());
	let descriptor = &section.items()[0];
	assert_eq!("hmac-sha1", descriptor.algorithm_id);
	assert_eq!(3, descriptor.messages.len());
	let lines = section.render_lines();
	assert_eq!(1, lines.len());
	assert_eq!(
		"- hmac-sha1: legacy warning; Only 10 samples collected (< 30 target); Median latency 5.10 ms exceeds 4.00 ms guidance",
		lines[0]
	);
}

#[test]
fn returns_empty_section_when_no_warnings() {
	let cases = vec![build_case("blake3", &[])];
	let section = section_for_cases(
		&cases,
		WarningRenderStyle::Console,
		"MAC Benchmark Run",
		WarningSource::Mac,
	);
	assert!(section.is_empty());
	assert!(section.render_lines().is_empty());
}

#[test]
fn summary_section_uses_summary_cases() {
	let scenario = BenchmarkScenario::new(
		BenchmarkMode::Mac,
		vec!["hmac-sha1".into()],
		5,
		None,
		None,
		false,
	)
	.expect("scenario");
	let summary = BenchmarkSummary::new(
		scenario,
		vec![build_case("hmac-sha1", &["legacy warning"])],
	)
	.expect("summary");
	let section =
		section_for_summary(&summary, WarningRenderStyle::Markdown);
	assert_eq!("### Warnings", section.heading());
	assert_eq!(WarningRenderStyle::Markdown, section.render_style());
	assert_eq!(1, section.render_lines().len());
}
