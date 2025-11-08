// SPDX-License-Identifier: MIT OR Apache-2.0
// Project: rustgenhash
// File: benchmark/mac.rs
// Author: Volker Schwaberow <volker@schwaberow.de>

use super::{
	format_benchmark_banner, BenchmarkBannerContext, BenchmarkError,
	BenchmarkResult, BenchmarkScenario, BenchmarkSummary,
	SharedBenchmarkArgs, DEFAULT_MAC_MESSAGE_BYTES,
};
use crate::rgh::mac::commands::legacy_warning_message;
use crate::rgh::mac::executor::consume_bytes;
use crate::rgh::mac::registry::{self, MacAlgorithm, MacError};
use std::cmp::Ordering;
use std::time::{Duration, Instant};

const MAC_SAMPLE_TARGET: u64 = 30;
const MIN_LATENCY_MS: f64 = 0.000_001;

pub fn supported_algorithms() -> Vec<String> {
	registry::metadata()
		.into_iter()
		.map(|meta| meta.identifier.to_string())
		.collect()
}

pub fn run_mac_benchmarks(
	mut scenario: BenchmarkScenario,
	shared: &SharedBenchmarkArgs,
) -> Result<BenchmarkSummary, BenchmarkError> {
	let payload_bytes =
		shared.message_bytes.unwrap_or(DEFAULT_MAC_MESSAGE_BYTES);
	let payload = build_payload(payload_bytes);
	let duration =
		Duration::from_secs(scenario.duration_seconds.max(1));

	let mut cases = Vec::with_capacity(scenario.algorithms.len());
	for identifier in &scenario.algorithms {
		let algorithm = registry::find_algorithm(identifier)
			.ok_or_else(|| {
				BenchmarkError::validation(format!(
					"unsupported MAC algorithm `{}`",
					identifier
				))
			})?;
		let result = benchmark_algorithm(
			algorithm,
			&payload,
			duration,
			shared.iterations,
		)?;
		cases.push(result);
	}

	scenario.algorithms =
		cases.iter().map(|case| case.algorithm.clone()).collect();

	BenchmarkSummary::new(scenario, cases)
}

pub fn print_mac_report(
	summary: &BenchmarkSummary,
	payload_bytes: usize,
) {
	let context =
		BenchmarkBannerContext::from_scenario(&summary.scenario)
			.with_payload_bytes(Some(payload_bytes));
	println!();
	println!("{}", format_benchmark_banner(&context));
	println!(
		"{:<16} {:>10} {:>14} {:>12} {:>12} {:>8}  Notes",
		"Algorithm",
		"Samples",
		"Ops/sec",
		"Median ms",
		"P95 ms",
		"Status"
	);
	println!("{}", "-".repeat(96));
	let mut rows: Vec<&BenchmarkResult> =
		summary.cases.iter().collect();
	rows.sort_by(|a, b| {
		b.avg_ops_per_sec
			.partial_cmp(&a.avg_ops_per_sec)
			.unwrap_or(Ordering::Equal)
	});
	for case in rows {
		let status = if case.compliance { "PASS" } else { "WARN" };
		println!(
			"{:<16} {:>10} {:>14.2} {:>12.3} {:>12.3} {:>8}  {}",
			case.algorithm,
			case.samples_collected,
			case.avg_ops_per_sec,
			case.median_latency_ms,
			case.p95_latency_ms,
			status,
			case.notes.as_deref().unwrap_or("-"),
		);
		for warning in &case.warnings {
			println!("    warning: {}", warning);
		}
	}
}

fn benchmark_algorithm(
	algorithm: &MacAlgorithm,
	payload: &[u8],
	target_duration: Duration,
	iterations_override: Option<u64>,
) -> Result<BenchmarkResult, BenchmarkError> {
	let metadata = algorithm.metadata;
	let key = synthetic_key_for(metadata.identifier);
	let mut samples = 0u64;
	let mut latencies_ms = Vec::new();
	let run_start = Instant::now();

	while should_continue(
		samples,
		target_duration,
		iterations_override,
		&run_start,
	) {
		let iter_start = Instant::now();
		let executor = (algorithm.factory)(&key)
			.map_err(|err| map_mac_error(metadata.identifier, err))?;
		consume_bytes(payload, executor);
		let iter_duration = iter_start.elapsed();
		let ms = (iter_duration.as_secs_f64() * 1000.0)
			.max(MIN_LATENCY_MS);
		latencies_ms.push(ms);
		samples = samples.saturating_add(1);
	}

	if latencies_ms.is_empty() {
		return Err(BenchmarkError::validation(format!(
			"failed to record latency samples for {}",
			metadata.identifier
		)));
	}

	let run_elapsed = run_start.elapsed();
	let total_secs = run_elapsed.as_secs_f64().max(f64::EPSILON);
	let avg_ops_per_sec = samples as f64 / total_secs;
	let median = percentile(&latencies_ms, 0.5);
	let p95 = percentile(&latencies_ms, 0.95);
	let compliance = samples >= MAC_SAMPLE_TARGET;
	let mut warnings = Vec::new();
	if !compliance {
		warnings.push(format!(
			"Only {} samples collected (< {} target)",
			samples, MAC_SAMPLE_TARGET
		));
	}
	if metadata.is_legacy() {
		warnings.push(legacy_warning_message(&metadata));
	}
	let notes = format!(
		"{} samples across {:.2}s; target {} samples",
		samples,
		run_elapsed.as_secs_f64(),
		MAC_SAMPLE_TARGET
	);

	Ok(BenchmarkResult {
		algorithm: metadata.identifier.to_string(),
		profile: None,
		samples_collected: samples,
		avg_ops_per_sec,
		median_latency_ms: median,
		p95_latency_ms: p95,
		compliance,
		warnings,
		notes: Some(notes),
	})
}

fn should_continue(
	samples: u64,
	target_duration: Duration,
	iterations_override: Option<u64>,
	run_start: &Instant,
) -> bool {
	if let Some(target) = iterations_override {
		return samples < target;
	}
	run_start.elapsed() < target_duration || samples == 0
}

fn percentile(values: &[f64], percentile: f64) -> f64 {
	if values.is_empty() {
		return MIN_LATENCY_MS;
	}
	let mut sorted = values.to_vec();
	sorted
		.sort_by(|a, b| a.partial_cmp(b).unwrap_or(Ordering::Equal));
	if sorted.len() == 1 {
		return sorted[0];
	}
	let rank =
		percentile.clamp(0.0, 1.0) * (sorted.len() as f64 - 1.0);
	let lower = rank.floor() as usize;
	let upper = rank.ceil() as usize;
	if lower == upper {
		return sorted[lower];
	}
	let weight = rank - lower as f64;
	sorted[lower] + (sorted[upper] - sorted[lower]) * weight
}

fn build_payload(len: usize) -> Vec<u8> {
	let mut payload = vec![0u8; len];
	for (idx, byte) in payload.iter_mut().enumerate() {
		*byte = ((idx * 31 + 17) & 0xFF) as u8;
	}
	payload
}

fn synthetic_key_for(identifier: &str) -> Vec<u8> {
	let lower = identifier.to_ascii_lowercase();
	let len = match lower.as_str() {
		"cmac-aes128" => 16,
		"cmac-aes192" => 24,
		"cmac-aes256" => 32,
		"poly1305" => 32,
		"blake3-keyed" => 32,
		_ => 32,
	};
	let mut key = vec![0u8; len];
	for (idx, byte) in key.iter_mut().enumerate() {
		*byte = ((idx * 19 + 113) & 0xFF) as u8;
	}
	key
}

fn map_mac_error(identifier: &str, err: MacError) -> BenchmarkError {
	BenchmarkError::validation(format!(
		"failed to initialize {} benchmark: {}",
		identifier, err
	))
}
