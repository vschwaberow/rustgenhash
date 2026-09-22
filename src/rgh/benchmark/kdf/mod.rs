// SPDX-License-Identifier: MIT OR Apache-2.0
// Project: rustgenhash

mod common;
mod hkdf;
mod pbkdf2;
mod scrypt;

use self::common::{
	lookup_pbkdf2_profile, lookup_scrypt_profile, KdfAlgorithm,
	PBKDF2_VARIANTS,
};
use self::hkdf::run_hkdf;
use self::pbkdf2::run_pbkdf2;
use self::scrypt::run_scrypt;
use super::warnings::{
	section_for_cases, WarningRenderStyle, WarningSource,
};
use super::{
	format_benchmark_banner, format_metric, runtime_banner_line,
	BenchmarkBannerContext, BenchmarkError, BenchmarkResult,
	BenchmarkScenario, BenchmarkSummary, MetricKind,
	SharedBenchmarkArgs,
};
use crate::rgh::kdf::hkdf::HKDF_VARIANTS;
use std::cmp::Ordering;
use std::collections::BTreeMap;
use std::time::{Duration, Instant};

pub fn supported_algorithms() -> Vec<String> {
	let mut entries =
		vec!["pbkdf2", "pbkdf2-sha256", "pbkdf2-sha512", "scrypt"];
	entries.extend(
		HKDF_VARIANTS
			.iter()
			.map(|variant| variant.identifier())
			.collect::<Vec<_>>(),
	);
	entries.sort();
	entries.into_iter().map(|s| s.to_string()).collect()
}

pub fn canonical_algorithm_id(
	raw: &str,
) -> Result<String, BenchmarkError> {
	let (_, canonical) = common::parse_algorithm(raw)?;
	Ok(canonical)
}

pub fn algorithm_requires_profile(
	raw: &str,
) -> Result<bool, BenchmarkError> {
	let (alg, _) = common::parse_algorithm(raw)?;
	Ok(alg.requires_profile())
}

pub fn run_kdf_benchmarks(
	mut scenario: BenchmarkScenario,
	shared: &SharedBenchmarkArgs,
) -> Result<BenchmarkSummary, BenchmarkError> {
	let wall_start = Instant::now();
	let mut cases = Vec::with_capacity(scenario.algorithms.len());
	let mut canonical_algorithms =
		Vec::with_capacity(scenario.algorithms.len());
	let mut normalized_profiles = BTreeMap::new();
	for (key, value) in &scenario.profiles {
		let canonical = canonical_algorithm_id(key)?;
		normalized_profiles.insert(canonical, value.clone());
	}
	let target_duration =
		Duration::from_secs(scenario.duration_seconds.max(1));

	for identifier in &scenario.algorithms {
		let (alg, canonical) = common::parse_algorithm(identifier)?;
		let result = match alg {
			KdfAlgorithm::Pbkdf2Sha256 => run_pbkdf2(
				PBKDF2_VARIANTS[0],
				&lookup_pbkdf2_profile(
					&canonical,
					&normalized_profiles,
				)?,
				shared,
				target_duration,
			)?,
			KdfAlgorithm::Pbkdf2Sha512 => run_pbkdf2(
				PBKDF2_VARIANTS[1],
				&lookup_pbkdf2_profile(
					&canonical,
					&normalized_profiles,
				)?,
				shared,
				target_duration,
			)?,
			KdfAlgorithm::Scrypt => run_scrypt(
				&lookup_scrypt_profile(
					&canonical,
					&normalized_profiles,
				)?,
				shared,
				target_duration,
			)?,
			KdfAlgorithm::Hkdf(variant) => {
				run_hkdf(variant, shared, target_duration)?
			}
		};
		canonical_algorithms.push(result.algorithm.clone());
		cases.push(result);
	}

	scenario.algorithms = canonical_algorithms;
	scenario.profiles = normalized_profiles;
	let planned_seconds = if scenario.iterations.is_none() {
		Some(scenario.duration_seconds as f64)
	} else {
		None
	};
	let planned_iterations = scenario.iterations;
	let mut summary = BenchmarkSummary::new(scenario, cases)?;
	let actual_seconds = Some(wall_start.elapsed().as_secs_f64());
	summary.set_runtime_metadata(
		planned_seconds,
		planned_iterations,
		actual_seconds,
	);
	Ok(summary)
}

pub fn print_kdf_report(summary: &BenchmarkSummary) {
	let context =
		BenchmarkBannerContext::from_scenario(&summary.scenario);
	println!();
	println!("{}", format_benchmark_banner(&context));
	println!("{}", runtime_banner_line(summary));
	println!(
		"{:<18} {:>10} {:>18} {:>14} {:>8}  Notes",
		"Algorithm",
		"Samples",
		"Ops/sec (kops)",
		"Median ms / P95 ms",
		"Status",
	);
	println!("{}", "-".repeat(106));
	let mut rows: Vec<&BenchmarkResult> =
		summary.cases.iter().collect();
	rows.sort_by(|a, b| {
		a.median_latency_ms
			.partial_cmp(&b.median_latency_ms)
			.unwrap_or(Ordering::Equal)
	});
	for case in rows {
		let status = if case.compliance { "PASS" } else { "WARN" };
		let throughput = format_metric(
			case.avg_ops_per_sec,
			MetricKind::Throughput,
		);
		let median = format_metric(
			case.median_latency_ms,
			MetricKind::Latency,
		);
		let p95 =
			format_metric(case.p95_latency_ms, MetricKind::Latency);
		println!(
			"{:<18} {:>10} {:>18} {:>14} {:>8}  {}",
			case.algorithm,
			case.samples_collected,
			throughput,
			format!("{}/{}", median, p95),
			status,
			case.notes.as_deref().unwrap_or("-"),
		);
	}
	let warnings_section = section_for_cases(
		&summary.cases,
		WarningRenderStyle::Console,
		"KDF Benchmark Run",
		WarningSource::Kdf,
	);
	if !warnings_section.is_empty() {
		println!();
		println!("{}", warnings_section.heading());
		for line in warnings_section.render_lines() {
			println!("{}", line);
		}
	}
}

