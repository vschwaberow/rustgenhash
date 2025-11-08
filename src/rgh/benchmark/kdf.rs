// SPDX-License-Identifier: MIT OR Apache-2.0
// Project: rustgenhash
// File: benchmark/kdf.rs
// Author: Volker Schwaberow <volker@schwaberow.de>

use super::{
	format_benchmark_banner, format_metric, BenchmarkBannerContext,
	BenchmarkError, BenchmarkResult, BenchmarkScenario,
	BenchmarkSummary, MetricKind, SharedBenchmarkArgs,
	KDF_SAMPLE_TARGET,
};
use crate::rgh::hash::{PHash, Pbkdf2Config, ScryptConfig};
use crate::rgh::kdf::hkdf::{
	self, HkdfInput as HkdfCliInput, HkdfMode, HkdfRequest,
	HkdfVariant, HKDF_VARIANTS,
};
use crate::rgh::kdf::profile::{
	get_pbkdf2_profile, get_scrypt_profile, Pbkdf2Profile,
	ScryptProfile,
};
use crate::rgh::kdf::SecretMaterial;
use scrypt::password_hash::SaltString as ScryptSaltString;
use std::cmp::Ordering;
use std::collections::BTreeMap;
use std::time::{Duration, Instant};

const PBKDF2_PASSWORD: &str = "benchmark-password";
const PBKDF2_SALT_B64: &str = "AAAAAAAAAAAAAAAAAAAAAA";
const SCRYPT_SALT_BYTES: [u8; 16] = *b"benchmark-scrypt";
const PBKDF2_MEDIAN_THRESHOLD_MS: f64 = 1500.0;
const SCRYPT_MEDIAN_THRESHOLD_MS: f64 = 2000.0;
const HKDF_DEFAULT_LENGTH: usize = 32;
const PBKDF2_ROUND_DIVISOR: u32 = 500;
const SCRYPT_LOG_N_REDUCTION: u8 = 4;

#[derive(Debug, Clone, Copy)]
enum KdfAlgorithm {
	Pbkdf2Sha256,
	Pbkdf2Sha512,
	Scrypt,
	Hkdf(HkdfVariant),
}

impl KdfAlgorithm {
	fn canonical_identifier(self) -> &'static str {
		match self {
			Self::Pbkdf2Sha256 => "pbkdf2-sha256",
			Self::Pbkdf2Sha512 => "pbkdf2-sha512",
			Self::Scrypt => "scrypt",
			Self::Hkdf(variant) => variant.identifier(),
		}
	}

	fn requires_profile(self) -> bool {
		matches!(
			self,
			KdfAlgorithm::Pbkdf2Sha256
				| KdfAlgorithm::Pbkdf2Sha512
				| KdfAlgorithm::Scrypt
		)
	}
}

#[derive(Debug, Clone, Copy)]
struct Pbkdf2Variant {
	algorithm: KdfAlgorithm,
	pbkdf2_scheme: &'static str,
}

const PBKDF2_VARIANTS: &[Pbkdf2Variant] = &[
	Pbkdf2Variant {
		algorithm: KdfAlgorithm::Pbkdf2Sha256,
		pbkdf2_scheme: "pbkdf2sha256",
	},
	Pbkdf2Variant {
		algorithm: KdfAlgorithm::Pbkdf2Sha512,
		pbkdf2_scheme: "pbkdf2sha512",
	},
];

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
	let (_, canonical) = parse_algorithm(raw)?;
	Ok(canonical)
}

pub fn algorithm_requires_profile(
	raw: &str,
) -> Result<bool, BenchmarkError> {
	let (alg, _) = parse_algorithm(raw)?;
	Ok(alg.requires_profile())
}

fn parse_algorithm(
	raw: &str,
) -> Result<(KdfAlgorithm, String), BenchmarkError> {
	let value = raw.trim().to_ascii_lowercase();
	if value.is_empty() {
		return Err(BenchmarkError::validation(
			"algorithm identifier must not be empty",
		));
	}
	if value == "pbkdf2" || value == "pbkdf2-sha256" {
		return Ok((
			KdfAlgorithm::Pbkdf2Sha256,
			"pbkdf2-sha256".into(),
		));
	}
	if value == "pbkdf2-sha512" {
		return Ok((
			KdfAlgorithm::Pbkdf2Sha512,
			"pbkdf2-sha512".into(),
		));
	}
	if value == "scrypt" {
		return Ok((KdfAlgorithm::Scrypt, "scrypt".into()));
	}
	for variant in HKDF_VARIANTS {
		if value == variant.identifier() {
			return Ok((
				KdfAlgorithm::Hkdf(*variant),
				variant.identifier().into(),
			));
		}
	}
	Err(BenchmarkError::validation(format!(
		"unsupported KDF algorithm `{}`",
		raw
	)))
}

pub fn run_kdf_benchmarks(
	mut scenario: BenchmarkScenario,
	shared: &SharedBenchmarkArgs,
) -> Result<BenchmarkSummary, BenchmarkError> {
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
		let (alg, canonical) = parse_algorithm(identifier)?;
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
	BenchmarkSummary::new(scenario, cases)
}

pub fn print_kdf_report(summary: &BenchmarkSummary) {
	let context =
		BenchmarkBannerContext::from_scenario(&summary.scenario);
	println!();
	println!("{}", format_benchmark_banner(&context));
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
		for warning in &case.warnings {
			println!("    warning: {}", warning);
		}
	}
}

fn run_pbkdf2(
	variant: Pbkdf2Variant,
	profile: &Pbkdf2Profile,
	shared: &SharedBenchmarkArgs,
	target_duration: Duration,
) -> Result<BenchmarkResult, BenchmarkError> {
	let effective_rounds =
		std::cmp::max(1, profile.rounds / PBKDF2_ROUND_DIVISOR);
	let config = Pbkdf2Config {
		rounds: effective_rounds,
		output_length: profile.output_len,
	};
	let mut samples = 0u64;
	let mut latencies = Vec::new();
	let run_start = Instant::now();
	while should_continue(
		samples,
		shared.iterations,
		target_duration,
		run_start.elapsed(),
	) {
		let iter_start = Instant::now();
		PHash::hash_pbkdf2_with_salt(
			PBKDF2_PASSWORD,
			variant.pbkdf2_scheme,
			&config,
			PBKDF2_SALT_B64,
		)
		.map_err(|err| {
			BenchmarkError::validation(format!(
				"pbkdf2 benchmark failed: {}",
				err
			))
		})?;
		latencies.push(elapsed_ms(iter_start.elapsed()));
		samples = samples.saturating_add(1);
	}
	finalize_result(
		variant.algorithm,
		samples,
		latencies,
		Some(profile.id.to_string()),
		Some(PBKDF2_MEDIAN_THRESHOLD_MS),
		format!(
			"profile {} (rounds {}, output {} bytes)",
			profile.id, profile.rounds, profile.output_len
		),
	)
}

fn run_scrypt(
	profile: &ScryptProfile,
	shared: &SharedBenchmarkArgs,
	target_duration: Duration,
) -> Result<BenchmarkResult, BenchmarkError> {
	let reduced_log_n =
		profile.log_n.saturating_sub(SCRYPT_LOG_N_REDUCTION);
	let config = ScryptConfig {
		log_n: std::cmp::max(reduced_log_n, 1),
		r: profile.r,
		p: profile.p.max(1),
	};
	let salt = ScryptSaltString::b64_encode(&SCRYPT_SALT_BYTES)
		.map_err(|err| {
			BenchmarkError::validation(format!(
				"failed to prepare scrypt salt: {}",
				err
			))
		})?;

	let mut samples = 0u64;
	let mut latencies = Vec::new();
	let run_start = Instant::now();
	while should_continue(
		samples,
		shared.iterations,
		target_duration,
		run_start.elapsed(),
	) {
		let iter_start = Instant::now();
		PHash::hash_scrypt_impl(PBKDF2_PASSWORD, &config, &salt)
			.map_err(|err| {
				BenchmarkError::validation(format!(
					"scrypt benchmark failed: {}",
					err
				))
			})?;
		latencies.push(elapsed_ms(iter_start.elapsed()));
		samples = samples.saturating_add(1);
	}

	finalize_result(
		KdfAlgorithm::Scrypt,
		samples,
		latencies,
		Some(profile.id.to_string()),
		Some(SCRYPT_MEDIAN_THRESHOLD_MS),
		format!(
			"profile {} (log_n {}, r {}, p {})",
			profile.id, profile.log_n, profile.r, profile.p
		),
	)
}

fn run_hkdf(
	variant: HkdfVariant,
	shared: &SharedBenchmarkArgs,
	target_duration: Duration,
) -> Result<BenchmarkResult, BenchmarkError> {
	let inputs = shared.hkdf_inputs.as_ref().ok_or_else(|| {
		BenchmarkError::validation(
			"HKDF benchmarks require --salt, --info, and secret material",
		)
	})?;
	let salt = inputs.salt.clone().ok_or_else(|| {
		BenchmarkError::validation(
			"--salt (hex) is required for HKDF",
		)
	})?;
	let info = inputs.info.clone().ok_or_else(|| {
		BenchmarkError::validation(
			"--info (hex) is required for HKDF",
		)
	})?;
	let ikm_source = inputs.ikm.clone();
	let prk_source = inputs.prk.clone();
	let length = inputs.length.unwrap_or_else(|| {
		variant.output_size().max(HKDF_DEFAULT_LENGTH)
	});
	let mut samples = 0u64;
	let mut latencies = Vec::new();
	let run_start = Instant::now();
	while should_continue(
		samples,
		shared.iterations,
		target_duration,
		run_start.elapsed(),
	) {
		let iter_start = Instant::now();
		let request = HkdfRequest {
			variant,
			// SecretMaterial zeroizes buffers on drop; each loop clones
			// the configured IKM/PRK into a fresh instance so sensitive bytes
			// never persist beyond this iteration.
			input: match variant.mode {
				HkdfMode::ExtractAndExpand => {
					let ikm = ikm_source
						.as_ref()
						.ok_or_else(|| {
							BenchmarkError::validation(
								"--ikm or --ikm-stdin required for HKDF extract mode",
							)
						})?
						.to_vec();
					HkdfCliInput::Extract(SecretMaterial::from_bytes(
						ikm,
					))
				}
				HkdfMode::ExpandOnly => {
					let prk = prk_source
						.as_ref()
						.ok_or_else(|| {
							BenchmarkError::validation(
								"--prk or --prk-stdin required for HKDF expand-only",
							)
						})?
						.to_vec();
					HkdfCliInput::Expand(SecretMaterial::from_bytes(
						prk,
					))
				}
			},
			salt: salt.clone(),
			info: info.clone(),
			length,
		};
		hkdf::derive(request).map_err(|err| {
			BenchmarkError::validation(format!(
				"HKDF benchmark failed: {}",
				err
			))
		})?;
		latencies.push(elapsed_ms(iter_start.elapsed()));
		samples = samples.saturating_add(1);
	}

	finalize_result(
		KdfAlgorithm::Hkdf(variant),
		samples,
		latencies,
		None,
		None,
		format!(
			"variant {} (length {} bytes)",
			variant.identifier(),
			length
		),
	)
}

fn finalize_result(
	algorithm: KdfAlgorithm,
	samples: u64,
	latencies: Vec<f64>,
	profile_id: Option<String>,
	latency_threshold_ms: Option<f64>,
	note_text: String,
) -> Result<BenchmarkResult, BenchmarkError> {
	if latencies.is_empty() {
		return Err(BenchmarkError::validation(format!(
			"no samples recorded for {}",
			algorithm.canonical_identifier()
		)));
	}
	let median = percentile(&latencies, 0.5);
	let p95 = percentile(&latencies, 0.95);
	let total_secs: f64 = latencies.iter().sum::<f64>() / 1000.0;
	let avg_ops = samples as f64 / total_secs.max(f64::EPSILON);
	let (compliance, warnings) =
		evaluate_compliance(samples, median, latency_threshold_ms);

	Ok(BenchmarkResult {
		algorithm: algorithm.canonical_identifier().to_string(),
		profile: profile_id,
		samples_collected: samples,
		avg_ops_per_sec: avg_ops,
		median_latency_ms: median,
		p95_latency_ms: p95,
		compliance,
		warnings,
		notes: Some(note_text),
	})
}

fn should_continue(
	samples: u64,
	iterations: Option<u64>,
	target_duration: Duration,
	elapsed: Duration,
) -> bool {
	if let Some(limit) = iterations {
		return samples < limit;
	}
	elapsed < target_duration || samples == 0
}

fn elapsed_ms(duration: Duration) -> f64 {
	duration.as_secs_f64() * 1000.0
}

fn percentile(values: &[f64], percentile: f64) -> f64 {
	let mut sorted = values.to_vec();
	sorted
		.sort_by(|a, b| a.partial_cmp(b).unwrap_or(Ordering::Equal));
	if sorted.is_empty() {
		return 0.0;
	}
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

fn evaluate_compliance(
	samples: u64,
	median_ms: f64,
	latency_threshold_ms: Option<f64>,
) -> (bool, Vec<String>) {
	let mut warnings = Vec::new();
	if samples < KDF_SAMPLE_TARGET {
		warnings.push(format!(
			"Only {} samples collected (< {} target)",
			samples, KDF_SAMPLE_TARGET
		));
	}
	if let Some(threshold) = latency_threshold_ms {
		if median_ms > threshold {
			warnings.push(format!(
				"Median latency {:.2} ms exceeds {:.1} ms guidance",
				median_ms, threshold
			));
		}
	}
	let compliance = warnings.is_empty();
	(compliance, warnings)
}

fn lookup_pbkdf2_profile(
	canonical_alg: &str,
	profiles: &BTreeMap<String, String>,
) -> Result<Pbkdf2Profile, BenchmarkError> {
	let profile_id =
		profiles.get(canonical_alg).ok_or_else(|| {
			BenchmarkError::validation(format!(
				"provide --profile for {}",
				canonical_alg
			))
		})?;
	get_pbkdf2_profile(profile_id).copied().ok_or_else(|| {
		BenchmarkError::validation(format!(
			"unknown PBKDF2 profile `{}`",
			profile_id
		))
	})
}

fn lookup_scrypt_profile(
	canonical_alg: &str,
	profiles: &BTreeMap<String, String>,
) -> Result<ScryptProfile, BenchmarkError> {
	let profile_id =
		profiles.get(canonical_alg).ok_or_else(|| {
			BenchmarkError::validation(
				"provide --profile for scrypt benchmarks",
			)
		})?;
	get_scrypt_profile(profile_id).copied().ok_or_else(|| {
		BenchmarkError::validation(format!(
			"unknown scrypt profile `{}`",
			profile_id
		))
	})
}
