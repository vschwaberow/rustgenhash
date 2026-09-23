// SPDX-License-Identifier: MIT OR Apache-2.0
// Project: rustgenhash

use crate::rgh::benchmark::{
	BenchmarkError, BenchmarkResult, KDF_SAMPLE_TARGET,
};
use crate::rgh::kdf::hkdf::{HkdfVariant, HKDF_VARIANTS};
use crate::rgh::kdf::profile::{
	get_pbkdf2_profile, get_scrypt_profile, Pbkdf2Profile,
	ScryptProfile,
};
use std::cmp::Ordering;
use std::collections::BTreeMap;
use std::time::Duration;

pub(crate) const PBKDF2_PASSWORD: &str = "benchmark-password";
pub(crate) const PBKDF2_SALT_B64: &str = "AAAAAAAAAAAAAAAAAAAAAA";
pub(crate) const SCRYPT_SALT_BYTES: [u8; 16] = *b"benchmark-scrypt";
pub(crate) const PBKDF2_MEDIAN_THRESHOLD_MS: f64 = 1500.0;
pub(crate) const SCRYPT_MEDIAN_THRESHOLD_MS: f64 = 2000.0;
pub(crate) const HKDF_DEFAULT_LENGTH: usize = 32;
pub(crate) const PBKDF2_ROUND_DIVISOR: u32 = 500;
pub(crate) const SCRYPT_LOG_N_REDUCTION: u8 = 4;

#[derive(Debug, Clone, Copy)]
pub(crate) enum KdfAlgorithm {
	Pbkdf2Sha256,
	Pbkdf2Sha512,
	Scrypt,
	Hkdf(HkdfVariant),
}

impl KdfAlgorithm {
	pub(crate) fn canonical_identifier(self) -> &'static str {
		match self {
			Self::Pbkdf2Sha256 => "pbkdf2-sha256",
			Self::Pbkdf2Sha512 => "pbkdf2-sha512",
			Self::Scrypt => "scrypt",
			Self::Hkdf(variant) => variant.identifier(),
		}
	}

	pub(crate) fn requires_profile(self) -> bool {
		matches!(
			self,
			KdfAlgorithm::Pbkdf2Sha256
				| KdfAlgorithm::Pbkdf2Sha512
				| KdfAlgorithm::Scrypt
		)
	}
}

#[derive(Debug, Clone, Copy)]
pub(crate) struct Pbkdf2Variant {
	pub(crate) algorithm: KdfAlgorithm,
	pub(crate) pbkdf2_scheme: &'static str,
}

pub(crate) const PBKDF2_VARIANTS: &[Pbkdf2Variant] = &[
	Pbkdf2Variant {
		algorithm: KdfAlgorithm::Pbkdf2Sha256,
		pbkdf2_scheme: "pbkdf2sha256",
	},
	Pbkdf2Variant {
		algorithm: KdfAlgorithm::Pbkdf2Sha512,
		pbkdf2_scheme: "pbkdf2sha512",
	},
];

pub(crate) fn parse_algorithm(
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

pub(crate) fn finalize_result(
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

pub(crate) fn should_continue(
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

pub(crate) fn elapsed_ms(duration: Duration) -> f64 {
	duration.as_secs_f64() * 1000.0
}

pub(crate) fn percentile(values: &[f64], percentile: f64) -> f64 {
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

pub(crate) fn evaluate_compliance(
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

pub(crate) fn lookup_pbkdf2_profile(
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

pub(crate) fn lookup_scrypt_profile(
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
