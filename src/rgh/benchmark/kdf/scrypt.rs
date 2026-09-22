// SPDX-License-Identifier: MIT OR Apache-2.0
// Project: rustgenhash

use super::common::{
	elapsed_ms, evaluate_compliance, finalize_result, should_continue,
	KdfAlgorithm, PBKDF2_PASSWORD, SCRYPT_LOG_N_REDUCTION,
	SCRYPT_MEDIAN_THRESHOLD_MS, SCRYPT_SALT_BYTES,
};
use crate::rgh::benchmark::{
	BenchmarkError, BenchmarkResult, SharedBenchmarkArgs, KDF_SAMPLE_TARGET,
};
use crate::rgh::hash::{PHash, ScryptConfig};
use crate::rgh::kdf::profile::ScryptProfile;
use scrypt::password_hash::SaltString as ScryptSaltString;
use std::time::{Duration, Instant};

pub(crate) fn run_scrypt(
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

