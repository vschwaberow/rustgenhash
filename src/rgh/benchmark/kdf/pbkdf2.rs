// SPDX-License-Identifier: MIT OR Apache-2.0
// Project: rustgenhash

use super::common::{
	elapsed_ms, evaluate_compliance, finalize_result, should_continue,
	Pbkdf2Variant, PBKDF2_MEDIAN_THRESHOLD_MS, PBKDF2_PASSWORD,
	PBKDF2_ROUND_DIVISOR, PBKDF2_SALT_B64,
};
use crate::rgh::benchmark::{
	BenchmarkError, BenchmarkResult, SharedBenchmarkArgs, KDF_SAMPLE_TARGET,
};
use crate::rgh::hash::{PHash, Pbkdf2Config};
use crate::rgh::kdf::profile::Pbkdf2Profile;
use std::time::{Duration, Instant};

pub(crate) fn run_pbkdf2(
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

