// SPDX-License-Identifier: MIT OR Apache-2.0
// Project: rustgenhash

use super::common::{
	elapsed_ms, finalize_result, should_continue, KdfAlgorithm,
	HKDF_DEFAULT_LENGTH,
};
use crate::rgh::benchmark::{
	BenchmarkError, BenchmarkResult, SharedBenchmarkArgs,
};
use crate::rgh::kdf::hkdf::{
	self, HkdfInput as HkdfCliInput, HkdfMode, HkdfRequest, HkdfVariant,
};
use crate::rgh::kdf::SecretMaterial;
use std::time::{Duration, Instant};

pub(crate) fn run_hkdf(
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

