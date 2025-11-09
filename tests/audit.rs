// SPDX-License-Identifier: MIT OR Apache-2.0
// Project: rustgenhash
// File: audit.rs
// Author: Volker Schwaberow <volker@schwaberow.de>

use std::env;
use std::fs::{self, File};
use std::io::{self, BufWriter, Write};
use std::path::{Path, PathBuf};

use rand_chacha::ChaCha20Rng;
use rand_core::{RngCore, SeedableRng};
use rustgenhash::rgh::audit::{
	collect_fixture_paths, compute_run_metadata, execute_cases,
	load_fixture, write_reports, AuditCase, AuditOutcome,
	AuditStatus,
};
use serde_json::Value;

const LARGE_STREAM_DIR: &str = "target/audit/large-stream";
const MAX_STREAM_CHUNK_SIZE: u64 = 8 * 1024 * 1024;

fn requested_case() -> Option<String> {
	let mut args = env::args().skip(1);
	while let Some(arg) = args.next() {
		if arg == "--case" {
			return args.next();
		}
	}
	None
}

fn load_all(paths: &[PathBuf]) -> Vec<AuditCase> {
	paths
		.iter()
		.map(|path| {
			load_fixture(path).unwrap_or_else(|err| {
				panic!(
					"Failed to load fixture {}: {err}",
					path.display()
				)
			})
		})
		.collect()
}

fn prepare_large_stream_inputs(
	cases: &[AuditCase],
) -> io::Result<()> {
	fs::create_dir_all(LARGE_STREAM_DIR)?;
	for case in cases {
		if let Some(config) = case.input.get("generate_large_stream")
		{
			let cfg = config.as_object().ok_or_else(|| {
				io::Error::new(
					io::ErrorKind::InvalidData,
					format!(
						"Fixture `{}` generate_large_stream must be an object",
						case.id
					),
				)
			})?;
			let path_str = cfg
				.get("path")
				.and_then(Value::as_str)
				.ok_or_else(|| {
					io::Error::new(
						io::ErrorKind::InvalidData,
						format!(
							"Fixture `{}` generate_large_stream.path missing",
							case.id
						),
					)
				})?;
			let length = cfg
				.get("length_bytes")
				.and_then(Value::as_u64)
				.ok_or_else(|| {
					io::Error::new(
						io::ErrorKind::InvalidData,
						format!(
							"Fixture `{}` generate_large_stream.length_bytes missing",
							case.id
						),
					)
				})?;
			let chunk_size = cfg
				.get("chunk_size")
				.and_then(Value::as_u64)
				.unwrap_or(MAX_STREAM_CHUNK_SIZE);
			if chunk_size == 0 || chunk_size > MAX_STREAM_CHUNK_SIZE {
				return Err(io::Error::new(
					io::ErrorKind::InvalidData,
					format!(
						"Fixture `{}` chunk_size must be 1..={} bytes",
						case.id,
						MAX_STREAM_CHUNK_SIZE
					),
				));
			}
			let seed =
				cfg.get("seed").and_then(Value::as_u64).unwrap_or(0);
			let path = Path::new(path_str);
			if let Some(parent) = path.parent() {
				fs::create_dir_all(parent)?;
			}
			if let Ok(meta) = fs::metadata(path) {
				if meta.len() == length {
					continue;
				}
			}
			write_large_stream(path, seed, length, chunk_size)?;
		}
	}
	Ok(())
}

fn write_large_stream(
	path: &Path,
	seed: u64,
	length: u64,
	chunk_size: u64,
) -> io::Result<()> {
	if let Some(parent) = path.parent() {
		fs::create_dir_all(parent)?;
	}
	let file = File::create(path)?;
	let mut writer = BufWriter::new(file);
	let mut rng = ChaCha20Rng::seed_from_u64(seed);
	let mut buffer = vec![0u8; chunk_size as usize];
	let mut remaining = length;
	while remaining > 0 {
		let write_len =
			std::cmp::min(buffer.len() as u64, remaining) as usize;
		rng.fill_bytes(&mut buffer[..write_len]);
		writer.write_all(&buffer[..write_len])?;
		remaining -= write_len as u64;
	}
	writer.flush()
}

fn assert_exit_code_with_message(
	case_id: &str,
	actual: &Value,
	expected_exit: i64,
	expected_substring: &str,
) {
	let exit_code = actual
		.get("exit_code")
		.and_then(Value::as_i64)
		.unwrap_or_else(|| {
			panic!(
				"Fixture `{}` missing exit_code in audit output: {}",
				case_id, actual
			)
		});
	assert_eq!(
		exit_code, expected_exit,
		"Fixture `{}` exit code mismatch",
		case_id
	);
	let stderr = actual
		.get("stderr")
		.and_then(Value::as_str)
		.or_else(|| actual.get("error").and_then(Value::as_str))
		.unwrap_or_else(|| {
			panic!(
				"Fixture `{}` missing stderr/error in audit output: {}",
				case_id, actual
			)
		});
	assert!(
		stderr.contains(expected_substring),
		"Fixture `{}` stderr `{}` did not contain expected substring `{}`",
		case_id,
		stderr,
		expected_substring
	);
}

fn validate_negative_path_outcomes(outcomes: &[AuditOutcome]) {
	for outcome in outcomes {
		let actual = &outcome.actual_output;
		match outcome.case.id.as_str() {
			"mac_poly1305_mismatched_key" => {
				assert_exit_code_with_message(
					&outcome.case.id,
					actual,
					2,
					"Poly1305 requires a 32-byte one-time key",
				);
			}
			"mac_cmac_padding_mismatch" => {
				assert_exit_code_with_message(
					&outcome.case.id,
					actual,
					2,
					"Invalid CMAC key length",
				);
			}
			"kdf_pbkdf2_invalid_iterations" => {
				assert_exit_code_with_message(
					&outcome.case.id,
					actual,
					2,
					"rounds",
				);
			}
			"kdf_scrypt_zero_password" => {
				assert_exit_code_with_message(
					&outcome.case.id,
					actual,
					2,
					"Password must not be empty",
				);
			}
			_ => {}
		}
	}
}

#[test]
fn audit_fixtures_smoke() {
	let requested = requested_case();
	let fixture_paths = collect_fixture_paths(requested.as_deref())
		.expect("Failed to discover fixture paths");
	let selected: Vec<PathBuf> = fixture_paths;

	assert!(
		!selected.is_empty(),
		"No fixtures found for selection {:?}",
		requested
	);

	let cases = load_all(&selected);
	assert_eq!(
		cases.len(),
		selected.len(),
		"Failed to load fixtures"
	);
	prepare_large_stream_inputs(&cases)
		.expect("failed to prepare runtime large-stream fixtures");

	if requested.is_none() {
		let required_cases = [
			"digest_string_empty",
			"digest_file_large_stream",
			"mac_cmac_aes128_string",
			"mac_cmac_aes256_file",
			"mac_poly1305_stdio",
			"mac_poly1305_key_error",
			"mac_poly1305_mismatched_key",
			"mac_cmac_padding_mismatch",
			"kdf_hkdf_blake3_basic",
			"kdf_hkdf_expand_only",
			"kdf_pbkdf2_profile_nist_sp800132",
			"kdf_scrypt_profile_owasp",
			"kdf_pbkdf2_invalid_iterations",
			"kdf_scrypt_zero_password",
		];
		for required in required_cases {
			assert!(
				cases.iter().any(|case| case.id == required),
				"Required CMAC fixture `{}` missing from audit registry",
				required
			);
		}
	}

	let outcomes =
		execute_cases(cases).expect("Failed to execute audit cases");
	let metadata = compute_run_metadata(&outcomes);
	write_reports(&metadata, &outcomes)
		.expect("Failed to write audit reports");
	validate_negative_path_outcomes(&outcomes);

	let failures: Vec<_> = outcomes
		.iter()
		.filter(|outcome| outcome.status == AuditStatus::Fail)
		.collect();

	if !failures.is_empty() {
		for failure in &failures {
			eprintln!(
                "Fixture {} (severity {:?}) failed. Notes: {}. Details: {}",
                failure.case.id,
                failure.case.metadata.severity,
                failure
                    .case
                    .metadata
                    .notes
                    .as_deref()
                    .unwrap_or("n/a"),
                failure
                    .message
                    .as_deref()
                    .unwrap_or("no additional context")
            );
		}
		panic!("{} audit fixtures failed", failures.len());
	}

	let passes = outcomes
		.iter()
		.filter(|outcome| outcome.status == AuditStatus::Pass)
		.count();
	let executed = outcomes
		.iter()
		.filter(|outcome| outcome.status != AuditStatus::Skipped)
		.count();

	if executed > 0 {
		assert!(passes > 0, "Audit produced zero passing fixtures");
	}
}
