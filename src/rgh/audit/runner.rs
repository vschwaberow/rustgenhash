// SPDX-License-Identifier: MIT OR Apache-2.0
// Project: rustgenhash
// File: runner.rs
// Author: Volker Schwaberow <volker@schwaberow.de>

use std::path::PathBuf;

use chrono::Utc;
use digest::Digest;
use serde_json::{json, Value};

use super::{
	AuditCase, AuditError, AuditMode, AuditRunMetadata, AuditSeverity,
};
use crate::rgh::analyze::{compare_hashes, HashAnalyzer};
use crate::rgh::app::OutputOptions;
use crate::rgh::hash::{
	digest_bytes_to_string, digest_path_to_strings, Argon2Config,
	BalloonConfig, BcryptConfig, PHash, Pbkdf2Config, ScryptConfig,
};
use base64::{engine::general_purpose::STANDARD, Engine};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AuditStatus {
	Pass,
	Fail,
	Skipped,
}

#[derive(Debug, Clone)]
pub struct AuditOutcome {
	pub case: AuditCase,
	pub actual_output: Value,
	pub status: AuditStatus,
	pub message: Option<String>,
}

impl AuditOutcome {
	pub fn skipped(case: AuditCase) -> Self {
		AuditOutcome {
			message: case.metadata.skip_reason.clone(),
			case,
			status: AuditStatus::Skipped,
			actual_output: Value::Null,
		}
	}

	pub fn with_result(
		case: AuditCase,
		actual_output: Value,
		message: Option<String>,
		status: AuditStatus,
	) -> Self {
		AuditOutcome {
			case,
			actual_output,
			status,
			message,
		}
	}
}

pub fn execute_case(
	case: AuditCase,
) -> Result<AuditOutcome, AuditError> {
	if case.is_skipped() {
		return Ok(AuditOutcome::skipped(case));
	}
	let expected = case.expected_output.clone();
	let actual = match case.mode {
		AuditMode::String => run_string_case(&case)?,
		AuditMode::File => run_file_case(&case)?,
		AuditMode::Stdio => run_stdio_case(&case)?,
		AuditMode::DigestString => run_digest_string_case(&case)?,
		AuditMode::DigestFile => run_digest_file_case(&case)?,
		AuditMode::DigestStdio => run_digest_stdio_case(&case)?,
		AuditMode::Kdf => run_kdf_case(&case)?,
		AuditMode::Analyze => run_analyze_case(&case)?,
		AuditMode::Compare => run_compare_case(&case)?,
		AuditMode::Header
		| AuditMode::Random
		| AuditMode::Benchmark
		| AuditMode::Interactive => {
			return Ok(AuditOutcome::skipped(case));
		}
	};

	let status = if actual == expected {
		AuditStatus::Pass
	} else {
		AuditStatus::Fail
	};

	let message = match status {
		AuditStatus::Pass => None,
		AuditStatus::Fail => {
			Some(format!("Expected {}, got {}", expected, actual))
		}
		AuditStatus::Skipped => None,
	};

	Ok(AuditOutcome::with_result(case, actual, message, status))
}

pub fn execute_cases(
	cases: Vec<AuditCase>,
) -> Result<Vec<AuditOutcome>, AuditError> {
	let mut outcomes = Vec::with_capacity(cases.len());
	for case in cases {
		let outcome = execute_case(case)?;
		outcomes.push(outcome);
	}
	Ok(outcomes)
}

pub fn compute_run_metadata(
	results: &[AuditOutcome],
) -> AuditRunMetadata {
	let total = results.len();
	let passed = results
		.iter()
		.filter(|outcome| outcome.status == AuditStatus::Pass)
		.count();
	let failed = results
		.iter()
		.filter(|outcome| outcome.status == AuditStatus::Fail)
		.count();
	let skipped = total.saturating_sub(passed + failed);
	AuditRunMetadata {
		run_id: Utc::now(),
		total,
		passed,
		failed,
		skipped,
	}
}

pub fn highest_severity(
	results: &[AuditOutcome],
) -> Option<AuditSeverity> {
	results
		.iter()
		.filter(|outcome| outcome.status == AuditStatus::Fail)
		.filter_map(|outcome| outcome.case.metadata.severity.clone())
		.max_by_key(|severity| match severity {
			AuditSeverity::Critical => 3,
			AuditSeverity::High => 2,
			AuditSeverity::Medium => 1,
			AuditSeverity::Low => 0,
		})
}

fn run_string_case(case: &AuditCase) -> Result<Value, AuditError> {
	let value =
		case.input.get("value").and_then(Value::as_str).ok_or_else(
			|| {
				AuditError::Invalid(format!(
					"Fixture `{}` missing input.value",
					case.id
				))
			},
		)?;
	let algorithm = case.algorithm.to_uppercase();
	let default_format = case
		.expected_output
		.get("format")
		.and_then(Value::as_str)
		.map(|s| s.to_lowercase());

	let (tokens, digest_repr, format_value) = match algorithm.as_str()
	{
		"ARGON2" => {
			let salt = case
				.input
				.get("salt")
				.and_then(Value::as_str)
				.ok_or_else(|| {
					AuditError::Invalid(format!(
						"Fixture `{}` missing input.salt for Argon2",
						case.id
					))
				})?;
			let hash = PHash::hash_argon2_with_salt(
				value,
				&Argon2Config::default(),
				salt,
			)
			.map_err(|err| {
				AuditError::Invalid(format!(
					"Argon2 derivation failed for fixture `{}`: {}",
					case.id, err
				))
			})?;
			let format =
				default_format.unwrap_or_else(|| "encoded".into());
			(vec![hash.clone()], hash, format)
		}
		"SCRYPT" => {
			let salt = case
				.input
				.get("salt")
				.and_then(Value::as_str)
				.ok_or_else(|| {
					AuditError::Invalid(format!(
						"Fixture `{}` missing input.salt for Scrypt",
						case.id
					))
				})?;
			let hash = PHash::hash_scrypt_with_salt(
				value,
				&ScryptConfig::default(),
				salt,
			)
			.map_err(|err| {
				AuditError::Invalid(format!(
					"Scrypt derivation failed for fixture `{}`: {}",
					case.id, err
				))
			})?;
			let format =
				default_format.unwrap_or_else(|| "encoded".into());
			(vec![hash.clone()], hash, format)
		}
		"BCRYPT" => {
			let salt = case
				.input
				.get("salt")
				.and_then(Value::as_str)
				.ok_or_else(|| {
					AuditError::Invalid(format!(
						"Fixture `{}` missing input.salt for Bcrypt",
						case.id
					))
				})?;
			let hash = PHash::hash_bcrypt_with_salt(
				value,
				&BcryptConfig::default(),
				salt,
			)
			.map_err(|err| {
				AuditError::Invalid(format!(
					"Bcrypt derivation failed for fixture `{}`: {}",
					case.id, err
				))
			})?;
			let format =
				default_format.unwrap_or_else(|| "hex".into());
			(vec![hash.clone()], hash, format)
		}
		"BALLOON" => {
			let salt = case
				.input
				.get("salt")
				.and_then(Value::as_str)
				.ok_or_else(|| {
					AuditError::Invalid(format!(
						"Fixture `{}` missing input.salt for Balloon",
						case.id
					))
				})?;
			let hash = PHash::hash_balloon_with_salt(
				value,
				&BalloonConfig::default(),
				salt,
			)
			.map_err(|err| {
				AuditError::Invalid(format!(
					"Balloon derivation failed for fixture `{}`: {}",
					case.id, err
				))
			})?;
			let format =
				default_format.unwrap_or_else(|| "encoded".into());
			(vec![hash.clone()], hash, format)
		}
		_ => {
			let digest_bytes = compute_digest_bytes(
				&case.algorithm,
				value.as_bytes(),
			)?;
			let digest_hex = hex::encode(&digest_bytes);
			let format =
				default_format.unwrap_or_else(|| "hex".into());
			let tokens = match format.as_str() {
				"base64" => vec![STANDARD.encode(&digest_bytes)],
				"hexbase64" => vec![
					hex::encode(&digest_bytes),
					STANDARD.encode(&digest_bytes),
				],
				_ => vec![digest_hex.clone()],
			};
			let digest_repr =
				tokens.first().cloned().unwrap_or_default();
			(tokens, digest_repr, format)
		}
	};

	let hash_only_line = tokens.join(" ");
	let mut default_tokens = tokens.clone();
	default_tokens.push(value.to_string());
	let default_line = default_tokens.join(" ");

	Ok(json!({
		"digest": digest_repr,
		"format": format_value,
		"default_line": default_line,
		"hash_only_line": hash_only_line
	}))
}

fn run_file_case(case: &AuditCase) -> Result<Value, AuditError> {
	let path_str =
		case.input.get("path").and_then(Value::as_str).ok_or_else(
			|| {
				AuditError::Invalid(format!(
					"Fixture `{}` missing input.path",
					case.id
				))
			},
		)?;
	let manifest = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
	let path = manifest.join(path_str);
	let data =
		std::fs::read(&path).map_err(|source| AuditError::Io {
			source,
			path: path.clone(),
		})?;
	let digest = compute_digest(&case.algorithm, &data)?;
	Ok(json!({
		"digest": digest,
		"format": case
			.expected_output
			.get("format")
			.and_then(Value::as_str)
			.unwrap_or("hex")
	}))
}

fn run_stdio_case(case: &AuditCase) -> Result<Value, AuditError> {
	let lines = case
		.input
		.get("lines")
		.and_then(Value::as_array)
		.ok_or_else(|| {
			AuditError::Invalid(format!(
				"Fixture `{}` missing input.lines",
				case.id
			))
		})?;
	let mut digests = Vec::with_capacity(lines.len());
	for entry in lines {
		let value = entry.as_str().ok_or_else(|| {
			AuditError::Invalid(format!(
				"Fixture `{}` expected string entries in input.lines",
				case.id
			))
		})?;
		let digest_bytes =
			compute_digest_bytes(&case.algorithm, value.as_bytes())?;
		let digest_hex = hex::encode(&digest_bytes);
		let hash_only_line = digest_hex.clone();
		let default_line = format!("{} {}", digest_hex, value);
		digests.push(json!({
			"source": value,
			"digest": digest_hex,
			"default_line": default_line,
			"hash_only_line": hash_only_line
		}));
	}
	Ok(json!({ "digests": digests }))
}

fn parse_output_option(value: Option<&str>) -> OutputOptions {
	if let Some(fmt) = value {
		if fmt.eq_ignore_ascii_case("base64") {
			OutputOptions::Base64
		} else if fmt.eq_ignore_ascii_case("hexbase64") {
			OutputOptions::HexBase64
		} else {
			OutputOptions::Hex
		}
	} else {
		OutputOptions::Hex
	}
}

fn run_digest_string_case(
	case: &AuditCase,
) -> Result<Value, AuditError> {
	let value =
		case.input.get("value").and_then(Value::as_str).ok_or_else(
			|| {
				AuditError::Invalid(format!(
					"Fixture `{}` missing input.value",
					case.id
				))
			},
		)?;
	let format_value = case
		.expected_output
		.get("format")
		.and_then(Value::as_str)
		.unwrap_or("hex");
	let output_option = parse_output_option(Some(format_value));
	let default_line = digest_bytes_to_string(
		&case.algorithm,
		value.as_bytes(),
		output_option,
		false,
		Some(value),
	)
	.map_err(|err| {
		AuditError::Invalid(format!(
			"Digest string command failed for fixture `{}`: {}",
			case.id, err
		))
	})?;
	let hash_only_line = digest_bytes_to_string(
		&case.algorithm,
		value.as_bytes(),
		output_option,
		true,
		Some(value),
	)
	.map_err(|err| {
		AuditError::Invalid(format!(
			"Digest string command failed for fixture `{}`: {}",
			case.id, err
		))
	})?;
	let digest = hash_only_line
		.split_whitespace()
		.next()
		.unwrap_or_default()
		.to_string();
	Ok(json!({
		"digest": digest,
		"format": format_value,
		"default_line": default_line,
		"hash_only_line": hash_only_line
	}))
}

fn run_digest_file_case(
	case: &AuditCase,
) -> Result<Value, AuditError> {
	let path_str =
		case.input.get("path").and_then(Value::as_str).ok_or_else(
			|| {
				AuditError::Invalid(format!(
					"Fixture `{}` missing input.path",
					case.id
				))
			},
		)?;
	let format_value = case
		.expected_output
		.get("format")
		.and_then(Value::as_str)
		.unwrap_or("hex");
	let output_option = parse_output_option(Some(format_value));
	let defaults = digest_path_to_strings(
		&case.algorithm,
		path_str,
		output_option,
		false,
	)
	.map_err(|err| {
		AuditError::Invalid(format!(
			"Digest file command failed for fixture `{}`: {}",
			case.id, err
		))
	})?;
	let hash_only = digest_path_to_strings(
		&case.algorithm,
		path_str,
		output_option,
		true,
	)
	.map_err(|err| {
		AuditError::Invalid(format!(
			"Digest file command failed for fixture `{}`: {}",
			case.id, err
		))
	})?;
	if defaults.len() != hash_only.len() {
		return Err(AuditError::Invalid(format!(
			"Digest file command returned mismatched line counts for fixture `{}`",
			case.id
		)));
	}
	let mut entries = Vec::with_capacity(defaults.len());
	for (default_line, hash_only_line) in
		defaults.iter().zip(hash_only.iter())
	{
		let digest = hash_only_line
			.split_whitespace()
			.next()
			.unwrap_or_default()
			.to_string();
		let path_token = default_line
			.rsplit_once(' ')
			.map(|(_, path)| path.to_string())
			.unwrap_or_else(|| path_str.to_string());
		entries.push(json!({
			"path": path_token,
			"digest": digest,
			"default_line": default_line,
			"hash_only_line": hash_only_line
		}));
	}
	Ok(json!({
		"format": format_value,
		"entries": entries
	}))
}

fn run_digest_stdio_case(
	case: &AuditCase,
) -> Result<Value, AuditError> {
	let lines = case
		.input
		.get("lines")
		.and_then(Value::as_array)
		.ok_or_else(|| {
			AuditError::Invalid(format!(
				"Fixture `{}` missing input.lines",
				case.id
			))
		})?;
	let format_value = case
		.expected_output
		.get("format")
		.and_then(Value::as_str)
		.unwrap_or("hex");
	let output_option = parse_output_option(Some(format_value));
	let mut digests = Vec::with_capacity(lines.len());
	for entry in lines {
		let value = entry.as_str().ok_or_else(|| {
			AuditError::Invalid(format!(
				"Fixture `{}` expected string entries in input.lines",
				case.id
			))
		})?;
		let default_line = digest_bytes_to_string(
			&case.algorithm,
			value.as_bytes(),
			output_option,
			false,
			Some(value),
		)
		.map_err(|err| {
			AuditError::Invalid(format!(
				"Digest stdio command failed for fixture `{}`: {}",
				case.id, err
			))
		})?;
		let hash_only_line = digest_bytes_to_string(
			&case.algorithm,
			value.as_bytes(),
			output_option,
			true,
			Some(value),
		)
		.map_err(|err| {
			AuditError::Invalid(format!(
				"Digest stdio command failed for fixture `{}`: {}",
				case.id, err
			))
		})?;
		let digest = hash_only_line
			.split_whitespace()
			.next()
			.unwrap_or_default()
			.to_string();
		digests.push(json!({
			"source": value,
			"digest": digest,
			"default_line": default_line,
			"hash_only_line": hash_only_line
		}));
	}
	Ok(json!({
		"format": format_value,
		"digests": digests
	}))
}

fn run_kdf_case(case: &AuditCase) -> Result<Value, AuditError> {
	let password = case
		.input
		.get("password")
		.and_then(Value::as_str)
		.ok_or_else(|| {
			AuditError::Invalid(format!(
				"Fixture `{}` missing input.password",
				case.id
			))
		})?;
	let salt =
		case.input.get("salt").and_then(Value::as_str).ok_or_else(
			|| {
				AuditError::Invalid(format!(
					"Fixture `{}` missing input.salt",
					case.id
				))
			},
		)?;
	match case.algorithm.to_uppercase().as_str() {
		"ARGON2" => {
			let defaults = Argon2Config::default();
			let mem_cost = case
				.input
				.get("mem_cost")
				.and_then(Value::as_u64)
				.map(|v| v as u32)
				.unwrap_or(defaults.mem_cost);
			let time_cost = case
				.input
				.get("time_cost")
				.and_then(Value::as_u64)
				.map(|v| v as u32)
				.unwrap_or(defaults.time_cost);
			let parallelism = case
				.input
				.get("parallelism")
				.and_then(Value::as_u64)
				.map(|v| v as u32)
				.unwrap_or(defaults.parallelism);
			let config = Argon2Config {
				mem_cost,
				time_cost,
				parallelism,
			};
			let digest =
				PHash::hash_argon2_with_salt(password, &config, salt)
					.map_err(|err| {
						AuditError::Invalid(format!(
						"Argon2 derivation failed for fixture `{}`: {}",
						case.id, err
					))
					})?;
			let metadata = json!({
				"mem_cost": mem_cost,
				"time_cost": time_cost,
				"parallelism": parallelism,
				"salt": salt
			});
			Ok(json!({ "digest": digest, "metadata": metadata }))
		}
		"PBKDF2_SHA256" | "PBKDF2-SHA256" | "PBKDF2SHA256" => {
			let defaults = Pbkdf2Config::default();
			let rounds = case
				.input
				.get("rounds")
				.and_then(Value::as_u64)
				.map(|v| v as u32)
				.unwrap_or(defaults.rounds);
			let output_length = case
				.input
				.get("output_length")
				.and_then(Value::as_u64)
				.map(|v| v as usize)
				.unwrap_or(defaults.output_length);
			let config = Pbkdf2Config {
				rounds,
				output_length,
			};
			let digest = PHash::hash_pbkdf2_with_salt(
				password,
				"pbkdf2sha256",
				&config,
				salt,
			)
			.map_err(|err| {
				AuditError::Invalid(format!(
					"PBKDF2-SHA256 derivation failed for fixture `{}`: {}",
					case.id, err
				))
			})?;
			let metadata = json!({
				"rounds": rounds,
				"output_length": output_length,
				"algorithm": "pbkdf2-sha256",
				"salt": salt
			});
			Ok(json!({ "digest": digest, "metadata": metadata }))
		}
		"PBKDF2_SHA512" | "PBKDF2-SHA512" | "PBKDF2SHA512" => {
			let defaults = Pbkdf2Config::default();
			let rounds = case
				.input
				.get("rounds")
				.and_then(Value::as_u64)
				.map(|v| v as u32)
				.unwrap_or(defaults.rounds);
			let output_length = case
				.input
				.get("output_length")
				.and_then(Value::as_u64)
				.map(|v| v as usize)
				.unwrap_or(defaults.output_length);
			let config = Pbkdf2Config {
				rounds,
				output_length,
			};
			let digest = PHash::hash_pbkdf2_with_salt(
				password,
				"pbkdf2sha512",
				&config,
				salt,
			)
			.map_err(|err| {
				AuditError::Invalid(format!(
					"PBKDF2-SHA512 derivation failed for fixture `{}`: {}",
					case.id, err
				))
			})?;
			let metadata = json!({
				"rounds": rounds,
				"output_length": output_length,
				"algorithm": "pbkdf2-sha512",
				"salt": salt
			});
			Ok(json!({ "digest": digest, "metadata": metadata }))
		}
		other => Err(AuditError::Invalid(format!(
			"Unsupported KDF algorithm `{}` in fixture `{}`",
			other, case.id
		))),
	}
}

fn run_analyze_case(case: &AuditCase) -> Result<Value, AuditError> {
	let hash_value =
		case.input.get("hash").and_then(Value::as_str).ok_or_else(
			|| {
				AuditError::Invalid(format!(
					"Fixture `{}` missing input.hash",
					case.id
				))
			},
		)?;
	let analyzer = HashAnalyzer::from_string(hash_value);
	let mut candidates = analyzer.detect_possible_hashes();
	candidates.sort();
	let expected_candidates = case
		.expected_output
		.get("candidates")
		.and_then(Value::as_array)
		.map(|arr| arr.len())
		.unwrap_or_default();
	let is_exact = expected_candidates == 1 && candidates.len() == 1;
	Ok(json!({
		"candidates": candidates,
		"is_exact": is_exact
	}))
}

fn run_compare_case(case: &AuditCase) -> Result<Value, AuditError> {
	let left =
		case.input.get("left").and_then(Value::as_str).ok_or_else(
			|| {
				AuditError::Invalid(format!(
					"Fixture `{}` missing input.left",
					case.id
				))
			},
		)?;
	let right =
		case.input.get("right").and_then(Value::as_str).ok_or_else(
			|| {
				AuditError::Invalid(format!(
					"Fixture `{}` missing input.right",
					case.id
				))
			},
		)?;
	let case_sensitive = case
		.input
		.get("case_sensitive")
		.and_then(Value::as_bool)
		.unwrap_or(true);
	let matches = if case_sensitive {
		left == right
	} else {
		compare_hashes(left, right)
	};
	Ok(json!({ "matches": matches }))
}

fn compute_digest(
	algorithm: &str,
	data: &[u8],
) -> Result<String, AuditError> {
	let bytes = compute_digest_bytes(algorithm, data)?;
	Ok(hex::encode(bytes))
}

fn compute_digest_bytes(
	algorithm: &str,
	data: &[u8],
) -> Result<Vec<u8>, AuditError> {
	match algorithm.to_uppercase().as_str() {
		"SHA256" => {
			let mut hasher = sha2::Sha256::new();
			hasher.update(data);
			Ok(hasher.finalize().to_vec())
		}
		"SHA1" => {
			let mut hasher = sha1::Sha1::new();
			hasher.update(data);
			Ok(hasher.finalize().to_vec())
		}
		"MD5" => {
			let mut hasher = md5::Md5::new();
			hasher.update(data);
			Ok(hasher.finalize().to_vec())
		}
		other => Err(AuditError::Invalid(format!(
			"Unsupported algorithm `{other}` in audit fixtures"
		))),
	}
}
