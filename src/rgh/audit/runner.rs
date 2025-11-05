// SPDX-License-Identifier: MIT OR Apache-2.0
// Project: rustgenhash
// File: runner.rs
// Author: Volker Schwaberow <volker@schwaberow.de>
// Copyright (c) 2022 Volker Schwaberow

use std::fs::File;
use std::path::PathBuf;
use std::time::Duration;

use chrono::Utc;
use clap::ValueEnum;
use digest::Digest;
use serde_json::{json, Map, Value};

use super::{
	AuditCase, AuditError, AuditMode, AuditRunMetadata, AuditSeverity,
};
use crate::rgh::analyze::{compare_hashes, HashAnalyzer};
use crate::rgh::app::Algorithm;
use crate::rgh::benchmark::run_benchmarks_to_writer;
use crate::rgh::file::{
	DirectoryHashPlan, EntryStatus, ErrorHandlingProfile,
	ErrorStrategy, ProgressConfig, ProgressMode, SymlinkPolicy,
	ThreadStrategy, WalkOrder,
};
use crate::rgh::hash::{
	digest_bytes_to_record, digest_with_options_collect,
	serialize_digest_output, Argon2Config, BalloonConfig,
	BcryptConfig, FileDigestOptions, PHash, Pbkdf2Config,
	ScryptConfig,
};
use crate::rgh::mac::executor as mac_executor;
use crate::rgh::mac::{
	commands::legacy_warning_message,
	key::{load_key as load_mac_key, KeySource as MacKeySource},
	registry::{
		self as mac_registry, MacAlgorithmMetadata, MacExecutor,
	},
};
use crate::rgh::output::{DigestOutputFormat, DigestSource};
use crate::rgh::weak::warning_for;
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
		AuditMode::MacString => run_mac_string_case(&case)?,
		AuditMode::MacFile => run_mac_file_case(&case)?,
		AuditMode::MacStdio => run_mac_stdio_case(&case)?,
		AuditMode::Kdf => run_kdf_case(&case)?,
		AuditMode::Analyze => run_analyze_case(&case)?,
		AuditMode::Compare => run_compare_case(&case)?,
		AuditMode::Benchmark => run_benchmark_case(&case)?,
		AuditMode::Header
		| AuditMode::Random
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

fn parse_output_format(value: Option<&str>) -> DigestOutputFormat {
	match value.unwrap_or("hex").to_ascii_lowercase().as_str() {
		"json" => DigestOutputFormat::Json,
		"jsonl" => DigestOutputFormat::JsonLines,
		"csv" => DigestOutputFormat::Csv,
		"base64" => DigestOutputFormat::Base64,
		"hashcat" => DigestOutputFormat::Hashcat,
		"multihash" => DigestOutputFormat::Multihash,
		_ => DigestOutputFormat::Hex,
	}
}

fn parse_symlink_policy(
	value: &str,
	case_id: &str,
) -> Result<SymlinkPolicy, AuditError> {
	match value.to_ascii_lowercase().as_str() {
		"never" => Ok(SymlinkPolicy::Never),
		"files" => Ok(SymlinkPolicy::Files),
		"all" => Ok(SymlinkPolicy::All),
		other => Err(AuditError::Invalid(format!(
			"Fixture `{}` has invalid follow_symlinks option '{}'.",
			case_id, other
		))),
	}
}

fn parse_thread_strategy(
	value: &str,
	case_id: &str,
) -> Result<ThreadStrategy, AuditError> {
	let trimmed = value.trim();
	if trimmed.eq_ignore_ascii_case("auto") {
		return Ok(ThreadStrategy::Auto);
	}
	let count: u16 = trimmed.parse().map_err(|_| {
		AuditError::Invalid(format!(
			"Fixture `{}` has invalid thread count '{}'.",
			case_id, trimmed
		))
	})?;
	if count == 0 {
		return Err(AuditError::Invalid(format!(
			"Fixture `{}` thread count must be >= 1.",
			case_id
		)));
	}
	if count == 1 {
		Ok(ThreadStrategy::Single)
	} else {
		Ok(ThreadStrategy::Fixed(count))
	}
}

fn parse_mmap_threshold(
	value: &str,
	case_id: &str,
) -> Result<Option<u64>, AuditError> {
	let trimmed = value.trim();
	if trimmed.is_empty() {
		return Err(AuditError::Invalid(format!(
			"Fixture `{}` mmap_threshold cannot be empty.",
			case_id
		)));
	}
	if trimmed.eq_ignore_ascii_case("off") {
		return Ok(None);
	}
	let lower = trimmed.to_ascii_lowercase();
	let mut split = lower.len();
	for (idx, ch) in lower.char_indices() {
		if !ch.is_ascii_digit() {
			split = idx;
			break;
		}
	}
	let (number, suffix) = lower.split_at(split);
	if number.is_empty() {
		return Err(AuditError::Invalid(format!(
			"Fixture `{}` has invalid mmap_threshold '{}'.",
			case_id, trimmed
		)));
	}
	let value: u64 = number.parse().map_err(|_| {
		AuditError::Invalid(format!(
			"Fixture `{}` has invalid mmap_threshold '{}'.",
			case_id, trimmed
		))
	})?;
	let factor: u64 = match suffix {
		"" | "b" => 1,
		"k" | "kb" | "kib" => 1024,
		"m" | "mb" | "mib" => 1024 * 1024,
		"g" | "gb" | "gib" => 1024 * 1024 * 1024,
		other => {
			return Err(AuditError::Invalid(format!(
				"Fixture `{}` has unsupported mmap_threshold suffix '{}'.",
				case_id, other
			)))
		}
	};
	value.checked_mul(factor).map(Some).ok_or_else(|| {
		AuditError::Invalid(format!(
			"Fixture `{}` mmap_threshold overflow.",
			case_id
		))
	})
}

fn parse_error_strategy(
	value: &str,
	case_id: &str,
) -> Result<ErrorStrategy, AuditError> {
	match value.to_ascii_lowercase().as_str() {
		"fail-fast" => Ok(ErrorStrategy::FailFast),
		"continue" => Ok(ErrorStrategy::Continue),
		"report-only" => Ok(ErrorStrategy::ReportOnly),
		other => Err(AuditError::Invalid(format!(
			"Fixture `{}` has invalid error_strategy '{}'.",
			case_id, other
		))),
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
	let output_format = parse_output_format(Some(format_value));
	let record = digest_bytes_to_record(
		&case.algorithm,
		value.as_bytes(),
		Some(value),
		DigestSource::String,
	)
	.map_err(|err| {
		AuditError::Invalid(format!(
			"Digest string command failed for fixture `{}`: {}",
			case.id, err
		))
	})?;
	let default_result = serialize_digest_output(
		std::slice::from_ref(&record),
		output_format,
		false,
	)
	.map_err(|err| {
		AuditError::Invalid(format!(
			"Digest string serialization failed for fixture `{}`: {}",
			case.id, err
		))
	})?;
	let hash_only_result = serialize_digest_output(
		std::slice::from_ref(&record),
		output_format,
		true,
	)
	.map_err(|err| {
		AuditError::Invalid(format!(
			"Digest string serialization failed for fixture `{}`: {}",
			case.id, err
		))
	})?;
	let mut output = json!({
		"digest": record.digest_hex,
		"format": format_value,
		"default_lines": default_result.lines,
		"hash_only_lines": hash_only_result.lines,
	});
	if let Some(warning) = warning_for(&case.algorithm) {
		if let Some(obj) = output.as_object_mut() {
			obj.insert(
				"warning_banner".to_string(),
				json!(warning.banner()),
			);
			obj.insert(
				"warning_references".to_string(),
				json!(warning.references),
			);
		}
	}
	if !default_result.warnings.is_empty() {
		if let Some(obj) = output.as_object_mut() {
			obj.insert(
				"default_warnings".to_string(),
				json!(default_result.warnings),
			);
		}
	}
	if !hash_only_result.warnings.is_empty() {
		if let Some(obj) = output.as_object_mut() {
			obj.insert(
				"hash_only_warnings".to_string(),
				json!(hash_only_result.warnings),
			);
		}
	}
	Ok(output)
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
	let output_format = parse_output_format(Some(format_value));
	let recursive = case
		.input
		.get("recursive")
		.and_then(Value::as_bool)
		.unwrap_or(false);
	let follow_policy = case
		.input
		.get("follow_symlinks")
		.and_then(Value::as_str)
		.unwrap_or("never");
	let symlink_policy =
		parse_symlink_policy(follow_policy, &case.id)?;
	let threads_raw = case
		.input
		.get("threads")
		.and_then(Value::as_str)
		.unwrap_or("1");
	let threads = parse_thread_strategy(threads_raw, &case.id)?;
	let mmap_raw = case
		.input
		.get("mmap_threshold")
		.and_then(Value::as_str)
		.unwrap_or("64MiB");
	let mmap_threshold = parse_mmap_threshold(mmap_raw, &case.id)?;
	let error_strategy_raw = case
		.input
		.get("error_strategy")
		.and_then(Value::as_str)
		.unwrap_or("fail-fast");
	let error_strategy =
		parse_error_strategy(error_strategy_raw, &case.id)?;

	let plan = DirectoryHashPlan {
		root_path: PathBuf::from(path_str),
		recursive,
		follow_symlinks: symlink_policy,
		order: WalkOrder::Lexicographic,
		threads,
		mmap_threshold,
	};
	let error_profile = ErrorHandlingProfile {
		strategy: error_strategy,
		..Default::default()
	};
	let progress = ProgressConfig {
		mode: ProgressMode::Disabled,
		throttle: Duration::from_millis(500),
	};
	let mut options = FileDigestOptions {
		algorithm: case.algorithm.clone(),
		plan,
		format: output_format,
		hash_only: false,
		progress,
		manifest_path: None,
		error_profile,
	};
	let defaults =
		digest_with_options_collect(&options).map_err(|err| {
			AuditError::Invalid(format!(
				"Digest file command failed for fixture `{}`: {}",
				case.id, err
			))
		})?;
	let default_lines = defaults.lines.clone();
	let default_warnings = defaults.warnings.clone();
	options.hash_only = true;
	let hash_only_result = digest_with_options_collect(&options)
		.map_err(|err| {
			AuditError::Invalid(format!(
				"Digest file command failed for fixture `{}`: {}",
				case.id, err
			))
		})?;
	let hash_only_lines = hash_only_result.lines.clone();
	let hash_only_warnings = hash_only_result.warnings.clone();
	let entries = defaults
		.summary
		.entries
		.iter()
		.filter(|entry| entry.status == EntryStatus::Hashed)
		.map(|entry| {
			json!({
				"path": entry.path.to_string_lossy(),
				"digest": entry.digest.clone().unwrap_or_default(),
			})
		})
		.collect::<Vec<_>>();
	let mut payload = json!({
		"format": format_value,
		"default_lines": default_lines,
		"hash_only_lines": hash_only_lines,
		"entries": entries,
		"exit_code": defaults.exit_code,
		"failure_count": defaults.summary.failure_count,
		"should_write_manifest": defaults.should_write_manifest,
		"fatal_error": defaults.fatal_error,
	});
	if let Some(warning) = warning_for(&case.algorithm) {
		if let Some(obj) = payload.as_object_mut() {
			obj.insert(
				"warning_banner".to_string(),
				json!(warning.banner()),
			);
			obj.insert(
				"warning_references".to_string(),
				json!(warning.references),
			);
		}
	}
	if !default_warnings.is_empty() {
		if let Some(obj) = payload.as_object_mut() {
			obj.insert(
				"default_warnings".to_string(),
				json!(default_warnings),
			);
		}
	}
	if !hash_only_warnings.is_empty() {
		if let Some(obj) = payload.as_object_mut() {
			obj.insert(
				"hash_only_warnings".to_string(),
				json!(hash_only_warnings),
			);
		}
	}
	Ok(payload)
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
	let output_format = parse_output_format(Some(format_value));
	let mut records = Vec::with_capacity(lines.len());
	for entry in lines {
		let value = entry.as_str().ok_or_else(|| {
			AuditError::Invalid(format!(
				"Fixture `{}` expected string entries in input.lines",
				case.id
			))
		})?;
		let record = digest_bytes_to_record(
			&case.algorithm,
			value.as_bytes(),
			Some(value),
			DigestSource::StdioLine,
		)
		.map_err(|err| {
			AuditError::Invalid(format!(
				"Digest stdio command failed for fixture `{}`: {}",
				case.id, err
			))
		})?;
		records.push((value.to_string(), record));
	}
	let record_metadata: Vec<_> = records
		.iter()
		.map(|(source, record)| {
			json!({
				"source": source,
				"digest": record.digest_hex.clone(),
			})
		})
		.collect();
	let record_values: Vec<_> =
		records.iter().map(|(_, record)| record.clone()).collect();
	if let Some(expected_exit) = case
		.expected_output
		.get("exit_code")
		.and_then(Value::as_i64)
	{
		if expected_exit != 0 {
			let default_error = serialize_digest_output(
				&record_values,
				output_format,
				false,
			)
			.expect_err("expected digest stdio failure");
			let hash_only_error = serialize_digest_output(
				&record_values,
				output_format,
				true,
			)
			.expect_err("expected digest stdio failure");
			let default_message = default_error.to_string();
			let hash_only_message = hash_only_error.to_string();
			if default_message != hash_only_message {
				return Err(AuditError::Invalid(format!(
					"Digest stdio failure emitted mismatched errors for fixture `{}`",
					case.id
				)));
			}
			let expected_error = case
				.expected_output
				.get("error")
				.and_then(Value::as_str)
				.unwrap_or_default();
			if !default_message.contains(expected_error) {
				return Err(AuditError::Invalid(format!(
					"Digest stdio failure message `{}` did not contain expected fragment `{}` for fixture `{}`",
					default_message,
					expected_error,
					case.id
				)));
			}
			return Ok(json!({
				"format": format_value,
				"exit_code": expected_exit,
				"error": default_message,
			}));
		}
	}
	let default_result =
		serialize_digest_output(&record_values, output_format, false)
			.map_err(|err| {
				AuditError::Invalid(format!(
			"Digest stdio serialization failed for fixture `{}`: {}",
			case.id, err
		))
			})?;
	let hash_only_result =
		serialize_digest_output(&record_values, output_format, true)
			.map_err(|err| {
				AuditError::Invalid(format!(
			"Digest stdio serialization failed for fixture `{}`: {}",
			case.id, err
		))
			})?;
	let mut payload = json!({
		"format": format_value,
		"records": record_metadata,
		"default_lines": default_result.lines,
		"hash_only_lines": hash_only_result.lines,
	});
	if let Some(warning) = warning_for(&case.algorithm) {
		if let Some(obj) = payload.as_object_mut() {
			obj.insert(
				"warning_banner".to_string(),
				json!(warning.banner()),
			);
			obj.insert(
				"warning_references".to_string(),
				json!(warning.references),
			);
		}
	}
	if !default_result.warnings.is_empty() {
		if let Some(obj) = payload.as_object_mut() {
			obj.insert(
				"default_warnings".to_string(),
				json!(default_result.warnings),
			);
		}
	}
	if !hash_only_result.warnings.is_empty() {
		if let Some(obj) = payload.as_object_mut() {
			obj.insert(
				"hash_only_warnings".to_string(),
				json!(hash_only_result.warnings),
			);
		}
	}
	Ok(payload)
}

fn parse_mac_key_source(
	case: &AuditCase,
) -> Result<MacKeySource, AuditError> {
	let key_value = case.key.as_ref().ok_or_else(|| {
		AuditError::Invalid(format!(
			"Fixture `{}` missing key definition",
			case.id
		))
	})?;
	let source = key_value
		.get("source")
		.and_then(Value::as_str)
		.ok_or_else(|| {
			AuditError::Invalid(format!(
				"Fixture `{}` missing key.source field",
				case.id
			))
		})?;
	Ok(MacKeySource::File(PathBuf::from(source)))
}

fn load_mac_fixture_key(key_source: &MacKeySource) -> Result<Vec<u8>, AuditError> {
	load_mac_key(key_source)
		.map_err(|err| AuditError::Invalid(format!("{}", err)))
}

fn create_mac_executor_for_case(
	algorithm: &str,
	case_id: &str,
	key: &[u8],
) -> Result<(Box<dyn MacExecutor>, MacAlgorithmMetadata), AuditError>
{
	mac_registry::create_executor(algorithm, key).map_err(|err| {
		AuditError::Invalid(format!("Fixture `{}`: {}", case_id, err))
	})
}

fn run_mac_string_case(
	case: &AuditCase,
) -> Result<Value, AuditError> {
	let key_source = parse_mac_key_source(case)?;
	let key_bytes = load_mac_fixture_key(&key_source)?;
	let input_obj = case.input.as_object().ok_or_else(|| {
		AuditError::Invalid(format!(
			"Fixture `{}` input must be an object",
			case.id
		))
	})?;
	let message = input_obj
		.get("value")
		.and_then(Value::as_str)
		.ok_or_else(|| {
			AuditError::Invalid(format!(
				"Fixture `{}` missing input.value",
				case.id
			))
		})?;
	let (executor, metadata) = create_mac_executor_for_case(
		&case.algorithm,
		&case.id,
		&key_bytes,
	)?;
	let digest =
		mac_executor::consume_bytes(message.as_bytes(), executor);
	let hex = mac_executor::digest_to_hex(&digest);
	let mut root = serde_json::Map::new();
	root.insert(
		"default_line".into(),
		Value::String(format!("{} {}", hex, message)),
	);
	root.insert("hash_only_line".into(), Value::String(hex.clone()));
	root.insert("exit_code".into(), Value::from(0));
	if metadata.is_legacy() {
		root.insert(
			"stderr_contains".into(),
			Value::Array(vec![Value::String(
				legacy_warning_message(&metadata),
			)]),
		);
	}
	Ok(Value::Object(root))
}

fn run_mac_file_case(case: &AuditCase) -> Result<Value, AuditError> {
	let key_source = parse_mac_key_source(case)?;
	let key_bytes = load_mac_fixture_key(&key_source)?;
	let path_str =
		case.input.get("path").and_then(Value::as_str).ok_or_else(
			|| {
				AuditError::Invalid(format!(
					"Fixture `{}` missing input.path",
					case.id
				))
			},
		)?;
	let path = PathBuf::from(path_str);
	let file =
		File::open(&path).map_err(|source| AuditError::Io {
			source,
			path: path.clone(),
		})?;
	let (executor, metadata) = create_mac_executor_for_case(
		&case.algorithm,
		&case.id,
		&key_bytes,
	)?;
	let digest = mac_executor::consume_reader(file, executor)
		.map_err(|source| AuditError::Io {
			source,
			path: path.clone(),
		})?;
	let hex = mac_executor::digest_to_hex(&digest);
	let mut root = Map::new();
	root.insert(
		"default_line".into(),
		Value::String(format!("{} {}", hex, path.display())),
	);
	root.insert("hash_only_line".into(), Value::String(hex.clone()));
	root.insert("exit_code".into(), Value::from(0));
	if metadata.is_legacy() {
		root.insert(
			"stderr_contains".into(),
			Value::Array(vec![Value::String(
				legacy_warning_message(&metadata),
			)]),
		);
	}
	Ok(Value::Object(root))
}

fn run_mac_stdio_case(case: &AuditCase) -> Result<Value, AuditError> {
	let key_source = parse_mac_key_source(case)?;
	let key_bytes = load_mac_fixture_key(&key_source)?;
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
	let mut default_lines = Vec::new();
	let mut hash_only_lines = Vec::new();
	let mut records = Vec::new();
	let mut legacy_warning: Option<Value> = None;
	for entry in lines {
		let line = entry.as_str().ok_or_else(|| {
			AuditError::Invalid(format!(
				"Fixture `{}` has non-string entry in input.lines",
				case.id
			))
		})?;
		let (executor, metadata) = create_mac_executor_for_case(
			&case.algorithm,
			&case.id,
			&key_bytes,
		)?;
		if metadata.is_legacy() && legacy_warning.is_none() {
			legacy_warning = Some(Value::String(
				legacy_warning_message(&metadata),
			));
		}
		let digest =
			mac_executor::consume_bytes(line.as_bytes(), executor);
		let hex = mac_executor::digest_to_hex(&digest);
		default_lines
			.push(Value::String(format!("{} {}", hex, line)));
		hash_only_lines.push(Value::String(hex.clone()));
		records.push(json!({ "source": line, "digest": hex }));
	}
	let mut root = Map::new();
	root.insert("default_lines".into(), Value::Array(default_lines));
	root.insert(
		"hash_only_lines".into(),
		Value::Array(hash_only_lines),
	);
	root.insert("records".into(), Value::Array(records));
	root.insert("exit_code".into(), Value::from(0));
	if let Some(warning) = legacy_warning {
		root.insert(
			"stderr_contains".into(),
			Value::Array(vec![warning]),
		);
	}
	Ok(Value::Object(root))
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

fn run_benchmark_case(case: &AuditCase) -> Result<Value, AuditError> {
	let iterations = case
		.input
		.get("iterations")
		.and_then(Value::as_u64)
		.unwrap_or(1000);
	let iterations = u32::try_from(iterations).map_err(|_| {
		AuditError::Invalid(format!(
			"Iteration count out of range for fixture `{}`",
			case.id
		))
	})?;

	let algorithm = Algorithm::from_str(&case.algorithm, true)
		.map_err(|_| {
			AuditError::Invalid(format!(
				"Unsupported benchmark algorithm `{}` in fixture `{}`",
				case.algorithm, case.id
			))
		})?;

	let mut buffer = Vec::new();
	let algorithms = [algorithm];
	run_benchmarks_to_writer(&algorithms, iterations, &mut buffer)
		.map_err(|err| {
			AuditError::Invalid(format!(
				"Benchmark execution failed for fixture `{}`: {}",
				case.id, err
			))
		})?;

	let stdout = String::from_utf8(buffer).map_err(|err| {
		AuditError::Invalid(format!(
			"Benchmark output not valid UTF-8 for fixture `{}`: {}",
			case.id, err
		))
	})?;

	let asm_enabled = stdout
		.lines()
		.find_map(|line| line.strip_prefix("asm_enabled: "))
		.map(|value| value.trim().eq_ignore_ascii_case("true"))
		.ok_or_else(|| {
			AuditError::Invalid(format!(
				"Benchmark output missing asm_enabled metadata for fixture `{}`",
				case.id
			))
		})?;

	Ok(json!({ "asm_enabled": asm_enabled }))
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
