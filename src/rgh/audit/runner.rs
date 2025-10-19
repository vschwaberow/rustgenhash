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
	let digest = compute_digest(&case.algorithm, value.as_bytes())?;
	Ok(json!({
		"digest": digest,
		"format": case
			.expected_output
			.get("format")
			.and_then(Value::as_str)
			.unwrap_or("hex")
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
		let digest =
			compute_digest(&case.algorithm, value.as_bytes())?;
		digests.push(json!({
			"source": value,
			"digest": digest
		}));
	}
	Ok(json!({ "digests": digests }))
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
	let digest_bytes = match algorithm.to_uppercase().as_str() {
		"SHA256" => {
			let mut hasher = sha2::Sha256::new();
			hasher.update(data);
			hasher.finalize().to_vec()
		}
		"SHA1" => {
			let mut hasher = sha1::Sha1::new();
			hasher.update(data);
			hasher.finalize().to_vec()
		}
		"MD5" => {
			let mut hasher = md5::Md5::new();
			hasher.update(data);
			hasher.finalize().to_vec()
		}
		other => {
			return Err(AuditError::Invalid(format!(
				"Unsupported algorithm `{other}` in audit fixtures"
			)))
		}
	};
	Ok(hex::encode(digest_bytes))
}
