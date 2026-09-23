// SPDX-License-Identifier: MIT OR Apache-2.0
// Project: rustgenhash
// File: mod.rs
// Author: Volker Schwaberow <volker@schwaberow.de>
// Copyright (c) 2022 Volker Schwaberow

mod digest;
mod kdf;
mod mac;
mod other;
mod parse;

use chrono::Utc;
use serde_json::Value;

use super::{
	AuditCase, AuditError, AuditMode, AuditRunMetadata, AuditSeverity,
};
use digest::{
	run_digest_file_case, run_digest_stdio_case,
	run_digest_string_case,
};
use kdf::run_kdf_case;
use mac::{
	run_mac_file_case, run_mac_stdio_case, run_mac_string_case,
};
use other::{run_analyze_case, run_benchmark_case, run_compare_case};

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
