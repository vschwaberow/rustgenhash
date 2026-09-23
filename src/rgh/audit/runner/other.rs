// SPDX-License-Identifier: MIT OR Apache-2.0
// Project: rustgenhash
// File: other.rs
// Author: Volker Schwaberow <volker@schwaberow.de>
// Copyright (c) 2022 Volker Schwaberow

use clap::ValueEnum;
use serde_json::{json, Value};

use super::super::{AuditCase, AuditError};
use crate::rgh::analyze::{compare_hashes, HashAnalyzer};
use crate::rgh::benchmark::run_digest_benchmarks;
use crate::rgh::cli::algorithms::Algorithm;
use crate::rgh::hash::asm_accelerated_digests;

pub(crate) fn run_analyze_case(
	case: &AuditCase,
) -> Result<Value, AuditError> {
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

pub(crate) fn run_compare_case(
	case: &AuditCase,
) -> Result<Value, AuditError> {
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

pub(crate) fn run_benchmark_case(
	case: &AuditCase,
) -> Result<Value, AuditError> {
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

	let algorithms = [algorithm];
	run_digest_benchmarks(&algorithms, iterations).map_err(
		|err| {
			AuditError::Invalid(format!(
				"Benchmark execution failed for fixture `{}`: {}",
				case.id, err
			))
		},
	)?;

	let asm_enabled = !asm_accelerated_digests().is_empty();

	Ok(json!({ "asm_enabled": asm_enabled }))
}
