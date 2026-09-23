// SPDX-License-Identifier: MIT OR Apache-2.0
// Project: rustgenhash
// File: digest.rs
// Author: Volker Schwaberow <volker@schwaberow.de>
// Copyright (c) 2022 Volker Schwaberow

use std::path::PathBuf;
use std::time::Duration;

use serde_json::{json, Value};

use super::super::{AuditCase, AuditError};
use crate::rgh::file::{
	DirectoryHashPlan, EntryStatus, ErrorHandlingProfile,
	ProgressConfig, ProgressMode, WalkOrder,
};
use crate::rgh::hash::{
	digest_bytes_to_record, digest_with_options_collect,
	serialize_digest_output, FileDigestOptions,
};
use crate::rgh::output::DigestSource;
use crate::rgh::weak::warning_for;

use super::parse::{
	parse_error_strategy, parse_mmap_threshold, parse_output_format,
	parse_symlink_policy, parse_thread_strategy,
};

pub(crate) fn run_digest_string_case(
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

pub(crate) fn run_digest_file_case(
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
		.unwrap_or("off");
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

pub(crate) fn run_digest_stdio_case(
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
