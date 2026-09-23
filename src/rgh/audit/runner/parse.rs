// SPDX-License-Identifier: MIT OR Apache-2.0
// Project: rustgenhash
// File: parse.rs
// Author: Volker Schwaberow <volker@schwaberow.de>
// Copyright (c) 2022 Volker Schwaberow

use crate::rgh::file::{
	ErrorStrategy, SymlinkPolicy, ThreadStrategy,
};
use crate::rgh::output::DigestOutputFormat;

use super::super::AuditError;

pub(crate) fn parse_output_format(
	value: Option<&str>,
) -> DigestOutputFormat {
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

pub(crate) fn parse_symlink_policy(
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

pub(crate) fn parse_thread_strategy(
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

pub(crate) fn parse_mmap_threshold(
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

pub(crate) fn parse_error_strategy(
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
