// SPDX-License-Identifier: MIT OR Apache-2.0
// Project: rustgenhash
// File: report.rs
// Author: Volker Schwaberow <volker@schwaberow.de>
// Copyright (c) 2022 Volker Schwaberow

use std::fmt::Write as FmtWrite;
use std::fs::File;
use std::io::Write;

use serde_json::json;

use super::{
	ensure_issues_dir, ensure_output_root, AuditOutcome,
	AuditRunMetadata, AuditStatus,
};

pub fn write_reports(
	metadata: &AuditRunMetadata,
	outcomes: &[AuditOutcome],
) -> Result<(), super::AuditError> {
	let output_dir = ensure_output_root()?;
	write_text_report(
		metadata,
		outcomes,
		&output_dir.join("summary.txt"),
	)?;
	write_json_report(
		metadata,
		outcomes,
		&output_dir.join("summary.json"),
	)?;
	write_issue_snippets(outcomes)?;
	Ok(())
}

fn write_text_report(
	metadata: &AuditRunMetadata,
	outcomes: &[AuditOutcome],
	path: &std::path::Path,
) -> Result<(), super::AuditError> {
	let mut file = File::create(path).map_err(|source| {
		super::AuditError::Io {
			source,
			path: path.to_path_buf(),
		}
	})?;

	let mut cases = outcomes.to_vec();
	cases.sort_by(|a, b| a.case.id.cmp(&b.case.id));

	let mut text = String::new();
	writeln!(&mut text, "Rustgenhash Audit Summary")
		.map_err(|err| super::AuditError::Invalid(err.to_string()))?;
	writeln!(
		&mut text,
		"Run: {}",
		metadata
			.run_id
			.to_rfc3339_opts(chrono::SecondsFormat::Secs, true)
	)
	.map_err(|err| super::AuditError::Invalid(err.to_string()))?;
	writeln!(
		&mut text,
		"Totals: {} total | {} passed | {} failed | {} skipped",
		metadata.total,
		metadata.passed,
		metadata.failed,
		metadata.skipped
	)
	.map_err(|err| super::AuditError::Invalid(err.to_string()))?;
	writeln!(&mut text)
		.map_err(|err| super::AuditError::Invalid(err.to_string()))?;
	writeln!(&mut text, "Cases:")
		.map_err(|err| super::AuditError::Invalid(err.to_string()))?;
	for outcome in &cases {
		let status = display_status(outcome.status);
		let severity = outcome
			.case
			.metadata
			.severity
			.as_ref()
			.map(|s| format!("{s:?}"))
			.unwrap_or_else(|| "None".to_string());
		let extra = match outcome.status {
			AuditStatus::Skipped => outcome
				.case
				.metadata
				.skip_reason
				.clone()
				.unwrap_or_else(|| "Skipped".to_string()),
			AuditStatus::Fail => outcome
				.message
				.clone()
				.unwrap_or_else(|| "Mismatch detected".to_string()),
			AuditStatus::Pass => "OK".to_string(),
		};
		writeln!(
			&mut text,
			" - [{}] {} :: {} :: severity={} :: {}",
			status,
			outcome.case.id,
			outcome.case.algorithm,
			severity,
			extra
		)
		.map_err(|err| super::AuditError::Invalid(err.to_string()))?;
	}

	file.write_all(text.as_bytes()).map_err(|source| {
		super::AuditError::Io {
			source,
			path: path.to_path_buf(),
		}
	})
}

fn write_json_report(
	metadata: &AuditRunMetadata,
	outcomes: &[AuditOutcome],
	path: &std::path::Path,
) -> Result<(), super::AuditError> {
	let mut cases = outcomes.to_vec();
	cases.sort_by(|a, b| a.case.id.cmp(&b.case.id));

	let json_payload = json!({
		"run_id": metadata.run_id.to_rfc3339_opts(chrono::SecondsFormat::Secs, true),
		"stats": {
			"total": metadata.total,
			"passed": metadata.passed,
			"failed": metadata.failed,
			"skipped": metadata.skipped
		},
		"cases": cases.iter().map(|outcome| {
			json!({
				"id": outcome.case.id,
				"mode": outcome.case.mode,
				"algorithm": outcome.case.algorithm,
				"status": display_status(outcome.status),
				"severity": outcome.case.metadata.severity,
				"skip_reason": outcome.case.metadata.skip_reason,
				"message": outcome.message,
				"expected_output": outcome.case.expected_output,
				"actual_output": outcome.actual_output
			})
		}).collect::<Vec<_>>()
	});

	let file = File::create(path).map_err(|source| {
		super::AuditError::Io {
			source,
			path: path.to_path_buf(),
		}
	})?;
	serde_json::to_writer_pretty(file, &json_payload).map_err(
		|source| super::AuditError::Parse {
			source,
			path: path.to_path_buf(),
		},
	)
}

fn display_status(status: AuditStatus) -> &'static str {
	match status {
		AuditStatus::Pass => "PASS",
		AuditStatus::Fail => "FAIL",
		AuditStatus::Skipped => "SKIP",
	}
}

fn write_issue_snippets(
	outcomes: &[AuditOutcome],
) -> Result<(), super::AuditError> {
	let issues_dir = ensure_issues_dir()?;
	let mut failures: Vec<&AuditOutcome> = outcomes
		.iter()
		.filter(|outcome| outcome.status == AuditStatus::Fail)
		.collect();
	failures.sort_by(|a, b| a.case.id.cmp(&b.case.id));

	for outcome in failures {
		let filename =
			format!("{}.md", sanitize_case_id(&outcome.case.id));
		let path = issues_dir.join(filename);
		let mut file = File::create(&path).map_err(|source| {
			super::AuditError::Io {
				source,
				path: path.clone(),
			}
		})?;
		let severity = outcome
			.case
			.metadata
			.severity
			.as_ref()
			.map(|s| format!("{s:?}"))
			.unwrap_or_else(|| "Unspecified".to_string());
		let message = outcome
			.message
			.clone()
			.unwrap_or_else(|| "Mismatch detected".to_string());
		let expected = serde_json::to_string_pretty(
			&outcome.case.expected_output,
		)
		.unwrap_or_else(|_| "<invalid expected output>".to_string());
		let actual =
			serde_json::to_string_pretty(&outcome.actual_output)
				.unwrap_or_else(|_| {
					"<invalid actual output>".to_string()
				});
		write!(
			file,
			"## {}\n\
Severity: {}\n\
Fixture: `{}`\n\
Algorithm: `{}`\n\
Notes: {}\n\
\n\
## Reproduction\n\
```\n\
cargo test --test audit -- --case {}\n\
```\n\
\n\
## Expected Output\n\
```\n\
{}\n\
```\n\
\n\
## Actual Output\n\
```\n\
{}\n\
```\n",
			outcome.case.id,
			severity,
			outcome.case.id,
			outcome.case.algorithm,
			message,
			outcome.case.id,
			expected,
			actual
		)
		.map_err(|err| super::AuditError::Invalid(err.to_string()))?;
	}

	Ok(())
}

fn sanitize_case_id(id: &str) -> String {
	id.chars()
		.map(|c| {
			if c.is_ascii_alphanumeric() || c == '-' || c == '_' {
				c
			} else {
				'_'
			}
		})
		.collect()
}
