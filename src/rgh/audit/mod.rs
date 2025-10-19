// SPDX-License-Identifier: MIT OR Apache-2.0
// Project: rustgenhash
// File: mod.rs
// Author: Volker Schwaberow <volker@schwaberow.de>

use std::fmt;
use std::fs::File;
use std::io::Read;
use std::path::{Path, PathBuf};

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use serde_json::Value;

pub mod fs;
pub mod report;
pub mod runner;

pub use fs::{
	collect_fixture_paths, ensure_issues_dir, ensure_output_root,
	fixtures_root,
};
pub use report::write_reports;
pub use runner::{
	compute_run_metadata, execute_case, execute_cases,
	highest_severity, AuditOutcome, AuditStatus,
};

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum AuditMode {
	String,
	File,
	Stdio,
	Header,
	Analyze,
	Random,
	Benchmark,
	Interactive,
	Compare,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum AuditSeverity {
	Critical,
	High,
	Medium,
	Low,
}

#[derive(
	Debug, Clone, Serialize, Deserialize, Default, PartialEq, Eq,
)]
pub struct AuditMetadata {
	pub severity: Option<AuditSeverity>,
	pub notes: Option<String>,
	pub skip_reason: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuditCase {
	pub id: String,
	pub mode: AuditMode,
	pub algorithm: String,
	pub input: Value,
	pub expected_output: Value,
	#[serde(default)]
	pub metadata: AuditMetadata,
}

impl AuditCase {
	pub fn is_skipped(&self) -> bool {
		self.metadata.skip_reason.is_some()
	}

	pub fn validate(&self) -> Result<(), AuditError> {
		if self.id.trim().is_empty() {
			return Err(AuditError::Invalid(
				"Fixture id cannot be empty".to_string(),
			));
		}
		if self.algorithm.trim().is_empty() {
			return Err(AuditError::Invalid(format!(
				"Fixture `{}` missing algorithm name",
				self.id
			)));
		}
		if self.expected_output.is_null() {
			return Err(AuditError::Invalid(format!(
				"Fixture `{}` missing expected_output payload",
				self.id
			)));
		}
		Ok(())
	}
}

#[derive(Debug)]
pub enum AuditError {
	Io {
		source: std::io::Error,
		path: PathBuf,
	},
	Parse {
		source: serde_json::Error,
		path: PathBuf,
	},
	Invalid(String),
}

impl fmt::Display for AuditError {
	fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
		match self {
			AuditError::Io { source, path } => {
				write!(
					f,
					"IO error reading {}: {}",
					path.display(),
					source
				)
			}
			AuditError::Parse { source, path } => {
				write!(
					f,
					"Failed to parse fixture {}: {}",
					path.display(),
					source
				)
			}
			AuditError::Invalid(msg) => {
				write!(f, "Invalid fixture: {}", msg)
			}
		}
	}
}

impl std::error::Error for AuditError {
	fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
		match self {
			AuditError::Io { source, .. } => Some(source),
			AuditError::Parse { source, .. } => Some(source),
			AuditError::Invalid(_) => None,
		}
	}
}

impl AuditError {
	pub fn context(self, path: impl Into<PathBuf>) -> Self {
		match self {
			AuditError::Io { source, .. } => AuditError::Io {
				source,
				path: path.into(),
			},
			AuditError::Parse { source, .. } => AuditError::Parse {
				source,
				path: path.into(),
			},
			AuditError::Invalid(msg) => AuditError::Invalid(msg),
		}
	}
}

pub fn load_fixture(path: &Path) -> Result<AuditCase, AuditError> {
	let mut file =
		File::open(path).map_err(|source| AuditError::Io {
			source,
			path: path.to_path_buf(),
		})?;

	let mut contents = String::new();
	file.read_to_string(&mut contents).map_err(|source| {
		AuditError::Io {
			source,
			path: path.to_path_buf(),
		}
	})?;

	let case: AuditCase =
		serde_json::from_str(&contents).map_err(|source| {
			AuditError::Parse {
				source,
				path: path.to_path_buf(),
			}
		})?;
	case.validate()?;
	Ok(case)
}

pub fn load_fixtures(
	paths: &[PathBuf],
) -> Result<Vec<AuditCase>, AuditError> {
	let mut cases = Vec::with_capacity(paths.len());
	for path in paths {
		let case = load_fixture(path)?;
		cases.push(case);
	}
	Ok(cases)
}

#[derive(Debug, Clone)]
pub struct AuditRunMetadata {
	pub run_id: DateTime<Utc>,
	pub total: usize,
	pub passed: usize,
	pub failed: usize,
	pub skipped: usize,
}
