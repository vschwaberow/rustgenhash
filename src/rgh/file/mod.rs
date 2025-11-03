// SPDX-License-Identifier: MIT OR Apache-2.0
// Project: rustgenhash
// File: mod.rs
// Author: Volker Schwaberow <volker@schwaberow.de>
// Copyright (c) 2022 Volker Schwaberow

pub mod manifest;
pub mod progress;
pub mod walker;

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::path::PathBuf;

pub use manifest::{ManifestOutcome, ManifestWriter};
pub use progress::{ProgressConfig, ProgressEmitter, ProgressMode};
pub use walker::{SymlinkPolicy, WalkEntry, Walker};

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct DirectoryHashPlan {
	pub root_path: PathBuf,
	pub recursive: bool,
	pub follow_symlinks: SymlinkPolicy,
	pub order: WalkOrder,
	pub threads: ThreadStrategy,
	pub mmap_threshold: Option<u64>,
}

impl DirectoryHashPlan {
	pub fn requires_recursion(&self) -> bool {
		self.recursive
	}

	pub fn should_use_mmap(&self, size: u64) -> bool {
		self.mmap_threshold
			.map_or(false, |threshold| size >= threshold)
	}
}

#[derive(
	Copy, Clone, Debug, Eq, PartialEq, Serialize, Deserialize,
)]
pub enum WalkOrder {
	Lexicographic,
}

#[derive(
	Copy, Clone, Debug, Eq, PartialEq, Serialize, Deserialize,
)]
pub enum ThreadStrategy {
	Single,
	Auto,
	Fixed(u16),
}

#[derive(
	Copy, Clone, Debug, Eq, PartialEq, Serialize, Deserialize,
)]
pub enum ErrorStrategy {
	FailFast,
	Continue,
	ReportOnly,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ErrorHandlingProfile {
	pub strategy: ErrorStrategy,
	pub exit_success: i32,
	pub exit_recoverable: i32,
	pub exit_fatal: i32,
}

impl Default for ErrorHandlingProfile {
	fn default() -> Self {
		Self {
			strategy: ErrorStrategy::FailFast,
			exit_success: 0,
			exit_recoverable: 2,
			exit_fatal: 1,
		}
	}
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ManifestEntry {
	pub path: PathBuf,
	pub algorithm: String,
	pub digest: Option<String>,
	pub size_bytes: u64,
	pub modified: Option<DateTime<Utc>>,
	pub status: EntryStatus,
	pub error: Option<String>,
}

#[derive(
	Copy, Clone, Debug, Eq, PartialEq, Serialize, Deserialize,
)]
pub enum EntryStatus {
	Hashed,
	Skipped,
	Error,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ManifestSummary {
	pub root: PathBuf,
	pub generated_at: DateTime<Utc>,
	pub success_count: u64,
	pub failure_count: u64,
	pub strategy: ErrorStrategy,
	pub performance: Option<PerformanceEnvelope>,
	pub entries: Vec<ManifestEntry>,
}

impl Default for ManifestSummary {
	fn default() -> Self {
		Self {
			root: PathBuf::new(),
			generated_at: Utc::now(),
			success_count: 0,
			failure_count: 0,
			strategy: ErrorStrategy::FailFast,
			performance: None,
			entries: Vec::new(),
		}
	}
}

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct PerformanceEnvelope {
	pub elapsed_ms: u64,
	pub bytes_per_second: f64,
	pub threads: usize,
	pub mmap_active: bool,
}
