use std::path::PathBuf;

use chrono::{DateTime, Utc};

use super::{
	DirectoryHashPlan, EntryStatus, ErrorHandlingProfile,
	ErrorStrategy, ManifestEntry, ManifestSummary,
	PerformanceEnvelope,
};

#[derive(Debug)]
pub struct ManifestOutcome {
	pub summary: ManifestSummary,
	pub exit_code: i32,
	pub should_write_manifest: bool,
	pub fatal_error: Option<String>,
}

pub struct ManifestWriter {
	plan: DirectoryHashPlan,
	error_profile: ErrorHandlingProfile,
	summary: ManifestSummary,
	fatal_encountered: bool,
	first_failure: Option<String>,
}

impl ManifestWriter {
	pub fn new(
		plan: DirectoryHashPlan,
		profile: ErrorHandlingProfile,
	) -> Self {
		let mut summary = ManifestSummary::default();
		summary.root = plan.root_path.clone();
		summary.strategy = profile.strategy;
		Self {
			plan,
			error_profile: profile,
			summary,
			fatal_encountered: false,
			first_failure: None,
		}
	}

	pub fn record_success(
		&mut self,
		path: PathBuf,
		algorithm: &str,
		digest: String,
		size_bytes: u64,
		modified: Option<DateTime<Utc>>,
	) {
		self.summary.success_count += 1;
		self.summary.entries.push(ManifestEntry {
			path,
			algorithm: algorithm.to_string(),
			digest: Some(digest),
			size_bytes,
			modified,
			status: EntryStatus::Hashed,
			error: None,
		});
	}

	pub fn record_failure(
		&mut self,
		path: PathBuf,
		algorithm: &str,
		error: impl Into<String>,
		status: EntryStatus,
	) -> bool {
		let message = error.into();
		if self.first_failure.is_none() {
			self.first_failure = Some(message.clone());
		}
		self.summary.failure_count += 1;
		self.summary.entries.push(ManifestEntry {
			path,
			algorithm: algorithm.to_string(),
			digest: None,
			size_bytes: 0,
			modified: None,
			status,
			error: Some(message),
		});
		match self.error_profile.strategy {
			ErrorStrategy::FailFast => {
				self.fatal_encountered = true;
				false
			}
			ErrorStrategy::Continue | ErrorStrategy::ReportOnly => {
				true
			}
		}
	}

	pub fn set_performance(&mut self, perf: PerformanceEnvelope) {
		self.summary.performance = Some(perf);
	}

	pub fn finalize(mut self) -> ManifestOutcome {
		self.summary.generated_at = Utc::now();
		let exit_code = if self.fatal_encountered {
			self.error_profile.exit_fatal
		} else if self.summary.failure_count > 0 {
			match self.error_profile.strategy {
				ErrorStrategy::FailFast => {
					self.error_profile.exit_fatal
				}
				ErrorStrategy::Continue => {
					self.error_profile.exit_recoverable
				}
				ErrorStrategy::ReportOnly => {
					self.error_profile.exit_success
				}
			}
		} else {
			self.error_profile.exit_success
		};
		let should_write_manifest = !(self.fatal_encountered
			&& matches!(
				self.error_profile.strategy,
				ErrorStrategy::FailFast
			));
		ManifestOutcome {
			summary: self.summary,
			exit_code,
			should_write_manifest,
			fatal_error: self.first_failure,
		}
	}

	pub fn error_profile(&self) -> &ErrorHandlingProfile {
		&self.error_profile
	}

	pub fn plan(&self) -> &DirectoryHashPlan {
		&self.plan
	}

	pub fn fatal_encountered(&self) -> bool {
		self.fatal_encountered
	}
}
