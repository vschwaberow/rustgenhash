// SPDX-License-Identifier: MIT OR Apache-2.0
// Project: rustgenhash
// File: hash/file.rs

use crate::rgh::multihash::MultihashEncoder;
use super::digest_ops::serialize_digest_output;
use super::rhash::RHash;
use crate::rgh::file::{
	DirectoryHashPlan, EntryStatus, ErrorHandlingProfile,
	ManifestEntry, ManifestOutcome, ManifestSummary, ManifestWriter,
	PerformanceEnvelope, ProgressConfig, ProgressEmitter,
	ThreadStrategy, Walker,
};
use crate::rgh::output::{
	DigestOutputFormat, DigestRecord, DigestSource, SerializationResult,
};
use chrono::{DateTime, Utc};
use rayon::prelude::*;
use serde_json::to_writer_pretty;
use std::collections::HashMap;
use std::fs::{self, File};
use std::io::{self, IsTerminal};
use std::path::{Path, PathBuf};
use std::time::Instant;

#[derive(Clone, Debug)]
pub struct FileDigestOptions {
	pub algorithm: String,
	pub plan: DirectoryHashPlan,
	pub format: DigestOutputFormat,
	pub hash_only: bool,
	pub progress: ProgressConfig,
	pub manifest_path: Option<PathBuf>,
	pub error_profile: ErrorHandlingProfile,
}

impl FileDigestOptions {
	fn algorithm_uppercase(&self) -> String {
		self.algorithm.to_uppercase()
	}
}

pub struct FileDigestResult {
	pub summary: ManifestSummary,
	pub lines: Vec<String>,
	pub warnings: Vec<String>,
	pub exit_code: i32,
	pub should_write_manifest: bool,
	pub fatal_error: Option<String>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum CompareMode {
	Manifest,
	Text,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum CompareDiffKind {
	Changed,
	MissingLeft,
	MissingRight,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CompareDifference {
	pub identifier: String,
	pub kind: CompareDiffKind,
	pub expected: Option<String>,
	pub actual: Option<String>,
}

#[derive(Clone, Debug)]
pub struct CompareSummary {
	pub mode: CompareMode,
	pub differences: Vec<CompareDifference>,
	pub exit_code: i32,
	pub incomplete: bool,
	pub left_failures: u64,
	pub right_failures: u64,
	pub left_entries: usize,
	pub right_entries: usize,
}

pub fn digest_with_options(
	options: &FileDigestOptions,
) -> Result<
	(ManifestOutcome, SerializationResult),
	Box<dyn std::error::Error>,
> {
	let is_tty = io::stderr().is_terminal();
	let mut emitter =
		if options.progress.should_emit(options.hash_only, is_tty) {
			Some(ProgressEmitter::new(options.progress))
		} else {
			None
		};

	let (outcome, records) = {
		let emitter_ref = emitter.as_mut();
		digest_with_options_internal(options, emitter_ref)?
	};

	if let Some(emitter) = emitter.as_mut() {
		emitter.emit_final();
	}

	let serialization = serialize_digest_output(
		&records,
		options.format,
		options.hash_only,
	)
	.map_err(|err| -> Box<dyn std::error::Error> { Box::new(err) })?;

	if outcome.should_write_manifest {
		if let Some(manifest_path) = &options.manifest_path {
			write_manifest(manifest_path, &outcome.summary)?;
		}
	}

	Ok((outcome, serialization))
}

pub fn digest_with_options_collect(
	options: &FileDigestOptions,
) -> Result<FileDigestResult, Box<dyn std::error::Error>> {
	let (outcome, serialization) = digest_with_options(options)?;
	let ManifestOutcome {
		summary,
		exit_code,
		should_write_manifest,
		fatal_error,
	} = outcome;
	Ok(FileDigestResult {
		summary,
		lines: serialization.lines,
		warnings: serialization.warnings,
		exit_code,
		should_write_manifest,
		fatal_error,
	})
}

enum HashedFile {
	Ok {
		path: PathBuf,
		digest_bytes: Vec<u8>,
		size: u64,
		modified: Option<DateTime<Utc>>,
		used_mmap: bool,
	},
	Fail {
		path: PathBuf,
		message: String,
		status: EntryStatus,
	},
}

impl HashedFile {
	fn path(&self) -> &Path {
		match self {
			Self::Ok { path, .. } | Self::Fail { path, .. } => path,
		}
	}
}

fn hash_walk_entry(
	algorithm: &str,
	plan: &DirectoryHashPlan,
	path: PathBuf,
) -> HashedFile {
	let display_path = path.to_string_lossy().into_owned();
	let metadata = match fs::metadata(&path) {
		Ok(meta) => meta,
		Err(err) => {
			let status = match err.kind() {
				io::ErrorKind::PermissionDenied => {
					EntryStatus::Skipped
				}
				_ => EntryStatus::Error,
			};
			return HashedFile::Fail {
				path,
				message: format!(
					"failed to read metadata for {}: {}",
					display_path, err
				),
				status,
			};
		}
	};
	let size = metadata.len();
	let modified = metadata.modified().ok().map(DateTime::<Utc>::from);
	let use_mmap = plan.should_use_mmap(size);
	let mut engine = match RHash::new(algorithm) {
		Ok(engine) => engine,
		Err(err) => {
			return HashedFile::Fail {
				path,
				message: format!(
					"failed to initialize hasher for {}: {}",
					display_path, err
				),
				status: EntryStatus::Error,
			};
		}
	};
	match engine.hash_path(&path, use_mmap) {
		Ok(digest_bytes) => HashedFile::Ok {
			path,
			digest_bytes,
			size,
			modified,
			used_mmap: use_mmap,
		},
		Err(err) => HashedFile::Fail {
			path,
			message: format!(
				"failed to hash {}: {}",
				display_path, err
			),
			status: entry_status_from_error(err.as_ref()),
		},
	}
}

fn worker_threads(strategy: ThreadStrategy) -> usize {
	match strategy {
		ThreadStrategy::Single => 1,
		ThreadStrategy::Auto => {
			std::thread::available_parallelism()
				.map(|n| n.get())
				.unwrap_or(1)
		}
		ThreadStrategy::Fixed(n) => u16::max(n, 1) as usize,
	}
}

fn digest_with_options_internal(
	options: &FileDigestOptions,
	mut emitter: Option<&mut ProgressEmitter>,
) -> Result<
	(ManifestOutcome, Vec<DigestRecord>),
	Box<dyn std::error::Error>,
> {
	let algorithm_upper = options.algorithm_uppercase();
	let walker = Walker::new(options.plan.clone());
	let entries = walker.walk()?;
	let mut writer = ManifestWriter::new(
		options.plan.clone(),
		options.error_profile.clone(),
	);
	let mut records = Vec::new();
	let started = Instant::now();
	let thread_count = worker_threads(options.plan.threads);

	let mut hashed: Vec<HashedFile> =
		if matches!(options.plan.threads, ThreadStrategy::Single) {
			entries
				.into_iter()
				.map(|entry| {
					hash_walk_entry(
						&algorithm_upper,
						&options.plan,
						entry.path,
					)
				})
				.collect()
		} else {
			let mut builder = rayon::ThreadPoolBuilder::new();
			if let ThreadStrategy::Fixed(n) = options.plan.threads {
				builder = builder.num_threads(u16::max(n, 1) as usize);
			}
			let pool = builder.build()?;
			pool.install(|| {
				entries
					.into_par_iter()
					.map(|entry| {
						hash_walk_entry(
							&algorithm_upper,
							&options.plan,
							entry.path,
						)
					})
					.collect()
			})
		};
	hashed.sort_by(|a, b| a.path().cmp(b.path()));

	let mut mmap_active = false;
	let mut hashed_bytes = 0u64;
	for item in hashed {
		match item {
			HashedFile::Fail {
				path,
				message,
				status,
			} => {
				eprintln!("{}", message);
				let should_continue = writer.record_failure(
					path,
					&options.algorithm,
					message,
					status,
				);
				if !should_continue {
					break;
				}
			}
			HashedFile::Ok {
				path,
				digest_bytes,
				size,
				modified,
				used_mmap,
			} => {
				mmap_active |= used_mmap;
				hashed_bytes = hashed_bytes.saturating_add(size);
				let display_path = path.to_string_lossy();
				let record = DigestRecord::from_digest(
					Some(display_path.to_string()),
					&options.algorithm,
					&digest_bytes,
					DigestSource::File,
				);
				if let Some(emitter) = emitter.as_mut() {
					emitter.record(size);
					emitter.maybe_emit();
				}
				let mut manifest_digest = record.digest_hex.clone();
				if options.format == DigestOutputFormat::Multihash {
					let algorithm =
						options.algorithm.to_ascii_lowercase();
					match MultihashEncoder::encode(
						&algorithm,
						&digest_bytes,
					) {
						Ok(token) => manifest_digest = token,
						Err(err) => eprintln!(
							"warning: failed to encode multihash for manifest entry {}: {}",
							display_path,
							err
						),
					}
				}
				records.push(record);
				writer.record_success(
					path,
					&options.algorithm,
					manifest_digest,
					size,
					modified,
				);
			}
		}
	}

	let elapsed = started.elapsed();
	let elapsed_ms = elapsed.as_millis() as u64;
	let secs = elapsed.as_secs_f64();
	let bytes_per_second = if secs > 0.0 {
		hashed_bytes as f64 / secs
	} else {
		0.0
	};
	writer.set_performance(PerformanceEnvelope {
		elapsed_ms,
		bytes_per_second,
		threads: thread_count,
		mmap_active,
	});

	Ok((writer.finalize(), records))
}

fn write_manifest(
	path: &PathBuf,
	summary: &ManifestSummary,
) -> Result<(), Box<dyn std::error::Error>> {
	if let Some(parent) = path.parent() {
		if !parent.as_os_str().is_empty() {
			fs::create_dir_all(parent)?;
		}
	}
	let file = File::create(path)?;
	to_writer_pretty(file, summary)?;
	Ok(())
}

enum CompareInput {
	Manifest(ManifestSummary),
	Lines(Vec<String>),
}

pub fn compare_file_hashes(
	baseline: &str,
	candidate: &str,
) -> Result<CompareSummary, Box<dyn std::error::Error>> {
	let baseline_path = Path::new(baseline);
	let candidate_path = Path::new(candidate);
	let baseline_input = load_compare_input(baseline_path)?;
	let candidate_input = load_compare_input(candidate_path)?;
	match (baseline_input, candidate_input) {
		(
			CompareInput::Manifest(left),
			CompareInput::Manifest(right),
		) => Ok(compare_manifests(left, right)),
		(CompareInput::Lines(left), CompareInput::Lines(right)) => {
			Ok(compare_line_lists(left, right))
		}
		(CompareInput::Manifest(_), CompareInput::Lines(_))
		| (CompareInput::Lines(_), CompareInput::Manifest(_)) => {
			Err(io::Error::new(
				io::ErrorKind::InvalidInput,
				"Cannot compare manifest JSON with plain digest list",
			)
			.into())
		}
	}
}

fn load_compare_input(
	path: &Path,
) -> Result<CompareInput, Box<dyn std::error::Error>> {
	let contents = fs::read_to_string(path)?;
	match serde_json::from_str::<ManifestSummary>(&contents) {
		Ok(summary) => Ok(CompareInput::Manifest(summary)),
		Err(err) => {
			if contents.trim_start().starts_with('{') {
				return Err(Box::new(err));
			}
			let lines = contents
				.lines()
				.map(|line| line.trim_end_matches(['\r', '\n']))
				.map(|line| line.to_string())
				.collect();
			Ok(CompareInput::Lines(lines))
		}
	}
}

fn compare_manifests(
	left: ManifestSummary,
	right: ManifestSummary,
) -> CompareSummary {
	let mut differences = Vec::new();
	let mut incomplete = false;
	let mut right_map: HashMap<PathBuf, &ManifestEntry> = right
		.entries
		.iter()
		.map(|entry| (entry.path.clone(), entry))
		.collect();
	for entry in &left.entries {
		if entry.status != EntryStatus::Hashed
			|| entry.digest.is_none()
		{
			incomplete = true;
		}
		match right_map.remove(&entry.path) {
			Some(other) => {
				if other.status != EntryStatus::Hashed
					|| other.digest.is_none()
				{
					incomplete = true;
				}
				match (entry.digest.as_ref(), other.digest.as_ref()) {
					(Some(expected), Some(actual)) => {
						if expected != actual {
							let identifier =
								entry.path.display().to_string();
							differences.push(CompareDifference {
								identifier,
								kind: CompareDiffKind::Changed,
								expected: Some(expected.clone()),
								actual: Some(actual.clone()),
							});
						}
					}
					(Some(expected), None) => {
						let identifier =
							entry.path.display().to_string();
						differences.push(CompareDifference {
							identifier,
							kind: CompareDiffKind::Changed,
							expected: Some(expected.clone()),
							actual: None,
						});
						incomplete = true;
					}
					(None, Some(actual)) => {
						let identifier =
							entry.path.display().to_string();
						differences.push(CompareDifference {
							identifier,
							kind: CompareDiffKind::Changed,
							expected: None,
							actual: Some(actual.clone()),
						});
						incomplete = true;
					}
					(None, None) => {
						incomplete = true;
					}
				}
			}
			None => {
				let identifier = entry.path.display().to_string();
				differences.push(CompareDifference {
					identifier,
					kind: CompareDiffKind::MissingRight,
					expected: entry.digest.clone(),
					actual: None,
				});
			}
		}
	}

	for entry in right_map.values() {
		let identifier = entry.path.display().to_string();
		differences.push(CompareDifference {
			identifier,
			kind: CompareDiffKind::MissingLeft,
			expected: None,
			actual: entry.digest.clone(),
		});
		if entry.status != EntryStatus::Hashed
			|| entry.digest.is_none()
		{
			incomplete = true;
		}
	}

	if left.failure_count > 0 || right.failure_count > 0 {
		incomplete = true;
	}

	let mut exit_code = 0;
	let has_mismatch = differences.iter().any(|diff| {
		matches!(
			diff.kind,
			CompareDiffKind::Changed
				| CompareDiffKind::MissingLeft
				| CompareDiffKind::MissingRight
		)
	});
	if has_mismatch {
		exit_code = 1;
	} else if incomplete {
		exit_code = 2;
	}

	differences.sort_by(|a, b| a.identifier.cmp(&b.identifier));

	CompareSummary {
		mode: CompareMode::Manifest,
		differences,
		exit_code,
		incomplete,
		left_failures: left.failure_count,
		right_failures: right.failure_count,
		left_entries: left.entries.len(),
		right_entries: right.entries.len(),
	}
}

fn compare_line_lists(
	left: Vec<String>,
	right: Vec<String>,
) -> CompareSummary {
	let mut differences = Vec::new();
	let max_len = left.len().max(right.len());
	for idx in 0..max_len {
		let left_line = left.get(idx);
		let right_line = right.get(idx);
		match (left_line, right_line) {
			(Some(expected), Some(actual)) => {
				if expected != actual {
					differences.push(CompareDifference {
						identifier: format!("line {}", idx + 1),
						kind: CompareDiffKind::Changed,
						expected: Some(expected.clone()),
						actual: Some(actual.clone()),
					});
				}
			}
			(Some(expected), None) => {
				differences.push(CompareDifference {
					identifier: format!("line {}", idx + 1),
					kind: CompareDiffKind::MissingRight,
					expected: Some(expected.clone()),
					actual: None,
				});
			}
			(None, Some(actual)) => {
				differences.push(CompareDifference {
					identifier: format!("line {}", idx + 1),
					kind: CompareDiffKind::MissingLeft,
					expected: None,
					actual: Some(actual.clone()),
				});
			}
			(None, None) => {}
		}
	}

	let exit_code = if differences.is_empty() { 0 } else { 1 };

	CompareSummary {
		mode: CompareMode::Text,
		differences,
		exit_code,
		incomplete: false,
		left_failures: 0,
		right_failures: 0,
		left_entries: left.len(),
		right_entries: right.len(),
	}
}

fn entry_status_from_error(
	err: &(dyn std::error::Error + 'static),
) -> EntryStatus {
	if let Some(io_err) = err.downcast_ref::<io::Error>() {
		return match io_err.kind() {
			io::ErrorKind::PermissionDenied => EntryStatus::Skipped,
			_ => EntryStatus::Error,
		};
	}
	EntryStatus::Error
}
