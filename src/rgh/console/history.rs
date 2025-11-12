// SPDX-License-Identifier: MIT OR Apache-2.0
// Project: rustgenhash
// File: history.rs
// Author: Volker Schwaberow <volker@schwaberow.de>
// Copyright (c) 2022 Volker Schwaberow

use serde::{Deserialize, Serialize};
use std::env;
use std::fmt;
use std::fs;
use std::io::{self, Write};
use std::path::{Path, PathBuf};
use std::str::FromStr;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

/// Retention level for persisted console history.
#[derive(
	Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default,
)]
#[serde(rename_all = "lowercase")]
pub enum HistoryRetention {
	Off,
	#[default]
	Sanitized,
	Verbatim,
}

impl HistoryRetention {
	pub fn is_enabled(&self) -> bool {
		!matches!(self, HistoryRetention::Off)
	}
}

impl fmt::Display for HistoryRetention {
	fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
		let label = match self {
			HistoryRetention::Off => "off",
			HistoryRetention::Sanitized => "sanitized",
			HistoryRetention::Verbatim => "verbatim",
		};
		f.write_str(label)
	}
}

impl FromStr for HistoryRetention {
	type Err = String;

	fn from_str(s: &str) -> Result<Self, Self::Err> {
		match s.to_ascii_lowercase().as_str() {
			"off" => Ok(HistoryRetention::Off),
			"sanitized" => Ok(HistoryRetention::Sanitized),
			"verbatim" => Ok(HistoryRetention::Verbatim),
			other => Err(format!(
				"unsupported history retention `{}`",
				other
			)),
		}
	}
}

/// CLI-level configuration for history persistence.
#[derive(Debug, Clone)]
pub struct ConsoleHistoryConfig {
	pub file_path: Option<PathBuf>,
	pub retention: HistoryRetention,
	pub force_script_history: bool,
	pub max_in_memory: usize,
	pub max_persisted: usize,
}

impl ConsoleHistoryConfig {
	pub fn disabled() -> Self {
		Self {
			file_path: None,
			retention: HistoryRetention::Off,
			force_script_history: false,
			max_in_memory: DEFAULT_MAX_IN_MEMORY,
			max_persisted: DEFAULT_MAX_PERSISTED,
		}
	}

	pub fn new(
		file_path: Option<PathBuf>,
		retention: HistoryRetention,
		force_script_history: bool,
	) -> Self {
		Self::with_limits(
			file_path,
			retention,
			force_script_history,
			DEFAULT_MAX_IN_MEMORY,
			DEFAULT_MAX_PERSISTED,
		)
	}

	pub fn with_limits(
		file_path: Option<PathBuf>,
		retention: HistoryRetention,
		force_script_history: bool,
		max_in_memory: usize,
		max_persisted: usize,
	) -> Self {
		let max_persisted = max_persisted.max(1);
		let max_in_memory = max_in_memory.max(1).min(max_persisted);
		Self {
			file_path,
			retention,
			force_script_history,
			max_in_memory,
			max_persisted,
		}
	}

	pub fn is_enabled(&self) -> bool {
		self.file_path.is_some() && self.retention.is_enabled()
	}

	pub fn limits(&self) -> (usize, usize) {
		(self.max_in_memory, self.max_persisted)
	}
}

/// Preferred default location for console history when the user opts in.
pub fn default_history_path() -> Option<PathBuf> {
	fn base_dir() -> Option<PathBuf> {
		#[cfg(windows)]
		{
			if let Some(appdata) = env::var_os("APPDATA") {
				return Some(PathBuf::from(appdata));
			}
			return env::var_os("HOME").map(PathBuf::from);
		}

		#[cfg(not(windows))]
		{
			if let Some(xdg) = env::var_os("XDG_CONFIG_HOME") {
				return Some(PathBuf::from(xdg));
			}
			env::var_os("HOME")
				.map(PathBuf::from)
				.map(|home| home.join(".config"))
		}
	}

	base_dir()
		.map(|root| root.join("rgh").join("console-history.json"))
}

/// Maximum number of entries retained in-memory per session.
pub const DEFAULT_MAX_IN_MEMORY: usize = 200;
/// Maximum number of entries persisted to disk.
pub const DEFAULT_MAX_PERSISTED: usize = 500;

const HISTORY_VERSION: u8 = 2;

#[derive(
	Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default,
)]
#[serde(rename_all = "lowercase")]
pub enum HistoryExecutionStatus {
	#[default]
	Success,
	Error,
	Cancelled,
}

#[derive(
	Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default,
)]
#[serde(rename_all = "lowercase")]
pub enum HistoryOrigin {
	#[default]
	Live,
	Persisted,
}

impl HistoryExecutionStatus {
	pub fn from_exit_code(exit_code: i32) -> Self {
		match exit_code {
			0 => Self::Success,
			code if code < 0 => Self::Cancelled,
			_ => Self::Error,
		}
	}
}

#[derive(Debug)]
pub enum HistoryError {
	Io(io::Error),
	Parse(String),
}

impl fmt::Display for HistoryError {
	fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
		match self {
			Self::Io(err) => write!(f, "{}", err),
			Self::Parse(msg) => write!(f, "{}", msg),
		}
	}
}

impl std::error::Error for HistoryError {}

impl From<io::Error> for HistoryError {
	fn from(value: io::Error) -> Self {
		Self::Io(value)
	}
}

fn default_history_version() -> u8 {
	0
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct PersistedHistoryEntry {
	timestamp: i64,
	command: String,
	exit_code: i32,
	#[serde(default)]
	execution_status: HistoryExecutionStatus,
	#[serde(default)]
	replay_of: Option<String>,
	#[serde(default)]
	origin: HistoryOrigin,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct PersistedHistoryFile {
	#[serde(default = "default_history_version")]
	version: u8,
	retention: HistoryRetention,
	entries: Vec<PersistedHistoryEntry>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct LegacyHistoryEntry {
	timestamp: i64,
	command: String,
	exit_code: i32,
}

#[derive(Debug, Clone)]
pub struct HistoryRecord {
	pub timestamp: SystemTime,
	pub command: String,
	pub exit_code: i32,
	pub execution_status: HistoryExecutionStatus,
	pub replay_of: Option<String>,
	pub origin: HistoryOrigin,
}

#[derive(Debug, Clone)]
pub struct HistorySnapshot {
	pub retention: HistoryRetention,
	pub entries: Vec<HistoryRecord>,
}

fn parse_persisted_file(
	data: &str,
) -> Result<PersistedHistoryFile, HistoryError> {
	match serde_json::from_str::<PersistedHistoryFile>(data) {
		Ok(file) => Ok(file),
		Err(primary_err) => {
			let legacy: Result<Vec<LegacyHistoryEntry>, _> =
				serde_json::from_str(data);
			match legacy {
				Ok(entries) => Ok(PersistedHistoryFile {
					version: 0,
					retention: HistoryRetention::Sanitized,
					entries: entries
						.into_iter()
						.map(|entry| PersistedHistoryEntry {
							timestamp: entry.timestamp,
							command: entry.command,
							exit_code: entry.exit_code,
							execution_status:
								HistoryExecutionStatus::from_exit_code(
									entry.exit_code,
								),
							replay_of: None,
							origin: HistoryOrigin::Persisted,
						})
						.collect(),
				}),
				Err(_) => {
					Err(HistoryError::Parse(primary_err.to_string()))
				}
			}
		}
	}
}

fn prune_to_limit<T>(entries: &mut Vec<T>, max_entries: usize) {
	if entries.len() > max_entries {
		let excess = entries.len() - max_entries;
		entries.drain(0..excess);
	}
}

pub fn load_snapshot(
	path: &Path,
) -> Result<HistorySnapshot, HistoryError> {
	let data = match fs::read_to_string(path) {
		Ok(content) => content,
		Err(err) if err.kind() == io::ErrorKind::NotFound => {
			return Ok(HistorySnapshot {
				retention: HistoryRetention::Off,
				entries: Vec::new(),
			})
		}
		Err(err) => return Err(HistoryError::Io(err)),
	};
	if data.trim().is_empty() {
		return Ok(HistorySnapshot {
			retention: HistoryRetention::Off,
			entries: Vec::new(),
		});
	}
	let mut file = parse_persisted_file(&data)?;
	prune_to_limit(&mut file.entries, DEFAULT_MAX_PERSISTED);
	let entries = file
		.entries
		.into_iter()
		.map(|entry| {
			let status = if entry.execution_status
				== HistoryExecutionStatus::default()
				&& entry.exit_code != 0
			{
				HistoryExecutionStatus::from_exit_code(
					entry.exit_code,
				)
			} else {
				entry.execution_status
			};
			let origin =
				if matches!(entry.origin, HistoryOrigin::Live) {
					HistoryOrigin::Persisted
				} else {
					entry.origin
				};
			HistoryRecord {
				timestamp: UNIX_EPOCH
					+ Duration::from_secs(entry.timestamp as u64),
				command: entry.command,
				exit_code: entry.exit_code,
				execution_status: status,
				replay_of: entry.replay_of,
				origin,
			}
		})
		.collect();
	Ok(HistorySnapshot {
		retention: file.retention,
		entries,
	})
}

pub fn save_snapshot(
	path: &Path,
	retention: HistoryRetention,
	entries: &[HistoryRecord],
) -> Result<(), HistoryError> {
	if let Some(parent) = path.parent() {
		fs::create_dir_all(parent)?;
	}
	let limited = if entries.len() > DEFAULT_MAX_PERSISTED {
		entries
			.iter()
			.skip(entries.len() - DEFAULT_MAX_PERSISTED)
			.cloned()
			.collect::<Vec<_>>()
	} else {
		entries.to_vec()
	};
	let file = PersistedHistoryFile {
		version: HISTORY_VERSION,
		retention,
		entries: limited
			.iter()
			.map(|entry| PersistedHistoryEntry {
				timestamp: entry
					.timestamp
					.duration_since(UNIX_EPOCH)
					.unwrap_or_else(|_| Duration::from_secs(0))
					.as_secs() as i64,
				command: entry.command.clone(),
				exit_code: entry.exit_code,
				execution_status: entry.execution_status,
				replay_of: entry.replay_of.clone(),
				origin: HistoryOrigin::Persisted,
			})
			.collect(),
	};
	let data = serde_json::to_vec_pretty(&file)
		.map_err(|err| HistoryError::Parse(err.to_string()))?;
	let tmp_path = path.with_extension("tmp");
	{
		let mut file = fs::File::create(&tmp_path)?;
		file.write_all(&data)?;
		file.sync_all()?;
	}
	fs::rename(&tmp_path, path)?;
	Ok(())
}

#[allow(dead_code)]
/// Sanitize a raw console command by redacting quoted literals so secrets do not leak
/// into persisted history when sanitized mode is active.
pub fn sanitize_command(raw: &str) -> String {
	let mut sanitized = String::with_capacity(raw.len());
	let mut chars = raw.chars().peekable();
	while let Some(ch) = chars.next() {
		if ch == '"' || ch == '\'' {
			let quote = ch;
			sanitized.push(quote);
			let mut redacted = false;
			for next in chars.by_ref() {
				if next == quote {
					redacted = true;
					break;
				}
			}
			if redacted {
				sanitized.push_str("******");
				sanitized.push(quote);
			} else {
				sanitized.push_str("******");
			}
		} else {
			sanitized.push(ch);
		}
	}
	sanitized
}
