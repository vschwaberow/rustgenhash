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
	Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize,
)]
#[serde(rename_all = "lowercase")]
pub enum HistoryRetention {
	Off,
	Sanitized,
	Verbatim,
}

impl HistoryRetention {
	pub fn is_enabled(&self) -> bool {
		!matches!(self, HistoryRetention::Off)
	}
}

impl Default for HistoryRetention {
	fn default() -> Self {
		HistoryRetention::Sanitized
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
}

impl ConsoleHistoryConfig {
	pub fn disabled() -> Self {
		Self {
			file_path: None,
			retention: HistoryRetention::Off,
			force_script_history: false,
		}
	}

	pub fn new(
		file_path: Option<PathBuf>,
		retention: HistoryRetention,
		force_script_history: bool,
	) -> Self {
		Self {
			file_path,
			retention,
			force_script_history,
		}
	}

	pub fn is_enabled(&self) -> bool {
		self.file_path.is_some() && self.retention.is_enabled()
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

const HISTORY_VERSION: u8 = 1;

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

#[derive(Debug, Clone, Serialize, Deserialize)]
struct PersistedHistoryEntry {
	timestamp: i64,
	command: String,
	exit_code: i32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct PersistedHistoryFile {
	version: u8,
	retention: HistoryRetention,
	entries: Vec<PersistedHistoryEntry>,
}

#[derive(Debug, Clone)]
pub struct HistoryRecord {
	pub timestamp: SystemTime,
	pub command: String,
	pub exit_code: i32,
}

#[derive(Debug, Clone)]
pub struct HistorySnapshot {
	pub retention: HistoryRetention,
	pub entries: Vec<HistoryRecord>,
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
	let file: PersistedHistoryFile = serde_json::from_str(&data)
		.map_err(|err| HistoryError::Parse(err.to_string()))?;
	let entries = file
		.entries
		.into_iter()
		.map(|entry| HistoryRecord {
			timestamp: UNIX_EPOCH
				+ Duration::from_secs(entry.timestamp as u64),
			command: entry.command,
			exit_code: entry.exit_code,
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
	let file = PersistedHistoryFile {
		version: HISTORY_VERSION,
		retention,
		entries: entries
			.iter()
			.map(|entry| PersistedHistoryEntry {
				timestamp: entry
					.timestamp
					.duration_since(UNIX_EPOCH)
					.unwrap_or_else(|_| Duration::from_secs(0))
					.as_secs() as i64,
				command: entry.command.clone(),
				exit_code: entry.exit_code,
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
			while let Some(next) = chars.next() {
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
