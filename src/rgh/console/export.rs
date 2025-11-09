// SPDX-License-Identifier: MIT OR Apache-2.0
// Project: rustgenhash
// File: export.rs
// Author: Volker Schwaberow <volker@schwaberow.de>
// Copyright (c) 2022 Volker Schwaberow

use super::variables::ConsoleVariable;
use serde::Serialize;
use std::fmt;
use std::fs;
use std::io::{self, Write};
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

#[derive(Debug)]
pub enum ExportError {
	Io(io::Error),
	Serialize(String),
}

impl From<io::Error> for ExportError {
	fn from(value: io::Error) -> Self {
		Self::Io(value)
	}
}

impl fmt::Display for ExportError {
	fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
		match self {
			Self::Io(err) => write!(f, "{}", err),
			Self::Serialize(msg) => write!(f, "{}", msg),
		}
	}
}

impl std::error::Error for ExportError {}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ExportFormat {
	Json,
	Yaml,
}

impl ExportFormat {
	pub fn from_str(raw: &str) -> Option<Self> {
		match raw.to_ascii_lowercase().as_str() {
			"json" => Some(Self::Json),
			"yaml" | "yml" => Some(Self::Yaml),
			_ => None,
		}
	}
}

#[derive(Serialize)]
struct VariableRecord<'a> {
	name: &'a str,
	preview: String,
	value: Option<&'a str>,
	sensitive: bool,
	created_at: u64,
}

#[derive(Serialize)]
struct VariableManifest<'a> {
	format_version: u8,
	generated_at: u64,
	includes_secrets: bool,
	records: Vec<VariableRecord<'a>>,
}

pub fn write_manifest(
	path: &Path,
	vars: &[&ConsoleVariable],
	format: ExportFormat,
	include_secrets: bool,
) -> Result<(), ExportError> {
	if let Some(parent) = path.parent() {
		fs::create_dir_all(parent)?;
	}
	let now = SystemTime::now()
		.duration_since(UNIX_EPOCH)
		.unwrap_or_default()
		.as_secs();
	let mut records = Vec::with_capacity(vars.len());
	for var in vars {
		let created_at = var
			.created_at
			.duration_since(UNIX_EPOCH)
			.unwrap_or_default()
			.as_secs();
		records.push(VariableRecord {
			name: &var.name,
			preview: var.preview(),
			value: if include_secrets {
				Some(var.value.as_str())
			} else {
				None
			},
			sensitive: var.sensitive,
			created_at,
		});
	}
	let manifest = VariableManifest {
		format_version: 1,
		generated_at: now,
		includes_secrets: include_secrets,
		records,
	};
	let tmp_path = path.with_extension("tmp");
	{
		let mut file = fs::File::create(&tmp_path)?;
		match format {
			ExportFormat::Json => {
				let data = serde_json::to_vec_pretty(&manifest)
					.map_err(|err| {
						ExportError::Serialize(err.to_string())
					})?;
				file.write_all(&data)?;
			}
			ExportFormat::Yaml => {
				let yaml = serde_yaml::to_string(&manifest).map_err(
					|err| ExportError::Serialize(err.to_string()),
				)?;
				file.write_all(yaml.as_bytes())?;
			}
		}
		file.sync_all()?;
	}
	fs::rename(&tmp_path, path)?;
	Ok(())
}

pub fn resolve_export_path(path: &str) -> PathBuf {
	PathBuf::from(path)
}
