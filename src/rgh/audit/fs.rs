// SPDX-License-Identifier: MIT OR Apache-2.0
// Project: rustgenhash
// File: fs.rs
// Author: Volker Schwaberow <volker@schwaberow.de>
// Copyright (c) 2022 Volker Schwaberow

use std::ffi::OsStr;
use std::fs;
use std::path::{Path, PathBuf};

use regex::Regex;

use super::AuditError;

pub fn fixtures_root() -> PathBuf {
	PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures")
}

pub fn collect_fixture_paths(
	case_filter: Option<&str>,
) -> Result<Vec<PathBuf>, AuditError> {
	let root = fixtures_root();
	let mut files = Vec::new();
	collect_recursive(&root, &mut files)?;
	files.sort();
	if let Some(filter) = case_filter {
		let matcher = if filter.contains('*') || filter.contains('?')
		{
			let escaped = regex::escape(filter)
				.replace("\\*", ".*")
				.replace("\\?", ".");
			Some(Regex::new(&format!("^{}$", escaped)).map_err(
				|source| {
					AuditError::Invalid(format!(
						"Invalid fixture filter `{}`: {}",
						filter, source
					))
				},
			)?)
		} else {
			None
		};

		let filtered: Vec<PathBuf> = files
			.into_iter()
			.filter(|path| {
				path.file_stem()
					.and_then(OsStr::to_str)
					.map(|stem| {
						if let Some(regex) = &matcher {
							regex.is_match(stem)
						} else {
							stem == filter
						}
					})
					.unwrap_or(false)
			})
			.collect();
		return Ok(filtered);
	}
	Ok(files)
}

fn collect_recursive(
	dir: &Path,
	paths: &mut Vec<PathBuf>,
) -> Result<(), AuditError> {
	for entry in
		fs::read_dir(dir).map_err(|source| AuditError::Io {
			source,
			path: dir.to_path_buf(),
		})? {
		let entry = entry.map_err(|source| AuditError::Io {
			source,
			path: dir.to_path_buf(),
		})?;
		let meta =
			entry.metadata().map_err(|source| AuditError::Io {
				source,
				path: entry.path(),
			})?;
		let path = entry.path();
		if meta.is_dir() {
			collect_recursive(&path, paths)?;
			continue;
		}
		if path.extension() == Some(OsStr::new("json")) {
			paths.push(path);
		}
	}
	Ok(())
}

pub fn ensure_output_root() -> Result<PathBuf, AuditError> {
	let path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
		.join("target/audit");
	fs::create_dir_all(&path).map_err(|source| AuditError::Io {
		source,
		path: path.clone(),
	})?;
	Ok(path)
}

pub fn ensure_issues_dir() -> Result<PathBuf, AuditError> {
	let root = ensure_output_root()?;
	let issues = root.join("issues");
	fs::create_dir_all(&issues).map_err(|source| AuditError::Io {
		source,
		path: issues.clone(),
	})?;
	Ok(issues)
}
