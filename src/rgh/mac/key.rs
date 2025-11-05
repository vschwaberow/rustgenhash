// SPDX-License-Identifier: MIT OR Apache-2.0
// Project: rustgenhash
// File: key.rs
// Author: Volker Schwaberow <volker@schwaberow.de>

//! Helper utilities for loading MAC keys from files, stdin, or inline values.

use std::fs;
use std::io::{self, Read};

use super::registry::{MacError, MacErrorKind};

#[derive(Debug)]
pub enum KeySource {
	File(std::path::PathBuf),
	Stdin,
	Inline(Vec<u8>),
}

impl KeySource {
	pub fn description(&self) -> &'static str {
		match self {
			KeySource::File(_) => "file",
			KeySource::Stdin => "stdin",
			KeySource::Inline(_) => "inline",
		}
	}
}

pub fn load_key(source: &KeySource) -> Result<Vec<u8>, MacError> {
	match source {
		KeySource::File(path) => fs::read(path).map_err(|err| {
			MacError::new(
				MacErrorKind::InvalidKey,
				format!(
					"failed to read key file `{}`: {}",
					path.display(),
					err
				),
			)
		}),
		KeySource::Stdin => {
			let mut buf = Vec::new();
			io::stdin().read_to_end(&mut buf).map_err(|err| {
				MacError::new(
					MacErrorKind::InvalidKey,
					format!("failed to read key from stdin: {}", err),
				)
			})?;
			if buf.is_empty() {
				Err(MacError::new(
					MacErrorKind::InvalidKey,
					"stdin key input was empty",
				))
			} else {
				Ok(buf)
			}
		}
		KeySource::Inline(bytes) => {
			if bytes.is_empty() {
				Err(MacError::new(
					MacErrorKind::InvalidKey,
					"inline key must not be empty",
				))
			} else {
				Ok(bytes.clone())
			}
		}
	}
}
