// SPDX-License-Identifier: MIT OR Apache-2.0
// Project: rustgenhash
// File: key.rs
// Author: Volker Schwaberow <volker@schwaberow.de>

//! Helper utilities for loading MAC keys from files, stdin, or inline values.

use std::fs;
use std::io::{self, Read};

use super::registry::{MacError, MacErrorKind};
use zeroize::Zeroizing;

const AES_CMAC_KEY_LENGTHS: &[usize] = &[16, 24, 32];
const POLY1305_KEY_LENGTH: usize = 32;

#[derive(Debug)]
pub enum KeySource {
	File(std::path::PathBuf),
	Stdin,
	Inline(Zeroizing<Vec<u8>>),
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
				Ok(bytes.as_slice().to_vec())
			}
		}
	}
}

/// Validates that the provided key length is suitable for AES-CMAC.
pub fn validate_cmac_key_length(key: &[u8]) -> Result<(), MacError> {
	if AES_CMAC_KEY_LENGTHS.contains(&key.len()) {
		Ok(())
	} else {
		Err(MacError::new(
			MacErrorKind::InvalidKeyLength,
			// NOTE: audit fixture `mac_cmac_padding_mismatch` asserts this error string.
			format!(
				"Invalid CMAC key length: expected 16, 24, or 32 bytes but received {}",
				key.len()
			),
		))
	}
}

/// Validates the Poly1305 one-time key length requirement.
pub fn validate_poly1305_key_length(
	key: &[u8],
) -> Result<(), MacError> {
	if key.len() == POLY1305_KEY_LENGTH {
		Ok(())
	} else {
		Err(MacError::new(
			MacErrorKind::InvalidKeyLength,
			// NOTE: audit fixture `mac_poly1305_mismatched_key` relies on this verbatim message.
			format!(
				"Poly1305 requires a 32-byte one-time key but received {} bytes",
				key.len()
			),
		))
	}
}
