// SPDX-License-Identifier: MIT OR Apache-2.0
// Project: rustgenhash
// File: src/rgh/kdf/mod.rs
// Author: rustgenhash maintainers
//
// Password-based key derivation command group.

use std::fs;
use std::io::{self, Read};
use std::path::Path;
use zeroize::Zeroizing;

pub mod commands;
pub mod hkdf;
pub mod profile;

/// Wrapper for secret byte buffers (passwords, PRKs, IKM) that guarantees
/// zeroization on drop.
#[derive(Debug)]
pub struct SecretMaterial {
	inner: Zeroizing<Vec<u8>>,
}

impl SecretMaterial {
	/// Creates a new instance from raw bytes.
	pub fn from_bytes(bytes: Vec<u8>) -> Self {
		Self {
			inner: Zeroizing::new(bytes),
		}
	}

	/// Loads secret material from a file path.
	pub fn from_file(path: &Path) -> Result<Self, io::Error> {
		let bytes = fs::read(path)?;
		Ok(Self::from_bytes(bytes))
	}

	/// Reads secret material from stdin until EOF.
	pub fn from_stdin() -> Result<Self, io::Error> {
		let mut buffer = Vec::new();
		io::stdin().read_to_end(&mut buffer)?;
		Ok(Self::from_bytes(buffer))
	}

	pub fn as_slice(&self) -> &[u8] {
		self.inner.as_slice()
	}

	pub fn is_empty(&self) -> bool {
		self.inner.is_empty()
	}

	pub fn len(&self) -> usize {
		self.inner.len()
	}

	pub fn into_bytes(self) -> Vec<u8> {
		let mut output = Vec::with_capacity(self.inner.len());
		output.extend_from_slice(self.inner.as_slice());
		output
	}
}
