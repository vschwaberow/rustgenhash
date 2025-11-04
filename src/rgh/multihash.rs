// SPDX-License-Identifier: MIT OR Apache-2.0
// Project: rustgenhash
// Module: multihash support
// Purpose: Map CLI algorithms to multicodec codes and expose an encoder that produces
//          base58btc multihash strings.
// Author: Volker Schwaberow <volker@schwaberow.de>
// Copyright (c) 2025 Volker Schwaberow

use multibase::Base;
use multihash::{Code, MultihashDigest};
use std::borrow::Cow;
use std::fmt;

/// Declarative mapping between CLI algorithm identifiers and multicodec metadata.
pub struct MulticodecSupportMatrix;

impl MulticodecSupportMatrix {
	pub const fn entries() -> &'static [MulticodecEntry] {
		ENTRIES
	}

	pub const fn algorithm_names() -> &'static [&'static str] {
		SUPPORTED_ALGORITHMS
	}

	pub fn lookup(
		algorithm: &str,
	) -> Option<&'static MulticodecEntry> {
		let normalized = algorithm.to_ascii_lowercase();
		Self::entries()
			.iter()
			.find(|entry| entry.algorithm == normalized)
	}
}

/// Single multicodec mapping entry.
#[derive(Clone, Copy, Debug)]
pub struct MulticodecEntry {
	pub algorithm: &'static str,
	pub code: Code,
	pub expected_digest_len: usize,
	pub description: &'static str,
}

/// Error type for multihash encoding failures.
#[derive(Debug)]
pub enum MultihashError {
	UnsupportedAlgorithm {
		algorithm: String,
	},
	InvalidDigestLength {
		algorithm: String,
		expected: usize,
		actual: usize,
	},
	EncodeFailure {
		algorithm: String,
		source: multihash::Error,
	},
}

impl fmt::Display for MultihashError {
	fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
		match self {
			Self::UnsupportedAlgorithm { algorithm } => {
				write!(
					f,
					"multihash format is unavailable for algorithm {}",
					algorithm
				)
			}
			Self::InvalidDigestLength {
				algorithm,
				expected,
				actual,
			} => write!(
				f,
				"multihash expected a {}-byte digest for {}, but received {} bytes",
				expected, algorithm, actual
			),
			Self::EncodeFailure { algorithm, source } => write!(
				f,
				"failed to wrap digest for {} into a multihash: {}",
				algorithm, source
			),
		}
	}
}

impl std::error::Error for MultihashError {
	fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
		match self {
			Self::EncodeFailure { source, .. } => Some(source),
			_ => None,
		}
	}
}

/// Convenience helper that wraps digest bytes into a base58btc multihash string.
pub struct MultihashEncoder;

impl MultihashEncoder {
	pub fn encode(
		algorithm: &str,
		digest: &[u8],
	) -> Result<String, MultihashError> {
		let entry = MulticodecSupportMatrix::lookup(algorithm)
			.ok_or_else(|| MultihashError::UnsupportedAlgorithm {
				algorithm: algorithm.to_string(),
			})?;

		let canonical_digest: Cow<'_, [u8]> = if digest.len()
			== entry.expected_digest_len
		{
			Cow::Borrowed(digest)
		} else if entry.algorithm == "blake2b"
			&& digest.len() == 64
			&& entry.expected_digest_len == 32
		{
			Cow::Owned(digest[..entry.expected_digest_len].to_vec())
		} else {
			return Err(MultihashError::InvalidDigestLength {
				algorithm: algorithm.to_string(),
				expected: entry.expected_digest_len,
				actual: digest.len(),
			});
		};

		let multihash = entry
			.code
			.wrap(canonical_digest.as_ref())
			.map_err(|source| MultihashError::EncodeFailure {
				algorithm: algorithm.to_string(),
				source,
			})?;

		Ok(multibase::encode(Base::Base58Btc, multihash.to_bytes()))
	}
}

const ENTRIES: &[MulticodecEntry] = &[
	MulticodecEntry {
		algorithm: "sha256",
		code: Code::Sha2_256,
		expected_digest_len: 32,
		description: "multihash code 0x12 (sha2-256)",
	},
	MulticodecEntry {
		algorithm: "sha512",
		code: Code::Sha2_512,
		expected_digest_len: 64,
		description: "multihash code 0x13 (sha2-512)",
	},
	MulticodecEntry {
		algorithm: "blake2b",
		code: Code::Blake2b256,
		expected_digest_len: 32,
		description: "multihash code 0xb220 (blake2b-256)",
	},
	MulticodecEntry {
		algorithm: "blake3",
		code: Code::Blake3_256,
		expected_digest_len: 32,
		description: "multihash code 0x1e (blake3-256)",
	},
];

const SUPPORTED_ALGORITHMS: &[&str] =
	&["sha256", "sha512", "blake2b", "blake3"];
