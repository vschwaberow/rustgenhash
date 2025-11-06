// SPDX-License-Identifier: MIT OR Apache-2.0
// Project: rustgenhash
// File: hkdf.rs
// Author: rustgenhash maintainers

//! HKDF helpers for CLI and audit harness integration.

use hmac::digest::KeyInit;
use hmac::{Hmac, Mac};
use sha2::{Sha256, Sha512};
use sha3::{Sha3_256, Sha3_512};
use std::fmt;

type HmacSha256 = Hmac<Sha256>;
type HmacSha512 = Hmac<Sha512>;
type HmacSha3_256 = Hmac<Sha3_256>;
type HmacSha3_512 = Hmac<Sha3_512>;

/// Supported digest cores for HKDF output expansion.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HkdfAlgorithm {
	Sha256,
	Sha512,
	Sha3_256,
	Sha3_512,
}

impl HkdfAlgorithm {
	pub fn identifier(self) -> &'static str {
		match self {
			Self::Sha256 => "hkdf-sha256",
			Self::Sha512 => "hkdf-sha512",
			Self::Sha3_256 => "hkdf-sha3-256",
			Self::Sha3_512 => "hkdf-sha3-512",
		}
	}

	pub fn output_size(self) -> usize {
		match self {
			Self::Sha256 | Self::Sha3_256 => 32,
			Self::Sha512 | Self::Sha3_512 => 64,
		}
	}

	pub fn max_length(self) -> usize {
		255 * self.output_size()
	}
}

impl std::str::FromStr for HkdfAlgorithm {
	type Err = HkdfError;

	fn from_str(value: &str) -> Result<Self, Self::Err> {
		match value.to_lowercase().as_str() {
			"sha256" | "hkdf-sha256" => Ok(Self::Sha256),
			"sha512" | "hkdf-sha512" => Ok(Self::Sha512),
			"sha3-256" | "hkdf-sha3-256" => Ok(Self::Sha3_256),
			"sha3-512" | "hkdf-sha3-512" => Ok(Self::Sha3_512),
			other => {
				Err(HkdfError::InvalidAlgorithm(other.to_string()))
			}
		}
	}
}

/// Structured HKDF request.
#[derive(Debug, Clone)]
pub struct HkdfRequest {
	pub algorithm: HkdfAlgorithm,
	pub ikm: Vec<u8>,
	pub salt: Vec<u8>,
	pub info: Vec<u8>,
	pub length: usize,
}

/// Result metadata returned from HKDF derivation.
#[derive(Debug, Clone)]
pub struct HkdfResponse {
	pub algorithm: &'static str,
	pub derived_key: Vec<u8>,
	pub length: usize,
	pub ikm_length: usize,
	pub salt: Vec<u8>,
	pub info: Vec<u8>,
}

#[derive(Debug)]
pub enum HkdfError {
	InvalidAlgorithm(String),
	MissingIkm,
	InvalidLength {
		requested: usize,
		max: usize,
	},
	InvalidHex {
		field: &'static str,
		message: String,
	},
	ExpandFailure,
}

impl fmt::Display for HkdfError {
	fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
		match self {
			Self::InvalidAlgorithm(name) => {
				write!(f, "Unsupported HKDF hash `{}`", name)
			}
			Self::MissingIkm => {
				write!(f, "input keying material must not be empty")
			}
			Self::InvalidLength { requested, max } => {
				write!(
					f,
					"requested HKDF length {} exceeds maximum {}",
					requested, max
				)
			}
			Self::InvalidHex { field, message } => {
				write!(f, "{} must be valid hex: {}", field, message)
			}
			Self::ExpandFailure => {
				write!(
					f,
					"hkdf expand failed for requested output length"
				)
			}
		}
	}
}

impl std::error::Error for HkdfError {}

fn decode_hex_input(
	field: &'static str,
	value: Option<&str>,
) -> Result<Vec<u8>, HkdfError> {
	match value {
		Some("") => Ok(Vec::new()),
		Some(raw) => {
			hex::decode(raw).map_err(|err| HkdfError::InvalidHex {
				field,
				message: err.to_string(),
			})
		}
		None => Ok(Vec::new()),
	}
}

/// Parse optional hex strings for salt/info fields.
pub fn parse_optional_hex(
	field: &'static str,
	value: Option<&String>,
) -> Result<Vec<u8>, HkdfError> {
	decode_hex_input(field, value.map(|s| s.as_str()))
}

pub fn derive(
	request: &HkdfRequest,
) -> Result<HkdfResponse, HkdfError> {
	if request.ikm.is_empty() {
		return Err(HkdfError::MissingIkm);
	}
	if request.length == 0 {
		return Err(HkdfError::InvalidLength {
			requested: 0,
			max: request.algorithm.max_length(),
		});
	}
	let max = request.algorithm.max_length();
	if request.length > max {
		return Err(HkdfError::InvalidLength {
			requested: request.length,
			max,
		});
	}

	match request.algorithm {
		HkdfAlgorithm::Sha256 => derive_with_mac(
			request,
			HkdfAlgorithm::Sha256.identifier(),
			HkdfAlgorithm::Sha256.output_size(),
			|key| {
				<HmacSha256 as KeyInit>::new_from_slice(key)
					.map_err(|_| HkdfError::ExpandFailure)
			},
		),
		HkdfAlgorithm::Sha512 => derive_with_mac(
			request,
			HkdfAlgorithm::Sha512.identifier(),
			HkdfAlgorithm::Sha512.output_size(),
			|key| {
				<HmacSha512 as KeyInit>::new_from_slice(key)
					.map_err(|_| HkdfError::ExpandFailure)
			},
		),
		HkdfAlgorithm::Sha3_256 => derive_with_mac(
			request,
			HkdfAlgorithm::Sha3_256.identifier(),
			HkdfAlgorithm::Sha3_256.output_size(),
			|key| {
				<HmacSha3_256 as KeyInit>::new_from_slice(key)
					.map_err(|_| HkdfError::ExpandFailure)
			},
		),
		HkdfAlgorithm::Sha3_512 => derive_with_mac(
			request,
			HkdfAlgorithm::Sha3_512.identifier(),
			HkdfAlgorithm::Sha3_512.output_size(),
			|key| {
				<HmacSha3_512 as KeyInit>::new_from_slice(key)
					.map_err(|_| HkdfError::ExpandFailure)
			},
		),
	}
}

fn derive_with_mac<M, F>(
	request: &HkdfRequest,
	algorithm: &'static str,
	digest_len: usize,
	mut factory: F,
) -> Result<HkdfResponse, HkdfError>
where
	M: Mac,
	F: FnMut(&[u8]) -> Result<M, HkdfError>,
{
	let salt_bytes = if request.salt.is_empty() {
		vec![0u8; digest_len]
	} else {
		request.salt.clone()
	};
	let mut prk_mac = factory(&salt_bytes)?;
	prk_mac.update(&request.ikm);
	let prk_bytes = prk_mac.finalize().into_bytes().to_vec();

	let mut okm = vec![0u8; request.length];
	let mut prev_block: Vec<u8> = Vec::new();
	let mut generated = 0usize;
	let mut counter: u8 = 1;
	while generated < request.length {
		let mut mac = factory(&prk_bytes)?;
		if !prev_block.is_empty() {
			mac.update(&prev_block);
		}
		mac.update(&request.info);
		mac.update(&[counter]);
		let block = mac.finalize().into_bytes();
		let block_vec = block.to_vec();
		let write_len = std::cmp::min(
			block_vec.len(),
			request.length - generated,
		);
		okm[generated..generated + write_len]
			.copy_from_slice(&block_vec[..write_len]);
		prev_block = block_vec;
		generated += write_len;
		counter =
			counter.checked_add(1).ok_or(HkdfError::ExpandFailure)?;
	}

	Ok(HkdfResponse {
		algorithm,
		derived_key: okm,
		length: request.length,
		ikm_length: request.ikm.len(),
		salt: request.salt.clone(),
		info: request.info.clone(),
	})
}
