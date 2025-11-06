// SPDX-License-Identifier: MIT OR Apache-2.0
// Project: rustgenhash
// File: hkdf.rs
// Author: rustgenhash maintainers

//! HKDF helpers for CLI and audit harness integration.

use blake3::Hasher as Blake3Hasher;
use hmac::digest::KeyInit;
use hmac::Mac;
use hmac::SimpleHmac as Hmac;
use sha2::{Sha256, Sha512};
use sha3::{Sha3_256, Sha3_512};
use std::fmt;
use std::str::FromStr;
use zeroize::Zeroizing;

use super::SecretMaterial;

pub const EXPAND_ONLY_PRK_HINT: &str =
	"Expand-only mode requires --prk <PATH> or --prk-stdin";

type HmacSha256 = Hmac<Sha256>;
type HmacSha512 = Hmac<Sha512>;
type HmacSha3_256 = Hmac<Sha3_256>;
type HmacSha3_512 = Hmac<Sha3_512>;
type HmacBlake3 = Hmac<Blake3Hasher>;

/// Supported digest cores for HKDF output expansion.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HkdfAlgorithm {
	Sha256,
	Sha512,
	Sha3_256,
	Sha3_512,
	Blake3,
}

impl HkdfAlgorithm {
	pub fn identifier(self) -> &'static str {
		match self {
			Self::Sha256 => "hkdf-sha256",
			Self::Sha512 => "hkdf-sha512",
			Self::Sha3_256 => "hkdf-sha3-256",
			Self::Sha3_512 => "hkdf-sha3-512",
			Self::Blake3 => "hkdf-blake3",
		}
	}

	pub fn display_name(self) -> &'static str {
		match self {
			Self::Sha256 => "HKDF-SHA256",
			Self::Sha512 => "HKDF-SHA512",
			Self::Sha3_256 => "HKDF-SHA3-256",
			Self::Sha3_512 => "HKDF-SHA3-512",
			Self::Blake3 => "HKDF-BLAKE3",
		}
	}

	pub fn output_size(self) -> usize {
		match self {
			Self::Sha256 | Self::Sha3_256 | Self::Blake3 => 32,
			Self::Sha512 | Self::Sha3_512 => 64,
		}
	}

	pub fn max_length(self) -> usize {
		255 * self.output_size()
	}
}

impl FromStr for HkdfAlgorithm {
	type Err = HkdfError;

	fn from_str(value: &str) -> Result<Self, Self::Err> {
		match value.to_lowercase().as_str() {
			"sha256" | "hkdf-sha256" => Ok(Self::Sha256),
			"sha512" | "hkdf-sha512" => Ok(Self::Sha512),
			"sha3-256" | "hkdf-sha3-256" => Ok(Self::Sha3_256),
			"sha3-512" | "hkdf-sha3-512" => Ok(Self::Sha3_512),
			"blake3" | "hkdf-blake3" => Ok(Self::Blake3),
			other => {
				Err(HkdfError::InvalidAlgorithm(other.to_string()))
			}
		}
	}
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HkdfMode {
	ExtractAndExpand,
	ExpandOnly,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct HkdfVariant {
	pub algorithm: HkdfAlgorithm,
	pub mode: HkdfMode,
}

impl HkdfVariant {
	pub const fn new(
		algorithm: HkdfAlgorithm,
		mode: HkdfMode,
	) -> Self {
		Self { algorithm, mode }
	}

	pub fn identifier(self) -> &'static str {
		match (self.algorithm, self.mode) {
			(HkdfAlgorithm::Sha256, HkdfMode::ExtractAndExpand) => {
				"hkdf-sha256"
			}
			(HkdfAlgorithm::Sha512, HkdfMode::ExtractAndExpand) => {
				"hkdf-sha512"
			}
			(HkdfAlgorithm::Sha3_256, HkdfMode::ExtractAndExpand) => {
				"hkdf-sha3-256"
			}
			(HkdfAlgorithm::Sha3_512, HkdfMode::ExtractAndExpand) => {
				"hkdf-sha3-512"
			}
			(HkdfAlgorithm::Blake3, HkdfMode::ExtractAndExpand) => {
				"hkdf-blake3"
			}
			(HkdfAlgorithm::Sha256, HkdfMode::ExpandOnly) => {
				"hkdf-expand-sha256"
			}
			(HkdfAlgorithm::Sha512, HkdfMode::ExpandOnly) => {
				"hkdf-expand-sha512"
			}
			(HkdfAlgorithm::Sha3_256, HkdfMode::ExpandOnly) => {
				"hkdf-expand-sha3-256"
			}
			(HkdfAlgorithm::Sha3_512, HkdfMode::ExpandOnly) => {
				"hkdf-expand-sha3-512"
			}
			(HkdfAlgorithm::Blake3, HkdfMode::ExpandOnly) => {
				"hkdf-expand-blake3"
			}
		}
	}

	pub fn display_name(self) -> &'static str {
		match self.mode {
			HkdfMode::ExtractAndExpand => {
				self.algorithm.display_name()
			}
			HkdfMode::ExpandOnly => match self.algorithm {
				HkdfAlgorithm::Sha256 => "HKDF-EXPAND-SHA256",
				HkdfAlgorithm::Sha512 => "HKDF-EXPAND-SHA512",
				HkdfAlgorithm::Sha3_256 => "HKDF-EXPAND-SHA3-256",
				HkdfAlgorithm::Sha3_512 => "HKDF-EXPAND-SHA3-512",
				HkdfAlgorithm::Blake3 => "HKDF-EXPAND-BLAKE3",
			},
		}
	}

	pub fn output_size(self) -> usize {
		self.algorithm.output_size()
	}

	pub fn max_length(self) -> usize {
		self.algorithm.max_length()
	}

	pub fn requires_prk(self) -> bool {
		matches!(self.mode, HkdfMode::ExpandOnly)
	}

	pub fn requires_ikm(self) -> bool {
		matches!(self.mode, HkdfMode::ExtractAndExpand)
	}
}

pub const HKDF_VARIANTS: &[HkdfVariant] = &[
	HkdfVariant::new(
		HkdfAlgorithm::Sha256,
		HkdfMode::ExtractAndExpand,
	),
	HkdfVariant::new(
		HkdfAlgorithm::Sha512,
		HkdfMode::ExtractAndExpand,
	),
	HkdfVariant::new(
		HkdfAlgorithm::Sha3_256,
		HkdfMode::ExtractAndExpand,
	),
	HkdfVariant::new(
		HkdfAlgorithm::Sha3_512,
		HkdfMode::ExtractAndExpand,
	),
	HkdfVariant::new(
		HkdfAlgorithm::Blake3,
		HkdfMode::ExtractAndExpand,
	),
	HkdfVariant::new(HkdfAlgorithm::Sha256, HkdfMode::ExpandOnly),
	HkdfVariant::new(HkdfAlgorithm::Sha512, HkdfMode::ExpandOnly),
	HkdfVariant::new(HkdfAlgorithm::Sha3_256, HkdfMode::ExpandOnly),
	HkdfVariant::new(HkdfAlgorithm::Sha3_512, HkdfMode::ExpandOnly),
	HkdfVariant::new(HkdfAlgorithm::Blake3, HkdfMode::ExpandOnly),
];

pub enum HkdfInput {
	Extract(SecretMaterial),
	Expand(SecretMaterial),
}

/// Structured HKDF request.
pub struct HkdfRequest {
	pub variant: HkdfVariant,
	pub input: HkdfInput,
	pub salt: Vec<u8>,
	pub info: Vec<u8>,
	pub length: usize,
}

/// Result metadata returned from HKDF derivation.
#[derive(Debug, Clone)]
pub struct HkdfResponse {
	pub variant: HkdfVariant,
	pub derived_key: Vec<u8>,
	pub length: usize,
	pub ikm_length: usize,
	pub prk_length: usize,
	pub salt: Vec<u8>,
	pub info: Vec<u8>,
}

#[derive(Debug)]
pub enum HkdfError {
	InvalidAlgorithm(String),
	MissingIkm,
	MissingPrk,
	InvalidLength {
		requested: usize,
		max: usize,
	},
	InvalidHex {
		field: &'static str,
		message: String,
	},
	ModeMismatch,
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
			Self::MissingPrk => {
				write!(f, "expand-only mode requires a PRK input")
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
			Self::ModeMismatch => {
				write!(
					f,
					"HKDF mode does not match supplied material"
				)
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
	request: HkdfRequest,
) -> Result<HkdfResponse, HkdfError> {
	let HkdfRequest {
		variant,
		input,
		salt,
		info,
		length,
	} = request;

	if length == 0 {
		return Err(HkdfError::InvalidLength {
			requested: 0,
			max: variant.max_length(),
		});
	}
	let max = variant.max_length();
	if length > max {
		return Err(HkdfError::InvalidLength {
			requested: length,
			max,
		});
	}

	match variant.algorithm {
		HkdfAlgorithm::Sha256 => derive_with_hmac::<HmacSha256>(
			variant, input, salt, info, length,
		),
		HkdfAlgorithm::Sha512 => derive_with_hmac::<HmacSha512>(
			variant, input, salt, info, length,
		),
		HkdfAlgorithm::Sha3_256 => derive_with_hmac::<HmacSha3_256>(
			variant, input, salt, info, length,
		),
		HkdfAlgorithm::Sha3_512 => derive_with_hmac::<HmacSha3_512>(
			variant, input, salt, info, length,
		),
		HkdfAlgorithm::Blake3 => derive_with_hmac::<HmacBlake3>(
			variant, input, salt, info, length,
		),
	}
}

fn derive_with_hmac<M>(
	variant: HkdfVariant,
	input: HkdfInput,
	salt: Vec<u8>,
	info: Vec<u8>,
	length: usize,
) -> Result<HkdfResponse, HkdfError>
where
	M: Mac + Clone + KeyInit,
{
	let digest_len = variant.output_size();
	let mut ikm_length = 0usize;
	let (prk_bytes, prk_length): (Zeroizing<Vec<u8>>, usize) =
		match (variant.mode, input) {
			(
				HkdfMode::ExtractAndExpand,
				HkdfInput::Extract(material),
			) => {
				if material.is_empty() {
					return Err(HkdfError::MissingIkm);
				}
				ikm_length = material.len();
				let ikm = Zeroizing::new(material.into_bytes());
				let salt_bytes = if salt.is_empty() {
					vec![0u8; digest_len]
				} else {
					salt.clone()
				};
				let mut prk_mac =
					<M as KeyInit>::new_from_slice(&salt_bytes)
						.map_err(|_| HkdfError::ExpandFailure)?;
				prk_mac.update(&ikm);
				let prk_vec =
					prk_mac.finalize().into_bytes().to_vec();
				let len = prk_vec.len();
				(Zeroizing::new(prk_vec), len)
			}
			(HkdfMode::ExpandOnly, HkdfInput::Expand(material)) => {
				if material.is_empty() {
					return Err(HkdfError::MissingPrk);
				}
				let bytes = material.into_bytes();
				let len = bytes.len();
				(Zeroizing::new(bytes), len)
			}
			(HkdfMode::ExtractAndExpand, HkdfInput::Expand(_))
			| (HkdfMode::ExpandOnly, HkdfInput::Extract(_)) => {
				return Err(HkdfError::ModeMismatch)
			}
		};

	let mut okm = vec![0u8; length];
	let mut prev_block: Vec<u8> = Vec::new();
	let mut generated = 0usize;
	let mut counter: u8 = 1;
	while generated < length {
		let mut mac = <M as KeyInit>::new_from_slice(&prk_bytes)
			.map_err(|_| HkdfError::ExpandFailure)?;
		if !prev_block.is_empty() {
			mac.update(&prev_block);
		}
		mac.update(&info);
		mac.update(&[counter]);
		let block = mac.finalize().into_bytes();
		let block_vec = block.to_vec();
		let write_len =
			usize::min(block_vec.len(), length - generated);
		okm[generated..generated + write_len]
			.copy_from_slice(&block_vec[..write_len]);
		prev_block = block_vec;
		generated += write_len;
		counter =
			counter.checked_add(1).ok_or(HkdfError::ExpandFailure)?;
	}

	Ok(HkdfResponse {
		variant,
		derived_key: okm,
		length,
		ikm_length,
		prk_length,
		salt,
		info,
	})
}
