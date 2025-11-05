// SPDX-License-Identifier: MIT OR Apache-2.0
// Project: rustgenhash
// File: hmac.rs
// Author: Volker Schwaberow <volker@schwaberow.de>

//! HMAC executor implementations covering SHA-1 (legacy) and SHA-2/SHA-3 variants.

use super::registry::{
	MacAlgorithm, MacAlgorithmMetadata, MacError, MacErrorKind,
	MacExecutor,
};
use hmac::{Hmac, Mac};
use sha1::Sha1;
use sha2::{Sha256, Sha512};
use sha3::{Sha3_256, Sha3_512};

type HmacSha1 = Hmac<Sha1>;
type HmacSha256 = Hmac<Sha256>;
type HmacSha512 = Hmac<Sha512>;
type HmacSha3_256 = Hmac<Sha3_256>;
type HmacSha3_512 = Hmac<Sha3_512>;

pub fn catalog() -> &'static [MacAlgorithm] {
	const ALGORITHMS: &[MacAlgorithm] = &[
		MacAlgorithm::new(
			MacAlgorithmMetadata::legacy("hmac-sha1", "HMAC-SHA1"),
			create_hmac_sha1,
		),
		MacAlgorithm::new(
			MacAlgorithmMetadata::current(
				"hmac-sha256",
				"HMAC-SHA256",
			),
			create_hmac_sha256,
		),
		MacAlgorithm::new(
			MacAlgorithmMetadata::current(
				"hmac-sha512",
				"HMAC-SHA512",
			),
			create_hmac_sha512,
		),
		MacAlgorithm::new(
			MacAlgorithmMetadata::current(
				"hmac-sha3-256",
				"HMAC-SHA3-256",
			),
			create_hmac_sha3_256,
		),
		MacAlgorithm::new(
			MacAlgorithmMetadata::current(
				"hmac-sha3-512",
				"HMAC-SHA3-512",
			),
			create_hmac_sha3_512,
		),
	];
	ALGORITHMS
}

enum HmacVariant {
	Sha1(HmacSha1),
	Sha256(HmacSha256),
	Sha512(HmacSha512),
	Sha3_256(HmacSha3_256),
	Sha3_512(HmacSha3_512),
}

struct HmacExecutor {
	inner: HmacVariant,
}

impl MacExecutor for HmacExecutor {
	fn update(&mut self, data: &[u8]) {
		match &mut self.inner {
			HmacVariant::Sha1(mac) => mac.update(data),
			HmacVariant::Sha256(mac) => mac.update(data),
			HmacVariant::Sha512(mac) => mac.update(data),
			HmacVariant::Sha3_256(mac) => mac.update(data),
			HmacVariant::Sha3_512(mac) => mac.update(data),
		}
	}

	fn finalize(self: Box<Self>) -> Vec<u8> {
		match self.inner {
			HmacVariant::Sha1(mac) => {
				mac.finalize().into_bytes().to_vec()
			}
			HmacVariant::Sha256(mac) => {
				mac.finalize().into_bytes().to_vec()
			}
			HmacVariant::Sha512(mac) => {
				mac.finalize().into_bytes().to_vec()
			}
			HmacVariant::Sha3_256(mac) => {
				mac.finalize().into_bytes().to_vec()
			}
			HmacVariant::Sha3_512(mac) => {
				mac.finalize().into_bytes().to_vec()
			}
		}
	}
}

fn create_hmac_sha1(
	key: &[u8],
) -> Result<Box<dyn MacExecutor>, MacError> {
	let mac = HmacSha1::new_from_slice(key).map_err(|_| {
		MacError::new(
			MacErrorKind::InvalidKeyLength,
			"HMAC key length must be at least one byte",
		)
	})?;
	Ok(Box::new(HmacExecutor {
		inner: HmacVariant::Sha1(mac),
	}))
}

fn create_hmac_sha256(
	key: &[u8],
) -> Result<Box<dyn MacExecutor>, MacError> {
	let mac = HmacSha256::new_from_slice(key).map_err(|_| {
		MacError::new(
			MacErrorKind::InvalidKeyLength,
			"HMAC key length must be at least one byte",
		)
	})?;
	Ok(Box::new(HmacExecutor {
		inner: HmacVariant::Sha256(mac),
	}))
}

fn create_hmac_sha512(
	key: &[u8],
) -> Result<Box<dyn MacExecutor>, MacError> {
	let mac = HmacSha512::new_from_slice(key).map_err(|_| {
		MacError::new(
			MacErrorKind::InvalidKeyLength,
			"HMAC key length must be at least one byte",
		)
	})?;
	Ok(Box::new(HmacExecutor {
		inner: HmacVariant::Sha512(mac),
	}))
}

fn create_hmac_sha3_256(
	key: &[u8],
) -> Result<Box<dyn MacExecutor>, MacError> {
	let mac = HmacSha3_256::new_from_slice(key).map_err(|_| {
		MacError::new(
			MacErrorKind::InvalidKeyLength,
			"HMAC key length must be at least one byte",
		)
	})?;
	Ok(Box::new(HmacExecutor {
		inner: HmacVariant::Sha3_256(mac),
	}))
}

fn create_hmac_sha3_512(
	key: &[u8],
) -> Result<Box<dyn MacExecutor>, MacError> {
	let mac = HmacSha3_512::new_from_slice(key).map_err(|_| {
		MacError::new(
			MacErrorKind::InvalidKeyLength,
			"HMAC key length must be at least one byte",
		)
	})?;
	Ok(Box::new(HmacExecutor {
		inner: HmacVariant::Sha3_512(mac),
	}))
}
