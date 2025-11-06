// SPDX-License-Identifier: MIT OR Apache-2.0
// Project: rustgenhash
// File: cmac.rs
// Author: Volker Schwaberow <volker@schwaberow.de>

//! CMAC executor implementations for AES-128/192/256 keys.

use aes::{Aes128, Aes192, Aes256};
use cmac::{Cmac, Mac};

use super::key::validate_cmac_key_length;
use super::registry::{
	MacAlgorithm, MacAlgorithmMetadata, MacError, MacErrorKind,
	MacExecutor,
};

type CmacAes128 = Cmac<Aes128>;
type CmacAes192 = Cmac<Aes192>;
type CmacAes256 = Cmac<Aes256>;

pub fn catalog() -> &'static [MacAlgorithm] {
	const ALGORITHMS: &[MacAlgorithm] = &[
		MacAlgorithm::new(
			MacAlgorithmMetadata::current(
				"cmac-aes128",
				"CMAC-AES128",
			),
			create_cmac_aes128,
		),
		MacAlgorithm::new(
			MacAlgorithmMetadata::current(
				"cmac-aes192",
				"CMAC-AES192",
			),
			create_cmac_aes192,
		),
		MacAlgorithm::new(
			MacAlgorithmMetadata::current(
				"cmac-aes256",
				"CMAC-AES256",
			),
			create_cmac_aes256,
		),
	];
	ALGORITHMS
}

enum CmacVariant {
	Aes128(CmacAes128),
	Aes192(CmacAes192),
	Aes256(CmacAes256),
}

struct CmacExecutor {
	inner: CmacVariant,
}

impl MacExecutor for CmacExecutor {
	fn update(&mut self, data: &[u8]) {
		match &mut self.inner {
			CmacVariant::Aes128(mac) => mac.update(data),
			CmacVariant::Aes192(mac) => mac.update(data),
			CmacVariant::Aes256(mac) => mac.update(data),
		}
	}

	fn finalize(self: Box<Self>) -> Vec<u8> {
		match self.inner {
			CmacVariant::Aes128(mac) => {
				mac.finalize().into_bytes().to_vec()
			}
			CmacVariant::Aes192(mac) => {
				mac.finalize().into_bytes().to_vec()
			}
			CmacVariant::Aes256(mac) => {
				mac.finalize().into_bytes().to_vec()
			}
		}
	}
}

fn create_cmac_aes128(
	key: &[u8],
) -> Result<Box<dyn MacExecutor>, MacError> {
	validate_cmac_key_length(key)?;
	if key.len() != 16 {
		return Err(MacError::new(
			MacErrorKind::InvalidKeyLength,
			format!(
				"Invalid CMAC-AES128 key length: expected 16 bytes but received {}",
				key.len()
			),
		));
	}
	let mac = CmacAes128::new_from_slice(key).map_err(|_| {
		MacError::new(
			MacErrorKind::InvalidKeyLength,
			"CMAC-AES128 failed to initialize with provided key",
		)
	})?;
	Ok(Box::new(CmacExecutor {
		inner: CmacVariant::Aes128(mac),
	}))
}

fn create_cmac_aes192(
	key: &[u8],
) -> Result<Box<dyn MacExecutor>, MacError> {
	validate_cmac_key_length(key)?;
	if key.len() != 24 {
		return Err(MacError::new(
			MacErrorKind::InvalidKeyLength,
			format!(
				"Invalid CMAC-AES192 key length: expected 24 bytes but received {}",
				key.len()
			),
		));
	}
	let mac = CmacAes192::new_from_slice(key).map_err(|_| {
		MacError::new(
			MacErrorKind::InvalidKeyLength,
			"CMAC-AES192 failed to initialize with provided key",
		)
	})?;
	Ok(Box::new(CmacExecutor {
		inner: CmacVariant::Aes192(mac),
	}))
}

fn create_cmac_aes256(
	key: &[u8],
) -> Result<Box<dyn MacExecutor>, MacError> {
	validate_cmac_key_length(key)?;
	if key.len() != 32 {
		return Err(MacError::new(
			MacErrorKind::InvalidKeyLength,
			format!(
				"Invalid CMAC-AES256 key length: expected 32 bytes but received {}",
				key.len()
			),
		));
	}
	let mac = CmacAes256::new_from_slice(key).map_err(|_| {
		MacError::new(
			MacErrorKind::InvalidKeyLength,
			"CMAC-AES256 failed to initialize with provided key",
		)
	})?;
	Ok(Box::new(CmacExecutor {
		inner: CmacVariant::Aes256(mac),
	}))
}
