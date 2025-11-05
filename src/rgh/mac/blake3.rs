// SPDX-License-Identifier: MIT OR Apache-2.0
// Project: rustgenhash
// File: blake3.rs
// Author: Volker Schwaberow <volker@schwaberow.de>

//! BLAKE3 keyed MAC executor implementation.

use super::registry::{
	MacAlgorithm, MacAlgorithmMetadata, MacError, MacErrorKind,
	MacExecutor,
};

pub fn catalog() -> &'static [MacAlgorithm] {
	const ALGORITHMS: &[MacAlgorithm] = &[MacAlgorithm::new(
		MacAlgorithmMetadata::current("blake3-keyed", "BLAKE3 keyed"),
		create_blake3_keyed,
	)];
	ALGORITHMS
}

struct Blake3Executor {
	hasher: blake3::Hasher,
}

impl MacExecutor for Blake3Executor {
	fn update(&mut self, data: &[u8]) {
		self.hasher.update(data);
	}

	fn finalize(self: Box<Self>) -> Vec<u8> {
		self.hasher.finalize().as_bytes().to_vec()
	}
}

fn create_blake3_keyed(
	key: &[u8],
) -> Result<Box<dyn MacExecutor>, MacError> {
	if key.len() != blake3::KEY_LEN {
		return Err(MacError::new(
			MacErrorKind::InvalidKeyLength,
			format!(
				"BLAKE3 keyed mode requires a {}-byte key (got {})",
				blake3::KEY_LEN,
				key.len()
			),
		));
	}
	let mut fixed = [0u8; blake3::KEY_LEN];
	fixed.copy_from_slice(key);
	let hasher = blake3::Hasher::new_keyed(&fixed);
	Ok(Box::new(Blake3Executor { hasher }))
}
