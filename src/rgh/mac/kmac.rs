// SPDX-License-Identifier: MIT OR Apache-2.0
// Project: rustgenhash
// File: kmac.rs
// Author: Volker Schwaberow <volker@schwaberow.de>

//! KMAC (NIST SP 800-185) executors for 128- and 256-bit variants.

use super::registry::{
	MacAlgorithm, MacAlgorithmMetadata, MacError, MacErrorKind,
	MacExecutor,
};
use sha3::digest::{ExtendableOutput, Update, XofReader};
use sha3::{CShake128, CShake128Core, CShake256, CShake256Core};

const KMAC128_RATE: usize = 168; // bytes
const KMAC256_RATE: usize = 136; // bytes
const CUSTOMIZATION: &[u8] = b"";
const FUNCTION_NAME: &[u8] = b"KMAC";
const OUTPUT_LEN_128: usize = 32;
const OUTPUT_LEN_256: usize = 64;

pub fn catalog() -> &'static [MacAlgorithm] {
	const ALGORITHMS: &[MacAlgorithm] = &[
		MacAlgorithm::new(
			MacAlgorithmMetadata::current("kmac128", "KMAC128"),
			create_kmac128,
		),
		MacAlgorithm::new(
			MacAlgorithmMetadata::current("kmac256", "KMAC256"),
			create_kmac256,
		),
	];
	ALGORITHMS
}

enum KmacVariant {
	Kmac128 {
		state: Option<CShake128>,
		output_len: usize,
	},
	Kmac256 {
		state: Option<CShake256>,
		output_len: usize,
	},
}

pub struct KmacExecutor {
	variant: KmacVariant,
}

impl MacExecutor for KmacExecutor {
	fn update(&mut self, data: &[u8]) {
		match &mut self.variant {
			KmacVariant::Kmac128 { state, .. } => {
				if let Some(hasher) = state.as_mut() {
					hasher.update(data);
				}
			}
			KmacVariant::Kmac256 { state, .. } => {
				if let Some(hasher) = state.as_mut() {
					hasher.update(data);
				}
			}
		}
	}

	fn finalize(mut self: Box<Self>) -> Vec<u8> {
		match &mut self.variant {
			KmacVariant::Kmac128 { state, output_len } => {
				let mut hasher = state
					.take()
					.expect("KMAC128 state already finalized");
				hasher
					.update(&right_encode((*output_len as u64) * 8));
				let mut reader = hasher.finalize_xof();
				let mut out = vec![0u8; *output_len];
				reader.read(&mut out);
				out
			}
			KmacVariant::Kmac256 { state, output_len } => {
				let mut hasher = state
					.take()
					.expect("KMAC256 state already finalized");
				hasher
					.update(&right_encode((*output_len as u64) * 8));
				let mut reader = hasher.finalize_xof();
				let mut out = vec![0u8; *output_len];
				reader.read(&mut out);
				out
			}
		}
	}
}

fn create_kmac128(
	key: &[u8],
) -> Result<Box<dyn MacExecutor>, MacError> {
	if key.is_empty() {
		return Err(MacError::new(
			MacErrorKind::InvalidKey,
			"KMAC128 key must not be empty",
		));
	}
	let core = CShake128Core::new_with_function_name(
		FUNCTION_NAME,
		CUSTOMIZATION,
	);
	let mut state = CShake128::from_core(core);
	state.update(&bytepad(&encode_string(key), KMAC128_RATE));
	Ok(Box::new(KmacExecutor {
		variant: KmacVariant::Kmac128 {
			state: Some(state),
			output_len: OUTPUT_LEN_128,
		},
	}))
}

fn create_kmac256(
	key: &[u8],
) -> Result<Box<dyn MacExecutor>, MacError> {
	if key.is_empty() {
		return Err(MacError::new(
			MacErrorKind::InvalidKey,
			"KMAC256 key must not be empty",
		));
	}
	let core = CShake256Core::new_with_function_name(
		FUNCTION_NAME,
		CUSTOMIZATION,
	);
	let mut state = CShake256::from_core(core);
	state.update(&bytepad(&encode_string(key), KMAC256_RATE));
	Ok(Box::new(KmacExecutor {
		variant: KmacVariant::Kmac256 {
			state: Some(state),
			output_len: OUTPUT_LEN_256,
		},
	}))
}

fn encode_string(input: &[u8]) -> Vec<u8> {
	let mut result = left_encode((input.len() * 8) as u64);
	result.extend_from_slice(input);
	result
}

fn left_encode(value: u64) -> Vec<u8> {
	let encoded = trim_be_bytes(value);
	let mut out = Vec::with_capacity(1 + encoded.len());
	out.push(encoded.len() as u8);
	out.extend_from_slice(&encoded);
	out
}

fn right_encode(value: u64) -> Vec<u8> {
	let encoded = trim_be_bytes(value);
	let mut out = Vec::with_capacity(1 + encoded.len());
	out.extend_from_slice(&encoded);
	out.push(encoded.len() as u8);
	out
}

fn bytepad(encoded: &[u8], w: usize) -> Vec<u8> {
	let mut result = left_encode(w as u64);
	result.extend_from_slice(encoded);
	while !result.len().is_multiple_of(w) {
		result.push(0);
	}
	result
}

fn trim_be_bytes(value: u64) -> Vec<u8> {
	let bytes = value.to_be_bytes();
	if value == 0 {
		return vec![0];
	}
	let first = bytes
		.iter()
		.position(|&b| b != 0)
		.unwrap_or(bytes.len() - 1);
	bytes[first..].to_vec()
}
