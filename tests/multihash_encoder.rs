// SPDX-License-Identifier: MIT OR Apache-2.0
use digest::Digest;
use rustgenhash::rgh::multihash::{MultihashEncoder, MultihashError};

#[test]
fn multihash_encoder_sha256_success() {
	let digest = sha2::Sha256::digest(b"rustgenhash");
	let token = MultihashEncoder::encode("sha256", &digest)
		.expect("sha256 multihash");
	assert_eq!(
		token,
		"zQmTY2GYmjoMc6n2Ka8up2xyYVKstkU3Hd3duBo9qhdNjFt"
	);
}

#[test]
fn multihash_encoder_blake2b_truncates_to_256_bits() {
	let digest = blake2::Blake2b512::digest(b"rustgenhash");
	assert_eq!(digest.len(), 64);
	let token = MultihashEncoder::encode("blake2b", &digest)
		.expect("blake2b multihash");
	assert_eq!(
		token,
		"z2DrjgbGGeZzzi7fgn8kgxMYW47tECEpmVM4XrLaAiT3wVAYKXQ"
	);
}

#[test]
fn multihash_encoder_rejects_unsupported_algorithm() {
	let digest = md5::Md5::digest(b"rustgenhash");
	let err = MultihashEncoder::encode("md5", &digest)
		.expect_err("md5 should fail");
	match err {
		MultihashError::UnsupportedAlgorithm { algorithm } => {
			assert_eq!(algorithm, "md5");
		}
		other => panic!("unexpected error: {other:?}", other = other),
	}
}

#[test]
fn multihash_encoder_rejects_wrong_length() {
	let digest = sha2::Sha256::digest(b"rustgenhash");
	let mut longer = digest.to_vec();
	longer.extend_from_slice(&[0u8; 5]);
	let err = MultihashEncoder::encode("sha256", &longer)
		.expect_err("length mismatch");
	match err {
		MultihashError::InvalidDigestLength {
			expected,
			actual,
			..
		} => {
			assert_eq!(expected, 32);
			assert_eq!(actual, 37);
		}
		other => panic!("unexpected error: {other:?}", other = other),
	}
}
