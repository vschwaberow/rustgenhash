// SPDX-License-Identifier: MIT OR Apache-2.0
// Project: rustgenhash
// File: multihash_encoder.rs
// Author: Volker Schwaberow <volker@schwaberow.de>
// Copyright (c) 2022 Volker Schwaberow
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
fn multihash_encoder_sha1_success() {
	let digest = sha1::Sha1::digest(b"rustgenhash");
	let token = MultihashEncoder::encode("sha1", &digest)
		.expect("sha1 multihash");
	assert_eq!(token, "z5dsYP79mzFVJMBqqbsYjVbWohnbBxe");
}

#[test]
fn multihash_encoder_sha384_success() {
	let digest = sha2::Sha384::digest(b"rustgenhash");
	let token = MultihashEncoder::encode("sha384", &digest)
		.expect("sha384 multihash");
	assert_eq!(
		token,
		"zQ1CvmxEEF3tb35Vmi5QumdfejfhSixDzqkcMux4pdptGa3ZqgemVdEq1eS1dvwgkAcba"
	);
}

#[test]
fn multihash_encoder_sha3_256_accepts_hyphen_and_underscore() {
	let digest = sha3::Sha3_256::digest(b"rustgenhash");
	let hyphen = MultihashEncoder::encode("sha3-256", &digest)
		.expect("sha3-256");
	let underscore = MultihashEncoder::encode("sha3_256", &digest)
		.expect("sha3_256");
	assert_eq!(hyphen, underscore);
	assert_eq!(
		hyphen,
		"zW1aq3KHqxYjoZBrmxCyjSjrLRA32NrbgAEosBzeQTvU4B8"
	);
}

#[test]
fn multihash_encoder_sha3_512_success() {
	let digest = sha3::Sha3_512::digest(b"rustgenhash");
	let token = MultihashEncoder::encode("sha3-512", &digest)
		.expect("sha3-512 multihash");
	assert_eq!(
		token,
		"z8tUcEJdeGrHwSXTAZf88F2y8yW1hyphFswy5x5ksWBonVFBgd8dttos9C2tqqnXRw26by8nSjKcEGEXpJiUpngqcLf"
	);
}

#[test]
fn multihash_encoder_blake2s_success() {
	let digest = blake2::Blake2s256::digest(b"rustgenhash");
	let token = MultihashEncoder::encode("blake2s", &digest)
		.expect("blake2s multihash");
	assert_eq!(
		token,
		"z2i3XjxD55xpfLUnmP6r5TMgSmiX7J9XgaVKpnnxanKvRS5T2ML"
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
