// SPDX-License-Identifier: MIT OR Apache-2.0
// Project: rustgenhash
// File: hash/registry.rs

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct DigestAlgorithm {
	pub id: &'static str,
	pub output_len: usize,
}

/// Canonical digest IDs accepted by [`RHash::new`], with fixed output widths.
pub const DIGEST_ALGORITHMS: &[DigestAlgorithm] = &[
	DigestAlgorithm { id: "ASCON", output_len: 32 },
	DigestAlgorithm { id: "BELTHASH", output_len: 32 },
	DigestAlgorithm { id: "BLAKE2B", output_len: 64 },
	DigestAlgorithm { id: "BLAKE2S", output_len: 32 },
	DigestAlgorithm { id: "BLAKE3", output_len: 32 },
	DigestAlgorithm { id: "FSB160", output_len: 20 },
	DigestAlgorithm { id: "FSB224", output_len: 28 },
	DigestAlgorithm { id: "FSB256", output_len: 32 },
	DigestAlgorithm { id: "FSB384", output_len: 48 },
	DigestAlgorithm { id: "FSB512", output_len: 64 },
	DigestAlgorithm { id: "GOST94", output_len: 32 },
	DigestAlgorithm { id: "GOST94TEST", output_len: 32 },
	DigestAlgorithm { id: "GOST94UA", output_len: 32 },
	DigestAlgorithm { id: "GROESTL", output_len: 32 },
	DigestAlgorithm { id: "JH224", output_len: 28 },
	DigestAlgorithm { id: "JH256", output_len: 32 },
	DigestAlgorithm { id: "JH384", output_len: 48 },
	DigestAlgorithm { id: "JH512", output_len: 64 },
	DigestAlgorithm { id: "MD2", output_len: 16 },
	DigestAlgorithm { id: "MD4", output_len: 16 },
	DigestAlgorithm { id: "MD5", output_len: 16 },
	DigestAlgorithm { id: "RIPEMD160", output_len: 20 },
	DigestAlgorithm { id: "RIPEMD320", output_len: 40 },
	DigestAlgorithm { id: "SHA1", output_len: 20 },
	DigestAlgorithm { id: "SHA224", output_len: 28 },
	DigestAlgorithm { id: "SHA256", output_len: 32 },
	DigestAlgorithm { id: "SHA384", output_len: 48 },
	DigestAlgorithm { id: "SHA512", output_len: 64 },
	DigestAlgorithm { id: "SHA3_224", output_len: 28 },
	DigestAlgorithm { id: "SHA3_256", output_len: 32 },
	DigestAlgorithm { id: "SHA3_384", output_len: 48 },
	DigestAlgorithm { id: "SHA3_512", output_len: 64 },
	DigestAlgorithm { id: "SHABAL192", output_len: 24 },
	DigestAlgorithm { id: "SHABAL224", output_len: 28 },
	DigestAlgorithm { id: "SHABAL256", output_len: 32 },
	DigestAlgorithm { id: "SHABAL384", output_len: 48 },
	DigestAlgorithm { id: "SHABAL512", output_len: 64 },
	DigestAlgorithm { id: "SKEIN256", output_len: 32 },
	DigestAlgorithm { id: "SKEIN512", output_len: 64 },
	DigestAlgorithm { id: "SKEIN1024", output_len: 128 },
	DigestAlgorithm { id: "SM3", output_len: 32 },
	DigestAlgorithm { id: "SNEFRU128", output_len: 16 },
	DigestAlgorithm { id: "SNEFRU256", output_len: 32 },
	DigestAlgorithm { id: "STREEBOG256", output_len: 32 },
	DigestAlgorithm { id: "STREEBOG512", output_len: 64 },
	DigestAlgorithm { id: "TIGER", output_len: 24 },
	DigestAlgorithm { id: "TIGER2", output_len: 24 },
	DigestAlgorithm { id: "WHIRLPOOL", output_len: 64 },
];

/// Aliases normalized by [`RHash::new`] to a canonical [`DIGEST_ALGORITHMS`] id.
pub const DIGEST_ALGORITHM_ALIASES: &[(&str, &str)] = &[
	("GOST94_TEST", "GOST94TEST"),
	("SNEFRU", "SNEFRU128"),
	("SNEFRU_128", "SNEFRU128"),
	("SNEFRU_256", "SNEFRU256"),
	("TIGER_2", "TIGER2"),
];

pub fn digest_algorithm_ids() -> impl Iterator<Item = &'static str> {
	DIGEST_ALGORITHMS.iter().map(|algo| algo.id)
}

