// SPDX-License-Identifier: MIT OR Apache-2.0
// Project: rustgenhash
// File: lib.rs
// Author: Volker Schwaberow <volker@schwaberow.de>
// Copyright (c) 2022 Volker Schwaberow

pub use serde::{Deserialize, Serialize};
use serde_json::{json, Value as JsonValue};

pub mod rgh {
	pub mod analyze;
	pub mod app;
	pub mod audit;
	pub mod benchmark;
	pub mod digest;
	pub mod file;
	pub mod hash;
	pub mod hhhash;
	pub mod kdf;
	pub mod output;
	pub mod random;
}

pub fn render_kdf_output(
	algorithm: &str,
	digest: &str,
	metadata: JsonValue,
	hash_only: bool,
) -> String {
	if hash_only {
		digest.to_string()
	} else {
		json!({
			"algorithm": algorithm,
			"digest": digest,
			"metadata": metadata
		})
		.to_string()
	}
}

#[cfg(test)]
mod tests {
	use crate::rgh::analyze::{compare_hashes, HashAnalyzer};

	#[test]
	fn test_analyze_argon2() {
		let hash = HashAnalyzer::from_string(
            "$argon2id$v=19$m=4096,t=3,p=1$aN8J49cAi1VFS560uw5vsw$wskiYeq9UkHSgzpulEDHauTHOJ9Nz2dOf+0OcfAULU0",
        );
		assert!(hash.is_argon2());
	}

	#[test]
	fn test_analyze_balloon() {
		let hash = HashAnalyzer::from_string(
            "$balloon$1$m=65536,t=2,p=1$e3b0c44298fc1c149afbf4c8996fb924"
        );
		assert!(hash.is_balloon());
	}

	#[test]
	fn test_analyze_bcrypt() {
		let hash = HashAnalyzer::from_string(
            "$2a$10$N9qo8uLOickgx2ZMRZoMyeIjZAgcfl7p92ldGxad68LJZdL17lhWy"
        );
		assert!(hash.is_bcrypt());
	}

	#[test]
	fn test_analyze_pbkdf2() {
		let hash = HashAnalyzer::from_string(
        "$pbkdf2$SHA256$131000$7573657273616c74$b6987782641e8b3c9936a3685b2c6ced2b8a0668d4f681fd52d0efdc5e2e261c"
    );
		assert!(hash.is_pbkdf2());
	}

	#[test]
	fn test_analyze_scrypt() {
		let hash = HashAnalyzer::from_string(
			"$scrypt$ln=16,r=8,p=1$TmFDbA$QAyRzIKGJvQnJ+e3Sdwp/Q",
		);
		assert!(hash.is_scrypt());
	}

	#[test]
	fn test_analyze_md5() {
		let hash = HashAnalyzer::from_string(
			"d41d8cd98f00b204e9800998ecf8427e",
		);
		assert!(hash
			.detect_possible_hashes()
			.contains(&"MD5".to_string()));
	}

	#[test]
	fn test_analyze_sha1() {
		let hash = HashAnalyzer::from_string(
			"da39a3ee5e6b4b0d3255bfef95601890afd80709",
		);
		assert!(hash
			.detect_possible_hashes()
			.contains(&"SHA1".to_string()));
	}

	#[test]
	fn test_analyze_sha256() {
		let hash = HashAnalyzer::from_string(
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
        );
		assert!(hash
			.detect_possible_hashes()
			.contains(&"SHA256".to_string()));
	}

	#[test]
	fn test_analyze_sha512() {
		let hash = HashAnalyzer::from_string(
            "cf83e1357eefb8bdf1542850d66d8007d620e4050b5715dc83f4a921d36ce9ce47d0d13c5d85f2b0ff8318d2877eec2f63b931bd47417a81a538327af927da3e",
        );
		assert!(hash
			.detect_possible_hashes()
			.contains(&"SHA512".to_string()));
	}

	#[test]
	fn test_analyze_uuid_v4() {
		let hash = HashAnalyzer::from_string(
			"123e4567-e89b-42d3-a456-556642440000",
		);
		assert!(hash.is_uuid_v4());
	}

	#[test]
	fn test_compare_hashes() {
		assert!(compare_hashes("abc123", "ABC123"));
		assert!(!compare_hashes("abc123", "def456"));
	}

	#[test]
	fn test_detect_possible_hashes() {
		let hash = HashAnalyzer::from_string(
            "5e884898da28047151d0e56f8dc6292773603d0d6aabbdd62a11ef721d1542d8",
        );
		let possible_hashes = hash.detect_possible_hashes();
		assert!(possible_hashes.contains(&"SHA256".to_string()));
		assert!(possible_hashes.contains(&"Blake2s".to_string()));
		assert!(!possible_hashes.contains(&"MD5".to_string()));
	}
}
