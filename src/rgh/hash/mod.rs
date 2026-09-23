// SPDX-License-Identifier: MIT OR Apache-2.0
// Project: rustgenhash
// File: hash/mod.rs

mod digest_ops;
mod file;
mod phash;
mod registry;
mod rhash;
mod weak;

pub use digest_ops::{digest_bytes_to_record, serialize_digest_output};
pub use file::{
	compare_file_hashes, CompareDiffKind, CompareDifference, CompareMode,
	CompareSummary, FileDigestOptions, FileDigestResult,
	digest_with_options, digest_with_options_collect,
};
pub use phash::{
	Argon2Config, BalloonConfig, BcryptConfig, PHash, Pbkdf2Config,
	ScryptConfig,
};
#[cfg(test)]
pub(crate) use phash::generate_phc_salt;
pub use registry::{
	digest_algorithm_ids, DigestAlgorithm, DIGEST_ALGORITHMS,
	DIGEST_ALGORITHM_ALIASES,
};
pub use rhash::RHash;
pub use weak::{weak_algorithm_warning, WeakAlgorithmWarning};

#[cfg(test)]
mod mmap_thread_tests {
	use super::RHash;
	use std::io::Write;

	#[test]
	fn hash_path_mmap_matches_stream() {
		let dir = tempfile::tempdir().unwrap();
		let path = dir.path().join("sample.bin");
		let mut file = std::fs::File::create(&path).unwrap();
		file.write_all(&(0u8..=255).cycle().take(4096).collect::<Vec<_>>()).unwrap();
		drop(file);
		let streamed = RHash::new("SHA256")
			.expect("SHA256")
			.hash_path(&path, false)
			.unwrap();
		let mapped = RHash::new("SHA256")
			.expect("SHA256")
			.hash_path(&path, true)
			.unwrap();
		assert_eq!(streamed, mapped);
	}
}

#[cfg(test)]
mod kdf_param_tests {
	use super::{generate_phc_salt, PHash, ScryptConfig};

	#[test]
	fn scrypt_rejects_invalid_log_n() {
		let cfg = ScryptConfig {
			log_n: 64,
			r: 8,
			p: 1,
		};
		let salt = generate_phc_salt();
		assert!(PHash::hash_scrypt_impl("secret", &cfg, &salt).is_err());
	}
}

#[cfg(test)]
mod gost94_sbox_tests {
	use super::RHash;

	#[test]
	fn gost94_default_differs_from_test_sbox() {
		let crypto = RHash::new("GOST94")
			.expect("GOST94")
			.process_string(b"rustgenhash");
		let test = RHash::new("gost94-test")
			.expect("gost94-test")
			.process_string(b"rustgenhash");
		assert_ne!(crypto, test);
	}
}

#[cfg(test)]
mod skein_output_tests {
	use super::RHash;

	#[test]
	fn skein512_empty_digest_is_64_bytes() {
		let mut h = RHash::new("SKEIN512").expect("SKEIN512");
		assert_eq!(h.process_string(b"").len(), 64);
	}

	#[test]
	fn skein1024_empty_digest_is_128_bytes() {
		let mut h = RHash::new("SKEIN1024").expect("SKEIN1024");
		assert_eq!(h.process_string(b"").len(), 128);
	}
}

#[cfg(test)]
mod rhash_new_tests {
	use super::RHash;

	#[test]
	fn rhash_accepts_hyphenated_sha3() {
		let mut h = RHash::new("sha3-256").expect("sha3-256");
		assert_eq!(h.process_string(b"").len(), 32);
	}

	#[test]
	fn rhash_accepts_snefru_aliases() {
		let a = RHash::new("snefru-128")
			.expect("snefru-128")
			.process_string(b"abc");
		let b = RHash::new("SNEFRU128")
			.expect("SNEFRU128")
			.process_string(b"abc");
		assert_eq!(a, b);
		assert_eq!(a.len(), 16);
		let c = RHash::new("snefru-256")
			.expect("snefru-256")
			.process_string(b"");
		assert_eq!(c.len(), 32);
	}

	#[test]
	fn rhash_rejects_unknown_algorithm() {
		assert!(RHash::new("nosuch").is_err());
	}
}

#[cfg(test)]
mod digest_registry_tests {
	use super::{
		DigestAlgorithm, DIGEST_ALGORITHM_ALIASES, DIGEST_ALGORITHMS,
		RHash,
	};

	#[test]
	fn every_registry_id_constructs_and_matches_output_len() {
		for DigestAlgorithm { id, output_len } in DIGEST_ALGORITHMS {
			let mut hasher = RHash::new(id).unwrap_or_else(|err| {
				panic!("RHash::new({id}) failed: {err}");
			});
			let digest = hasher.process_string(b"");
			assert_eq!(
				digest.len(),
				*output_len,
				"{id} empty digest width"
			);
		}
	}

	#[test]
	fn aliases_match_canonical_digest() {
		for (alias, canonical) in DIGEST_ALGORITHM_ALIASES {
			let alias_digest = RHash::new(alias)
				.expect(alias)
				.process_string(b"rustgenhash");
			let canonical_digest = RHash::new(canonical)
				.expect(canonical)
				.process_string(b"rustgenhash");
			assert_eq!(alias_digest, canonical_digest, "{alias} vs {canonical}");
		}
	}

	#[test]
	fn skein512_matches_upstream_full_width_empty() {
		use digest::{consts::U64, Digest};
		use skein::Skein512;
		let upstream = Skein512::<U64>::digest(b"");
		let via_rhash = RHash::new("SKEIN512")
			.expect("SKEIN512")
			.process_string(b"");
		assert_eq!(via_rhash.as_slice(), upstream.as_slice());
	}

	#[test]
	fn skein1024_matches_upstream_full_width_empty() {
		use digest::{consts::U128, Digest};
		use skein::Skein1024;
		let upstream = Skein1024::<U128>::digest(b"");
		let via_rhash = RHash::new("SKEIN1024")
			.expect("SKEIN1024")
			.process_string(b"");
		assert_eq!(via_rhash.as_slice(), upstream.as_slice());
	}

	#[test]
	fn gost94_matches_upstream_cryptopro_fox() {
		use gost94::{Digest, Gost94CryptoPro};
		let msg = b"The quick brown fox jumps over the lazy dog";
		let upstream = Gost94CryptoPro::digest(msg);
		let via_rhash = RHash::new("GOST94")
			.expect("GOST94")
			.process_string(msg);
		assert_eq!(via_rhash.as_slice(), upstream.as_slice());
	}
}
