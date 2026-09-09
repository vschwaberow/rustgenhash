// SPDX-License-Identifier: MIT OR Apache-2.0
// Project: rustgenhash

use strum::EnumIter;

#[derive(clap::ValueEnum, Debug, Copy, Clone, EnumIter)]
pub enum Algorithm {
	Ascon,
	Argon2,
	Balloon,
	Bcrypt,
	Belthash,
	Blake2b,
	Blake2s,
	Blake3,
	Fsb160,
	Fsb224,
	Fsb256,
	Fsb384,
	Fsb512,
	Gost94,
	Gost94Test,
	Gost94ua,
	Groestl,
	Jh224,
	Jh256,
	Jh384,
	Jh512,
	Md2,
	Md4,
	Md5,
	Pbkdf2Sha256,
	Pbkdf2Sha512,
	Ripemd160,
	Ripemd320,
	Scrypt,
	Sha1,
	Sha224,
	Sha256,
	Sha384,
	Sha512,
	Sha3_224,
	Sha3_256,
	Sha3_384,
	Sha3_512,
	Shabal192,
	Shabal224,
	Shabal256,
	Shabal384,
	Shabal512,
	Shacrypt,
	Skein256,
	Skein512,
	Skein1024,
	Snefru128,
	Snefru256,
	Sm3,
	Streebog256,
	Streebog512,
	Tiger,
	Whirlpool,
}

struct AlgorithmProperties {
	file_support: bool,
}

const ASCON_PROPERTIES: AlgorithmProperties = AlgorithmProperties {
	file_support: false,
};

const ARGON2_PROPERTIES: AlgorithmProperties = AlgorithmProperties {
	file_support: false,
};
const PBKDF2_PROPERTIES: AlgorithmProperties = AlgorithmProperties {
	file_support: false,
};
const SCRYPT_PROPERTIES: AlgorithmProperties = AlgorithmProperties {
	file_support: false,
};
const SHACRYPT_PROPERTIES: AlgorithmProperties =
	AlgorithmProperties {
		file_support: false,
	};
const BCRYPT_PROPERTIES: AlgorithmProperties = AlgorithmProperties {
	file_support: false,
};
const BALLOON_PROPERTIES: AlgorithmProperties = AlgorithmProperties {
	file_support: false,
};
const DEFAULT_PROPERTIES: AlgorithmProperties =
	AlgorithmProperties { file_support: true };

impl std::fmt::Display for Algorithm {
	fn fmt(
		&self,
		f: &mut std::fmt::Formatter<'_>,
	) -> std::fmt::Result {
		write!(f, "{:?}", self)
	}
}

impl Algorithm {
	fn properties(&self) -> AlgorithmProperties {
		match *self {
			Algorithm::Ascon => ASCON_PROPERTIES,
			Algorithm::Argon2 => ARGON2_PROPERTIES,
			Algorithm::Pbkdf2Sha256 | Algorithm::Pbkdf2Sha512 => {
				PBKDF2_PROPERTIES
			}
			Algorithm::Scrypt => SCRYPT_PROPERTIES,
			Algorithm::Shacrypt => SHACRYPT_PROPERTIES,
			Algorithm::Bcrypt => BCRYPT_PROPERTIES,
			Algorithm::Balloon => BALLOON_PROPERTIES,
			_ => DEFAULT_PROPERTIES,
		}
	}

    pub fn supports_file_hashing(&self) -> bool {
        self.properties().file_support
    }
}
impl Algorithm {
	pub fn is_password_kdf(self) -> bool {
		matches!(
			self,
			Self::Argon2
				| Self::Balloon
				| Self::Bcrypt
				| Self::Pbkdf2Sha256
				| Self::Pbkdf2Sha512
				| Self::Scrypt
				| Self::Shacrypt
		)
	}

	/// Canonical [`crate::rgh::hash::RHash`] id when this variant is a digest.
	pub fn digest_rhash_id(self) -> Option<String> {
		if self.is_password_kdf() {
			None
		} else {
			Some(format!("{:?}", self).to_ascii_uppercase())
		}
	}
}

#[cfg(test)]
mod digest_registry_drift {
	use super::*;
	use crate::rgh::hash::{
		DIGEST_ALGORITHM_ALIASES, DIGEST_ALGORITHMS, RHash,
	};
	use strum::IntoEnumIterator;

	fn resolve_digest_id(id: &str) -> &str {
		DIGEST_ALGORITHM_ALIASES
			.iter()
			.find(|(alias, _)| *alias == id)
			.map(|(_, target)| *target)
			.unwrap_or(id)
	}

	#[test]
	fn digest_capable_algorithms_are_in_digest_registry() {
		let registry: std::collections::HashSet<&str> =
			DIGEST_ALGORITHMS.iter().map(|algo| algo.id).collect();
		for alg in Algorithm::iter() {
			let Some(id) = alg.digest_rhash_id() else {
				continue;
			};
			let canonical = resolve_digest_id(&id);
			assert!(
				registry.contains(canonical),
				"Algorithm::{alg:?} maps to `{id}` → `{canonical}` missing from DIGEST_ALGORITHMS"
			);
			RHash::new(canonical).unwrap_or_else(|err| {
				panic!("RHash::new({canonical}) failed for {alg:?}: {err}")
			});
		}
	}
}
