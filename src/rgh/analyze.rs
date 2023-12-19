// SPDX-License-Identifier: MIT OR Apache-2.0
// Project: rustgenhash
// File: analyze.rs
// Author: Volker Schwaberow <volker@schwaberow.de>
// Copyright (c) 2022 Volker Schwaberow

use regex::Regex;

pub struct HashAnalyzer {
	pub hash: String,
}

impl HashAnalyzer {
	pub fn from_string(hash: &str) -> HashAnalyzer {
		HashAnalyzer {
			hash: hash.to_owned(),
		}
	}

	fn check_hash(&self, length: usize) -> bool {
		self.hash.len() == length
			&& self.hash.chars().all(|c| c.is_ascii_hexdigit())
	}

	pub fn is_balloon(&self) -> bool {
		if !self.hash.starts_with("$balloon$") {
			return false;
		}

		let params: Vec<&str> = self.hash.split('$').collect();
		if params.len() != 5 {
			return false;
		}

		let version = params[2].parse::<u32>().ok();
		if version != Some(1) && version != Some(2) {
			return false;
		}

		let param_values: Vec<&str> = params[3].split(',').collect();
		if param_values.len() != 3 {
			return false;
		}

		let mut memory_cost = None;
		let mut time_cost = None;
		let mut parallelism = None;
		for value in param_values {
			let parts: Vec<&str> = value.split('=').collect();
			if parts.len() != 2 {
				return false;
			}
			match parts[0] {
				"m" => memory_cost = parts[1].parse::<u32>().ok(),
				"t" => time_cost = parts[1].parse::<u32>().ok(),
				"p" => parallelism = parts[1].parse::<u32>().ok(),
				_ => return false,
			}
		}

		if memory_cost.is_none()
			|| time_cost.is_none()
			|| parallelism.is_none()
		{
			return false;
		}

		true
	}

	pub fn is_md4(&self) -> bool {
		self.check_hash(32)
	}

	pub fn is_md5(&self) -> bool {
		self.check_hash(32)
	}

	pub fn is_groestl(&self) -> bool {
		self.check_hash(64)
	}

	pub fn is_sha1(&self) -> bool {
		self.check_hash(40)
	}

	pub fn is_streebog256(&self) -> bool {
		self.check_hash(64)
	}

	pub fn is_streebog512(&self) -> bool {
		self.check_hash(128)
	}

	pub fn is_sha256(&self) -> bool {
		self.check_hash(64)
	}

	pub fn is_tiger(&self) -> bool {
		self.check_hash(48)
	}

	pub fn is_shabal192(&self) -> bool {
		self.check_hash(48)
	}

	pub fn is_shabal224(&self) -> bool {
		self.check_hash(56)
	}

	pub fn is_shabal256(&self) -> bool {
		self.check_hash(64)
	}

	pub fn is_shabal384(&self) -> bool {
		self.check_hash(96)
	}

	pub fn is_shabal512(&self) -> bool {
		self.check_hash(128)
	}

	pub fn is_fsb160(&self) -> bool {
		self.check_hash(40)
	}

	pub fn is_fsb224(&self) -> bool {
		self.check_hash(56)
	}

	pub fn is_fsb256(&self) -> bool {
		self.check_hash(64)
	}

	pub fn is_fsb384(&self) -> bool {
		self.check_hash(96)
	}

	pub fn is_fsb512(&self) -> bool {
		self.check_hash(128)
	}

	pub fn is_blake2b(&self) -> bool {
		self.check_hash(128)
	}
	pub fn is_blake2s(&self) -> bool {
		self.check_hash(64)
	}

	pub fn is_gost94(&self) -> bool {
		self.check_hash(64)
	}

	pub fn is_gost94ua(&self) -> bool {
		self.check_hash(64)
	}
	pub fn is_belthash(&self) -> bool {
		self.check_hash(64)
	}

	pub fn is_ripe160(&self) -> bool {
		self.check_hash(40)
	}

	pub fn is_ripemd320(&self) -> bool {
		self.check_hash(80)
	}

	pub fn is_sha384(&self) -> bool {
		self.check_hash(96)
	}

	pub fn is_sha512(&self) -> bool {
		self.check_hash(128)
	}

	pub fn is_sm3(&self) -> bool {
		self.check_hash(64)
	}

	pub fn is_ascon(&self) -> bool {
		self.check_hash(128)
	}

	pub fn is_argon2(&self) -> bool {
		if !self.hash.starts_with("$argon2") {
			return false;
		}

		let params: Vec<&str> = self.hash[1..].split('$').collect();
		if params.len() < 5 {
			return false;
		}

		let version = params[1]
			.split('=')
			.nth(1)
			.and_then(|s| s.parse::<u32>().ok());
		let others = params[2].split(',').collect::<Vec<&str>>();
		if others.len() != 3 {
			return false;
		}
		let memory_cost = others[0]
			.split('=')
			.nth(1)
			.and_then(|s| s.parse::<u32>().ok());
		let time_cost = others[1]
			.split('=')
			.nth(1)
			.and_then(|s| s.parse::<u32>().ok());
		let parallelism = others[2]
			.split('=')
			.nth(1)
			.and_then(|s| s.parse::<u32>().ok());
		version.is_some()
			&& memory_cost.is_some()
			&& time_cost.is_some()
			&& parallelism.is_some()
	}

	pub fn is_pbkdf2(&self) -> bool {
		if !self.hash.starts_with("$pbkdf2$") {
			return false;
		}

		let params: Vec<&str> = self.hash.split('$').collect();
		if params.len() != 5 {
			return false;
		}

		let hash_function = params[2];
		if !["MD5", "SHA1", "SHA256", "SHA512"]
			.contains(&hash_function)
		{
			return false;
		}

		let iterations = params[3].parse::<u32>().ok();
		if iterations.is_none() {
			return false;
		}

		true
	}

	pub fn is_sha3_224(&self) -> bool {
		self.check_hash(56)
	}

	pub fn is_sha3_256(&self) -> bool {
		self.check_hash(64)
	}

	pub fn is_sha3_384(&self) -> bool {
		self.check_hash(96)
	}

	pub fn is_sha3_512(&self) -> bool {
		self.check_hash(128)
	}

	pub fn is_bcrypt(&self) -> bool {
		if !self.hash.starts_with("$2a$") {
			return false;
		}

		let params: Vec<&str> = self.hash.split('$').collect();
		if params.len() != 4 {
			return false;
		}

		let cost = params[2].parse::<u32>().ok();
		if cost.is_none() {
			return false;
		}

		let salt = params[3].get(..22);
		if salt.is_none() {
			return false;
		}

		let hash = params[3].get(22..);
		if hash.is_none() || hash.unwrap().len() != 31 {
			return false;
		}

		true
	}

	pub fn is_whirlpool(&self) -> bool {
		self.check_hash(128)
	}

	pub fn is_scrypt(&self) -> bool {
		if !self.hash.starts_with("$scrypt") {
			return false;
		}

		let params: Vec<&str> = self.hash[1..].split('$').collect();
		if params.len() < 4 {
			return false;
		}

		let others = params[1].split(',').collect::<Vec<&str>>();
		if others.len() != 3 {
			return false;
		}
		let logarithm = others[0]
			.split('=')
			.nth(1)
			.and_then(|s| s.parse::<u32>().ok());
		let block_size_factor = others[1]
			.split('=')
			.nth(1)
			.and_then(|s| s.parse::<u32>().ok());
		let parallelization = others[2]
			.split('=')
			.nth(1)
			.and_then(|s| s.parse::<u32>().ok());

		logarithm.is_some()
			&& block_size_factor.is_some()
			&& parallelization.is_some()
	}

	pub fn is_uuid_v4(&self) -> bool {
		let re = Regex::new(
			r"^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$",
		);
		match re {
			Ok(re) => re.is_match(&self.hash),
			Err(_) => false,
		}
	}

	pub fn detect_possible_hashes(&self) -> Vec<String> {
		let mut possible_hashes = Vec::new();
		if self.is_balloon() {
			possible_hashes.push(String::from("Balloon"));
		}
		if self.is_bcrypt() {
			possible_hashes.push(String::from("bcrypt"));
		}
		if self.is_belthash() {
			possible_hashes.push(String::from("BeltHash"));
		}
		if self.is_blake2b() {
			possible_hashes.push(String::from("Blake2b"));
		}
		if self.is_blake2s() {
			possible_hashes.push(String::from("Blake2s"));
		}
		if self.is_fsb160() {
			possible_hashes.push(String::from("FSB160"));
		}
		if self.is_fsb224() {
			possible_hashes.push(String::from("FSB224"));
		}
		if self.is_fsb256() {
			possible_hashes.push(String::from("FSB256"));
		}
		if self.is_fsb384() {
			possible_hashes.push(String::from("FSB384"));
		}
		if self.is_fsb512() {
			possible_hashes.push(String::from("FSB512"));
		}
		if self.is_gost94() {
			possible_hashes.push(String::from("GOST94"));
		}
		if self.is_gost94ua() {
			possible_hashes.push(String::from("GOST94-ua"));
		}
		if self.is_groestl() {
			possible_hashes.push(String::from("Groestl"));
		}
		if self.is_md4() {
			possible_hashes.push(String::from("MD4"));
		}
		if self.is_md5() {
			possible_hashes.push(String::from("MD5"));
		}
		if self.is_scrypt() {
			possible_hashes.push(String::from("scrypt"));
		}
		if self.is_ripe160() {
			possible_hashes.push(String::from("RIPE160"));
		}
		if self.is_ripemd320() {
			possible_hashes.push(String::from("RIPEMD320"));
		}
		if self.is_sha1() {
			possible_hashes.push(String::from("SHA1"));
		}
		if self.is_sha256() {
			possible_hashes.push(String::from("SHA256"));
		}
		if self.is_sha384() {
			possible_hashes.push(String::from("SHA384"));
		}
		if self.is_sha512() {
			possible_hashes.push(String::from("SHA512"));
		}
		if self.is_shabal192() {
			possible_hashes.push(String::from("Shabal192"));
		}
		if self.is_shabal224() {
			possible_hashes.push(String::from("Shabal224"));
		}
		if self.is_shabal256() {
			possible_hashes.push(String::from("Shabal256"));
		}
		if self.is_shabal384() {
			possible_hashes.push(String::from("Shabal384"));
		}
		if self.is_shabal512() {
			possible_hashes.push(String::from("Shabal512"));
		}
		if self.is_tiger() {
			possible_hashes.push(String::from("Tiger"));
		}
		if self.is_argon2() {
			possible_hashes.push(String::from("Argon2"));
		}
		if self.is_pbkdf2() {
			possible_hashes.push(String::from("PBKDF2"));
		}
		if self.is_uuid_v4() {
			possible_hashes.push(String::from("UUIDv4"));
		}
		if self.is_sm3() {
			possible_hashes.push(String::from("SM3"));
		}
		if self.is_streebog256() {
			possible_hashes.push(String::from("Streebog256"));
		}
		if self.is_streebog512() {
			possible_hashes.push(String::from("Streebog512"));
		}
		if self.is_sha3_224() {
			possible_hashes.push(String::from("SHA3-224"));
		}
		if self.is_sha3_256() {
			possible_hashes.push(String::from("SHA3-256"));
		}
		if self.is_sha3_384() {
			possible_hashes.push(String::from("SHA3-384"));
		}
		if self.is_sha3_512() {
			possible_hashes.push(String::from("SHA3-512"));
		}
		if self.is_whirlpool() {
			possible_hashes.push(String::from("Whirlpool"));
		}
		possible_hashes.sort();
		possible_hashes
	}
}

#[cfg(test)]
mod tests {
	use super::*;

	#[test]
	fn test_analyze_argon2() {
		let hash = HashAnalyzer::from_string(
			"$argon2id$v=19$m=4096,t=3,p=1$aN8J49cAi1VFS560uw5vsw$wskiYeq9UkHSgzpulEDHauTHOJ9Nz2dOf+0OcfAULU0",
		);
		assert!(hash.is_argon2());
	}

	#[test]
	fn test_analyze_ascon() {
		let hash = HashAnalyzer::from_string(
			"1c0fe130cdde2e5018892d7749f859ab65858a19312174427576717694352734c53ba393b5ef475ee4c49f26ccd489b35cc4c72ce511b5a67e6f19e95d69db43",
		);
		assert!(hash.is_ascon());
	}

	#[test]
	fn test_balloon() {
		let hash = HashAnalyzer::from_string(
			"$balloon$1$m=65536,t=2,p=1$e3b0c44298fc1c149afbf4c8996fb924"
		);
		assert!(hash.is_balloon());
	}

	#[test]
	fn test_analyze_md4() {
		let hash = HashAnalyzer::from_string(
			"31d6cfe0d16ae931b73c59d7e0c089c0",
		);
		assert!(hash.is_md4());
	}

	#[test]
	fn test_analyze_md5() {
		let hash = HashAnalyzer::from_string(
			"d41d8cd98f00b204e9800998ecf8427e",
		);
		assert!(hash.is_md5());
	}

	#[test]
	fn test_analyze_groestl() {
		let hash = HashAnalyzer::from_string(
			"5fc07d8c8d9d54bf2733c8f3d4d2aa8b3f1603970001fc987f1cdecde18f520f",
		);
		assert!(hash.is_groestl());
	}

	#[test]
	fn test_analyze_sha1() {
		let hash = HashAnalyzer::from_string(
			"da39a3ee5e6b4b0d3255bfef95601890afd80709",
		);
		assert!(hash.is_sha1());
	}

	#[test]
	fn test_analyze_streebog256() {
		let hash = HashAnalyzer::from_string(
			"5e884898da28047151d0e56f8dc6292773603d0d6aabbdd62a11ef721d1542d8",
		);
		assert!(hash.is_streebog256());
	}

	#[test]
	fn test_analyze_streebog512() {
		let hash = HashAnalyzer::from_string(
			"1c0fe130cdde2e5018892d7749f859ab65858a19312174427576717694352734c53ba393b5ef475ee4c49f26ccd489b35cc4c72ce511b5a67e6f19e95d69db43",
		);
		assert!(hash.is_streebog512());
	}

	#[test]
	fn test_analyze_sha256() {
		let hash = HashAnalyzer::from_string(
			"5e884898da28047151d0e56f8dc6292773603d0d6aabbdd62a11ef721d1542d8",
		);
		assert!(hash.is_sha256());
	}

	#[test]
	fn test_analyze_sha512() {
		let hash = HashAnalyzer::from_string(
			"1c0fe130cdde2e5018892d7749f859ab65858a19312174427576717694352734c53ba393b5ef475ee4c49f26ccd489b35cc4c72ce511b5a67e6f19e95d69db43",
		);
		assert!(hash.is_sha512());
	}

	#[test]
	fn test_analyze_tiger() {
		let hash = HashAnalyzer::from_string(
			"3293ac630c13f0245f92bbb1766e16167a4e58492dde73f3",
		);
		assert!(hash.is_tiger());
	}
}
