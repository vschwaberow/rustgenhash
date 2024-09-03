// SPDX-License-Identifier: MIT OR Apache-2.0
// Project: rustgenhash
// File: analyze.rs
// Author: Volker Schwaberow <volker@schwaberow.de>
// Copyright (c) 2022 Volker Schwaberow

use std::collections::HashSet;

macro_rules! check_hash_lengths {
    ($self:expr, $($len:expr => $names:expr),+ $(,)?) => {
        {
            let mut checks = Vec::new();
            $(
                checks.push(($self.check_hash($len), $names));
            )+
            checks
        }
    };
}

pub struct HashAnalyzer {
	hash: String,
}

impl HashAnalyzer {
	pub fn from_string(hash: &str) -> Self {
		Self {
			hash: hash.to_owned(),
		}
	}

	fn check_hash(&self, length: usize) -> bool {
		self.hash.len() == length
			&& self.hash.chars().all(|c| c.is_ascii_hexdigit())
	}

	pub fn is_balloon(&self) -> bool {
		let parts: Vec<&str> = self.hash.split('$').collect();
		parts.len() == 5
			&& parts[1] == "balloon"
			&& ["1", "2"].contains(&parts[2])
			&& parts[3].split(',').count() == 3
			&& parts[3].split(',').all(|p| p.split('=').count() == 2)
	}

	pub fn is_argon2(&self) -> bool {
		let parts: Vec<&str> = self.hash.split('$').collect();
		parts.len() >= 4
			&& parts[1].starts_with("argon2")
			&& parts[2].starts_with("v=")
			&& parts[3].split(',').count() == 3
			&& parts[3].split(',').all(|p| p.split('=').count() == 2)
	}

	pub fn is_bcrypt(&self) -> bool {
		let parts: Vec<&str> = self.hash.split('$').collect();
		parts.len() == 4
			&& parts[1] == "2a"
			&& parts[2].parse::<u32>().is_ok()
			&& parts[3].len() == 53
	}

	pub fn is_pbkdf2(&self) -> bool {
		let parts: Vec<&str> = self.hash.split('$').collect();
		match parts.as_slice() {
			["", "pbkdf2", hash_fn, iterations, salt, hash]
				if ["MD5", "SHA1", "SHA256", "SHA512"]
					.contains(hash_fn) && iterations
					.parse::<u32>()
					.is_ok() && !salt.is_empty()
					&& !hash.is_empty() =>
			{
				true
			}

			["", pbkdf2_sha, params, salt, hash]
				if pbkdf2_sha.starts_with("pbkdf2-sha")
					&& params.starts_with("i=")
					&& params.contains(",l=")
					&& !salt.is_empty() && !hash.is_empty() =>
			{
				true
			}

			_ => false,
		}
	}

	pub fn is_scrypt(&self) -> bool {
		let parts: Vec<&str> = self.hash.split('$').collect();
		parts.len() >= 3
			&& parts[1] == "scrypt"
			&& parts[2].split(',').count() == 3
			&& parts[2].split(',').all(|p| {
				p.split('=')
					.nth(1)
					.and_then(|s| s.parse::<u32>().ok())
					.is_some()
			})
	}

	pub fn is_uuid_v4(&self) -> bool {
		let parts: Vec<&str> = self.hash.split('-').collect();
		parts.len() == 5
			&& [8, 4, 4, 4, 12].iter().zip(parts.iter()).all(
				|(&len, &part)| {
					part.len() == len
						&& part.chars().all(|c| c.is_ascii_hexdigit())
				},
			) && parts[2].starts_with('4')
			&& ["8", "9", "a", "b"]
				.contains(&parts[3].get(..1).unwrap_or(""))
	}

	pub fn detect_possible_hashes(&self) -> Vec<String> {
		let mut possible_hashes = HashSet::new();

		let specific_checks = [
			(self.is_balloon(), "Balloon"),
			(self.is_bcrypt(), "bcrypt"),
			(self.is_argon2(), "Argon2"),
			(self.is_pbkdf2(), "PBKDF2"), // Make sure this line is present
			(self.is_scrypt(), "scrypt"),
			(self.is_uuid_v4(), "UUIDv4"),
		];

		let length_checks = check_hash_lengths!(self,
			32 => "MD4/MD5",
			40 => "SHA1/RIPE160/FSB160",
			48 => "Tiger/Shabal192",
			56 => "SHA3-224/Shabal224/FSB224",
			64 => "SHA256/SHA3-256/Blake3/Blake2s/Groestl/Shabal256/SM3/Streebog256/GOST94/GOST94ua/BeltHash",
			80 => "RIPEMD320",
			96 => "SHA384/SHA3-384/Shabal384/FSB384",
			128 => "SHA512/SHA3-512/Blake2b/Whirlpool/Shabal512/FSB512/Streebog512/Ascon",
		);

		for (check, hash_names) in
			specific_checks.iter().chain(length_checks.iter())
		{
			if *check {
				possible_hashes
					.extend(hash_names.split('/').map(String::from));
			}
		}

		let mut result: Vec<_> =
			possible_hashes.into_iter().collect();
		result.sort_unstable();
		result
	}
}

pub fn compare_hashes(hash1: &str, hash2: &str) -> bool {
	hash1.eq_ignore_ascii_case(hash2)
}

pub fn compare_file_hashes(
	file_src: &str,
	file_dst: &str,
) -> std::io::Result<bool> {
	let hash_src = std::fs::read_to_string(file_src)?;
	let hash_dst = std::fs::read_to_string(file_dst)?;

	for (line_number, (src, dst)) in
		hash_src.lines().zip(hash_dst.lines()).enumerate()
	{
		if src == dst {
			println!("Line {}: {} == {}", line_number + 1, src, dst);
		}
	}
	Ok(true)
}
