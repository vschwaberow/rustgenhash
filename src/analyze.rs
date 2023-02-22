/*
Copyright 2022 Volker Schwaberow <volker@schwaberow.de>
Permission is hereby granted, free of charge, to any person obtaining a
copy of this software and associated documentation files (the
"Software"), to deal in the Software without restriction, including without
limitation the rights to use, copy, modify, merge, publish, distribute,
sublicense, and/or sell copies of the Software, and to permit persons to whom the
Software is furnished to do so, subject to the following conditions:
The above copyright notice and this permission notice shall be
included in all copies or substantial portions of the Software.
THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS
OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT
SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR
OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE,
ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER
DEALINGS IN THE SOFTWARE.
Author(s): Volker Schwaberow
*/

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
		if self.hash.len() != 32 {
			return false;
		}
		self.hash.chars().all(|c| c.is_digit(16))
	}

	pub fn is_md5(&self) -> bool {
		if self.hash.len() != 32 {
			return false;
		}
		self.hash.chars().all(|c| c.is_digit(16))
	}

	pub fn is_groestl(&self) -> bool {
		if self.hash.len() != 64 {
			return false;
		}
		self.hash.chars().all(|c| c.is_digit(16))
	}

	pub fn is_sha1(&self) -> bool {
		if self.hash.len() != 40 {
			return false;
		}
		self.hash
			.chars()
			.all(|c| c.is_digit(16) || c.is_ascii_lowercase())
	}

	pub fn is_sha256(&self) -> bool {
		if self.hash.len() != 64 {
			return false;
		}
		self.hash.chars().all(|c| c.is_digit(16))
	}

	pub fn is_fsb160(&self) -> bool {
		if self.hash.len() != 40 {
			return false;
		}
		self.hash.chars().all(|c| c.is_digit(16))
	}

	pub fn is_fsb224(&self) -> bool {
		if self.hash.len() != 56 {
			return false;
		}
		self.hash.chars().all(|c| c.is_digit(16))
	}

	pub fn is_fsb256(&self) -> bool {
		if self.hash.len() != 64 {
			return false;
		}
		self.hash.chars().all(|c| c.is_digit(16))
	}

	pub fn is_fsb384(&self) -> bool {
		if self.hash.len() != 96 {
			return false;
		}
		self.hash.chars().all(|c| c.is_digit(16))
	}

	pub fn is_fsb512(&self) -> bool {
		if self.hash.len() != 128 {
			return false;
		}
		self.hash.chars().all(|c| c.is_digit(16))
	}

	pub fn is_blake2b(&self) -> bool {
		if self.hash.len() != 128 {
			return false;
		}
		self.hash.chars().all(|c| c.is_digit(16))
	}
	pub fn is_blake2s(&self) -> bool {
		if self.hash.len() != 64 {
			return false;
		}
		self.hash.chars().all(|c| c.is_digit(16))
	}

	pub fn is_gost94(&self) -> bool {
		if self.hash.len() != 64 {
			return false;
		}
		self.hash.chars().all(|c| c.is_digit(16))
	}

	pub fn is_gost94ua(&self) -> bool {
		if self.hash.len() != 64 {
			return false;
		}
		self.hash.chars().all(|c| c.is_digit(16))
	}
	pub fn is_belthash(&self) -> bool {
		if self.hash.len() != 64 {
			return false;
		}
		self.hash.chars().all(|c| c.is_digit(16))
	}

	pub fn is_sha512(&self) -> bool {
		if self.hash.len() != 128 {
			return false;
		}
		self.hash.chars().all(|c| c.is_digit(16))
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
			.split("=")
			.nth(1)
			.and_then(|s| s.parse::<u32>().ok());
		let others = params[2].split(",").collect::<Vec<&str>>();
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

	pub fn is_scrypt(&self) -> bool {
		if !self.hash.starts_with("$scrypt") {
			return false;
		}

		let params: Vec<&str> = self.hash[1..].split('$').collect();
		if params.len() < 4 {
			return false;
		}

		let others = params[1].split(",").collect::<Vec<&str>>();
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
		if self.is_sha1() {
			possible_hashes.push(String::from("SHA1"));
		}
		if self.is_sha256() {
			possible_hashes.push(String::from("SHA256"));
		}
		if self.is_sha512() {
			possible_hashes.push(String::from("SHA512"));
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
		possible_hashes.sort();
		possible_hashes
	}
}
