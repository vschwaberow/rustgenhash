// SPDX-License-Identifier: MIT OR Apache-2.0
// Project: rustgenhash
// File: hash.rs
// Author: Volker Schwaberow <volker@schwaberow.de>
// Copyright (c) 2022 Volker Schwaberow

use crate::rgh::app::OutputOptions;
use argon2::{
	password_hash::{rand_core::OsRng, PasswordHasher, SaltString},
	Argon2,
};
use ascon_hash::AsconHash;
use balloon_hash::{
	password_hash::{
		rand_core::OsRng as BalOsRng, SaltString as BalSaltString,
	},
	Balloon,
};
use blake2::Digest;
use digest::DynDigest;
use pbkdf2::{
	password_hash::{Ident as PbIdent, SaltString as PbSaltString},
	Pbkdf2,
};
use std::{collections::HashMap, io::Read};

use scrypt::{password_hash::SaltString as ScSaltString, Scrypt};
use skein::{consts::U32, Skein1024, Skein256, Skein512};

pub struct PHash {}

impl PHash {
	pub fn hash_ascon(password: &str) {
		let mut hasher = AsconHash::new();
		Digest::update(&mut hasher, password.as_bytes());
		let result = hasher.finalize();
		println!("{} {}", hex::encode(result), password);
	}

	pub fn hash_argon2(password: &str) {
		let salt = SaltString::generate(&mut OsRng);
		let argon2 = Argon2::default();
		let password_hash =
			match argon2.hash_password(password.as_bytes(), &salt) {
				Ok(hash) => hash.to_string(),
				Err(e) => {
					println!("Error hashing password: {}", e);
					return;
				}
			};
		println!("{} {}", password_hash, password);
	}

	pub fn hash_bcrypt(password: &str) {
		let salt = SaltString::generate(&mut OsRng);
		let salt = salt.as_ref().as_bytes();
		let mut output = [0; 64];
		bcrypt_pbkdf::bcrypt_pbkdf(
			password.as_bytes(),
			salt,
			36,
			&mut output,
		)
		.unwrap_or_else(|e| {
			eprintln!("Error: {}", e);
			std::process::exit(1);
		});
		println!("{} {}", hex::encode(output), password);
	}

	pub fn hash_sha_crypt(password: &str) {
		let params = sha_crypt::Sha512Params::new(10_000)
			.unwrap_or_else(|e| {
				println!("Error: {:?}", e);
				std::process::exit(1);
			});
		let password_hash =
			sha_crypt::sha512_simple(password, &params)
				.unwrap_or_else(|e| {
					println!("Error: {:?}", e);
					std::process::exit(1);
				});
		println!("{} {}", password_hash, password);
	}

	pub fn hash_balloon(password: &str) {
		let salt = BalSaltString::generate(&mut BalOsRng);
		let balloon = Balloon::<sha2::Sha256>::default();
		let password_hash =
			match balloon.hash_password(password.as_bytes(), &salt) {
				Ok(hash) => hash.to_string(),
				Err(e) => {
					println!("Error hashing password: {}", e);
					return;
				}
			};
		println!("{} {}", password_hash, password);
	}

	pub fn hash_pbkdf2(password: &str, pb_scheme: &str) {
		let pb_scheme_hmap: HashMap<&str, &str> = [
			("pbkdf2sha256", "pbkdf2-sha256"),
			("pbkdf2sha512", "pbkdf2-sha512"),
		]
		.iter()
		.cloned()
		.collect();

		let pb_s = pb_scheme_hmap.get(pb_scheme).unwrap_or(&"NONE");
		let algorithm = PbIdent::new(pb_s).unwrap();
		let salt = PbSaltString::generate(&mut OsRng);
		let params = pbkdf2::Params {
			output_length: 32,
			rounds: 100_000,
		};
		let password_hash = pbkdf2::Pbkdf2::hash_password_customized(
			&Pbkdf2,
			password.as_bytes(),
			Some(algorithm),
			None,
			params,
			salt.as_salt(),
		)
		.unwrap_or_else(|_| {
			eprintln!("Error: Could not hash PBKDF2 password");
			std::process::exit(1);
		});
		println!("{} {}", password_hash, password);
	}

	pub fn hash_scrypt(password: &str) {
		let salt = ScSaltString::generate(&mut OsRng);
		let password_hash =
			match Scrypt.hash_password(password.as_bytes(), &salt) {
				Ok(hash) => hash.to_string(),
				Err(e) => {
					println!("Error hashing password: {}", e);
					return;
				}
			};
		println!("{} {}", password_hash, password);
	}
}

#[derive(Clone)]
pub struct RHash {
	digest: Box<dyn DynDigest>,
}

impl RHash {
	pub fn new(alg: &str) -> Self {
		Self {
			digest: match alg {
				"BELTHASH" => Box::new(belt_hash::BeltHash::new()),
				"BLAKE2B" => Box::new(blake2::Blake2b512::new()),
				"BLAKE2S" => Box::new(blake2::Blake2s256::new()),
				"FSB160" => Box::new(fsb::Fsb160::new()),
				"FSB224" => Box::new(fsb::Fsb224::new()),
				"FSB256" => Box::new(fsb::Fsb256::new()),
				"FSB384" => Box::new(fsb::Fsb384::new()),
				"FSB512" => Box::new(fsb::Fsb512::new()),
				"GOST94" => Box::new(gost94::Gost94Test::new()),
				"GOST94UA" => Box::new(gost94::Gost94UA::new()),
				"GROESTL" => Box::new(groestl::Groestl256::new()),
				"JH224" => Box::new(jh::Jh224::new()),
				"JH256" => Box::new(jh::Jh256::new()),
				"JH384" => Box::new(jh::Jh384::new()),
				"JH512" => Box::new(jh::Jh512::new()),
				"MD2" => Box::new(md2::Md2::new()),
				"MD5" => Box::new(md5::Md5::new()),
				"MD4" => Box::new(md4::Md4::new()),
				"RIPEMD160" => Box::new(ripemd::Ripemd160::new()),
				"RIPEMD320" => Box::new(ripemd::Ripemd320::new()),
				"SHA1" => Box::new(sha1::Sha1::new()),
				"SHA224" => Box::new(sha2::Sha224::new()),
				"SHA256" => Box::new(sha2::Sha256::new()),
				"SHA384" => Box::new(sha2::Sha384::new()),
				"SHA512" => Box::new(sha2::Sha512::new()),
				"SHA3_224" => Box::new(sha3::Sha3_224::new()),
				"SHA3_256" => Box::new(sha3::Sha3_256::new()),
				"SHA3_384" => Box::new(sha3::Sha3_384::new()),
				"SHA3_512" => Box::new(sha3::Sha3_512::new()),
				"SHABAL192" => Box::new(shabal::Shabal192::new()),
				"SHABAL224" => Box::new(shabal::Shabal224::new()),
				"SHABAL256" => Box::new(shabal::Shabal256::new()),
				"SHABAL384" => Box::new(shabal::Shabal384::new()),
				"SHABAL512" => Box::new(shabal::Shabal512::new()),
				"SKEIN256" => Box::new(Skein256::<U32>::new()),
				"SKEIN512" => Box::new(Skein512::<U32>::new()),
				"SKEIN1024" => Box::new(Skein1024::<U32>::new()),
				"SM3" => Box::new(sm3::Sm3::new()),
				"STREEBOG256" => {
					Box::new(streebog::Streebog256::new())
				}
				"STREEBOG512" => {
					Box::new(streebog::Streebog512::new())
				}
				"TIGER" => Box::new(tiger::Tiger::new()),
				"WHIRLPOOL" => Box::new(whirlpool::Whirlpool::new()),
				_ => panic!("Unknown algorithm"),
			},
		}
	}

	pub fn process_string(&mut self, data: &[u8]) -> Vec<u8> {
		self.digest.update(data);
		self.digest.finalize_reset().to_vec()
	}

	pub fn process_file(
		&mut self,
		file: &str,
		output: OutputOptions,
	) -> Result<(), Box<dyn std::error::Error>> {
		let md = std::fs::metadata(file)?;
		if md.is_file() {
			let hashed_file = self.read_buffered(file)?;
			let string = match self.format_hashed_file(
				&hashed_file,
				file,
				output,
			) {
				Ok(result) => result,
				Err(error) => panic!("Error: {}", error),
			};
			self.print_hashed_file(&string);
		} else if md.is_dir() {
			let mut files = std::fs::read_dir(file)?;
			while let Some(Ok(entry)) = files.next() {
				if entry.path().is_file() {
					let path = self.match_path(entry.path().to_str());
					let hashed_file = self.read_buffered(&path)?;
					let string = match self.format_hashed_file(
						&hashed_file,
						&path,
						output.clone(),
					) {
						Ok(result) => result,
						Err(error) => panic!("Error: {}", error),
					};
					self.print_hashed_file(&string);
				}
			}
		}
		Ok(())
	}

	fn print_hashed_file(&self, hash: &str) {
		println!("{}", hash);
	}

	fn format_hashed_file(
		&self,
		hashed_file: &[u8],
		path: &str,
		output: OutputOptions,
	) -> Result<String, Box<dyn std::error::Error>> {
		match output {
			OutputOptions::Base64 => Ok(format!(
				"{} {}",
				base64::encode(hashed_file),
				path
			)),
			OutputOptions::Hex => {
				Ok(format!("{} {}", hex::encode(hashed_file), path))
			}
			OutputOptions::HexBase64 => Ok(format!(
				"{} {} {}",
				hex::encode(hashed_file),
				base64::encode(hashed_file),
				path
			)),
		}
	}

	pub fn read_buffered(
		&mut self,
		file: &str,
	) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
		let f = std::fs::File::open(file)?;
		let mut f = std::io::BufReader::new(f);
		let buffer_size = f.capacity();
		let mut buffer = vec![0; buffer_size];
		loop {
			let count = f.read(&mut buffer)?;
			if count == 0 {
				break;
			}
			self.digest.update(&buffer[..count]);
		}
		Ok(self.digest.finalize_reset().to_vec())
	}

	fn match_path(&mut self, path: Option<&str>) -> String {
		match path {
			Some(t) => t.to_string(),
			None => {
				eprintln!("Error: Invalid path");
				std::process::exit(1);
			}
		}
	}
}

