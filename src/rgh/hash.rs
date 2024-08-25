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

macro_rules! impl_hash_function {
	($name:ident, $hasher:expr) => {
		pub fn $name(password: &str) {
			let result = $hasher(password.as_bytes());
			println!("{} {}", hex::encode(result), password);
		}
	};
}

macro_rules! impl_password_hash {
	($name:ident, $hasher:expr, $salt_gen:expr) => {
		pub fn $name(password: &str) {
			let salt = $salt_gen;
			let password_hash = match $hasher
				.hash_password(password.as_bytes(), &salt)
			{
				Ok(hash) => hash.to_string(),
				Err(e) => {
					println!("Error hashing password: {}", e);
					return;
				}
			};
			println!("{} {}", password_hash, password);
		}
	};
}

pub struct PHash {}

impl PHash {
	impl_hash_function!(hash_ascon, AsconHash::digest);
	impl_password_hash!(
		hash_argon2,
		Argon2::default(),
		SaltString::generate(&mut OsRng)
	);
	impl_password_hash!(
		hash_balloon,
		Balloon::<sha2::Sha256>::default(),
		BalSaltString::generate(&mut BalOsRng)
	);
	impl_password_hash!(
		hash_scrypt,
		Scrypt,
		ScSaltString::generate(&mut OsRng)
	);

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
}

macro_rules! create_hasher {
    ($alg:expr, $($pattern:expr => $hasher:expr),+ $(,)?) => {
        match $alg {
            $(
                $pattern => Box::new($hasher),
            )+
            _ => panic!("Unknown algorithm"),
        }
    };
}

#[derive(Clone)]
pub struct RHash {
	digest: Box<dyn DynDigest>,
}

impl RHash {
	pub fn new(alg: &str) -> Self {
		Self {
			digest: create_hasher!(alg,
				"BELTHASH" => belt_hash::BeltHash::new(),
				"BLAKE2B" => blake2::Blake2b512::new(),
				"BLAKE2S" => blake2::Blake2s256::new(),
				"BLAKE3" => blake3::Hasher::new(),
				"FSB160" => fsb::Fsb160::new(),
				"FSB224" => fsb::Fsb224::new(),
				"FSB256" => fsb::Fsb256::new(),
				"FSB384" => fsb::Fsb384::new(),
				"FSB512" => fsb::Fsb512::new(),
				"GOST94" => gost94::Gost94Test::new(),
				"GOST94UA" => gost94::Gost94UA::new(),
				"GROESTL" => groestl::Groestl256::new(),
				"JH224" => jh::Jh224::new(),
				"JH256" => jh::Jh256::new(),
				"JH384" => jh::Jh384::new(),
				"JH512" => jh::Jh512::new(),
				"MD2" => md2::Md2::new(),
				"MD5" => md5::Md5::new(),
				"MD4" => md4::Md4::new(),
				"RIPEMD160" => ripemd::Ripemd160::new(),
				"RIPEMD320" => ripemd::Ripemd320::new(),
				"SHA1" => sha1::Sha1::new(),
				"SHA224" => sha2::Sha224::new(),
				"SHA256" => sha2::Sha256::new(),
				"SHA384" => sha2::Sha384::new(),
				"SHA512" => sha2::Sha512::new(),
				"SHA3_224" => sha3::Sha3_224::new(),
				"SHA3_256" => sha3::Sha3_256::new(),
				"SHA3_384" => sha3::Sha3_384::new(),
				"SHA3_512" => sha3::Sha3_512::new(),
				"SHABAL192" => shabal::Shabal192::new(),
				"SHABAL224" => shabal::Shabal224::new(),
				"SHABAL256" => shabal::Shabal256::new(),
				"SHABAL384" => shabal::Shabal384::new(),
				"SHABAL512" => shabal::Shabal512::new(),
				"SKEIN256" => Skein256::<U32>::new(),
				"SKEIN512" => Skein512::<U32>::new(),
				"SKEIN1024" => Skein1024::<U32>::new(),
				"SM3" => sm3::Sm3::new(),
				"STREEBOG256" => streebog::Streebog256::new(),
				"STREEBOG512" => streebog::Streebog512::new(),
				"TIGER" => tiger::Tiger::new(),
				"WHIRLPOOL" => whirlpool::Whirlpool::new(),
			),
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
			let string =
				self.format_hashed_file(&hashed_file, file, output)?;
			self.print_hashed_file(&string);
		} else if md.is_dir() {
			for entry in std::fs::read_dir(file)? {
				let entry = entry?;
				if entry.path().is_file() {
					let path_buf = entry.path();
					let path =
						path_buf.to_str().ok_or_else(|| {
							std::io::Error::new(
								std::io::ErrorKind::InvalidData,
								"Invalid path",
							)
						})?;
					let hashed_file = self.read_buffered(path)?;
					let string = self.format_hashed_file(
						&hashed_file,
						path,
						output.clone(),
					)?;
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
		Ok(match output {
			OutputOptions::Base64 => {
				format!("{} {}", base64::encode(hashed_file), path)
			}
			OutputOptions::Hex => {
				format!("{} {}", hex::encode(hashed_file), path)
			}
			OutputOptions::HexBase64 => format!(
				"{} {} {}",
				hex::encode(hashed_file),
				base64::encode(hashed_file),
				path
			),
		})
	}

	pub fn read_buffered(
		&mut self,
		file: &str,
	) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
		let mut f =
			std::io::BufReader::new(std::fs::File::open(file)?);
		let mut buffer = vec![0; f.capacity()];
		loop {
			let count = f.read(&mut buffer)?;
			if count == 0 {
				break;
			}
			self.digest.update(&buffer[..count]);
		}
		Ok(self.digest.finalize_reset().to_vec())
	}
}
