// SPDX-License-Identifier: MIT OR Apache-2.0
// Project: rustgenhash
// File: hash/phash.rs

use argon2::{password_hash::PasswordHasher, Argon2};
use balloon_hash::{
	password_hash::PasswordHasher as BalloonPasswordHasher,
	Algorithm as BalAlgorithm, Balloon, Params as BalParams,
};
use base64::{engine::general_purpose::STANDARD_NO_PAD, Engine};
use password_hash::{
	phc::{Salt, SaltString},
	CustomizedPasswordHasher,
};
use pbkdf2::{Algorithm as Pbkdf2Algorithm, Params as PbParams, Pbkdf2};
use scrypt::{Params as ScParams, Scrypt};

pub(crate) fn assemble_output(
	hash_only: bool,
	mut tokens: Vec<String>,
	original: Option<&str>,
) -> String {
	if !hash_only {
		if let Some(value) = original {
			tokens.push(value.to_string());
		}
	}
	tokens.join(" ")
}


#[derive(Clone, Debug)]
pub struct Argon2Config {
	pub mem_cost: u32,
	pub time_cost: u32,
	pub parallelism: u32,
}
impl Default for Argon2Config {
	fn default() -> Self {
		Self {
			mem_cost: 65536,
			time_cost: 3,
			parallelism: 4,
		}
	}
}

#[derive(Clone, Debug)]
pub struct ScryptConfig {
	pub log_n: u8,
	pub r: u32,
	pub p: u32,
}
impl Default for ScryptConfig {
	fn default() -> Self {
		Self {
			log_n: 15,
			r: 8,
			p: 1,
		}
	}
}

#[derive(Clone, Debug)]
pub struct BcryptConfig {
	pub cost: u32,
}
impl Default for BcryptConfig {
	fn default() -> Self {
		Self { cost: 12 }
	}
}

#[derive(Clone, Debug)]
pub struct Pbkdf2Config {
	pub rounds: u32,
	pub output_length: usize,
}
impl Default for Pbkdf2Config {
	fn default() -> Self {
		Self {
			rounds: 100_000,
			output_length: 32,
		}
	}
}

#[derive(Clone, Debug)]
pub struct BalloonConfig {
	pub time_cost: u32,
	pub memory_cost: u32,
	pub parallelism: u32,
}
impl Default for BalloonConfig {
	fn default() -> Self {
		Self {
			time_cost: 3,
			memory_cost: 65536,
			parallelism: 4,
		}
	}
}

macro_rules! impl_password_hash_fn {
	($name:ident, $impl_fn:ident, $cfg:ty, $salt:expr) => {
		pub fn $name(password: &str, config: &$cfg, hash_only: bool) {
			let salt = $salt;
			let hash = match Self::$impl_fn(password, config, &salt) {
				Ok(h) => h,
				Err(e) => {
					println!("Error hashing password: {}", e);
					return;
				}
			};
			let output = assemble_output(
				hash_only,
				vec![hash],
				Some(password),
			);
			println!("{}", output);
		}
	};
}


pub(crate) fn generate_phc_salt() -> SaltString {
	SaltString::generate()
}

pub(crate) fn salt_string_from_raw(bytes: &[u8]) -> Result<SaltString, String> {
	Salt::new(bytes)
		.map(|salt| salt.to_salt_string())
		.map_err(|err| err.to_string())
}

pub(crate) fn generate_balloon_salt() -> SaltString {
	generate_phc_salt()
}

pub(crate) fn balloon_salt_from_raw(bytes: &[u8]) -> Result<SaltString, String> {
	salt_string_from_raw(bytes)
}

pub(crate) fn pbkdf2_algorithm(scheme: &str) -> Result<Pbkdf2Algorithm, String> {
	match scheme {
		"pbkdf2sha256" | "pbkdf2-sha256" | "sha256" => {
			Ok(Pbkdf2Algorithm::Pbkdf2Sha256)
		}
		"pbkdf2sha512" | "pbkdf2-sha512" | "sha512" => {
			Ok(Pbkdf2Algorithm::Pbkdf2Sha512)
		}
		other => Err(format!("Unsupported PBKDF2 algorithm `{other}`")),
	}
}

pub struct PHash {}
impl PHash {
	pub fn derive_argon2_output(
		password: &str,
		cfg: &Argon2Config,
		hash_only: bool,
	) -> Result<String, String> {
		let salt = generate_phc_salt();
		Self::hash_argon2_impl(password, cfg, &salt)
			.map(|hash| {
				assemble_output(hash_only, vec![hash], Some(password))
			})
			.map_err(|err| err.to_string())
	}

	impl_password_hash_fn!(
		hash_argon2,
		hash_argon2_impl,
		Argon2Config,
		generate_phc_salt()
	);
	pub(crate) fn hash_argon2_impl(
		password: &str,
		cfg: &Argon2Config,
		salt: &SaltString,
	) -> Result<String, argon2::password_hash::Error> {
		let argon2 = Argon2::new(
			argon2::Algorithm::Argon2id,
			argon2::Version::V0x13,
			argon2::Params::new(
				cfg.mem_cost,
				cfg.time_cost,
				cfg.parallelism,
				None,
			)?,
		);
		Ok(argon2
			.hash_password_with_salt(
				password.as_bytes(),
				salt.to_salt().as_ref(),
			)?
			.to_string())
	}

	pub fn hash_balloon(
		password: &str,
		config: &BalloonConfig,
		hash_only: bool,
	) {
		match Self::derive_balloon_output(password, config, hash_only)
		{
			Ok(output) => println!("{}", output),
			Err(err) => {
				println!("Error hashing password: {}", err);
			}
		}
	}
	pub fn derive_balloon_output(
		password: &str,
		cfg: &BalloonConfig,
		hash_only: bool,
	) -> Result<String, String> {
		let salt = generate_balloon_salt();
		Self::hash_balloon_impl(password, cfg, &salt)
			.map(|hash| {
				assemble_output(hash_only, vec![hash], Some(password))
			})
			.map_err(|err| err.to_string())
	}
	pub(crate) fn hash_balloon_impl(
		password: &str,
		cfg: &BalloonConfig,
		salt: &SaltString,
	) -> Result<String, balloon_hash::password_hash::Error> {
		let balloon = Balloon::<sha2::Sha256>::new(
			BalAlgorithm::Balloon,
			BalParams::new(
				cfg.time_cost,
				cfg.memory_cost,
				cfg.parallelism,
			)?,
			None,
		);
		Ok(BalloonPasswordHasher::hash_password_with_salt(
			&balloon,
			password.as_bytes(),
			salt.to_salt().as_ref(),
		)?
		.to_string())
	}

	impl_password_hash_fn!(
		hash_scrypt,
		hash_scrypt_impl,
		ScryptConfig,
		generate_phc_salt()
	);
	pub fn derive_scrypt_output(
		password: &str,
		cfg: &ScryptConfig,
		hash_only: bool,
	) -> Result<String, String> {
		let salt = generate_phc_salt();
		Self::hash_scrypt_impl(password, cfg, &salt)
			.map(|hash| {
				assemble_output(hash_only, vec![hash], Some(password))
			})
			.map_err(|err| err.to_string())
	}
	pub(crate) fn hash_scrypt_impl(
		password: &str,
		cfg: &ScryptConfig,
		salt: &SaltString,
	) -> Result<String, scrypt::password_hash::Error> {
		let params = ScParams::new(cfg.log_n, cfg.r, cfg.p)
			.map_err(|_| scrypt::password_hash::Error::Crypto)?;
		let scrypt = Scrypt::new_with_params(params);
		Ok(CustomizedPasswordHasher::hash_password_customized(
			&scrypt,
			password.as_bytes(),
			salt.to_salt().as_ref(),
			None,
			None,
			params,
		)?
		.to_string())
	}

	pub fn hash_bcrypt(
		password: &str,
		cfg: &BcryptConfig,
		hash_only: bool,
	) {
		match Self::derive_bcrypt_output(password, cfg, hash_only) {
			Ok(output) => {
				println!("{}", output);
			}
			Err(err) => {
				eprintln!("Error: {}", err);
				std::process::exit(1);
			}
		}
	}

	pub fn derive_bcrypt_output(
		password: &str,
		cfg: &BcryptConfig,
		hash_only: bool,
	) -> Result<String, String> {
		let salt = generate_phc_salt();
		Self::hash_bcrypt_hex(password, cfg, &salt)
			.map(|hex| {
				assemble_output(hash_only, vec![hex], Some(password))
			})
			.map_err(|err| err.to_string())
	}

	pub fn hash_sha_crypt(password: &str, hash_only: bool) {
		match Self::derive_sha_crypt_output(password, hash_only) {
			Ok(output) => println!("{}", output),
			Err(err) => {
				eprintln!("Error: {}", err);
				std::process::exit(1);
			}
		}
	}

	pub fn derive_sha_crypt_output(
		password: &str,
		hash_only: bool,
	) -> Result<String, String> {
		let salt = generate_phc_salt();
		Self::hash_sha_crypt_with_salt(
			password,
			salt.to_salt().as_ref(),
		)
			.map(|digest| {
				assemble_output(hash_only, vec![digest], Some(password))
			})
	}

	pub fn hash_sha_crypt_with_salt(
		password: &str,
		salt: &[u8],
	) -> Result<String, String> {
		let params = sha_crypt::Params::new(10_000)
			.map_err(|err| format!("{:?}", err))?;
		let sha_crypt = sha_crypt::ShaCrypt::new(
			sha_crypt::Algorithm::Sha512Crypt,
			params,
		);
		let hash = sha_crypt::PasswordHasher::hash_password_with_salt(
			&sha_crypt,
			password.as_bytes(),
			salt,
		)
		.map_err(|err| format!("{:?}", err))?;
		Ok(hash.to_string())
	}

	pub fn hash_pbkdf2(
		password: &str,
		pb_scheme: &str,
		cfg: &Pbkdf2Config,
		hash_only: bool,
	) {
		match Self::derive_pbkdf2_output(
			password, pb_scheme, cfg, hash_only,
		) {
			Ok(output) => println!("{}", output),
			Err(err) => {
				eprintln!("Error: {}", err);
				std::process::exit(1);
			}
		}
	}

	pub fn derive_pbkdf2_output(
		password: &str,
		pb_scheme: &str,
		cfg: &Pbkdf2Config,
		hash_only: bool,
	) -> Result<String, String> {
		let algorithm = pbkdf2_algorithm(pb_scheme)?;
		let salt = generate_phc_salt();
		let params = PbParams::new_with_output_len(
			cfg.rounds,
			cfg.output_length,
		)
		.map_err(|err| err.to_string())?;
		let pbkdf2 = Pbkdf2::new(algorithm, params);
		let hash = CustomizedPasswordHasher::hash_password_customized(
			&pbkdf2,
			password.as_bytes(),
			salt.to_salt().as_ref(),
			Some(algorithm.to_str()),
			None,
			params,
		)
		.map_err(|err| err.to_string())?;
		Ok(assemble_output(
			hash_only,
			vec![hash.to_string()],
			Some(password),
		))
	}

	pub fn hash_pbkdf2_with_salt(
		password: &str,
		pb_scheme: &str,
		cfg: &Pbkdf2Config,
		salt_b64: &str,
	) -> Result<String, String> {
		let algorithm = pbkdf2_algorithm(pb_scheme)?;
		let salt_bytes = STANDARD_NO_PAD
			.decode(salt_b64)
			.map_err(|err| err.to_string())?;
		let salt = salt_string_from_raw(&salt_bytes)?;
		let params = PbParams::new_with_output_len(
			cfg.rounds,
			cfg.output_length,
		)
		.map_err(|err| err.to_string())?;
		let pbkdf2 = Pbkdf2::new(algorithm, params);
		let hash = CustomizedPasswordHasher::hash_password_customized(
			&pbkdf2,
			password.as_bytes(),
			salt.to_salt().as_ref(),
			Some(algorithm.to_str()),
			None,
			params,
		)
		.map_err(|err| err.to_string())?;
		Ok(hash.to_string())
	}

	pub(crate) fn hash_bcrypt_hex(
		password: &str,
		cfg: &BcryptConfig,
		salt: &SaltString,
	) -> Result<String, bcrypt_pbkdf::Error> {
		let mut out = [0; 64];
		bcrypt_pbkdf::bcrypt_pbkdf(
			password.as_bytes(),
			salt.as_ref().as_bytes(),
			cfg.cost,
			&mut out,
		)?;
		Ok(hex::encode(out))
	}

	pub fn hash_bcrypt_with_salt(
		password: &str,
		cfg: &BcryptConfig,
		salt_b64: &str,
	) -> Result<String, String> {
		let salt_bytes = STANDARD_NO_PAD
			.decode(salt_b64)
			.map_err(|err| err.to_string())?;
		let salt = salt_string_from_raw(&salt_bytes)?;
		Self::hash_bcrypt_hex(password, cfg, &salt)
			.map_err(|err| err.to_string())
	}

	pub fn hash_argon2_with_salt(
		password: &str,
		cfg: &Argon2Config,
		salt_b64: &str,
	) -> Result<String, String> {
		let salt_bytes = STANDARD_NO_PAD
			.decode(salt_b64)
			.map_err(|err| err.to_string())?;
		let salt = salt_string_from_raw(&salt_bytes)?;
		Self::hash_argon2_impl(password, cfg, &salt)
			.map_err(|err| err.to_string())
	}

	pub fn hash_balloon_with_salt(
		password: &str,
		cfg: &BalloonConfig,
		salt_b64: &str,
	) -> Result<String, String> {
		let salt_bytes = STANDARD_NO_PAD
			.decode(salt_b64)
			.map_err(|err| err.to_string())?;
		let salt = balloon_salt_from_raw(&salt_bytes)?;
		Self::hash_balloon_impl(password, cfg, &salt)
			.map_err(|err| err.to_string())
	}

	pub fn hash_scrypt_with_salt(
		password: &str,
		cfg: &ScryptConfig,
		salt_b64: &str,
	) -> Result<String, String> {
		let salt_bytes = STANDARD_NO_PAD
			.decode(salt_b64)
			.map_err(|err| err.to_string())?;
		let salt = salt_string_from_raw(&salt_bytes)?;
		Self::hash_scrypt_impl(password, cfg, &salt)
			.map_err(|err| err.to_string())
	}
}

