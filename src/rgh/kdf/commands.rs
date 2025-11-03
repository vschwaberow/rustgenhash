// SPDX-License-Identifier: MIT OR Apache-2.0
// Project: rustgenhash
// File: commands.rs
// Author: Volker Schwaberow <volker@schwaberow.de>
// Copyright (c) 2022 Volker Schwaberow

#![allow(dead_code)]

use crate::render_kdf_output;
use crate::rgh::hash::{
	Argon2Config, BalloonConfig, BcryptConfig, PHash, Pbkdf2Config,
	ScryptConfig,
};
use argon2::password_hash::{
	rand_core::OsRng as ArgonOsRng, SaltString as ArgonSaltString,
};
use balloon_hash::password_hash::{
	rand_core::OsRng as BalloonOsRng, SaltString as BalloonSaltString,
};
use password_hash::PasswordHasher;
use pbkdf2::{
	password_hash::{
		Ident as Pbkdf2Ident, SaltString as Pbkdf2SaltString,
	},
	Params as Pbkdf2Params, Pbkdf2,
};
use rand_core::OsRng;
use scrypt::password_hash::SaltString as ScryptSaltString;
use serde_json::json;
use sha_crypt::Sha512Params;
use std::error::Error;
use std::io;

fn ensure_password(password: &str) -> Result<(), Box<dyn Error>> {
	if password.is_empty() {
		return Err(Box::new(io::Error::new(
			io::ErrorKind::InvalidInput,
			"Password must not be empty",
		)));
	}
	Ok(())
}

fn normalize_pbkdf2_scheme(
	scheme: &str,
) -> Result<&'static str, Box<dyn Error>> {
	if scheme.eq_ignore_ascii_case("sha256")
		|| scheme.eq_ignore_ascii_case("pbkdf2sha256")
		|| scheme.eq_ignore_ascii_case("pbkdf2-sha256")
	{
		Ok("pbkdf2-sha256")
	} else if scheme.eq_ignore_ascii_case("sha512")
		|| scheme.eq_ignore_ascii_case("pbkdf2sha512")
		|| scheme.eq_ignore_ascii_case("pbkdf2-sha512")
	{
		Ok("pbkdf2-sha512")
	} else {
		Err(Box::new(io::Error::new(
			io::ErrorKind::InvalidInput,
			format!("Unsupported PBKDF2 algorithm `{scheme}`"),
		)))
	}
}

/// Derive a key using Argon2 with user-specified parameters.
pub fn derive_argon2(
	password: &str,
	config: &Argon2Config,
	hash_only: bool,
) -> Result<(), Box<dyn Error>> {
	ensure_password(password)?;
	let mut rng = ArgonOsRng;
	let salt = ArgonSaltString::generate(&mut rng);
	let digest = PHash::hash_argon2_impl(password, config, &salt)
		.map_err(|err| io::Error::other(err.to_string()))?;
	let metadata = json!({
		"mem_cost": config.mem_cost,
		"time_cost": config.time_cost,
		"parallelism": config.parallelism,
		"salt": salt.as_str()
	});
	println!(
		"{}",
		render_kdf_output("argon2", &digest, metadata, hash_only)
	);
	Ok(())
}

/// Derive a key using Scrypt with user-specified parameters.
pub fn derive_scrypt(
	password: &str,
	config: &ScryptConfig,
	hash_only: bool,
) -> Result<(), Box<dyn Error>> {
	ensure_password(password)?;
	let mut rng = OsRng;
	let salt = ScryptSaltString::generate(&mut rng);
	let digest = PHash::hash_scrypt_impl(password, config, &salt)
		.map_err(|err| io::Error::other(err.to_string()))?;
	let metadata = json!({
		"log_n": config.log_n,
		"r": config.r,
		"p": config.p,
		"salt": salt.as_str()
	});
	println!(
		"{}",
		render_kdf_output("scrypt", &digest, metadata, hash_only)
	);
	Ok(())
}

/// Derive a key using PBKDF2 with user-specified parameters.
pub fn derive_pbkdf2(
	password: &str,
	scheme: &str,
	config: &Pbkdf2Config,
	hash_only: bool,
) -> Result<(), Box<dyn Error>> {
	ensure_password(password)?;
	let normalized = normalize_pbkdf2_scheme(scheme)?;
	let mut rng = OsRng;
	let salt = Pbkdf2SaltString::generate(&mut rng);
	let ident = Pbkdf2Ident::new(normalized)
		.map_err(|err| io::Error::other(err.to_string()))?;
	let params = Pbkdf2Params {
		output_length: config.output_length,
		rounds: config.rounds,
	};
	let hash = Pbkdf2::hash_password_customized(
		&Pbkdf2,
		password.as_bytes(),
		Some(ident),
		None,
		params,
		salt.as_salt(),
	)
	.map_err(|err| io::Error::other(err.to_string()))?;
	let digest = hash.to_string();
	let metadata = json!({
		"rounds": config.rounds,
		"output_length": config.output_length,
		"algorithm": normalized,
		"salt": salt.as_str()
	});
	println!(
		"{}",
		render_kdf_output("pbkdf2", &digest, metadata, hash_only)
	);
	Ok(())
}

/// Derive a key using Bcrypt with user-specified parameters.
pub fn derive_bcrypt(
	password: &str,
	config: &BcryptConfig,
	hash_only: bool,
) -> Result<(), Box<dyn Error>> {
	ensure_password(password)?;
	let mut rng = ArgonOsRng;
	let salt = ArgonSaltString::generate(&mut rng);
	let digest = PHash::hash_bcrypt_hex(password, config, &salt)
		.map_err(|err| io::Error::other(err.to_string()))?;
	let metadata = json!({
		"cost": config.cost,
		"salt": salt.as_str()
	});
	println!(
		"{}",
		render_kdf_output("bcrypt", &digest, metadata, hash_only)
	);
	Ok(())
}

/// Derive a key using Balloon hashing with user-specified parameters.
pub fn derive_balloon(
	password: &str,
	config: &BalloonConfig,
	hash_only: bool,
) -> Result<(), Box<dyn Error>> {
	ensure_password(password)?;
	let mut rng = BalloonOsRng;
	let salt = BalloonSaltString::generate(&mut rng);
	let digest = PHash::hash_balloon_impl(password, config, &salt)
		.map_err(|err| io::Error::other(err.to_string()))?;
	let metadata = json!({
		"time_cost": config.time_cost,
		"memory_cost": config.memory_cost,
		"parallelism": config.parallelism,
		"salt": salt.as_str()
	});
	println!(
		"{}",
		render_kdf_output("balloon", &digest, metadata, hash_only)
	);
	Ok(())
}

/// Derive a key using SHA-crypt with user-specified parameters.
pub fn derive_sha_crypt(
	password: &str,
	hash_only: bool,
) -> Result<(), Box<dyn Error>> {
	ensure_password(password)?;
	let params = Sha512Params::new(10_000)
		.map_err(|err| io::Error::other(format!("{:?}", err)))?;
	let digest = sha_crypt::sha512_simple(password, &params)
		.map_err(|err| io::Error::other(format!("{:?}", err)))?;
	let metadata = json!({
		"rounds": 10_000,
		"salt_embedded": true
	});
	println!(
		"{}",
		render_kdf_output("sha-crypt", &digest, metadata, hash_only)
	);
	Ok(())
}
