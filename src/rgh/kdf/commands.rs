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
use crate::rgh::kdf::hkdf::{
	self, HkdfError, HkdfInput, HkdfMode, HkdfRequest, HkdfVariant,
};
use crate::rgh::kdf::profile::{Pbkdf2Profile, ScryptProfile};
use crate::rgh::kdf::SecretMaterial;
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
use rand_core::{OsRng, RngCore};
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
	profile: Option<&ScryptProfile>,
	salt_override: Option<ScryptSaltString>,
	hash_only: bool,
) -> Result<(), Box<dyn Error>> {
	ensure_password(password)?;
	let mut rng = OsRng;
	let salt = match salt_override {
		Some(salt) => salt,
		None => {
			if let Some(profile) = profile {
				let mut salt_bytes = vec![0u8; profile.salt_len];
				rng.fill_bytes(&mut salt_bytes);
				ScryptSaltString::b64_encode(&salt_bytes).map_err(
					|err| io::Error::other(err.to_string()),
				)?
			} else {
				ScryptSaltString::generate(&mut rng)
			}
		}
	};
	let digest = PHash::hash_scrypt_impl(password, config, &salt)
		.map_err(|err| io::Error::other(err.to_string()))?;
	let n = 1u64 << config.log_n;
	let memory_bytes = 128u64 * config.r as u64 * n;
	let estimated_ops = n * config.p as u64;
	let mut metadata = json!({
		"log_n": config.log_n,
		"r": config.r,
		"p": config.p,
		"salt": salt.as_str(),
		"memory_bytes": memory_bytes,
		"memory_kib": memory_bytes / 1024,
		"estimated_operations": estimated_ops
	});
	let mut salt_buffer =
		vec![0u8; profile.map_or(16usize, |p| p.salt_len).max(16)];
	let salt_length_bytes = salt
		.as_salt()
		.b64_decode(&mut salt_buffer)
		.map_err(|err| io::Error::other(err.to_string()))?
		.len();
	metadata["salt_length_bytes"] = json!(salt_length_bytes);
	if let Some(profile) = profile {
		metadata["profile"] = json!({
			"id": profile.id,
			"reference": profile.reference,
			"description": profile.description,
			"salt_length": profile.salt_len,
			"output_length": profile.output_len,
			"log_n": profile.log_n,
			"r": profile.r,
			"p": profile.p
		});
	}
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
	profile: Option<&Pbkdf2Profile>,
	salt_override: Option<Pbkdf2SaltString>,
	hash_only: bool,
) -> Result<(), Box<dyn Error>> {
	ensure_password(password)?;
	let normalized = normalize_pbkdf2_scheme(scheme)?;
	let mut rng = OsRng;
	let salt = match salt_override {
		Some(salt) => salt,
		None => {
			if let Some(profile) = profile {
				let mut salt_bytes = vec![0u8; profile.salt_len];
				rng.fill_bytes(&mut salt_bytes);
				Pbkdf2SaltString::b64_encode(&salt_bytes).map_err(
					|err| io::Error::other(err.to_string()),
				)?
			} else {
				Pbkdf2SaltString::generate(&mut rng)
			}
		}
	};
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
	let expected_salt_len = profile.map_or(16usize, |p| p.salt_len);
	let mut salt_buffer = vec![0u8; expected_salt_len.max(16)];
	let salt_length = salt
		.as_salt()
		.b64_decode(&mut salt_buffer)
		.map_err(|err| io::Error::other(err.to_string()))?
		.len();
	let mut metadata = json!({
		"rounds": config.rounds,
		"output_length": config.output_length,
		"algorithm": normalized,
		"salt": salt.as_str(),
		"salt_length_bytes": salt_length
	});
	if let Some(profile) = profile {
		metadata["profile"] = json!({
			"id": profile.id,
			"reference": profile.reference,
			"description": profile.description,
			"salt_length": profile.salt_len,
			"output_length": profile.output_len,
			"rounds": profile.rounds
		});
	}
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

pub struct HkdfCliOptions {
	pub variant: HkdfVariant,
	pub ikm: Option<SecretMaterial>,
	pub prk: Option<SecretMaterial>,
	pub salt: Vec<u8>,
	pub info: Vec<u8>,
	pub length: usize,
	pub hash_only: bool,
}

pub fn derive_hkdf(
	options: HkdfCliOptions,
) -> Result<(), Box<dyn Error>> {
	let input = match options.variant.mode {
		HkdfMode::ExtractAndExpand => options
			.ikm
			.map(HkdfInput::Extract)
			.ok_or(HkdfError::MissingIkm)?,
		HkdfMode::ExpandOnly => options
			.prk
			.map(HkdfInput::Expand)
			.ok_or(HkdfError::MissingPrk)?,
	};
	let request = HkdfRequest {
		variant: options.variant,
		input,
		salt: options.salt,
		info: options.info,
		length: options.length,
	};
	let response = hkdf::derive(request)?;
	let digest_hex = hex::encode(response.derived_key);
	let label = match response.variant.mode {
		HkdfMode::ExtractAndExpand => response.variant.display_name(),
		HkdfMode::ExpandOnly => "HKDF-EXPAND",
	};
	let metadata = json!({
		"variant": response.variant.identifier(),
		"display_name": response.variant.display_name(),
		"label": label,
		"mode": match response.variant.mode {
			HkdfMode::ExtractAndExpand => "extract-expand",
			HkdfMode::ExpandOnly => "expand-only",
		},
		"length": response.length,
		"ikm_length": response.ikm_length,
		"prk_length": response.prk_length,
		"salt": hex::encode(response.salt),
		"info": hex::encode(response.info),
	});
	let algorithm_tag: &str = if options.hash_only {
		response.variant.identifier()
	} else {
		label
	};
	println!(
		"{}",
		render_kdf_output(
			algorithm_tag,
			&digest_hex,
			metadata,
			options.hash_only,
		)
	);
	Ok(())
}
