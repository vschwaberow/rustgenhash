// SPDX-License-Identifier: MIT OR Apache-2.0
// Project: rustgenhash
// File: commands.rs
// Author: Volker Schwaberow <volker@schwaberow.de>
// Copyright (c) 2022 Volker Schwaberow

#![allow(dead_code)]

use crate::rgh::kdf::render_kdf_output;
use crate::rgh::hash::{
	Argon2Config, BalloonConfig, BcryptConfig, PHash, Pbkdf2Config,
	ScryptConfig,
};
use crate::rgh::kdf::hkdf::{
	self, HkdfError, HkdfInput, HkdfMode, HkdfRequest, HkdfVariant,
};
use crate::rgh::kdf::profile::{Pbkdf2Profile, ScryptProfile};
use crate::rgh::kdf::SecretMaterial;
use balloon_hash::password_hash::SaltString as BalloonSaltString;
use password_hash::phc::{Salt, SaltString as PhcSaltString};
use serde_json::json;
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
	let salt = PhcSaltString::generate();
	let digest = PHash::hash_argon2_impl(password, config, &salt)
		.map_err(|err| io::Error::other(err.to_string()))?;
	let metadata = json!({
		"mem_cost": config.mem_cost,
		"time_cost": config.time_cost,
		"parallelism": config.parallelism,
		"salt": salt.as_ref()
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
	salt_override: Option<PhcSaltString>,
	hash_only: bool,
) -> Result<(), Box<dyn Error>> {
	ensure_password(password)?;
	let salt = match salt_override {
		Some(salt) => salt,
		None => {
			if let Some(profile) = profile {
				let mut salt_bytes = vec![0u8; profile.salt_len];
				getrandom::fill(&mut salt_bytes)
					.map_err(|err| io::Error::other(err.to_string()))?;
				Salt::new(&salt_bytes)
					.map(|salt| salt.to_salt_string())
					.map_err(|err| io::Error::other(err.to_string()))?
			} else {
				PhcSaltString::generate()
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
		"salt": salt.as_ref(),
		"memory_bytes": memory_bytes,
		"memory_kib": memory_bytes / 1024,
		"estimated_operations": estimated_ops
	});
	metadata["salt_length_bytes"] = json!(salt.to_salt().len());
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
	salt_override: Option<PhcSaltString>,
	hash_only: bool,
) -> Result<(), Box<dyn Error>> {
	ensure_password(password)?;
	let normalized = normalize_pbkdf2_scheme(scheme)?;
	let salt = match salt_override {
		Some(salt) => salt,
		None => {
			if let Some(profile) = profile {
				let mut salt_bytes = vec![0u8; profile.salt_len];
				getrandom::fill(&mut salt_bytes)
					.map_err(|err| io::Error::other(err.to_string()))?;
				Salt::new(&salt_bytes)
					.map(|salt| salt.to_salt_string())
					.map_err(|err| io::Error::other(err.to_string()))?
			} else {
				PhcSaltString::generate()
			}
		}
	};
	let digest = PHash::hash_pbkdf2_with_salt(
		password,
		normalized,
		config,
		salt.as_ref(),
	)
	.map_err(|err| io::Error::other(err))?;
	let salt_length = salt.to_salt().len();
	let mut metadata = json!({
		"rounds": config.rounds,
		"output_length": config.output_length,
		"algorithm": normalized,
		"salt": salt.as_ref(),
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
	let salt = PhcSaltString::generate();
	let digest = PHash::hash_bcrypt_hex(password, config, &salt)
		.map_err(|err| io::Error::other(err.to_string()))?;
	let metadata = json!({
		"cost": config.cost,
		"salt": salt.as_ref()
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
	let mut salt_bytes = [0u8; 16];
	getrandom::fill(&mut salt_bytes).map_err(|err| io::Error::other(err.to_string()))?;
	let salt = BalloonSaltString::encode_b64(&salt_bytes)
		.map_err(|err| io::Error::other(err.to_string()))?;
	let digest = PHash::hash_balloon_impl(password, config, &salt)
		.map_err(|err| io::Error::other(err.to_string()))?;
	let metadata = json!({
		"time_cost": config.time_cost,
		"memory_cost": config.memory_cost,
		"parallelism": config.parallelism,
		"salt": salt.as_ref()
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
	let params = sha_crypt::Params::new(10_000)
		.map_err(|err| io::Error::other(format!("{:?}", err)))?;
	let salt = PhcSaltString::generate();
	let sha_crypt_hasher = sha_crypt::ShaCrypt::new(sha_crypt::Algorithm::Sha512Crypt, params);
	let digest = sha_crypt::PasswordHasher::hash_password_with_salt(&sha_crypt_hasher, password.as_bytes(), salt.as_ref().as_bytes())
		.map_err(|err| io::Error::other(format!("{:?}", err)))?
		.to_string();
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
