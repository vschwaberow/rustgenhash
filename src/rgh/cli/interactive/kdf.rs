// SPDX-License-Identifier: MIT OR Apache-2.0
// Project: rustgenhash

use super::common::prompt_password;
use crate::rgh::hash::{
	Argon2Config, BalloonConfig, BcryptConfig, Pbkdf2Config,
	ScryptConfig,
};
use crate::rgh::kdf::{
	commands as kdf_commands,
	hkdf::{self, HkdfMode, HKDF_VARIANTS},
	profile, SecretMaterial,
};
use colored::*;
use dialoguer::{Confirm, Input, Password, Select};
use std::error::Error;
use std::io;

pub(crate) fn interactive_kdf_menu() -> Result<(), Box<dyn Error>> {
	let actions = vec![
		"Argon2",
		"Scrypt",
		"PBKDF2",
		"Bcrypt",
		"Balloon",
		"SHA-crypt",
		"HKDF",
		"Back",
	];
	loop {
		let selection = Select::new()
			.with_prompt("KDF options")
			.items(&actions)
			.interact()?;
		match selection {
			0 => {
				let password =
					prompt_password("Enter password for Argon2")?;
				let config = get_argon2_config_interactive()?;
				let hash_only = Confirm::new()
					.with_prompt("Emit only the derived key output?")
					.default(false)
					.interact()?;
				kdf_commands::derive_argon2(
					&password, &config, hash_only,
				)?;
			}
			1 => {
				let password =
					prompt_password("Enter password for Scrypt")?;
				let (config, preset) =
					get_scrypt_config_interactive()?;
				let hash_only = Confirm::new()
					.with_prompt("Emit only the derived key output?")
					.default(false)
					.interact()?;
				kdf_commands::derive_scrypt(
					&password, &config, preset, None, hash_only,
				)?;
			}
			2 => {
				let password =
					prompt_password("Enter password for PBKDF2")?;
				let (config, preset) =
					get_pbkdf2_config_interactive()?;
				let variants = vec!["sha256", "sha512"];
				let variant_idx = Select::new()
					.with_prompt("Select PBKDF2 digest variant")
					.items(&variants)
					.interact()?;
				let scheme = variants[variant_idx];
				let hash_only = Confirm::new()
					.with_prompt("Emit only the derived key output?")
					.default(false)
					.interact()?;
				kdf_commands::derive_pbkdf2(
					&password, scheme, &config, preset, None,
					hash_only,
				)?;
			}
			3 => {
				let password = prompt_password(
					"Enter password for bcrypt-pbkdf",
				)?;
				let config = get_bcrypt_config_interactive()?;
				let hash_only = Confirm::new()
					.with_prompt("Emit only the derived key output?")
					.default(false)
					.interact()?;
				kdf_commands::derive_bcrypt(
					&password, &config, hash_only,
				)?;
			}
			4 => {
				let password =
					prompt_password("Enter password for Balloon")?;
				let config = get_balloon_config_interactive()?;
				let hash_only = Confirm::new()
					.with_prompt("Emit only the derived key output?")
					.default(false)
					.interact()?;
				kdf_commands::derive_balloon(
					&password, &config, hash_only,
				)?;
			}
			5 => {
				let password =
					prompt_password("Enter password for SHA-crypt")?;
				let hash_only = Confirm::new()
					.with_prompt("Emit only the derived key output?")
					.default(false)
					.interact()?;
				kdf_commands::derive_sha_crypt(&password, hash_only)?;
			}
			6 => {
				interactive_hkdf()?;
			}
			7 => break,
			_ => unreachable!(),
		}
	}
	Ok(())
}

pub(crate) fn interactive_hkdf() -> Result<(), Box<dyn Error>> {
	let variant_labels: Vec<String> = HKDF_VARIANTS
		.iter()
		.map(|variant| {
			let mode_label = match variant.mode {
				HkdfMode::ExtractAndExpand => "extract+expand",
				HkdfMode::ExpandOnly => "expand-only",
			};
			format!("{} ({mode_label})", variant.display_name())
		})
		.collect();
	let variant_index = Select::new()
		.with_prompt("Select HKDF variant")
		.items(&variant_labels)
		.default(0)
		.interact()?;
	let variant = HKDF_VARIANTS[variant_index];
	let proceed = Confirm::new()
		.with_prompt("Continue with HKDF derivation?")
		.default(false)
		.interact()?;
	if !proceed {
		println!("{}", "HKDF flow cancelled before entry.".cyan());
		return Ok(());
	}
	let ikm = if variant.requires_ikm() {
		println!(
			"{}",
			"Input keying material will be captured without echo."
				.yellow()
		);
		let ikm_text = Password::new()
			.with_prompt("Enter input keying material (IKM)")
			.allow_empty_password(false)
			.interact()?;
		Some(SecretMaterial::from_bytes(ikm_text.into_bytes()))
	} else {
		None
	};
	let prk = if variant.requires_prk() {
		println!(
			"Expand-only mode selected: provide a PRK generated in a trusted environment.",
		);
		let prk_hex: String = Input::new()
			.with_prompt("Enter PRK (hex)")
			.allow_empty(false)
			.interact_text()?;
		let prk_bytes =
			hex::decode(prk_hex.trim()).map_err(|err| {
				io::Error::new(
					io::ErrorKind::InvalidInput,
					format!("PRK must be hex: {}", err),
				)
			})?;
		if prk_bytes.is_empty() {
			return Err(Box::new(io::Error::new(
				io::ErrorKind::InvalidInput,
				"PRK must not be empty",
			)));
		}
		Some(SecretMaterial::from_bytes(prk_bytes))
	} else {
		None
	};
	let length: usize = Input::new()
		.with_prompt("Derived length (bytes)")
		.default(variant.output_size())
		.interact_text()?;
	if length == 0 {
		return Err(Box::new(io::Error::new(
			io::ErrorKind::InvalidInput,
			"Derived length must be greater than zero",
		)));
	}
	let salt_text: String = Input::new()
		.with_prompt("Salt (hex, leave blank for empty)")
		.allow_empty(true)
		.interact_text()?;
	let salt_clean = salt_text.trim().to_string();
	let salt_value = if salt_clean.is_empty() {
		None
	} else {
		Some(salt_clean)
	};
	let salt_bytes =
		hkdf::parse_optional_hex("salt", salt_value.as_ref())?;
	if salt_value.is_none() && variant.requires_ikm() {
		eprintln!("info: default salt = empty string");
	}
	let info_text: String = Input::new()
		.with_prompt("Info (hex, optional)")
		.allow_empty(true)
		.interact_text()?;
	let info_clean = info_text.trim().to_string();
	let info_value = if info_clean.is_empty() {
		None
	} else {
		Some(info_clean)
	};
	let info_bytes =
		hkdf::parse_optional_hex("info", info_value.as_ref())?;
	let hash_only = Confirm::new()
		.with_prompt("Emit only derived key hex?")
		.default(false)
		.interact()?;
	let confirm = Confirm::new()
		.with_prompt("Compute HKDF now and display the result?")
		.default(false)
		.interact()?;
	if !confirm {
		println!(
			"{}",
			"HKDF derivation cancelled before execution.".cyan()
		);
		return Ok(());
	}
	let options = kdf_commands::HkdfCliOptions {
		variant,
		ikm,
		prk,
		salt: salt_bytes,
		info: info_bytes,
		length,
		hash_only,
	};
	kdf_commands::derive_hkdf(options)?;
	println!("{}", "HKDF derivation complete.".green());
	Ok(())
}

pub(crate) fn get_argon2_config_interactive(
) -> Result<Argon2Config, Box<dyn Error>> {
	let mem_cost: u32 = Input::new()
		.with_prompt("Argon2 memory cost (KiB)")
		.default(65536)
		.interact_text()?;
	let time_cost: u32 = Input::new()
		.with_prompt("Argon2 time cost (iterations)")
		.default(3)
		.interact_text()?;
	let parallelism: u32 = Input::new()
		.with_prompt("Argon2 parallelism")
		.default(4)
		.interact_text()?;

	Ok(Argon2Config {
		mem_cost,
		time_cost,
		parallelism,
	})
}

pub(crate) fn get_scrypt_config_interactive() -> Result<
	(ScryptConfig, Option<&'static profile::ScryptProfile>),
	Box<dyn Error>,
> {
	let mut options = vec!["Custom parameters".to_string()];
	options.extend(profile::SCRYPT_PROFILES.iter().map(|preset| {
		format!("{} — {}", preset.id, preset.description)
	}));
	let selection = Select::new()
		.with_prompt("Select scrypt preset (or Custom)")
		.items(&options)
		.default(0)
		.interact()?;
	let preset: Option<&'static profile::ScryptProfile> =
		if selection == 0 {
			None
		} else {
			Some(&profile::SCRYPT_PROFILES[selection - 1])
		};
	if let Some(profile) = preset {
		println!(
		"Using preset `{}` (log_n={}, r={}, p={}, salt_len={} bytes). Values you enter must meet or exceed these minimums.",
		profile.id,
		profile.log_n,
		profile.r,
		profile.p,
		profile.salt_len,
	);
	}
	let default_log_n = preset.map_or(15, |p| p.log_n);
	let default_r = preset.map_or(8, |p| p.r);
	let default_p = preset.map_or(1, |p| p.p);
	let log_n: u8 = Input::new()
		.with_prompt("Scrypt log_n (2^n)")
		.default(default_log_n)
		.interact_text()?;
	let r: u32 = Input::new()
		.with_prompt("Scrypt r")
		.default(default_r)
		.interact_text()?;
	let p: u32 = Input::new()
		.with_prompt("Scrypt p")
		.default(default_p)
		.interact_text()?;
	if let Some(profile) = preset {
		if log_n < profile.log_n || r < profile.r || p < profile.p {
			return Err(Box::new(io::Error::new(
				io::ErrorKind::InvalidInput,
				"Supplied parameters must meet or exceed profile minimums",
			)));
		}
	}
	Ok((ScryptConfig { log_n, r, p }, preset))
}

pub(crate) fn get_bcrypt_config_interactive(
) -> Result<BcryptConfig, Box<dyn Error>> {
	let cost: u32 = Input::new()
		.with_prompt("Bcrypt cost")
		.default(12)
		.interact_text()?;

	Ok(BcryptConfig { cost })
}

pub(crate) fn get_pbkdf2_config_interactive() -> Result<
	(Pbkdf2Config, Option<&'static profile::Pbkdf2Profile>),
	Box<dyn Error>,
> {
	let mut options = vec!["Custom parameters".to_string()];
	options.extend(profile::PBKDF2_PROFILES.iter().map(|preset| {
		format!("{} — {}", preset.id, preset.description)
	}));
	let selection = Select::new()
		.with_prompt("Select PBKDF2 profile (or Custom)")
		.items(&options)
		.default(0)
		.interact()?;
	let preset: Option<&'static profile::Pbkdf2Profile> =
		if selection == 0 {
			None
		} else {
			Some(&profile::PBKDF2_PROFILES[selection - 1])
		};
	if let Some(profile) = preset {
		println!(
		"Using preset `{}` (rounds {}, salt_len {} bytes, output_len {} bytes). Overrides must be ≥ the preset values.",
		profile.id,
		profile.rounds,
		profile.salt_len,
		profile.output_len,
	);
	}
	let default_rounds = preset.map_or(100_000, |p| p.rounds);
	let default_length = preset.map_or(32, |p| p.output_len);
	let rounds: u32 = Input::new()
		.with_prompt("PBKDF2 rounds")
		.default(default_rounds)
		.interact_text()?;
	let output_length: usize = Input::new()
		.with_prompt("PBKDF2 output length (bytes)")
		.default(default_length)
		.interact_text()?;
	if let Some(profile) = preset {
		if rounds < profile.rounds
			|| output_length < profile.output_len
		{
			return Err(Box::new(io::Error::new(
				io::ErrorKind::InvalidInput,
				"Supplied parameters must meet or exceed profile minimums",
			)));
		}
	}
	Ok((
		Pbkdf2Config {
			rounds,
			output_length,
		},
		preset,
	))
}

pub(crate) fn get_balloon_config_interactive(
) -> Result<BalloonConfig, Box<dyn Error>> {
	let time_cost: u32 = Input::new()
		.with_prompt("Balloon time cost (iterations)")
		.default(3)
		.interact_text()?;
	let memory_cost: u32 = Input::new()
		.with_prompt("Balloon memory cost (KiB)")
		.default(65536)
		.interact_text()?;
	let parallelism: u32 = Input::new()
		.with_prompt("Balloon parallelism")
		.default(4)
		.interact_text()?;

	Ok(BalloonConfig {
		time_cost,
		memory_cost,
		parallelism,
	})
}

