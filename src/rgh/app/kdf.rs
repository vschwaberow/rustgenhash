// SPDX-License-Identifier: MIT OR Apache-2.0
// Project: rustgenhash
// File: app/kdf.rs

use crate::rgh::hash::{
	Argon2Config, BalloonConfig, BcryptConfig, Pbkdf2Config, ScryptConfig,
};
use crate::rgh::kdf::{
	commands as kdf_commands,
	hkdf::{self, HkdfAlgorithm, HkdfMode, HKDF_VARIANTS},
	profile, SecretMaterial,
};
use clap::parser::ValueSource;
use dialoguer::Password;
use password_hash::phc::Salt;
use std::error::Error;
use std::io::{self, Read};
use std::path::Path;
use std::process;
use std::str::FromStr;

pub(crate) fn resolve_kdf_password(
	args: &clap::ArgMatches,
) -> Result<String, Box<dyn Error>> {
	if let Some(explicit) = args.get_one::<String>("password") {
		return Ok(explicit.clone());
	}
	if args.get_flag("password-stdin") {
		let mut stdin = io::stdin();
		let mut buffer = String::new();
		stdin.read_to_string(&mut buffer)?;
		let trimmed = buffer.trim_end_matches(&['\n', '\r'][..]).to_string();
		return Ok(trimmed);
	}
	let password = Password::new()
		.with_prompt("Enter password")
		.allow_empty_password(false)
		.interact()?;
	Ok(password)
}

pub(crate) fn handle_kdf_command(
	matches: &clap::ArgMatches,
) -> Result<(), Box<dyn Error>> {
	match matches.subcommand() {
		Some(("argon2", args)) => {
			let password = resolve_kdf_password(args)?;
			let hash_only = args.get_flag("hash-only");
			let config = Argon2Config {
				mem_cost: *args
					.get_one::<u32>("mem-cost")
					.expect("mem-cost has default"),
				time_cost: *args
					.get_one::<u32>("time-cost")
					.expect("time-cost has default"),
				parallelism: *args
					.get_one::<u32>("parallelism")
					.expect("parallelism has default"),
			};
			kdf_commands::derive_argon2(&password, &config, hash_only)
		}
		Some(("scrypt", args)) => {
			let password = resolve_kdf_password(args)?;
			let hash_only = args.get_flag("hash-only");
			let profile =
				match args.get_one::<String>("profile") {
					Some(id) => {
						Some(
							profile::get_scrypt_profile(id)
									.ok_or_else(|| {
										io::Error::new(
											io::ErrorKind::InvalidInput,
											format!("Unknown scrypt profile `{}`", id),
										)
									})
						?,
						)
					}
					None => None,
				};
			let log_n_source = args.value_source("log-n");
			let r_source = args.value_source("r");
			let p_source = args.value_source("p");
			let mut log_n = *args
				.get_one::<u8>("log-n")
				.expect("log-n has default");
			let mut r =
				*args.get_one::<u32>("r").expect("r has default");
			let mut p =
				*args.get_one::<u32>("p").expect("p has default");
			if let Some(profile) = profile {
				if matches!(
						log_n_source,
						Some(ValueSource::DefaultValue)
				) {
					log_n = profile.log_n;
				}
				else if log_n < profile.log_n {
					return Err(Box::new(io::Error::new(
						io::ErrorKind::InvalidInput,
						format!(
							"Scrypt log_n {} must be >= profile minimum {}",
							log_n,
							profile.log_n
						),
					)));
				}
				if matches!(r_source, Some(ValueSource::DefaultValue))
				{
					r = profile.r;
				}
				else if r < profile.r {
					return Err(Box::new(io::Error::new(
						io::ErrorKind::InvalidInput,
						format!("Scrypt r {} must be >= profile minimum {}", r, profile.r)
					)));
				}
				if matches!(p_source, Some(ValueSource::DefaultValue))
				{
					p = profile.p;
				}
				else if p < profile.p {
					return Err(Box::new(io::Error::new(
						io::ErrorKind::InvalidInput,
						format!("Scrypt p {} must be >= profile minimum {}", p, profile.p)
					)));
				}
			}
			let config = ScryptConfig { log_n, r, p };
			let salt_override = match args.get_one::<String>("salt") {
				Some(hex_value) => {
					let bytes = hex::decode(hex_value).map_err(|err| {
						io::Error::new(
							io::ErrorKind::InvalidInput,
							format!("salt must be hex: {}", err),
						)
					})?;
					if bytes.is_empty() {
						return Err(Box::new(io::Error::new(
							io::ErrorKind::InvalidInput,
							"Scrypt salt must not be empty",
						)));
					}
					if let Some(profile) = profile {
						if bytes.len() < profile.salt_len {
							return Err(Box::new(io::Error::new(
								io::ErrorKind::InvalidInput,
								format!(
								"Scrypt salt length {} must be >= profile minimum {} bytes",
								bytes.len(),
								profile.salt_len
							),
						)));
						}
					}
					Some(
						Salt::new(&bytes)
							.map(|s| s.to_salt_string())
							.map_err(|err| {
								io::Error::other(err.to_string())
							})?,
					)
				}
				None => None,
			};
			kdf_commands::derive_scrypt(
				&password,
				&config,
				profile,
			salt_override,
			hash_only,
		)
		}
		Some(("pbkdf2", args)) => {
			let password = resolve_kdf_password(args)?;
			let hash_only = args.get_flag("hash-only");
			let profile =
				match args.get_one::<String>("profile") {
					Some(id) => {
						Some(
							profile::get_pbkdf2_profile(id)
									.ok_or_else(|| {
										io::Error::new(
											io::ErrorKind::InvalidInput,
											format!("Unknown PBKDF2 profile `{}`", id),
										)
									})
						?,
						)
					}
					None => None,
				};
			let rounds_source = args.value_source("rounds");
			let length_source = args.value_source("length");
			let mut rounds = *args
				.get_one::<u32>("rounds")
				.expect("rounds has default");
			let mut output_length = *args
				.get_one::<usize>("length")
				.expect("length has default");
			if let Some(profile) = profile {
				if matches!(
						rounds_source,
						Some(ValueSource::DefaultValue)
				) {
					rounds = profile.rounds;
				}
				else if rounds < profile.rounds {
					return Err(Box::new(io::Error::new(
						io::ErrorKind::InvalidInput,
						// Audit harness fixture `kdf_pbkdf2_invalid_iterations` relies on this exact wording.
						format!(
							"PBKDF2 rounds {} must be >= profile minimum {}",
							rounds,
						profile.rounds
						),
					)));
				}
				if matches!(
						length_source,
						Some(ValueSource::DefaultValue)
				) {
					output_length = profile.output_len;
				}
				else if output_length < profile.output_len {
					return Err(Box::new(io::Error::new(
						io::ErrorKind::InvalidInput,
						format!(
							"PBKDF2 length {} must be >= profile minimum {}",
							output_length,
							profile.output_len
						),
					)));
				}
			}
			let config = Pbkdf2Config {
				rounds,
				output_length,
			};
			let scheme = args
				.get_one::<String>("algorithm")
				.expect("algorithm has default");
			let salt_override = match args.get_one::<String>("salt") {
				Some(hex_value) => {
					let bytes = hex::decode(hex_value).map_err(|err| {
						io::Error::new(
							io::ErrorKind::InvalidInput,
							format!("salt must be hex: {}", err),
						)
					})?;
					if bytes.is_empty() {
						return Err(Box::new(io::Error::new(
							io::ErrorKind::InvalidInput,
							"PBKDF2 salt must not be empty",
						)));
					}
					if let Some(profile) = profile {
						if bytes.len() < profile.salt_len {
							return Err(Box::new(io::Error::new(
								io::ErrorKind::InvalidInput,
								format!(
								"PBKDF2 salt length {} must be >= profile minimum {} bytes",
								bytes.len(),
								profile.salt_len
							),
						)));
						}
					}
					Some(
						Salt::new(&bytes)
							.map(|s| s.to_salt_string())
							.map_err(|err| {
								io::Error::other(err.to_string())
							})?,
					)
				}
				None => None,
			};
			kdf_commands::derive_pbkdf2(
				&password,
				scheme,
				&config,
				profile,
			salt_override,
			hash_only,
		)
		}
		Some(("bcrypt", args)) => {
			let password = resolve_kdf_password(args)?;
			let hash_only = args.get_flag("hash-only");
			let config = BcryptConfig {
				cost: *args
					.get_one::<u32>("cost")
					.expect("cost has default"),
			};
			kdf_commands::derive_bcrypt(&password, &config, hash_only)
		}
		Some(("hkdf", args)) => {
			let expand_only = args.get_flag("expand-only");
			let ikm_stdin = args.get_flag("ikm-stdin");
			let prk_stdin = args.get_flag("prk-stdin");
			if ikm_stdin && prk_stdin {
				return Err(Box::new(io::Error::new(
					io::ErrorKind::InvalidInput,
					"Cannot read IKM and PRK from stdin in the same invocation",
				)));
			}
			let hash = args
				.get_one::<String>("hash")
				.expect("hash has default");
			let algorithm = HkdfAlgorithm::from_str(hash)?;
			let variant = HKDF_VARIANTS
				.iter()
				.find(|variant| {
					variant.algorithm == algorithm
						&& variant.mode
								== if expand_only {
										HkdfMode::ExpandOnly
									} else {
										HkdfMode::ExtractAndExpand
									}
				})
				.copied()
				.ok_or_else(|| {
					io::Error::new(
						io::ErrorKind::InvalidInput,
						"Unsupported HKDF variant",
					)
				})?;
			let salt_arg = args.get_one::<String>("salt");
			let info_arg = args.get_one::<String>("info");
			let salt = hkdf::parse_optional_hex("salt", salt_arg)?;
			let info = hkdf::parse_optional_hex("info", info_arg)?;
			if salt_arg.is_none() && !expand_only {
				eprintln!("info: default salt = empty string");
			}
			let mut stdin_consumed = false;
			let ikm = if expand_only {
				if ikm_stdin || args.contains_id("ikm") {
					return Err(Box::new(io::Error::new(
						io::ErrorKind::InvalidInput,
						"Expand-only mode must not include IKM input",
					)));
				}
				None
			} else {
				let ikm_material = if let Some(hex) = args.get_one::<String>("ikm") {
					let bytes = hex::decode(hex).map_err(|err| {
						io::Error::new(
							io::ErrorKind::InvalidInput,
							format!("ikm must be hex: {}", err),
						)
					})?;
					SecretMaterial::from_bytes(bytes)
				} else if ikm_stdin {
					stdin_consumed = true;
					SecretMaterial::from_stdin()?
				} else {
					return Err(Box::new(io::Error::new(
						io::ErrorKind::InvalidInput,
						"Provide --ikm <HEX> or --ikm-stdin for HKDF",
					)));
				};
				if ikm_material.is_empty() {
					return Err(Box::new(io::Error::new(
						io::ErrorKind::InvalidInput,
						"input keying material must not be empty",
					)));
				}
				Some(ikm_material)
			};
			let prk = if expand_only {
				if let Some(path) = args.get_one::<String>("prk") {
					let prk =
						SecretMaterial::from_file(Path::new(path))?;
					if prk.is_empty() {
						return Err(Box::new(io::Error::new(
							io::ErrorKind::InvalidInput,
							"PRK file was empty",
						)));
					}
					Some(prk)
				} else if prk_stdin {
					if stdin_consumed {
						return Err(Box::new(io::Error::new(
							io::ErrorKind::InvalidInput,
							"stdin already consumed for IKM",
						)));
					}
					let prk = SecretMaterial::from_stdin()?;
					if prk.is_empty() {
						return Err(Box::new(io::Error::new(
							io::ErrorKind::InvalidInput,
							"PRK from stdin was empty",
						)));
					}
					Some(prk)
				} else {
					eprintln!(
						"error: {}",
						hkdf::EXPAND_ONLY_PRK_HINT
					);
					process::exit(2);
				}
			} else {
				None
			};
			let length = *args
				.get_one::<usize>("len")
				.expect("len is required");
			let options = kdf_commands::HkdfCliOptions {
				variant,
				ikm,
				prk,
			salt,
			info,
			length,
			hash_only: args.get_flag("hash-only"),
			};
			kdf_commands::derive_hkdf(options)
		}
		Some(("balloon", args)) => {
			let password = resolve_kdf_password(args)?;
			let hash_only = args.get_flag("hash-only");
			let config = BalloonConfig {
				time_cost: *args
					.get_one::<u32>("time-cost")
					.expect("time-cost has default"),
				memory_cost: *args
					.get_one::<u32>("memory-cost")
					.expect("memory-cost has default"),
				parallelism: *args
					.get_one::<u32>("parallelism")
					.expect("parallelism has default"),
			};
			kdf_commands::derive_balloon(
				&password, &config, hash_only,
			)
		}
		Some(("sha-crypt", args)) => {
			let password = resolve_kdf_password(args)?;
			let hash_only = args.get_flag("hash-only");
			kdf_commands::derive_sha_crypt(&password, hash_only)
		}
		_ => Ok(()),
	}
}

