// SPDX-License-Identifier: MIT OR Apache-2.0
// Project: rustgenhash
// File: app.rs
// Author: Volker Schwaberow <volker@schwaberow.de>
// Copyright (c) 2022 Volker Schwaberow

use crate::rgh::analyze::HashAnalyzer;
use crate::rgh::benchmark::{
	self, digest_benchmark_presets, kdf_benchmark_presets,
	render_digest_report, run_digest_benchmarks, BenchmarkMode,
};
pub use crate::rgh::cli::algorithms::Algorithm;
use crate::rgh::cli::benchmark::{
	kdf_benchmark_subcommand, mac_benchmark_subcommand,
	run_benchmark_family, run_benchmark_summary,
	summarize_benchmark_subcommand,
};
use crate::rgh::cli::defs::{
	digest_algorithm_help_text, HELP_TEMPLATE, MAC_ALGORITHMS,
	MAC_ALGORITHM_HELP, MAC_ALGORITHM_MATRIX_HELP,
};
use crate::rgh::cli::handlers::{
	hash_file, hash_string, HashConfigs,
};
use crate::rgh::cli::interactive::{
	render_compare_summary, run_interactive_mode,
};
use crate::rgh::cli::parser::{
	build_progress_config,
	parse_error_strategy,
	parse_mmap_threshold,
	parse_symlink_policy,
	parse_thread_strategy,
};
use crate::rgh::console::{
	self,
	history,
	ColorMode,
	ConsoleHistoryConfig,
	ConsoleOptions,
	HistoryRetention,
};
use crate::rgh::digest::commands as digest_commands;
use crate::rgh::file::{
	DirectoryHashPlan, ErrorHandlingProfile, WalkOrder,
};
use crate::rgh::hash::{
	compare_file_hashes, Argon2Config, BalloonConfig,
	BcryptConfig, Pbkdf2Config, ScryptConfig,
};
use crate::rgh::analyze::compare_hashes;
use crate::rgh::hhhash::generate_hhhash;
use crate::rgh::kdf::{
	commands as kdf_commands,
	hkdf::{
		self,
		HkdfAlgorithm,
		HkdfMode,
		HKDF_VARIANTS,
	},
	profile,
	SecretMaterial,
};
use crate::rgh::mac::commands::{run_mac, MacInput, MacOptions};
use crate::rgh::mac::key::KeySource;
use crate::rgh::mac::registry;
use crate::rgh::output::DigestOutputFormat;
use crate::rgh::random::{RandomNumberGenerator, RngType};
use clap::builder::{PossibleValuesParser, ValueParser};
use clap::parser::ValueSource;
use clap::{crate_name, Arg, ArgAction, ArgGroup};
use clap_complete::{generate, Generator, Shell};
use colored::*;
use dialoguer::Password;
use pbkdf2::password_hash::SaltString as Pbkdf2SaltString;
use scrypt::password_hash::SaltString as ScryptSaltString;
use std::error::Error;
use std::fs;
use std::io::{self, BufRead, Read};
use std::path::{Path, PathBuf};
use std::process;
use std::str::FromStr;

pub fn run() -> Result<(), Box<dyn Error>> {
	let capp = build_cli();
	let m = capp.get_matches();

	match m.subcommand() {
		Some(("digest", matches)) => {
			handle_digest_command(matches)?;
		}
		Some(("mac", matches)) => {
			handle_mac_command(matches)?;
		}
		Some(("kdf", matches)) => {
			handle_kdf_command(matches)?;
		}
		Some(("interactive", _)) => {
			run_interactive_mode()?;
		}
		Some(("console", args)) => {
			let ignore_errors = args.get_flag("ignore-errors");
			let color_mode = args
				.get_one::<String>("color")
				.and_then(|raw| ColorMode::from_str(raw).ok())
				.unwrap_or(ColorMode::Auto);
			let mut options = if let Some(path) =
				args.get_one::<String>("script").map(PathBuf::from)
			{
				ConsoleOptions::from_script(path, ignore_errors)
			} else {
				ConsoleOptions::interactive()
			};
			options.ignore_errors = ignore_errors;
			options.color_mode = color_mode;
			options.force_color_override = match color_mode {
				ColorMode::Always | ColorMode::Never => {
					Some(color_mode)
				}
				_ => None,
			};
			let history_file_arg = args
				.get_one::<String>("history-file")
				.map(PathBuf::from);
			let requested_retention = args
				.get_one::<String>("history-retention")
				.and_then(|raw| HistoryRetention::from_str(raw).ok());
			let force_script_history =
				args.get_flag("force-script-history");
			let history_enabled = history_file_arg.is_some()
				|| requested_retention.is_some();
			let default_retention = if matches!(
				options.tty_mode,
				console::ConsoleMode::Script
			) {
				HistoryRetention::Off
			} else {
				HistoryRetention::Sanitized
			};
			let retention = if history_enabled {
				requested_retention.unwrap_or(default_retention)
			} else {
				HistoryRetention::Off
			};
			let resolved_history_path = history_file_arg.or_else(|| {
				if history_enabled && retention.is_enabled() {
					history::default_history_path()
				} else {
					None
				}
			});
			let (history_path, effective_retention) = match (
				resolved_history_path,
				retention,
			) {
				(Some(path), mode) if mode.is_enabled() => {
					(Some(path), mode)
				}
				(None, mode) if mode.is_enabled() => {
					eprintln!(
							"warning: history retention requested but no config directory available; history disabled"
						);
					(None, HistoryRetention::Off)
				}
				(other_path, _) => {
					(other_path, HistoryRetention::Off)
				}
			};
			options.history = ConsoleHistoryConfig::new(
				history_path,
				effective_retention,
				force_script_history,
			);
			match console::run_console(options) {
				Ok(code) => {
					if code != 0 {
						process::exit(code);
					}
				}
				Err(err) => {
					eprintln!("error: {}", err);
					process::exit(err.exit_code());
				}
			}
		}
		Some(("string", s)) => {
			emit_legacy_warning(
				"string",
				"rgh digest string -a <algorithm> <INPUT>",
			);
			let st = s.get_one::<String>("INPUTSTRING");
			let st = match st {
				Some(s) => s,
				None => {
					println!("No string provided.");
					std::process::exit(1);
				}
			};
			let a = s.get_one::<Algorithm>("algorithm");
			let a = match a {
				Some(a) => *a,
				None => panic!("Algorithm not found."),
			};
			let format = s
				.get_one::<DigestOutputFormat>("format")
				.copied()
				.unwrap_or(DigestOutputFormat::Hex);
			let argon2_config = Argon2Config {
				mem_cost: *s
					.get_one::<u32>("argon2-mem-cost")
					.unwrap(),
				time_cost: *s
					.get_one::<u32>("argon2-time-cost")
					.unwrap(),
				parallelism: *s
					.get_one::<u32>("argon2-parallelism")
					.unwrap(),
			};
			let scrypt_config = ScryptConfig {
				log_n: *s.get_one::<u8>("scrypt-log-n").unwrap(),
				r: *s.get_one::<u32>("scrypt-r").unwrap(),
				p: *s.get_one::<u32>("scrypt-p").unwrap(),
			};
			let bcrypt_config = BcryptConfig {
				cost: *s.get_one::<u32>("bcrypt-cost").unwrap(),
			};
			let pbkdf2_config = Pbkdf2Config {
				rounds: *s.get_one::<u32>("pbkdf2-rounds").unwrap(),
				output_length: *s
					.get_one::<usize>("pbkdf2-output-length")
					.unwrap(),
			};
			let balloon_config = BalloonConfig {
				time_cost: *s
					.get_one::<u32>("balloon-time-cost")
					.unwrap(),
				memory_cost: *s
					.get_one::<u32>("balloon-memory-cost")
					.unwrap(),
				parallelism: *s
					.get_one::<u32>("balloon-parallelism")
					.unwrap(),
			};
			let hash_only = s.get_flag("hash-only");
			let configs = HashConfigs {
				argon2: &argon2_config,
				scrypt: &scrypt_config,
				bcrypt: &bcrypt_config,
				pbkdf2: &pbkdf2_config,
				balloon: &balloon_config,
			};

			hash_string(a, st, format, &configs, hash_only);
		}
		Some(("compare-file", s)) => {
			let baseline = s
				.get_one::<String>("manifest")
				.or_else(|| s.get_one::<String>("FILE1"))
				.map(|value| value.to_owned())
				.unwrap_or_else(|| {
					println!("Baseline file missing.");
					std::process::exit(1);
				});
			let candidate = s
				.get_one::<String>("against")
				.or_else(|| s.get_one::<String>("FILE2"))
				.map(|value| value.to_owned())
				.unwrap_or_else(|| {
					println!("Comparison file missing.");
					std::process::exit(1);
				});
			match compare_file_hashes(&baseline, &candidate) {
				Ok(summary) => {
					render_compare_summary(&summary);
					std::process::exit(summary.exit_code);
				}
				Err(err) => {
					eprintln!("Error comparing files: {}", err);
					std::process::exit(1);
				}
			}
		}
		Some(("compare-hash", s)) => {
			let st1 = s.get_one::<String>("HASH1");
			let st2 = s.get_one::<String>("HASH2");
			let st1 = st1.unwrap_or_else(|| {
				println!("No hash provided.");
				std::process::exit(1);
			});
			let st2 = st2.unwrap_or_else(|| {
				println!("No hash provided.");
				std::process::exit(1);
			});
			if compare_hashes(st1, st2) {
				println!("The hashes are equal.");
				std::process::exit(0);
			} else {
				println!("The hashes are not equal.");
				std::process::exit(1);
			}
		}
		Some(("file", s)) => {
			emit_legacy_warning(
				"file",
				"rgh digest file -a <algorithm> <PATH>",
			);
			let f = s.get_one::<String>("FILE");
			let f = match f {
				Some(f) => f,
				None => {
					println!("No file provided.");
					std::process::exit(1);
				}
			};
			let a = s.get_one::<Algorithm>("algorithm");
			let a = match a {
				Some(a) => *a,
				None => panic!("Algorithm not found."),
			};
			let format = s
				.get_one::<DigestOutputFormat>("format")
				.copied()
				.unwrap_or(DigestOutputFormat::Hex);
			let hash_only = s.get_flag("hash-only");
			hash_file(a, f, format, hash_only);
		}
		Some(("stdio", s)) => {
			emit_legacy_warning(
				"stdio",
				"rgh digest stdio -a <algorithm>",
			);
			let stdin = std::io::stdin();
			let hash_only = s.get_flag("hash-only");
			stdin.lock().lines().for_each(|l| {
				let a = s.get_one::<Algorithm>("algorithm");
				let a = match a {
					Some(a) => *a,
					None => {
						println!("Algorithm error. This should really not happen.");
						std::process::exit(1);
					}
				};
				let l = match l {
					Ok(l) => l,
					Err(e) => {
						eprintln!("Error: {}", e);
						std::process::exit(1);
					}
				};
				let format = s
					.get_one::<DigestOutputFormat>("format")
					.copied()
					.unwrap_or(DigestOutputFormat::Hex);
				let argon2_config = Argon2Config::default();
				let scrypt_config = ScryptConfig::default();
				let bcrypt_config = BcryptConfig::default();
				let pbkdf2_config = Pbkdf2Config::default();
				let balloon_config = BalloonConfig::default();
				let configs = HashConfigs {
					argon2: &argon2_config,
					scrypt: &scrypt_config,
					bcrypt: &bcrypt_config,
					pbkdf2: &pbkdf2_config,
					balloon: &balloon_config,
				};

				hash_string(a, &l, format, &configs, hash_only);
			});
		}
		Some(("generate-auto-completions", s)) => {
			if let Some(gen) = s.get_one::<Shell>("SHELL") {
				let mut capp = build_cli();
				print_completions(*gen, &mut capp);
			};
		}
		Some(("random", s)) => {
			let a = s.get_one::<RngType>("algorithm");
			let a = match a {
				Some(a) => *a,
				None => panic!("Algorithm not found."),
			};
			let format = s
				.get_one::<DigestOutputFormat>("format")
				.copied()
				.unwrap_or(DigestOutputFormat::Hex);
			let len = s.get_one::<u64>("length");
			let len = match len {
				Some(l) => l,
				None => {
					println!("No length provided.");
					std::process::exit(1);
				}
			};
			if !matches!(
				format,
				DigestOutputFormat::Hex | DigestOutputFormat::Base64
			) {
				eprintln!(
					"warning: random command supports only hex or base64 formats"
				);
				std::process::exit(1);
			}
			let out = RandomNumberGenerator::new(a)
				.generate(*len, format)?;
			println!("{}", out);
		}
		Some(("analyze", s)) => {
			let st = s.get_one::<String>("INPUTSTRING");
			let st = match st {
				Some(s) => s,
				None => {
					println!("No string provided.");
					std::process::exit(1);
				}
			};

			let h = HashAnalyzer::from_string(st);
			let out = h.detect_possible_hashes();
			if out.is_empty() {
				println!("No possible hash class found.");
				std::process::exit(1);
			}
			print!("Possible class of hash: ");
			for o in out {
				print!("{} ", o);
			}
			println!();
		}
		Some(("header", s)) => {
			let url = s.get_one::<String>("URL").unwrap();
			let url = url.clone();
			let hash = generate_hhhash(url)?;
			println!("{}", hash);
		}
		Some(("benchmark", matches)) => {
			if let Some(("summarize", args)) = matches.subcommand() {
				run_benchmark_summary(args)?;
			} else if let Some(("mac", args)) = matches.subcommand() {
				run_benchmark_family(BenchmarkMode::Mac, args)?;
			} else if let Some(("kdf", args)) = matches.subcommand() {
				run_benchmark_family(BenchmarkMode::Kdf, args)?;
			} else {
				let algorithms: Vec<Algorithm> = matches
					.get_many("algorithms")
					.map(|v| v.cloned().collect())
					.unwrap_or_else(|| {
						let mut presets = digest_benchmark_presets();
						presets.extend(kdf_benchmark_presets());
						presets
					});
				let iterations =
					*matches.get_one::<u32>("iterations").unwrap();
				let summary =
					run_digest_benchmarks(&algorithms, iterations)
						.map_err(|err| {
							Box::new(err) as Box<dyn Error>
						})?;
				render_digest_report(&summary);
			}
		}
		_ => {}
	}
	Ok(())
}

fn handle_digest_command(
	matches: &clap::ArgMatches,
) -> Result<(), Box<dyn Error>> {
	match matches.subcommand() {
		Some(("string", args)) => {
			let algorithm = args
				.get_one::<String>("algorithm")
				.expect("algorithm must be provided");
			let input = args
				.get_one::<String>("input")
				.expect("input must be provided");
			let format = args
				.get_one::<DigestOutputFormat>("format")
				.copied()
				.unwrap_or(DigestOutputFormat::Hex);
			let hash_only = args.get_flag("hash-only");
			digest_commands::digest_string(
				algorithm, input, format, hash_only,
			)
		}
		Some(("file", args)) => {
			let algorithm = args
				.get_one::<String>("algorithm")
				.expect("algorithm must be provided")
				.clone();
			let format = args
				.get_one::<DigestOutputFormat>("format")
				.copied()
				.unwrap_or(DigestOutputFormat::Hex);
			let hash_only = args.get_flag("hash-only");
			let recursive = args.get_flag("recursive");
			let symlink_policy = args
				.get_one::<String>("follow-symlinks")
				.map(String::as_str)
				.unwrap_or("never");
			let symlink_policy = parse_symlink_policy(symlink_policy);
			let thread_value = args
				.get_one::<String>("threads")
				.map(String::as_str)
				.unwrap_or("1");
			let threads = parse_thread_strategy(thread_value)
				.map_err(|msg| {
					io::Error::new(io::ErrorKind::InvalidInput, msg)
				})?;
			let mmap_value = args
				.get_one::<String>("mmap-threshold")
				.map(String::as_str)
				.unwrap_or("64MiB");
			let mmap_threshold = parse_mmap_threshold(mmap_value)
				.map_err(|msg| {
					io::Error::new(io::ErrorKind::InvalidInput, msg)
				})?;
			let progress = build_progress_config(args);
			let error_strategy = args
				.get_one::<String>("error-strategy")
				.map(String::as_str)
				.unwrap_or("fail-fast");
			let error_strategy = parse_error_strategy(error_strategy);
			let manifest_path =
				args.get_one::<String>("manifest").map(PathBuf::from);
			let path = args
				.get_one::<String>("path")
				.expect("path must be provided");
			let plan = DirectoryHashPlan {
				root_path: PathBuf::from(path),
				recursive,
				follow_symlinks: symlink_policy,
				order: WalkOrder::Lexicographic,
				threads,
				mmap_threshold,
			};
			let error_profile = ErrorHandlingProfile {
				strategy: error_strategy,
				..Default::default()
			};
			let options = crate::rgh::hash::FileDigestOptions {
				algorithm,
				plan,
				format,
				hash_only,
				progress,
				manifest_path,
				error_profile,
			};
			digest_commands::digest_path(options)
		}
		Some(("stdio", args)) => {
			let algorithm = args
				.get_one::<String>("algorithm")
				.expect("algorithm must be provided");
			let format = args
				.get_one::<DigestOutputFormat>("format")
				.copied()
				.unwrap_or(DigestOutputFormat::Hex);
			let hash_only = args.get_flag("hash-only");
			digest_commands::digest_stdio(
				algorithm, format, hash_only,
			)
		}
		_ => Ok(()),
	}
}

fn resolve_kdf_password(
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

fn handle_kdf_command(
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
						ScryptSaltString::b64_encode(&bytes)
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
						Pbkdf2SaltString::b64_encode(&bytes)
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

fn handle_mac_command(
	matches: &clap::ArgMatches,
) -> Result<(), Box<dyn Error>> {
	let algorithm = matches
		.get_one::<String>("algorithm")
		.expect("algorithm must be provided")
		.to_owned();

	let key_source =
		if let Some(path) = matches.get_one::<String>("key") {
			KeySource::File(PathBuf::from(path))
		} else if matches.get_flag("key-stdin") {
			KeySource::Stdin
		} else {
			return Err(Box::new(io::Error::new(
			io::ErrorKind::InvalidInput,
			"exactly one of --key or --key-stdin must be supplied",
		)));
		};

	let input = if let Some(text) = matches.get_one::<String>("input")
	{
		MacInput::Inline(text.clone())
	} else if let Some(path) = matches.get_one::<String>("file") {
		MacInput::File(PathBuf::from(path))
	} else if matches.get_flag("stdin") {
		MacInput::Stdin
	} else {
		return Err(Box::new(io::Error::new(
			io::ErrorKind::InvalidInput,
			"provide one of --input, --file, or --stdin",
		)));
	};

	let hash_only = matches.get_flag("hash-only");
	let json = matches
		.get_one::<String>("format")
		.map(|value| value.eq_ignore_ascii_case("json"))
		.unwrap_or(false);

	let options = MacOptions {
		algorithm,
		key_source,
		input,
		hash_only,
		json,
	};

	match run_mac(options) {
		Ok(_) => Ok(()),
		Err(err) => match err.downcast::<registry::MacError>() {
			Ok(mac_err) => match mac_err.kind() {
				registry::MacErrorKind::InvalidKey
				| registry::MacErrorKind::InvalidKeyLength
				| registry::MacErrorKind::UnsupportedAlgorithm => {
					eprintln!("error: {}", mac_err);
					process::exit(2);
				}
				registry::MacErrorKind::Crypto => {
					Err(mac_err as Box<dyn Error>)
				}
			},
			Err(err) => Err(err),
		},
	}
}

fn emit_legacy_warning(command: &str, replacement: &str) {
	eprintln!(
		"{}",
		format!(
			"warning: `rgh {}` is deprecated; use `{}` instead.",
			command,
			replacement
		)
		.yellow()
	);
}

pub(crate) fn build_cli() -> clap::Command {
	clap::Command::new(clap::crate_name!()) 
			.color(clap::ColorChoice::Never)
			.help_template(HELP_TEMPLATE)
			.bin_name(crate_name!())
			.version(clap::crate_version!())
			.author(clap::crate_authors!())
			.about("A simple hashing utility")
			.subcommand_required(true)
			.arg_required_else_help(true)
			.subcommand(
				clap::command!("digest")
					.about("Digest data using classic hash algorithms")
					.subcommand_required(true)
					.arg_required_else_help(true)
					.subcommand(
						clap::command!("string")
							.about("Hash a provided string")
							.arg(
							Arg::new("algorithm")
								.short('a')
								.long("algorithm")
								.help(digest_algorithm_help_text())
								.required(true),
							)
							.arg(
								Arg::new("input")
									.help("String to hash")
									.required(true),
							)
							.arg(
								Arg::new("format")
									.short('f')
									.long("format")
									.value_parser(
										clap::value_parser!(
											DigestOutputFormat
										)
									)
								.help("Output format (json, jsonl, csv, hex, base64, hashcat, multihash=base58btc)")
									.default_value("hex"),
							)
							.arg(
								Arg::new("hash-only")
									.long("hash-only")
									.help("Emit only digests without original input")
									.action(ArgAction::SetTrue),
							)
						,
					)
				.subcommand(
						clap::command!("file")
							.about("Hash the contents of a file or directory")
							.arg(
							Arg::new("algorithm")
								.short('a')
								.long("algorithm")
								.help(digest_algorithm_help_text())
								.required(true),
							)
							.arg(
								Arg::new("path")
									.help("File or directory path to hash")
									.required(true),
							)
							.arg(
								Arg::new("format")
									.short('f')
									.long("format")
									.value_parser(
										clap::value_parser!(
											DigestOutputFormat
										)
									)
								.help("Output format (json, jsonl, csv, hex, base64, hashcat, multihash=base58btc)")
									.default_value("hex"),
							)
							.arg(
								Arg::new("hash-only")
									.long("hash-only")
									.help("Emit only digests without file names")
									.action(ArgAction::SetTrue),
							)
							.arg(
								Arg::new("recursive")
									.long("recursive")
									.help("Traverse directories recursively")
									.action(ArgAction::SetTrue),
							)
							.arg(
								Arg::new("follow-symlinks")
									.long("follow-symlinks")
									.value_parser(["never", "files", "all"])
									.default_value("never")
									.help("Control how symlinks are handled (never, files, all)"),
							)
							.arg(
								Arg::new("threads")
									.long("threads")
									.default_value("1")
									.help("Worker strategy: 1 (single), auto, or explicit count"),
							)
							.arg(
								Arg::new("mmap-threshold")
									.long("mmap-threshold")
									.default_value("64MiB")
									.help("Enable mmap for files ≥ threshold (use 'off' to disable)"),
							)
							.arg(
								Arg::new("progress")
									.long("progress")
									.help("Force progress reporting on stderr")
									.action(ArgAction::SetTrue)
									.conflicts_with("no-progress"),
							)
							.arg(
								Arg::new("no-progress")
									.long("no-progress")
									.help("Disable progress reporting")
									.action(ArgAction::SetTrue),
							)
				.arg(
					Arg::new("manifest")
						.long("manifest")
						.help(
							"Write JSON manifest to this path (fail-fast suppresses the file)",
						),
				)
				.arg(
					Arg::new("error-strategy")
						.long("error-strategy")
						.value_parser(["fail-fast", "continue", "report-only"])
						.default_value("fail-fast")
					.help(
						"Control error handling: fail-fast (exit 1), continue (exit 2 on failures), report-only (exit 0)",
					),
				)
				.after_help(
					"Exit codes: 0 = success/report-only, 1 = fail-fast abort, 2 = recoverable errors",
				),
		)
					.subcommand(
						clap::command!("stdio")
							.about("Hash newline-delimited stdin input")
							.arg(
							Arg::new("algorithm")
								.short('a')
								.long("algorithm")
								.help(digest_algorithm_help_text())
								.required(true),
							)
							.arg(
								Arg::new("format")
									.short('f')
									.long("format")
									.value_parser(
										clap::value_parser!(
											DigestOutputFormat
										)
									)
								.help("Output format (json, jsonl, csv, hex, base64, hashcat, multihash=base58btc)")
									.default_value("hex"),
							)
							.arg(
								Arg::new("hash-only")
									.long("hash-only")
									.help("Emit only digests without echoing input lines")
									.action(ArgAction::SetTrue),
							),
			),
	)
	.subcommand(
		clap::command!("mac")
			.about("Generate message authentication codes")
			.after_help(MAC_ALGORITHM_MATRIX_HELP)
			.arg(
				Arg::new("algorithm")
				.short('a')
				.long("alg")
					.visible_alias("algorithm")
					.help(MAC_ALGORITHM_HELP)
					.value_parser(MAC_ALGORITHMS)
					.required(true),
			)
			.arg(
				Arg::new("key")
					.long("key")
					.value_name("PATH")
					.help("Read key bytes from file")
					.conflicts_with("key-stdin"),
			)
			.arg(
				Arg::new("key-stdin")
					.long("key-stdin")
					.help("Read key bytes from stdin")
					.action(ArgAction::SetTrue)
					.conflicts_with("key"),
			)
			.arg(
				Arg::new("input")
					.long("input")
					.value_name("TEXT")
					.help("Inline UTF-8 text to authenticate")
					.conflicts_with("file")
					.conflicts_with("stdin"),
			)
			.arg(
				Arg::new("file")
					.long("file")
					.value_name("PATH")
					.help("Hash the contents of a file")
					.conflicts_with("stdin"),
			)
			.arg(
				Arg::new("stdin")
					.long("stdin")
					.help("Read newline-delimited input from stdin")
					.action(ArgAction::SetTrue),
			)
			.arg(
				Arg::new("hash-only")
					.long("hash-only")
					.help("Emit only the MAC digest without input echo")
					.action(ArgAction::SetTrue),
			)
			.arg(
				Arg::new("format")
					.long("format")
					.help("MAC output format")
					.value_parser(["text", "json"])
					.default_value("text"),
			)
			.group(ArgGroup::new("mac-key").args(["key", "key-stdin"]).required(true))
			.group(ArgGroup::new("mac-input").args(["input", "file", "stdin"]).required(true)),
	)
	.subcommand(
		clap::command!("kdf")
					.about("Derive keys using password-based algorithms")
					.subcommand_required(true)
					.arg_required_else_help(true)
					.subcommand(
						clap::command!("argon2")
							.about("Derive a key using Argon2id")
					.arg(
							Arg::new("password")
								.long("password")
								.help("Password to derive (omit to prompt)")
								.required(false)
								.conflicts_with("password-stdin"),
						)
					.arg(
							Arg::new("password-stdin")
								.long("password-stdin")
								.help("Read password from stdin (newline trimmed)")
								.action(ArgAction::SetTrue)
								.conflicts_with("password"),
						)
							.arg(
								Arg::new("hash-only")
									.long("hash-only")
									.help("Emit only derived key output")
									.action(ArgAction::SetTrue),
							)
							.arg(
								Arg::new("mem-cost")
									.long("mem-cost")
									.value_parser(clap::value_parser!(u32))
									.help("Argon2 memory cost in KiB")
									.default_value("65536"),
							)
							.arg(
								Arg::new("time-cost")
									.long("time-cost")
									.value_parser(clap::value_parser!(u32))
									.help("Argon2 time cost (iterations)")
									.default_value("3"),
							)
							.arg(
								Arg::new("parallelism")
									.long("parallelism")
									.value_parser(clap::value_parser!(u32))
									.help("Argon2 parallelism")
									.default_value("4"),
							)
					)
		.subcommand(
						clap::command!("scrypt")
							.about("Derive a key using Scrypt")
				.arg(
							Arg::new("password")
								.long("password")
								.help("Password to derive (omit to prompt)")
								.required(false)
								.conflicts_with("password-stdin"),
						)
				.arg(
							Arg::new("password-stdin")
								.long("password-stdin")
								.help("Read password from stdin (newline trimmed)")
								.action(ArgAction::SetTrue)
								.conflicts_with("password"),
						)
							.arg(
								Arg::new("hash-only")
									.long("hash-only")
									.help("Emit only derived key output")
									.action(ArgAction::SetTrue),
							)
				.arg(
							Arg::new("profile")
								.long("profile")
								.value_name("ID")
								.value_parser(PossibleValuesParser::new(
									profile::scrypt_profile_ids()
								))
								.help("Compliance profile preset (e.g., owasp-2024)"),
				)
				.arg(
							Arg::new("salt")
								.long("salt")
								.value_name("HEX")
								.help("Hex-encoded salt to override generated value"),
				)
							.arg(
								Arg::new("log-n")
									.long("log-n")
									.value_parser(clap::value_parser!(u8))
									.help("Scrypt log2(N)")
									.default_value("15"),
							)
									.arg(
										Arg::new("r")
											.long("r")
											.value_parser(clap::value_parser!(u32))
											.help("Scrypt r parameter")
											.default_value("8"),
									)
									.arg(
										Arg::new("p")
											.long("p")
											.value_parser(clap::value_parser!(u32))
											.help("Scrypt p parameter")
											.default_value("1"),
									)
					)
		.subcommand(
						clap::command!("pbkdf2")
							.about("Derive a key using PBKDF2")
				.arg(
							Arg::new("password")
								.long("password")
								.help("Password to derive (omit to prompt)")
								.required(false)
								.conflicts_with("password-stdin"),
						)
				.arg(
							Arg::new("password-stdin")
								.long("password-stdin")
								.help("Read password from stdin (newline trimmed)")
								.action(ArgAction::SetTrue)
								.conflicts_with("password"),
						)
							.arg(
								Arg::new("hash-only")
									.long("hash-only")
									.help("Emit only derived key output")
									.action(ArgAction::SetTrue),
							)
				.arg(
							Arg::new("profile")
								.long("profile")
								.value_name("ID")
								.value_parser(PossibleValuesParser::new(
									profile::pbkdf2_profile_ids()
								))
								.help("Compliance profile preset (e.g., nist-sp800-132-2023)"),
				)
				.arg(
							Arg::new("salt")
								.long("salt")
								.value_name("HEX")
								.help("Hex-encoded salt to override generated value"),
				)
							.arg(
								Arg::new("rounds")
									.long("rounds")
									.value_parser(clap::value_parser!(u32))
									.help("PBKDF2 rounds")
									.default_value("100000"),
							)
									.arg(
										Arg::new("length")
											.long("length")
											.value_parser(clap::value_parser!(usize))
											.help("PBKDF2 output length (bytes)")
											.default_value("32"),
									)
									.arg(
										Arg::new("algorithm")
											.long("algorithm")
											.help("Digest variant for PBKDF2 (sha256|sha512)")
											.default_value("sha256"),
									)
					)
					.subcommand(
							clap::command!("bcrypt")
								.about("Derive a key using bcrypt-pbkdf")
					.arg(
								Arg::new("password")
									.long("password")
									.help("Password to derive (omit to prompt)")
									.required(false)
									.conflicts_with("password-stdin"),
						)
					.arg(
								Arg::new("password-stdin")
									.long("password-stdin")
									.help("Read password from stdin (newline trimmed)")
									.action(ArgAction::SetTrue)
									.conflicts_with("password"),
						)
							.arg(
								Arg::new("hash-only")
									.long("hash-only")
									.help("Emit only derived key output")
									.action(ArgAction::SetTrue),
							)
							.arg(
								Arg::new("cost")
									.long("cost")
									.value_parser(clap::value_parser!(u32))
									.help("Bcrypt cost factor")
									.default_value("12"),
						)
		)
		.subcommand(
						clap::command!("hkdf")
							.about("Derive key material using HKDF (RFC 5869)")
  .arg(
							Arg::new("ikm")
								.long("ikm")
								.value_name("HEX")
								.help("Hex-encoded input keying material (omit when using --ikm-stdin)")
								.conflicts_with("ikm-stdin"),
						)
					.arg(
							Arg::new("ikm-stdin")
								.long("ikm-stdin")
								.help("Read input keying material from stdin")
								.action(ArgAction::SetTrue),
						)
					.arg(
							Arg::new("expand-only")
								.long("expand-only")
								.help("Skip extract phase and expand using supplied PRK")
								.action(ArgAction::SetTrue),
						)
					.arg(
							Arg::new("prk")
								.long("prk")
								.value_name("PATH")
								.help("Read PRK bytes from file for expand-only mode")
								.requires("expand-only")
								.conflicts_with("prk-stdin"),
						)
					.arg(
							Arg::new("prk-stdin")
								.long("prk-stdin")
								.help("Read PRK bytes from stdin for expand-only mode")
								.action(ArgAction::SetTrue)
								.requires("expand-only"),
						)
					.arg(
							Arg::new("salt")
								.long("salt")
								.value_name("HEX")
								.help("Optional hex-encoded salt (defaults to empty; ignored for expand-only)"),
					)
					.arg(
							Arg::new("info")
								.long("info")
								.value_name("HEX")
								.help("Optional hex-encoded context info"),
					)
					.arg(
							Arg::new("len")
								.long("len")
								.value_parser(clap::value_parser!(usize))
								.help("Desired derived length in bytes")
								.required(true),
					)
					.arg(
							Arg::new("hash")
								.long("hash")
								.value_parser(["sha256", "sha512", "sha3-256", "sha3-512", "blake3"])
								.help("Digest variant for HKDF")
								.default_value("sha256"),
					)
					.arg(
							Arg::new("hash-only")
								.long("hash-only")
								.help("Emit only the derived key hex output")
								.action(ArgAction::SetTrue),
					)
				.after_help(
					"Provide either --ikm <HEX> or --ikm-stdin for extract+expand flows. For expand-only use --expand-only with --prk <PATH> or --prk-stdin.",
				)
		)
		.subcommand(
						clap::command!("balloon")
							.about("Derive a key using Balloon hashing")
								.arg(
									Arg::new("password")
										.long("password")
										.help("Password to derive (omit to prompt)")
										.required(false)
										.conflicts_with("password-stdin"),
						)
							.arg(
								Arg::new("password-stdin")
									.long("password-stdin")
									.help("Read password from stdin (newline trimmed)")
									.action(ArgAction::SetTrue)
									.conflicts_with("password"),
						)
							.arg(
								Arg::new("hash-only")
									.long("hash-only")
									.help("Emit only derived key output")
									.action(ArgAction::SetTrue),
							)
							.arg(
								Arg::new("time-cost")
									.long("time-cost")
									.value_parser(clap::value_parser!(u32))
									.help("Balloon time cost")
									.default_value("3"),
							)
							.arg(
								Arg::new("memory-cost")
									.long("memory-cost")
									.value_parser(clap::value_parser!(u32))
									.help("Balloon memory cost in KiB")
									.default_value("65536"),
							)
							.arg(
								Arg::new("parallelism")
									.long("parallelism")
									.value_parser(clap::value_parser!(u32))
									.help("Balloon parallelism")
																		.default_value("4"),
																)
											)
											.subcommand(
												clap::command!("sha-crypt")
									.about("Derive a key using SHA-crypt (SHA512)")
					.arg(
									Arg::new("password")
										.long("password")
										.help("Password to derive (omit to prompt)")
										.required(false)
										.conflicts_with("password-stdin"),
						)
					.arg(
								Arg::new("password-stdin")
									.long("password-stdin")
									.help("Read password from stdin (newline trimmed)")
									.action(ArgAction::SetTrue)
									.conflicts_with("password"),
						)
							.arg(
								Arg::new("hash-only")
									.long("hash-only")
									.help("Emit only derived key output")
									.action(ArgAction::SetTrue),
							)
					)
		)
			.subcommand(
						clap::command!("string")
							.about("Hash single string object")
						.arg(
								Arg::new("INPUTSTRING")
									.help("String to hash")
									.required(true),
						)
						.arg_required_else_help(true)
						.display_order(3)
						.arg(
								Arg::new("interactive")
						)
						.arg(
								Arg::new("algorithm")
									.short('a')
									.long("algorithm")
									.value_parser(clap::value_parser!(Algorithm))
									.required(true)
									.display_order(1),
						)
						.arg(
								Arg::new("argon2-mem-cost")
									.long("argon2-mem-cost")
									.value_parser(clap::value_parser!(u32))
									.help("Argon2 memory cost (KiB)")
									.default_value("65536")
						)
						.arg(
								Arg::new("argon2-time-cost")
									.long("argon2-time-cost")
									.value_parser(clap::value_parser!(u32))
									.help("Argon2 time cost (iterations)")
									.default_value("3")
						)
						.arg(
								Arg::new("argon2-parallelism")
									.long("argon2-parallelism")
									.value_parser(clap::value_parser!(u32))
									.help("Argon2 parallelism")
									.default_value("4")
						)
						.arg(
								Arg::new("scrypt-log-n")
									.long("scrypt-log-n")
									.value_parser(clap::value_parser!(u8))
									.help("Scrypt log_n (2^n)")
									.default_value("15")
						)
						.arg(
								Arg::new("scrypt-r")
									.long("scrypt-r")
									.value_parser(clap::value_parser!(u32))
									.help("Scrypt r")
									.default_value("8")
						)
						.arg(
								Arg::new("scrypt-p")
									.long("scrypt-p")
									.value_parser(clap::value_parser!(u32))
									.help("Scrypt p")
									.default_value("1")
						)
						.arg(
								Arg::new("bcrypt-cost")
									.long("bcrypt-cost")
									.value_parser(clap::value_parser!(u32))
									.help("Bcrypt cost")
									.default_value("12")
						)
						.arg(
								Arg::new("pbkdf2-rounds")
									.long("pbkdf2-rounds")
									.value_parser(clap::value_parser!(u32))
									.help("PBKDF2 rounds")
									.default_value("100000")
						)
						.arg(
								Arg::new("pbkdf2-output-length")
									.long("pbkdf2-output-length")
									.value_parser(clap::value_parser!(usize))
									.help("PBKDF2 output length (bytes)")
									.default_value("32")
						)
						.arg(
								Arg::new("balloon-time-cost")
									.long("balloon-time-cost")
									.value_parser(clap::value_parser!(u32))
									.help("Balloon time cost (iterations)")
									.default_value("3")
						)
						.arg(
								Arg::new("balloon-memory-cost")
									.long("balloon-memory-cost")
									.value_parser(clap::value_parser!(u32))
									.help("Balloon memory cost (KiB)")
									.default_value("65536")
						)
						.arg(
								Arg::new("balloon-parallelism")
									.long("balloon-parallelism")
									.value_parser(clap::value_parser!(u32))
									.help("Balloon parallelism")
									.default_value("4")
						)
						.arg(
								Arg::new("format")
									.short('f')
									.long("format")
									.value_parser(clap::value_parser!(
										DigestOutputFormat
									))
									.help("Output format")
									.default_value("hex")
									.display_order(1),
						)
						.arg(
								Arg::new("hash-only")
									.short('H')
									.long("hash-only")
									.help("Print only the hash value without the source input")
									.action(ArgAction::SetTrue)
									.display_order(1),
						)
			)
		.subcommand(
						clap::command!("file")
							.about("Hash single file or single directory")
						.arg(Arg::new("FILE").display_order(1).required(true))
						.arg(
							Arg::new("algorithm")
								.display_order(2)
								.value_parser(clap::value_parser!(Algorithm))
								.help(digest_algorithm_help_text())
								.short('a')
								.long("algorithm")
								.required(true),
						)
						.arg(
								Arg::new("format")
									.short('f')
									.long("format")
									.value_parser(clap::value_parser!(DigestOutputFormat))
									.help("Output format")
									.default_value("hex")
									.display_order(1),
						)
						.arg(
								Arg::new("hash-only")
									.short('H')
									.long("hash-only")
									.help("Print only the hash for each file entry")
									.action(ArgAction::SetTrue)
									.display_order(1),
						),
		)
		.subcommand(
						clap::command!("stdio")
							.about("Hash input from stdin")
						.display_order(2)
						.arg(
							Arg::new("algorithm")
								.required(true)
								.short('a')
								.long("algorithm")
								.value_parser(clap::value_parser!(Algorithm))
								.help(digest_algorithm_help_text()),
						)
						.arg(
								Arg::new("format")
									.short('f')
									.long("format")
									.value_parser(clap::value_parser!(DigestOutputFormat))
									.help("Output format")
									.default_value("hex")
									.display_order(1),
						)
						.arg(
								Arg::new("hash-only")
									.short('H')
									.long("hash-only")
									.help("Print only the hash for each input line")
									.action(ArgAction::SetTrue)
									.display_order(1),
						),
		)
			.subcommand(
						clap::command!("random")
							.about("Generate random string")
						.display_order(3)
						.arg(
								Arg::new("algorithm")
									.required(true)
									.short('a')
									.long("algorithm")
									.value_parser(clap::value_parser!(RngType)),
						)
						.arg(
								Arg::new("length")
									.short('l')
									.long("length")
									.default_value("32")
									.value_parser(clap::value_parser!(u64)),
						)
						.arg(
								Arg::new("format")
									.short('f')
									.long("format")
									.value_parser(clap::value_parser!(
										DigestOutputFormat
									))
									.help("Output format")
									.default_value("hex")
									.display_order(1),
						),
		)
			.subcommand(
						clap::command!("analyze")
							.about("Analyze a hash")
						.display_order(1)
						.arg(
								Arg::new("INPUTSTRING")
									                                    .help("String to analyze")
									                                    .required(true),
									                        )
									                        .arg_required_else_help(true),
									            )
									            .subcommand(
									                clap::command!("compare-hash")
									                    .about("Compare two strings")
									                    .arg(
									                        Arg::new("HASH1")
									                            .help("First hash to compare")
									                            .required(true),
									                    )
									                    .arg(
									                        Arg::new("HASH2")
									                            .help("Second hash to compare")
									                            .required(true),
									                    ),
									            )
									        .subcommand(
									                        clap::command!("compare-file")							.about("Compare manifest JSON or digest outputs for equality")
						.alias("compare-file-hashes")
						.arg(
								Arg::new("manifest")
									.long("manifest")
									.value_name("BASELINE")
									.help(
										"Baseline manifest or digest list (defaults to first positional argument)",
									)
									.requires("against"),
						)
						.arg(
								Arg::new("against")
									.long("against")
									.value_name("CANDIDATE")
									.help(
										"Manifest or digest list to compare against the baseline",
									)
									.requires("manifest"),
						)
						.arg(
								Arg::new("FILE1")
									.help("Baseline manifest or digest list")
									.conflicts_with("manifest")
									.required_unless_present("manifest"),
						)
						.arg(
								Arg::new("FILE2")
									.help("Comparison manifest or digest list")
									.conflicts_with("against")
									.required_unless_present("manifest"),
						)
						.after_help(
							"Exit codes: 0 = identical, 1 = differences detected or incompatibility, 2 = comparison incomplete (manifest recorded failures)",
					)
						.arg_required_else_help(true),
		)
			.subcommand(
						clap::command!("generate-auto-completions")
							.about("Generate shell completions")
						.arg(
								Arg::new("SHELL")
									.required(true)
									.value_parser(clap::value_parser!(Shell))
									.help("Shell to generate completions for"),
						)
			)
			.subcommand(clap::command!("interactive")
				.about("Enter interactive mode")
			)
			.subcommand(
						clap::command!("console")
							.about("Network appliance-style console shell for chaining rustgenhash commands")
						.arg(
								Arg::new("script")
									.long("script")
									.value_name("FILE")
									.help("Run console commands from a script file (non-interactive mode)"),
						)
						.arg(
								Arg::new("ignore-errors")
									.long("ignore-errors")
									.action(ArgAction::SetTrue)
									.help("Continue executing script commands after failures"),
						)
						.arg(
								Arg::new("color")
									.long("color")
									.value_name("WHEN")
									.value_parser(PossibleValuesParser::new([
										"auto",
										"always",
										"never",
									]))
									.default_value("auto")
									.help(
										"Color console-owned output: auto (default), always, or never",
									),
					)
						.arg(
								Arg::new("history-file")
									.long("history-file")
									.value_name("FILE")
									.help(
										"Persist console history to FILE (defaults to platform config path; keeps 200 in-memory entries per session and persists up to 500 commands)",
									),
					)
						.arg(
								Arg::new("history-retention")
									.long("history-retention")
									.value_name("MODE")
									.value_parser(PossibleValuesParser::new([
										"off",
										"sanitized",
										"verbatim",
									]))
									.help(
										"History retention policy (sanitized is default for interactive sessions, off for scripts); retention obeys the 200/500 entry limits noted above",
									),
					)
						.arg(
								Arg::new("force-script-history")
									.long("force-script-history")
									.action(ArgAction::SetTrue)
																	.help(
																		"Allow scripts to write history even though it is disabled by default (requires explicit retention)",
																	),
																)
															.after_help("Examples:\n  rgh console\n  rgh console --script playbook.rgh\n  rgh console --script playbook.rgh --ignore-errors")
												)
												.subcommand(						clap::command!("header")
							.about("Generate a HHHash of HTTP header")
						.arg(
								Arg::new("URL")
									.help("URL to fetch")
																		.required(true),
															)
												)
												.subcommand(
													clap::command!("benchmark")							.about("Run benchmarks for digest, MAC, and KDF algorithms")
						.arg(
								Arg::new("algorithms")
									.short('a')
									.long("algorithms")
									.value_parser(clap::value_parser!(Algorithm))
									.help("Specify digest algorithms to benchmark (default: all)")
						)
						.arg(
								Arg::new("iterations")
									.short('i')
									.long("iterations")
									.value_parser(clap::value_parser!(u32))
									.default_value("100")
									.help("Number of iterations for each benchmark")
						)
						.subcommand(mac_benchmark_subcommand())
						.subcommand(kdf_benchmark_subcommand())
						.subcommand(summarize_benchmark_subcommand())
	)
}

/// Render the help text for a given command path (e.g., `["digest", "string"]`).
/// Returns `None` if the path does not exist in the CLI tree.
pub(crate) fn render_help_for_path(
	path: &[String],
) -> Option<String> {
	let mut current = build_cli();
	if path.is_empty() {
		return Some(render_help_text(current));
	}
	for segment in path {
		let next = current
			.get_subcommands()
			.find(|sub| sub.get_name().eq_ignore_ascii_case(segment))
			.cloned()?;
		current = next;
	}
	Some(render_help_text(current))
}

fn render_help_text(mut command: clap::Command) -> String {
	let mut buffer = Vec::new();
	if command.write_long_help(&mut buffer).is_err() {
		let _ = command.write_help(&mut buffer);
	}
	String::from_utf8_lossy(&buffer).into_owned()
}

fn print_completions<G: Generator>(gen: G, cmd: &mut clap::Command) {
	generate(
		gen,
		cmd,
		cmd.get_name().to_string(),
		&mut std::io::stdout(),
	);
}

