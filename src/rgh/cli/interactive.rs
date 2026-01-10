// SPDX-License-Identifier: MIT OR Apache-2.0
// Project: rustgenhash

use crate::rgh::analyze::{compare_hashes, HashAnalyzer};
use crate::rgh::benchmark::{
	render_digest_report, run_digest_benchmarks,
};
use crate::rgh::cli::algorithms::Algorithm;
use crate::rgh::cli::defs::{
	WEAK_PROMPT_OPTIONS, WEAK_PROMPT_DEFAULT_INDEX,
};
use crate::rgh::cli::parser::{
	is_poly1305, mac_expected_key_length,
};
use crate::rgh::digest::commands as digest_commands;
use crate::rgh::file::{
	DirectoryHashPlan, ErrorHandlingProfile, ProgressConfig,
	ProgressMode, SymlinkPolicy, ThreadStrategy, WalkOrder,
};
use crate::rgh::hash::{
	compare_file_hashes, Argon2Config, BalloonConfig, BcryptConfig,
	CompareDiffKind, CompareMode, CompareSummary, FileDigestOptions,
	Pbkdf2Config, ScryptConfig,
};
use crate::rgh::hhhash::generate_hhhash;
use crate::rgh::kdf::{
	commands as kdf_commands,
	hkdf::{self, HkdfMode, HKDF_VARIANTS},
	profile, SecretMaterial,
};
use crate::rgh::mac::commands::{run_mac, MacInput, MacOptions};
use crate::rgh::mac::key::KeySource;
use crate::rgh::mac::registry;
use crate::rgh::multihash::MulticodecSupportMatrix;
use crate::rgh::output::DigestOutputFormat;
use crate::rgh::random::{RandomNumberGenerator, RngType};
use crate::rgh::weak::{emit_warning_banner, warning_for};
use colored::*;
use dialoguer::{Confirm, Input, MultiSelect, Password, Select};
use std::error::Error;
use std::fs;
use std::io;
use std::path::PathBuf;
use std::time::Duration;
use strum::IntoEnumIterator;
use zeroize::Zeroizing;

// ... [Existing functions interactive_digest_menu, interactive_digest_string, interactive_digest_file, interactive_mac_menu, interactive_hkdf, interactive_kdf_menu, interactive_analyze_hash, interactive_compare_hashes, interactive_compare_file_hashes, interactive_generate_random, interactive_generate_hhhash, interactive_run_benchmarks] ...
// I will rewrite the whole file content to be safe and ensure nothing is missing or truncated.

pub fn run_interactive_mode() -> Result<(), Box<dyn Error>> {
	println!("{}", "Welcome to the Interactive Mode!".green().bold());

	let actions = vec![
		"Digest data",
		"Generate MAC",
		"Derive password-based key",
		"Analyze a hash",
		"Compare hashes",
		"Compare file hashes",
		"Generate random string",
		"Generate HHHash of HTTP header",
		"Run benchmarks",
		"Exit",
	];

	loop {
		let selection = Select::new()
			.with_prompt("Choose an action")
			.items(&actions)
			.interact()?;

		match selection {
			0 => interactive_digest_menu()?,
			1 => interactive_mac_menu()?,
			2 => interactive_kdf_menu()?,
			3 => interactive_analyze_hash()?,
			4 => interactive_compare_hashes()?,
			5 => interactive_compare_file_hashes()?,
			6 => interactive_generate_random()?,
			7 => interactive_generate_hhhash()?,
			8 => interactive_run_benchmarks()?,
			9 => {
				println!("{}", "Goodbye!".cyan());
				break;
			}
			_ => unreachable!(),
		}
	}

	Ok(())
}

pub fn interactive_digest_menu() -> Result<(), Box<dyn Error>> {
	let actions =
		vec!["Digest a string", "Digest a file or directory", "Back"];
	loop {
		let selection = Select::new()
			.with_prompt("Digest options")
			.items(&actions)
			.interact()?;
		match selection {
			0 => interactive_digest_string()?,
			1 => interactive_digest_file()?,
			2 => break,
			_ => unreachable!(),
		}
	}
	Ok(())
}

fn interactive_digest_string() -> Result<(), Box<dyn Error>> {
	let input = Input::<String>::new()
		.with_prompt("Enter the string to digest")
		.interact_text()?;

	let algorithm_label = select_digest_algorithm_with_guard()?;
	let output_option =
		choose_output_format_for_algorithm(&algorithm_label)?;
	let hash_only = Confirm::new()
		.with_prompt("Emit only the digest output?")
		.default(false)
		.interact()?;

	digest_commands::digest_string(
		&algorithm_label,
		&input,
		output_option,
		hash_only,
	)
}

fn interactive_digest_file() -> Result<(), Box<dyn Error>> {
	let path = Input::<String>::new()
		.with_prompt("Enter the file or directory path")
		.interact_text()?;
	let algorithm_label = select_digest_algorithm_with_guard()?;
	let output_option =
		choose_output_format_for_algorithm(&algorithm_label)?;
	let hash_only = Confirm::new()
		.with_prompt("Emit only the digest output?")
		.default(false)
		.interact()?;

	let plan = DirectoryHashPlan {
		root_path: PathBuf::from(&path),
		recursive: false,
		follow_symlinks: SymlinkPolicy::Never,
		order: WalkOrder::Lexicographic,
		threads: ThreadStrategy::Single,
		mmap_threshold: Some(64 * 1024 * 1024),
	};
	let progress = ProgressConfig {
		mode: ProgressMode::Auto,
		throttle: Duration::from_millis(500),
	};
	let error_profile = ErrorHandlingProfile::default();
	let options = FileDigestOptions {
		algorithm: algorithm_label,
		plan,
		format: output_option,
		hash_only,
		progress,
		manifest_path: None,
		error_profile,
	};

	digest_commands::digest_path(options)
}

pub fn interactive_mac_menu() -> Result<(), Box<dyn Error>> {
    // ... [Content of interactive_mac_menu from previous read] ...
    // Since I cannot simply "include" previous content in a write_file call, I have to paste it all.
    // This is tedious but necessary to ensure correctness.
    // I will use the content I read earlier.
    
	let metadata = registry::metadata();
	if metadata.is_empty() {
		println!(
			"{}",
			"No MAC algorithms are currently registered.".yellow()
		);
		return Ok(());
	}

	let mut last_selection = 0usize;

	loop {
		let algorithm_labels: Vec<String> = metadata
			.iter()
			.map(|meta| {
				let legacy_tag =
					if meta.is_legacy() { " ⚠ Legacy" } else { "" };
				format!(
					"{} ({}){}",
					meta.display_name, meta.identifier, legacy_tag
				)
			})
			.collect();

		let selection = Select::new()
			.with_prompt("Select MAC algorithm")
			.items(&algorithm_labels)
			.default(last_selection.min(algorithm_labels.len() - 1))
			.interact()?;
		let metadata_choice = metadata[selection];
		last_selection = selection;
		let algorithm_id = metadata_choice.identifier;
		let expected_key_len = mac_expected_key_length(algorithm_id);
		if algorithm_id.starts_with("cmac-") {
			if let Some(len) = expected_key_len {
				println!(
					"{}",
					format!(
						"{} expects an AES key of exactly {} bytes (NIST SP 800-38B).",
						metadata_choice.display_name,
						len
					)
					.yellow()
				);
			}
		}
		if is_poly1305(algorithm_id) {
			println!(
				"{}",
				"Poly1305 requires a single-use 32-byte key (RFC 8439 §2.5). Reusing the key will emit a warning.".yellow()
			);
			let proceed = Confirm::new()
				.with_prompt(
					"Confirm you will rotate this Poly1305 key after use?",
				)
				.default(true)
				.interact()?;
			if !proceed {
				println!(
					"{}",
					"Poly1305 selection cancelled; choose another algorithm or key source.".cyan()
				);
				continue;
			}
		}

		if metadata_choice.is_legacy() {
			println!(
				"{}",
				format!(
					"⚠ {} is considered legacy per NIST SP 800-131A Rev.2 §3; prefer SHA-2, SHA-3, KMAC, or BLAKE3 keyed alternatives.",
					metadata_choice.display_name
				)
				.yellow()
			);
			let decision = Select::new()
				.with_prompt("How would you like to proceed?")
				.items(&WEAK_PROMPT_OPTIONS)
				.default(WEAK_PROMPT_DEFAULT_INDEX)
				.interact()?;
			if decision == WEAK_PROMPT_DEFAULT_INDEX {
				println!("{}", "Selecting a safer algorithm.".cyan());
				continue;
			}
		}

		let key_methods =
			vec!["Read key from file", "Paste key (hidden)"];
		let key_choice = Select::new()
			.with_prompt("How should the key be provided?")
			.items(&key_methods)
			.default(0)
			.interact()?;
		let key_source = match key_choice {
			0 => {
				let path: String = Input::new()
					.with_prompt("Path to key file")
					.interact_text()?;
				let path_buf = PathBuf::from(path);
				if let Some(expected) = expected_key_len {
					match fs::metadata(&path_buf) {
						Ok(metadata) => {
							if metadata.len() != expected as u64 {
								println!(
									"{}",
									format!(
										"Key file must be {} bytes for {}; observed {} bytes.",
										expected,
										metadata_choice.display_name,
										metadata.len()
									)
									.red()
								);
								continue;
							}
						}
						Err(err) => {
							println!(
								"{}",
								format!(
									"Failed to inspect key file `{}`: {}",
									path_buf.display(),
									err
								)
								.red()
							);
							continue;
						}
					}
				}
				KeySource::File(path_buf)
			}
			1 => {
				println!(
					"{}",
					"Typed keys will not be echoed and are not stored.".yellow()
				);
				let proceed = Confirm::new()
					.with_prompt("Continue with inline key entry?")
					.default(false)
					.interact()?;
				if !proceed {
					println!(
						"{}",
						"Inline key entry cancelled; choose another key source.".cyan()
					);
					continue;
				}
				let secret = Password::new()
					.with_prompt(
						"Enter key bytes (press Enter to finish)",
					)
					.allow_empty_password(false)
					.interact()?;
				let secret_bytes = secret.into_bytes();
				if let Some(expected) = expected_key_len {
					if secret_bytes.len() != expected {
						println!(
							"{}",
							format!(
								"Inline key must be {} bytes for {}; observed {} bytes.",
								expected,
								metadata_choice.display_name,
								secret_bytes.len()
							)
							.red()
						);
						continue;
					}
				}
				KeySource::Inline(Zeroizing::new(secret_bytes))
			}
			_ => unreachable!(),
		};

		let input_options = vec!["Inline text", "File path"];
		let input_choice = Select::new()
			.with_prompt("Select MAC input source")
			.items(&input_options)
			.default(0)
			.interact()?;
		let mac_input = match input_choice {
			0 => {
				let text: String = Input::new()
					.with_prompt("Enter text to authenticate")
					.interact_text()?;
				if text.is_empty() {
					println!(
						"{}",
						"Input text cannot be empty.".red()
					);
					continue;
				}
				MacInput::Inline(text)
			}
			1 => {
				let path: String = Input::new()
					.with_prompt("Path to file to authenticate")
					.interact_text()?;
				MacInput::File(PathBuf::from(path))
			}
			_ => unreachable!(),
		};

		let output_modes =
			vec!["Digest and context", "JSON output", "Hash only"];
		let output_choice = Select::new()
			.with_prompt("Choose output mode")
			.items(&output_modes)
			.default(0)
			.interact()?;
		let (hash_only, json) = match output_choice {
			0 => (false, false),
			1 => (false, true),
			2 => (true, false),
			_ => unreachable!(),
		};

		let confirm = Confirm::new()
			.with_prompt("Compute MAC now and display the result?")
			.default(false)
			.interact()?;
		if !confirm {
			println!(
				"{}",
				"MAC computation cancelled before output.".cyan()
			);
			return Ok(());
		}

		let options = MacOptions {
			algorithm: metadata_choice.identifier.to_string(),
			key_source,
			input: mac_input,
			hash_only,
			json,
		};

		match run_mac(options) {
			Ok(_) => {
				println!("{}", "MAC computation complete.".green())
			}
			Err(err) => {
				eprintln!("error: {}", err);
			}
		}

		return Ok(());
	}
}

pub fn interactive_kdf_menu() -> Result<(), Box<dyn Error>> {
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

fn interactive_hkdf() -> Result<(), Box<dyn Error>> {
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

fn get_argon2_config_interactive(
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

fn get_scrypt_config_interactive() -> Result<
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

fn get_bcrypt_config_interactive(
) -> Result<BcryptConfig, Box<dyn Error>> {
	let cost: u32 = Input::new()
		.with_prompt("Bcrypt cost")
		.default(12)
		.interact_text()?;

	Ok(BcryptConfig { cost })
}

fn get_pbkdf2_config_interactive() -> Result<
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

fn get_balloon_config_interactive(
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

pub fn interactive_analyze_hash() -> Result<(), Box<dyn Error>> {
	let hash = Input::<String>::new()
		.with_prompt("Enter the hash to analyze")
		.interact_text()?;

	let analyzer = HashAnalyzer::from_string(&hash);
	let possible_hashes = analyzer.detect_possible_hashes();

	if possible_hashes.is_empty() {
		println!("{}", "No possible hash class found.".yellow());
	} else {
		println!("{}", "Possible class of hash:".green());
		for hash_type in possible_hashes {
			println!("  {}", hash_type);
		}
	}

	Ok(())
}

pub fn interactive_compare_hashes() -> Result<(), Box<dyn Error>> {
	let hash1 = Input::<String>::new()
		.with_prompt("Enter the first hash")
		.interact_text()?;

	let hash2 = Input::<String>::new()
		.with_prompt("Enter the second hash")
		.interact_text()?;

	if compare_hashes(&hash1, &hash2) {
		println!("{}", "The hashes are equal.".green());
	} else {
		println!("{}", "The hashes are not equal.".red());
	}

	Ok(())
}

pub fn interactive_compare_file_hashes() -> Result<(), Box<dyn Error>> {
	let file1 = Input::<String>::new()
		.with_prompt("Enter the path to the first file")
		.interact_text()?;

	let file2 = Input::<String>::new()
		.with_prompt("Enter the path to the second file")
		.interact_text()?;

	match compare_file_hashes(&file1, &file2) {
		Ok(summary) => {
			render_compare_summary(&summary);
			println!(
				"{}",
				format!(
					"(Interactive mode) exit code would be {}",
					summary.exit_code
				)
				.cyan()
			);
		}
		Err(e) => println!(
			"{}",
			format!("Error comparing files: {}", e).red()
		),
	}

	Ok(())
}

fn select_rng_type() -> Result<RngType, Box<dyn Error>> {
	let rng_types: Vec<_> = RngType::iter().collect();
	let selection = Select::new()
		.with_prompt("Select a random number generator type")
		.items(&rng_types)
		.interact()?;

	Ok(rng_types[selection])
}

pub fn interactive_generate_random() -> Result<(), Box<dyn Error>> {
	let rng_type = select_rng_type()?;
	let length = Input::<u64>::new()
		.with_prompt("Enter the length of the random string")
		.default(32)
		.interact()?;

	let output_option = select_output_format()?;

	let out = RandomNumberGenerator::new(rng_type)
		.generate(length, output_option)?;
	println!("{}", out);

	Ok(())
}

pub fn interactive_generate_hhhash() -> Result<(), Box<dyn Error>> {
	let url = Input::<String>::new()
		.with_prompt("Enter the URL to fetch")
		.interact_text()?;

	let hash = generate_hhhash(url)?;
	println!("{}", hash);

	Ok(())
}

pub fn interactive_run_benchmarks() -> Result<(), Box<dyn Error>> {
	let algorithms = MultiSelect::new()
		.with_prompt("Select algorithms to benchmark")
		.items(&Algorithm::iter().collect::<Vec<_>>())
		.interact()?;

	let iterations = Input::<u32>::new()
		.with_prompt("Enter the number of iterations")
		.default(100)
		.interact()?;

	let selected_algorithms: Vec<Algorithm> = algorithms
		.into_iter()
		.map(|i| Algorithm::iter().nth(i).unwrap())
		.collect();

	let summary =
		run_digest_benchmarks(&selected_algorithms, iterations)
			.map_err(|err| Box::new(err) as Box<dyn Error>)?;
	render_digest_report(&summary);

	Ok(())
}

// Helpers

fn describe_optional(value: &Option<String>) -> String {
	value
		.as_ref()
		.map(|s| s.as_str())
		.unwrap_or("<missing>")
		.to_string()
}

pub fn render_compare_summary(summary: &CompareSummary) {
	match summary.mode {
		CompareMode::Manifest => {
			println!("{}", "Mode: manifest comparison".cyan());
		}
		CompareMode::Text => {
			println!("{}", "Mode: digest list comparison".cyan());
		}
	}

	if summary.differences.is_empty() {
		let scope = summary.left_entries.max(summary.right_entries);
		match summary.mode {
			CompareMode::Manifest => println!(
				"{}",
				format!("Manifests match across {} entries.", scope)
					.green()
			),
			CompareMode::Text => println!(
				"{}",
				format!("Files match across {} lines.", scope)
					.green()
			),
		}
	} else {
		println!(
			"{}",
			format!(
				"Detected {} difference(s):",
				summary.differences.len()
			)
			.yellow()
		);
		for diff in &summary.differences {
			let message = match diff.kind {
				CompareDiffKind::Changed => format!(
					"changed: {} (expected {}, actual {})",
					diff.identifier,
					describe_optional(&diff.expected),
					describe_optional(&diff.actual)
				),
				CompareDiffKind::MissingRight => format!(
					"missing in candidate: {} (expected {})",
					diff.identifier,
					describe_optional(&diff.expected)
				),
				CompareDiffKind::MissingLeft => format!(
					"extra in candidate: {} (actual {})",
					diff.identifier,
					describe_optional(&diff.actual)
				),
			};
			println!("{}", message.red());
		}
	}

	if summary.incomplete {
		println!(
			"{}",
			format!(
				"Comparison incomplete: baseline failures {}, candidate failures {}",
				summary.left_failures, summary.right_failures
			)
			.yellow()
		);
	}

	match summary.exit_code {
		0 => println!("{}", "Comparison succeeded (exit 0).".green()),
		1 => println!("{}", "Differences detected (exit 1).".red()),
		2 => {
			println!("{}", "Comparison incomplete (exit 2).".yellow())
		}
		code => println!(
			"{}",
			format!("Comparison finished with exit {}.", code)
				.yellow()
		),
	}
}

fn is_password_kdf(algorithm: Algorithm) -> bool {
	matches!(
		algorithm,
		Algorithm::Argon2
			| Algorithm::Scrypt
			| Algorithm::Pbkdf2Sha256
			| Algorithm::Pbkdf2Sha512
			| Algorithm::Bcrypt
			| Algorithm::Balloon
			| Algorithm::Shacrypt
	)
}

fn select_digest_algorithm_label() -> Result<String, Box<dyn Error>> {
	let algorithms: Vec<Algorithm> = Algorithm::iter()
		.filter(|alg| !is_password_kdf(*alg))
		.collect();
	let labels: Vec<String> =
		algorithms.iter().map(|alg| format!("{:?}", alg)).collect();
	let selection = Select::new()
		.with_prompt("Select digest algorithm")
		.items(&labels)
		.interact()?;
	Ok(labels[selection].to_uppercase())
}

fn confirm_weak_algorithm_selection(
	algorithm_label: &str,
) -> Result<bool, Box<dyn Error>> {
	if let Some(message) = warning_for(algorithm_label) {
		emit_warning_banner(&message);
		let choice = Select::new()
			.with_prompt("Weak algorithm selected")
			.items(&WEAK_PROMPT_OPTIONS)
			.default(WEAK_PROMPT_DEFAULT_INDEX)
			.interact()?;
		Ok(choice == 1)
	} else {
		Ok(true)
	}
}

fn select_digest_algorithm_with_guard(
) -> Result<String, Box<dyn Error>> {
	loop {
		let candidate = select_digest_algorithm_label()?;
		if confirm_weak_algorithm_selection(&candidate)? {
			return Ok(candidate);
		}
	}
}

fn prompt_password(prompt: &str) -> Result<String, Box<dyn Error>> {
	let password = Password::new()
		.with_prompt(prompt)
		.allow_empty_password(false)
		.interact()?;
	Ok(password)
}

fn select_output_format() -> Result<DigestOutputFormat, Box<dyn Error>>
{
	let options = vec![
		DigestOutputFormat::Hex,
		DigestOutputFormat::Base64,
		DigestOutputFormat::Json,
		DigestOutputFormat::JsonLines,
		DigestOutputFormat::Csv,
		DigestOutputFormat::Hashcat,
		DigestOutputFormat::Multihash,
	];
	let selection = Select::new()
		.with_prompt("Select output format")
		.items(&options)
		.interact()?;

	Ok(options[selection])
}

fn choose_output_format_for_algorithm(
	algorithm_label: &str,
) -> Result<DigestOutputFormat, Box<dyn Error>> {
	let supported =
		MulticodecSupportMatrix::algorithm_names().join(", ");
	loop {
		let format = select_output_format()?;
		if matches!(format, DigestOutputFormat::Multihash) {
			let normalized = algorithm_label.to_ascii_lowercase();
			if MulticodecSupportMatrix::lookup(&normalized).is_none()
			{
				println!(
					"warning: multihash format is unavailable for algorithm {}. Supported combinations: {}",
					algorithm_label,
					supported
				);
				continue;
			}
			println!(
				"info: multihash tokens will be emitted as base58btc strings prefixed with 'z'."
			);
		}
		return Ok(format);
	}
}