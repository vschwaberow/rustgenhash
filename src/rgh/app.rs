// SPDX-License-Identifier: MIT OR Apache-2.0
// Project: rustgenhash
// File: app.rs
// Author: Volker Schwaberow <volker@schwaberow.de>
// Copyright (c) 2022 Volker Schwaberow

use crate::rgh::analyze::compare_hashes;
use crate::rgh::analyze::HashAnalyzer;
use crate::rgh::benchmark::{
	digest_benchmark_presets, kdf_benchmark_presets, run_benchmarks,
};
use crate::rgh::digest::commands as digest_commands;
use crate::rgh::file::{
	DirectoryHashPlan, ErrorHandlingProfile, ErrorStrategy,
	ProgressConfig, ProgressMode, SymlinkPolicy, ThreadStrategy,
	WalkOrder,
};
use crate::rgh::hash::{
	compare_file_hashes, digest_bytes_to_record,
	serialize_digest_output, Argon2Config, BalloonConfig,
	BcryptConfig, CompareDiffKind, CompareMode, CompareSummary,
	FileDigestOptions, PHash, Pbkdf2Config, ScryptConfig,
};
use crate::rgh::hhhash::generate_hhhash;
use crate::rgh::kdf::commands as kdf_commands;
use crate::rgh::multihash::MulticodecSupportMatrix;
use crate::rgh::output::{
	DigestOutputFormat, DigestSource, SerializationResult,
};
use crate::rgh::random::{RandomNumberGenerator, RngType};
use clap::{crate_name, Arg, ArgAction};
use clap_complete::{generate, Generator, Shell};
use colored::*;
use dialoguer::{Confirm, Input, MultiSelect, Password, Select};
use std::error::Error;
use std::io::{self, BufRead, Read};
use std::path::PathBuf;
use std::time::Duration;
use strum::{EnumIter, IntoEnumIterator};

const HELP_TEMPLATE: &str = "{before-help}{name} {version}
Written by {author-with-newline}{about-with-newline}
Primary command families:
  rgh digest <mode>   Hash strings/files/stdin (e.g. rgh digest string -a sha256 'text')
  rgh kdf <algorithm> Derive passwords with JSON metadata (e.g. rgh kdf argon2 --password-stdin)
{usage-heading} {usage}

{all-args}{after-help}
";

#[derive(clap::ValueEnum, Debug, Copy, Clone, EnumIter)]
pub enum Algorithm {
	Ascon,
	Argon2,
	Balloon,
	Bcrypt,
	Belthash,
	Blake2b,
	Blake2s,
	Blake3,
	Fsb160,
	Fsb224,
	Fsb256,
	Fsb384,
	Fsb512,
	Gost94,
	Gost94ua,
	Groestl,
	Jh224,
	Jh256,
	Jh384,
	Jh512,
	Md2,
	Md4,
	Md5,
	Pbkdf2Sha256,
	Pbkdf2Sha512,
	Ripemd160,
	Ripemd320,
	Scrypt,
	Sha1,
	Sha224,
	Sha256,
	Sha384,
	Sha512,
	Sha3_224,
	Sha3_256,
	Sha3_384,
	Sha3_512,
	Shabal192,
	Shabal224,
	Shabal256,
	Shabal384,
	Shabal512,
	Shacrypt,
	Skein256,
	Skein512,
	Skein1024,
	Sm3,
	Streebog256,
	Streebog512,
	Tiger,
	Whirlpool,
}

const ASCON_PROPERTIES: AlgorithmProperties = AlgorithmProperties {
	file_support: false,
};

const ARGON2_PROPERTIES: AlgorithmProperties = AlgorithmProperties {
	file_support: false,
};
const PBKDF2_PROPERTIES: AlgorithmProperties = AlgorithmProperties {
	file_support: false,
};
const SCRYPT_PROPERTIES: AlgorithmProperties = AlgorithmProperties {
	file_support: false,
};
const SHACRYPT_PROPERTIES: AlgorithmProperties =
	AlgorithmProperties {
		file_support: false,
	};
const BCRYPT_PROPERTIES: AlgorithmProperties = AlgorithmProperties {
	file_support: false,
};
const BALLOON_PROPERTIES: AlgorithmProperties = AlgorithmProperties {
	file_support: false,
};
const DEFAULT_PROPERTIES: AlgorithmProperties =
	AlgorithmProperties { file_support: true };

struct AlgorithmProperties {
	file_support: bool,
}

impl std::fmt::Display for Algorithm {
	fn fmt(
		&self,
		f: &mut std::fmt::Formatter<'_>,
	) -> std::fmt::Result {
		write!(f, "{:?}", self)
	}
}

impl Algorithm {
	fn properties(&self) -> AlgorithmProperties {
		match *self {
			Algorithm::Ascon => ASCON_PROPERTIES,
			Algorithm::Argon2 => ARGON2_PROPERTIES,
			Algorithm::Pbkdf2Sha256 | Algorithm::Pbkdf2Sha512 => {
				PBKDF2_PROPERTIES
			}
			Algorithm::Scrypt => SCRYPT_PROPERTIES,
			Algorithm::Shacrypt => SHACRYPT_PROPERTIES,
			Algorithm::Bcrypt => BCRYPT_PROPERTIES,
			Algorithm::Balloon => BALLOON_PROPERTIES,
			_ => DEFAULT_PROPERTIES,
		}
	}
}

struct HashConfigs<'a> {
	argon2: &'a Argon2Config,
	scrypt: &'a ScryptConfig,
	bcrypt: &'a BcryptConfig,
	pbkdf2: &'a Pbkdf2Config,
	balloon: &'a BalloonConfig,
}

fn hash_string(
	algor: Algorithm,
	password: &str,
	format: DigestOutputFormat,
	configs: &HashConfigs,
	hash_only: bool,
) {
	use Algorithm as alg;
	match algor {
		alg::Ascon => {
			hash_digest_output(algor, password, format, hash_only)
		}
		alg::Argon2 => {
			PHash::hash_argon2(password, configs.argon2, hash_only)
		}
		alg::Balloon => {
			PHash::hash_balloon(password, configs.balloon, hash_only)
		}
		alg::Bcrypt => {
			PHash::hash_bcrypt(password, configs.bcrypt, hash_only)
		}
		alg::Pbkdf2Sha256 | alg::Pbkdf2Sha512 => {
			let pb_scheme = format!("{:?}", algor).to_lowercase();
			PHash::hash_pbkdf2(
				password,
				pb_scheme.as_str(),
				configs.pbkdf2,
				hash_only,
			);
		}
		alg::Scrypt => {
			PHash::hash_scrypt(password, configs.scrypt, hash_only);
		}
		alg::Shacrypt => PHash::hash_sha_crypt(password, hash_only),
		_ => hash_digest_output(algor, password, format, hash_only),
	}
}

fn hash_digest_output(
	algorithm: Algorithm,
	input: &str,
	format: DigestOutputFormat,
	hash_only: bool,
) {
	use Algorithm as alg;
	match algorithm {
		alg::Ascon => {
			PHash::hash_ascon(input, hash_only);
		}
		_ => {
			let alg_s = format!("{:?}", algorithm).to_uppercase();
			match digest_bytes_to_record(
				&alg_s,
				input.as_bytes(),
				Some(input),
				DigestSource::String,
			) {
				Ok(record) => {
					match serialize_digest_output(
						&[record],
						format,
						hash_only,
					) {
						Ok(result) => {
							emit_serialization_to_stdout(result)
						}
						Err(err) => {
							eprintln!("Serialization error: {}", err);
							std::process::exit(1);
						}
					}
				}
				Err(err) => {
					eprintln!("Failed to digest input: {}", err);
					std::process::exit(1);
				}
			}
		}
	}
}

fn hash_file(
	alg: Algorithm,
	input: &str,
	format: DigestOutputFormat,
	hash_only: bool,
) {
	if !alg.properties().file_support {
		println!("Algorithm {:?} does not support file hashing", alg);
		std::process::exit(1);
	}
	let algorithm_label = format!("{:?}", alg).to_uppercase();
	let plan = DirectoryHashPlan {
		root_path: PathBuf::from(input),
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
		format,
		hash_only,
		progress,
		manifest_path: None,
		error_profile,
	};
	if let Err(err) = digest_commands::digest_path(options) {
		eprintln!("Error: {}", err);
		std::process::exit(1);
	}
}

fn emit_serialization_to_stdout(result: SerializationResult) {
	for warning in result.warnings {
		eprintln!("warning: {}", warning);
	}
	for line in result.lines {
		println!("{}", line);
	}
}

fn interactive_digest_string() -> Result<(), Box<dyn Error>> {
	let input = Input::<String>::new()
		.with_prompt("Enter the string to digest")
		.interact_text()?;

	let algorithm_label = select_digest_algorithm_label()?;
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
	let algorithm_label = select_digest_algorithm_label()?;
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

fn interactive_digest_menu() -> Result<(), Box<dyn Error>> {
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

fn interactive_kdf_menu() -> Result<(), Box<dyn Error>> {
	let actions = vec![
		"Argon2",
		"Scrypt",
		"PBKDF2",
		"Bcrypt",
		"Balloon",
		"SHA-crypt",
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
				let config = get_scrypt_config_interactive()?;
				let hash_only = Confirm::new()
					.with_prompt("Emit only the derived key output?")
					.default(false)
					.interact()?;
				kdf_commands::derive_scrypt(
					&password, &config, hash_only,
				)?;
			}
			2 => {
				let password =
					prompt_password("Enter password for PBKDF2")?;
				let config = get_pbkdf2_config_interactive()?;
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
					&password, scheme, &config, hash_only,
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
			6 => break,
			_ => unreachable!(),
		}
	}
	Ok(())
}

fn interactive_analyze_hash() -> Result<(), Box<dyn Error>> {
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

fn interactive_compare_hashes() -> Result<(), Box<dyn Error>> {
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

fn describe_optional(value: &Option<String>) -> String {
	value
		.as_ref()
		.map(|s| s.as_str())
		.unwrap_or("<missing>")
		.to_string()
}

fn render_compare_summary(summary: &CompareSummary) {
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

fn interactive_compare_file_hashes() -> Result<(), Box<dyn Error>> {
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

fn interactive_generate_random() -> Result<(), Box<dyn Error>> {
	let rng_type = select_rng_type()?;
	let length = Input::<u64>::new()
		.with_prompt("Enter the length of the random string")
		.default(32)
		.interact()?;

	let output_option = select_output_format()?;

	let out = RandomNumberGenerator::new(rng_type)
		.generate(length, output_option);
	println!("{}", out);

	Ok(())
}

fn interactive_generate_hhhash() -> Result<(), Box<dyn Error>> {
	let url = Input::<String>::new()
		.with_prompt("Enter the URL to fetch")
		.interact_text()?;

	let hash = generate_hhhash(url)?;
	println!("{}", hash);

	Ok(())
}

fn interactive_run_benchmarks() -> Result<(), Box<dyn Error>> {
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

	run_benchmarks(&selected_algorithms, iterations);

	Ok(())
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

fn get_scrypt_config_interactive(
) -> Result<ScryptConfig, Box<dyn Error>> {
	let log_n: u8 = Input::new()
		.with_prompt("Scrypt log_n (2^n)")
		.default(15)
		.interact_text()?;
	let r: u32 = Input::new()
		.with_prompt("Scrypt r")
		.default(8)
		.interact_text()?;
	let p: u32 = Input::new()
		.with_prompt("Scrypt p")
		.default(1)
		.interact_text()?;

	Ok(ScryptConfig { log_n, r, p })
}

fn get_bcrypt_config_interactive(
) -> Result<BcryptConfig, Box<dyn Error>> {
	let cost: u32 = Input::new()
		.with_prompt("Bcrypt cost")
		.default(12)
		.interact_text()?;

	Ok(BcryptConfig { cost })
}

fn get_pbkdf2_config_interactive(
) -> Result<Pbkdf2Config, Box<dyn Error>> {
	let rounds: u32 = Input::new()
		.with_prompt("PBKDF2 rounds")
		.default(100_000)
		.interact_text()?;
	let output_length: usize = Input::new()
		.with_prompt("PBKDF2 output length (bytes)")
		.default(32)
		.interact_text()?;

	Ok(Pbkdf2Config {
		rounds,
		output_length,
	})
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

fn run_interactive_mode() -> Result<(), Box<dyn Error>> {
	println!("{}", "Welcome to the Interactive Mode!".green().bold());

	let actions = vec![
		"Digest data",
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
			1 => interactive_kdf_menu()?,
			2 => interactive_analyze_hash()?,
			3 => interactive_compare_hashes()?,
			4 => interactive_compare_file_hashes()?,
			5 => interactive_generate_random()?,
			6 => interactive_generate_hhhash()?,
			7 => interactive_run_benchmarks()?,
			8 => {
				println!("{}", "Goodbye!".cyan());
				break;
			}
			_ => unreachable!(),
		}
	}

	Ok(())
}

fn build_cli() -> clap::Command {
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
									.help("Digest algorithm identifier (e.g., sha256)")
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
										),
									)
					.help("Output format (json, jsonl, csv, hex, base64, hashcat, multihash=base58btc)")
									.default_value("hex"),
							)
							.arg(
								Arg::new("hash-only")
									.long("hash-only")
									.help("Emit only digests without original input")
									.action(ArgAction::SetTrue),
							),
					)
				.subcommand(
					clap::command!("file")
						.about("Hash the contents of a file or directory")
						.arg(
							Arg::new("algorithm")
								.short('a')
								.long("algorithm")
								.help("Digest algorithm identifier (e.g., sha256)")
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
									),
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
									.help("Digest algorithm identifier (e.g., sha256)")
									.required(true),
							)
							.arg(
								Arg::new("format")
									.short('f')
									.long("format")
									.value_parser(
										clap::value_parser!(
											DigestOutputFormat
										),
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
							),
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
							),
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
							),
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
							),
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
							),
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
							),
					),
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
			),
			)
		.subcommand(
			clap::command!("file")
				.about("Hash single file or single directory")
				.arg(Arg::new("FILE").display_order(1).required(true))
				.arg(
					Arg::new("algorithm")
						.display_order(2)
						.value_parser(clap::value_parser!(Algorithm))
						.help("Hashing algorithm to use")
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
						.help("Hashing algorithm"),
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
			clap::command!("compare-file")
				.about("Compare manifest JSON or digest outputs for equality")
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
					),
			)
			.subcommand(clap::command!("interactive")
				.about("Enter interactive mode")
			)
			.subcommand(
				clap::command!("header")
					.about("Generate a HHHash of HTTP header")
					.arg(
						Arg::new("URL")
							.help("URL to fetch")
							.required(true),
					),
			)
					.subcommand(
				clap::command!("benchmark")
					.about("Run benchmarks for hash functions")
					.arg(
						Arg::new("algorithms")
							.short('a')
							.long("algorithms")
							.value_parser(clap::value_parser!(Algorithm))
			 //               .multiple_values(true)
							.help("Specify algorithms to benchmark (default: all)")
					)
					.arg(
						Arg::new("iterations")
							.short('i')
							.long("iterations")
							.value_parser(clap::value_parser!(u32))
							.default_value("100")
							.help("Number of iterations for each benchmark")
					)
			)
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
		let manifest_path = args
			.get_one::<String>("manifest")
			.map(PathBuf::from);
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

fn parse_symlink_policy(value: &str) -> SymlinkPolicy {
	match value.to_ascii_lowercase().as_str() {
		"never" => SymlinkPolicy::Never,
		"files" => SymlinkPolicy::Files,
		"all" => SymlinkPolicy::All,
		_ => SymlinkPolicy::Never,
	}
}

fn parse_thread_strategy(
	value: &str,
) -> Result<ThreadStrategy, String> {
	let trimmed = value.trim();
	if trimmed.eq_ignore_ascii_case("auto") {
		return Ok(ThreadStrategy::Auto);
	}
	let count: u16 = trimmed
		.parse()
		.map_err(|_| format!("Invalid thread count '{trimmed}'"))?;
	if count == 0 {
		return Err("Thread count must be >= 1".into());
	}
	if count == 1 {
		Ok(ThreadStrategy::Single)
	} else {
		Ok(ThreadStrategy::Fixed(count))
	}
}

fn parse_mmap_threshold(value: &str) -> Result<Option<u64>, String> {
	let trimmed = value.trim();
	if trimmed.is_empty() {
		return Err("mmap threshold cannot be empty".into());
	}
	if trimmed.eq_ignore_ascii_case("off") {
		return Ok(None);
	}
	let lower = trimmed.to_ascii_lowercase();
	let mut split = lower.len();
	for (idx, ch) in lower.char_indices() {
		if !ch.is_ascii_digit() {
			split = idx;
			break;
		}
	}
	let (number, suffix) = lower.split_at(split);
	if number.is_empty() {
		return Err(format!("Invalid mmap threshold '{trimmed}'"));
	}
	let value: u64 = number
		.parse()
		.map_err(|_| format!("Invalid mmap threshold '{trimmed}'"))?;
	let factor: u64 = match suffix {
		"" | "b" => 1,
		"k" | "kb" | "kib" => 1024,
		"m" | "mb" | "mib" => 1024 * 1024,
		"g" | "gb" | "gib" => 1024 * 1024 * 1024,
		other => {
			return Err(format!(
				"Unsupported size suffix '{}' for mmap threshold",
				other
			))
		}
	};
	value
		.checked_mul(factor)
		.map(Some)
		.ok_or_else(|| "mmap threshold overflow".into())
}

fn parse_error_strategy(value: &str) -> ErrorStrategy {
	match value.to_ascii_lowercase().as_str() {
		"fail-fast" => ErrorStrategy::FailFast,
		"continue" => ErrorStrategy::Continue,
		"report-only" => ErrorStrategy::ReportOnly,
		_ => ErrorStrategy::FailFast,
	}
}

fn build_progress_config(args: &clap::ArgMatches) -> ProgressConfig {
	let mode = if args.get_flag("no-progress") {
		ProgressMode::Disabled
	} else if args.get_flag("progress") {
		ProgressMode::Enabled
	} else {
		ProgressMode::Auto
	};
	ProgressConfig {
		mode,
		throttle: Duration::from_millis(500),
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
		let trimmed =
			buffer.trim_end_matches(&['\n', '\r'][..]).to_string();
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
			let config = ScryptConfig {
				log_n: *args
					.get_one::<u8>("log-n")
					.expect("log-n has default"),
				r: *args.get_one::<u32>("r").expect("r has default"),
				p: *args.get_one::<u32>("p").expect("p has default"),
			};
			kdf_commands::derive_scrypt(&password, &config, hash_only)
		}
		Some(("pbkdf2", args)) => {
			let password = resolve_kdf_password(args)?;
			let hash_only = args.get_flag("hash-only");
			let config = Pbkdf2Config {
				rounds: *args
					.get_one::<u32>("rounds")
					.expect("rounds has default"),
				output_length: *args
					.get_one::<usize>("length")
					.expect("length has default"),
			};
			let scheme = args
				.get_one::<String>("algorithm")
				.expect("algorithm has default");
			kdf_commands::derive_pbkdf2(
				&password, scheme, &config, hash_only,
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

fn emit_legacy_warning(command: &str, replacement: &str) {
	eprintln!(
		"{}",
		format!(
			"warning: `rgh {}` is deprecated; use `{}` instead.",
			command, replacement
		)
		.yellow()
	);
}

pub fn run() -> Result<(), Box<dyn Error>> {
	let capp = build_cli();
	let m = capp.get_matches();

	match m.subcommand() {
		Some(("digest", matches)) => {
			handle_digest_command(matches)?;
		}
		Some(("kdf", matches)) => {
			handle_kdf_command(matches)?;
		}
		Some(("interactive", _)) => {
			run_interactive_mode()?;
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
			let out =
				RandomNumberGenerator::new(a).generate(*len, format);
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
		Some(("benchmark", sub_m)) => {
			let algorithms: Vec<Algorithm> = sub_m
				.get_many("algorithms")
				.map(|v| v.cloned().collect())
				.unwrap_or_else(|| {
					let mut presets = digest_benchmark_presets();
					presets.extend(kdf_benchmark_presets());
					presets
				});
			let iterations =
				*sub_m.get_one::<u32>("iterations").unwrap();
			run_benchmarks(&algorithms, iterations);
		}
		_ => {}
	}
	Ok(())
}

fn print_completions<G: Generator>(gen: G, cmd: &mut clap::Command) {
	generate(
		gen,
		cmd,
		cmd.get_name().to_string(),
		&mut std::io::stdout(),
	);
}
