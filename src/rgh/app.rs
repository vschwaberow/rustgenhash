// SPDX-License-Identifier: MIT OR Apache-2.0
// Project: rustgenhash
// File: app.rs
// Author: Volker Schwaberow <volker@schwaberow.de>
// Copyright (c) 2022 Volker Schwaberow

use crate::rgh::analyze::compare_hashes;
use crate::rgh::analyze::HashAnalyzer;
use crate::rgh::benchmark::run_benchmarks;
use crate::rgh::hash::{PHash, RHash, Argon2Config, ScryptConfig, BcryptConfig, Pbkdf2Config, BalloonConfig};
use crate::rgh::hhhash::generate_hhhash;
use crate::rgh::random::{RandomNumberGenerator, RngType};
use clap::{crate_name, Arg};
use clap_complete::{generate, Generator, Shell};
use colored::*;
use dialoguer::{Input, MultiSelect, Select};
use std::error::Error;
use std::io::BufRead;
use strum::{EnumIter, IntoEnumIterator};

use super::analyze::compare_file_hashes;

const HELP_TEMPLATE: &str = "{before-help}{name} {version}
Written by {author-with-newline}{about-with-newline}
{usage-heading} {usage}

{all-args}{after-help}
";

#[derive(clap::ValueEnum, Debug, Copy, EnumIter, Clone)]
pub enum OutputOptions {
	Hex,
	Base64,
	HexBase64,
}

impl std::fmt::Display for OutputOptions {
	fn fmt(
		&self,
		f: &mut std::fmt::Formatter<'_>,
	) -> std::fmt::Result {
		write!(f, "{:?}", self)
	}
}

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

fn hash_string(
	algor: Algorithm,
	password: &str,
	option: OutputOptions,
    argon2_config: &Argon2Config,
    scrypt_config: &ScryptConfig,
    bcrypt_config: &BcryptConfig,
    pbkdf2_config: &Pbkdf2Config,
    balloon_config: &BalloonConfig,
) {
	use Algorithm as alg;
	match algor {
		alg::Ascon => {
			PHash::hash_ascon(password);
		}
		alg::Argon2 => {
			PHash::hash_argon2(password, argon2_config);
		}
        alg::Balloon => {
            PHash::hash_balloon(password, balloon_config);
        }
		alg::Bcrypt => {
			PHash::hash_bcrypt(password, bcrypt_config);
		}
		alg::Pbkdf2Sha256 | alg::Pbkdf2Sha512 => {
			PHash::hash_pbkdf2(
				password,
				format!("{:?}", algor).to_lowercase().as_str(),
                pbkdf2_config
			);
		}
		alg::Scrypt => {
			PHash::hash_scrypt(password, scrypt_config);
		}
		alg::Shacrypt => {
			PHash::hash_sha_crypt(password);
		}
		_ => {
			let alg_s = format!("{:?}", algor).to_uppercase();
			let b = RHash::new(&alg_s)
				.process_string(password.as_bytes());
			match option {
				OutputOptions::Hex => {
					println!("{} {}", hex::encode(b), password)
				}
				OutputOptions::Base64 => {
					println!("{} {}", base64::encode(b), password)
				}
				OutputOptions::HexBase64 => {
					println!(
						"{} {} {}",
						hex::encode(&b),
						base64::encode(&b),
						password
					);
				}
			}
		}
	}
}

fn hash_file(alg: Algorithm, input: &str, option: OutputOptions) {
	if !alg.properties().file_support {
		println!("Algorithm {:?} does not support file hashing", alg);
		std::process::exit(1);
	}
	let alg_s = format!("{:?}", alg).to_uppercase();
	let result = RHash::new(&alg_s).process_file(input, option);
	match result {
		Ok(_) => {}
		Err(e) => {
			eprintln!("Error: {}", e);
			std::process::exit(1);
		}
	}
}

fn interactive_hash_string() -> Result<(), Box<dyn Error>> {
	let input = Input::<String>::new()
		.with_prompt("Enter the string to hash")
		.interact_text()?;

	let algorithm = select_algorithm()?;
	let output_option = select_output_option()?;

    let mut argon2_config = Argon2Config::default();
    let mut scrypt_config = ScryptConfig::default();
    let mut bcrypt_config = BcryptConfig::default();
    let mut pbkdf2_config = Pbkdf2Config::default();
    let mut balloon_config = BalloonConfig::default();

    match algorithm {
        Algorithm::Argon2 => {
            argon2_config = get_argon2_config_interactive()?;
        }
        Algorithm::Scrypt => {
            scrypt_config = get_scrypt_config_interactive()?;
        }
        Algorithm::Bcrypt => {
            bcrypt_config = get_bcrypt_config_interactive()?;
        }
        Algorithm::Pbkdf2Sha256 | Algorithm::Pbkdf2Sha512 => {
            pbkdf2_config = get_pbkdf2_config_interactive()?;
        }
        Algorithm::Balloon => {
            balloon_config = get_balloon_config_interactive()?;
        }
        _ => {}
    }


	hash_string(algorithm, &input, output_option, &argon2_config, &scrypt_config, &bcrypt_config, &pbkdf2_config, &balloon_config);
	Ok(())
}

fn interactive_hash_file() -> Result<(), Box<dyn Error>> {
	let file_path = Input::<String>::new()
		.with_prompt("Enter the file path")
		.interact_text()?;

	let algorithm = select_algorithm()?;
	let output_option = select_output_option()?;

	hash_file(algorithm, &file_path, output_option);
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

fn interactive_compare_file_hashes() -> Result<(), Box<dyn Error>> {
	let file1 = Input::<String>::new()
		.with_prompt("Enter the path to the first file")
		.interact_text()?;

	let file2 = Input::<String>::new()
		.with_prompt("Enter the path to the second file")
		.interact_text()?;

	match compare_file_hashes(&file1, &file2) {
		Ok(_) => println!("{}", "File operation complete.".green()),
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

	let output_option = select_output_option()?;

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

fn select_algorithm() -> Result<Algorithm, Box<dyn Error>> {
	let algorithms: Vec<_> = Algorithm::iter().collect();
	let selection = Select::new()
		.with_prompt("Select an algorithm")
		.items(&algorithms)
		.interact()?;

	Ok(algorithms[selection])
}

fn select_output_option() -> Result<OutputOptions, Box<dyn Error>> {
	let options = vec![
		OutputOptions::Hex,
		OutputOptions::Base64,
		OutputOptions::HexBase64,
	];
	let selection = Select::new()
		.with_prompt("Select output format")
		.items(&options)
		.interact()?;

	Ok(options[selection])
}

fn get_argon2_config_interactive() -> Result<Argon2Config, Box<dyn Error>> {
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

fn get_scrypt_config_interactive() -> Result<ScryptConfig, Box<dyn Error>> {
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

fn get_bcrypt_config_interactive() -> Result<BcryptConfig, Box<dyn Error>> {
    let cost: u32 = Input::new()
        .with_prompt("Bcrypt cost")
        .default(12)
        .interact_text()?;

    Ok(BcryptConfig { cost })
}

fn get_pbkdf2_config_interactive() -> Result<Pbkdf2Config, Box<dyn Error>> {
    let rounds: u32 = Input::new()
        .with_prompt("PBKDF2 rounds")
        .default(100_000)
        .interact_text()?;
    let output_length: usize = Input::new()
        .with_prompt("PBKDF2 output length (bytes)")
        .default(32)
        .interact_text()?;

    Ok(Pbkdf2Config { rounds, output_length })
}

fn get_balloon_config_interactive() -> Result<BalloonConfig, Box<dyn Error>> {
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
        .default(4).interact_text()?;

		Ok(BalloonConfig {
			time_cost,
			memory_cost,
			parallelism,
		})
	}
	
	
	fn run_interactive_mode() -> Result<(), Box<dyn Error>> {
		println!("{}", "Welcome to the Interactive Mode!".green().bold());
	
		let actions = vec![
			"Hash a string",
			"Hash a file",
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
				0 => interactive_hash_string()?,
				1 => interactive_hash_file()?,
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
						Arg::new("output")
							.short('o')
							.long("output")
							.value_parser(clap::value_parser!(
								OutputOptions
							))
							.help("Output format")
							.default_value("hex")
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
						Arg::new("output")
							.short('o')
							.long("output")
							.value_parser(clap::value_parser!(
								OutputOptions
							))
							.help("Output format")
							.default_value("hex")
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
						Arg::new("output")
							.short('o')
							.long("output")
							.value_parser(clap::value_parser!(
								OutputOptions
							))
							.help("Output format")
							.default_value("hex")
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
						Arg::new("output")
							.short('o')
							.long("output")
							.value_parser(clap::value_parser!(
								OutputOptions
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
				clap::command!("compare-file-hashes")
					.about("Compare two files with hashes")
					.arg(
						Arg::new("FILE1")
							.help("First file to compare")
							.required(true),
					)
					.arg(
						Arg::new("FILE2")
							.help("Second file to compare")
							.required(true),
					),
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
	
	pub fn run() -> Result<(), Box<dyn Error>> {
		let capp = build_cli();
		let m = capp.get_matches();
	
		match m.subcommand() {
			Some(("interactive", _)) => {
				run_interactive_mode()?;
			}
			Some(("string", s)) => {
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
					Some(a) => a.clone(),
					None => panic!("Algorithm not found."),
				};
				let option = s.get_one::<OutputOptions>("output");
				let option = match option {
					Some(o) => o.clone(),
					None => {
						println!("No output format provided.");
						std::process::exit(1);
					}
				};
				let argon2_config = Argon2Config {
					mem_cost: *s.get_one::<u32>("argon2-mem-cost").unwrap(),
					time_cost: *s.get_one::<u32>("argon2-time-cost").unwrap(),
					parallelism: *s.get_one::<u32>("argon2-parallelism").unwrap(),
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
					output_length: *s.get_one::<usize>("pbkdf2-output-length").unwrap(),
				};
				let balloon_config = BalloonConfig {
					time_cost: *s.get_one::<u32>("balloon-time-cost").unwrap(),
					memory_cost: *s.get_one::<u32>("balloon-memory-cost").unwrap(),
					parallelism: *s.get_one::<u32>("balloon-parallelism").unwrap(),
				};
	
				hash_string(a, st, option, &argon2_config, &scrypt_config, &bcrypt_config, &pbkdf2_config, &balloon_config);
			}
			Some(("compare-file-hashes", s)) => {
				let file1 = s.get_one::<String>("FILE1");
				let file2 = s.get_one::<String>("FILE2");
				let file1 = file1.unwrap_or_else(|| {
					println!("No file provided.");
					std::process::exit(1);
				});
				let file2 = file2.unwrap_or_else(|| {
					println!("No file provided.");
					std::process::exit(1);
				});
				match compare_file_hashes(file1, file2) {
					Ok(_) => println!("File operation complete."),
					Err(e) => {
						eprintln!("Error comparing files: {}", e);
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
					Some(a) => a.clone(),
					None => panic!("Algorithm not found."),
				};
				let option = s.get_one::<OutputOptions>("output");
				let option = match option {
					Some(o) => o.clone(),
					None => {
						println!("No output format provided.");
						std::process::exit(1);
					}
				};
				hash_file(a,f, option);
			}
			Some(("stdio", s)) => {
				let stdin = std::io::stdin();
				stdin.lock().lines().for_each(|l| {
					let a = s.get_one::<Algorithm>("algorithm");
					let a = match a {
						Some(a) => a.clone(),
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
					let option = s.get_one::<OutputOptions>("output");
					let option = match option {
						Some(o) => o.clone(),
						None => {
							println!("No output format provided.");
							std::process::exit(1);
						}
					};
					let argon2_config = Argon2Config::default();
					let scrypt_config = ScryptConfig::default();
					let bcrypt_config = BcryptConfig::default();
					let pbkdf2_config = Pbkdf2Config::default();
					let balloon_config = BalloonConfig::default();
	
					hash_string(a, &l, option, &argon2_config, &scrypt_config, &bcrypt_config, &pbkdf2_config, &balloon_config);
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
					Some(a) => a.clone(),
					None => panic!("Algorithm not found."),
				};
				let option = s.get_one::<OutputOptions>("output");
				let option = match option {
					Some(o) => o.clone(),
					None => {
						println!("No output format provided.");
						std::process::exit(1);
					}
				};
				let len = s.get_one::<u64>("length");
				let len = match len {
					Some(l) => l,
					None => {
						println!("No length provided.");
						std::process::exit(1);
					}
				};
				let out =
					RandomNumberGenerator::new(a).generate(*len, option);
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
						vec![
							Algorithm::Md5,
							Algorithm::Sha256,
							Algorithm::Blake2b,
							Algorithm::Argon2,
							Algorithm::Sha1,
							Algorithm::Sha512,
							Algorithm::Blake3,
							Algorithm::Blake2s,
							Algorithm::Groestl,
							Algorithm::Sha3_256,
							Algorithm::Sha3_512,
							Algorithm::Whirlpool,
							Algorithm::Sm3,
							Algorithm::Streebog256,
							Algorithm::Streebog512,
							Algorithm::Ripemd160,
							Algorithm::Ripemd320,
							Algorithm::Tiger,
							Algorithm::Gost94,
							Algorithm::Gost94ua,
							Algorithm::Fsb160,
							Algorithm::Fsb224,
							Algorithm::Fsb256,
							Algorithm::Fsb384,
							Algorithm::Fsb512,
							Algorithm::Shabal192,
							Algorithm::Shabal224,
							Algorithm::Shabal256,
							Algorithm::Shabal384,
							Algorithm::Shabal512,
							Algorithm::Bcrypt,
							Algorithm::Scrypt,
							Algorithm::Pbkdf2Sha256,
							Algorithm::Pbkdf2Sha512,
							Algorithm::Balloon,
							Algorithm::Ascon,
						]
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