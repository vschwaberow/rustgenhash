// SPDX-License-Identifier: MIT OR Apache-2.0
// Project: rustgenhash
// File: app.rs
// Author: Volker Schwaberow <volker@schwaberow.de>
// Copyright (c) 2022 Volker Schwaberow

use crate::rgh::analyze::compare_hashes;
use crate::rgh::analyze::HashAnalyzer;
use crate::rgh::hash::{PHash, RHash};
use crate::rgh::hhhash::generate_hhhash;
use crate::rgh::random::{RandomNumberGenerator, RngType};
use clap::{crate_name, Arg};
use clap_complete::{generate, Generator, Shell};
use std::error::Error;
use std::io::BufRead;

const HELP_TEMPLATE: &str = "{before-help}{name} {version}
Written by {author-with-newline}{about-with-newline}
{usage-heading} {usage}

{all-args}{after-help}
";

#[derive(clap::ValueEnum, Debug, Clone)]
pub enum OutputOptions {
	Hex,
	Base64,
	HexBase64,
}

#[derive(clap::ValueEnum, Debug, Clone)]
pub enum Algorithm {
	Ascon,
	Argon2,
	Balloon,
	Bcrypt,
	Belthash,
	Blake2b,
	Blake2s,
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
) {
	use Algorithm as alg;
	match algor {
		alg::Ascon => {
			PHash::hash_ascon(password);
		}
		alg::Argon2 => {
			PHash::hash_argon2(password);
		}
		alg::Balloon => {
			PHash::hash_balloon(password);
		}
		alg::Bcrypt => {
			PHash::hash_bcrypt(password);
		}
		alg::Pbkdf2Sha256 | alg::Pbkdf2Sha512 => {
			PHash::hash_pbkdf2(
				password,
				format!("{:?}", algor).to_lowercase().as_str(),
			);
		}
		alg::Scrypt => {
			PHash::hash_scrypt(password);
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
		Ok(r) => println!("{:?}", r),
		Err(e) => {
			eprintln!("Error: {}", e);
			std::process::exit(1);
		}
	}
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
					Arg::new("algorithm")
						.short('a')
						.long("algorithm")
						.value_parser(clap::value_parser!(Algorithm))
						.required(true)
						.display_order(1),
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
			clap::command!("compare-string")
				.about("Compare two strings")
				.arg(
					Arg::new("STRING1")
						.help("First string to compare")
						.required(true),
				)
				.arg(
					Arg::new("STRING2")
						.help("Second string to compare")
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
		.subcommand(
			clap::command!("header")
				.about("Generate a HHHash of HTTP header")
				.arg(
					Arg::new("URL")
						.help("URL to fetch")
						.required(true),
				),
		)
}

pub fn run() -> Result<(), Box<dyn Error>> {
	let capp = build_cli();
	let m = capp.get_matches();

	match m.subcommand() {
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
			hash_string(a, st, option);
		}
		Some(("compare-string", s)) => {
			let st1 = s.get_one::<String>("STRING1");
			let st1 = match st1 {
				Some(s) => s,
				None => {
					println!("No string provided.");
					std::process::exit(1);
				}
			};
			let st2 = s.get_one::<String>("STRING2");
			let st2 = match st2 {
				Some(s) => s,
				None => {
					println!("No string provided.");
					std::process::exit(1);
				}
			};
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
			hash_file(a, f, option);
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
				hash_string(a, &l, option);
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
			// get url from
			let url = s.get_one::<String>("URL").unwrap();
			let url = url.clone();
			let hash = generate_hhhash(url)?;
			println!("{}", hash);
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
