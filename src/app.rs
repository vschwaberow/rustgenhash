/*
Copyright 2022 Volker Schwaberow <volker@schwaberow.de>
Permission is hereby granted, free of charge, to any person obtaining a
copy of this software and associated documentation files (the
"Software"), to deal in the Software without restriction, including without
limitation the rights to use, copy, modify, merge, publish, distribute,
sublicense, and/or sell copies of the Software, and to permit persons to whom the
Software is furnished to do so, subject to the following conditions:
The above copyright notice and this permission notice shall be
included in all copies or substantial portions of the Software.
THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS
OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT
SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR
OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE,
ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER
DEALINGS IN THE SOFTWARE.
Author(s): Volker Schwaberow
*/
use crate::hash::{PHash, RHash};
use clap::{crate_name, Arg};
use clap_complete::{generate, Generator, Shell};
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
	Sm3,
	Streebog256,
	Streebog512,
	Tiger,
	Whirlpool,
}

struct AlgorithmProperties {
	file_support: bool,
}

impl Algorithm {
	fn properties(&self) -> AlgorithmProperties {
		match *self {
			Algorithm::Argon2 => AlgorithmProperties { file_support: false },
			Algorithm::Pbkdf2Sha256 | Algorithm::Pbkdf2Sha512 => {
				AlgorithmProperties { file_support: false }
			},
			Algorithm::Scrypt => AlgorithmProperties { file_support: false },
			Algorithm::Shacrypt => AlgorithmProperties { file_support: false },
			Algorithm::Bcrypt => AlgorithmProperties { file_support: false },
			Algorithm::Balloon => AlgorithmProperties { file_support: false },
			_ => AlgorithmProperties { file_support: true }
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
	RHash::new(&alg_s).process_file(input, option);
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
			clap::command!("generate-auto-completions")
				.about("Generate shell completions")
				.arg(
					Arg::new("SHELL")
						.required(true)
						.value_parser(clap::value_parser!(Shell))
						.help("Shell to generate completions for"),
				),
		)
}

pub fn run() {
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
		_ => {}
	}
}

fn print_completions<G: Generator>(gen: G, cmd: &mut clap::Command) {
	generate(
		gen,
		cmd,
		cmd.get_name().to_string(),
		&mut std::io::stdout(),
	);
}

#[test]
fn test_function_hash_string() {
	use Algorithm as alg;
	use OutputOptions as opt;
	hash_string(alg::Argon2, "test", opt::Hex);
	hash_string(alg::Md5, "password", opt::Hex);
	hash_string(alg::Sha1, "password", opt::Hex);
	hash_string(alg::Sha256, "password", opt::Hex);
	hash_string(alg::Sha512, "password", opt::Hex);
	hash_string(alg::Md5, "password", opt::Base64);
	hash_string(alg::Sha1, "password", opt::Base64);
	hash_string(alg::Sha256, "password", opt::Base64);
	hash_string(alg::Sha512, "password", opt::Base64);
	hash_string(alg::Md5, "password", opt::HexBase64);
	hash_string(alg::Sha3_512, "password", opt::HexBase64);
}
#[test]
fn test_function_hash_file() {
	use Algorithm as alg;
	use OutputOptions as opt;
	hash_file(alg::Md5, "Cargo.toml", opt::Hex);
	hash_file(alg::Sha1, "Cargo.toml", opt::Hex);
	hash_file(alg::Sha256, "Cargo.toml", opt::Hex);
	hash_file(alg::Sha512, "Cargo.toml", opt::Hex);
	hash_file(alg::Md5, "Cargo.toml", opt::Base64);
	hash_file(alg::Sha1, "Cargo.toml", opt::Base64);
	hash_file(alg::Sha256, "Cargo.toml", opt::Base64);
	hash_file(alg::Sha512, "Cargo.toml", opt::Base64);
}
