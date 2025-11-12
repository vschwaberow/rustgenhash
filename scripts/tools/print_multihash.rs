// SPDX-License-Identifier: MIT OR Apache-2.0
// Utility: Convert a raw digest into a base58btc multihash token.
// Usage: cargo run --bin print_multihash -- [--algorithm sha256] <hex-digest>

use rustgenhash::rgh::multihash::{
	MulticodecSupportMatrix, MultihashEncoder,
};
use std::env;
use std::process;

fn print_usage_and_exit() -> ! {
	eprintln!(
        "Usage: print_multihash [--algorithm <name>] <hex-digest>\n       Supported algorithms: {}",
        MulticodecSupportMatrix::algorithm_names().join(", ")
    );
	process::exit(64);
}

fn main() {
	let mut args = env::args().skip(1);
	let mut algorithm = "sha256".to_string();
	let mut digest_hex: Option<String> = None;

	while let Some(arg) = args.next() {
		match arg.as_str() {
			"--algorithm" | "--alg" | "-a" => {
				let Some(value) = args.next() else {
					eprintln!("error: --algorithm requires a value");
					print_usage_and_exit();
				};
				algorithm = value.to_ascii_lowercase();
			}
			"--help" | "-h" => {
				print_usage_and_exit();
			}
			other if other.starts_with('-') => {
				eprintln!("error: unrecognized argument `{}`", other);
				print_usage_and_exit();
			}
			value => {
				digest_hex = Some(value.to_string());
				break;
			}
		}
	}

	let Some(digest_hex) = digest_hex else {
		eprintln!("error: missing hex digest");
		print_usage_and_exit();
	};

	if args.next().is_some() {
		eprintln!("error: unexpected extra arguments");
		print_usage_and_exit();
	}

	let digest_bytes = match hex::decode(digest_hex.trim()) {
		Ok(bytes) => bytes,
		Err(err) => {
			eprintln!("error: invalid hex digest: {}", err);
			process::exit(65);
		}
	};

	match MultihashEncoder::encode(&algorithm, &digest_bytes) {
		Ok(token) => {
			println!("Algorithm: {}", algorithm);
			println!("Digest bytes: {}", digest_bytes.len());
			println!("Multihash: {}", token);
		}
		Err(err) => {
			eprintln!("error: {}", err);
			process::exit(66);
		}
	}
}
