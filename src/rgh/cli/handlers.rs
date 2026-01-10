// SPDX-License-Identifier: MIT OR Apache-2.0
// Project: rustgenhash

use crate::rgh::cli::algorithms::Algorithm;
use crate::rgh::digest::commands as digest_commands;
use crate::rgh::file::{
	DirectoryHashPlan, ErrorHandlingProfile, ProgressConfig,
	ProgressMode, SymlinkPolicy, ThreadStrategy, WalkOrder,
};
use crate::rgh::hash::{
	digest_bytes_to_record, serialize_digest_output, Argon2Config,
	BalloonConfig, BcryptConfig, FileDigestOptions, PHash,
	Pbkdf2Config, ScryptConfig,
};
use crate::rgh::output::{
	DigestOutputFormat, DigestSource, SerializationResult,
};
use std::path::PathBuf;
use std::time::Duration;

pub struct HashConfigs<'a> {
	pub argon2: &'a Argon2Config,
	pub scrypt: &'a ScryptConfig,
	pub bcrypt: &'a BcryptConfig,
	pub pbkdf2: &'a Pbkdf2Config,
	pub balloon: &'a BalloonConfig,
}

pub fn hash_string(
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

pub fn hash_digest_output(
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

pub fn hash_file(
	alg: Algorithm,
	input: &str,
	format: DigestOutputFormat,
	hash_only: bool,
) {
	if !alg.supports_file_hashing() {
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

pub fn emit_serialization_to_stdout(result: SerializationResult) {
	for warning in result.warnings {
		eprintln!("warning: {}", warning);
	}
	for line in result.lines {
		println!("{}", line);
	}
}
