// SPDX-License-Identifier: MIT OR Apache-2.0
// Project: rustgenhash
// File: app/digest.rs

use crate::rgh::cli::parser::{
	build_progress_config, parse_error_strategy, parse_mmap_threshold,
	parse_symlink_policy, parse_thread_strategy,
};
use crate::rgh::digest::commands as digest_commands;
use crate::rgh::file::{
	DirectoryHashPlan, ErrorHandlingProfile, WalkOrder,
};
use crate::rgh::output::DigestOutputFormat;
use std::error::Error;
use std::io;
use std::path::PathBuf;

pub(crate) fn handle_digest_command(
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
				.unwrap_or("off");
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

