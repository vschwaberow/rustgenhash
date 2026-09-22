// SPDX-License-Identifier: MIT OR Apache-2.0
// Project: rustgenhash

use super::common::{
	choose_output_format_for_algorithm, select_digest_algorithm_with_guard,
};
use crate::rgh::digest::commands as digest_commands;
use crate::rgh::file::{
	DirectoryHashPlan, ErrorHandlingProfile, ProgressConfig,
	ProgressMode, SymlinkPolicy, ThreadStrategy, WalkOrder,
};
use crate::rgh::hash::FileDigestOptions;
use dialoguer::{Confirm, Input, Select};
use std::error::Error;
use std::path::PathBuf;
use std::time::Duration;

pub(crate) fn interactive_digest_menu() -> Result<(), Box<dyn Error>> {
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

pub(crate) fn interactive_digest_string() -> Result<(), Box<dyn Error>> {
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

pub(crate) fn interactive_digest_file() -> Result<(), Box<dyn Error>> {
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
		mmap_threshold: None,
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

