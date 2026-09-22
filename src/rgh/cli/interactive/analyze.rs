// SPDX-License-Identifier: MIT OR Apache-2.0
// Project: rustgenhash

use super::common::render_compare_summary;
use crate::rgh::analyze::{compare_hashes, HashAnalyzer};
use crate::rgh::hash::compare_file_hashes;
use colored::*;
use dialoguer::Input;
use std::error::Error;

pub(crate) fn interactive_analyze_hash() -> Result<(), Box<dyn Error>> {
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

pub(crate) fn interactive_compare_hashes() -> Result<(), Box<dyn Error>> {
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

pub(crate) fn interactive_compare_file_hashes() -> Result<(), Box<dyn Error>> {
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

