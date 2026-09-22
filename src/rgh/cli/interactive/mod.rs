// SPDX-License-Identifier: MIT OR Apache-2.0
// Project: rustgenhash

mod analyze;
mod common;
mod digest;
mod kdf;
mod mac;
mod misc;

pub use common::render_compare_summary;

use analyze::{
	interactive_analyze_hash, interactive_compare_file_hashes,
	interactive_compare_hashes,
};
use digest::interactive_digest_menu;
use kdf::interactive_kdf_menu;
use mac::interactive_mac_menu;
use misc::{
	interactive_generate_hhhash, interactive_generate_random,
	interactive_run_benchmarks,
};
use colored::*;
use dialoguer::Select;
use std::error::Error;

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

