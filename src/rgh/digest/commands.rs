// SPDX-License-Identifier: MIT OR Apache-2.0
// Project: rustgenhash
// Digest command handlers (string/file/stdin)

#![allow(dead_code)]

use crate::rgh::app::OutputOptions;
use crate::rgh::hash::{
	digest_bytes_to_string, digest_with_options, FileDigestOptions,
};
use std::error::Error;
use std::io::{self, BufRead};

/// Hash a provided string using the selected digest algorithm.
pub fn digest_string(
	algorithm: &str,
	input: &str,
	output: OutputOptions,
	hash_only: bool,
) -> Result<(), Box<dyn Error>> {
	let formatted = digest_bytes_to_string(
		algorithm,
		input.as_bytes(),
		output,
		hash_only,
		Some(input),
	)
	.map_err(io::Error::other)?;
	println!("{}", formatted);
	Ok(())
}

/// Hash a file or directory path with the selected digest algorithm.
pub fn digest_path(
	options: FileDigestOptions,
) -> Result<(), Box<dyn Error>> {
	let outcome = digest_with_options(&options)?;
	if outcome.exit_code != 0 {
		std::process::exit(outcome.exit_code);
	}
	Ok(())
}

/// Hash newline-delimited stdin using the selected digest algorithm.
pub fn digest_stdio(
	algorithm: &str,
	output: OutputOptions,
	hash_only: bool,
) -> Result<(), Box<dyn Error>> {
	let stdin = std::io::stdin();
	for line in stdin.lock().lines() {
		let line = line?;
		let formatted = digest_bytes_to_string(
			algorithm,
			line.as_bytes(),
			output,
			hash_only,
			Some(&line),
		)
		.map_err(io::Error::other)?;
		println!("{}", formatted);
	}
	Ok(())
}
