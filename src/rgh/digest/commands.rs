// SPDX-License-Identifier: MIT OR Apache-2.0
// Project: rustgenhash
// Digest command handlers (string/file/stdin)

use crate::rgh::hash::{
	digest_bytes_to_record, digest_with_options,
	serialize_digest_output, FileDigestOptions,
};
use crate::rgh::multihash::MulticodecSupportMatrix;
use crate::rgh::output::{
	DigestOutputFormat, DigestSource, OutputError,
	SerializationResult,
};
use std::error::Error;
use std::io::{self, BufRead};

/// Hash a provided string using the selected digest algorithm.
pub fn digest_string(
	algorithm: &str,
	input: &str,
	format: DigestOutputFormat,
	hash_only: bool,
) -> Result<(), Box<dyn Error>> {
	let record = digest_bytes_to_record(
		algorithm,
		input.as_bytes(),
		Some(input),
		DigestSource::String,
	)
	.map_err(io::Error::other)?;
	let serialization =
		match serialize_digest_output(&[record], format, hash_only) {
			Ok(result) => result,
			Err(err) => {
				exit_on_multihash_error(&err);
				return Err(Box::new(io::Error::other(err)));
			}
		};
	emit_serialized_output(serialization);
	Ok(())
}

/// Hash a file or directory path with the selected digest algorithm.
pub fn digest_path(
	options: FileDigestOptions,
) -> Result<(), Box<dyn Error>> {
	let (outcome, serialization) = match digest_with_options(&options)
	{
		Ok(result) => result,
		Err(err) => match err.downcast::<OutputError>() {
			Ok(output_err) => {
				exit_on_multihash_error(&output_err);
				return Err(output_err);
			}
			Err(other) => return Err(other),
		},
	};
	emit_serialized_output(serialization);
	if outcome.exit_code != 0 {
		std::process::exit(outcome.exit_code);
	}
	Ok(())
}

/// Hash newline-delimited stdin using the selected digest algorithm.
pub fn digest_stdio(
	algorithm: &str,
	format: DigestOutputFormat,
	hash_only: bool,
) -> Result<(), Box<dyn Error>> {
	if matches!(format, DigestOutputFormat::Multihash)
		&& MulticodecSupportMatrix::lookup(algorithm).is_none()
	{
		eprintln!(
			"error: multihash format is unavailable for algorithm {}",
			algorithm
		);
		std::process::exit(2);
	}
	let stdin = std::io::stdin();
	let mut records = Vec::new();
	for line in stdin.lock().lines() {
		let line = line?;
		let record = digest_bytes_to_record(
			algorithm,
			line.as_bytes(),
			Some(&line),
			DigestSource::StdioLine,
		)
		.map_err(io::Error::other)?;
		records.push(record);
	}
	let serialization =
		match serialize_digest_output(&records, format, hash_only) {
			Ok(result) => result,
			Err(err) => {
				exit_on_multihash_error(&err);
				return Err(Box::new(io::Error::other(err)));
			}
		};
	emit_serialized_output(serialization);
	Ok(())
}

fn emit_serialized_output(result: SerializationResult) {
	for warning in result.warnings {
		eprintln!("warning: {}", warning);
	}

	for line in result.lines {
		println!("{}", line);
	}
}

fn exit_on_multihash_error(err: &OutputError) {
	if let Some(multihash_err) = err.multihash() {
		eprintln!("error: {}", multihash_err);
		std::process::exit(2);
	}
}
