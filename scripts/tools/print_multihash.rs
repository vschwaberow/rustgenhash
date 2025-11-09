// SPDX-License-Identifier: MIT OR Apache-2.0
// Project: rustgenhash
// File: print_multihash.rs
// Author: Volker Schwaberow <volker@schwaberow.de>
// Copyright (c) 2022 Volker Schwaberow
// Helper binary to emit multibase multihash tokens for fixture generation.

use clap::{Parser, ValueEnum};
use rustgenhash::rgh::{
	hash::{digest_bytes_to_record, serialize_digest_output},
	output::{DigestOutputFormat, DigestSource},
};
use std::io;

#[derive(ValueEnum, Clone, Copy, Debug)]
enum InputType {
	Literal,
	File,
}

#[derive(Parser, Debug)]
#[command(
	author,
	version,
	about = "Generate multihash tokens for fixture scaffolding"
)]
struct Args {
	/// Digest algorithm identifier (e.g. sha256)
	#[arg(short, long)]
	algorithm: String,
	/// Input source type (literal string or file path)
	#[arg(short = 't', long, value_enum)]
	input_type: InputType,
	/// Value for the chosen input type (string literal or file path)
	#[arg(short, long)]
	value: String,
	/// Emit hash-only output (no original label)
	#[arg(long, default_value_t = false)]
	hash_only: bool,
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
	let args = Args::parse();
	let bytes = match args.input_type {
		InputType::Literal => args.value.as_bytes().to_vec(),
		InputType::File => std::fs::read(&args.value)?,
	};

	let label = if args.hash_only {
		None
	} else {
		Some(match args.input_type {
			InputType::Literal => args.value.as_str(),
			InputType::File => args.value.as_str(),
		})
	};

	let record = digest_bytes_to_record(
		&args.algorithm,
		&bytes,
		label,
		DigestSource::String,
	)
	.map_err(io::Error::other)?;

	let result = serialize_digest_output(
		&[record],
		DigestOutputFormat::Multihash,
		args.hash_only,
	)
	.map_err(io::Error::other)?;

	for line in result.lines {
		println!("{}", line);
	}

	Ok(())
}
