// SPDX-License-Identifier: MIT OR Apache-2.0
// Project: rustgenhash
// File: commands.rs
// Author: Volker Schwaberow <volker@schwaberow.de>

//! CLI dispatch for `rgh mac`.

use crate::rgh::mac::executor::{
	consume_bytes, consume_reader, digest_to_hex,
};
use crate::rgh::mac::key::{load_key, KeySource};
use crate::rgh::mac::poly1305::Poly1305ReuseTracker;
use crate::rgh::mac::registry::{
	self, MacAlgorithmMetadata, MacExecutor,
};
use serde_json::json;
use std::error::Error;
use std::fs::File;
use std::io::{self, BufRead};
use std::path::PathBuf;
use zeroize::Zeroize;

#[derive(Debug)]
pub struct MacOptions {
	pub algorithm: String,
	pub key_source: KeySource,
	pub input: MacInput,
	pub hash_only: bool,
	pub json: bool,
}

#[derive(Debug)]
pub enum MacInput {
	Inline(String),
	File(PathBuf),
	Stdin,
}

pub fn run_mac(options: MacOptions) -> Result<(), Box<dyn Error>> {
	let mut key = load_key(&options.key_source)
		.map_err(|err| Box::new(err) as Box<dyn Error>)?;
	let mut poly1305_tracker =
		if options.algorithm.eq_ignore_ascii_case("poly1305") {
			Some(Poly1305ReuseTracker::default())
		} else {
			None
		};

	let result = match &options.input {
		MacInput::Inline(text) => {
			if let Some(tracker) = poly1305_tracker.as_mut() {
				if let Some(warning) = tracker.check_reuse(&key) {
					eprintln!("{}", warning);
				}
			}
			let (executor, metadata) =
				create_executor(&options.algorithm, &key)?;
			print_legacy_banner(&metadata);
			let digest = consume_bytes(text.as_bytes(), executor);
			emit_output(
				&options,
				&metadata,
				MacOutput::Inline(text),
				&digest,
			)
		}
		MacInput::File(path) => {
			let file = File::open(path).map_err(|err| {
				Box::new(io::Error::other(format!(
					"failed to open `{}`: {}",
					path.display(),
					err
				))) as Box<dyn Error>
			})?;
			if let Some(tracker) = poly1305_tracker.as_mut() {
				if let Some(warning) = tracker.check_reuse(&key) {
					eprintln!("{}", warning);
				}
			}
			let (executor, metadata) =
				create_executor(&options.algorithm, &key)?;
			print_legacy_banner(&metadata);
			let digest = consume_reader(file, executor)
				.map_err(|err| Box::new(err) as Box<dyn Error>)?;
			emit_output(
				&options,
				&metadata,
				MacOutput::File(path),
				&digest,
			)
		}
		MacInput::Stdin => {
			let mut warned_blank = false;
			let mut legacy_printed = false;
			let stdin = io::stdin();
			for line_result in stdin.lock().lines() {
				let line = line_result
					.map_err(|err| Box::new(err) as Box<dyn Error>)?;
				if line.is_empty() {
					if !warned_blank {
						eprintln!(
							"warning: skipping empty stdin line"
						);
						warned_blank = true;
					}
					continue;
				}
				if let Some(tracker) = poly1305_tracker.as_mut() {
					if let Some(warning) = tracker.check_reuse(&key) {
						eprintln!("{}", warning);
					}
				}
				let (executor, metadata) =
					create_executor(&options.algorithm, &key)?;
				if !legacy_printed {
					print_legacy_banner(&metadata);
					legacy_printed = true;
				}
				let digest = consume_bytes(line.as_bytes(), executor);
				emit_output(
					&options,
					&metadata,
					MacOutput::StdinLine(&line),
					&digest,
				)?;
			}
			Ok(())
		}
	};

	key.zeroize();
	result
}

enum MacOutput<'a> {
	Inline(&'a str),
	File(&'a PathBuf),
	StdinLine(&'a str),
}

pub fn legacy_warning_message(
	metadata: &MacAlgorithmMetadata,
) -> String {
	format!(
		"warning: {} is considered legacy per NIST SP 800-131A Rev.2 §3; prefer SHA-2, SHA-3, KMAC, or BLAKE3 keyed alternatives",
		metadata.display_name
	)
}

fn print_legacy_banner(metadata: &MacAlgorithmMetadata) {
	if metadata.is_legacy() {
		eprintln!("{}", legacy_warning_message(metadata));
	}
}

fn emit_output(
	options: &MacOptions,
	metadata: &MacAlgorithmMetadata,
	context: MacOutput,
	digest: &[u8],
) -> Result<(), Box<dyn Error>> {
	let hex = digest_to_hex(digest);

	if options.hash_only {
		println!("{}", hex);
		return Ok(());
	}

	if options.json {
		let input_value = match &context {
			MacOutput::Inline(text) => {
				json!({ "type": "inline", "value": text })
			}
			MacOutput::File(path) => {
				json!({ "type": "file", "value": path.display().to_string() })
			}
			MacOutput::StdinLine(line) => {
				json!({ "type": "stdin", "value": line })
			}
		};
		let payload = json!({
			"algorithm": metadata.identifier,
			"display_name": metadata.display_name,
			"legacy": metadata.is_legacy(),
			"digest": hex,
			"input": input_value,
			"key_source": options.key_source.description(),
		});
		println!("{}", payload);
	} else {
		match &context {
			MacOutput::Inline(text) => println!("{} {}", hex, text),
			MacOutput::File(path) => {
				println!("{} {}", hex, path.display())
			}
			MacOutput::StdinLine(line) => {
				println!("{} {}", hex, line)
			}
		};
	}

	Ok(())
}

fn create_executor(
	algorithm: &str,
	key: &[u8],
) -> Result<
	(Box<dyn MacExecutor>, MacAlgorithmMetadata),
	Box<dyn Error>,
> {
	registry::create_executor(algorithm, key)
		.map_err(|err| Box::new(err) as Box<dyn Error>)
}
