// SPDX-License-Identifier: MIT OR Apache-2.0
// Project: rustgenhash

use crate::rgh::cli::defs::{
	WEAK_PROMPT_DEFAULT_INDEX, WEAK_PROMPT_OPTIONS,
};
use crate::rgh::cli::parser::{
	is_poly1305, mac_expected_key_length,
};
use crate::rgh::mac::commands::{run_mac, MacInput, MacOptions};
use crate::rgh::mac::key::KeySource;
use crate::rgh::mac::registry;
use colored::*;
use dialoguer::{Confirm, Input, Password, Select};
use std::error::Error;
use std::fs;
use std::path::PathBuf;
use zeroize::Zeroizing;

pub(crate) fn interactive_mac_menu() -> Result<(), Box<dyn Error>> {
    
	let metadata = registry::metadata();
	if metadata.is_empty() {
		println!(
			"{}",
			"No MAC algorithms are currently registered.".yellow()
		);
		return Ok(());
	}

	let mut last_selection = 0usize;

	loop {
		let algorithm_labels: Vec<String> = metadata
			.iter()
			.map(|meta| {
				let legacy_tag =
					if meta.is_legacy() { " ⚠ Legacy" } else { "" };
				format!(
					"{} ({}){}",
					meta.display_name, meta.identifier, legacy_tag
				)
			})
			.collect();

		let selection = Select::new()
			.with_prompt("Select MAC algorithm")
			.items(&algorithm_labels)
			.default(last_selection.min(algorithm_labels.len() - 1))
			.interact()?;
		let metadata_choice = metadata[selection];
		last_selection = selection;
		let algorithm_id = metadata_choice.identifier;
		let expected_key_len = mac_expected_key_length(algorithm_id);
		if algorithm_id.starts_with("cmac-") {
			if let Some(len) = expected_key_len {
				println!(
					"{}",
					format!(
						"{} expects an AES key of exactly {} bytes (NIST SP 800-38B).",
						metadata_choice.display_name,
						len
					)
					.yellow()
				);
			}
		}
		if is_poly1305(algorithm_id) {
			println!(
				"{}",
				"Poly1305 requires a single-use 32-byte key (RFC 8439 §2.5). Reusing the key will emit a warning.".yellow()
			);
			let proceed = Confirm::new()
				.with_prompt(
					"Confirm you will rotate this Poly1305 key after use?",
				)
				.default(true)
				.interact()?;
			if !proceed {
				println!(
					"{}",
					"Poly1305 selection cancelled; choose another algorithm or key source.".cyan()
				);
				continue;
			}
		}

		if metadata_choice.is_legacy() {
			println!(
				"{}",
				format!(
					"⚠ {} is considered legacy per NIST SP 800-131A Rev.2 §3; prefer SHA-2, SHA-3, KMAC, or BLAKE3 keyed alternatives.",
					metadata_choice.display_name
				)
				.yellow()
			);
			let decision = Select::new()
				.with_prompt("How would you like to proceed?")
				.items(&WEAK_PROMPT_OPTIONS)
				.default(WEAK_PROMPT_DEFAULT_INDEX)
				.interact()?;
			if decision == WEAK_PROMPT_DEFAULT_INDEX {
				println!("{}", "Selecting a safer algorithm.".cyan());
				continue;
			}
		}

		let key_methods =
			vec!["Read key from file", "Paste key (hidden)"];
		let key_choice = Select::new()
			.with_prompt("How should the key be provided?")
			.items(&key_methods)
			.default(0)
			.interact()?;
		let key_source = match key_choice {
			0 => {
				let path: String = Input::new()
					.with_prompt("Path to key file")
					.interact_text()?;
				let path_buf = PathBuf::from(path);
				if let Some(expected) = expected_key_len {
					match fs::metadata(&path_buf) {
						Ok(metadata) => {
							if metadata.len() != expected as u64 {
								println!(
									"{}",
									format!(
										"Key file must be {} bytes for {}; observed {} bytes.",
										expected,
										metadata_choice.display_name,
										metadata.len()
									)
									.red()
								);
								continue;
							}
						}
						Err(err) => {
							println!(
								"{}",
								format!(
									"Failed to inspect key file `{}`: {}",
									path_buf.display(),
									err
								)
								.red()
							);
							continue;
						}
					}
				}
				KeySource::File(path_buf)
			}
			1 => {
				println!(
					"{}",
					"Typed keys will not be echoed and are not stored.".yellow()
				);
				let proceed = Confirm::new()
					.with_prompt("Continue with inline key entry?")
					.default(false)
					.interact()?;
				if !proceed {
					println!(
						"{}",
						"Inline key entry cancelled; choose another key source.".cyan()
					);
					continue;
				}
				let secret = Password::new()
					.with_prompt(
						"Enter key bytes (press Enter to finish)",
					)
					.allow_empty_password(false)
					.interact()?;
				let secret_bytes = secret.into_bytes();
				if let Some(expected) = expected_key_len {
					if secret_bytes.len() != expected {
						println!(
							"{}",
							format!(
								"Inline key must be {} bytes for {}; observed {} bytes.",
								expected,
								metadata_choice.display_name,
								secret_bytes.len()
							)
							.red()
						);
						continue;
					}
				}
				KeySource::Inline(Zeroizing::new(secret_bytes))
			}
			_ => unreachable!(),
		};

		let input_options = vec!["Inline text", "File path"];
		let input_choice = Select::new()
			.with_prompt("Select MAC input source")
			.items(&input_options)
			.default(0)
			.interact()?;
		let mac_input = match input_choice {
			0 => {
				let text: String = Input::new()
					.with_prompt("Enter text to authenticate")
					.interact_text()?;
				if text.is_empty() {
					println!(
						"{}",
						"Input text cannot be empty.".red()
					);
					continue;
				}
				MacInput::Inline(text)
			}
			1 => {
				let path: String = Input::new()
					.with_prompt("Path to file to authenticate")
					.interact_text()?;
				MacInput::File(PathBuf::from(path))
			}
			_ => unreachable!(),
		};

		let output_modes =
			vec!["Digest and context", "JSON output", "Hash only"];
		let output_choice = Select::new()
			.with_prompt("Choose output mode")
			.items(&output_modes)
			.default(0)
			.interact()?;
		let (hash_only, json) = match output_choice {
			0 => (false, false),
			1 => (false, true),
			2 => (true, false),
			_ => unreachable!(),
		};

		let confirm = Confirm::new()
			.with_prompt("Compute MAC now and display the result?")
			.default(false)
			.interact()?;
		if !confirm {
			println!(
				"{}",
				"MAC computation cancelled before output.".cyan()
			);
			return Ok(());
		}

		let options = MacOptions {
			algorithm: metadata_choice.identifier.to_string(),
			key_source,
			input: mac_input,
			hash_only,
			json,
		};

		match run_mac(options) {
			Ok(_) => {
				println!("{}", "MAC computation complete.".green())
			}
			Err(err) => {
				eprintln!("error: {}", err);
			}
		}

		return Ok(());
	}
}

