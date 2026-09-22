// SPDX-License-Identifier: MIT OR Apache-2.0
// Project: rustgenhash

use crate::rgh::cli::algorithms::Algorithm;
use crate::rgh::cli::defs::{
	WEAK_PROMPT_DEFAULT_INDEX, WEAK_PROMPT_OPTIONS,
};
use crate::rgh::hash::{
	CompareDiffKind, CompareMode, CompareSummary,
};
use crate::rgh::multihash::MulticodecSupportMatrix;
use crate::rgh::output::DigestOutputFormat;
use crate::rgh::weak::{emit_warning_banner, warning_for};
use colored::*;
use dialoguer::{Password, Select};
use std::error::Error;
use strum::IntoEnumIterator;

pub(crate) fn describe_optional(value: &Option<String>) -> String {
	value
		.as_ref()
		.map(|s| s.as_str())
		.unwrap_or("<missing>")
		.to_string()
}

pub fn render_compare_summary(summary: &CompareSummary) {
	match summary.mode {
		CompareMode::Manifest => {
			println!("{}", "Mode: manifest comparison".cyan());
		}
		CompareMode::Text => {
			println!("{}", "Mode: digest list comparison".cyan());
		}
	}

	if summary.differences.is_empty() {
		let scope = summary.left_entries.max(summary.right_entries);
		match summary.mode {
			CompareMode::Manifest => println!(
				"{}",
				format!("Manifests match across {} entries.", scope)
					.green()
			),
			CompareMode::Text => println!(
				"{}",
				format!("Files match across {} lines.", scope)
					.green()
			),
		}
	} else {
		println!(
			"{}",
			format!(
				"Detected {} difference(s):",
				summary.differences.len()
			)
			.yellow()
		);
		for diff in &summary.differences {
			let message = match diff.kind {
				CompareDiffKind::Changed => format!(
					"changed: {} (expected {}, actual {})",
					diff.identifier,
					describe_optional(&diff.expected),
					describe_optional(&diff.actual)
				),
				CompareDiffKind::MissingRight => format!(
					"missing in candidate: {} (expected {})",
					diff.identifier,
					describe_optional(&diff.expected)
				),
				CompareDiffKind::MissingLeft => format!(
					"extra in candidate: {} (actual {})",
					diff.identifier,
					describe_optional(&diff.actual)
				),
			};
			println!("{}", message.red());
		}
	}

	if summary.incomplete {
		println!(
			"{}",
			format!(
				"Comparison incomplete: baseline failures {}, candidate failures {}",
				summary.left_failures, summary.right_failures
			)
			.yellow()
		);
	}

	match summary.exit_code {
		0 => println!("{}", "Comparison succeeded (exit 0).".green()),
		1 => println!("{}", "Differences detected (exit 1).".red()),
		2 => {
			println!("{}", "Comparison incomplete (exit 2).".yellow())
		}
		code => println!(
			"{}",
			format!("Comparison finished with exit {}.", code)
				.yellow()
		),
	}
}

pub(crate) fn is_password_kdf(algorithm: Algorithm) -> bool {
	matches!(
		algorithm,
		Algorithm::Argon2
			| Algorithm::Scrypt
			| Algorithm::Pbkdf2Sha256
			| Algorithm::Pbkdf2Sha512
			| Algorithm::Bcrypt
			| Algorithm::Balloon
			| Algorithm::Shacrypt
	)
}

pub(crate) fn select_digest_algorithm_label() -> Result<String, Box<dyn Error>> {
	let algorithms: Vec<Algorithm> = Algorithm::iter()
		.filter(|alg| !is_password_kdf(*alg))
		.collect();
	let labels: Vec<String> =
		algorithms.iter().map(|alg| format!("{:?}", alg)).collect();
	let selection = Select::new()
		.with_prompt("Select digest algorithm")
		.items(&labels)
		.interact()?;
	Ok(labels[selection].to_uppercase())
}

pub(crate) fn confirm_weak_algorithm_selection(
	algorithm_label: &str,
) -> Result<bool, Box<dyn Error>> {
	if let Some(message) = warning_for(algorithm_label) {
		emit_warning_banner(&message);
		let choice = Select::new()
			.with_prompt("Weak algorithm selected")
			.items(&WEAK_PROMPT_OPTIONS)
			.default(WEAK_PROMPT_DEFAULT_INDEX)
			.interact()?;
		Ok(choice == 1)
	} else {
		Ok(true)
	}
}

pub(crate) fn select_digest_algorithm_with_guard(
) -> Result<String, Box<dyn Error>> {
	loop {
		let candidate = select_digest_algorithm_label()?;
		if confirm_weak_algorithm_selection(&candidate)? {
			return Ok(candidate);
		}
	}
}

pub(crate) fn prompt_password(prompt: &str) -> Result<String, Box<dyn Error>> {
	let password = Password::new()
		.with_prompt(prompt)
		.allow_empty_password(false)
		.interact()?;
	Ok(password)
}

pub(crate) fn select_output_format() -> Result<DigestOutputFormat, Box<dyn Error>>
{
	let options = vec![
		DigestOutputFormat::Hex,
		DigestOutputFormat::Base64,
		DigestOutputFormat::Json,
		DigestOutputFormat::JsonLines,
		DigestOutputFormat::Csv,
		DigestOutputFormat::Hashcat,
		DigestOutputFormat::Multihash,
	];
	let selection = Select::new()
		.with_prompt("Select output format")
		.items(&options)
		.interact()?;

	Ok(options[selection])
}

pub(crate) fn choose_output_format_for_algorithm(
	algorithm_label: &str,
) -> Result<DigestOutputFormat, Box<dyn Error>> {
	let supported =
		MulticodecSupportMatrix::algorithm_names().join(", ");
	loop {
		let format = select_output_format()?;
		if matches!(format, DigestOutputFormat::Multihash) {
			let normalized = algorithm_label.to_ascii_lowercase();
			if MulticodecSupportMatrix::lookup(&normalized).is_none()
			{
				println!(
					"warning: multihash format is unavailable for algorithm {}. Supported combinations: {}",
					algorithm_label,
					supported
				);
				continue;
			}
			println!(
				"info: multihash tokens will be emitted as base58btc strings prefixed with 'z'."
			);
		}
		return Ok(format);
	}
}