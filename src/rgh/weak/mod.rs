// SPDX-License-Identifier: MIT OR Apache-2.0
// Project: rustgenhash
// Module: weak algorithm warnings helper
// Author: Volker Schwaberow <volker@schwaberow.de>
// Copyright (c) 2025 Volker Schwaberow

//! Helpers for identifying compromised/weak digest algorithms and presenting
//! consistent warning banners across CLI modes.

use colored::Colorize;

const NIST_REFERENCE: &str =
	"https://doi.org/10.6028/NIST.SP.800-131Ar2";
const BSI_REFERENCE: &str =
    "https://www.bsi.bund.de/SharedDocs/Downloads/EN/BSI/Publications/TechGuidelines/TG02102/BSI-TR-02102-1.pdf";

const REFERENCES: &[&str] = &[NIST_REFERENCE, BSI_REFERENCE];

/// Metadata describing a weak algorithm entry in the registry.
#[derive(Debug, Clone)]
pub struct WeakAlgorithmMetadata {
	/// Canonical lowercase identifier used by CLI flags (e.g., "md5").
	pub algorithm_id: &'static str,
	/// Human-friendly display name shown in warning headings.
	pub display_name: &'static str,
	/// Replacement suggestion shown to the user (e.g., "Use SHA-256").
	pub replacement_hint: &'static str,
}

/// Warning banner content emitted to stderr when a weak algorithm is used.
#[derive(Debug, Clone)]
pub struct WarningMessage {
	pub severity_icon: &'static str,
	pub headline: String,
	pub body: String,
	pub references: &'static [&'static str],
}

impl WarningMessage {
	/// Returns the banner text as displayed on stderr.
	pub fn banner(&self) -> String {
		format!(
			"{} {} {}",
			self.severity_icon, self.headline, self.body
		)
	}
}

const WEAK_ALGORITHMS: &[WeakAlgorithmMetadata] = &[
	WeakAlgorithmMetadata {
		algorithm_id: "md5",
		display_name: "MD5",
		replacement_hint: "Use SHA-256 or BLAKE3 for new digests",
	},
	WeakAlgorithmMetadata {
		algorithm_id: "sha1",
		display_name: "SHA-1",
		replacement_hint: "Use SHA-256 or SHA-512",
	},
	WeakAlgorithmMetadata {
		algorithm_id: "sha224",
		display_name: "SHA-224",
		replacement_hint: "Use SHA-256 or SHA-512",
	},
];

/// Returns registry metadata for a given algorithm identifier.
pub fn metadata_for(
	algorithm: &str,
) -> Option<&'static WeakAlgorithmMetadata> {
	let needle = algorithm.to_ascii_lowercase();
	WEAK_ALGORITHMS
		.iter()
		.find(|entry| entry.algorithm_id == needle)
}

/// Returns warning banner content for known weak algorithms.
pub fn warning_for(algorithm: &str) -> Option<WarningMessage> {
	let metadata = metadata_for(algorithm)?;
	let headline = format!(
		"WARNING: {} is a weak algorithm (collisions known)",
		metadata.display_name
	);
	let body = format!(
		"See NIST SP 800-131A rev.2 §3 and BSI TR-02102-1 recommendations. {}.",
		metadata.replacement_hint
	);
	Some(WarningMessage {
		severity_icon: "⚠",
		headline,
		body,
		references: REFERENCES,
	})
}

/// Returns the list of known weak algorithms for documentation/help output.
pub fn all_metadata() -> &'static [WeakAlgorithmMetadata] {
	WEAK_ALGORITHMS
}

/// Emit the warning banner and supporting references to stderr using ANSI
/// highlighting when the terminal supports it.
pub fn emit_warning_banner(message: &WarningMessage) {
	let banner = message.banner();
	let references = message.references.join(" | ");
	let colored_banner = banner.yellow().bold();
	let references_line =
		format!("References: {}", references).yellow();
	eprintln!("{}", colored_banner);
	eprintln!("{}", references_line);
}
