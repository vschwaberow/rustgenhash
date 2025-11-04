// SPDX-License-Identifier: MIT OR Apache-2.0
// Project: rustgenhash
// Module: weak algorithm warnings helper
// Author: Volker Schwaberow <volker@schwaberow.de>
// Copyright (c) 2025 Volker Schwaberow
//! Helpers for identifying compromised/weak digest algorithms and presenting
use rustgenhash::rgh::app::{
    WEAK_PROMPT_DEFAULT_INDEX, WEAK_PROMPT_OPTIONS,
};
use rustgenhash::rgh::weak::{
    all_metadata, metadata_for, warning_for,
};
use std::process::Command;

#[test]
fn metadata_lists_expected_algorithms() {
	let ids: Vec<&str> = all_metadata()
		.iter()
		.map(|meta| meta.algorithm_id)
		.collect();
	assert!(ids.contains(&"md5"));
	assert!(ids.contains(&"sha1"));
	assert!(ids.contains(&"sha224"));
}

#[test]
fn warning_for_returns_expected_banner() {
    let warning = warning_for("MD5").expect("md5 should be weak");
    assert!(warning.headline.contains("MD5"));
    assert!(warning.body.contains("NIST SP 800-131A"));
    assert!(warning.body.contains("ENISA"));
    assert!(warning.body.contains("BSI"));
    // References should include both citation URLs.
    assert!(warning.references.iter().any(|r| r.contains("NIST")));
    assert!(warning.references.iter().any(|r| r.contains("enisa")));
    assert!(warning.references.iter().any(|r| r.contains("bsi")));

	// Non-weak algorithm returns None.
	assert!(warning_for("sha256").is_none());
	assert!(metadata_for("sha256").is_none());
}

#[test]
fn cli_digest_string_emits_single_warning_banner(
) -> Result<(), Box<dyn std::error::Error>> {
	let mut cmd = Command::new(assert_cmd::cargo::cargo_bin!("rgh"));
	cmd.env("NO_COLOR", "1")
		.args(["digest", "string", "-a", "md5", "secret"]);
	let output = cmd.output()?;
	assert!(output.status.success());
	let stderr = String::from_utf8_lossy(&output.stderr);
	let warning_lines: Vec<_> = stderr
		.lines()
		.filter(|line| line.contains("weak algorithm"))
		.collect();
	assert_eq!(
		warning_lines.len(),
		1,
		"expected single warning banner, got `{}`",
		stderr
	);
	let reference_lines: Vec<_> = stderr
		.lines()
		.filter(|line| line.starts_with("References:"))
		.collect();
	assert_eq!(
		reference_lines.len(),
		1,
		"expected single references line, got `{}`",
		stderr
	);
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("secret"));
    Ok(())
}

#[test]
fn interactive_prompt_defaults_are_safe() {
    assert_eq!(WEAK_PROMPT_DEFAULT_INDEX, 0);
    assert_eq!(WEAK_PROMPT_OPTIONS[0], "Choose safer algorithm");
    assert_eq!(WEAK_PROMPT_OPTIONS[1], "Continue anyway");
}
