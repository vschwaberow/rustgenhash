// SPDX-License-Identifier: MIT OR Apache-2.0
// Project: rustgenhash
// File: audit.rs
// Author: Volker Schwaberow <volker@schwaberow.de>

use std::env;
use std::path::PathBuf;

use rustgenhash::rgh::audit::{
	collect_fixture_paths, compute_run_metadata, execute_cases,
	load_fixture, write_reports, AuditCase, AuditStatus,
};

fn requested_case() -> Option<String> {
	let mut args = env::args().skip(1);
	while let Some(arg) = args.next() {
		if arg == "--case" {
			return args.next();
		}
	}
	None
}

fn load_all(paths: &[PathBuf]) -> Vec<AuditCase> {
	paths
		.iter()
		.map(|path| {
			load_fixture(path).unwrap_or_else(|err| {
				panic!(
					"Failed to load fixture {}: {err}",
					path.display()
				)
			})
		})
		.collect()
}

#[test]
fn audit_fixtures_smoke() {
	let requested = requested_case();
	let fixture_paths = collect_fixture_paths(requested.as_deref())
		.expect("Failed to discover fixture paths");
	let selected: Vec<PathBuf> = fixture_paths;

	assert!(
		!selected.is_empty(),
		"No fixtures found for selection {:?}",
		requested
	);

	let cases = load_all(&selected);
	assert_eq!(
		cases.len(),
		selected.len(),
		"Failed to load fixtures"
	);

	let required_cases = [
		"mac_cmac_aes128_string",
		"mac_cmac_aes256_file",
		"mac_poly1305_stdio",
		"mac_poly1305_key_error",
		"kdf_hkdf_blake3_basic",
		"kdf_hkdf_expand_only",
		"kdf_pbkdf2_profile_nist_sp800132",
		"kdf_scrypt_profile_owasp",
	];
	for required in required_cases {
		assert!(
			cases.iter().any(|case| case.id == required),
			"Required CMAC fixture `{}` missing from audit registry",
			required
		);
	}

	let outcomes =
		execute_cases(cases).expect("Failed to execute audit cases");
	let metadata = compute_run_metadata(&outcomes);
	write_reports(&metadata, &outcomes)
		.expect("Failed to write audit reports");

	let failures: Vec<_> = outcomes
		.iter()
		.filter(|outcome| outcome.status == AuditStatus::Fail)
		.collect();

	if !failures.is_empty() {
		for failure in &failures {
			eprintln!(
                "Fixture {} (severity {:?}) failed. Notes: {}. Details: {}",
                failure.case.id,
                failure.case.metadata.severity,
                failure
                    .case
                    .metadata
                    .notes
                    .as_deref()
                    .unwrap_or("n/a"),
                failure
                    .message
                    .as_deref()
                    .unwrap_or("no additional context")
            );
		}
		panic!("{} audit fixtures failed", failures.len());
	}

	let passes = outcomes
		.iter()
		.filter(|outcome| outcome.status == AuditStatus::Pass)
		.count();

	assert!(passes > 0, "Audit produced zero passing fixtures");
}
