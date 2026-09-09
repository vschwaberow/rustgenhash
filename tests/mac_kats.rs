// SPDX-License-Identifier: MIT OR Apache-2.0
// Project: rustgenhash

use rustgenhash::rgh::mac::executor::{consume_bytes, digest_to_hex};
use rustgenhash::rgh::mac::registry;
use serde::Deserialize;
use std::collections::HashSet;
use std::fs;
use std::path::{Path, PathBuf};

#[derive(Debug, Deserialize)]
struct KatSource {
	title: String,
	url: String,
}

#[derive(Debug, Deserialize)]
struct KatInput {
	encoding: String,
	value: String,
}

#[derive(Debug, Deserialize)]
struct KatKey {
	path: String,
}

#[derive(Debug, Deserialize)]
struct KatFixture {
	algorithm: String,
	key: KatKey,
	input: KatInput,
	expected_hex: String,
	source: KatSource,
}

fn kats_dir() -> PathBuf {
	PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/mac/kats")
}

fn load_fixtures() -> Vec<(PathBuf, KatFixture)> {
	let mut entries = Vec::new();
	for entry in fs::read_dir(kats_dir()).expect("mac kats directory") {
		let entry = entry.expect("dir entry");
		let path = entry.path();
		if path.extension().and_then(|ext| ext.to_str()) != Some("json") {
			continue;
		}
		let raw = fs::read_to_string(&path).unwrap_or_else(|err| {
			panic!("read {}: {err}", path.display());
		});
		let fixture: KatFixture = serde_json::from_str(&raw).unwrap_or_else(|err| {
			panic!("parse {}: {err}", path.display());
		});
		assert!(
			!fixture.source.title.is_empty() && !fixture.source.url.is_empty(),
			"{} missing source citation",
			path.display()
		);
		entries.push((path, fixture));
	}
	entries.sort_by(|a, b| a.0.cmp(&b.0));
	assert!(!entries.is_empty(), "no MAC KAT fixtures found");
	entries
}

fn input_bytes(input: &KatInput) -> Vec<u8> {
	match input.encoding.as_str() {
		"utf8" => input.value.as_bytes().to_vec(),
		"hex" => hex::decode(&input.value).expect("hex input"),
		other => panic!("unsupported input encoding `{other}`"),
	}
}

fn resolve_key(path: &str) -> Vec<u8> {
	let full = if Path::new(path).is_absolute() {
		PathBuf::from(path)
	} else {
		PathBuf::from(env!("CARGO_MANIFEST_DIR")).join(path)
	};
	fs::read(&full).unwrap_or_else(|err| panic!("read key {}: {err}", full.display()))
}

#[test]
fn published_mac_kats_match_registry_executors() {
	for (path, fixture) in load_fixtures() {
		let key = resolve_key(&fixture.key.path);
		let data = input_bytes(&fixture.input);
		let (executor, _) = registry::create_executor(&fixture.algorithm, &key)
			.unwrap_or_else(|err| {
				panic!(
					"create_executor({}) failed for {}: {}",
					fixture.algorithm,
					path.display(),
					err
				);
			});
		let actual = digest_to_hex(&consume_bytes(&data, executor));
		assert_eq!(
			actual, fixture.expected_hex,
			"MAC KAT mismatch for {} ({})",
			fixture.algorithm,
			path.display()
		);
	}
}

#[test]
fn every_registry_mac_has_a_published_kat() {
	let covered: HashSet<String> = load_fixtures()
		.into_iter()
		.map(|(_, fixture)| fixture.algorithm)
		.collect();
	for alg in registry::algorithms() {
		assert!(
			covered.contains(alg.metadata.identifier),
			"missing MAC KAT for {}",
			alg.metadata.identifier
		);
	}
}

#[test]
fn mac_kat_fixtures_have_no_orphan_algorithms() {
	let known: HashSet<&str> = registry::algorithms()
		.map(|alg| alg.metadata.identifier)
		.collect();
	for (path, fixture) in load_fixtures() {
		assert!(
			known.contains(fixture.algorithm.as_str()),
			"orphan MAC KAT {} in {}",
			fixture.algorithm,
			path.display()
		);
	}
}
