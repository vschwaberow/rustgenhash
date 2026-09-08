// SPDX-License-Identifier: MIT OR Apache-2.0
// Project: rustgenhash

use rustgenhash::rgh::hash::{DIGEST_ALGORITHMS, RHash};
use serde::Deserialize;
use std::collections::HashSet;
use std::fs;
use std::path::PathBuf;

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
struct KatFixture {
	algorithm: String,
	input: KatInput,
	expected_hex: String,
	source: KatSource,
}

fn kats_dir() -> PathBuf {
	PathBuf::from(env!("CARGO_MANIFEST_DIR"))
		.join("tests/fixtures/digest/kats")
}

fn load_fixtures() -> Vec<(PathBuf, KatFixture)> {
	let mut entries = Vec::new();
	for entry in fs::read_dir(kats_dir()).expect("kats directory") {
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
	assert!(!entries.is_empty(), "no digest KAT fixtures found");
	entries
}

fn input_bytes(input: &KatInput) -> Vec<u8> {
	match input.encoding.as_str() {
		"utf8" => input.value.as_bytes().to_vec(),
		"hex" => hex::decode(&input.value).unwrap_or_else(|err| {
			panic!("hex decode failed: {err}");
		}),
		other => panic!("unsupported input encoding `{other}`"),
	}
}

fn digest_hex(algorithm: &str, data: &[u8]) -> String {
	let mut hasher = RHash::new(algorithm).unwrap_or_else(|err| {
		panic!("RHash::new({algorithm}) failed: {err}");
	});
	hex::encode(hasher.process_string(data))
}

#[test]
fn published_kats_match_rhash() {
	for (path, fixture) in load_fixtures() {
		let data = input_bytes(&fixture.input);
		let actual = digest_hex(&fixture.algorithm, &data);
		assert_eq!(
			actual, fixture.expected_hex,
			"KAT mismatch for {} ({})",
			fixture.algorithm,
			path.display()
		);
		assert_eq!(
			fixture.expected_hex.len() % 2,
			0,
			"odd hex length in {}",
			path.display()
		);
		let expected_len = fixture.expected_hex.len() / 2;
		let registry_len = DIGEST_ALGORITHMS
			.iter()
			.find(|algo| algo.id == fixture.algorithm)
			.map(|algo| algo.output_len);
		assert_eq!(
			registry_len,
			Some(expected_len),
			"{} output length vs registry ({})",
			fixture.algorithm,
			path.display()
		);
	}
}

#[test]
fn every_registry_algorithm_has_a_published_kat() {
	let covered: HashSet<String> = load_fixtures()
		.into_iter()
		.map(|(_, fixture)| fixture.algorithm)
		.collect();
	for algo in DIGEST_ALGORITHMS {
		assert!(
			covered.contains(algo.id),
			"missing published KAT fixture for {}",
			algo.id
		);
	}
}

#[test]
fn kat_fixtures_have_no_orphan_algorithms() {
	let known: HashSet<&str> = DIGEST_ALGORITHMS.iter().map(|algo| algo.id).collect();
	for (path, fixture) in load_fixtures() {
		assert!(
			known.contains(fixture.algorithm.as_str()),
			"orphan KAT algorithm {} in {}",
			fixture.algorithm,
			path.display()
		);
	}
}
