// SPDX-License-Identifier: MIT OR Apache-2.0
// Project: rustgenhash

use base64::{engine::general_purpose::STANDARD_NO_PAD, Engine};
use rustgenhash::rgh::hash::{
	Argon2Config, BalloonConfig, BcryptConfig, PHash, Pbkdf2Config,
	ScryptConfig,
};
use rustgenhash::rgh::kdf::hkdf::{
	derive, HkdfAlgorithm, HkdfInput, HkdfMode, HkdfRequest, HkdfVariant,
};
use rustgenhash::rgh::kdf::{SecretMaterial, KDF_ALGORITHM_IDS};
use serde::Deserialize;
use std::collections::HashSet;
use std::fs;
use std::path::PathBuf;
use std::str::FromStr;

#[derive(Debug, Deserialize)]
struct KatSource {
	title: String,
	url: String,
}

#[derive(Debug, Deserialize)]
struct KatBytes {
	encoding: String,
	value: String,
}

#[derive(Debug, Deserialize)]
struct KatParams {
	mem_cost: Option<u32>,
	time_cost: Option<u32>,
	parallelism: Option<u32>,
	log_n: Option<u8>,
	r: Option<u32>,
	p: Option<u32>,
	cost: Option<u32>,
	rounds: Option<u32>,
	output_length: Option<usize>,
	memory_cost: Option<u32>,
	length: Option<usize>,
}

#[derive(Debug, Deserialize)]
struct KatFixture {
	algorithm: String,
	password: Option<KatBytes>,
	salt: Option<KatBytes>,
	ikm: Option<KatBytes>,
	info: Option<KatBytes>,
	params: Option<KatParams>,
	expected: String,
	source: KatSource,
}

fn kats_dir() -> PathBuf {
	PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/kdf/kats")
}

fn load_fixtures() -> Vec<(PathBuf, KatFixture)> {
	let mut entries = Vec::new();
	for entry in fs::read_dir(kats_dir()).expect("kdf kats directory") {
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
	assert!(!entries.is_empty(), "no KDF KAT fixtures found");
	entries
}

fn decode_bytes(label: &str, input: &KatBytes) -> Vec<u8> {
	match input.encoding.as_str() {
		"utf8" => input.value.as_bytes().to_vec(),
		"hex" => hex::decode(&input.value)
			.unwrap_or_else(|err| panic!("{label} hex: {err}")),
		other => panic!("unsupported {label} encoding `{other}`"),
	}
}

fn salt_b64(salt: &KatBytes) -> String {
	STANDARD_NO_PAD.encode(decode_bytes("salt", salt))
}

fn password_str(password: &KatBytes) -> String {
	String::from_utf8(decode_bytes("password", password))
		.expect("password utf8")
}

fn derive_kat(fixture: &KatFixture) -> String {
	let params = fixture.params.as_ref();
	match fixture.algorithm.as_str() {
		"argon2" => PHash::hash_argon2_with_salt(
			&password_str(fixture.password.as_ref().expect("password")),
			&Argon2Config {
				mem_cost: params.and_then(|p| p.mem_cost).unwrap_or(4096),
				time_cost: params.and_then(|p| p.time_cost).unwrap_or(1),
				parallelism: params.and_then(|p| p.parallelism).unwrap_or(1),
			},
			&salt_b64(fixture.salt.as_ref().expect("salt")),
		)
		.expect("argon2"),
		"scrypt" => PHash::hash_scrypt_with_salt(
			&password_str(fixture.password.as_ref().expect("password")),
			&ScryptConfig {
				log_n: params.and_then(|p| p.log_n).unwrap_or(14),
				r: params.and_then(|p| p.r).unwrap_or(8),
				p: params.and_then(|p| p.p).unwrap_or(1),
			},
			&salt_b64(fixture.salt.as_ref().expect("salt")),
		)
		.expect("scrypt"),
		"bcrypt" => PHash::hash_bcrypt_with_salt(
			&password_str(fixture.password.as_ref().expect("password")),
			&BcryptConfig {
				cost: params.and_then(|p| p.cost).unwrap_or(4),
			},
			&salt_b64(fixture.salt.as_ref().expect("salt")),
		)
		.expect("bcrypt"),
		"balloon" => PHash::hash_balloon_with_salt(
			&password_str(fixture.password.as_ref().expect("password")),
			&BalloonConfig {
				time_cost: params.and_then(|p| p.time_cost).unwrap_or(1),
				memory_cost: params.and_then(|p| p.memory_cost).unwrap_or(1024),
				parallelism: params.and_then(|p| p.parallelism).unwrap_or(1),
			},
			&salt_b64(fixture.salt.as_ref().expect("salt")),
		)
		.expect("balloon"),
		"pbkdf2-sha256" => PHash::hash_pbkdf2_with_salt(
			&password_str(fixture.password.as_ref().expect("password")),
			"pbkdf2sha256",
			&Pbkdf2Config {
				rounds: params.and_then(|p| p.rounds).unwrap_or(1000),
				output_length: params.and_then(|p| p.output_length).unwrap_or(32),
			},
			&salt_b64(fixture.salt.as_ref().expect("salt")),
		)
		.expect("pbkdf2-sha256"),
		"pbkdf2-sha512" => PHash::hash_pbkdf2_with_salt(
			&password_str(fixture.password.as_ref().expect("password")),
			"pbkdf2sha512",
			&Pbkdf2Config {
				rounds: params.and_then(|p| p.rounds).unwrap_or(1000),
				output_length: params.and_then(|p| p.output_length).unwrap_or(64),
			},
			&salt_b64(fixture.salt.as_ref().expect("salt")),
		)
		.expect("pbkdf2-sha512"),
		"sha-crypt" => {
			let salt = decode_bytes("salt", fixture.salt.as_ref().expect("salt"));
			PHash::hash_sha_crypt_with_salt(
				&password_str(fixture.password.as_ref().expect("password")),
				&salt,
			)
			.expect("sha-crypt")
		}
		alg if alg.starts_with("hkdf-") => {
			let algorithm = HkdfAlgorithm::from_str(alg).expect("hkdf algorithm");
			let length = params.and_then(|p| p.length).unwrap_or(algorithm.output_size());
			let resp = derive(HkdfRequest {
				variant: HkdfVariant::new(algorithm, HkdfMode::ExtractAndExpand),
				input: HkdfInput::Extract(SecretMaterial::from_bytes(decode_bytes(
					"ikm",
					fixture.ikm.as_ref().expect("ikm"),
				))),
				salt: fixture
					.salt
					.as_ref()
					.map(|s| decode_bytes("salt", s))
					.unwrap_or_default(),
				info: fixture
					.info
					.as_ref()
					.map(|s| decode_bytes("info", s))
					.unwrap_or_default(),
				length,
			})
			.expect("hkdf derive");
			hex::encode(resp.derived_key)
		}
		other => panic!("unsupported KDF algorithm `{other}`"),
	}
}

#[test]
fn published_kdf_kats_match_implementations() {
	for (path, fixture) in load_fixtures() {
		let actual = derive_kat(&fixture);
		assert_eq!(
			actual, fixture.expected,
			"KDF KAT mismatch for {} ({})",
			fixture.algorithm,
			path.display()
		);
	}
}

#[test]
fn every_kdf_algorithm_id_has_a_published_kat() {
	let covered: HashSet<String> = load_fixtures()
		.into_iter()
		.map(|(_, fixture)| fixture.algorithm)
		.collect();
	for alg in KDF_ALGORITHM_IDS {
		assert!(
			covered.contains(*alg),
			"missing KDF KAT for {alg}"
		);
	}
}

#[test]
fn kdf_kat_fixtures_have_no_orphan_algorithms() {
	let known: HashSet<&str> = KDF_ALGORITHM_IDS.iter().copied().collect();
	for (path, fixture) in load_fixtures() {
		assert!(
			known.contains(fixture.algorithm.as_str()),
			"orphan KDF KAT {} in {}",
			fixture.algorithm,
			path.display()
		);
	}
}
