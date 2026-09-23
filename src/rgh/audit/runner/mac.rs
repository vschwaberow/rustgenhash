// SPDX-License-Identifier: MIT OR Apache-2.0
// Project: rustgenhash
// File: mac.rs
// Author: Volker Schwaberow <volker@schwaberow.de>
// Copyright (c) 2022 Volker Schwaberow

use std::fs::File;
use std::path::PathBuf;

use serde_json::{json, Map, Value};

use super::super::{AuditCase, AuditError};
use crate::rgh::mac::executor as mac_executor;
use crate::rgh::mac::{
	commands::legacy_warning_message,
	key::{load_key as load_mac_key, KeySource as MacKeySource},
	poly1305::Poly1305ReuseTracker,
	registry::{
		self as mac_registry, MacAlgorithmMetadata, MacExecutor,
	},
};

pub(crate) fn parse_mac_key_source(
	case: &AuditCase,
) -> Result<MacKeySource, AuditError> {
	let key_value = case.key.as_ref().ok_or_else(|| {
		AuditError::Invalid(format!(
			"Fixture `{}` missing key definition",
			case.id
		))
	})?;
	let source = key_value
		.get("source")
		.and_then(Value::as_str)
		.ok_or_else(|| {
			AuditError::Invalid(format!(
				"Fixture `{}` missing key.source field",
				case.id
			))
		})?;
	Ok(MacKeySource::File(PathBuf::from(source)))
}

pub(crate) fn load_mac_fixture_key(
	key_source: &MacKeySource,
) -> Result<Vec<u8>, AuditError> {
	load_mac_key(key_source)
		.map_err(|err| AuditError::Invalid(format!("{}", err)))
}

pub(crate) fn create_mac_executor_for_case(
	algorithm: &str,
	case_id: &str,
	key: &[u8],
) -> Result<(Box<dyn MacExecutor>, MacAlgorithmMetadata), AuditError>
{
	mac_registry::create_executor(algorithm, key).map_err(|err| {
		AuditError::Invalid(format!("Fixture `{}`: {}", case_id, err))
	})
}

pub(crate) fn run_mac_string_case(
	case: &AuditCase,
) -> Result<Value, AuditError> {
	let key_source = parse_mac_key_source(case)?;
	let key_bytes = load_mac_fixture_key(&key_source)?;
	let input_obj = case.input.as_object().ok_or_else(|| {
		AuditError::Invalid(format!(
			"Fixture `{}` input must be an object",
			case.id
		))
	})?;
	let message = input_obj
		.get("value")
		.and_then(Value::as_str)
		.ok_or_else(|| {
			AuditError::Invalid(format!(
				"Fixture `{}` missing input.value",
				case.id
			))
		})?;
	let expected =
		case.expected_output.as_object().ok_or_else(|| {
			AuditError::Invalid(format!(
				"Fixture `{}` expected_output must be an object",
				case.id
			))
		})?;
	let expected_exit = expected
		.get("exit_code")
		.and_then(Value::as_i64)
		.unwrap_or(0);

	match mac_registry::create_executor(&case.algorithm, &key_bytes) {
		Ok((executor, metadata)) => {
			let digest = mac_executor::consume_bytes(
				message.as_bytes(),
				executor,
			);
			let hex = mac_executor::digest_to_hex(&digest);
			let mut root = serde_json::Map::new();
			root.insert(
				"default_line".into(),
				Value::String(format!("{} {}", hex, message)),
			);
			root.insert(
				"hash_only_line".into(),
				Value::String(hex.clone()),
			);
			root.insert("exit_code".into(), Value::from(0));
			if metadata.is_legacy() {
				root.insert(
					"stderr_contains".into(),
					Value::Array(vec![Value::String(
						legacy_warning_message(&metadata),
					)]),
				);
			}
			Ok(Value::Object(root))
		}
		Err(err) => {
			if expected_exit == 2 {
				let message = err.to_string();
				let mut root = serde_json::Map::new();
				root.insert(
					"error".into(),
					Value::String(message.clone()),
				);
				root.insert("stderr".into(), Value::String(message));
				root.insert("exit_code".into(), Value::from(2));
				return Ok(Value::Object(root));
			}
			Err(AuditError::Invalid(format!(
				"Fixture `{}`: {}",
				case.id, err
			)))
		}
	}
}

pub(crate) fn run_mac_file_case(
	case: &AuditCase,
) -> Result<Value, AuditError> {
	let key_source = parse_mac_key_source(case)?;
	let key_bytes = load_mac_fixture_key(&key_source)?;
	let path_str =
		case.input.get("path").and_then(Value::as_str).ok_or_else(
			|| {
				AuditError::Invalid(format!(
					"Fixture `{}` missing input.path",
					case.id
				))
			},
		)?;
	let path = PathBuf::from(path_str);
	let file =
		File::open(&path).map_err(|source| AuditError::Io {
			source,
			path: path.clone(),
		})?;
	let (executor, metadata) = create_mac_executor_for_case(
		&case.algorithm,
		&case.id,
		&key_bytes,
	)?;
	let digest = mac_executor::consume_reader(file, executor)
		.map_err(|source| AuditError::Io {
			source,
			path: path.clone(),
		})?;
	let hex = mac_executor::digest_to_hex(&digest);
	let mut root = Map::new();
	root.insert(
		"default_line".into(),
		Value::String(format!("{} {}", hex, path.display())),
	);
	root.insert("hash_only_line".into(), Value::String(hex.clone()));
	root.insert("exit_code".into(), Value::from(0));
	if metadata.is_legacy() {
		root.insert(
			"stderr_contains".into(),
			Value::Array(vec![Value::String(
				legacy_warning_message(&metadata),
			)]),
		);
	}
	Ok(Value::Object(root))
}

pub(crate) fn run_mac_stdio_case(
	case: &AuditCase,
) -> Result<Value, AuditError> {
	let key_source = parse_mac_key_source(case)?;
	let key_bytes = load_mac_fixture_key(&key_source)?;
	let lines = case
		.input
		.get("lines")
		.and_then(Value::as_array)
		.ok_or_else(|| {
			AuditError::Invalid(format!(
				"Fixture `{}` missing input.lines",
				case.id
			))
		})?;
	let mut default_lines = Vec::new();
	let mut hash_only_lines = Vec::new();
	let mut records = Vec::new();
	let mut warnings: Vec<String> = Vec::new();
	let mut reuse_tracker =
		if case.algorithm.eq_ignore_ascii_case("poly1305") {
			Some(Poly1305ReuseTracker::default())
		} else {
			None
		};
	for entry in lines {
		let line = entry.as_str().ok_or_else(|| {
			AuditError::Invalid(format!(
				"Fixture `{}` has non-string entry in input.lines",
				case.id
			))
		})?;
		if let Some(tracker) = reuse_tracker.as_mut() {
			if let Some(warning) = tracker.check_reuse(&key_bytes) {
				if !warnings.iter().any(|w| w == warning) {
					warnings.push(warning.to_string());
				}
			}
		}
		let (executor, metadata) = create_mac_executor_for_case(
			&case.algorithm,
			&case.id,
			&key_bytes,
		)?;
		if metadata.is_legacy() {
			let warning_msg = legacy_warning_message(&metadata);
			if !warnings.iter().any(|w| w == &warning_msg) {
				warnings.push(warning_msg);
			}
		}
		let digest =
			mac_executor::consume_bytes(line.as_bytes(), executor);
		let hex = mac_executor::digest_to_hex(&digest);
		default_lines
			.push(Value::String(format!("{} {}", hex, line)));
		hash_only_lines.push(Value::String(hex.clone()));
		records.push(json!({ "source": line, "digest": hex }));
	}
	let mut root = Map::new();
	root.insert("default_lines".into(), Value::Array(default_lines));
	root.insert(
		"hash_only_lines".into(),
		Value::Array(hash_only_lines),
	);
	root.insert("records".into(), Value::Array(records));
	root.insert("exit_code".into(), Value::from(0));
	if !warnings.is_empty() {
		root.insert(
			"stderr_contains".into(),
			Value::Array(
				warnings.into_iter().map(Value::String).collect(),
			),
		);
	}
	Ok(Value::Object(root))
}
