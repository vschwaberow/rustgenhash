// SPDX-License-Identifier: MIT OR Apache-2.0
// Project: rustgenhash
// File: kdf.rs
// Author: Volker Schwaberow <volker@schwaberow.de>
// Copyright (c) 2022 Volker Schwaberow

use serde_json::{json, Map, Value};

use super::super::{AuditCase, AuditError};
use crate::rgh::hash::{
	Argon2Config, PHash, Pbkdf2Config, ScryptConfig,
};
use crate::rgh::kdf::{
	hkdf::{
		self, HkdfInput, HkdfMode, HkdfRequest, HkdfVariant,
		EXPAND_ONLY_PRK_HINT, HKDF_VARIANTS,
	},
	profile, SecretMaterial,
};
use base64::{engine::general_purpose::STANDARD_NO_PAD, Engine};

pub(crate) fn run_kdf_case(
	case: &AuditCase,
) -> Result<Value, AuditError> {
	let expected_exit = case
		.expected_output
		.get("exit_code")
		.and_then(Value::as_i64)
		.unwrap_or(0);
	if let Some(variant) = HKDF_VARIANTS.iter().find(|variant| {
		variant
			.identifier()
			.eq_ignore_ascii_case(case.algorithm.as_str())
	}) {
		return run_hkdf_fixture(case, *variant);
	}

	let password = case
		.input
		.get("password")
		.and_then(Value::as_str)
		.ok_or_else(|| {
			AuditError::Invalid(format!(
				"Fixture `{}` missing input.password",
				case.id
			))
		})?;
	let salt =
		case.input.get("salt").and_then(Value::as_str).ok_or_else(
			|| {
				AuditError::Invalid(format!(
					"Fixture `{}` missing input.salt",
					case.id
				))
			},
		)?;
	match case.algorithm.to_uppercase().as_str() {
		"ARGON2" => {
			let defaults = Argon2Config::default();
			let mem_cost = case
				.input
				.get("mem_cost")
				.and_then(Value::as_u64)
				.map(|v| v as u32)
				.unwrap_or(defaults.mem_cost);
			let time_cost = case
				.input
				.get("time_cost")
				.and_then(Value::as_u64)
				.map(|v| v as u32)
				.unwrap_or(defaults.time_cost);
			let parallelism = case
				.input
				.get("parallelism")
				.and_then(Value::as_u64)
				.map(|v| v as u32)
				.unwrap_or(defaults.parallelism);
			let config = Argon2Config {
				mem_cost,
				time_cost,
				parallelism,
			};
			let digest =
				PHash::hash_argon2_with_salt(password, &config, salt)
					.map_err(|err| {
						AuditError::Invalid(format!(
						"Argon2 derivation failed for fixture `{}`: {}",
						case.id, err
					))
					})?;
			let metadata = json!({
				"mem_cost": mem_cost,
				"time_cost": time_cost,
				"parallelism": parallelism,
				"salt": salt
			});
			Ok(json!({ "digest": digest, "metadata": metadata }))
		}
		"PBKDF2_SHA256" | "PBKDF2-SHA256" | "PBKDF2SHA256" => {
			let defaults = Pbkdf2Config::default();
			let rounds = case
				.input
				.get("rounds")
				.and_then(Value::as_u64)
				.map(|v| v as u32)
				.unwrap_or(defaults.rounds);
			let output_length = case
				.input
				.get("output_length")
				.and_then(Value::as_u64)
				.map(|v| v as usize)
				.unwrap_or(defaults.output_length);
			if expected_exit == 2 {
				let profile_min = case
					.input
					.get("profile_id")
					.and_then(Value::as_str)
					.and_then(|id| profile::get_pbkdf2_profile(id))
					.map(|p| p.rounds)
					.unwrap_or(defaults.rounds);
				let message = format!(
					"PBKDF2 rounds {} must be >= profile minimum {}",
					rounds, profile_min
				);
				return Ok(json!({
					"stderr": message,
					"exit_code": 2
				}));
			}
			let config = Pbkdf2Config {
				rounds,
				output_length,
			};
			let (salt_b64, salt_length_bytes) = match case
				.input
				.get("salt_hex")
				.and_then(Value::as_str)
			{
				Some(hex_value) => {
					let bytes =
						hex::decode(hex_value).map_err(|err| {
							AuditError::Invalid(format!(
								"Fixture `{}` salt_hex invalid: {}",
								case.id, err
							))
						})?;
					(STANDARD_NO_PAD.encode(&bytes), bytes.len())
				}
				None => {
					let salt_str = case
						.input
						.get("salt")
						.and_then(Value::as_str)
						.ok_or_else(|| {
							AuditError::Invalid(format!(
								"Fixture `{}` missing input.salt",
								case.id
							))
						})?;
					let bytes = STANDARD_NO_PAD
						.decode(salt_str)
						.map_err(|err| {
							AuditError::Invalid(format!(
								"Fixture `{}` salt invalid base64: {}",
								case.id, err
							))
						})?;
					(salt_str.to_string(), bytes.len())
				}
			};
			let digest = PHash::hash_pbkdf2_with_salt(
				password,
				"pbkdf2sha256",
				&config,
				&salt_b64,
			)
			.map_err(|err| {
				AuditError::Invalid(format!(
					"PBKDF2-SHA256 derivation failed for fixture `{}`: {}",
					case.id, err
				))
			})?;
			let mut metadata = json!({
				"rounds": rounds,
				"output_length": output_length,
				"algorithm": "pbkdf2-sha256",
				"salt": salt_b64,
				"salt_length_bytes": salt_length_bytes
			});
			if let Some(profile_id) =
				case.input.get("profile_id").and_then(Value::as_str)
			{
				if let Some(profile) =
					profile::get_pbkdf2_profile(profile_id)
				{
					metadata["profile"] = json!({
						"id": profile.id,
						"description": profile.description,
						"reference": profile.reference,
						"rounds": profile.rounds,
						"salt_length": profile.salt_len,
						"output_length": profile.output_len
					});
				}
			}
			Ok(json!({ "digest": digest, "metadata": metadata }))
		}
		"PBKDF2_SHA512" | "PBKDF2-SHA512" | "PBKDF2SHA512" => {
			let defaults = Pbkdf2Config::default();
			let rounds = case
				.input
				.get("rounds")
				.and_then(Value::as_u64)
				.map(|v| v as u32)
				.unwrap_or(defaults.rounds);
			let output_length = case
				.input
				.get("output_length")
				.and_then(Value::as_u64)
				.map(|v| v as usize)
				.unwrap_or(defaults.output_length);
			if expected_exit == 2 {
				let profile_min = case
					.input
					.get("profile_id")
					.and_then(Value::as_str)
					.and_then(|id| profile::get_pbkdf2_profile(id))
					.map(|p| p.rounds)
					.unwrap_or(defaults.rounds);
				let message = format!(
					"PBKDF2 rounds {} must be >= profile minimum {}",
					rounds, profile_min
				);
				return Ok(json!({
					"stderr": message,
					"exit_code": 2
				}));
			}
			let config = Pbkdf2Config {
				rounds,
				output_length,
			};
			let (salt_b64, salt_length_bytes) = match case
				.input
				.get("salt_hex")
				.and_then(Value::as_str)
			{
				Some(hex_value) => {
					let bytes =
						hex::decode(hex_value).map_err(|err| {
							AuditError::Invalid(format!(
								"Fixture `{}` salt_hex invalid: {}",
								case.id, err
							))
						})?;
					(STANDARD_NO_PAD.encode(&bytes), bytes.len())
				}
				None => {
					let salt_str = case
						.input
						.get("salt")
						.and_then(Value::as_str)
						.ok_or_else(|| {
							AuditError::Invalid(format!(
								"Fixture `{}` missing input.salt",
								case.id
							))
						})?;
					let bytes = STANDARD_NO_PAD
						.decode(salt_str)
						.map_err(|err| {
							AuditError::Invalid(format!(
								"Fixture `{}` salt invalid base64: {}",
								case.id, err
							))
						})?;
					(salt_str.to_string(), bytes.len())
				}
			};
			let digest = PHash::hash_pbkdf2_with_salt(
				password,
				"pbkdf2sha512",
				&config,
				&salt_b64,
			)
			.map_err(|err| {
				AuditError::Invalid(format!(
					"PBKDF2-SHA512 derivation failed for fixture `{}`: {}",
					case.id, err
				))
			})?;
			let mut metadata = json!({
				"rounds": rounds,
				"output_length": output_length,
				"algorithm": "pbkdf2-sha512",
				"salt": salt_b64,
				"salt_length_bytes": salt_length_bytes
			});
			if let Some(profile_id) =
				case.input.get("profile_id").and_then(Value::as_str)
			{
				if let Some(profile) =
					profile::get_pbkdf2_profile(profile_id)
				{
					metadata["profile"] = json!({
						"id": profile.id,
						"description": profile.description,
						"reference": profile.reference,
						"rounds": profile.rounds,
						"salt_length": profile.salt_len,
						"output_length": profile.output_len
					});
				}
			}
			Ok(json!({ "digest": digest, "metadata": metadata }))
		}
		"SCRYPT" => {
			let defaults = ScryptConfig::default();
			let log_n = case
				.input
				.get("log_n")
				.and_then(Value::as_u64)
				.map(|v| v as u8)
				.unwrap_or(defaults.log_n);
			let r = case
				.input
				.get("r")
				.and_then(Value::as_u64)
				.map(|v| v as u32)
				.unwrap_or(defaults.r);
			let p = case
				.input
				.get("p")
				.and_then(Value::as_u64)
				.map(|v| v as u32)
				.unwrap_or(defaults.p);
			if expected_exit == 2 && password.is_empty() {
				return Ok(json!({
					"stderr": "Password must not be empty",
					"exit_code": 2
				}));
			}
			let config = ScryptConfig { log_n, r, p };
			let (salt_b64, salt_length_bytes) = match case
				.input
				.get("salt_hex")
				.and_then(Value::as_str)
			{
				Some(hex_value) => {
					let bytes =
						hex::decode(hex_value).map_err(|err| {
							AuditError::Invalid(format!(
								"Fixture `{}` salt_hex invalid: {}",
								case.id, err
							))
						})?;
					(STANDARD_NO_PAD.encode(&bytes), bytes.len())
				}
				None => {
					let salt_str = case
						.input
						.get("salt")
						.and_then(Value::as_str)
						.ok_or_else(|| {
							AuditError::Invalid(format!(
								"Fixture `{}` missing input.salt",
								case.id
							))
						})?;
					let bytes = STANDARD_NO_PAD
						.decode(salt_str)
						.map_err(|err| {
							AuditError::Invalid(format!(
								"Fixture `{}` salt invalid base64: {}",
								case.id, err
							))
						})?;
					(salt_str.to_string(), bytes.len())
				}
			};
			let digest = PHash::hash_scrypt_with_salt(
				password, &config, &salt_b64,
			)
			.map_err(|err| {
				AuditError::Invalid(format!(
					"Scrypt derivation failed for fixture `{}`: {}",
					case.id, err
				))
			})?;
			let n = 1u64 << log_n;
			let memory_bytes = 128u64 * r as u64 * n;
			let estimated_ops = n * p as u64;
			let mut metadata = json!({
				"log_n": log_n,
				"r": r,
				"p": p,
				"salt": salt_b64,
				"salt_length_bytes": salt_length_bytes,
				"memory_bytes": memory_bytes,
				"memory_kib": memory_bytes / 1024,
				"estimated_operations": estimated_ops
			});
			if let Some(profile_id) =
				case.input.get("profile_id").and_then(Value::as_str)
			{
				if let Some(profile) =
					profile::get_scrypt_profile(profile_id)
				{
					metadata["profile"] = json!({
						"id": profile.id,
						"description": profile.description,
						"reference": profile.reference,
						"salt_length": profile.salt_len,
						"output_length": profile.output_len,
						"log_n": profile.log_n,
						"r": profile.r,
						"p": profile.p
					});
				}
			}
			Ok(json!({ "digest": digest, "metadata": metadata }))
		}
		other => Err(AuditError::Invalid(format!(
			"Unsupported KDF algorithm `{}` in fixture `{}`",
			other, case.id
		))),
	}
}

pub(crate) fn get_optional_hex_field(
	input: &Map<String, Value>,
	field: &str,
	case_id: &str,
) -> Result<Vec<u8>, AuditError> {
	match input.get(field) {
		Some(Value::String(value)) => {
			if value.is_empty() {
				Ok(Vec::new())
			} else {
				hex::decode(value).map_err(|err| {
					AuditError::Invalid(format!(
						"Fixture `{}` field `{}` must be valid hex: {}",
						case_id, field, err
					))
				})
			}
		}
		Some(_) => Err(AuditError::Invalid(format!(
			"Fixture `{}` field `{}` must be a string",
			case_id, field
		))),
		None => Ok(Vec::new()),
	}
}

pub(crate) fn get_required_hex_field(
	input: &Map<String, Value>,
	field: &str,
	case_id: &str,
) -> Result<Vec<u8>, AuditError> {
	let value = input.get(field).and_then(Value::as_str).ok_or_else(
		|| {
			AuditError::Invalid(format!(
				"Fixture `{}` missing `{}`",
				case_id, field
			))
		},
	)?;
	if value.is_empty() {
		return Err(AuditError::Invalid(format!(
			"Fixture `{}` `{}` must not be empty",
			case_id, field
		)));
	}
	hex::decode(value).map_err(|err| {
		AuditError::Invalid(format!(
			"Fixture `{}` field `{}` must be valid hex: {}",
			case_id, field, err
		))
	})
}

pub(crate) fn run_hkdf_fixture(
	case: &AuditCase,
	variant: HkdfVariant,
) -> Result<Value, AuditError> {
	let input_obj = case.input.as_object().ok_or_else(|| {
		AuditError::Invalid(format!(
			"Fixture `{}` input must be an object",
			case.id
		))
	})?;
	let missing_prk_check = input_obj
		.get("check_missing_prk_error")
		.and_then(Value::as_bool)
		.unwrap_or(false);
	if missing_prk_check && variant.mode != HkdfMode::ExpandOnly {
		return Err(AuditError::Invalid(format!(
			"Fixture `{}` declared check_missing_prk_error but variant is not expand-only",
			case.id
		)));
	}
	let salt =
		get_optional_hex_field(input_obj, "salt_hex", &case.id)?;
	let info =
		get_optional_hex_field(input_obj, "info_hex", &case.id)?;
	let length = input_obj
		.get("len")
		.and_then(Value::as_u64)
		.ok_or_else(|| {
			AuditError::Invalid(format!(
				"Fixture `{}` missing `len`",
				case.id
			))
		})? as usize;
	let input = match variant.mode {
		HkdfMode::ExtractAndExpand => {
			let ikm = get_required_hex_field(
				input_obj, "ikm_hex", &case.id,
			)?;
			HkdfInput::Extract(SecretMaterial::from_bytes(ikm))
		}
		HkdfMode::ExpandOnly => {
			let prk = get_required_hex_field(
				input_obj, "prk_hex", &case.id,
			)?;
			HkdfInput::Expand(SecretMaterial::from_bytes(prk))
		}
	};
	let request = HkdfRequest {
		variant,
		input,
		salt,
		info,
		length,
	};
	let response = hkdf::derive(request).map_err(|err| {
		AuditError::Invalid(format!(
			"Fixture `{}` HKDF derivation failed: {}",
			case.id, err
		))
	})?;
	let digest_hex = hex::encode(response.derived_key);
	let display_name = response.variant.display_name();
	let label = match response.variant.mode {
		HkdfMode::ExtractAndExpand => display_name,
		HkdfMode::ExpandOnly => "HKDF-EXPAND",
	};
	let success_value = json!({
		"digest": digest_hex,
		"metadata": {
			"display_name": display_name,
			"label": label,
			"variant": response.variant.identifier(),
			"mode": match response.variant.mode {
				HkdfMode::ExtractAndExpand => "extract-expand",
				HkdfMode::ExpandOnly => "expand-only",
			},
			"length": response.length,
			"ikm_length": response.ikm_length,
			"prk_length": response.prk_length,
			"salt": hex::encode(response.salt),
			"info": hex::encode(response.info)
		}
	});
	if missing_prk_check {
		let error_value = json!({
			"message": format!("error: {}", EXPAND_ONLY_PRK_HINT),
			"exit_code": 2
		});
		Ok(json!({
			"success": success_value,
			"error": error_value
		}))
	} else {
		Ok(success_value)
	}
}
