// SPDX-License-Identifier: MIT OR Apache-2.0
// Project: rustgenhash
// Module: output
// Purpose: Unified digest serialization across CLI formats.

use crate::rgh::multihash::{MultihashEncoder, MultihashError};
use base64::{engine::general_purpose::STANDARD, Engine as _};
use chrono::{DateTime, Utc};
use clap::ValueEnum;
use csv::WriterBuilder;
use serde::Serialize;
use std::fmt;

use strum::EnumIter;

/// Supported digest output formats surfaced via the CLI `--format` flag.
#[derive(Clone, Copy, Debug, Eq, PartialEq, ValueEnum, EnumIter)]
#[value(rename_all = "kebab-case")]
pub enum DigestOutputFormat {
	Json,
	#[value(alias = "jsonl")]
	JsonLines,
	Csv,
	Hex,
	Base64,
	Hashcat,
	Multihash,
}

impl DigestOutputFormat {
	pub fn canonical_name(self) -> &'static str {
		match self {
			Self::Json => "json",
			Self::JsonLines => "jsonl",
			Self::Csv => "csv",
			Self::Hex => "hex",
			Self::Base64 => "base64",
			Self::Hashcat => "hashcat",
			Self::Multihash => "multihash",
		}
	}
}

impl fmt::Display for DigestOutputFormat {
	fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
		let label = match self {
			Self::Json => "JSON manifest",
			Self::JsonLines => "JSON Lines",
			Self::Csv => "CSV",
			Self::Hex => "Hexadecimal",
			Self::Base64 => "Base64",
			Self::Hashcat => "Hashcat (wordlist)",
			Self::Multihash => "Multihash (base58btc)",
		};
		write!(f, "{}", label)
	}
}

/// Metadata describing how an output format behaves.
#[derive(Clone, Debug)]
pub struct OutputFormatProfile {
	pub kind: DigestOutputFormat,
	pub mime_hint: Option<&'static str>,
	pub structured: bool,
	pub supports_hash_only: bool,
}

impl OutputFormatProfile {
	pub fn new(kind: DigestOutputFormat) -> Self {
		let (mime_hint, structured, supports_hash_only) = match kind {
			DigestOutputFormat::Json => {
				(Some("application/json"), true, false)
			}
			DigestOutputFormat::JsonLines => {
				(Some("application/x-ndjson"), true, false)
			}
			DigestOutputFormat::Csv => {
				(Some("text/csv"), true, false)
			}
			DigestOutputFormat::Hex => {
				(Some("text/plain"), false, true)
			}
			DigestOutputFormat::Base64 => {
				(Some("text/plain"), false, true)
			}
			DigestOutputFormat::Hashcat => {
				(Some("text/plain"), false, true)
			}
			DigestOutputFormat::Multihash => {
				(Some("text/plain"), false, true)
			}
		};

		Self {
			kind,
			mime_hint,
			structured,
			supports_hash_only,
		}
	}

	pub fn structured(&self) -> bool {
		self.structured
	}

	pub fn supports_hash_only(&self) -> bool {
		self.supports_hash_only
	}
}

/// Canonical digest record shared between structured serializers.
#[derive(Clone, Debug, Serialize)]
pub struct DigestRecord {
	pub path: Option<String>,
	pub algorithm: String,
	pub digest: Vec<u8>,
	pub digest_hex: String,
	pub digest_base64: String,
	pub source: DigestSource,
}

impl DigestRecord {
	pub fn from_digest(
		path: Option<String>,
		algorithm: &str,
		digest: &[u8],
		source: DigestSource,
	) -> Self {
		Self {
			path,
			algorithm: algorithm.to_uppercase(),
			digest: digest.to_vec(),
			digest_hex: hex::encode(digest),
			digest_base64: STANDARD.encode(digest),
			source,
		}
	}
}

/// Identifies where the digest originated (used in structured outputs).
#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum DigestSource {
	File,
	String,
	StdioLine,
}

/// Result returned by serialization routines.
#[derive(Debug)]
pub struct SerializationResult {
	pub lines: Vec<String>,
	pub warnings: Vec<String>,
}

impl SerializationResult {
	fn new() -> Self {
		Self {
			lines: Vec::new(),
			warnings: Vec::new(),
		}
	}
}

/// Error type emitted by output serializers.
#[derive(Debug)]
pub struct OutputError {
	message: String,
	multihash: Option<Box<MultihashError>>,
}

impl OutputError {
	pub fn new(message: impl Into<String>) -> Self {
		Self {
			message: message.into(),
			multihash: None,
		}
	}

	pub fn from_multihash(error: MultihashError) -> Self {
		let message = error.to_string();
		Self {
			message,
			multihash: Some(Box::new(error)),
		}
	}

	pub fn multihash(&self) -> Option<&MultihashError> {
		self.multihash.as_deref()
	}
}

impl fmt::Display for OutputError {
	fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
		write!(f, "{}", self.message)
	}
}

impl std::error::Error for OutputError {}

#[derive(Serialize)]
struct JsonManifest<'a> {
	algorithm: &'a str,
	generated_at: DateTime<Utc>,
	entries: &'a [JsonManifestEntry<'a>],
}

#[derive(Serialize)]
struct JsonManifestEntry<'a> {
	path: Option<&'a str>,
	digest_hex: &'a str,
	digest_base64: &'a str,
	source: &'a DigestSource,
}

#[derive(Serialize)]
struct JsonLineEntry<'a> {
	path: Option<&'a str>,
	algorithm: &'a str,
	digest_hex: &'a str,
	digest_base64: &'a str,
	source: &'a DigestSource,
}

/// Serialize a set of digest records according to the requested format.
pub fn serialize_records(
	records: &[DigestRecord],
	profile: &OutputFormatProfile,
	hash_only: bool,
) -> Result<SerializationResult, OutputError> {
	let mut result = SerializationResult::new();

	if records.is_empty() {
		return Ok(result);
	}

	if profile.structured() && hash_only {
		result.warnings.push(
			"--hash-only ignored for structured formats".to_string(),
		);
	}

	match profile.kind {
		DigestOutputFormat::Json => {
			serialize_json(records, &mut result)?
		}
		DigestOutputFormat::JsonLines => {
			serialize_jsonl(records, &mut result)?
		}
		DigestOutputFormat::Csv => {
			serialize_csv(records, &mut result)?
		}
		DigestOutputFormat::Hex => {
			serialize_hex(records, hash_only, &mut result)
		}
		DigestOutputFormat::Base64 => {
			serialize_base64(records, hash_only, &mut result)
		}
		DigestOutputFormat::Hashcat => {
			serialize_hashcat(records, hash_only, &mut result)?
		}
		DigestOutputFormat::Multihash => {
			serialize_multihash(records, hash_only, &mut result)?
		}
	}

	Ok(result)
}

fn serialize_json(
	records: &[DigestRecord],
	result: &mut SerializationResult,
) -> Result<(), OutputError> {
	let entries: Vec<JsonManifestEntry<'_>> = records
		.iter()
		.map(|record| JsonManifestEntry {
			path: record.path.as_deref(),
			digest_hex: record.digest_hex.as_str(),
			digest_base64: record.digest_base64.as_str(),
			source: &record.source,
		})
		.collect();

	let manifest = JsonManifest {
		algorithm: records
			.first()
			.map(|record| record.algorithm.as_str())
			.unwrap_or_default(),
		generated_at: Utc::now(),
		entries: &entries,
	};

	let serialized = serde_json::to_string(&manifest)
		.map_err(|err| OutputError::new(err.to_string()))?;
	result.lines.push(serialized);
	Ok(())
}

fn serialize_jsonl(
	records: &[DigestRecord],
	result: &mut SerializationResult,
) -> Result<(), OutputError> {
	for record in records {
		let entry = JsonLineEntry {
			path: record.path.as_deref(),
			algorithm: record.algorithm.as_str(),
			digest_hex: record.digest_hex.as_str(),
			digest_base64: record.digest_base64.as_str(),
			source: &record.source,
		};
		let serialized = serde_json::to_string(&entry)
			.map_err(|err| OutputError::new(err.to_string()))?;
		result.lines.push(serialized);
	}
	Ok(())
}

fn serialize_csv(
	records: &[DigestRecord],
	result: &mut SerializationResult,
) -> Result<(), OutputError> {
	let mut buffer = Vec::new();
	{
		let mut writer = WriterBuilder::new()
			.flexible(false)
			.has_headers(true)
			.from_writer(&mut buffer);

		writer
			.write_record(["digest", "path", "algorithm"])
			.map_err(|err| OutputError::new(err.to_string()))?;

		for record in records {
			writer
				.write_record([
					record.digest_hex.as_str(),
					record.path.as_deref().unwrap_or(""),
					record.algorithm.as_str(),
				])
				.map_err(|err| OutputError::new(err.to_string()))?;
		}

		writer
			.flush()
			.map_err(|err| OutputError::new(err.to_string()))?;
	}

	let csv_output = String::from_utf8(buffer)
		.map_err(|err| OutputError::new(err.to_string()))?;
	result
		.lines
		.push(csv_output.trim_end_matches('\n').to_string());
	Ok(())
}

fn serialize_hex(
	records: &[DigestRecord],
	hash_only: bool,
	result: &mut SerializationResult,
) {
	for record in records {
		if hash_only {
			result.lines.push(record.digest_hex.clone());
		} else {
			match record.path.as_deref() {
				Some(path) if !path.is_empty() => {
					result.lines.push(format!(
						"{} {}",
						record.digest_hex, path
					));
				}
				_ => result.lines.push(record.digest_hex.clone()),
			}
		}
	}
}

fn serialize_base64(
	records: &[DigestRecord],
	hash_only: bool,
	result: &mut SerializationResult,
) {
	for record in records {
		if hash_only {
			result.lines.push(record.digest_base64.clone());
		} else {
			match record.path.as_deref() {
				Some(path) if !path.is_empty() => {
					result.lines.push(format!(
						"{} {}",
						record.digest_base64, path
					));
				}
				_ => result.lines.push(record.digest_base64.clone()),
			}
		}
	}
}

fn serialize_hashcat(
	records: &[DigestRecord],
	hash_only: bool,
	result: &mut SerializationResult,
) -> Result<(), OutputError> {
	enforce_hashcat_support(records)?;

	if !hash_only {
		result.warnings.push(
			"--hash-only implied for hashcat exports".to_string(),
		);
	}

	for record in records {
		result.lines.push(record.digest_hex.clone());
	}

	Ok(())
}

fn serialize_multihash(
	records: &[DigestRecord],
	hash_only: bool,
	result: &mut SerializationResult,
) -> Result<(), OutputError> {
	for record in records {
		let algorithm = record.algorithm.to_ascii_lowercase();
		let token =
			MultihashEncoder::encode(&algorithm, &record.digest)
				.map_err(OutputError::from_multihash)?;
		if hash_only {
			result.lines.push(token);
		} else {
			match record.path.as_deref() {
				Some(path) if !path.is_empty() => {
					result.lines.push(format!("{token} {path}"));
				}
				_ => result.lines.push(token),
			}
		}
	}

	Ok(())
}

fn enforce_hashcat_support(
	records: &[DigestRecord],
) -> Result<(), OutputError> {
	let supported = [
		"MD5",
		"SHA1",
		"SHA224",
		"SHA256",
		"SHA384",
		"SHA512",
		"NTLM",
		"RIPEMD160",
	];

	if let Some(record) = records.first() {
		let algorithm = record.algorithm.as_str();
		if !supported.contains(&algorithm) {
			return Err(OutputError::new(format!(
				"Algorithm {algorithm} is not supported for hashcat output"
			)));
		}
	}

	Ok(())
}
