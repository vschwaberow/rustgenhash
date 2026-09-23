// SPDX-License-Identifier: MIT OR Apache-2.0
// Project: rustgenhash
// File: hash/digest_ops.rs

use super::rhash::RHash;
use crate::rgh::output::{
	serialize_records, DigestOutputFormat, DigestRecord, DigestSource,
	OutputError, OutputFormatProfile, SerializationResult,
};

pub fn digest_bytes_to_record(
	algorithm: &str,
	data: &[u8],
	label: Option<&str>,
	source: DigestSource,
) -> Result<DigestRecord, String> {
	let mut engine = RHash::new(algorithm)?;
	let digest = engine.process_string(data);
	let path = label.map(|value| value.to_string());
	Ok(DigestRecord::from_digest(path, algorithm, &digest, source))
}

pub fn serialize_digest_output(
	records: &[DigestRecord],
	format: DigestOutputFormat,
	hash_only: bool,
) -> Result<SerializationResult, OutputError> {
	let profile = OutputFormatProfile::new(format);
	serialize_records(records, &profile, hash_only)
}

