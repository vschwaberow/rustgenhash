// SPDX-License-Identifier: MIT OR Apache-2.0
// Project: rustgenhash

use crate::rgh::benchmark::{self, BenchmarkError, HkdfInputMaterial};
use std::collections::{BTreeMap, VecDeque};
use std::io::{self, Read};
use std::time::Duration;
use zeroize::Zeroizing;

pub fn mac_expected_key_length(identifier: &str) -> Option<usize> {
	match identifier {
		"cmac-aes128" => Some(16),
		"cmac-aes192" => Some(24),
		"cmac-aes256" => Some(32),
		"poly1305" => Some(32),
		_ => None,
	}
}

pub fn is_poly1305(identifier: &str) -> bool {
	identifier.eq_ignore_ascii_case("poly1305")
}

pub fn parse_duration_arg(raw: &str) -> Result<Duration, String> {
	let trimmed = raw.trim();
	if trimmed.is_empty() {
		return Err("duration cannot be empty".into());
	}
	let lower = trimmed.to_ascii_lowercase();
	let (value_str, unit) = if lower.ends_with("ms") {
		(lower.trim_end_matches("ms"), "ms")
	} else if lower.ends_with('s') {
		(lower.trim_end_matches('s'), "s")
	} else if lower.ends_with('m') {
		(lower.trim_end_matches('m'), "m")
	} else if lower.ends_with('h') {
		(lower.trim_end_matches('h'), "h")
	} else {
		(lower.as_str(), "s")
	};
	let value = value_str
		.parse::<u64>()
		.map_err(|_| format!("invalid duration `{}`", raw))?;
	if value == 0 {
		return Err("duration must be greater than zero".into());
	}
	let duration = match unit {
		"ms" => Duration::from_millis(value),
		"s" => Duration::from_secs(value),
		"m" => Duration::from_secs(value.saturating_mul(60)),
		"h" => Duration::from_secs(value.saturating_mul(3600)),
		_ => Duration::from_secs(value),
	};
	Ok(duration)
}

pub fn parse_hex_field(
	field: &str,
	value: Option<&String>,
) -> Result<Option<Vec<u8>>, BenchmarkError> {
	match value {
		Some(raw) => {
			let normalized = raw.trim();
			if normalized.is_empty() {
				return Err(BenchmarkError::validation(format!(
					"{} must not be empty",
					field
				)));
			}
			let bytes = hex::decode(normalized).map_err(|err| {
				BenchmarkError::validation(format!(
					"{} must be hex: {}",
					field, err
				))
			})?;
			Ok(Some(bytes))
		}
		None => Ok(None),
	}
}

pub fn parse_sensitive_hex_field(
	field: &str,
	value: Option<&String>,
) -> Result<Option<Zeroizing<Vec<u8>>>, BenchmarkError> {
	Ok(parse_hex_field(field, value)?.map(Zeroizing::new))
}

pub fn read_stdin_sensitive(
	label: &str,
) -> Result<Zeroizing<Vec<u8>>, BenchmarkError> {
	let mut buffer = Vec::new();
	io::stdin()
		.read_to_end(&mut buffer)
		.map_err(BenchmarkError::Io)?;
	if buffer.is_empty() {
		return Err(BenchmarkError::validation(format!(
			"{} from stdin was empty",
			label
		)));
	}
	Ok(Zeroizing::new(buffer))
}

pub fn collect_profile_overrides(
	matches: &clap::ArgMatches,
	canonical_algs: &[String],
) -> Result<BTreeMap<String, String>, BenchmarkError> {
	let mut overrides = BTreeMap::new();
	let mut defaults = VecDeque::new();
	if let Some(values) = matches.get_many::<String>("profile") {
		for raw in values {
			if let Some((alg, profile)) = raw.split_once('=') {
				let canonical =
					benchmark::kdf::canonical_algorithm_id(alg)?;
				let trimmed = profile.trim();
				if trimmed.is_empty() {
					return Err(BenchmarkError::validation(format!(
						"profile assignment for {} must not be empty",
						canonical
					)));
				}
				if overrides
					.insert(canonical.clone(), trimmed.to_string())
					.is_some()
				{
					return Err(BenchmarkError::validation(format!(
						"duplicate --profile for {}",
						canonical
					)));
				}
			} else {
				defaults.push_back(raw.trim().to_string());
			}
		}
	}
	for alg in canonical_algs {
		if !benchmark::kdf::algorithm_requires_profile(alg)? {
			continue;
		}
		if overrides.contains_key(alg) {
			continue;
		}
		let value = defaults.pop_front().ok_or_else(|| {
			BenchmarkError::validation(format!(
				"missing --profile assignment for {}",
				alg
			))
		})?;
		overrides.insert(alg.clone(), value);
	}
	if let Some(extra) = defaults.pop_front() {
		return Err(BenchmarkError::validation(format!(
			"unused --profile value `{}`",
			extra
		)));
	}
	Ok(overrides)
}

pub fn parse_hkdf_inputs(
	matches: &clap::ArgMatches,
) -> Result<Option<HkdfInputMaterial>, BenchmarkError> {
	let salt =
		parse_hex_field("salt", matches.get_one::<String>("salt"))?;
	let info =
		parse_hex_field("info", matches.get_one::<String>("info"))?;
	let mut ikm = parse_sensitive_hex_field(
		"ikm",
		matches.get_one::<String>("ikm"),
	)?;
	let mut prk = parse_sensitive_hex_field(
		"prk",
		matches.get_one::<String>("prk"),
	)?;
	if matches.get_flag("ikm-stdin") {
		if ikm.is_some() {
			return Err(BenchmarkError::validation(
				"Provide either --ikm HEX or --ikm-stdin",
			));
		}
		ikm = Some(read_stdin_sensitive("HKDF IKM")?);
	}
	if matches.get_flag("prk-stdin") {
		if prk.is_some() {
			return Err(BenchmarkError::validation(
				"Provide either --prk HEX or --prk-stdin",
			));
		}
		prk = Some(read_stdin_sensitive("HKDF PRK")?);
	}
	let length = matches.get_one::<usize>("length").copied();
	if salt.is_none()
		&& info.is_none()
		&& ikm.is_none()
		&& prk.is_none()
		&& length.is_none()
	{
		return Ok(None);
	}
	Ok(Some(HkdfInputMaterial {
		salt,
		info,
		ikm,
		prk,
		length,
	}))
}

use crate::rgh::file::{
	ErrorStrategy, ProgressConfig, ProgressMode, SymlinkPolicy,
	ThreadStrategy,
};

pub fn parse_symlink_policy(value: &str) -> SymlinkPolicy {
	match value.to_ascii_lowercase().as_str() {
		"never" => SymlinkPolicy::Never,
		"files" => SymlinkPolicy::Files,
		"all" => SymlinkPolicy::All,
		_ => SymlinkPolicy::Never,
	}
}

pub fn parse_thread_strategy(
	value: &str,
) -> Result<ThreadStrategy, String> {
	let trimmed = value.trim();
	if trimmed.eq_ignore_ascii_case("auto") {
		return Ok(ThreadStrategy::Auto);
	}
	let count: u16 = trimmed
		.parse()
		.map_err(|_| format!("Invalid thread count '{trimmed}'"))?;
	if count == 0 {
		return Err("Thread count must be >= 1".into());
	}
	if count == 1 {
		Ok(ThreadStrategy::Single)
	} else {
		Ok(ThreadStrategy::Fixed(count))
	}
}

pub fn parse_mmap_threshold(value: &str) -> Result<Option<u64>, String> {
	let trimmed = value.trim();
	if trimmed.is_empty() {
		return Err("mmap threshold cannot be empty".into());
	}
	if trimmed.eq_ignore_ascii_case("off") {
		return Ok(None);
	}
	let lower = trimmed.to_ascii_lowercase();
	let mut split = lower.len();
	for (idx, ch) in lower.char_indices() {
		if !ch.is_ascii_digit() {
			split = idx;
			break;
		}
	}
	let (number, suffix) = lower.split_at(split);
	if number.is_empty() {
		return Err(format!("Invalid mmap threshold '{trimmed}'"));
	}
	let value: u64 = number
		.parse()
		.map_err(|_| format!("Invalid mmap threshold '{trimmed}'"))?;
	let factor: u64 = match suffix {
		"" | "b" => 1,
		"k" | "kb" | "kib" => 1024,
		"m" | "mb" | "mib" => 1024 * 1024,
		"g" | "gb" | "gib" => 1024 * 1024 * 1024,
		other => {
			return Err(format!(
				"Unsupported size suffix '{}' for mmap threshold",
				other
			))
		}
	};
	value
		.checked_mul(factor)
		.map(Some)
		.ok_or_else(|| "mmap threshold overflow".into())
}

pub fn parse_error_strategy(value: &str) -> ErrorStrategy {
	match value.to_ascii_lowercase().as_str() {
		"fail-fast" => ErrorStrategy::FailFast,
		"continue" => ErrorStrategy::Continue,
		"report-only" => ErrorStrategy::ReportOnly,
		_ => ErrorStrategy::FailFast,
	}
}

pub fn build_progress_config(args: &clap::ArgMatches) -> ProgressConfig {
	let mode = if args.get_flag("no-progress") {
		ProgressMode::Disabled
	} else if args.get_flag("progress") {
		ProgressMode::Enabled
	} else {
		ProgressMode::Auto
	};
	ProgressConfig {
		mode,
		throttle: Duration::from_millis(500),
	}
}

