// SPDX-License-Identifier: MIT OR Apache-2.0
// Project: rustgenhash
// File: benchmark/mod.rs
// Author: Volker Schwaberow <volker@schwaberow.de>
// Copyright (c) 2025

use chrono::{DateTime, Utc};
use dialoguer::Confirm;
use serde::{Deserialize, Serialize};
use std::cmp::Ordering;
use std::collections::BTreeMap;
use std::error::Error;
use std::fmt::{self, Write};
use std::fs;
use std::io;
use std::path::{Path, PathBuf};
use std::time::Duration;
use zeroize::Zeroizing;

pub mod digest;
pub mod kdf;
pub mod mac;

pub use digest::{
	digest_benchmark_presets, kdf_benchmark_presets,
	render_digest_report, run_digest_benchmarks,
};

pub const DEFAULT_DURATION_SECONDS: u64 = 5;
pub const MAX_DURATION_SECONDS: u64 = 15 * 60;
pub const DEFAULT_MAC_MESSAGE_BYTES: usize = 1024;
pub const MIN_MAC_MESSAGE_BYTES: usize = 64;
pub const MAX_MAC_MESSAGE_BYTES: usize = 1024 * 1024;
pub const KDF_SAMPLE_TARGET: u64 = 30;

#[derive(
	Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize,
)]
#[serde(rename_all = "lowercase")]
pub enum BenchmarkMode {
	Digest,
	Mac,
	Kdf,
}

impl fmt::Display for BenchmarkMode {
	fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
		let label = match self {
			BenchmarkMode::Digest => "digest",
			BenchmarkMode::Mac => "mac",
			BenchmarkMode::Kdf => "kdf",
		};
		write!(f, "{}", label)
	}
}

#[derive(Debug)]
pub enum BenchmarkError {
	Validation(String),
	Io(io::Error),
	Encoding(String),
	NotImplemented(&'static str),
	UserAborted,
}

impl BenchmarkError {
	pub fn validation(message: impl Into<String>) -> Self {
		Self::Validation(message.into())
	}
}

impl fmt::Display for BenchmarkError {
	fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
		match self {
			BenchmarkError::Validation(msg) => write!(f, "{}", msg),
			BenchmarkError::Io(err) => write!(f, "{}", err),
			BenchmarkError::Encoding(msg) => write!(f, "{}", msg),
			BenchmarkError::NotImplemented(msg) => {
				write!(f, "{}", msg)
			}
			BenchmarkError::UserAborted => {
				write!(f, "benchmark execution cancelled")
			}
		}
	}
}

impl Error for BenchmarkError {
	fn source(&self) -> Option<&(dyn Error + 'static)> {
		match self {
			BenchmarkError::Io(err) => Some(err),
			_ => None,
		}
	}
}

impl From<io::Error> for BenchmarkError {
	fn from(value: io::Error) -> Self {
		Self::Io(value)
	}
}

impl From<serde_json::Error> for BenchmarkError {
	fn from(value: serde_json::Error) -> Self {
		Self::Encoding(value.to_string())
	}
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BenchmarkScenario {
	pub mode: BenchmarkMode,
	pub algorithms: Vec<String>,
	pub duration_seconds: u64,
	pub iterations: Option<u64>,
	pub profiles: BTreeMap<String, String>,
	pub output_path: Option<PathBuf>,
	pub stdin_required: bool,
	pub created_at: DateTime<Utc>,
}

impl BenchmarkScenario {
	pub fn new(
		mode: BenchmarkMode,
		algorithms: Vec<String>,
		duration_seconds: u64,
		iterations: Option<u64>,
		output_path: Option<PathBuf>,
		stdin_required: bool,
	) -> Result<Self, BenchmarkError> {
		if algorithms.is_empty() {
			return Err(BenchmarkError::validation(
				"at least one algorithm must be specified",
			));
		}
		if duration_seconds == 0 {
			return Err(BenchmarkError::validation(
				"duration must be at least one second",
			));
		}
		if duration_seconds > MAX_DURATION_SECONDS {
			return Err(BenchmarkError::validation(format!(
				"duration exceeds {} second safety cap",
				MAX_DURATION_SECONDS
			)));
		}
		Ok(Self {
			mode,
			algorithms,
			duration_seconds,
			iterations,
			profiles: BTreeMap::new(),
			output_path,
			stdin_required,
			created_at: Utc::now(),
		})
	}
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BenchmarkResult {
	pub algorithm: String,
	pub profile: Option<String>,
	pub samples_collected: u64,
	pub avg_ops_per_sec: f64,
	pub median_latency_ms: f64,
	pub p95_latency_ms: f64,
	pub compliance: bool,
	pub warnings: Vec<String>,
	pub notes: Option<String>,
}

impl BenchmarkResult {
	pub fn validate(&self) -> Result<(), BenchmarkError> {
		if self.algorithm.trim().is_empty() {
			return Err(BenchmarkError::validation(
				"result is missing algorithm identifier",
			));
		}
		if self.samples_collected == 0 {
			return Err(BenchmarkError::validation(
				"result is missing samples",
			));
		}
		if !(self.avg_ops_per_sec.is_finite()
			&& self.avg_ops_per_sec > 0.0)
		{
			return Err(BenchmarkError::validation(
				"avg_ops_per_sec must be > 0",
			));
		}
		if !(self.median_latency_ms.is_finite()
			&& self.median_latency_ms > 0.0)
		{
			return Err(BenchmarkError::validation(
				"median_latency_ms must be > 0",
			));
		}
		if !(self.p95_latency_ms.is_finite()
			&& self.p95_latency_ms > 0.0)
		{
			return Err(BenchmarkError::validation(
				"p95_latency_ms must be > 0",
			));
		}
		Ok(())
	}
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct BenchmarkEnvironment {
	pub hostname: Option<String>,
	pub os: Option<String>,
	pub cpu: Option<String>,
	pub tool_version: Option<String>,
}

impl BenchmarkEnvironment {
	pub fn detect() -> Self {
		let hostname = std::env::var("HOSTNAME")
			.or_else(|_| std::env::var("COMPUTERNAME"))
			.ok();
		Self {
			hostname,
			os: Some(std::env::consts::OS.to_string()),
			cpu: Some(std::env::consts::ARCH.to_string()),
			tool_version: Some(env!("CARGO_PKG_VERSION").to_string()),
		}
	}
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BenchmarkSummary {
	pub scenario: BenchmarkScenario,
	pub cases: Vec<BenchmarkResult>,
	pub environment: Option<BenchmarkEnvironment>,
}

impl BenchmarkSummary {
	pub fn new(
		scenario: BenchmarkScenario,
		cases: Vec<BenchmarkResult>,
	) -> Result<Self, BenchmarkError> {
		for case in &cases {
			case.validate()?;
		}
		Ok(Self {
			scenario,
			cases,
			environment: Some(BenchmarkEnvironment::detect()),
		})
	}

	pub fn validate(&self) -> Result<(), BenchmarkError> {
		for case in &self.cases {
			case.validate()?;
		}
		Ok(())
	}
}

#[derive(Debug, Clone, Default)]
pub struct SharedBenchmarkArgs {
	pub duration: Option<Duration>,
	pub iterations: Option<u64>,
	pub json: bool,
	pub output_path: Option<PathBuf>,
	pub auto_confirm: bool,
	pub message_bytes: Option<usize>,
	pub profile_overrides: BTreeMap<String, String>,
	pub hkdf_inputs: Option<HkdfInputMaterial>,
}

impl SharedBenchmarkArgs {
	pub fn validate(&self) -> Result<(), BenchmarkError> {
		if self.duration.is_some() && self.iterations.is_some() {
			return Err(BenchmarkError::validation(
				"use either --duration or --iterations, not both",
			));
		}
		if let Some(bytes) = self.message_bytes {
			if !(MIN_MAC_MESSAGE_BYTES..=MAX_MAC_MESSAGE_BYTES)
				.contains(&bytes)
			{
				return Err(BenchmarkError::validation(format!(
					"--message-bytes must be between {} and {} bytes",
					MIN_MAC_MESSAGE_BYTES, MAX_MAC_MESSAGE_BYTES
				)));
			}
		}
		Ok(())
	}

	pub fn effective_duration(&self) -> Duration {
		self.duration.unwrap_or_else(|| {
			Duration::from_secs(DEFAULT_DURATION_SECONDS)
		})
	}
}

pub fn default_duration() -> Duration {
	Duration::from_secs(DEFAULT_DURATION_SECONDS)
}

pub fn list_supported_algorithms(mode: BenchmarkMode) -> Vec<String> {
	match mode {
		BenchmarkMode::Digest => digest::algorithm_catalog(),
		BenchmarkMode::Mac => mac::supported_algorithms(),
		BenchmarkMode::Kdf => kdf::supported_algorithms(),
	}
}

pub fn print_supported_algorithms(mode: BenchmarkMode) {
	let mut entries = list_supported_algorithms(mode);
	entries.sort();
	for entry in entries {
		println!("{}", entry);
	}
}

pub fn estimate_total_runtime(
	algorithm_count: usize,
	duration_per_algorithm: Duration,
) -> Duration {
	let secs = duration_per_algorithm.as_secs().max(1);
	Duration::from_secs(secs.saturating_mul(algorithm_count as u64))
}

pub fn format_runtime(duration: Duration) -> String {
	let total_secs = duration.as_secs();
	let minutes = total_secs / 60;
	let seconds = total_secs % 60;
	if minutes == 0 {
		format!("{}s", seconds)
	} else {
		format!("{}m {}s", minutes, seconds)
	}
}

pub fn confirm_runtime(
	mode: BenchmarkMode,
	algorithm_count: usize,
	duration_per_algorithm: Duration,
	auto_confirm: bool,
) -> Result<(), BenchmarkError> {
	if auto_confirm {
		return Ok(());
	}
	let estimate = estimate_total_runtime(
		algorithm_count,
		duration_per_algorithm,
	);
	let prompt = format!(
		"Run {} {} benchmark{} (~{})?",
		algorithm_count,
		mode,
		if algorithm_count == 1 { "" } else { "s" },
		format_runtime(estimate)
	);
	let confirmed = Confirm::new()
		.with_prompt(prompt)
		.default(true)
		.interact()
		.map_err(|err| BenchmarkError::Io(io::Error::other(err.to_string())))?;
	if confirmed {
		Ok(())
	} else {
		Err(BenchmarkError::UserAborted)
	}
}

pub fn write_summary_outputs(
	summary: &BenchmarkSummary,
	json_stdout: bool,
	output_path: Option<&Path>,
) -> Result<(), BenchmarkError> {
	summary.validate()?;
	if !json_stdout && output_path.is_none() {
		return Ok(());
	}
	let payload = serde_json::to_string_pretty(summary)?;
	if json_stdout {
		println!("{}", payload);
	}
	if let Some(path) = output_path {
		if let Some(parent) = path.parent() {
			fs::create_dir_all(parent)?;
		}
		fs::write(path, &payload)?;
		println!("Wrote benchmark summary to {}", path.display());
	}
	Ok(())
}

pub fn execute_named_mode(
	mode: BenchmarkMode,
	mut algorithms: Vec<String>,
	shared: &SharedBenchmarkArgs,
) -> Result<BenchmarkSummary, BenchmarkError> {
	shared.validate()?;
	if algorithms.is_empty() {
		algorithms = list_supported_algorithms(mode);
	}
	if algorithms.is_empty() {
		return Err(BenchmarkError::validation(format!(
			"no {} algorithms available",
			mode
		)));
	}
	let duration = shared.effective_duration();
	confirm_runtime(
		mode,
		algorithms.len(),
		duration,
		shared.auto_confirm,
	)?;
	let scenario = BenchmarkScenario::new(
		mode,
		algorithms.clone(),
		duration.as_secs().max(1),
		shared.iterations,
		shared.output_path.clone(),
		false,
	)?;
	match mode {
		BenchmarkMode::Mac => {
			mac::run_mac_benchmarks(scenario, shared)
		}
		BenchmarkMode::Kdf => {
			let mut scenario = scenario;
			scenario.profiles = shared.profile_overrides.clone();
			kdf::run_kdf_benchmarks(scenario, shared)
		}
		BenchmarkMode::Digest => Err(BenchmarkError::validation(
			"use legacy digest entrypoint for digest benchmarks",
		)),
	}
}

#[derive(Debug, Clone, Default)]
pub struct HkdfInputMaterial {
	pub salt: Option<Vec<u8>>,
	pub info: Option<Vec<u8>>,
	pub ikm: Option<Zeroizing<Vec<u8>>>,
	pub prk: Option<Zeroizing<Vec<u8>>>,
	pub length: Option<usize>,
}

pub fn load_summary_from_path(
	path: &Path,
) -> Result<BenchmarkSummary, BenchmarkError> {
	let data = fs::read_to_string(path)?;
	let summary: BenchmarkSummary = serde_json::from_str(&data)?;
	summary.validate()?;
	Ok(summary)
}

pub fn render_console_summary(
	summary: &BenchmarkSummary,
	source_path: &Path,
) -> String {
	let mut out = String::new();
	let algorithms = if summary.scenario.algorithms.is_empty() {
		"(not recorded)".to_string()
	} else {
		summary.scenario.algorithms.join(", ")
	};
	let iterations = summary
		.scenario
		.iterations
		.map(|value| value.to_string())
		.unwrap_or_else(|| "auto".to_string());
	let _ = writeln!(
		out,
		"Benchmark summary from {}",
		source_path.display()
	);
	let _ = writeln!(
		out,
		"  Mode: {} · Duration: {}s · Iterations: {}",
		summary.scenario.mode,
		summary.scenario.duration_seconds,
		iterations
	);
	let _ = writeln!(out, "  Algorithms: {}", algorithms);
	if !summary.scenario.profiles.is_empty() {
		let _ = writeln!(out, "  Profiles:");
		for (alg, profile) in &summary.scenario.profiles {
			let _ = writeln!(out, "    - {} → {}", alg, profile);
		}
	}
	if let Some(env) = &summary.environment {
		let _ = writeln!(out, "  Environment:");
		if let Some(host) = &env.hostname {
			let _ = writeln!(out, "    Host: {}", host);
		}
		if let Some(os) = &env.os {
			let _ = writeln!(out, "    OS: {}", os);
		}
		if let Some(cpu) = &env.cpu {
			let _ = writeln!(out, "    CPU: {}", cpu);
		}
		if let Some(version) = &env.tool_version {
			let _ = writeln!(out, "    Tool: rgh {}", version);
		}
	}
	let _ = writeln!(out);
	let _ = writeln!(
		out,
		"{:<18} {:>8} {:>12} {:>12} {:>12} {:>8}  Notes",
		"Algorithm",
		"Samples",
		"Ops/sec",
		"Median ms",
		"P95 ms",
		"Status",
	);
	let _ = writeln!(out, "{}", "-".repeat(90));
	for case in sorted_cases(summary) {
		let _ = writeln!(
			out,
			"{:<18} {:>8} {:>12.2} {:>12.3} {:>12.3} {:>8}  {}",
			case.algorithm,
			case.samples_collected,
			case.avg_ops_per_sec,
			case.median_latency_ms,
			case.p95_latency_ms,
			compliance_badge(case),
			case.notes.as_deref().unwrap_or("-"),
		);
		for warning in &case.warnings {
			let _ = writeln!(out, "    warning: {}", warning);
		}
	}
	out
}

pub fn render_markdown_summary(summary: &BenchmarkSummary) -> String {
	let mut lines = Vec::new();
	let iterations = summary
		.scenario
		.iterations
		.map(|val| val.to_string())
		.unwrap_or_else(|| "auto".to_string());
	lines.push(format!(
		"> Mode: {} · Duration: {}s · Iterations: {}",
		summary.scenario.mode,
		summary.scenario.duration_seconds,
		iterations
	));
	lines.push(format!(
		"> Created at {}",
		summary.scenario.created_at.to_rfc3339()
	));
	if let Some(env) = &summary.environment {
		let mut env_bits = Vec::new();
		if let Some(host) = &env.hostname {
			env_bits.push(format!("host: {}", host));
		}
		if let Some(os) = &env.os {
			env_bits.push(format!("os: {}", os));
		}
		if let Some(cpu) = &env.cpu {
			env_bits.push(format!("cpu: {}", cpu));
		}
		if let Some(version) = &env.tool_version {
			env_bits.push(format!("rgh {}", version));
		}
		if !env_bits.is_empty() {
			lines.push(format!(
				"> Environment {}",
				env_bits.join(" · ")
			));
		}
	}
	lines.push(String::new());
	lines.push("| Algorithm | Profile | Ops/sec | Median ms | Samples | Status | Notes |".to_string());
	lines.push("|-----------|---------|---------|-----------|---------|--------|-------|".to_string());
	for case in sorted_cases(summary) {
		let profile = case.profile.as_deref().unwrap_or("—");
		let mut note =
			case.notes.clone().unwrap_or_else(|| "—".into());
		if !case.warnings.is_empty() {
			if note == "—" {
				note.clear();
			}
			if !note.is_empty() {
				note.push(' ');
			}
			note.push_str(&case.warnings.join(" / "));
		}
		if note.is_empty() {
			note.push('—');
		}
		let sanitized_note =
			note.replace('|', "\\|").replace('\n', "<br>");
		lines.push(format!(
			"| {} | {} | {:.2} | {:.3} | {} | {} | {} |",
			case.algorithm,
			profile,
			case.avg_ops_per_sec,
			case.median_latency_ms,
			case.samples_collected,
			compliance_badge(case),
			sanitized_note
		));
	}
	lines.push(String::new());
	lines.join("\n")
}

fn sorted_cases(summary: &BenchmarkSummary) -> Vec<&BenchmarkResult> {
	let mut rows = summary.cases.iter().collect::<Vec<_>>();
	match summary.scenario.mode {
		BenchmarkMode::Mac | BenchmarkMode::Digest => {
			rows.sort_by(|a, b| {
				b.avg_ops_per_sec
					.partial_cmp(&a.avg_ops_per_sec)
					.unwrap_or(Ordering::Equal)
			})
		}
		BenchmarkMode::Kdf => rows.sort_by(|a, b| {
			a.median_latency_ms
				.partial_cmp(&b.median_latency_ms)
				.unwrap_or(Ordering::Equal)
		}),
	}
	rows
}

fn compliance_badge(case: &BenchmarkResult) -> &'static str {
	if case.compliance {
		"✅ PASS"
	} else {
		"⚠ WARN"
	}
}
