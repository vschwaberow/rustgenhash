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
pub mod warnings;

use self::warnings::{section_for_summary, WarningRenderStyle};

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
	#[serde(default)]
	pub runtime_planned_seconds: Option<f64>,
	#[serde(default)]
	pub runtime_planned_iterations: Option<u64>,
	#[serde(default)]
	pub runtime_actual_seconds: Option<f64>,
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
			runtime_planned_seconds: None,
			runtime_planned_iterations: None,
			runtime_actual_seconds: None,
		})
	}

	pub fn validate(&self) -> Result<(), BenchmarkError> {
		for case in &self.cases {
			case.validate()?;
		}
		Ok(())
	}

	pub fn set_runtime_metadata(
		&mut self,
		planned_seconds: Option<f64>,
		planned_iterations: Option<u64>,
		actual_seconds: Option<f64>,
	) {
		self.runtime_planned_seconds = planned_seconds;
		self.runtime_planned_iterations = planned_iterations;
		self.runtime_actual_seconds = actual_seconds;
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

#[derive(Debug, Clone)]
pub struct BenchmarkBannerContext {
	pub mode: BenchmarkMode,
	pub duration_seconds: u64,
	pub iterations: Option<u64>,
	pub payload_bytes: Option<usize>,
}

impl BenchmarkBannerContext {
	pub fn from_scenario(scenario: &BenchmarkScenario) -> Self {
		Self {
			mode: scenario.mode,
			duration_seconds: scenario.duration_seconds,
			iterations: scenario.iterations,
			payload_bytes: None,
		}
	}

	pub fn with_payload_bytes(
		mut self,
		payload_bytes: Option<usize>,
	) -> Self {
		self.payload_bytes = payload_bytes;
		self
	}

	pub fn metadata_fragments(&self) -> Vec<String> {
		let mut fragments =
			vec![format!("duration {}s", self.duration_seconds)];
		let iterations = self
			.iterations
			.map(|value| format!("iterations {}", value))
			.unwrap_or_else(|| "iterations auto".to_string());
		fragments.push(iterations);
		if let Some(bytes) = self.payload_bytes {
			fragments.push(format!("payload {} bytes", bytes));
		}
		fragments
	}

	pub fn formatted_context(&self) -> String {
		self.metadata_fragments().join(", ")
	}
}

pub fn benchmark_mode_label(mode: BenchmarkMode) -> &'static str {
	match mode {
		BenchmarkMode::Digest => "Digest",
		BenchmarkMode::Mac => "MAC",
		BenchmarkMode::Kdf => "KDF",
	}
}

pub fn format_benchmark_banner(
	context: &BenchmarkBannerContext,
) -> String {
	let label = match context.mode {
		BenchmarkMode::Digest => "Digest Benchmarks",
		BenchmarkMode::Mac => "MAC Benchmarks",
		BenchmarkMode::Kdf => "KDF Benchmarks",
	};
	let context_line = context.formatted_context();
	if context_line.is_empty() {
		format!("=== {} ===", label)
	} else {
		format!("=== {} ({}) ===", label, context_line)
	}
}

pub fn format_summary_banner(mode: BenchmarkMode) -> String {
	format!(
		"=== Benchmark Summary: {} ===",
		benchmark_mode_label(mode)
	)
}

pub fn format_markdown_banner_line(line: &str) -> String {
	format!("> {}", line)
}

fn format_seconds(value: f64) -> String {
	format!("{value:.1}s")
}

fn runtime_planned_seconds(
	summary: &BenchmarkSummary,
) -> Option<f64> {
	if let Some(seconds) = summary.runtime_planned_seconds {
		Some(seconds)
	} else if summary.runtime_planned_iterations.is_none()
		&& summary.scenario.iterations.is_none()
	{
		Some(summary.scenario.duration_seconds as f64)
	} else {
		None
	}
}

pub fn runtime_banner_line(summary: &BenchmarkSummary) -> String {
	let planned_text =
		if let Some(seconds) = summary.runtime_planned_seconds {
			format!("Planned {}", format_seconds(seconds))
		} else if let Some(iterations) = summary
			.runtime_planned_iterations
			.or(summary.scenario.iterations)
		{
			format!("Planned iterations {}", iterations)
		} else {
			"Planned unknown".to_string()
		};

	let actual_text =
		if let Some(seconds) = summary.runtime_actual_seconds {
			format!("Actual {}", format_seconds(seconds))
		} else {
			"Actual unknown".to_string()
		};

	let delta_text = if let (Some(actual), Some(planned)) = (
		summary.runtime_actual_seconds,
		runtime_planned_seconds(summary),
	) {
		let diff = actual - planned;
		let sign = if diff >= 0.0 { "+" } else { "" };
		Some(format!(" ({}{:.1}s)", sign, diff))
	} else {
		None
	};

	format!(
		"{} · {}{}",
		planned_text,
		actual_text,
		delta_text.unwrap_or_default()
	)
}

pub const SUMMARY_TABLE_COLUMNS: &[BenchmarkColumnFormat] = &[
	BenchmarkColumnFormat::new(
		"Algorithm",
		ColumnAlignment::Left,
		None,
	),
	BenchmarkColumnFormat::new(
		"Samples",
		ColumnAlignment::Right,
		None,
	),
	BenchmarkColumnFormat::new(
		"Ops/sec (kops)",
		ColumnAlignment::Right,
		Some(MetricKind::Throughput),
	),
	BenchmarkColumnFormat::new(
		"Median ms",
		ColumnAlignment::Right,
		Some(MetricKind::Latency),
	),
	BenchmarkColumnFormat::new(
		"P95 ms",
		ColumnAlignment::Right,
		Some(MetricKind::Latency),
	),
	BenchmarkColumnFormat::new(
		"Status",
		ColumnAlignment::Right,
		None,
	),
];

pub fn default_duration() -> Duration {
	Duration::from_secs(DEFAULT_DURATION_SECONDS)
}

#[derive(Debug, Clone, Copy)]
pub enum MetricKind {
	Throughput,
	Latency,
}

impl MetricKind {
	pub fn scale_factor(self) -> f64 {
		match self {
			Self::Throughput => 1e-3, // ops/sec -> kops/s
			Self::Latency => 1.0,
		}
	}

	pub fn precision(self) -> usize {
		match self {
			Self::Throughput => 2,
			Self::Latency => 3,
		}
	}

	pub fn unit_suffix(self) -> &'static str {
		match self {
			Self::Throughput => " kops/s",
			Self::Latency => " ms",
		}
	}
}

#[derive(Debug, Clone, Copy)]
pub enum ColumnAlignment {
	Left,
	Right,
}

#[derive(Debug, Clone, Copy)]
pub struct BenchmarkColumnFormat {
	pub title: &'static str,
	pub alignment: ColumnAlignment,
	pub metric: Option<MetricKind>,
}

impl BenchmarkColumnFormat {
	pub const fn new(
		title: &'static str,
		alignment: ColumnAlignment,
		metric: Option<MetricKind>,
	) -> Self {
		Self {
			title,
			alignment,
			metric,
		}
	}
}

pub fn format_metric(value: f64, kind: MetricKind) -> String {
	let scaled = value * kind.scale_factor();
	let precision = kind.precision();
	let suffix = kind.unit_suffix();
	format!(
		"{scaled:.prec$}{suffix}",
		scaled = scaled,
		prec = precision,
		suffix = suffix,
	)
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
		.map_err(|err| {
			BenchmarkError::Io(io::Error::other(err.to_string()))
		})?;
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
	let banner = format_summary_banner(summary.scenario.mode);
	let _ = writeln!(out, "{}", banner);
	let _ = writeln!(out);
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
	if summary.runtime_planned_seconds.is_some()
		|| summary.runtime_planned_iterations.is_some()
		|| summary.runtime_actual_seconds.is_some()
	{
		let _ = writeln!(out, "{}", runtime_banner_line(summary));
	}
	let _ = writeln!(out);
	let _ = writeln!(
		out,
		"{:<18} {:>8} {:>18} {:>14} {:>14} {:>8}  Notes",
		"Algorithm",
		"Samples",
		"Ops/sec (kops)",
		"Median ms",
		"P95 ms",
		"Status",
	);
	let _ = writeln!(out, "{}", "-".repeat(110));
	for case in sorted_cases(summary) {
		let throughput = format_metric(
			case.avg_ops_per_sec,
			MetricKind::Throughput,
		);
		let median = format_metric(
			case.median_latency_ms,
			MetricKind::Latency,
		);
		let p95 =
			format_metric(case.p95_latency_ms, MetricKind::Latency);
		let _ = writeln!(
			out,
			"{:<18} {:>8} {:>18} {:>14} {:>14} {:>8}  {}",
			case.algorithm,
			case.samples_collected,
			throughput,
			median,
			p95,
			compliance_badge(case),
			case.notes.as_deref().unwrap_or("-"),
		);
	}
	let warnings_section =
		section_for_summary(summary, WarningRenderStyle::Console);
	if !warnings_section.is_empty() {
		let _ = writeln!(out);
		let _ = writeln!(out, "{}", warnings_section.heading());
		for line in warnings_section.render_lines() {
			let _ = writeln!(out, "{}", line);
		}
	}
	out
}

pub fn render_markdown_summary(summary: &BenchmarkSummary) -> String {
	let mut lines = Vec::new();
	let banner = format_markdown_banner_line(&format_summary_banner(
		summary.scenario.mode,
	));
	lines.push(banner);
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
	if summary.runtime_planned_seconds.is_some()
		|| summary.runtime_planned_iterations.is_some()
		|| summary.runtime_actual_seconds.is_some()
	{
		lines.push(format!("> {}", runtime_banner_line(summary)));
	}
	lines.push(String::new());
	lines.push("| Algorithm | Profile | Ops/sec (kops) | Median ms | P95 ms | Samples | Status | Notes |".to_string());
	lines.push("|-----------|---------|----------------|-----------|--------|---------|--------|-------|".to_string());
	for case in sorted_cases(summary) {
		let profile = case.profile.as_deref().unwrap_or("—");
		let mut note =
			case.notes.clone().unwrap_or_else(|| "—".into());
		if note.trim().is_empty() {
			note = "—".into();
		}
		let sanitized_note =
			note.replace('|', "\\|").replace('\n', "<br>");
		let throughput = format_metric(
			case.avg_ops_per_sec,
			MetricKind::Throughput,
		);
		let median = format_metric(
			case.median_latency_ms,
			MetricKind::Latency,
		);
		let p95 =
			format_metric(case.p95_latency_ms, MetricKind::Latency);
		lines.push(format!(
			"| {} | {} | {} | {} | {} | {} | {} | {} |",
			case.algorithm,
			profile,
			throughput,
			median,
			p95,
			case.samples_collected,
			compliance_badge(case),
			sanitized_note
		));
	}
	lines.push(String::new());
	let warnings_section =
		section_for_summary(summary, WarningRenderStyle::Markdown);
	if !warnings_section.is_empty() {
		lines.push(warnings_section.heading().to_string());
		lines.extend(warnings_section.render_lines());
	}
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
