// SPDX-License-Identifier: MIT OR Apache-2.0
// Project: rustgenhash

use crate::rgh::benchmark::{
	self,
	digest_benchmark_presets,
	kdf_benchmark_presets,
	render_digest_report,
	run_digest_benchmarks,
	BenchmarkError,
	BenchmarkMode,
	SharedBenchmarkArgs,
	DEFAULT_MAC_MESSAGE_BYTES,
};
use crate::rgh::cli::algorithms::Algorithm;
use crate::rgh::cli::parser::{
	collect_profile_overrides, parse_duration_arg, parse_hkdf_inputs,
};
use clap::builder::ValueParser;
use clap::{Arg, ArgAction};
use std::collections::BTreeMap;
use std::error::Error;
use std::path::PathBuf;
use std::time::Duration;

pub fn mac_benchmark_subcommand() -> clap::Command {
	benchmark_family_subcommand(
		"mac",
		"Benchmark MAC algorithms (Poly1305, HMAC, CMAC, etc.)",
	)
	.arg(
		Arg::new("message-bytes")
			.long("message-bytes")
			.value_name("BYTES")
			.value_parser(clap::value_parser!(usize))
			.default_value("1024")
			.help(
				"Payload size per sample (default 1024 bytes, range 64-1048576)",
			),
	)
	.after_help(
		concat!(
			"Example: rgh benchmark mac --alg poly1305 --alg hmac-sha256 --duration 5s --output target/benchmark/mac.json\n",
			"\n",
			"Console output now begins with a banner line (e.g. === MAC Benchmarks (...) ===), shows the runtime banner (Planned vs Actual), and labels columns with fixed units (Ops/sec in kops/s, latency in ms). ",
			"A dedicated `Warnings` section lists weak/legacy algorithms once per run; inline warning rows have been removed. ",
			"Use --json when you need banner-free, warning-free machine-readable output for scripts."
		),
	)
}

pub fn kdf_benchmark_subcommand() -> clap::Command {
	benchmark_family_subcommand(
		"kdf",
		"Benchmark password-based KDF algorithms (PBKDF2, scrypt, HKDF)",
	)
	.arg(
		Arg::new("profile")
			.long("profile")
			.value_name("PROFILE")
			.action(ArgAction::Append)
			.help(
				"Profile assignment (e.g. --profile pbkdf2=nist-sp800-132-2023)",
			),
	)
	.arg(
		Arg::new("salt")
			.long("salt")
			.value_name("HEX")
			.help("Hex-encoded HKDF salt (required when benchmarking HKDF)"),
	)
	.arg(
		Arg::new("info")
			.long("info")
			.value_name("HEX")
			.help("Hex-encoded HKDF info/context (required for HKDF)"),
	)
	.arg(
		Arg::new("ikm")
			.long("ikm")
			.value_name("HEX")
			.help("Hex-encoded HKDF input keying material"),
	)
	.arg(
		Arg::new("ikm-stdin")
			.long("ikm-stdin")
			.action(ArgAction::SetTrue)
			.conflicts_with("ikm")
			.help("Read HKDF IKM bytes from stdin"),
	)
	.arg(
		Arg::new("prk")
			.long("prk")
			.value_name("HEX")
			.help("Hex-encoded HKDF PRK for expand-only variants"),
	)
	.arg(
		Arg::new("prk-stdin")
			.long("prk-stdin")
			.action(ArgAction::SetTrue)
			.conflicts_with("prk")
			.conflicts_with("ikm-stdin")
			.help("Read HKDF PRK bytes from stdin"),
	)
	.arg(
		Arg::new("length")
			.long("length")
			.value_name("BYTES")
			.value_parser(clap::value_parser!(usize))
			.help("HKDF output length in bytes (defaults to variant length)"),
	)
	.after_help(
		"Console output begins with a banner line (e.g. === KDF Benchmarks (...) ===), shows the runtime banner (Planned vs Actual), reports throughput/latency with explicit units (kops/s, ms), and concludes with a single `Warnings` block whenever profile guidance or sample-count warnings fire. Use --json to suppress banners, warnings, and unitized text when piping results."
	)
}

pub fn summarize_benchmark_subcommand() -> clap::Command {
	clap::command!("summarize")
		.about("Summarize benchmark JSON output")
		.arg(
			Arg::new("input")
				.short('i')
				.long("input")
				.value_name("PATH")
				.required(true)
				.help("Path to a benchmark summary JSON file produced by --output"),
		)
		.arg(
			Arg::new("format")
				.short('f')
				.long("format")
				.value_name("FORMAT")
				.value_parser(["console", "markdown"])
				.default_value("console")
				.help("Output format: console (default) or markdown"),
		)
		.after_help(
			"Console + Markdown summaries mirror the runtime banner and append a grouped `Warnings` section after the table (one bullet per algorithm) so evidence stays readable; use the original JSON when you need raw manifests."
	)
}

fn benchmark_family_subcommand(
	name: &'static str,
	about: &'static str,
) -> clap::Command {
	let command = clap::Command::new(name).about(about).arg(
		Arg::new("alg")
			.long("alg")
			.short('a')
			.value_name("ALGORITHM")
			.action(ArgAction::Append)
			.help(
				"Algorithm identifier (repeat for multiple entries, e.g. --alg poly1305)",
			),
	);
	attach_shared_benchmark_args(command)
}

fn attach_shared_benchmark_args(
	command: clap::Command,
) -> clap::Command {
	command
		.arg(
			Arg::new("duration")
				.long("duration")
				.value_name("DURATION")
				.value_parser(ValueParser::new(parse_duration_arg))
				.conflicts_with("iterations")
				.help("Time window per algorithm (e.g. 5s, 2m)"),
		)
		.arg(
			Arg::new("iterations")
				.long("iterations")
				.value_name("COUNT")
				.value_parser(clap::value_parser!(u64).range(1..))
				.help("Override iteration count for each algorithm"),
		)
		.arg(
			Arg::new("json")
				.long("json")
				.action(ArgAction::SetTrue)
				.help("Emit JSON summary to stdout"),
		)
		.arg(
			Arg::new("output")
				.long("output")
				.value_name("PATH")
				.value_parser(clap::value_parser!(PathBuf))
				.help("Write JSON summary to file"),
		)
		.arg(
			Arg::new("list-algorithms")
				.long("list-algorithms")
				.action(ArgAction::SetTrue)
				.help(
					"List supported algorithms for the selected mode and exit",
				),
		)
		.arg(
			Arg::new("yes")
				.long("yes")
				.action(ArgAction::SetTrue)
				.help("Skip runtime confirmation prompt"),
		)
}

pub fn run_benchmark_family(
	mode: BenchmarkMode,
	matches: &clap::ArgMatches,
) -> Result<(), Box<dyn Error>> {
	if matches.get_flag("list-algorithms") {
		benchmark::print_supported_algorithms(mode);
		return Ok(());
	}

	let algorithms: Vec<String> = matches
		.get_many::<String>("alg")
		.map(|values| values.cloned().collect())
		.unwrap_or_default();

	let mut shared = SharedBenchmarkArgs {
		duration: matches.get_one::<Duration>("duration").copied(),
		iterations: matches.get_one::<u64>("iterations").copied(),
		json: matches.get_flag("json"),
		output_path: matches.get_one::<PathBuf>("output").cloned(),
		auto_confirm: matches.get_flag("yes"),
		message_bytes: None,
		profile_overrides: BTreeMap::new(),
		hkdf_inputs: None,
	};

	if let BenchmarkMode::Mac = mode {
		let payload = matches
			.get_one::<usize>("message-bytes")
			.copied()
			.unwrap_or(DEFAULT_MAC_MESSAGE_BYTES);
		shared.message_bytes = Some(payload);
	} else if let BenchmarkMode::Kdf = mode {
		let canonical_algs = algorithms
			.iter()
			.map(|alg| benchmark::kdf::canonical_algorithm_id(alg))
			.collect::<Result<Vec<_>, _>>()
			.map_err(|err| Box::new(err) as Box<dyn Error>)?;
		shared.profile_overrides =
			collect_profile_overrides(matches, &canonical_algs)
				.map_err(|err| Box::new(err) as Box<dyn Error>)?;
		shared.hkdf_inputs = parse_hkdf_inputs(matches)
				.map_err(|err| Box::new(err) as Box<dyn Error>)?;
	}

	match benchmark::execute_named_mode(mode, algorithms, &shared) {
		Ok(summary) => {
			match mode {
				BenchmarkMode::Mac => {
					if !shared.json {
						let payload =
							shared
								.message_bytes
								.unwrap_or(DEFAULT_MAC_MESSAGE_BYTES);
						benchmark::mac::print_mac_report(
								&summary,
								payload,
						);
					}
				}
				BenchmarkMode::Kdf => {
					if !shared.json {
						benchmark::kdf::print_kdf_report(&summary);
					}
				}
				BenchmarkMode::Digest => {
					if !shared.json {
						println!(
							"Completed {} benchmark with {} case(s)",
							mode,
							summary.cases.len()
						);
					}
				}
			}
			let emit_stdout_json =
				shared.json && shared.output_path.is_none();
			benchmark::write_summary_outputs(
				&summary,
				emit_stdout_json,
				shared.output_path.as_deref(),
			)?;
		}
		Err(BenchmarkError::UserAborted) => {}
		Err(err) => return Err(Box::new(err)),
	}

	Ok(())
}

pub fn run_benchmark_summary(
	matches: &clap::ArgMatches,
) -> Result<(), Box<dyn Error>> {
	let input = matches
		.get_one::<String>("input")
		.expect("input is required");
	let path = PathBuf::from(input);
	let summary = benchmark::load_summary_from_path(&path)
		.map_err(|err| Box::new(err) as Box<dyn Error>)?;
	let format = matches
		.get_one::<String>("format")
		.map(|value| value.as_str())
		.unwrap_or("console");
	match format {
		"markdown" => {
			println!(
				"{}",
				benchmark::render_markdown_summary(&summary)
			);
		}
		_ => {
			println!(
				"{}",
				benchmark::render_console_summary(&summary, &path),
			);
		}
	}
	Ok(())
}
