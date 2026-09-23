// SPDX-License-Identifier: MIT OR Apache-2.0
// Project: rustgenhash
// File: app/mod.rs

mod cli;
mod digest;
mod kdf;
mod mac;

pub use crate::rgh::cli::algorithms::Algorithm;
pub(crate) use cli::{build_cli, render_help_for_path};

use crate::rgh::analyze::{compare_hashes, HashAnalyzer};
use crate::rgh::benchmark::{
	digest_benchmark_presets, kdf_benchmark_presets,
	render_digest_report, run_digest_benchmarks, BenchmarkMode,
};
use crate::rgh::cli::benchmark::{
	run_benchmark_family, run_benchmark_summary,
};
use crate::rgh::cli::interactive::{
	render_compare_summary, run_interactive_mode,
};
use crate::rgh::console::{
	self, history, ColorMode, ConsoleHistoryConfig, ConsoleOptions,
	HistoryRetention,
};
use crate::rgh::hash::compare_file_hashes;
use crate::rgh::hhhash::generate_hhhash;
use crate::rgh::output::DigestOutputFormat;
use crate::rgh::random::{RandomNumberGenerator, RngType};
use clap_complete::Shell;
use std::error::Error;
use std::path::PathBuf;
use std::process;
use std::str::FromStr;

pub fn run() -> Result<(), Box<dyn Error>> {
	let capp = build_cli();
	let m = capp.get_matches();

	match m.subcommand() {
		Some(("digest", matches)) => {
			digest::handle_digest_command(matches)?;
		}
		Some(("mac", matches)) => {
			mac::handle_mac_command(matches)?;
		}
		Some(("kdf", matches)) => {
			kdf::handle_kdf_command(matches)?;
		}
		Some(("interactive", _)) => {
			run_interactive_mode()?;
		}
		Some(("console", args)) => {
			let ignore_errors = args.get_flag("ignore-errors");
			let color_mode = args
				.get_one::<String>("color")
				.and_then(|raw| ColorMode::from_str(raw).ok())
				.unwrap_or(ColorMode::Auto);
			let mut options = if let Some(path) =
				args.get_one::<String>("script").map(PathBuf::from)
			{
				ConsoleOptions::from_script(path, ignore_errors)
			} else {
				ConsoleOptions::interactive()
			};
			options.ignore_errors = ignore_errors;
			options.color_mode = color_mode;
			options.force_color_override = match color_mode {
				ColorMode::Always | ColorMode::Never => {
					Some(color_mode)
				}
				_ => None,
			};
			let history_file_arg = args
				.get_one::<String>("history-file")
				.map(PathBuf::from);
			let requested_retention = args
				.get_one::<String>("history-retention")
				.and_then(|raw| HistoryRetention::from_str(raw).ok());
			let force_script_history =
				args.get_flag("force-script-history");
			let history_enabled = history_file_arg.is_some()
				|| requested_retention.is_some();
			let default_retention = if matches!(
				options.tty_mode,
				console::ConsoleMode::Script
			) {
				HistoryRetention::Off
			} else {
				HistoryRetention::Sanitized
			};
			let retention = if history_enabled {
				requested_retention.unwrap_or(default_retention)
			} else {
				HistoryRetention::Off
			};
			let resolved_history_path = history_file_arg.or_else(|| {
				if history_enabled && retention.is_enabled() {
					history::default_history_path()
				} else {
					None
				}
			});
			let (history_path, effective_retention) = match (
				resolved_history_path,
				retention,
			) {
				(Some(path), mode) if mode.is_enabled() => {
					(Some(path), mode)
				}
				(None, mode) if mode.is_enabled() => {
					eprintln!(
							"warning: history retention requested but no config directory available; history disabled"
						);
					(None, HistoryRetention::Off)
				}
				(other_path, _) => {
					(other_path, HistoryRetention::Off)
				}
			};
			options.history = ConsoleHistoryConfig::new(
				history_path,
				effective_retention,
				force_script_history,
			);
			match console::run_console(options) {
				Ok(code) => {
					if code != 0 {
						process::exit(code);
					}
				}
				Err(err) => {
					eprintln!("error: {}", err);
					process::exit(err.exit_code());
				}
			}
		}
		Some(("compare-file", s)) => {
			let baseline = s
				.get_one::<String>("manifest")
				.or_else(|| s.get_one::<String>("FILE1"))
				.map(|value| value.to_owned())
				.unwrap_or_else(|| {
					println!("Baseline file missing.");
					std::process::exit(1);
				});
			let candidate = s
				.get_one::<String>("against")
				.or_else(|| s.get_one::<String>("FILE2"))
				.map(|value| value.to_owned())
				.unwrap_or_else(|| {
					println!("Comparison file missing.");
					std::process::exit(1);
				});
			match compare_file_hashes(&baseline, &candidate) {
				Ok(summary) => {
					render_compare_summary(&summary);
					std::process::exit(summary.exit_code);
				}
				Err(err) => {
					eprintln!("Error comparing files: {}", err);
					std::process::exit(1);
				}
			}
		}
		Some(("compare-hash", s)) => {
			let st1 = s.get_one::<String>("HASH1");
			let st2 = s.get_one::<String>("HASH2");
			let st1 = st1.unwrap_or_else(|| {
				println!("No hash provided.");
				std::process::exit(1);
			});
			let st2 = st2.unwrap_or_else(|| {
				println!("No hash provided.");
				std::process::exit(1);
			});
			if compare_hashes(st1, st2) {
				println!("The hashes are equal.");
				std::process::exit(0);
			} else {
				println!("The hashes are not equal.");
				std::process::exit(1);
			}
		}
		Some(("generate-auto-completions", s)) => {
			if let Some(gen) = s.get_one::<Shell>("SHELL") {
				let mut capp = build_cli();
				cli::print_completions(*gen, &mut capp);
			};
		}
		Some(("random", s)) => {
			let a = s.get_one::<RngType>("algorithm");
			let a = match a {
				Some(a) => *a,
				None => panic!("Algorithm not found."),
			};
			let format = s
				.get_one::<DigestOutputFormat>("format")
				.copied()
				.unwrap_or(DigestOutputFormat::Hex);
			let len = s.get_one::<u64>("length");
			let len = match len {
				Some(l) => l,
				None => {
					println!("No length provided.");
					std::process::exit(1);
				}
			};
			if !matches!(
				format,
				DigestOutputFormat::Hex | DigestOutputFormat::Base64
			) {
				eprintln!(
					"warning: random command supports only hex or base64 formats"
				);
				std::process::exit(1);
			}
			let out = RandomNumberGenerator::new(a)
				.generate(*len, format)?;
			println!("{}", out);
		}
		Some(("analyze", s)) => {
			let st = s.get_one::<String>("INPUTSTRING");
			let st = match st {
				Some(s) => s,
				None => {
					println!("No string provided.");
					std::process::exit(1);
				}
			};

			let h = HashAnalyzer::from_string(st);
			let out = h.detect_possible_hashes();
			if out.is_empty() {
				println!("No possible hash class found.");
				std::process::exit(1);
			}
			print!("Possible class of hash: ");
			for o in out {
				print!("{} ", o);
			}
			println!();
		}
		Some(("header", s)) => {
			let url = s.get_one::<String>("URL").unwrap();
			let url = url.clone();
			let hash = generate_hhhash(url)?;
			println!("{}", hash);
		}
		Some(("benchmark", matches)) => {
			if let Some(("summarize", args)) = matches.subcommand() {
				run_benchmark_summary(args)?;
			} else if let Some(("mac", args)) = matches.subcommand() {
				run_benchmark_family(BenchmarkMode::Mac, args)?;
			} else if let Some(("kdf", args)) = matches.subcommand() {
				run_benchmark_family(BenchmarkMode::Kdf, args)?;
			} else {
				let algorithms: Vec<Algorithm> = matches
					.get_many("algorithms")
					.map(|v| v.cloned().collect())
					.unwrap_or_else(|| {
						let mut presets = digest_benchmark_presets();
						presets.extend(kdf_benchmark_presets());
						presets
					});
				let iterations =
					*matches.get_one::<u32>("iterations").unwrap();
				let summary =
					run_digest_benchmarks(&algorithms, iterations)
						.map_err(|err| {
							Box::new(err) as Box<dyn Error>
						})?;
				render_digest_report(&summary);
			}
		}
		_ => {}
	}
	Ok(())
}

