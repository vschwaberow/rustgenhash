// SPDX-License-Identifier: MIT OR Apache-2.0
// Project: rustgenhash
// File: app/cli.rs

use crate::rgh::cli::algorithms::Algorithm;
use crate::rgh::cli::benchmark::{
	kdf_benchmark_subcommand, mac_benchmark_subcommand,
	summarize_benchmark_subcommand,
};
use crate::rgh::cli::defs::{
	digest_algorithm_help_text, HELP_TEMPLATE, MAC_ALGORITHMS,
	MAC_ALGORITHM_HELP, MAC_ALGORITHM_MATRIX_HELP,
};
use crate::rgh::kdf::profile;
use crate::rgh::output::DigestOutputFormat;
use crate::rgh::random::RngType;
use clap::builder::PossibleValuesParser;
use clap::{crate_name, Arg, ArgAction, ArgGroup};
use clap_complete::{generate, Generator, Shell};

pub(crate) fn build_cli() -> clap::Command {
	clap::Command::new(clap::crate_name!()) 
			.color(clap::ColorChoice::Never)
			.help_template(HELP_TEMPLATE)
			.bin_name(crate_name!())
			.version(clap::crate_version!())
			.author(clap::crate_authors!())
			.about("A simple hashing utility")
			.subcommand_required(true)
			.arg_required_else_help(true)
			.subcommand(
				clap::command!("digest")
					.about("Digest data using classic hash algorithms")
					.subcommand_required(true)
					.arg_required_else_help(true)
					.subcommand(
						clap::command!("string")
							.about("Hash a provided string")
							.arg(
							Arg::new("algorithm")
								.short('a')
								.long("algorithm")
								.help(digest_algorithm_help_text())
								.required(true),
							)
							.arg(
								Arg::new("input")
									.help("String to hash")
									.required(true),
							)
							.arg(
								Arg::new("format")
									.short('f')
									.long("format")
									.value_parser(
										clap::value_parser!(
											DigestOutputFormat
										)
									)
								.help("Output format (json, jsonl, csv, hex, base64, hashcat, multihash=base58btc)")
									.default_value("hex"),
							)
							.arg(
								Arg::new("hash-only")
									.long("hash-only")
									.help("Emit only digests without original input")
									.action(ArgAction::SetTrue),
							)
						,
					)
				.subcommand(
						clap::command!("file")
							.about("Hash the contents of a file or directory")
							.arg(
							Arg::new("algorithm")
								.short('a')
								.long("algorithm")
								.help(digest_algorithm_help_text())
								.required(true),
							)
							.arg(
								Arg::new("path")
									.help("File or directory path to hash")
									.required(true),
							)
							.arg(
								Arg::new("format")
									.short('f')
									.long("format")
									.value_parser(
										clap::value_parser!(
											DigestOutputFormat
										)
									)
								.help("Output format (json, jsonl, csv, hex, base64, hashcat, multihash=base58btc)")
									.default_value("hex"),
							)
							.arg(
								Arg::new("hash-only")
									.long("hash-only")
									.help("Emit only digests without file names")
									.action(ArgAction::SetTrue),
							)
							.arg(
								Arg::new("recursive")
									.long("recursive")
									.help("Traverse directories recursively")
									.action(ArgAction::SetTrue),
							)
							.arg(
								Arg::new("follow-symlinks")
									.long("follow-symlinks")
									.value_parser(["never", "files", "all"])
									.default_value("never")
									.help("Control how symlinks are handled (never, files, all)"),
							)
							.arg(
								Arg::new("threads")
									.long("threads")
									.default_value("1")
									.help("Worker strategy: 1 (single), auto, or explicit count"),
							)
							.arg(
								Arg::new("mmap-threshold")
									.long("mmap-threshold")
									.default_value("off")
									.help("Map files at or above this size (default off)"),
							)
							.arg(
								Arg::new("progress")
									.long("progress")
									.help("Force progress reporting on stderr")
									.action(ArgAction::SetTrue)
									.conflicts_with("no-progress"),
							)
							.arg(
								Arg::new("no-progress")
									.long("no-progress")
									.help("Disable progress reporting")
									.action(ArgAction::SetTrue),
							)
				.arg(
					Arg::new("manifest")
						.long("manifest")
						.help(
							"Write JSON manifest to this path (fail-fast suppresses the file)",
						),
				)
				.arg(
					Arg::new("error-strategy")
						.long("error-strategy")
						.value_parser(["fail-fast", "continue", "report-only"])
						.default_value("fail-fast")
					.help(
						"Control error handling: fail-fast (exit 1), continue (exit 2 on failures), report-only (exit 0)",
					),
				)
				.after_help(
					"Exit codes: 0 = success/report-only, 1 = fail-fast abort, 2 = recoverable errors",
				),
		)
					.subcommand(
						clap::command!("stdio")
							.about("Hash newline-delimited stdin input")
							.arg(
							Arg::new("algorithm")
								.short('a')
								.long("algorithm")
								.help(digest_algorithm_help_text())
								.required(true),
							)
							.arg(
								Arg::new("format")
									.short('f')
									.long("format")
									.value_parser(
										clap::value_parser!(
											DigestOutputFormat
										)
									)
								.help("Output format (json, jsonl, csv, hex, base64, hashcat, multihash=base58btc)")
									.default_value("hex"),
							)
							.arg(
								Arg::new("hash-only")
									.long("hash-only")
									.help("Emit only digests without echoing input lines")
									.action(ArgAction::SetTrue),
							),
			),
	)
	.subcommand(
		clap::command!("mac")
			.about("Generate message authentication codes")
			.after_help(MAC_ALGORITHM_MATRIX_HELP)
			.arg(
				Arg::new("algorithm")
				.short('a')
				.long("alg")
					.visible_alias("algorithm")
					.help(MAC_ALGORITHM_HELP)
					.value_parser(MAC_ALGORITHMS)
					.required(true),
			)
			.arg(
				Arg::new("key")
					.long("key")
					.value_name("PATH")
					.help("Read key bytes from file")
					.conflicts_with("key-stdin"),
			)
			.arg(
				Arg::new("key-stdin")
					.long("key-stdin")
					.help("Read key bytes from stdin")
					.action(ArgAction::SetTrue)
					.conflicts_with("key"),
			)
			.arg(
				Arg::new("input")
					.long("input")
					.value_name("TEXT")
					.help("Inline UTF-8 text to authenticate")
					.conflicts_with("file")
					.conflicts_with("stdin"),
			)
			.arg(
				Arg::new("file")
					.long("file")
					.value_name("PATH")
					.help("Hash the contents of a file")
					.conflicts_with("stdin"),
			)
			.arg(
				Arg::new("stdin")
					.long("stdin")
					.help("Read newline-delimited input from stdin")
					.action(ArgAction::SetTrue),
			)
			.arg(
				Arg::new("hash-only")
					.long("hash-only")
					.help("Emit only the MAC digest without input echo")
					.action(ArgAction::SetTrue),
			)
			.arg(
				Arg::new("format")
					.long("format")
					.help("MAC output format")
					.value_parser(["text", "json"])
					.default_value("text"),
			)
			.group(ArgGroup::new("mac-key").args(["key", "key-stdin"]).required(true))
			.group(ArgGroup::new("mac-input").args(["input", "file", "stdin"]).required(true)),
	)
	.subcommand(
		clap::command!("kdf")
					.about("Derive keys using password-based algorithms")
					.subcommand_required(true)
					.arg_required_else_help(true)
					.subcommand(
						clap::command!("argon2")
							.about("Derive a key using Argon2id")
					.arg(
							Arg::new("password")
								.long("password")
								.help("Password to derive (omit to prompt)")
								.required(false)
								.conflicts_with("password-stdin"),
						)
					.arg(
							Arg::new("password-stdin")
								.long("password-stdin")
								.help("Read password from stdin (newline trimmed)")
								.action(ArgAction::SetTrue)
								.conflicts_with("password"),
						)
							.arg(
								Arg::new("hash-only")
									.long("hash-only")
									.help("Emit only derived key output")
									.action(ArgAction::SetTrue),
							)
							.arg(
								Arg::new("mem-cost")
									.long("mem-cost")
									.value_parser(clap::value_parser!(u32))
									.help("Argon2 memory cost in KiB")
									.default_value("65536"),
							)
							.arg(
								Arg::new("time-cost")
									.long("time-cost")
									.value_parser(clap::value_parser!(u32))
									.help("Argon2 time cost (iterations)")
									.default_value("3"),
							)
							.arg(
								Arg::new("parallelism")
									.long("parallelism")
									.value_parser(clap::value_parser!(u32))
									.help("Argon2 parallelism")
									.default_value("4"),
							)
					)
		.subcommand(
						clap::command!("scrypt")
							.about("Derive a key using Scrypt")
				.arg(
							Arg::new("password")
								.long("password")
								.help("Password to derive (omit to prompt)")
								.required(false)
								.conflicts_with("password-stdin"),
						)
				.arg(
							Arg::new("password-stdin")
								.long("password-stdin")
								.help("Read password from stdin (newline trimmed)")
								.action(ArgAction::SetTrue)
								.conflicts_with("password"),
						)
							.arg(
								Arg::new("hash-only")
									.long("hash-only")
									.help("Emit only derived key output")
									.action(ArgAction::SetTrue),
							)
				.arg(
							Arg::new("profile")
								.long("profile")
								.value_name("ID")
								.value_parser(PossibleValuesParser::new(
									profile::scrypt_profile_ids()
								))
								.help("Compliance profile preset (e.g., owasp-2024)"),
				)
				.arg(
							Arg::new("salt")
								.long("salt")
								.value_name("HEX")
								.help("Hex-encoded salt to override generated value"),
				)
							.arg(
								Arg::new("log-n")
									.long("log-n")
									.value_parser(clap::value_parser!(u8))
									.help("Scrypt log2(N)")
									.default_value("15"),
							)
									.arg(
										Arg::new("r")
											.long("r")
											.value_parser(clap::value_parser!(u32))
											.help("Scrypt r parameter")
											.default_value("8"),
									)
									.arg(
										Arg::new("p")
											.long("p")
											.value_parser(clap::value_parser!(u32))
											.help("Scrypt p parameter")
											.default_value("1"),
									)
					)
		.subcommand(
						clap::command!("pbkdf2")
							.about("Derive a key using PBKDF2")
				.arg(
							Arg::new("password")
								.long("password")
								.help("Password to derive (omit to prompt)")
								.required(false)
								.conflicts_with("password-stdin"),
						)
				.arg(
							Arg::new("password-stdin")
								.long("password-stdin")
								.help("Read password from stdin (newline trimmed)")
								.action(ArgAction::SetTrue)
								.conflicts_with("password"),
						)
							.arg(
								Arg::new("hash-only")
									.long("hash-only")
									.help("Emit only derived key output")
									.action(ArgAction::SetTrue),
							)
				.arg(
							Arg::new("profile")
								.long("profile")
								.value_name("ID")
								.value_parser(PossibleValuesParser::new(
									profile::pbkdf2_profile_ids()
								))
								.help("Compliance profile preset (e.g., nist-sp800-132-2023)"),
				)
				.arg(
							Arg::new("salt")
								.long("salt")
								.value_name("HEX")
								.help("Hex-encoded salt to override generated value"),
				)
							.arg(
								Arg::new("rounds")
									.long("rounds")
									.value_parser(clap::value_parser!(u32))
									.help("PBKDF2 rounds")
									.default_value("100000"),
							)
									.arg(
										Arg::new("length")
											.long("length")
											.value_parser(clap::value_parser!(usize))
											.help("PBKDF2 output length (bytes)")
											.default_value("32"),
									)
									.arg(
										Arg::new("algorithm")
											.long("algorithm")
											.help("Digest variant for PBKDF2 (sha256|sha512)")
											.default_value("sha256"),
									)
					)
					.subcommand(
							clap::command!("bcrypt")
								.about("Derive a key using bcrypt-pbkdf")
					.arg(
								Arg::new("password")
									.long("password")
									.help("Password to derive (omit to prompt)")
									.required(false)
									.conflicts_with("password-stdin"),
						)
					.arg(
								Arg::new("password-stdin")
									.long("password-stdin")
									.help("Read password from stdin (newline trimmed)")
									.action(ArgAction::SetTrue)
									.conflicts_with("password"),
						)
							.arg(
								Arg::new("hash-only")
									.long("hash-only")
									.help("Emit only derived key output")
									.action(ArgAction::SetTrue),
							)
							.arg(
								Arg::new("cost")
									.long("cost")
									.value_parser(clap::value_parser!(u32))
									.help("Bcrypt cost factor")
									.default_value("12"),
						)
		)
		.subcommand(
						clap::command!("hkdf")
							.about("Derive key material using HKDF (RFC 5869)")
  .arg(
							Arg::new("ikm")
								.long("ikm")
								.value_name("HEX")
								.help("Hex-encoded input keying material (omit when using --ikm-stdin)")
								.conflicts_with("ikm-stdin"),
						)
					.arg(
							Arg::new("ikm-stdin")
								.long("ikm-stdin")
								.help("Read input keying material from stdin")
								.action(ArgAction::SetTrue),
						)
					.arg(
							Arg::new("expand-only")
								.long("expand-only")
								.help("Skip extract phase and expand using supplied PRK")
								.action(ArgAction::SetTrue),
						)
					.arg(
							Arg::new("prk")
								.long("prk")
								.value_name("PATH")
								.help("Read PRK bytes from file for expand-only mode")
								.requires("expand-only")
								.conflicts_with("prk-stdin"),
						)
					.arg(
							Arg::new("prk-stdin")
								.long("prk-stdin")
								.help("Read PRK bytes from stdin for expand-only mode")
								.action(ArgAction::SetTrue)
								.requires("expand-only"),
						)
					.arg(
							Arg::new("salt")
								.long("salt")
								.value_name("HEX")
								.help("Optional hex-encoded salt (defaults to empty; ignored for expand-only)"),
					)
					.arg(
							Arg::new("info")
								.long("info")
								.value_name("HEX")
								.help("Optional hex-encoded context info"),
					)
					.arg(
							Arg::new("len")
								.long("len")
								.value_parser(clap::value_parser!(usize))
								.help("Desired derived length in bytes")
								.required(true),
					)
					.arg(
							Arg::new("hash")
								.long("hash")
								.value_parser(["sha256", "sha512", "sha3-256", "sha3-512", "blake3"])
								.help("Digest variant for HKDF")
								.default_value("sha256"),
					)
					.arg(
							Arg::new("hash-only")
								.long("hash-only")
								.help("Emit only the derived key hex output")
								.action(ArgAction::SetTrue),
					)
				.after_help(
					"Provide either --ikm <HEX> or --ikm-stdin for extract+expand flows. For expand-only use --expand-only with --prk <PATH> or --prk-stdin.",
				)
		)
		.subcommand(
						clap::command!("balloon")
							.about("Derive a key using Balloon hashing")
								.arg(
									Arg::new("password")
										.long("password")
										.help("Password to derive (omit to prompt)")
										.required(false)
										.conflicts_with("password-stdin"),
						)
							.arg(
								Arg::new("password-stdin")
									.long("password-stdin")
									.help("Read password from stdin (newline trimmed)")
									.action(ArgAction::SetTrue)
									.conflicts_with("password"),
						)
							.arg(
								Arg::new("hash-only")
									.long("hash-only")
									.help("Emit only derived key output")
									.action(ArgAction::SetTrue),
							)
							.arg(
								Arg::new("time-cost")
									.long("time-cost")
									.value_parser(clap::value_parser!(u32))
									.help("Balloon time cost")
									.default_value("3"),
							)
							.arg(
								Arg::new("memory-cost")
									.long("memory-cost")
									.value_parser(clap::value_parser!(u32))
									.help("Balloon memory cost in KiB")
									.default_value("65536"),
							)
							.arg(
								Arg::new("parallelism")
									.long("parallelism")
									.value_parser(clap::value_parser!(u32))
									.help("Balloon parallelism")
																		.default_value("4"),
																)
											)
											.subcommand(
												clap::command!("sha-crypt")
									.about("Derive a key using SHA-crypt (SHA512)")
					.arg(
									Arg::new("password")
										.long("password")
										.help("Password to derive (omit to prompt)")
										.required(false)
										.conflicts_with("password-stdin"),
						)
					.arg(
								Arg::new("password-stdin")
									.long("password-stdin")
									.help("Read password from stdin (newline trimmed)")
									.action(ArgAction::SetTrue)
									.conflicts_with("password"),
						)
							.arg(
								Arg::new("hash-only")
									.long("hash-only")
									.help("Emit only derived key output")
									.action(ArgAction::SetTrue),
							)
					)
		)
										.subcommand(
						clap::command!("random")
							.about("Generate random string")
						.display_order(3)
						.arg(
								Arg::new("algorithm")
									.required(true)
									.short('a')
									.long("algorithm")
									.value_parser(clap::value_parser!(RngType)),
						)
						.arg(
								Arg::new("length")
									.short('l')
									.long("length")
									.default_value("32")
									.value_parser(clap::value_parser!(u64)),
						)
						.arg(
								Arg::new("format")
									.short('f')
									.long("format")
									.value_parser(clap::value_parser!(
										DigestOutputFormat
									))
									.help("Output format")
									.default_value("hex")
									.display_order(1),
						),
		)
			.subcommand(
						clap::command!("analyze")
							.about("Analyze a hash")
						.display_order(1)
						.arg(
								Arg::new("INPUTSTRING")
									                                    .help("String to analyze")
									                                    .required(true),
									                        )
									                        .arg_required_else_help(true),
									            )
									            .subcommand(
									                clap::command!("compare-hash")
									                    .about("Compare two strings")
									                    .arg(
									                        Arg::new("HASH1")
									                            .help("First hash to compare")
									                            .required(true),
									                    )
									                    .arg(
									                        Arg::new("HASH2")
									                            .help("Second hash to compare")
									                            .required(true),
									                    ),
									            )
									        .subcommand(
									                        clap::command!("compare-file")							.about("Compare manifest JSON or digest outputs for equality")
						.alias("compare-file-hashes")
						.arg(
								Arg::new("manifest")
									.long("manifest")
									.value_name("BASELINE")
									.help(
										"Baseline manifest or digest list (defaults to first positional argument)",
									)
									.requires("against"),
						)
						.arg(
								Arg::new("against")
									.long("against")
									.value_name("CANDIDATE")
									.help(
										"Manifest or digest list to compare against the baseline",
									)
									.requires("manifest"),
						)
						.arg(
								Arg::new("FILE1")
									.help("Baseline manifest or digest list")
									.conflicts_with("manifest")
									.required_unless_present("manifest"),
						)
						.arg(
								Arg::new("FILE2")
									.help("Comparison manifest or digest list")
									.conflicts_with("against")
									.required_unless_present("manifest"),
						)
						.after_help(
							"Exit codes: 0 = identical, 1 = differences detected or incompatibility, 2 = comparison incomplete (manifest recorded failures)",
					)
						.arg_required_else_help(true),
		)
			.subcommand(
						clap::command!("generate-auto-completions")
							.about("Generate shell completions")
						.arg(
								Arg::new("SHELL")
									.required(true)
									.value_parser(clap::value_parser!(Shell))
									.help("Shell to generate completions for"),
						)
			)
			.subcommand(clap::command!("interactive")
				.about("Enter interactive mode")
			)
			.subcommand(
						clap::command!("console")
							.about("Network appliance-style console shell for chaining rustgenhash commands")
						.arg(
								Arg::new("script")
									.long("script")
									.value_name("FILE")
									.help("Run console commands from a script file (non-interactive mode)"),
						)
						.arg(
								Arg::new("ignore-errors")
									.long("ignore-errors")
									.action(ArgAction::SetTrue)
									.help("Continue executing script commands after failures"),
						)
						.arg(
								Arg::new("color")
									.long("color")
									.value_name("WHEN")
									.value_parser(PossibleValuesParser::new([
										"auto",
										"always",
										"never",
									]))
									.default_value("auto")
									.help(
										"Color console-owned output: auto (default), always, or never",
									),
					)
						.arg(
								Arg::new("history-file")
									.long("history-file")
									.value_name("FILE")
									.help(
										"Persist console history to FILE (defaults to platform config path; keeps 200 in-memory entries per session and persists up to 500 commands)",
									),
					)
						.arg(
								Arg::new("history-retention")
									.long("history-retention")
									.value_name("MODE")
									.value_parser(PossibleValuesParser::new([
										"off",
										"sanitized",
										"verbatim",
									]))
									.help(
										"History retention policy (sanitized is default for interactive sessions, off for scripts); retention obeys the 200/500 entry limits noted above",
									),
					)
						.arg(
								Arg::new("force-script-history")
									.long("force-script-history")
									.action(ArgAction::SetTrue)
																	.help(
																		"Allow scripts to write history even though it is disabled by default (requires explicit retention)",
																	),
																)
															.after_help("Examples:\n  rgh console\n  rgh console --script playbook.rgh\n  rgh console --script playbook.rgh --ignore-errors")
												)
												.subcommand(						clap::command!("header")
							.about("Generate a HHHash of HTTP header")
						.arg(
								Arg::new("URL")
									.help("URL to fetch")
																		.required(true),
															)
												)
												.subcommand(
													clap::command!("benchmark")							.about("Run benchmarks for digest, MAC, and KDF algorithms")
						.arg(
								Arg::new("algorithms")
									.short('a')
									.long("algorithms")
									.value_parser(clap::value_parser!(Algorithm))
									.help("Specify digest algorithms to benchmark (default: all)")
						)
						.arg(
								Arg::new("iterations")
									.short('i')
									.long("iterations")
									.value_parser(clap::value_parser!(u32))
									.default_value("100")
									.help("Number of iterations for each benchmark")
						)
						.subcommand(mac_benchmark_subcommand())
						.subcommand(kdf_benchmark_subcommand())
						.subcommand(summarize_benchmark_subcommand())
	)
}

/// Render the help text for a given command path (e.g., `["digest", "string"]`).
/// Returns `None` if the path does not exist in the CLI tree.
pub(crate) fn render_help_for_path(
	path: &[String],
) -> Option<String> {
	let mut current = build_cli();
	if path.is_empty() {
		return Some(render_help_text(current));
	}
	for segment in path {
		let next = current
			.get_subcommands()
			.find(|sub| sub.get_name().eq_ignore_ascii_case(segment))
			.cloned()?;
		current = next;
	}
	Some(render_help_text(current))
}

pub(crate) fn render_help_text(mut command: clap::Command) -> String {
	let mut buffer = Vec::new();
	if command.write_long_help(&mut buffer).is_err() {
		let _ = command.write_help(&mut buffer);
	}
	String::from_utf8_lossy(&buffer).into_owned()
}

pub(crate) fn print_completions<G: Generator>(gen: G, cmd: &mut clap::Command) {
	generate(
		gen,
		cmd,
		cmd.get_name().to_string(),
		&mut std::io::stdout(),
	);
}

