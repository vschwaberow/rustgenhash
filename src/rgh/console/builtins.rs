// SPDX-License-Identifier: MIT OR Apache-2.0
// Project: rustgenhash
// File: builtins.rs
// Author: Volker Schwaberow <volker@schwaberow.de>
// Copyright (c) 2025 Volker Schwaberow

use super::color::{ColorMode, ColorState, ConsoleLineRole};
use super::completion::{CompletionContext, CompletionEngine};
use super::export::ExportFormat;
use super::help::{tokenize_topic, HelpResolver};
use super::session::{CommandEntry, ConsoleMode};
use super::variables::ConsoleVariableStore;
use std::path::PathBuf;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum BuiltinAction {
	NotHandled,
	Continue,
	Exit(i32),
	CommandResult(i32),
	ColorChange(ColorMode),
	HistorySave(PathBuf),
	HistoryLoad(PathBuf),
	HistoryClear,
	ExportVars {
		path: PathBuf,
		format: ExportFormat,
		include_secrets: bool,
		auto_confirm: bool,
	},
}

pub fn handle_builtin(
	command: &str,
	vars: &mut ConsoleVariableStore,
	history: &[CommandEntry],
	completion: &CompletionEngine,
	help_resolver: &HelpResolver,
	mode: ConsoleMode,
	color: &ColorState,
) -> BuiltinAction {
	let normalized = command.trim();
	let lowered = normalized.to_ascii_lowercase();

	if lowered == "exit" || lowered == "quit" {
		return BuiltinAction::Exit(0);
	}

	if lowered == "help" {
		print_help(color);
		return BuiltinAction::Continue;
	}

	if let Some(topic) = normalized.strip_prefix("help ") {
		return handle_context_help(topic, help_resolver, color);
	}

	if lowered == "complete" || lowered.starts_with("complete ") {
		let query = normalized
			.strip_prefix("complete")
			.unwrap_or("")
			.trim_start();
		return handle_completion_builtin(
			query, completion, mode, color,
		);
	}

	match lowered.as_str() {
		"show vars" => {
			show_vars(vars, color);
			BuiltinAction::Continue
		}
		"show history" => {
			show_history(history, color);
			BuiltinAction::Continue
		}
		"configure terminal" => {
			print_info(
				color,
				"Opening interactive mode... run `rgh interactive` in another shell for now.",
			);
			BuiltinAction::Continue
		}
		"abort" => {
			print_warning(
				color,
				"Aborting current session (exit code 130).",
			);
			BuiltinAction::Exit(130)
		}
		_ if lowered.starts_with("clear var ") => {
			let name = normalized["clear var ".len()..]
				.trim()
				.trim_start_matches('$');
			if vars.clear(name) {
				print_success(color, &format!("Cleared ${}", name));
			} else {
				print_warning(
					color,
					&format!("Variable ${} not defined.", name),
				);
			}
			BuiltinAction::Continue
		}
		_ if lowered.starts_with("set color ") => {
			handle_set_color_builtin(lowered.as_str(), color)
		}
		_ if lowered.starts_with("history save ") => {
			if let Some(path) =
				parse_path_arg(&normalized["history save ".len()..])
			{
				BuiltinAction::HistorySave(path)
			} else {
				print_error(color, "usage: history save <path>");
				BuiltinAction::CommandResult(64)
			}
		}
		_ if lowered.starts_with("history load ") => {
			if let Some(path) =
				parse_path_arg(&normalized["history load ".len()..])
			{
				BuiltinAction::HistoryLoad(path)
			} else {
				print_error(color, "usage: history load <path>");
				BuiltinAction::CommandResult(64)
			}
		}
		"history clear" => BuiltinAction::HistoryClear,
		_ if lowered.starts_with("export vars") => {
			parse_export_vars_builtin(normalized, color)
		}
		_ => BuiltinAction::NotHandled,
	}
}

fn print_help(color: &ColorState) {
	print_info(color, "Console built-ins:");
	println!(
		"  help                Show this message or `help <topic>` for CLI docs"
	);
	println!(
		"  complete <prefix>   List suggestions deterministically"
	);
	println!("  show vars           List stored variables");
	println!(
		"  show history        Display last commands and exit codes"
	);
	println!(
		"  history save <FILE> Persist current history to a custom file"
	);
	println!(
		"  history load <FILE> Replace history with commands from FILE"
	);
	println!(
		"  history clear       Remove in-memory history entries"
	);
	println!("  clear var $name     Remove a stored variable");
	println!(
		"  export vars <FILE> [--format json|yaml] [--include-secrets --yes]"
	);
	println!(
		"  configure terminal  Jump to legacy interactive wizard"
	);
	println!("  abort               Attempt to stop active command");
	println!("  exit/quit           Leave console");
}

fn show_vars(vars: &ConsoleVariableStore, color: &ColorState) {
	if vars.list().is_empty() {
		print_info(color, "(no variables defined)");
		return;
	}
	for var in vars.list() {
		println!("${} = {}", var.name, var.preview());
	}
}

fn show_history(history: &[CommandEntry], color: &ColorState) {
	if history.is_empty() {
		print_info(color, "(history empty)");
		return;
	}
	for (idx, entry) in history.iter().enumerate() {
		println!(
			"{:>3}: {:<60} [{}]",
			idx + 1,
			entry.command,
			entry.exit_code
		);
	}
}

fn handle_completion_builtin(
	query: &str,
	completion: &CompletionEngine,
	mode: ConsoleMode,
	color: &ColorState,
) -> BuiltinAction {
	let ctx = CompletionContext::new(
		query,
		query.len(),
		mode == ConsoleMode::Script,
	);
	let mut result = completion.suggest(&ctx);
	if result.suggestions.is_empty() {
		print_error(
			color,
			&format!("no completion matches for `{}`", query.trim()),
		);
		return BuiltinAction::CommandResult(66);
	}
	result.suggestions.sort_by(|a, b| a.value.cmp(&b.value));
	let prefix = ctx.prefix().trim();
	print_info(
		color,
		&format!(
			"# completions prefix='{}' matches={}",
			prefix,
			result.suggestions.len()
		),
	);
	for suggestion in &result.suggestions {
		println!("{}", suggestion.value);
	}
	BuiltinAction::CommandResult(0)
}

fn parse_path_arg(raw: &str) -> Option<PathBuf> {
	let trimmed = raw.trim();
	if trimmed.is_empty() {
		return None;
	}
	let unquoted = trimmed
		.strip_prefix('"')
		.and_then(|rest| rest.strip_suffix('"'))
		.or_else(|| {
			trimmed
				.strip_prefix('\'')
				.and_then(|rest| rest.strip_suffix('\''))
		})
		.unwrap_or(trimmed);
	if unquoted.is_empty() {
		None
	} else {
		Some(PathBuf::from(unquoted))
	}
}

fn split_path_and_rest(input: &str) -> Option<(PathBuf, &str)> {
	let trimmed = input.trim_start();
	if trimmed.is_empty() {
		return None;
	}
	if trimmed.starts_with('"') || trimmed.starts_with('\'') {
		let quote = trimmed.chars().next().unwrap();
		let mut consumed = 1;
		let mut path = String::new();
		for ch in trimmed[1..].chars() {
			consumed += ch.len_utf8();
			if ch == quote {
				break;
			}
			path.push(ch);
		}
		let rest = &trimmed[consumed..];
		return Some((PathBuf::from(path), rest));
	}
	let mut end = 0;
	for (idx, ch) in trimmed.char_indices() {
		if ch.is_whitespace() {
			break;
		}
		end = idx + ch.len_utf8();
	}
	if end == 0 {
		return Some((PathBuf::from(trimmed), ""));
	}
	let path = PathBuf::from(&trimmed[..end]);
	let rest = &trimmed[end..];
	Some((path, rest))
}

fn parse_export_vars_builtin(
	command: &str,
	color: &ColorState,
) -> BuiltinAction {
	let remainder = command["export vars".len()..].trim_start();
	let Some((path, rest)) = split_path_and_rest(remainder) else {
		print_error(color, "usage: export vars <FILE> [--format json|yaml] [--include-secrets --yes]");
		return BuiltinAction::CommandResult(64);
	};
	let mut format = ExportFormat::Json;
	let mut include_secrets = false;
	let mut auto_confirm = false;
	let mut tokens = rest.trim().split_whitespace().peekable();
	while let Some(token) = tokens.next() {
		match token {
			"--include-secrets" => include_secrets = true,
			"--format" => {
				let Some(value) = tokens.next() else {
					print_error(
						color,
						"--format requires json or yaml",
					);
					return BuiltinAction::CommandResult(64);
				};
				match ExportFormat::from_str(value) {
					Some(fmt) => format = fmt,
					None => {
						print_error(
							color,
							"supported export formats are json or yaml",
						);
						return BuiltinAction::CommandResult(64);
					}
				}
			}
			"--yes" => auto_confirm = true,
			other => {
				print_warning(
					color,
					&format!(
						"ignoring unrecognized flag `{}`",
						other
					),
				);
			}
		}
	}
	BuiltinAction::ExportVars {
		path,
		format,
		include_secrets,
		auto_confirm,
	}
}

fn handle_context_help(
	topic: &str,
	helper: &HelpResolver,
	color: &ColorState,
) -> BuiltinAction {
	let tokens = tokenize_topic(topic);
	match helper.resolve(&tokens) {
		Ok(doc) => {
			println!("{}", doc.body);
			BuiltinAction::CommandResult(0)
		}
		Err(err) => {
			print_error(color, &err.to_string());
			BuiltinAction::CommandResult(err.exit_code())
		}
	}
}

fn print_success(color: &ColorState, message: &str) {
	println!("{}", color.format(ConsoleLineRole::Success, message));
}

fn print_info(color: &ColorState, message: &str) {
	println!("{}", color.format(ConsoleLineRole::Info, message));
}

fn print_warning(color: &ColorState, message: &str) {
	println!("{}", color.format(ConsoleLineRole::Warning, message));
}

fn print_error(color: &ColorState, message: &str) {
	eprintln!("{}", color.format(ConsoleLineRole::Error, message));
}

fn handle_set_color_builtin(
	lowered: &str,
	color: &ColorState,
) -> BuiltinAction {
	let value =
		lowered.strip_prefix("set color").unwrap_or("").trim();
	if value.is_empty() {
		print_error(color, "set color requires a mode (auto|always|never|high-contrast)");
		return BuiltinAction::CommandResult(64);
	}
	let parsed = match value.parse::<ColorMode>() {
		Ok(mode) => mode,
		Err(err) => {
			print_error(color, &err);
			return BuiltinAction::CommandResult(64);
		}
	};
	BuiltinAction::ColorChange(parsed)
}
