// SPDX-License-Identifier: MIT OR Apache-2.0
// Project: rustgenhash
// File: builtins.rs
// Author: Volker Schwaberow <volker@schwaberow.de>
// Copyright (c) 2025 Volker Schwaberow

use super::color::{ColorMode, ColorState, ConsoleLineRole};
use super::completion::{CompletionContext, CompletionEngine};
use super::help::{tokenize_topic, HelpResolver};
use super::session::{CommandEntry, ConsoleMode};
use super::variables::ConsoleVariableStore;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BuiltinAction {
	NotHandled,
	Continue,
	Exit(i32),
	CommandResult(i32),
	ColorChange(ColorMode),
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
	println!("  clear var $name     Remove a stored variable");
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
