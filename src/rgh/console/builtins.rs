// SPDX-License-Identifier: MIT OR Apache-2.0

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
}

pub fn handle_builtin(
	command: &str,
	vars: &mut ConsoleVariableStore,
	history: &[CommandEntry],
	completion: &CompletionEngine,
	help_resolver: &HelpResolver,
	mode: ConsoleMode,
) -> BuiltinAction {
	let normalized = command.trim();
	let lowered = normalized.to_ascii_lowercase();

	if lowered == "exit" || lowered == "quit" {
		return BuiltinAction::Exit(0);
	}

	if lowered == "help" {
		print_help();
		return BuiltinAction::Continue;
	}

	if let Some(topic) = normalized.strip_prefix("help ") {
		return handle_context_help(topic, help_resolver);
	}

	if lowered == "complete" || lowered.starts_with("complete ") {
		let query = normalized
			.strip_prefix("complete")
			.unwrap_or("")
			.trim_start();
		return handle_completion_builtin(query, completion, mode);
	}

	match lowered.as_str() {
		"show vars" => {
			show_vars(vars);
			BuiltinAction::Continue
		}
		"show history" => {
			show_history(history);
			BuiltinAction::Continue
		}
		"configure terminal" => {
			println!(
				"Opening interactive mode... run `rgh interactive` in another shell for now."
			);
			BuiltinAction::Continue
		}
		"abort" => {
			println!("Aborting current session (exit code 130).");
			BuiltinAction::Exit(130)
		}
		_ if lowered.starts_with("clear var ") => {
			let name = normalized["clear var ".len()..]
				.trim()
				.trim_start_matches('$');
			if vars.clear(name) {
				println!("Cleared ${}", name);
			} else {
				println!("Variable ${} not defined.", name);
			}
			BuiltinAction::Continue
		}
		_ => BuiltinAction::NotHandled,
	}
}

fn print_help() {
	println!("Console built-ins:");
	println!("  help                Show this message or `help <topic>` for CLI docs");
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

fn show_vars(vars: &ConsoleVariableStore) {
	if vars.list().is_empty() {
		println!("(no variables defined)");
		return;
	}
	for var in vars.list() {
		println!("${} = {}", var.name, var.preview());
	}
}

fn show_history(history: &[CommandEntry]) {
	if history.is_empty() {
		println!("(history empty)");
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
) -> BuiltinAction {
	let ctx = CompletionContext::new(
		query,
		query.len(),
		mode == ConsoleMode::Script,
	);
	let mut result = completion.suggest(&ctx);
	if result.suggestions.is_empty() {
		eprintln!("no completion matches for `{}`", query.trim());
		return BuiltinAction::CommandResult(66);
	}
	result.suggestions.sort_by(|a, b| a.value.cmp(&b.value));
	let prefix = ctx.prefix().trim();
	println!(
		"# completions prefix='{}' matches={}",
		prefix,
		result.suggestions.len()
	);
	for suggestion in &result.suggestions {
		println!("{}", suggestion.value);
	}
	BuiltinAction::CommandResult(0)
}

fn handle_context_help(
	topic: &str,
	helper: &HelpResolver,
) -> BuiltinAction {
	let tokens = tokenize_topic(topic);
	match helper.resolve(&tokens) {
		Ok(doc) => {
			println!("{}", doc.body);
			BuiltinAction::CommandResult(0)
		}
		Err(err) => {
			eprintln!("{}", err);
			BuiltinAction::CommandResult(err.exit_code())
		}
	}
}
