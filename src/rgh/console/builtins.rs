// SPDX-License-Identifier: MIT OR Apache-2.0

use super::session::CommandEntry;
use super::variables::ConsoleVariableStore;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BuiltinAction {
	NotHandled,
	Continue,
	Exit(i32),
}

pub fn handle_builtin(
	command: &str,
	vars: &mut ConsoleVariableStore,
	history: &[CommandEntry],
) -> BuiltinAction {
	let normalized = command.trim();
	let lowered = normalized.to_ascii_lowercase();

	if lowered == "exit" || lowered == "quit" {
		return BuiltinAction::Exit(0);
	}

	match lowered.as_str() {
		"help" => {
			print_help();
			BuiltinAction::Continue
		}
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
	println!("  help                Show this message");
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
