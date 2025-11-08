// SPDX-License-Identifier: MIT OR Apache-2.0

use super::builtins::{handle_builtin, BuiltinAction};
use super::completion::{CompletionContext, CompletionEngine};
use super::dispatcher;
use super::dispatcher::DispatchOutput;
use super::help::HelpResolver;
use super::interpolation;
use super::parser::parse_command;
use super::script;
use super::variables::{ConsoleValueType, ConsoleVariableStore};
use super::{ConsoleError, ConsoleOptions};
use colored::control;
use rustyline::completion::{Completer, Pair};
use rustyline::error::ReadlineError;
use rustyline::highlight::Highlighter;
use rustyline::hint::Hinter;
use rustyline::history::DefaultHistory;
use rustyline::validate::{
	ValidationContext, ValidationResult, Validator,
};
use rustyline::{CompletionType, Config, Context, Editor, Helper};
use std::time::SystemTime;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ConsoleMode {
	Interactive,
	Script,
}

#[derive(Debug, Clone)]
pub struct CommandEntry {
	pub command: String,
	pub exit_code: i32,
	pub timestamp: SystemTime,
}

pub(crate) enum Flow {
	Continue,
	Exit(i32),
}

/// Represents a running console session (interactive or scripted).
pub struct ConsoleSession {
	options: ConsoleOptions,
	variables: ConsoleVariableStore,
	history: Vec<CommandEntry>,
	prompt_label: String,
	completion: CompletionEngine,
	help: HelpResolver,
}

impl ConsoleSession {
	pub fn new(options: ConsoleOptions) -> Self {
		if matches!(options.tty_mode, ConsoleMode::Script) {
			control::set_override(false);
		}
		Self {
			options,
			variables: ConsoleVariableStore::default(),
			history: Vec::new(),
			prompt_label: "rgh-console".into(),
			completion: CompletionEngine::default(),
			help: HelpResolver::default(),
		}
	}

	pub fn run(&mut self) -> Result<i32, ConsoleError> {
		match self.options.tty_mode {
			ConsoleMode::Interactive => self.run_interactive(),
			ConsoleMode::Script => self.run_scripted(),
		}
	}

	fn run_interactive(&mut self) -> Result<i32, ConsoleError> {
		let config = Config::builder()
			.completion_type(CompletionType::List)
			.build();
		let mut editor =
			Editor::<ConsoleHelper, DefaultHistory>::with_config(
				config,
			)
			.map_err(|err| ConsoleError::Message(err.to_string()))?;
		editor.set_helper(Some(ConsoleHelper::new(
			self.completion.clone(),
		)));
		let prompt = format!("{}# ", self.prompt_label);
		loop {
			match editor.readline(&prompt) {
				Ok(line) => {
					if !line.trim().is_empty() {
						let _ =
							editor.add_history_entry(line.as_str());
					}
					match self.execute_line(&line)? {
						Flow::Continue => continue,
						Flow::Exit(code) => return Ok(code),
					}
				}
				Err(ReadlineError::Interrupted) => {
					println!("^C");
				}
				Err(ReadlineError::Eof) => {
					println!();
					return Ok(0);
				}
				Err(err) => {
					return Err(ConsoleError::Message(
						err.to_string(),
					));
				}
			}
		}
	}

	fn should_abort_on_failure(&self) -> bool {
		matches!(self.options.tty_mode, ConsoleMode::Script)
			&& !self.options.ignore_errors
	}

	fn run_scripted(&mut self) -> Result<i32, ConsoleError> {
		let Some(path) = self.options.script_path.clone() else {
			return Err(ConsoleError::Message(
				"script path required for --script".into(),
			));
		};
		let ignore_errors = self.options.ignore_errors;
		script::run_script(self, &path, ignore_errors)
	}

	pub(crate) fn execute_line(
		&mut self,
		raw: &str,
	) -> Result<Flow, ConsoleError> {
		let trimmed = raw.trim();
		if trimmed.is_empty() || trimmed.starts_with('#') {
			return Ok(Flow::Continue);
		}

		match handle_builtin(
			trimmed,
			&mut self.variables,
			&self.history,
			&self.completion,
			&self.help,
			self.options.tty_mode,
		) {
			BuiltinAction::Exit(code) => return Ok(Flow::Exit(code)),
			BuiltinAction::Continue => return Ok(Flow::Continue),
			BuiltinAction::CommandResult(code) => {
				self.record_history(trimmed, code);
				if code != 0 && self.should_abort_on_failure() {
					return Ok(Flow::Exit(code));
				}
				return Ok(Flow::Continue);
			}
			BuiltinAction::NotHandled => {}
		}

		self.run_console_command(trimmed)
	}

	fn run_console_command(
		&mut self,
		line: &str,
	) -> Result<Flow, ConsoleError> {
		let parsed = parse_command(line);
		let is_assignment = parsed.is_assignment();
		let assignment = parsed.assignment.clone();
		let tokens = parsed.tokens;
		if tokens.is_empty() {
			return Ok(Flow::Continue);
		}

		let args_slice = if is_assignment {
			&tokens[3..]
		} else {
			&tokens[..]
		};

		let mut args = Vec::with_capacity(args_slice.len());
		for token in args_slice {
			let value = match interpolation::interpolate(
				token,
				&self.variables,
			) {
				Ok(val) => val,
				Err(interpolation::InterpolationError::UndefinedVariable(
					name,
				)) => {
					return Err(ConsoleError::Variable(name));
				}
				Err(err) => {
					return Err(ConsoleError::Message(err.to_string()));
				}
			};
			args.push(value);
		}

		let exit_code = if is_assignment {
			let assignment =
				assignment.as_deref().unwrap_or_default();
			self.run_assignment_command(assignment, args)?
		} else {
			dispatcher::run_command(&args)?
		};

		self.record_history(line, exit_code);
		if exit_code != 0 {
			eprintln!("command exited with code {}", exit_code);
			if self.should_abort_on_failure() {
				return Ok(Flow::Exit(exit_code));
			}
		}
		Ok(Flow::Continue)
	}

	fn run_assignment_command(
		&mut self,
		name: &str,
		args: Vec<String>,
	) -> Result<i32, ConsoleError> {
		validate_variable_name(name)?;
		let output: DispatchOutput =
			dispatcher::run_command_capture(&args)?;
		if !output.stdout.is_empty() {
			print!("{}", output.stdout);
		}
		if !output.stderr.is_empty() {
			eprint!("{}", output.stderr);
		}
		if output.exit_code == 0 {
			let value = extract_last_line(&output.stdout);
			let value_type = detect_value_type(&value);
			let sensitive = is_sensitive_value(&value, value_type);
			self.variables.set(
				name.to_string(),
				value,
				value_type,
				sensitive,
			);
		}
		Ok(output.exit_code)
	}

	fn record_history(&mut self, command: &str, exit_code: i32) {
		self.history.push(CommandEntry {
			command: command.to_string(),
			exit_code,
			timestamp: SystemTime::now(),
		});
		if self.history.len() > 1000 {
			self.history.remove(0);
		}
	}
}

fn validate_variable_name(name: &str) -> Result<(), ConsoleError> {
	if name.is_empty()
		|| !name
			.chars()
			.all(|c| c.is_ascii_alphanumeric() || c == '_')
	{
		return Err(ConsoleError::Message(format!(
			"invalid variable name `${}` (use alphanumeric/underscore)",
			name
		)));
	}
	Ok(())
}

fn extract_last_line(stdout: &str) -> String {
	let line = stdout
		.lines()
		.rev()
		.find(|line| !line.trim().is_empty())
		.unwrap_or("")
		.trim();

	if line.starts_with('{') || line.starts_with('[') {
		return line.to_string();
	}

	if let Some(token) = line.split_whitespace().next() {
		return token.to_string();
	}

	line.to_string()
}

fn detect_value_type(value: &str) -> ConsoleValueType {
	if value.starts_with('{') || value.starts_with('[') {
		ConsoleValueType::Json
	} else if value.contains(std::path::MAIN_SEPARATOR) {
		ConsoleValueType::Path
	} else {
		ConsoleValueType::Generic
	}
}

fn is_sensitive_value(
	value: &str,
	value_type: ConsoleValueType,
) -> bool {
	if matches!(
		value_type,
		ConsoleValueType::Json | ConsoleValueType::Path
	) {
		return false;
	}
	let trimmed = value.trim();
	trimmed.len() >= 16
		&& trimmed.chars().all(|c| c.is_ascii_hexdigit())
}

struct ConsoleHelper {
	engine: CompletionEngine,
}

impl ConsoleHelper {
	fn new(engine: CompletionEngine) -> Self {
		Self { engine }
	}
}

impl Helper for ConsoleHelper {}

impl Completer for ConsoleHelper {
	type Candidate = Pair;

	fn complete(
		&self,
		line: &str,
		pos: usize,
		_: &Context<'_>,
	) -> Result<(usize, Vec<Pair>), ReadlineError> {
		let ctx = CompletionContext::new(line, pos, false);
		let result = self.engine.suggest(&ctx);
		let start = ctx.insertion_start();
		let pairs = result
			.suggestions
			.iter()
			.map(|suggestion| suggestion.as_pair())
			.collect();
		Ok((start, pairs))
	}
}

impl Hinter for ConsoleHelper {
	type Hint = String;

	fn hint(
		&self,
		_: &str,
		_: usize,
		_: &Context<'_>,
	) -> Option<Self::Hint> {
		None
	}
}

impl Highlighter for ConsoleHelper {}

impl Validator for ConsoleHelper {
	fn validate(
		&self,
		_: &mut ValidationContext<'_>,
	) -> Result<ValidationResult, ReadlineError> {
		Ok(ValidationResult::Valid(None))
	}
}
