// SPDX-License-Identifier: MIT OR Apache-2.0
// Project: rustgenhash
// File: session.rs
// Author: Volker Schwaberow <volker@schwaberow.de>
// Copyright (c) 2022 Volker Schwaberow

use super::builtins::{handle_builtin, BuiltinAction};
use super::color::{
	ColorMode, ColorState, ConsoleLineRole, PlatformCapabilityProfile,
};
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
	color: ColorState,
}

impl ConsoleSession {
	pub fn new(options: ConsoleOptions) -> Self {
		let capability =
			PlatformCapabilityProfile::detect(options.tty_mode);
		let mut color =
			ColorState::new(options.color_mode, capability);
		if let Some(force) = options.force_color_override {
			color = ColorState::new(force, capability);
		}
		control::set_override(color.should_emit());
		let session = Self {
			options,
			variables: ConsoleVariableStore::default(),
			history: Vec::new(),
			prompt_label: "rgh-console".into(),
			completion: CompletionEngine::default(),
			help: HelpResolver,
			color,
		};

		if let Some(message) = session.color.capability.legacy_notice
		{
			session.emit_console_stdout(
				ConsoleLineRole::Warning,
				message,
			);
		}

		session
	}

	pub fn run(&mut self) -> Result<i32, ConsoleError> {
		match self.options.tty_mode {
			ConsoleMode::Interactive => self.run_interactive(),
			ConsoleMode::Script => self.run_scripted(),
		}
	}

	pub(crate) fn color_state(&self) -> &ColorState {
		&self.color
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
		loop {
			let prompt = self.render_prompt();
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
					self.emit_console_stdout(
						ConsoleLineRole::Warning,
						"^C",
					);
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

		let color = self.color.clone();
		match handle_builtin(
			trimmed,
			&mut self.variables,
			&self.history,
			&self.completion,
			&self.help,
			self.options.tty_mode,
			&color,
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
			BuiltinAction::ColorChange(mode) => {
				self.apply_color_request(mode);
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
			self.emit_console_stderr(
				ConsoleLineRole::Warning,
				&format!("command exited with code {}", exit_code),
			);
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
			self.emit_child_stdout(&output.stdout);
		}
		if !output.stderr.is_empty() {
			self.emit_child_stderr(&output.stderr);
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

	fn apply_color_request(&mut self, requested: ColorMode) {
		if let Some(forced) = self.options.force_color_override {
			match forced {
				ColorMode::Always => {
					if matches!(
						requested,
						ColorMode::Never | ColorMode::Auto
					) {
						self.emit_console_stdout(
							ConsoleLineRole::Warning,
							"ignoring request: --color=always keeps colors enabled",
						);
					} else {
						self.apply_color_mode(requested);
					}
				}
				ColorMode::Never => {
					if matches!(requested, ColorMode::Never) {
						self.emit_console_stdout(
							ConsoleLineRole::Info,
							"color disabled via --color=never",
						);
					} else {
						self.emit_console_stdout(
							ConsoleLineRole::Warning,
							"ignoring request: --color=never disables colors for this session",
						);
					}
				}
				_ => {}
			}
			return;
		}

		if self.color.capability.no_color_env
			&& !matches!(requested, ColorMode::Never)
		{
			self.emit_console_stdout(
				ConsoleLineRole::Warning,
				"NO_COLOR is set; pass --color=always to force ANSI",
			);
			return;
		}

		if matches!(self.options.tty_mode, ConsoleMode::Script)
			&& !matches!(requested, ColorMode::Never)
		{
			self.emit_console_stdout(
				ConsoleLineRole::Warning,
				"script mode stays monochrome; use --color=always when launching",
			);
			return;
		}

		self.apply_color_mode(requested);
	}

	fn apply_color_mode(&mut self, requested: ColorMode) {
		self.color.update_mode(requested);
		control::set_override(self.color.should_emit());
		let message = match requested {
			ColorMode::Auto => format!(
				"color auto-detect active ({})",
				self.color.reason
			),
			ColorMode::Always => "color output forced on".to_string(),
			ColorMode::Never => "color output disabled".to_string(),
			ColorMode::HighContrast => {
				"high-contrast palette enabled".to_string()
			}
		};
		self.emit_console_stdout(ConsoleLineRole::Success, &message);
	}

	fn render_prompt(&self) -> String {
		let base = format!("{}# ", self.prompt_label);
		self.color.format(ConsoleLineRole::Prompt, &base)
	}

	fn emit_child_stdout(&self, text: &str) {
		if text.is_empty() {
			return;
		}
		debug_assert!(
			!self.color.allows_coloring(ConsoleLineRole::ChildStdout),
			"child stdout must never be colorized",
		);
		print!("{}", text);
	}

	fn emit_child_stderr(&self, text: &str) {
		if text.is_empty() {
			return;
		}
		debug_assert!(
			!self.color.allows_coloring(ConsoleLineRole::ChildStderr),
			"child stderr must never be colorized",
		);
		eprint!("{}", text);
	}

	fn emit_console_stdout(
		&self,
		role: ConsoleLineRole,
		message: &str,
	) {
		debug_assert!(
			role.is_console_owned(),
			"console stdout helper used for child role",
		);
		let styled = self.color.format(role, message);
		println!("{}", styled);
	}

	fn emit_console_stderr(
		&self,
		role: ConsoleLineRole,
		message: &str,
	) {
		debug_assert!(
			role.is_console_owned(),
			"console stderr helper used for child role",
		);
		let styled = self.color.format(role, message);
		eprintln!("{}", styled);
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
