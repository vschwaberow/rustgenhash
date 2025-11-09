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
use super::export::{self, ExportFormat};
use super::help::HelpResolver;
use super::history::{self, ConsoleHistoryConfig, HistoryRetention};
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
use std::path::PathBuf;
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
	history_path: Option<PathBuf>,
	history_retention: HistoryRetention,
	history_dirty: bool,
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
		let (history_path, history_retention) =
			Self::resolve_history_prefs(
				options.tty_mode,
				&options.history,
			);
		control::set_override(color.should_emit());
		let mut session = Self {
			options,
			variables: ConsoleVariableStore::default(),
			history: Vec::new(),
			prompt_label: "rgh-console".into(),
			completion: CompletionEngine::default(),
			help: HelpResolver,
			color,
			history_path,
			history_retention,
			history_dirty: false,
		};
		session.load_history_from_disk();

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
			BuiltinAction::HistorySave(path) => {
				self.handle_manual_history_save(&path);
				return Ok(Flow::Continue);
			}
			BuiltinAction::HistoryLoad(path) => {
				self.handle_manual_history_load(&path);
				return Ok(Flow::Continue);
			}
			BuiltinAction::HistoryClear => {
				self.handle_manual_history_clear();
				return Ok(Flow::Continue);
			}
			BuiltinAction::ExportVars {
				path,
				format,
				include_secrets,
				auto_confirm,
			} => {
				self.handle_export_vars_command(
					path,
					format,
					include_secrets,
					auto_confirm,
				);
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
		let stored_command = match self.history_retention {
			HistoryRetention::Sanitized => {
				history::sanitize_command(command)
			}
			_ => command.to_string(),
		};
		self.history.push(CommandEntry {
			command: stored_command,
			exit_code,
			timestamp: SystemTime::now(),
		});
		if self.history.len() > 1000 {
			self.history.remove(0);
		}
		if self.history_active() {
			self.history_dirty = true;
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

	fn manual_history_allowed(&self) -> bool {
		matches!(self.options.tty_mode, ConsoleMode::Interactive)
			|| self.options.history.force_script_history
	}

	fn handle_manual_history_save(&mut self, path: &PathBuf) {
		if !self.manual_history_allowed() {
			self.emit_console_stdout(
				ConsoleLineRole::Warning,
				"history commands unavailable in script mode",
			);
			return;
		}
		if self.history.is_empty() {
			self.emit_console_stdout(
				ConsoleLineRole::Info,
				"(history empty; nothing to save)",
			);
			return;
		}
		let retention = if self.history_retention.is_enabled() {
			self.history_retention
		} else {
			HistoryRetention::Sanitized
		};
		let records: Vec<history::HistoryRecord> = self
			.history
			.iter()
			.map(|entry| history::HistoryRecord {
				timestamp: entry.timestamp,
				command: if matches!(
					retention,
					HistoryRetention::Sanitized
				) {
					history::sanitize_command(&entry.command)
				} else {
					entry.command.clone()
				},
				exit_code: entry.exit_code,
			})
			.collect();
		match history::save_snapshot(path, retention, &records) {
			Ok(_) => self.emit_console_stdout(
				ConsoleLineRole::Success,
				&format!(
					"saved history to {} ({}, entries={})",
					path.display(),
					retention,
					self.history.len()
				),
			),
			Err(err) => self.emit_console_stderr(
				ConsoleLineRole::Warning,
				&format!(
					"failed to save history ({}): {}",
					path.display(),
					err
				),
			),
		}
	}

	fn handle_manual_history_load(&mut self, path: &PathBuf) {
		if !self.manual_history_allowed() {
			self.emit_console_stdout(
				ConsoleLineRole::Warning,
				"history commands unavailable in script mode",
			);
			return;
		}
		match history::load_snapshot(path) {
			Ok(snapshot) => {
				if matches!(
					snapshot.retention,
					HistoryRetention::Verbatim
				) && !matches!(
					self.history_retention,
					HistoryRetention::Verbatim
				) {
					self.emit_console_stdout(
						ConsoleLineRole::Warning,
						"loaded verbatim history; commands may include secrets",
					);
				}
				self.history.clear();
				for entry in snapshot.entries {
					self.history.push(CommandEntry {
						command: entry.command,
						exit_code: entry.exit_code,
						timestamp: entry.timestamp,
					});
				}
				while self.history.len() > 1000 {
					self.history.remove(0);
				}
				self.history_dirty =
					self.history_active() && !self.history.is_empty();
				self.emit_console_stdout(
					ConsoleLineRole::Success,
					&format!(
						"loaded {} history entries from {}",
						self.history.len(),
						path.display()
					),
				);
			}
			Err(err) => {
				self.emit_console_stderr(
					ConsoleLineRole::Warning,
					&format!(
						"failed to load history ({}): {}",
						path.display(),
						err
					),
				);
			}
		}
	}

	fn handle_manual_history_clear(&mut self) {
		if !self.manual_history_allowed() {
			self.emit_console_stdout(
				ConsoleLineRole::Warning,
				"history commands unavailable in script mode",
			);
			return;
		}
		self.history.clear();
		self.history_dirty = false;
		self.emit_console_stdout(
			ConsoleLineRole::Info,
			"history cleared",
		);
	}

	fn handle_export_vars_command(
		&mut self,
		path: PathBuf,
		format: ExportFormat,
		include_secrets: bool,
		auto_confirm: bool,
	) {
		let vars = self.variables.list();
		if vars.is_empty() {
			self.emit_console_stdout(
				ConsoleLineRole::Info,
				"(no variables defined; nothing to export)",
			);
			return;
		}
		if include_secrets && !auto_confirm {
			self.emit_console_stdout(
				ConsoleLineRole::Warning,
				"export vars --include-secrets requires --yes to confirm disk writes",
			);
			return;
		}
		let includes = include_secrets;
		match export::write_manifest(&path, &vars, format, includes) {
			Ok(_) => {
				let detail = if includes {
					"includes secrets"
				} else {
					"masked"
				};
				let fmt = match format {
					ExportFormat::Json => "json",
					ExportFormat::Yaml => "yaml",
				};
				self.emit_console_stdout(
					ConsoleLineRole::Success,
					&format!(
						"wrote {} variables to {} ({}, {})",
						vars.len(),
						path.display(),
						fmt,
						detail
					),
				);
			}
			Err(err) => {
				self.emit_console_stderr(
					ConsoleLineRole::Warning,
					&format!(
						"failed to export vars ({}): {}",
						path.display(),
						err
					),
				);
			}
		}
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

	fn history_active(&self) -> bool {
		self.history_path.is_some()
			&& self.history_retention.is_enabled()
	}

	fn load_history_from_disk(&mut self) {
		if !self.history_active() {
			return;
		}
		let Some(path) = self.history_path.clone() else {
			return;
		};
		match history::load_snapshot(&path) {
			Ok(snapshot) => {
				for entry in snapshot.entries {
					self.history.push(CommandEntry {
						command: entry.command,
						exit_code: entry.exit_code,
						timestamp: entry.timestamp,
					});
				}
				self.history_dirty = false;
			}
			Err(err) => {
				self.emit_console_stderr(
					ConsoleLineRole::Warning,
					&format!(
						"failed to load console history ({}): {}",
						path.display(),
						err
					),
				);
			}
		}
	}

	fn flush_history(&mut self) {
		if !self.history_active() || !self.history_dirty {
			return;
		}
		let Some(path) = self.history_path.clone() else {
			return;
		};
		let retention = self.history_retention;
		let records: Vec<history::HistoryRecord> = self
			.history
			.iter()
			.map(|entry| history::HistoryRecord {
				timestamp: entry.timestamp,
				command: if matches!(
					retention,
					HistoryRetention::Sanitized
				) {
					history::sanitize_command(&entry.command)
				} else {
					entry.command.clone()
				},
				exit_code: entry.exit_code,
			})
			.collect();
		if let Err(err) =
			history::save_snapshot(&path, retention, &records)
		{
			self.emit_console_stderr(
				ConsoleLineRole::Warning,
				&format!(
					"failed to save console history ({}): {}",
					path.display(),
					err
				),
			);
		} else {
			self.history_dirty = false;
		}
	}

	fn resolve_history_prefs(
		mode: ConsoleMode,
		config: &ConsoleHistoryConfig,
	) -> (Option<PathBuf>, HistoryRetention) {
		let allowed = !matches!(mode, ConsoleMode::Script)
			|| config.force_script_history;
		if !allowed {
			return (None, HistoryRetention::Off);
		}
		let retention = config.retention;
		let path = if retention.is_enabled() {
			config.file_path.clone()
		} else {
			None
		};
		if path.is_none() {
			return (None, HistoryRetention::Off);
		}
		(path, retention)
	}
}

impl Drop for ConsoleSession {
	fn drop(&mut self) {
		self.flush_history();
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
