// SPDX-License-Identifier: MIT OR Apache-2.0
// Project: rustgenhash

pub mod builtins;
pub mod completion;
pub mod dispatcher;
pub mod help;
pub mod interpolation;
pub mod parser;
pub mod script;
pub mod session;
pub mod variables;

use session::{ConsoleMode as SessionConsoleMode, ConsoleSession};
use std::fmt::{self, Display};
use std::path::PathBuf;

/// Options provided when launching the console.
#[derive(Debug, Clone)]
pub struct ConsoleOptions {
	pub script_path: Option<PathBuf>,
	pub ignore_errors: bool,
	pub tty_mode: ConsoleMode,
}

impl ConsoleOptions {
	pub fn interactive() -> Self {
		Self {
			script_path: None,
			ignore_errors: false,
			tty_mode: SessionConsoleMode::Interactive,
		}
	}

	pub fn from_script(path: PathBuf, ignore_errors: bool) -> Self {
		Self {
			script_path: Some(path),
			ignore_errors,
			tty_mode: SessionConsoleMode::Script,
		}
	}
}

/// Error wrapper for console-related failures.
#[derive(Debug)]
pub enum ConsoleError {
	Io(std::io::Error),
	Message(String),
	Variable(String),
}

impl Display for ConsoleError {
	fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
		match self {
			Self::Io(err) => write!(f, "{}", err),
			Self::Message(msg) => write!(f, "{}", msg),
			Self::Variable(name) => {
				write!(f, "undefined variable ${}", name)
			}
		}
	}
}

impl std::error::Error for ConsoleError {}

impl From<std::io::Error> for ConsoleError {
	fn from(value: std::io::Error) -> Self {
		Self::Io(value)
	}
}

impl ConsoleError {
	pub fn exit_code(&self) -> i32 {
		match self {
			ConsoleError::Variable(_) => 65,
			ConsoleError::Io(_) | ConsoleError::Message(_) => 70,
		}
	}
}

/// Entry point invoked by `rgh console`.
pub fn run_console(
	options: ConsoleOptions,
) -> Result<i32, ConsoleError> {
	let mut session = ConsoleSession::new(options);
	session.run()
}

pub use parser::{parse_command, ParsedCommand};
pub use session::ConsoleMode;
pub use variables::{
	ConsoleValueType, ConsoleVariable, ConsoleVariableStore,
};
