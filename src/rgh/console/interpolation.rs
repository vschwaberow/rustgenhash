// SPDX-License-Identifier: MIT OR Apache-2.0

use super::variables::ConsoleVariableStore;
use std::fmt;

/// Errors that can occur during variable interpolation.
#[derive(Debug, Clone)]
pub enum InterpolationError {
	DanglingDollar,
	UndefinedVariable(String),
}

impl fmt::Display for InterpolationError {
	fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
		match self {
			Self::DanglingDollar => {
				write!(f, "dangling `$` without variable name")
			}
			Self::UndefinedVariable(name) => {
				write!(f, "undefined variable ${}", name)
			}
		}
	}
}

/// Performs basic `$name` substitution using the provided variable store.
pub fn interpolate(
	input: &str,
	store: &ConsoleVariableStore,
) -> Result<String, InterpolationError> {
	let mut output = String::new();
	let mut chars = input.chars().peekable();
	while let Some(ch) = chars.next() {
		if ch == '$' {
			if let Some('$') = chars.peek() {
				chars.next();
				output.push('$');
				continue;
			}
			let mut name = String::new();
			while let Some(c) = chars.peek() {
				if c.is_alphanumeric() || *c == '_' {
					name.push(*c);
					chars.next();
				} else {
					break;
				}
			}
			if name.is_empty() {
				return Err(InterpolationError::DanglingDollar);
			}
			if let Some(var) = store.get(&name) {
				output.push_str(&var.value);
			} else {
				return Err(InterpolationError::UndefinedVariable(
					name,
				));
			}
		} else {
			output.push(ch);
		}
	}
	Ok(output)
}
