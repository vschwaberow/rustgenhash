// SPDX-License-Identifier: MIT OR Apache-2.0

/// Parsed representation of a console command.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ParsedCommand {
	pub raw: String,
	pub tokens: Vec<String>,
	pub assignment: Option<String>,
}

impl ParsedCommand {
	pub fn is_assignment(&self) -> bool {
		self.assignment.is_some()
	}
}

/// Basic tokenizer supporting `set $var =` prefix and quoted strings.
#[allow(clippy::while_let_on_iterator)]
pub fn parse_command(input: &str) -> ParsedCommand {
	let trimmed = input.trim();
	if trimmed.is_empty() {
		return ParsedCommand {
			raw: String::new(),
			tokens: Vec::new(),
			assignment: None,
		};
	}

	let mut tokens = Vec::new();
	let mut current = String::new();
	let mut chars = trimmed.chars().peekable();
	let mut in_quotes = false;

	while let Some(ch) = chars.next() {
		match ch {
			'"' => {
				in_quotes = !in_quotes;
			}
			' ' | '\t' if !in_quotes => {
				if !current.is_empty() {
					tokens.push(current.clone());
					current.clear();
				}
			}
			_ => current.push(ch),
		}
	}
	if !current.is_empty() {
		tokens.push(current);
	}

	let assignment = if tokens.len() >= 4
		&& tokens[0].eq_ignore_ascii_case("set")
		&& tokens[2] == "="
		&& tokens[1].starts_with('$')
	{
		Some(tokens[1].trim_start_matches('$').to_string())
	} else {
		None
	};

	ParsedCommand {
		raw: trimmed.to_string(),
		tokens,
		assignment,
	}
}
