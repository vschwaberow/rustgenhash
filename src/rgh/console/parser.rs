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

/// Token snapshot for completion analysis.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CursorTokens {
	pub tokens: Vec<String>,
	pub prefix: String,
	pub in_quotes: bool,
}

/// Basic tokenizer supporting `set $var =` prefix and quoted strings.
pub fn parse_command(input: &str) -> ParsedCommand {
	let trimmed = input.trim();
	if trimmed.is_empty() {
		return ParsedCommand {
			raw: String::new(),
			tokens: Vec::new(),
			assignment: None,
		};
	}

	let (tokens, _, _) = tokenize_segments(trimmed, false);

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

/// Returns the tokens completed before the cursor plus the in-progress prefix.
pub fn cursor_tokens(input: &str, cursor: usize) -> CursorTokens {
	let cursor = cursor.min(input.len());
	let (tokens, prefix, in_quotes) =
		tokenize_segments(&input[..cursor], true);
	CursorTokens {
		tokens,
		prefix,
		in_quotes,
	}
}

fn tokenize_segments(
	input: &str,
	keep_partial: bool,
) -> (Vec<String>, String, bool) {
	let mut tokens = Vec::new();
	let mut current = String::new();
	let mut in_quotes = false;

	for ch in input.chars() {
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

	if !keep_partial && !current.is_empty() {
		tokens.push(current.clone());
		current.clear();
	}

	(
		tokens,
		if keep_partial { current } else { String::new() },
		in_quotes,
	)
}

#[cfg(test)]
mod tests {
	use super::*;

	#[test]
	fn cursor_tokens_tracks_partial_subcommand() {
		let ctx = cursor_tokens("digest str", "digest str".len());
		assert_eq!(ctx.tokens, vec!["digest".to_string()]);
		assert_eq!(ctx.prefix, "str");
	}

	#[test]
	fn cursor_tokens_handles_quotes() {
		let buffer = "digest \"alpha beta";
		let ctx = cursor_tokens(buffer, buffer.len());
		assert_eq!(ctx.tokens, vec!["digest".to_string()]);
		assert_eq!(ctx.prefix, "\"alpha beta");
		assert!(ctx.in_quotes);
	}
}
