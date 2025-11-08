// SPDX-License-Identifier: MIT OR Apache-2.0

use crate::rgh::app;
use std::fmt;

const TOPIC_ALIASES: &[(&[&str], &[&str])] = &[
	(&["digest"], &["digest"]),
	(&["digest", "string"], &["digest", "string"]),
	(&["digest", "file"], &["digest", "file"]),
	(&["digest", "stdio"], &["digest", "stdio"]),
	(&["kdf"], &["kdf"]),
	(&["kdf", "hkdf"], &["kdf", "hkdf"]),
	(&["kdf", "argon2"], &["kdf", "argon2"]),
	(&["kdf", "scrypt"], &["kdf", "scrypt"]),
	(&["mac"], &["mac"]),
	(&["benchmark", "mac"], &["benchmark", "mac"]),
	(&["benchmark", "kdf"], &["benchmark", "kdf"]),
	(&["benchmark", "summarize"], &["benchmark", "summarize"]),
	(&["console"], &["console"]),
];

#[derive(Debug, Clone)]
pub struct HelpDocument {
	pub title: String,
	pub body: String,
	pub path: Vec<String>,
}

#[derive(Debug, Clone)]
pub enum HelpError {
	EmptyTopic,
	UnknownTopic(Vec<String>),
}

impl HelpError {
	pub fn exit_code(&self) -> i32 {
		match self {
			HelpError::EmptyTopic => 64,
			HelpError::UnknownTopic(_) => 64,
		}
	}
}

impl fmt::Display for HelpError {
	fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
		match self {
			HelpError::EmptyTopic => write!(f, "help topic required"),
			HelpError::UnknownTopic(path) => {
				write!(f, "unknown topic '{}'", path.join(" "))
			}
		}
	}
}

impl std::error::Error for HelpError {}

#[derive(Debug, Clone, Default)]
pub struct HelpResolver;

impl HelpResolver {
	pub fn resolve(
		&self,
		topic: &[String],
	) -> Result<HelpDocument, HelpError> {
		if topic.is_empty() {
			return Err(HelpError::EmptyTopic);
		}
		let normalized = canonicalize_topic(topic);
		match app::render_help_for_path(&normalized) {
			Some(body) => Ok(HelpDocument {
				title: normalized.join(" "),
				body,
				path: normalized,
			}),
			None => Err(HelpError::UnknownTopic(normalized)),
		}
	}
}

pub fn tokenize_topic(input: &str) -> Vec<String> {
	input
		.split_whitespace()
		.filter(|segment| !segment.is_empty())
		.map(|segment| segment.to_string())
		.collect()
}

fn canonicalize_topic(tokens: &[String]) -> Vec<String> {
	if tokens.is_empty() {
		return Vec::new();
	}
	let lowered: Vec<String> = tokens
		.iter()
		.map(|segment| segment.to_ascii_lowercase())
		.collect();
	for (alias, target) in TOPIC_ALIASES {
		if alias.len() == lowered.len()
			&& alias
				.iter()
				.zip(&lowered)
				.all(|(expected, actual)| expected == actual)
		{
			return target
				.iter()
				.map(|segment| segment.to_string())
				.collect();
		}
	}
	lowered
}

#[cfg(test)]
mod tests {
	use super::*;

	#[test]
	fn resolves_known_topic() {
		let resolver = HelpResolver::default();
		let doc = resolver
			.resolve(&vec!["digest".into(), "string".into()])
			.expect("topic");
		assert_eq!(doc.path, vec!["digest", "string"]);
		assert!(!doc.body.trim().is_empty());
	}

	#[test]
	fn alias_maps_to_known_topic() {
		let resolver = HelpResolver::default();
		let doc = resolver
			.resolve(&vec!["Benchmark".into(), "Mac".into()])
			.expect("topic");
		assert_eq!(doc.path, vec!["benchmark", "mac"]);
	}
}
