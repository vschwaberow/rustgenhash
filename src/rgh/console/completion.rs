// SPDX-License-Identifier: MIT OR Apache-2.0
// Project: rustgenhash
// File: completion.rs
// Author: Volker Schwaberow <volker@schwaberow.de>
// Copyright (c) 2022 Volker Schwaberow

use super::parser;
use crate::rgh::app;
use clap::Command;
use rustyline::completion::Pair;
use std::cmp::Ordering;
use std::sync::OnceLock;

/// Represents the logical scope of the token currently being completed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CompletionScope {
	Root,
	Command { path: Vec<String> },
	Flag { path: Vec<String> },
	Assignment,
	Unknown,
}

/// Snapshot of the editor buffer at the moment completion was requested.
#[derive(Debug, Clone)]
pub struct CompletionContext {
	cursor: usize,
	tokens: Vec<String>,
	prefix: String,
	scope: CompletionScope,
	script_mode: bool,
}

impl CompletionContext {
	pub fn new(
		buffer: &str,
		cursor: usize,
		script_mode: bool,
	) -> Self {
		let cursor = cursor.min(buffer.len());
		let snapshot = parser::cursor_tokens(buffer, cursor);
		let scope = infer_scope(&snapshot.tokens, &snapshot.prefix);
		Self {
			cursor,
			tokens: snapshot.tokens,
			prefix: snapshot.prefix,
			scope,
			script_mode,
		}
	}

	pub fn prefix(&self) -> &str {
		&self.prefix
	}

	pub fn scope(&self) -> &CompletionScope {
		&self.scope
	}

	pub fn script_mode(&self) -> bool {
		self.script_mode
	}

	pub fn completed_tokens(&self) -> &[String] {
		&self.tokens
	}

	pub fn insertion_start(&self) -> usize {
		self.cursor.saturating_sub(self.prefix.len())
	}
}

fn infer_scope(tokens: &[String], prefix: &str) -> CompletionScope {
	if tokens
		.first()
		.map(|token| token.eq_ignore_ascii_case("set"))
		.unwrap_or(false)
	{
		return CompletionScope::Assignment;
	}

	let path: Vec<String> = tokens
		.iter()
		.take_while(|token| !token.starts_with('-'))
		.cloned()
		.collect();

	if prefix.starts_with('-') {
		return CompletionScope::Flag { path };
	}

	if tokens.iter().any(|token| token.starts_with('-')) {
		return CompletionScope::Flag { path };
	}

	if path.is_empty() {
		CompletionScope::Root
	} else {
		CompletionScope::Command { path }
	}
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CompletionKind {
	Command,
	Flag,
}

#[derive(Debug, Clone)]
pub struct CompletionSuggestion {
	pub value: String,
	pub display: String,
	pub kind: CompletionKind,
}

impl CompletionSuggestion {
	fn command(value: &str, description: Option<&str>) -> Self {
		let display = match description {
			Some(desc) if !desc.is_empty() => {
				format!("{:<20} {}", value, desc)
			}
			_ => value.to_string(),
		};
		Self {
			value: value.to_string(),
			display,
			kind: CompletionKind::Command,
		}
	}

	fn flag(value: &str, description: Option<&str>) -> Self {
		let display = match description {
			Some(desc) if !desc.is_empty() => {
				format!("{:<20} {}", value, desc)
			}
			_ => value.to_string(),
		};
		Self {
			value: value.to_string(),
			display,
			kind: CompletionKind::Flag,
		}
	}

	pub fn as_pair(&self) -> Pair {
		Pair {
			display: self.display.clone(),
			replacement: self.value.clone(),
		}
	}
}

#[derive(Debug, Default, Clone)]
pub struct CompletionResult {
	pub suggestions: Vec<CompletionSuggestion>,
	pub replacement: Option<String>,
}

pub struct CompletionEngine {
	catalog: &'static CompletionCatalog,
}

impl Clone for CompletionEngine {
	fn clone(&self) -> Self {
		Self {
			catalog: self.catalog,
		}
	}
}

impl Default for CompletionEngine {
	fn default() -> Self {
		Self {
			catalog: get_catalog(),
		}
	}
}

impl CompletionEngine {
	pub fn suggest(
		&self,
		ctx: &CompletionContext,
	) -> CompletionResult {
		let suggestions = match ctx.scope() {
			CompletionScope::Root => {
				self.catalog.suggest_commands(&[], ctx.prefix())
			}
			CompletionScope::Command { path } => {
				self.catalog.suggest_commands(path, ctx.prefix())
			}
			CompletionScope::Flag { path } => {
				self.catalog.suggest_flags(path, ctx.prefix())
			}
			CompletionScope::Assignment
			| CompletionScope::Unknown => Vec::new(),
		};
		let replacement =
			determine_replacement(ctx.prefix(), &suggestions);
		CompletionResult {
			suggestions,
			replacement,
		}
	}
}

fn determine_replacement(
	prefix: &str,
	suggestions: &[CompletionSuggestion],
) -> Option<String> {
	if suggestions.len() == 1 {
		let value = &suggestions[0].value;
		if value.eq(prefix) {
			None
		} else {
			Some(value.clone())
		}
	} else {
		None
	}
}

#[derive(Debug)]
struct CompletionCatalog {
	nodes: Vec<CommandNode>,
}

impl CompletionCatalog {
	fn node_for_path(&self, path: &[String]) -> Option<&CommandNode> {
		self.nodes.iter().find(|node| node.matches(path))
	}

	fn suggest_commands(
		&self,
		path: &[String],
		prefix: &str,
	) -> Vec<CompletionSuggestion> {
		let node = self
			.node_for_path(path)
			.or_else(|| self.node_for_path(&[]));
		let Some(node) = node else {
			return Vec::new();
		};
		let mut results: Vec<_> = node
			.subcommands
			.iter()
			.filter(|child| {
				prefix.is_empty() || child.name.starts_with(prefix)
			})
			.map(|child| {
				CompletionSuggestion::command(
					&child.name,
					child.about.as_deref(),
				)
			})
			.collect();
		results.sort_by(|a, b| a.value.cmp(&b.value));
		results
	}

	fn suggest_flags(
		&self,
		path: &[String],
		prefix: &str,
	) -> Vec<CompletionSuggestion> {
		let node = self
			.node_for_path(path)
			.or_else(|| self.node_for_path(&[]));
		let Some(node) = node else {
			return Vec::new();
		};
		let mut results: Vec<_> = node
			.flags
			.iter()
			.filter(|flag| {
				prefix.is_empty() || flag.value.starts_with(prefix)
			})
			.map(|flag| {
				CompletionSuggestion::flag(
					&flag.value,
					flag.description.as_deref(),
				)
			})
			.collect();
		results.sort_by(|a, b| match (a.kind, b.kind) {
			(CompletionKind::Command, CompletionKind::Flag) => {
				Ordering::Less
			}
			(CompletionKind::Flag, CompletionKind::Command) => {
				Ordering::Greater
			}
			_ => a.value.cmp(&b.value),
		});
		results
	}
}

#[derive(Debug, Clone)]
struct CommandNode {
	path: Vec<String>,
	subcommands: Vec<CommandChild>,
	flags: Vec<FlagEntry>,
}

impl CommandNode {
	fn matches(&self, path: &[String]) -> bool {
		self.path.len() == path.len()
			&& self
				.path
				.iter()
				.zip(path)
				.all(|(left, right)| left.eq_ignore_ascii_case(right))
	}
}

#[derive(Debug, Clone)]
struct CommandChild {
	name: String,
	about: Option<String>,
}

#[derive(Debug, Clone)]
struct FlagEntry {
	value: String,
	description: Option<String>,
}

fn get_catalog() -> &'static CompletionCatalog {
	static CACHE: OnceLock<CompletionCatalog> = OnceLock::new();
	CACHE.get_or_init(|| CompletionCatalog {
		nodes: build_nodes(app::build_cli()),
	})
}

fn build_nodes(command: Command) -> Vec<CommandNode> {
	let mut nodes = Vec::new();
	collect_nodes(command, Vec::new(), &mut nodes);
	nodes
}

fn collect_nodes(
	command: Command,
	path: Vec<String>,
	nodes: &mut Vec<CommandNode>,
) {
	let subcommands: Vec<CommandChild> = command
		.get_subcommands()
		.map(|sub| CommandChild {
			name: sub.get_name().to_string(),
			about: sub.get_about().map(|s| s.to_string()),
		})
		.collect();

	let mut flags = Vec::new();
	for arg in command.get_arguments() {
		if arg.is_hide_set() {
			continue;
		}
		if let Some(long) = arg.get_long() {
			flags.push(FlagEntry {
				value: format!("--{}", long),
				description: arg.get_help().map(|s| s.to_string()),
			});
		}
		if let Some(short) = arg.get_short() {
			flags.push(FlagEntry {
				value: format!("-{}", short),
				description: arg.get_help().map(|s| s.to_string()),
			});
		}
	}

	nodes.push(CommandNode {
		path: path.clone(),
		subcommands,
		flags,
	});

	for sub in command.get_subcommands() {
		let mut child_path = path.clone();
		child_path.push(sub.get_name().to_string());
		collect_nodes(sub.clone(), child_path, nodes);
	}
}

#[cfg(test)]
mod tests {
	use super::*;

	#[test]
	fn suggests_top_level_commands() {
		let engine = CompletionEngine::default();
		let ctx = CompletionContext::new("", 0, false);
		let result = engine.suggest(&ctx);
		let values: Vec<_> = result
			.suggestions
			.iter()
			.map(|s| s.value.clone())
			.collect();
		assert!(values.contains(&"digest".to_string()));
		assert!(values.contains(&"kdf".to_string()));
		assert!(values.contains(&"mac".to_string()));
	}

	#[test]
	fn suggests_digest_subcommands() {
		let engine = CompletionEngine::default();
		let ctx =
			CompletionContext::new("digest ", "digest ".len(), false);
		let result = engine.suggest(&ctx);
		let values: Vec<_> = result
			.suggestions
			.iter()
			.map(|s| s.value.clone())
			.collect();
		assert!(values.contains(&"string".to_string()));
		assert!(values.contains(&"file".to_string()));
	}

	#[test]
	fn suggests_digest_flags() {
		let engine = CompletionEngine::default();
		let ctx = CompletionContext::new(
			"digest string --",
			"digest string --".len(),
			false,
		);
		let result = engine.suggest(&ctx);
		let values: Vec<_> = result
			.suggestions
			.iter()
			.map(|s| s.value.clone())
			.collect();
		assert!(values.iter().any(|val| val == "--algorithm"));
	}
}
