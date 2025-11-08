// SPDX-License-Identifier: MIT OR Apache-2.0
// Project: rustgenhash
// Module: benchmark warnings view helpers

use std::collections::HashMap;

use crate::rgh::benchmark::{BenchmarkResult, BenchmarkSummary};
use crate::rgh::hash;

/// Identifies where warning data originated so renderers can scope sections.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WarningSource {
	Mac,
	Kdf,
	Summary,
}

/// Controls how heading + bullet lines should be rendered.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WarningRenderStyle {
	Console,
	Markdown,
}

/// Presentation-ready warning data for a single algorithm profile.
#[derive(Debug, Clone)]
pub struct WarningDescriptor {
	pub algorithm_id: String,
	pub display_name: String,
	pub messages: Vec<String>,
	pub citations: Vec<String>,
	pub source: WarningSource,
	pub occurrence_index: usize,
}

impl WarningDescriptor {
	pub fn combined_text(&self) -> String {
		self.messages
			.iter()
			.map(|msg| msg.trim())
			.filter(|msg| !msg.is_empty())
			.collect::<Vec<_>>()
			.join("; ")
	}

	pub fn render_line(&self) -> String {
		let message = self.combined_text();
		if message.is_empty() {
			return String::new();
		}
		format!("{}: {}", self.display_name, message)
	}
}

/// View object shared by MAC, KDF, and summary renderers.
#[derive(Debug, Clone)]
pub struct WarningsSectionView {
	heading: &'static str,
	context_label: String,
	render_style: WarningRenderStyle,
	items: Vec<WarningDescriptor>,
}

impl WarningsSectionView {
	pub fn new(
		style: WarningRenderStyle,
		context_label: impl Into<String>,
		items: Vec<WarningDescriptor>,
	) -> Self {
		let heading = match style {
			WarningRenderStyle::Console => "Warnings",
			WarningRenderStyle::Markdown => "### Warnings",
		};
		Self {
			heading,
			context_label: context_label.into(),
			render_style: style,
			items,
		}
	}

	pub fn heading(&self) -> &str {
		self.heading
	}

	pub fn context_label(&self) -> &str {
		&self.context_label
	}

	pub fn render_style(&self) -> WarningRenderStyle {
		self.render_style
	}

	pub fn items(&self) -> &[WarningDescriptor] {
		&self.items
	}

	pub fn is_empty(&self) -> bool {
		self.items.is_empty()
	}

	pub fn render_lines(&self) -> Vec<String> {
		if self.is_empty() {
			return Vec::new();
		}
		self.items
			.iter()
			.map(|item| format!("- {}", item.render_line()))
			.collect()
	}
}

fn normalize_warning_text(text: &str) -> String {
	text.trim()
		.trim_start_matches("warning:")
		.trim()
		.replace("  ", " ")
}

fn populate_descriptor_citations(algorithm: &str) -> Vec<String> {
	hash::weak_algorithm_warning(algorithm)
		.map(|warning| {
			warning
				.references
				.iter()
				.map(|reference| reference.to_string())
				.collect()
		})
		.unwrap_or_default()
}

fn dedupe_descriptors(
	cases: &[BenchmarkResult],
	source: WarningSource,
) -> Vec<WarningDescriptor> {
	let mut map: HashMap<String, WarningDescriptor> = HashMap::new();
	for (index, case) in cases.iter().enumerate() {
		if case.warnings.is_empty() {
			continue;
		}
		let entry =
			map.entry(case.algorithm.clone()).or_insert_with(|| {
				WarningDescriptor {
					algorithm_id: case.algorithm.clone(),
					display_name: case.algorithm.clone(),
					messages: Vec::new(),
					citations: populate_descriptor_citations(
						&case.algorithm,
					),
					source,
					occurrence_index: index,
				}
			});
		for warning in &case.warnings {
			let normalized = normalize_warning_text(warning);
			if normalized.is_empty() {
				continue;
			}
			if !entry.messages.iter().any(|msg| msg == &normalized) {
				entry.messages.push(normalized);
			}
		}
	}
	let mut descriptors: Vec<_> = map.into_values().collect();
	descriptors.sort_by_key(|descriptor| descriptor.occurrence_index);
	descriptors
}

fn build_section_from_cases(
	cases: &[BenchmarkResult],
	style: WarningRenderStyle,
	context_label: impl Into<String>,
	source: WarningSource,
) -> WarningsSectionView {
	let items = dedupe_descriptors(cases, source);
	WarningsSectionView::new(style, context_label, items)
}

pub fn section_for_summary(
	summary: &BenchmarkSummary,
	style: WarningRenderStyle,
) -> WarningsSectionView {
	build_section_from_cases(
		&summary.cases,
		style,
		format!("{} summary", summary.scenario.mode),
		WarningSource::Summary,
	)
}

pub fn section_for_cases(
	cases: &[BenchmarkResult],
	style: WarningRenderStyle,
	context_label: impl Into<String>,
	source: WarningSource,
) -> WarningsSectionView {
	build_section_from_cases(cases, style, context_label, source)
}
