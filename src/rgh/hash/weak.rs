// SPDX-License-Identifier: MIT OR Apache-2.0
// Project: rustgenhash
// File: hash/weak.rs

use crate::rgh::weak as weak_registry;

pub struct WeakAlgorithmWarning {
	pub severity_icon: &'static str,
	pub headline: String,
	pub body: String,
	pub references: &'static [&'static str],
}

impl From<weak_registry::WarningMessage> for WeakAlgorithmWarning {
	fn from(value: weak_registry::WarningMessage) -> Self {
		Self {
			severity_icon: value.severity_icon,
			headline: value.headline,
			body: value.body,
			references: value.references,
		}
	}
}

pub fn weak_algorithm_warning(
	algorithm: &str,
) -> Option<WeakAlgorithmWarning> {
	weak_registry::warning_for(algorithm).map(WeakAlgorithmWarning::from)
}
