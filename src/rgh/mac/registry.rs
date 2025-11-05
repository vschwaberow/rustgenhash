// SPDX-License-Identifier: MIT OR Apache-2.0
// Project: rustgenhash
// File: registry.rs
// Author: Volker Schwaberow <volker@schwaberow.de>
// Copyright (c) 2025

//! Registry definitions for MAC algorithms, including factory dispatch and
//! metadata helpers shared by the CLI and audit harness.

use std::borrow::Cow;

use super::{blake3, hmac, kmac};

pub trait MacExecutor: Send + 'static {
	fn update(&mut self, data: &[u8]);
	fn finalize(self: Box<Self>) -> Vec<u8>;
}

#[derive(Clone, Copy, Debug)]
pub struct MacAlgorithmMetadata {
	pub identifier: &'static str,
	pub display_name: &'static str,
	pub legacy: bool,
}

impl MacAlgorithmMetadata {
	pub const fn new(
		identifier: &'static str,
		display_name: &'static str,
		legacy: bool,
	) -> Self {
		Self {
			identifier,
			display_name,
			legacy,
		}
	}

	pub const fn legacy(
		identifier: &'static str,
		display_name: &'static str,
	) -> Self {
		Self::new(identifier, display_name, true)
	}

	pub const fn current(
		identifier: &'static str,
		display_name: &'static str,
	) -> Self {
		Self::new(identifier, display_name, false)
	}

	pub fn is_legacy(&self) -> bool {
		self.legacy
	}
}

pub type MacFactory =
	fn(&[u8]) -> Result<Box<dyn MacExecutor>, MacError>;

#[derive(Clone, Copy)]
pub struct MacAlgorithm {
	pub metadata: MacAlgorithmMetadata,
	pub factory: MacFactory,
}

impl MacAlgorithm {
	pub const fn new(
		metadata: MacAlgorithmMetadata,
		factory: MacFactory,
	) -> Self {
		Self { metadata, factory }
	}
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MacErrorKind {
	UnsupportedAlgorithm,
	InvalidKey,
	InvalidKeyLength,
	Crypto,
}

#[derive(Debug)]
pub struct MacError {
	kind: MacErrorKind,
	message: Cow<'static, str>,
}

impl MacError {
	pub fn new(
		kind: MacErrorKind,
		message: impl Into<Cow<'static, str>>,
	) -> Self {
		Self {
			kind,
			message: message.into(),
		}
	}

	pub fn kind(&self) -> MacErrorKind {
		self.kind
	}

	pub fn message(&self) -> &str {
		self.message.as_ref()
	}
}

impl std::fmt::Display for MacError {
	fn fmt(
		&self,
		f: &mut std::fmt::Formatter<'_>,
	) -> std::fmt::Result {
		write!(f, "{}", self.message)
	}
}

impl std::error::Error for MacError {}

pub fn algorithms() -> impl Iterator<Item = &'static MacAlgorithm> {
	hmac::catalog()
		.iter()
		.chain(kmac::catalog().iter())
		.chain(blake3::catalog().iter())
}

pub fn metadata() -> Vec<MacAlgorithmMetadata> {
	algorithms().map(|alg| alg.metadata).collect()
}

pub fn find_algorithm(
	identifier: &str,
) -> Option<&'static MacAlgorithm> {
	algorithms().find(|alg| {
		alg.metadata.identifier.eq_ignore_ascii_case(identifier)
	})
}

pub fn create_executor(
	identifier: &str,
	key: &[u8],
) -> Result<(Box<dyn MacExecutor>, MacAlgorithmMetadata), MacError> {
	let algorithm = find_algorithm(identifier).ok_or_else(|| {
		MacError::new(
			MacErrorKind::UnsupportedAlgorithm,
			format!("unsupported MAC algorithm `{}`", identifier),
		)
	})?;
	let executor = (algorithm.factory)(key)?;
	Ok((executor, algorithm.metadata))
}
