// SPDX-License-Identifier: MIT OR Apache-2.0
// Project: rustgenhash
// File: progress.rs
// Author: Volker Schwaberow <volker@schwaberow.de>
// Copyright (c) 2022 Volker Schwaberow

use std::io::{self, Write};
use std::time::{Duration, Instant};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ProgressMode {
	Auto,
	Enabled,
	Disabled,
}

#[derive(Clone, Copy, Debug)]
pub struct ProgressConfig {
	pub mode: ProgressMode,
	pub throttle: Duration,
}

impl ProgressConfig {
	pub fn should_emit(&self, hash_only: bool, is_tty: bool) -> bool {
		match self.mode {
			ProgressMode::Disabled => false,
			ProgressMode::Enabled => !hash_only,
			ProgressMode::Auto => !hash_only && is_tty,
		}
	}
}

pub struct ProgressEmitter {
	config: ProgressConfig,
	last_emit: Instant,
	processed_entries: u64,
	processed_bytes: u128,
	start: Instant,
}

impl ProgressEmitter {
	pub fn new(config: ProgressConfig) -> Self {
		Self {
			config,
			last_emit: Instant::now(),
			processed_entries: 0,
			processed_bytes: 0,
			start: Instant::now(),
		}
	}

	pub fn record(&mut self, bytes: u64) {
		self.processed_entries += 1;
		self.processed_bytes += bytes as u128;
	}

	pub fn maybe_emit(&mut self) {
		if self.last_emit.elapsed() < self.config.throttle {
			return;
		}
		self.emit_message();
	}

	pub fn emit_final(&mut self) {
		self.emit_message();
	}

	fn emit_message(&mut self) {
		self.last_emit = Instant::now();
		let elapsed = self.start.elapsed().as_secs_f64().max(0.001);
		let throughput = (self.processed_bytes as f64) / elapsed;
		let message = format!(
			"Processed {} items ({:.1} KiB/s)",
			self.processed_entries,
			throughput / 1024.0,
		);
		let _ = writeln!(io::stderr(), "{}", message);
	}
}
