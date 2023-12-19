// SPDX-License-Identifier: MIT OR Apache-2.0
// Project: rustgenhash
// File: main.rs
// Author: Volker Schwaberow <volker@schwaberow.de>
// Copyright (c) 2022 Volker Schwaberow

use rustgenhash::rgh::app;

fn main() -> Result<(), Box<dyn std::error::Error>> {
	app::run()?;
	Ok(())
}
