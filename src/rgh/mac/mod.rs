// SPDX-License-Identifier: MIT OR Apache-2.0
// Project: rustgenhash
// Module: mac (message authentication codes)
// Author: Volker Schwaberow <volker@schwaberow.de>
// Copyright (c) 2025 Volker Schwaberow

//! Shared entry point for keyed message authentication code (MAC) support.
//! Submodules provide registry, key loading, algorithm executors, and CLI handlers.

pub mod blake3;
pub mod commands;
pub mod executor;
pub mod hmac;
pub mod key;
pub mod kmac;
pub mod registry;
