// SPDX-License-Identifier: MIT OR Apache-2.0
// Project: rustgenhash
// File: executor.rs
// Author: Volker Schwaberow <volker@schwaberow.de>

//! Streaming helpers for MAC computation.

use super::registry::MacExecutor;
use hex::encode;
use std::io::{self, Read};

const MAC_BUFFER_SIZE: usize = 8192;

pub fn consume_reader<R: Read>(
	mut reader: R,
	mut executor: Box<dyn MacExecutor>,
) -> io::Result<Vec<u8>> {
	let mut buffer = [0u8; MAC_BUFFER_SIZE];
	loop {
		let n = reader.read(&mut buffer)?;
		if n == 0 {
			break;
		}
		executor.update(&buffer[..n]);
	}
	Ok(executor.finalize())
}

pub fn consume_bytes(
	data: &[u8],
	mut executor: Box<dyn MacExecutor>,
) -> Vec<u8> {
	executor.update(data);
	executor.finalize()
}

pub fn digest_to_hex(bytes: &[u8]) -> String {
	encode(bytes)
}
