// SPDX-License-Identifier: MIT OR Apache-2.0
// Project: rustgenhash
// File: poly1305.rs
// Author: Volker Schwaberow <volker@schwaberow.de>

//! Poly1305 executor with one-time key reuse tracking.

use blake3::Hasher;
use poly1305::{
	universal_hash::generic_array::GenericArray,
	universal_hash::KeyInit, universal_hash::UniversalHash,
	Poly1305 as Poly1305Mac,
};

use super::key::validate_poly1305_key_length;
use super::registry::{
	MacAlgorithm, MacAlgorithmMetadata, MacError, MacErrorKind,
	MacExecutor,
};

/// Warning emitted when a Poly1305 key is reused during the same invocation.
pub const POLY1305_REUSE_WARNING: &str =
	"Poly1305 requires one-time keys; reuse detected";

#[derive(Clone, Copy)]
struct Poly1305Session {
	fingerprint: [u8; 16],
	usage_count: u32,
}

/// Tracks Poly1305 key reuse within a single command execution.
#[derive(Default)]
pub struct Poly1305ReuseTracker {
	session: Option<Poly1305Session>,
}

impl Poly1305ReuseTracker {
	/// Returns `Some(POLY1305_REUSE_WARNING)` when the key has been used before in
	/// the current session, otherwise `None`.
	pub fn check_reuse(
		&mut self,
		key: &[u8],
	) -> Option<&'static str> {
		let fingerprint = fingerprint_key(key);
		match &mut self.session {
			Some(session) if session.fingerprint == fingerprint => {
				session.usage_count =
					session.usage_count.saturating_add(1);
				if session.usage_count == 2 {
					Some(POLY1305_REUSE_WARNING)
				} else {
					None
				}
			}
			_ => {
				self.session = Some(Poly1305Session {
					fingerprint,
					usage_count: 1,
				});
				None
			}
		}
	}

	/// Resets the tracker, clearing any recorded key usage.
	pub fn reset(&mut self) {
		self.session = None;
	}
}

fn fingerprint_key(key: &[u8]) -> [u8; 16] {
	let mut hasher = Hasher::new();
	hasher.update(key);
	let mut output = [0u8; 16];
	output.copy_from_slice(&hasher.finalize().as_bytes()[..16]);
	output
}

pub fn catalog() -> &'static [MacAlgorithm] {
	const ALGORITHMS: &[MacAlgorithm] = &[MacAlgorithm::new(
		MacAlgorithmMetadata::current("poly1305", "Poly1305"),
		create_poly1305,
	)];
	ALGORITHMS
}

const POLY1305_BLOCK: usize = 16;

struct Poly1305Executor {
	inner: Poly1305Mac,
	leftover: Vec<u8>,
}

impl MacExecutor for Poly1305Executor {
	fn update(&mut self, data: &[u8]) {
		if data.is_empty() {
			return;
		}
		let mut input = std::mem::take(&mut self.leftover);
		input.extend_from_slice(data);
		let full = input.len() - (input.len() % POLY1305_BLOCK);
		if full > 0 {
			let mut blocks = Vec::with_capacity(full / POLY1305_BLOCK);
			for chunk in input[..full].chunks_exact(POLY1305_BLOCK) {
				blocks.push(GenericArray::clone_from_slice(chunk));
			}
			self.inner.update(&blocks);
		}
		self.leftover = input[full..].to_vec();
	}

	fn finalize(self: Box<Self>) -> Vec<u8> {
		let this = *self;
		let mut inner = this.inner;
		inner.update_padded(&this.leftover);
		inner.finalize().to_vec()
	}
}

fn create_poly1305(
	key: &[u8],
) -> Result<Box<dyn MacExecutor>, MacError> {
	validate_poly1305_key_length(key)?;
	let mac = Poly1305Mac::new_from_slice(key).map_err(|_| {
		MacError::new(
			MacErrorKind::InvalidKeyLength,
			"Poly1305 failed to initialize with provided key",
		)
	})?;
	Ok(Box::new(Poly1305Executor {
		inner: mac,
		leftover: Vec::new(),
	}))
}

#[cfg(test)]
mod poly1305_stream_tests {
	use super::create_poly1305;
	fn tag(chunks: &[&[u8]]) -> Vec<u8> {
		let key = [7u8; 32];
		let mut exec = create_poly1305(&key).expect("key");
		for chunk in chunks {
			exec.update(chunk);
		}
		exec.finalize()
	}

	#[test]
	fn poly1305_chunked_matches_oneshot() {
		let data: Vec<u8> = (0..8193).map(|i| (i % 251) as u8).collect();
		let oneshot = tag(&[&data]);
		let mut chunks = Vec::new();
		for piece in data.chunks(100) {
			chunks.push(piece);
		}
		let chunked = tag(&chunks);
		assert_eq!(oneshot, chunked);
	}
}
