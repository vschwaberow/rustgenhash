// SPDX-License-Identifier: MIT OR Apache-2.0
// Project: rustgenhash

mod sbox;

use digest::{
	typenum::{U16, U32},
	FixedOutput, FixedOutputReset, HashMarker, Output,
	OutputSizeUser, Reset, Update,
};

const ROUNDS: usize = 8;

#[derive(Clone)]
struct Core {
	hash: [u32; 8],
	buffer: [u8; 48],
	index: usize,
	length: u64,
	digest_len: usize,
}

impl Core {
	fn new(digest_len: usize) -> Self {
		Self {
			hash: [0; 8],
			buffer: [0; 48],
			index: 0,
			length: 0,
			digest_len,
		}
	}

	fn block_size(&self) -> usize {
		64 - self.digest_len
	}

	fn process_block(&mut self, block: &[u8]) {
		let mut w = [0u32; 16];
		w[0] = self.hash[0];
		w[1] = self.hash[1];
		w[2] = self.hash[2];
		w[3] = self.hash[3];
		let mut off = 0;
		if self.digest_len == 32 {
			w[4] = self.hash[4];
			w[5] = self.hash[5];
			w[6] = self.hash[6];
			w[7] = self.hash[7];
		} else {
			for i in 0..4 {
				let mut word = [0u8; 4];
				word.copy_from_slice(&block[off..off + 4]);
				w[4 + i] = u32::from_be_bytes(word);
				off += 4;
			}
		}
		for i in 0..8 {
			let mut word = [0u8; 4];
			word.copy_from_slice(&block[off..off + 4]);
			w[8 + i] = u32::from_be_bytes(word);
			off += 4;
		}
		for round in 0..ROUNDS {
			let sbox = &sbox::SBOX[round * 512..(round + 1) * 512];
			let mut rot = 0x1810_0810u32;
			while rot != 0 {
				let r = rot as u8;
				for i in 0..16 {
					let x = sbox[(i << 7 & 0x100) + (w[i] as usize & 0xff)];
					let prev = (i.wrapping_sub(1)) & 0x0f;
					w[prev] ^= x;
					if i >= 2 {
						w[prev] = w[prev].rotate_right(r as u32);
					}
					w[(i + 1) & 0x0f] ^= x;
				}
				w[0] = w[0].rotate_right(r as u32);
				w[15] = w[15].rotate_right(r as u32);
				rot >>= 8;
			}
		}
		self.hash[0] ^= w[15];
		self.hash[1] ^= w[14];
		self.hash[2] ^= w[13];
		self.hash[3] ^= w[12];
		if self.digest_len == 32 {
			self.hash[4] ^= w[11];
			self.hash[5] ^= w[10];
			self.hash[6] ^= w[9];
			self.hash[7] ^= w[8];
		}
	}

	fn absorb(&mut self, mut msg: &[u8]) {
		let bs = self.block_size();
		self.length = self.length.wrapping_add(msg.len() as u64);
		if self.index != 0 {
			let left = bs - self.index;
			let take = left.min(msg.len());
			self.buffer[self.index..self.index + take]
				.copy_from_slice(&msg[..take]);
			if take < left {
				self.index += take;
				return;
			}
			let owned = self.buffer;
			self.process_block(&owned[..bs]);
			msg = &msg[take..];
			self.index = 0;
		}
		while msg.len() >= bs {
			self.process_block(&msg[..bs]);
			msg = &msg[bs..];
		}
		if !msg.is_empty() {
			self.buffer[..msg.len()].copy_from_slice(msg);
		}
		self.index = msg.len();
	}

	fn finish(&mut self, out: &mut [u8]) {
		let bs = self.block_size();
		let dw = self.digest_len / 4;
		if self.index != 0 {
			self.buffer[self.index..bs].fill(0);
			let owned = self.buffer;
			self.process_block(&owned[..bs]);
		}
		self.buffer[..bs].fill(0);
		let hi = (self.length >> 29) as u32;
		let lo = (self.length << 3) as u32;
		let idx_hi = 14 - dw;
		let idx_lo = 15 - dw;
		self.buffer[idx_hi * 4..idx_hi * 4 + 4]
			.copy_from_slice(&hi.to_be_bytes());
		self.buffer[idx_lo * 4..idx_lo * 4 + 4]
			.copy_from_slice(&lo.to_be_bytes());
		let owned = self.buffer;
		self.process_block(&owned[..bs]);
		for (i, word) in self.hash.iter().take(dw).enumerate() {
			out[i * 4..i * 4 + 4]
				.copy_from_slice(&word.to_be_bytes());
		}
	}
}

#[derive(Clone)]
pub struct Snefru128 {
	core: Core,
}

impl Default for Snefru128 {
	fn default() -> Self {
		Self {
			core: Core::new(16),
		}
	}
}

impl Snefru128 {
	pub fn new() -> Self {
		Self::default()
	}
}

impl HashMarker for Snefru128 {}

impl OutputSizeUser for Snefru128 {
	type OutputSize = U16;
}

impl Update for Snefru128 {
	fn update(&mut self, data: &[u8]) {
		self.core.absorb(data);
	}
}

impl FixedOutput for Snefru128 {
	fn finalize_into(mut self, out: &mut Output<Self>) {
		self.core.finish(out);
	}
}

impl Reset for Snefru128 {
	fn reset(&mut self) {
		self.core = Core::new(16);
	}
}

impl FixedOutputReset for Snefru128 {
	fn finalize_into_reset(&mut self, out: &mut Output<Self>) {
		self.core.finish(out);
		self.core = Core::new(16);
	}
}

#[derive(Clone)]
pub struct Snefru256 {
	core: Core,
}

impl Default for Snefru256 {
	fn default() -> Self {
		Self {
			core: Core::new(32),
		}
	}
}

impl Snefru256 {
	pub fn new() -> Self {
		Self::default()
	}
}

impl HashMarker for Snefru256 {}

impl OutputSizeUser for Snefru256 {
	type OutputSize = U32;
}

impl Update for Snefru256 {
	fn update(&mut self, data: &[u8]) {
		self.core.absorb(data);
	}
}

impl FixedOutput for Snefru256 {
	fn finalize_into(mut self, out: &mut Output<Self>) {
		self.core.finish(out);
	}
}

impl Reset for Snefru256 {
	fn reset(&mut self) {
		self.core = Core::new(32);
	}
}

impl FixedOutputReset for Snefru256 {
	fn finalize_into_reset(&mut self, out: &mut Output<Self>) {
		self.core.finish(out);
		self.core = Core::new(32);
	}
}

#[cfg(test)]
mod tests {
	use super::{Snefru128, Snefru256};
	use digest::Digest;

	fn hex(bytes: impl AsRef<[u8]>) -> String {
		bytes.as_ref().iter().map(|b| format!("{b:02x}")).collect()
	}

	#[test]
	fn snefru128_empty() {
		assert_eq!(
			hex(Snefru128::digest(b"")),
			"8617f366566a011837f4fb4ba5bedea2"
		);
	}

	#[test]
	fn snefru128_abc() {
		assert_eq!(
			hex(Snefru128::digest(b"abc")),
			"553d0648928299a0f22a275a02c83b10"
		);
	}

	#[test]
	fn snefru256_empty() {
		assert_eq!(
			hex(Snefru256::digest(b"")),
			"8617f366566a011837f4fb4ba5bedea2b892f3ed8b894023d16ae344b2be5881"
		);
	}

	#[test]
	fn snefru256_abc() {
		assert_eq!(
			hex(Snefru256::digest(b"abc")),
			"7d033205647a2af3dc8339f6cb25643c33ebc622d32979c4b612b02c4903031b"
		);
	}

	#[test]
	fn snefru128_chunked_matches_oneshot() {
		let data: Vec<u8> = (0..200).map(|i| i as u8).collect();
		let oneshot = hex(Snefru128::digest(&data));
		let mut h = Snefru128::new();
		for chunk in data.chunks(7) {
			h.update(chunk);
		}
		assert_eq!(hex(h.finalize()), oneshot);
	}
}
