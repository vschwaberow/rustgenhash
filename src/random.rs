/*
Copyright 2022 Volker Schwaberow <volker@schwaberow.de>
Permission is hereby granted, free of charge, to any person obtaining a
copy of this software and associated documentation files (the
"Software"), to deal in the Software without restriction, including without
limitation the rights to use, copy, modify, merge, publish, distribute,
sublicense, and/or sell copies of the Software, and to permit persons to whom the
Software is furnished to do so, subject to the following conditions:
The above copyright notice and this permission notice shall be
included in all copies or substantial portions of the Software.
THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS
OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT
SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR
OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE,
ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER
DEALINGS IN THE SOFTWARE.
Author(s): Volker Schwaberow
*/

use crate::app::OutputOptions;
use base64::{encode_config, URL_SAFE_NO_PAD};
use getrandom::getrandom;
use rand::thread_rng;
use rand_core::{RngCore, SeedableRng};
use std::error::Error;

pub trait Rng {
	fn generate(
		&mut self,
		buffer: &mut [u8],
	) -> Result<(), Box<dyn Error>>;
}
#[derive(clap::ValueEnum, Debug, Clone)]
pub enum RngType {
	GetRandom,
	ThreadRng,
	OsRng,
	ChaChaRng,
	Hc128Rng,
	IsaacRng,
	JitterRng,
	Pcg32,
	XorShiftRng,
	Uuidv4
}

pub struct RandomNumberGenerator {
	rng: RngType,
}

impl RandomNumberGenerator {
	pub fn new(rng: RngType) -> Self {
		Self { rng }
	}

	pub fn generate(
		&mut self,
		output_length: u64,
		output_format: OutputOptions,
	) -> String {
		let mut buffer = vec![0; output_length as usize];

		match &mut self.rng {
			RngType::GetRandom => {
				getrandom(&mut buffer).unwrap();
			}
			RngType::ThreadRng => {
				thread_rng().fill_bytes(&mut buffer);
			}
			RngType::OsRng => {
				let mut rng = rand::rngs::OsRng;
				rng.fill_bytes(&mut buffer);
			}
			RngType::ChaChaRng => {
				let mut rng = rand_chacha::ChaChaRng::from_entropy();
				rng.fill_bytes(&mut buffer);
			}
			RngType::Hc128Rng => {
				let mut rng = rand_hc::Hc128Rng::from_entropy();
				rng.fill_bytes(&mut buffer);
			}
			RngType::IsaacRng => {
				let mut rng = rand_isaac::IsaacRng::from_entropy();
				rng.fill_bytes(&mut buffer);
			}
			RngType::JitterRng => {
				use rand_jitter::rand_core::RngCore;
				use std::time::{SystemTime, UNIX_EPOCH};
				let mut rng =
					rand_jitter::JitterRng::new_with_timer(|| {
						let dur = SystemTime::now()
							.duration_since(UNIX_EPOCH)
							.unwrap();
						dur.as_secs() << 30
							| dur.subsec_nanos() as u64
					});
				rng.fill_bytes(&mut buffer);
			}
			RngType::Pcg32 => {
				let mut rng = rand_pcg::Pcg32::from_entropy();
				rng.fill_bytes(&mut buffer);
			}
			RngType::XorShiftRng => {
				let mut rng =
					rand_xorshift::XorShiftRng::from_entropy();
				rng.fill_bytes(&mut buffer);
			}
			RngType::Uuidv4 => {
				let uuid = uuid::Uuid::new_v4();
				print!("{}", uuid.hyphenated().to_string());
				std::process::exit(0);
			}
		}
		let buffer_clone = buffer.clone();
		match output_format {
			OutputOptions::Hex => hex::encode(buffer),
			OutputOptions::Base64 => {
				encode_config(&buffer_clone, URL_SAFE_NO_PAD)
			}
			OutputOptions::HexBase64 => {
				let mut hex = hex::encode(&buffer_clone);
				hex.push_str(" ");
				hex.push_str(&encode_config(
					&buffer_clone,
					URL_SAFE_NO_PAD,
				));
				hex
			}
		}
	}
}
