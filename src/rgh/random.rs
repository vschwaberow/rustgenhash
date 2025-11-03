// SPDX-License-Identifier: MIT OR Apache-2.0
// Project: rustgenhash
// File: random.rs
// Author: Volker Schwaberow <volker@schwaberow.de>
// Copyright (c) 2022 Volker Schwaberow

use crate::rgh::output::DigestOutputFormat;
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
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
#[derive(clap::ValueEnum, Debug, Copy, Clone)]
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
	Uuidv4,
}

impl std::fmt::Display for RngType {
	fn fmt(
		&self,
		f: &mut std::fmt::Formatter<'_>,
	) -> std::fmt::Result {
		write!(f, "{:?}", self)
	}
}

impl RngType {
	pub fn iter() -> impl Iterator<Item = RngType> {
		vec![
			RngType::GetRandom,
			RngType::ThreadRng,
			RngType::OsRng,
			RngType::ChaChaRng,
			RngType::Hc128Rng,
			RngType::IsaacRng,
			RngType::JitterRng,
			RngType::Pcg32,
			RngType::XorShiftRng,
			RngType::Uuidv4,
		]
		.into_iter()
	}
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
		output_format: DigestOutputFormat,
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
				print!("{}", uuid.hyphenated());
				std::process::exit(0);
			}
		}
		match output_format {
			DigestOutputFormat::Hex => hex::encode(buffer),
			DigestOutputFormat::Base64 => {
				URL_SAFE_NO_PAD.encode(&buffer)
			}
			_ => unreachable!(
				"Unsupported format for random generator"
			),
		}
	}
}
