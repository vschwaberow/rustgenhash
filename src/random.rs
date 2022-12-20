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

use std::error::Error;

extern crate getrandom;
extern crate rand;
extern crate rand_chacha;
extern crate rand_core;
extern crate rand_hc;
extern crate rand_isaac;
extern crate rand_jitter;
extern crate rand_pcg;
extern crate rand_xorshift;

trait Rng {
	fn generate(
		&mut self,
		buffer: &mut [u8],
	) -> Result<(), Box<dyn Error>>;
}

enum RngType {
	GetRandom,
	ThreadRng,
	OsRng,
	ChaChaRng(rand_chacha::ChaChaRng),
	CoreOsRng,
	Hc128Rng(rand_hc::Hc128Rng),
	IsaacRng(rand_isaac::IsaacRng),
	JitterRng(rand_jitter::JitterRng),
	Pcg32(rand_pcg::Pcg32),
	XorShiftRng(rand_xorshift::XorShiftRng),
}

struct RandomNumberGenerator {
	rng: RngType,
}

impl RandomNumberGenerator {
	fn new(rng: RngType) -> Self {
		Self { rng }
	}

	fn generate(
		&mut self,
		buffer: &mut [u8],
        output_length: usize,
        output_format: OutputFormat,
	) -> Result<(), Box<dyn Error>> {
		match &mut self.rng {
			RngType::GetRandom => {
				getrandom(buffer).map_err(|e| e.into())
			}
			RngType::ThreadRng => {
				rand::thread_rng().fill(buffer);
				Ok(())
			}
			RngType::OsRng => {
				rand::OsRng.fill(buffer);
				Ok(())
			}
			RngType::ChaChaRng(rng) => {
				rng.fill(buffer);
				Ok(())
			}
			RngType::CoreOsRng => {
				rand_core::OsRng.fill(buffer);
				Ok(())
			}
			RngType::Hc128Rng(rng) => {
				rng.fill(buffer);
				Ok(())
			}
			RngType::IsaacRng(rng) => {
				rng.fill(buffer);
				Ok(())
			}
			RngType::JitterRng(rng) => {
				rng.fill(buffer);
				Ok(())
			}
			RngType::Pcg32(rng) => {
				rng.fill(buffer);
				Ok(())
			}
			RngType::XorShiftRng(rng) => {
				rng.fill(buffer);
				Ok(())
			}
		}
	}
}
