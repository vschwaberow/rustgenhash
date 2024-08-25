// SPDX-License-Identifier: MIT OR Apache-2.0
// Project: rustgenhash
// File: benchmark.rs
// Author: Volker Schwaberow <volker@schwaberow.de>
// Copyright (c) 2022 Volker Schwaberow

use crate::rgh::app::Algorithm;
use crate::rgh::hash::{PHash, RHash};
use std::time::{Duration, Instant};

pub fn run_benchmarks(algorithms: &[Algorithm], iterations: u32) {
	println!("Running benchmarks...");
	println!("Iterations per algorithm: {}", iterations);
	println!("----------------------------");

	for alg in algorithms {
		let duration = match alg {
			Algorithm::Md5 => benchmark_rhash("MD5", iterations),
			Algorithm::Sha256 => {
				benchmark_rhash("SHA256", iterations)
			}
			Algorithm::Sha512 => {
				benchmark_rhash("SHA512", iterations)
			}
			Algorithm::Ascon => benchmark_rhash("ASCON", iterations),
			Algorithm::Blake2s => {
				benchmark_rhash("BLAKE2S", iterations)
			}
			Algorithm::Blake2b => {
				benchmark_rhash("BLAKE2B", iterations)
			}
			Algorithm::Blake3 => {
				benchmark_rhash("BLAKE3", iterations)
			}
			Algorithm::Fsb160 => {
				benchmark_rhash("FSB160", iterations)
			}
			Algorithm::Fsb224 => {
				benchmark_rhash("FSB224", iterations)
			}
			Algorithm::Fsb256 => {
				benchmark_rhash("FSB256", iterations)
			}
			Algorithm::Fsb384 => {
				benchmark_rhash("FSB384", iterations)
			}
			Algorithm::Fsb512 => {
				benchmark_rhash("FSB512", iterations)
			}
			Algorithm::Gost94 => {
				benchmark_rhash("GOST94", iterations)
			}
			Algorithm::Gost94ua => {
				benchmark_rhash("GOST94UA", iterations)
			}
			Algorithm::Argon2 => {
				benchmark_phash(PHash::hash_argon2, iterations)
			}
			Algorithm::Groestl => {
				benchmark_rhash("GROESTL", iterations)
			}
			Algorithm::Jh224 => benchmark_rhash("JH224", iterations),
			Algorithm::Jh256 => benchmark_rhash("JH256", iterations),
			Algorithm::Jh384 => benchmark_rhash("JH384", iterations),
			Algorithm::Jh512 => benchmark_rhash("JH512", iterations),
			Algorithm::Md2 => benchmark_rhash("MD2", iterations),
			Algorithm::Md4 => benchmark_rhash("MD4", iterations),
			Algorithm::Ripemd160 => {
				benchmark_rhash("RIPEMD160", iterations)
			}
			Algorithm::Sha1 => benchmark_rhash("SHA1", iterations),
			Algorithm::Sha3_224 => {
				benchmark_rhash("SHA3_224", iterations)
			}
			Algorithm::Sha3_256 => {
				benchmark_rhash("SHA3_256", iterations)
			}
			Algorithm::Sha3_384 => {
				benchmark_rhash("SHA3_384", iterations)
			}
			Algorithm::Sha3_512 => {
				benchmark_rhash("SHA3_512", iterations)
			}
			Algorithm::Shabal192 => {
				benchmark_rhash("SHABAL192", iterations)
			}
			Algorithm::Shabal224 => {
				benchmark_rhash("SHABAL224", iterations)
			}
			Algorithm::Shabal256 => {
				benchmark_rhash("SHABAL256", iterations)
			}
			Algorithm::Shabal384 => {
				benchmark_rhash("SHABAL384", iterations)
			}
			Algorithm::Shabal512 => {
				benchmark_rhash("SHABAL512", iterations)
			}
			Algorithm::Skein256 => {
				benchmark_rhash("SKEIN256", iterations)
			}
			Algorithm::Skein512 => {
				benchmark_rhash("SKEIN512", iterations)
			}
			Algorithm::Skein1024 => {
				benchmark_rhash("SKEIN1024", iterations)
			}
			Algorithm::Sm3 => benchmark_rhash("SM3", iterations),
			Algorithm::Streebog256 => {
				benchmark_rhash("STREEBOG256", iterations)
			}
			Algorithm::Streebog512 => {
				benchmark_rhash("STREEBOG512", iterations)
			}
			Algorithm::Tiger => benchmark_rhash("TIGER", iterations),
			Algorithm::Whirlpool => {
				benchmark_rhash("WHIRLPOOL", iterations)
			}
			Algorithm::Balloon => {
				benchmark_phash(PHash::hash_balloon, iterations)
			}
			Algorithm::Bcrypt => {
				benchmark_phash(PHash::hash_bcrypt, iterations)
			}
			Algorithm::Shacrypt => {
				benchmark_phash(PHash::hash_sha_crypt, iterations)
			}
			Algorithm::Scrypt => {
				benchmark_phash(PHash::hash_scrypt, iterations)
			}
			_ => {
				println!("Benchmark not implemented for {:?}", alg);
				continue;
			}
		};

		println!(
			"{:?}: avg time per operation: {:.6} ms",
			alg,
			duration.as_secs_f64() * 1000.0 / iterations as f64
		);
	}
}

fn benchmark_rhash(alg: &str, iterations: u32) -> Duration {
	let start = Instant::now();
	for _ in 0..iterations {
		let mut hasher = RHash::new(alg);
		hasher.process_string(b"Hello, world!");
	}
	start.elapsed()
}

fn benchmark_phash<F>(hash_fn: F, iterations: u32) -> Duration
where
	F: Fn(&str),
{
	let start = Instant::now();
	for _ in 0..iterations {
		hash_fn("password123");
	}
	start.elapsed()
}
