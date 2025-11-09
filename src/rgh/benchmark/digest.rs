// SPDX-License-Identifier: MIT OR Apache-2.0
// Project: rustgenhash
// File: benchmark/digest.rs
// Author: Volker Schwaberow <volker@schwaberow.de>
// (C) 2022

use super::{
	BenchmarkError, BenchmarkMode, BenchmarkResult,
	BenchmarkScenario, BenchmarkSummary,
};
use crate::rgh::app::Algorithm;
use crate::rgh::hash::{
	asm_accelerated_digests, Argon2Config, BalloonConfig,
	BcryptConfig, PHash, Pbkdf2Config, RHash, ScryptConfig,
};
use std::time::{Duration, Instant};
use strum::IntoEnumIterator;

pub fn run_digest_benchmarks(
	algorithms: &[Algorithm],
	iterations: u32,
) -> Result<BenchmarkSummary, BenchmarkError> {
	if algorithms.is_empty() {
		return Err(BenchmarkError::validation(
			"provide at least one algorithm to benchmark",
		));
	}
	let scenario = BenchmarkScenario::new(
		BenchmarkMode::Digest,
		algorithms.iter().map(|alg| format!("{:?}", alg)).collect(),
		super::DEFAULT_DURATION_SECONDS,
		Some(iterations as u64),
		None,
		false,
	)?;

	let argon2_config = Argon2Config::default();
	let scrypt_config = ScryptConfig::default();
	let bcrypt_config = BcryptConfig::default();
	let pbkdf2_config = Pbkdf2Config::default();
	let balloon_config = BalloonConfig::default();

	let mut cases = Vec::with_capacity(algorithms.len());

	for alg in algorithms {
		let Some(total_duration) = benchmark_algorithm(
			*alg,
			iterations,
			&argon2_config,
			&scrypt_config,
			&bcrypt_config,
			&pbkdf2_config,
			&balloon_config,
		) else {
			eprintln!("Benchmark not implemented for {:?}", alg);
			continue;
		};
		let seconds = total_duration.as_secs_f64().max(f64::EPSILON);
		let per_op_ms = (seconds * 1000.0) / iterations as f64;
		let ops_per_sec = iterations as f64 / seconds;
		cases.push(BenchmarkResult {
			algorithm: format!("{:?}", alg),
			profile: None,
			samples_collected: iterations as u64,
			avg_ops_per_sec: ops_per_sec,
			median_latency_ms: per_op_ms,
			p95_latency_ms: per_op_ms,
			compliance: true,
			warnings: Vec::new(),
			notes: None,
		});
	}

	BenchmarkSummary::new(scenario, cases)
}

pub fn render_digest_report(summary: &BenchmarkSummary) {
	println!("Running benchmarks...");
	if let Some(iterations) = summary.scenario.iterations {
		println!("Iterations per algorithm: {}", iterations);
	}
	println!("----------------------------");
	println!("asm_enabled: {}", asm_acceleration_active());
	for case in &summary.cases {
		println!(
			"{}: avg time per operation: {:.6} ms",
			case.algorithm, case.median_latency_ms
		);
	}
}

fn benchmark_algorithm(
	alg: Algorithm,
	iterations: u32,
	argon2_config: &Argon2Config,
	scrypt_config: &ScryptConfig,
	bcrypt_config: &BcryptConfig,
	pbkdf2_config: &Pbkdf2Config,
	balloon_config: &BalloonConfig,
) -> Option<Duration> {
	let duration = match alg {
		Algorithm::Md5 => benchmark_rhash("MD5", iterations),
		Algorithm::Sha256 => benchmark_rhash("SHA256", iterations),
		Algorithm::Sha512 => benchmark_rhash("SHA512", iterations),
		Algorithm::Ascon => benchmark_rhash("ASCON", iterations),
		Algorithm::Blake2s => benchmark_rhash("BLAKE2S", iterations),
		Algorithm::Blake2b => benchmark_rhash("BLAKE2B", iterations),
		Algorithm::Blake3 => benchmark_rhash("BLAKE3", iterations),
		Algorithm::Fsb160 => benchmark_rhash("FSB160", iterations),
		Algorithm::Fsb224 => benchmark_rhash("FSB224", iterations),
		Algorithm::Fsb256 => benchmark_rhash("FSB256", iterations),
		Algorithm::Fsb384 => benchmark_rhash("FSB384", iterations),
		Algorithm::Fsb512 => benchmark_rhash("FSB512", iterations),
		Algorithm::Gost94 => benchmark_rhash("GOST94", iterations),
		Algorithm::Gost94ua => {
			benchmark_rhash("GOST94UA", iterations)
		}
		Algorithm::Argon2 => benchmark_phash(
			|password| {
				PHash::hash_argon2(password, argon2_config, false)
			},
			iterations,
		),
		Algorithm::Groestl => benchmark_rhash("GROESTL", iterations),
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
		Algorithm::Balloon => benchmark_phash(
			|password| {
				PHash::hash_balloon(password, balloon_config, false)
			},
			iterations,
		),
		Algorithm::Bcrypt => benchmark_phash(
			|password| {
				PHash::hash_bcrypt(password, bcrypt_config, false)
			},
			iterations,
		),
		Algorithm::Shacrypt => benchmark_phash(
			|password| PHash::hash_sha_crypt(password, false),
			iterations,
		),
		Algorithm::Scrypt => benchmark_phash(
			|password| {
				PHash::hash_scrypt(password, scrypt_config, false)
			},
			iterations,
		),
		Algorithm::Pbkdf2Sha256 => benchmark_phash(
			|password| {
				PHash::hash_pbkdf2(
					password,
					"pbkdf2sha256",
					pbkdf2_config,
					false,
				)
			},
			iterations,
		),
		Algorithm::Pbkdf2Sha512 => benchmark_phash(
			|password| {
				PHash::hash_pbkdf2(
					password,
					"pbkdf2sha512",
					pbkdf2_config,
					false,
				)
			},
			iterations,
		),
		Algorithm::Belthash => {
			benchmark_rhash("BELTHASH", iterations)
		}
		_ => return None,
	};
	Some(duration)
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

fn asm_acceleration_active() -> bool {
	!asm_accelerated_digests().is_empty()
}

fn is_kdf_algorithm(alg: Algorithm) -> bool {
	matches!(
		alg,
		Algorithm::Argon2
			| Algorithm::Scrypt
			| Algorithm::Pbkdf2Sha256
			| Algorithm::Pbkdf2Sha512
			| Algorithm::Bcrypt
			| Algorithm::Balloon
			| Algorithm::Shacrypt
	)
}

pub fn digest_benchmark_presets() -> Vec<Algorithm> {
	Algorithm::iter()
		.filter(|alg| !is_kdf_algorithm(*alg))
		.collect()
}

pub fn kdf_benchmark_presets() -> Vec<Algorithm> {
	Algorithm::iter()
		.filter(|alg| is_kdf_algorithm(*alg))
		.collect()
}

pub fn algorithm_catalog() -> Vec<String> {
	Algorithm::iter().map(|alg| format!("{:?}", alg)).collect()
}
