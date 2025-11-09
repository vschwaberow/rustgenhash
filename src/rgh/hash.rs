// SPDX-License-Identifier: MIT OR Apache-2.0
// Project: rustgenhash
// File: hash.rs
// Author: Volker Schwaberow <volker@schwaberow.de>
// Copyright (c) 2022 Volker Schwaberow

use crate::rgh::file::{
	DirectoryHashPlan, EntryStatus, ErrorHandlingProfile,
	ManifestEntry, ManifestOutcome, ManifestSummary, ManifestWriter,
	ProgressConfig, ProgressEmitter, Walker,
};
use crate::rgh::multihash::MultihashEncoder;
use crate::rgh::output::{
	serialize_records, DigestOutputFormat, DigestRecord,
	DigestSource, OutputError, OutputFormatProfile,
	SerializationResult,
};
use crate::rgh::weak;
use argon2::{
	password_hash::{rand_core::OsRng, PasswordHasher, SaltString},
	Argon2,
};
use ascon_hash::AsconHash;
use balloon_hash::{
	password_hash::{
		rand_core::OsRng as BalOsRng, SaltString as BalSaltString,
	},
	Algorithm as BalAlgorithm, Balloon, Params as BalParams,
};
use base64::{engine::general_purpose::STANDARD_NO_PAD, Engine};
use blake2::Digest;
use chrono::{DateTime, Utc};
use digest::DynDigest;
use pbkdf2::{
	password_hash::{Ident as PbIdent, SaltString as PbSaltString},
	Pbkdf2,
};
use scrypt::{
	password_hash::SaltString as ScSaltString, Params as ScParams,
	Scrypt,
};
use serde_json::to_writer_pretty;
use skein::{consts::U32, Skein1024, Skein256, Skein512};
use std::fs::{self, File};
use std::io::IsTerminal;
use std::path::{Path, PathBuf};
use std::{collections::HashMap, io};

#[cfg(all(
	feature = "asm-accel",
	not(feature = "portable-only"),
	any(target_arch = "x86", target_arch = "x86_64")
))]
const ASM_ACCEL_DIGESTS: &[&str] = &[
	"MD5",
	"SHA1",
	"SHA224",
	"SHA256",
	"SHA384",
	"SHA512",
	"WHIRLPOOL",
];

#[cfg(all(
	feature = "asm-accel",
	not(feature = "portable-only"),
	target_arch = "aarch64"
))]
const ASM_ACCEL_DIGESTS: &[&str] =
	&["SHA1", "SHA224", "SHA256", "SHA384", "SHA512"];

#[cfg(any(
	not(feature = "asm-accel"),
	feature = "portable-only",
	all(
		feature = "asm-accel",
		not(any(
			target_arch = "x86",
			target_arch = "x86_64",
			target_arch = "aarch64"
		))
	)
))]
const ASM_ACCEL_DIGESTS: &[&str] = &[];

pub fn asm_accelerated_digests() -> &'static [&'static str] {
	ASM_ACCEL_DIGESTS
}

pub fn algorithm_uses_asm(algorithm: &str) -> bool {
	let needle = algorithm.to_uppercase();
	ASM_ACCEL_DIGESTS
		.iter()
		.any(|candidate| candidate.eq_ignore_ascii_case(&needle))
}

#[derive(Clone, Debug)]
pub struct WeakAlgorithmWarning {
	pub severity_icon: &'static str,
	pub headline: String,
	pub body: String,
	pub references: &'static [&'static str],
}

impl From<weak::WarningMessage> for WeakAlgorithmWarning {
	fn from(value: weak::WarningMessage) -> Self {
		Self {
			severity_icon: value.severity_icon,
			headline: value.headline,
			body: value.body,
			references: value.references,
		}
	}
}

pub fn weak_algorithm_warning(
	algorithm: &str,
) -> Option<WeakAlgorithmWarning> {
	weak::warning_for(algorithm).map(WeakAlgorithmWarning::from)
}

pub(crate) fn assemble_output(
	hash_only: bool,
	mut tokens: Vec<String>,
	original: Option<&str>,
) -> String {
	if !hash_only {
		if let Some(value) = original {
			tokens.push(value.to_string());
		}
	}
	tokens.join(" ")
}

#[derive(Clone, Debug)]
pub struct FileDigestOptions {
	pub algorithm: String,
	pub plan: DirectoryHashPlan,
	pub format: DigestOutputFormat,
	pub hash_only: bool,
	pub progress: ProgressConfig,
	pub manifest_path: Option<PathBuf>,
	pub error_profile: ErrorHandlingProfile,
}

impl FileDigestOptions {
	fn algorithm_uppercase(&self) -> String {
		self.algorithm.to_uppercase()
	}
}

pub struct FileDigestResult {
	pub summary: ManifestSummary,
	pub lines: Vec<String>,
	pub warnings: Vec<String>,
	pub exit_code: i32,
	pub should_write_manifest: bool,
	pub fatal_error: Option<String>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum CompareMode {
	Manifest,
	Text,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum CompareDiffKind {
	Changed,
	MissingLeft,
	MissingRight,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CompareDifference {
	pub identifier: String,
	pub kind: CompareDiffKind,
	pub expected: Option<String>,
	pub actual: Option<String>,
}

#[derive(Clone, Debug)]
pub struct CompareSummary {
	pub mode: CompareMode,
	pub differences: Vec<CompareDifference>,
	pub exit_code: i32,
	pub incomplete: bool,
	pub left_failures: u64,
	pub right_failures: u64,
	pub left_entries: usize,
	pub right_entries: usize,
}

#[derive(Clone, Debug)]
pub struct Argon2Config {
	pub mem_cost: u32,
	pub time_cost: u32,
	pub parallelism: u32,
}
impl Default for Argon2Config {
	fn default() -> Self {
		Self {
			mem_cost: 65536,
			time_cost: 3,
			parallelism: 4,
		}
	}
}

#[derive(Clone, Debug)]
pub struct ScryptConfig {
	pub log_n: u8,
	pub r: u32,
	pub p: u32,
}
impl Default for ScryptConfig {
	fn default() -> Self {
		Self {
			log_n: 15,
			r: 8,
			p: 1,
		}
	}
}

#[derive(Clone, Debug)]
pub struct BcryptConfig {
	pub cost: u32,
}
impl Default for BcryptConfig {
	fn default() -> Self {
		Self { cost: 12 }
	}
}

#[derive(Clone, Debug)]
pub struct Pbkdf2Config {
	pub rounds: u32,
	pub output_length: usize,
}
impl Default for Pbkdf2Config {
	fn default() -> Self {
		Self {
			rounds: 100_000,
			output_length: 32,
		}
	}
}

#[derive(Clone, Debug)]
pub struct BalloonConfig {
	pub time_cost: u32,
	pub memory_cost: u32,
	pub parallelism: u32,
}
impl Default for BalloonConfig {
	fn default() -> Self {
		Self {
			time_cost: 3,
			memory_cost: 65536,
			parallelism: 4,
		}
	}
}

macro_rules! impl_password_hash_fn {
	($name:ident, $impl_fn:ident, $cfg:ty, $salt:expr) => {
		pub fn $name(password: &str, config: &$cfg, hash_only: bool) {
			let salt = $salt;
			let hash = match Self::$impl_fn(password, config, &salt) {
				Ok(h) => h,
				Err(e) => {
					println!("Error hashing password: {}", e);
					return;
				}
			};
			let output = assemble_output(
				hash_only,
				vec![hash],
				Some(password),
			);
			println!("{}", output);
		}
	};
}

macro_rules! impl_hash_function {
	($name:ident, $hasher:expr) => {
		pub fn $name(password: &str, hash_only: bool) {
			let result = $hasher(password.as_bytes());
			let output = assemble_output(
				hash_only,
				vec![hex::encode(result)],
				Some(password),
			);
			println!("{}", output);
		}
	};
}

pub struct PHash {}
impl PHash {
	pub fn derive_argon2_output(
		password: &str,
		cfg: &Argon2Config,
		hash_only: bool,
	) -> Result<String, String> {
		let salt = SaltString::generate(&mut OsRng);
		Self::hash_argon2_impl(password, cfg, &salt)
			.map(|hash| {
				assemble_output(hash_only, vec![hash], Some(password))
			})
			.map_err(|err| err.to_string())
	}

	impl_hash_function!(hash_ascon, AsconHash::digest);

	impl_password_hash_fn!(
		hash_argon2,
		hash_argon2_impl,
		Argon2Config,
		SaltString::generate(&mut OsRng)
	);
	pub(crate) fn hash_argon2_impl(
		password: &str,
		cfg: &Argon2Config,
		salt: &SaltString,
	) -> Result<String, argon2::password_hash::Error> {
		let argon2 = Argon2::new(
			argon2::Algorithm::Argon2id,
			argon2::Version::V0x13,
			argon2::Params::new(
				cfg.mem_cost,
				cfg.time_cost,
				cfg.parallelism,
				None,
			)
			.unwrap(),
		);
		Ok(argon2
			.hash_password(password.as_bytes(), salt)?
			.to_string())
	}

	impl_password_hash_fn!(
		hash_balloon,
		hash_balloon_impl,
		BalloonConfig,
		BalSaltString::generate(&mut BalOsRng)
	);
	pub fn derive_balloon_output(
		password: &str,
		cfg: &BalloonConfig,
		hash_only: bool,
	) -> Result<String, String> {
		let salt = BalSaltString::generate(&mut BalOsRng);
		Self::hash_balloon_impl(password, cfg, &salt)
			.map(|hash| {
				assemble_output(hash_only, vec![hash], Some(password))
			})
			.map_err(|err| err.to_string())
	}
	pub(crate) fn hash_balloon_impl(
		password: &str,
		cfg: &BalloonConfig,
		salt: &BalSaltString,
	) -> Result<String, balloon_hash::password_hash::Error> {
		let balloon = Balloon::<sha2::Sha256>::new(
			BalAlgorithm::Balloon,
			BalParams::new(
				cfg.time_cost,
				cfg.memory_cost,
				cfg.parallelism,
			)
			.unwrap(),
			None,
		);
		Ok(balloon
			.hash_password(password.as_bytes(), salt)?
			.to_string())
	}

	impl_password_hash_fn!(
		hash_scrypt,
		hash_scrypt_impl,
		ScryptConfig,
		ScSaltString::generate(&mut OsRng)
	);
	pub fn derive_scrypt_output(
		password: &str,
		cfg: &ScryptConfig,
		hash_only: bool,
	) -> Result<String, String> {
		let salt = ScSaltString::generate(&mut OsRng);
		Self::hash_scrypt_impl(password, cfg, &salt)
			.map(|hash| {
				assemble_output(hash_only, vec![hash], Some(password))
			})
			.map_err(|err| err.to_string())
	}
	pub(crate) fn hash_scrypt_impl(
		password: &str,
		cfg: &ScryptConfig,
		salt: &ScSaltString,
	) -> Result<String, scrypt::password_hash::Error> {
		let params = ScParams::new(cfg.log_n, cfg.r, cfg.p).unwrap();
		Ok(Scrypt
			.hash_password_customized(
				password.as_bytes(),
				None,
				None,
				params,
				salt.as_salt(),
			)?
			.to_string())
	}

	pub fn hash_bcrypt(
		password: &str,
		cfg: &BcryptConfig,
		hash_only: bool,
	) {
		match Self::derive_bcrypt_output(password, cfg, hash_only) {
			Ok(output) => {
				println!("{}", output);
			}
			Err(err) => {
				eprintln!("Error: {}", err);
				std::process::exit(1);
			}
		}
	}

	pub fn derive_bcrypt_output(
		password: &str,
		cfg: &BcryptConfig,
		hash_only: bool,
	) -> Result<String, String> {
		let salt = SaltString::generate(&mut OsRng);
		Self::hash_bcrypt_hex(password, cfg, &salt)
			.map(|hex| {
				assemble_output(hash_only, vec![hex], Some(password))
			})
			.map_err(|err| err.to_string())
	}

	pub fn hash_sha_crypt(password: &str, hash_only: bool) {
		match Self::derive_sha_crypt_output(password, hash_only) {
			Ok(output) => println!("{}", output),
			Err(err) => {
				eprintln!("Error: {}", err);
				std::process::exit(1);
			}
		}
	}

	pub fn derive_sha_crypt_output(
		password: &str,
		hash_only: bool,
	) -> Result<String, String> {
		let params = sha_crypt::Sha512Params::new(10_000)
			.map_err(|err| format!("{:?}", err))?;
		let hash = sha_crypt::sha512_simple(password, &params)
			.map_err(|err| format!("{:?}", err))?;
		Ok(assemble_output(hash_only, vec![hash], Some(password)))
	}

	pub fn hash_pbkdf2(
		password: &str,
		pb_scheme: &str,
		cfg: &Pbkdf2Config,
		hash_only: bool,
	) {
		match Self::derive_pbkdf2_output(
			password, pb_scheme, cfg, hash_only,
		) {
			Ok(output) => println!("{}", output),
			Err(err) => {
				eprintln!("Error: {}", err);
				std::process::exit(1);
			}
		}
	}

	pub fn derive_pbkdf2_output(
		password: &str,
		pb_scheme: &str,
		cfg: &Pbkdf2Config,
		hash_only: bool,
	) -> Result<String, String> {
		let schemes = HashMap::from([
			("pbkdf2sha256", "pbkdf2-sha256"),
			("pbkdf2sha512", "pbkdf2-sha512"),
		]);
		let alg =
			PbIdent::new(schemes.get(pb_scheme).unwrap_or(&"NONE"))
				.map_err(|err| err.to_string())?;
		let salt = PbSaltString::generate(&mut OsRng);
		let params = pbkdf2::Params {
			output_length: cfg.output_length,
			rounds: cfg.rounds,
		};
		let hash = Pbkdf2::hash_password_customized(
			&Pbkdf2,
			password.as_bytes(),
			Some(alg),
			None,
			params,
			salt.as_salt(),
		)
		.map_err(|err| err.to_string())?;
		Ok(assemble_output(
			hash_only,
			vec![hash.to_string()],
			Some(password),
		))
	}

	pub(crate) fn hash_pbkdf2_with_salt(
		password: &str,
		pb_scheme: &str,
		cfg: &Pbkdf2Config,
		salt_b64: &str,
	) -> Result<String, String> {
		let schemes = HashMap::from([
			("pbkdf2sha256", "pbkdf2-sha256"),
			("pbkdf2sha512", "pbkdf2-sha512"),
		]);
		let alg =
			PbIdent::new(schemes.get(pb_scheme).unwrap_or(&"NONE"))
				.map_err(|err| err.to_string())?;
		let salt_bytes = STANDARD_NO_PAD
			.decode(salt_b64)
			.map_err(|err| err.to_string())?;
		let salt = PbSaltString::b64_encode(&salt_bytes)
			.map_err(|err| err.to_string())?;
		let params = pbkdf2::Params {
			output_length: cfg.output_length,
			rounds: cfg.rounds,
		};
		let hash = Pbkdf2::hash_password_customized(
			&Pbkdf2,
			password.as_bytes(),
			Some(alg),
			None,
			params,
			salt.as_salt(),
		)
		.map_err(|err| err.to_string())?;
		Ok(hash.to_string())
	}

	pub(crate) fn hash_bcrypt_hex(
		password: &str,
		cfg: &BcryptConfig,
		salt: &SaltString,
	) -> Result<String, bcrypt_pbkdf::Error> {
		let mut out = [0; 64];
		bcrypt_pbkdf::bcrypt_pbkdf(
			password.as_bytes(),
			salt.as_bytes(),
			cfg.cost,
			&mut out,
		)?;
		Ok(hex::encode(out))
	}

	pub(crate) fn hash_bcrypt_with_salt(
		password: &str,
		cfg: &BcryptConfig,
		salt_b64: &str,
	) -> Result<String, String> {
		let salt_bytes = STANDARD_NO_PAD
			.decode(salt_b64)
			.map_err(|err| err.to_string())?;
		let salt = SaltString::b64_encode(&salt_bytes)
			.map_err(|err| err.to_string())?;
		Self::hash_bcrypt_hex(password, cfg, &salt)
			.map_err(|err| err.to_string())
	}

	pub(crate) fn hash_argon2_with_salt(
		password: &str,
		cfg: &Argon2Config,
		salt_b64: &str,
	) -> Result<String, String> {
		let salt_bytes = STANDARD_NO_PAD
			.decode(salt_b64)
			.map_err(|err| err.to_string())?;
		let salt = SaltString::b64_encode(&salt_bytes)
			.map_err(|err| err.to_string())?;
		Self::hash_argon2_impl(password, cfg, &salt)
			.map_err(|err| err.to_string())
	}

	pub(crate) fn hash_balloon_with_salt(
		password: &str,
		cfg: &BalloonConfig,
		salt_b64: &str,
	) -> Result<String, String> {
		let salt_bytes = STANDARD_NO_PAD
			.decode(salt_b64)
			.map_err(|err| err.to_string())?;
		let salt = BalSaltString::b64_encode(&salt_bytes)
			.map_err(|err| err.to_string())?;
		Self::hash_balloon_impl(password, cfg, &salt)
			.map_err(|err| err.to_string())
	}

	pub(crate) fn hash_scrypt_with_salt(
		password: &str,
		cfg: &ScryptConfig,
		salt_b64: &str,
	) -> Result<String, String> {
		let salt_bytes = STANDARD_NO_PAD
			.decode(salt_b64)
			.map_err(|err| err.to_string())?;
		let salt = ScSaltString::b64_encode(&salt_bytes)
			.map_err(|err| err.to_string())?;
		Self::hash_scrypt_impl(password, cfg, &salt)
			.map_err(|err| err.to_string())
	}
}

macro_rules! create_hasher {
    ($alg:expr, $($pat:expr => $hasher:expr),+ $(,)?) => {
        match $alg {
            $($pat => Box::new($hasher),)+
            _ => panic!("Unknown algorithm"),
        }
    };
}

#[derive(Clone)]
pub struct RHash {
	digest: Box<dyn DynDigest>,
}
impl RHash {
	pub fn new(alg: &str) -> Self {
		Self {
			digest: create_hasher!(alg,
				"BELTHASH" => belt_hash::BeltHash::new(),
			"BLAKE2B"   => blake2::Blake2b512::new(),
				"BLAKE2S"   => blake2::Blake2s256::new(),
				"BLAKE3"    => blake3::Hasher::new(),
				"FSB160"    => fsb::Fsb160::new(),
				"FSB224"    => fsb::Fsb224::new(),
				"FSB256"    => fsb::Fsb256::new(),
				"FSB384"    => fsb::Fsb384::new(),
				"FSB512"    => fsb::Fsb512::new(),
				"GOST94"    => gost94::Gost94Test::new(),
				"GOST94UA"  => gost94::Gost94UA::new(),
				"GROESTL"   => groestl::Groestl256::new(),
				"JH224"     => jh::Jh224::new(),
				"JH256"     => jh::Jh256::new(),
				"JH384"     => jh::Jh384::new(),
				"JH512"     => jh::Jh512::new(),
				"MD2"       => md2::Md2::new(),
				"MD5"       => md5::Md5::new(),
				"MD4"       => md4::Md4::new(),
				"RIPEMD160" => ripemd::Ripemd160::new(),
				"RIPEMD320" => ripemd::Ripemd320::new(),
				"SHA1"      => sha1::Sha1::new(),
				"SHA224"    => sha2::Sha224::new(),
				"SHA256"    => sha2::Sha256::new(),
				"SHA384"    => sha2::Sha384::new(),
				"SHA512"    => sha2::Sha512::new(),
				"SHA3_224"  => sha3::Sha3_224::new(),
				"SHA3_256"  => sha3::Sha3_256::new(),
				"SHA3_384"  => sha3::Sha3_384::new(),
				"SHA3_512"  => sha3::Sha3_512::new(),
				"SHABAL192" => shabal::Shabal192::new(),
				"SHABAL224" => shabal::Shabal224::new(),
				"SHABAL256" => shabal::Shabal256::new(),
				"SHABAL384" => shabal::Shabal384::new(),
				"SHABAL512" => shabal::Shabal512::new(),
				"SKEIN256"  => Skein256::<U32>::new(),
				"SKEIN512"  => Skein512::<U32>::new(),
				"SKEIN1024" => Skein1024::<U32>::new(),
				"SM3"       => sm3::Sm3::new(),
				"STREEBOG256" => streebog::Streebog256::new(),
				"STREEBOG512" => streebog::Streebog512::new(),
				"TIGER"     => tiger::Tiger::new(),
				"WHIRLPOOL" => whirlpool::Whirlpool::new(),
			),
		}
	}

	pub fn process_string(&mut self, data: &[u8]) -> Vec<u8> {
		self.digest.update(data);
		self.digest.finalize_reset().to_vec()
	}

	pub fn read_file(
		&mut self,
		path: &str,
	) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
		let data = std::fs::read(path)?;
		self.digest.update(&data);
		Ok(self.digest.finalize_reset().to_vec())
	}
}

pub fn digest_bytes_to_record(
	algorithm: &str,
	data: &[u8],
	label: Option<&str>,
	source: DigestSource,
) -> Result<DigestRecord, String> {
	let mut engine = RHash::new(&algorithm.to_uppercase());
	let digest = engine.process_string(data);
	let path = label.map(|value| value.to_string());
	Ok(DigestRecord::from_digest(path, algorithm, &digest, source))
}

pub fn serialize_digest_output(
	records: &[DigestRecord],
	format: DigestOutputFormat,
	hash_only: bool,
) -> Result<SerializationResult, OutputError> {
	let profile = OutputFormatProfile::new(format);
	serialize_records(records, &profile, hash_only)
}

pub fn digest_with_options(
	options: &FileDigestOptions,
) -> Result<
	(ManifestOutcome, SerializationResult),
	Box<dyn std::error::Error>,
> {
	let is_tty = io::stderr().is_terminal();
	let mut emitter =
		if options.progress.should_emit(options.hash_only, is_tty) {
			Some(ProgressEmitter::new(options.progress))
		} else {
			None
		};

	let (outcome, records) = {
		let emitter_ref = emitter.as_mut();
		digest_with_options_internal(options, emitter_ref)?
	};

	if let Some(emitter) = emitter.as_mut() {
		emitter.emit_final();
	}

	let serialization = serialize_digest_output(
		&records,
		options.format,
		options.hash_only,
	)
	.map_err(|err| -> Box<dyn std::error::Error> { Box::new(err) })?;

	if outcome.should_write_manifest {
		if let Some(manifest_path) = &options.manifest_path {
			write_manifest(manifest_path, &outcome.summary)?;
		}
	}

	Ok((outcome, serialization))
}

pub fn digest_with_options_collect(
	options: &FileDigestOptions,
) -> Result<FileDigestResult, Box<dyn std::error::Error>> {
	let (outcome, serialization) = digest_with_options(options)?;
	let ManifestOutcome {
		summary,
		exit_code,
		should_write_manifest,
		fatal_error,
	} = outcome;
	Ok(FileDigestResult {
		summary,
		lines: serialization.lines,
		warnings: serialization.warnings,
		exit_code,
		should_write_manifest,
		fatal_error,
	})
}

fn digest_with_options_internal(
	options: &FileDigestOptions,
	mut emitter: Option<&mut ProgressEmitter>,
) -> Result<
	(ManifestOutcome, Vec<DigestRecord>),
	Box<dyn std::error::Error>,
> {
	let algorithm_upper = options.algorithm_uppercase();
	let walker = Walker::new(options.plan.clone());
	let entries = walker.walk()?;
	let mut writer = ManifestWriter::new(
		options.plan.clone(),
		options.error_profile.clone(),
	);
	let mut records = Vec::new();

	for entry in entries {
		let path = entry.path.clone();
		let display_path = path.to_string_lossy();
		let metadata = match fs::metadata(&path) {
			Ok(meta) => meta,
			Err(err) => {
				let status = match err.kind() {
					io::ErrorKind::PermissionDenied => {
						EntryStatus::Skipped
					}
					_ => EntryStatus::Error,
				};
				let message = format!(
					"failed to read metadata for {}: {}",
					display_path, err
				);
				let should_continue = writer.record_failure(
					path,
					&options.algorithm,
					message.clone(),
					status,
				);
				eprintln!("{}", message);
				if !should_continue {
					return Ok((writer.finalize(), records));
				}
				continue;
			}
		};
		let size = metadata.len();
		let modified =
			metadata.modified().ok().map(DateTime::<Utc>::from);

		let mut engine = RHash::new(&algorithm_upper);
		let digest_bytes = match engine
			.read_file(display_path.as_ref())
		{
			Ok(bytes) => bytes,
			Err(err) => {
				let status = entry_status_from_error(err.as_ref());
				let message = format!(
					"failed to hash {}: {}",
					display_path, err
				);
				let should_continue = writer.record_failure(
					path,
					&options.algorithm,
					message.clone(),
					status,
				);
				eprintln!("{}", message);
				if !should_continue {
					return Ok((writer.finalize(), records));
				}
				continue;
			}
		};
		let record = DigestRecord::from_digest(
			Some(display_path.to_string()),
			&options.algorithm,
			&digest_bytes,
			DigestSource::File,
		);
		if let Some(emitter) = emitter.as_mut() {
			emitter.record(size);
			emitter.maybe_emit();
		}
		let mut manifest_digest = record.digest_hex.clone();
		if options.format == DigestOutputFormat::Multihash {
			let algorithm = options.algorithm.to_ascii_lowercase();
			match MultihashEncoder::encode(&algorithm, &digest_bytes)
			{
				Ok(token) => manifest_digest = token,
				Err(err) => eprintln!(
					"warning: failed to encode multihash for manifest entry {}: {}",
					display_path,
					err
				),
			}
		}
		records.push(record);
		writer.record_success(
			path,
			&options.algorithm,
			manifest_digest,
			size,
			modified,
		);
	}

	Ok((writer.finalize(), records))
}

fn write_manifest(
	path: &PathBuf,
	summary: &ManifestSummary,
) -> Result<(), Box<dyn std::error::Error>> {
	if let Some(parent) = path.parent() {
		if !parent.as_os_str().is_empty() {
			fs::create_dir_all(parent)?;
		}
	}
	let file = File::create(path)?;
	to_writer_pretty(file, summary)?;
	Ok(())
}

enum CompareInput {
	Manifest(ManifestSummary),
	Lines(Vec<String>),
}

pub fn compare_file_hashes(
	baseline: &str,
	candidate: &str,
) -> Result<CompareSummary, Box<dyn std::error::Error>> {
	let baseline_path = Path::new(baseline);
	let candidate_path = Path::new(candidate);
	let baseline_input = load_compare_input(baseline_path)?;
	let candidate_input = load_compare_input(candidate_path)?;
	match (baseline_input, candidate_input) {
		(
			CompareInput::Manifest(left),
			CompareInput::Manifest(right),
		) => Ok(compare_manifests(left, right)),
		(CompareInput::Lines(left), CompareInput::Lines(right)) => {
			Ok(compare_line_lists(left, right))
		}
		(CompareInput::Manifest(_), CompareInput::Lines(_))
		| (CompareInput::Lines(_), CompareInput::Manifest(_)) => {
			Err(io::Error::new(
				io::ErrorKind::InvalidInput,
				"Cannot compare manifest JSON with plain digest list",
			)
			.into())
		}
	}
}

fn load_compare_input(
	path: &Path,
) -> Result<CompareInput, Box<dyn std::error::Error>> {
	let contents = fs::read_to_string(path)?;
	match serde_json::from_str::<ManifestSummary>(&contents) {
		Ok(summary) => Ok(CompareInput::Manifest(summary)),
		Err(err) => {
			if contents.trim_start().starts_with('{') {
				return Err(Box::new(err));
			}
			let lines = contents
				.lines()
				.map(|line| line.trim_end_matches(['\r', '\n']))
				.map(|line| line.to_string())
				.collect();
			Ok(CompareInput::Lines(lines))
		}
	}
}

fn compare_manifests(
	left: ManifestSummary,
	right: ManifestSummary,
) -> CompareSummary {
	let mut differences = Vec::new();
	let mut incomplete = false;
	let mut right_map: HashMap<PathBuf, &ManifestEntry> = right
		.entries
		.iter()
		.map(|entry| (entry.path.clone(), entry))
		.collect();
	for entry in &left.entries {
		if entry.status != EntryStatus::Hashed
			|| entry.digest.is_none()
		{
			incomplete = true;
		}
		match right_map.remove(&entry.path) {
			Some(other) => {
				if other.status != EntryStatus::Hashed
					|| other.digest.is_none()
				{
					incomplete = true;
				}
				match (entry.digest.as_ref(), other.digest.as_ref()) {
					(Some(expected), Some(actual)) => {
						if expected != actual {
							let identifier =
								entry.path.display().to_string();
							differences.push(CompareDifference {
								identifier,
								kind: CompareDiffKind::Changed,
								expected: Some(expected.clone()),
								actual: Some(actual.clone()),
							});
						}
					}
					(Some(expected), None) => {
						let identifier =
							entry.path.display().to_string();
						differences.push(CompareDifference {
							identifier,
							kind: CompareDiffKind::Changed,
							expected: Some(expected.clone()),
							actual: None,
						});
						incomplete = true;
					}
					(None, Some(actual)) => {
						let identifier =
							entry.path.display().to_string();
						differences.push(CompareDifference {
							identifier,
							kind: CompareDiffKind::Changed,
							expected: None,
							actual: Some(actual.clone()),
						});
						incomplete = true;
					}
					(None, None) => {
						incomplete = true;
					}
				}
			}
			None => {
				let identifier = entry.path.display().to_string();
				differences.push(CompareDifference {
					identifier,
					kind: CompareDiffKind::MissingRight,
					expected: entry.digest.clone(),
					actual: None,
				});
			}
		}
	}

	for entry in right_map.values() {
		let identifier = entry.path.display().to_string();
		differences.push(CompareDifference {
			identifier,
			kind: CompareDiffKind::MissingLeft,
			expected: None,
			actual: entry.digest.clone(),
		});
		if entry.status != EntryStatus::Hashed
			|| entry.digest.is_none()
		{
			incomplete = true;
		}
	}

	if left.failure_count > 0 || right.failure_count > 0 {
		incomplete = true;
	}

	let mut exit_code = 0;
	let has_mismatch = differences.iter().any(|diff| {
		matches!(
			diff.kind,
			CompareDiffKind::Changed
				| CompareDiffKind::MissingLeft
				| CompareDiffKind::MissingRight
		)
	});
	if has_mismatch {
		exit_code = 1;
	} else if incomplete {
		exit_code = 2;
	}

	differences.sort_by(|a, b| a.identifier.cmp(&b.identifier));

	CompareSummary {
		mode: CompareMode::Manifest,
		differences,
		exit_code,
		incomplete,
		left_failures: left.failure_count,
		right_failures: right.failure_count,
		left_entries: left.entries.len(),
		right_entries: right.entries.len(),
	}
}

fn compare_line_lists(
	left: Vec<String>,
	right: Vec<String>,
) -> CompareSummary {
	let mut differences = Vec::new();
	let max_len = left.len().max(right.len());
	for idx in 0..max_len {
		let left_line = left.get(idx);
		let right_line = right.get(idx);
		match (left_line, right_line) {
			(Some(expected), Some(actual)) => {
				if expected != actual {
					differences.push(CompareDifference {
						identifier: format!("line {}", idx + 1),
						kind: CompareDiffKind::Changed,
						expected: Some(expected.clone()),
						actual: Some(actual.clone()),
					});
				}
			}
			(Some(expected), None) => {
				differences.push(CompareDifference {
					identifier: format!("line {}", idx + 1),
					kind: CompareDiffKind::MissingRight,
					expected: Some(expected.clone()),
					actual: None,
				});
			}
			(None, Some(actual)) => {
				differences.push(CompareDifference {
					identifier: format!("line {}", idx + 1),
					kind: CompareDiffKind::MissingLeft,
					expected: None,
					actual: Some(actual.clone()),
				});
			}
			(None, None) => {}
		}
	}

	let exit_code = if differences.is_empty() { 0 } else { 1 };

	CompareSummary {
		mode: CompareMode::Text,
		differences,
		exit_code,
		incomplete: false,
		left_failures: 0,
		right_failures: 0,
		left_entries: left.len(),
		right_entries: right.len(),
	}
}

fn entry_status_from_error(
	err: &(dyn std::error::Error + 'static),
) -> EntryStatus {
	if let Some(io_err) = err.downcast_ref::<io::Error>() {
		return match io_err.kind() {
			io::ErrorKind::PermissionDenied => EntryStatus::Skipped,
			_ => EntryStatus::Error,
		};
	}
	EntryStatus::Error
}
