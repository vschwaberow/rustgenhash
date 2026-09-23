// SPDX-License-Identifier: MIT OR Apache-2.0
// Project: rustgenhash
// File: hash/rhash.rs

use crate::rgh::snefru::{Snefru128, Snefru256};
use ascon_hash::AsconHash256;
use blake2::Digest;
use digest::consts::{U128, U32, U64};
use digest::DynDigest;
use skein::{Skein1024, Skein256, Skein512};
use std::fs::File;
use std::io::Read;
use std::path::Path;

macro_rules! create_hasher {
    ($alg:expr, $($pat:expr => $hasher:expr),+ $(,)?) => {
        match $alg {
            $($pat => Ok(Box::new($hasher) as Box<dyn digest::DynDigest>),)+
            other => Err(format!("Unknown algorithm: {other}")),
        }
    };
}

#[derive(Clone)]
pub struct RHash {
	digest: Box<dyn DynDigest>,
}
impl RHash {
	pub fn new(alg: &str) -> Result<Self, String> {
		let normalized = alg.to_ascii_uppercase().replace('-', "_");
		Ok(Self {
			digest: create_hasher!(normalized.as_str(),
				"ASCON"     => AsconHash256::new(),
				"BELTHASH"  => belt_hash::BeltHash::new(),
				"BLAKE2B"   => blake2::Blake2b512::new(),
				"BLAKE2S"   => blake2::Blake2s256::new(),
				"BLAKE3"    => blake3::Hasher::new(),
				"FSB160"    => fsb::Fsb160::new(),
				"FSB224"    => fsb::Fsb224::new(),
				"FSB256"    => fsb::Fsb256::new(),
				"FSB384"    => fsb::Fsb384::new(),
				"FSB512"    => fsb::Fsb512::new(),
				"GOST94"    => gost94::Gost94CryptoPro::new(),
				"GOST94TEST" => gost94::Gost94Test::new(),
				"GOST94_TEST" => gost94::Gost94Test::new(),
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
				"SKEIN512"  => Skein512::<U64>::new(),
				"SKEIN1024" => Skein1024::<U128>::new(),
				"SNEFRU" => Snefru128::new(),
				"SNEFRU128" => Snefru128::new(),
				"SNEFRU_128" => Snefru128::new(),
				"SNEFRU256" => Snefru256::new(),
				"SNEFRU_256" => Snefru256::new(),
				"SM3"       => sm3::Sm3::new(),
				"STREEBOG256" => streebog::Streebog256::new(),
				"STREEBOG512" => streebog::Streebog512::new(),
				"TIGER"     => tiger::Tiger::new(),
				"TIGER2"    => tiger::Tiger2::new(),
				"TIGER_2"   => tiger::Tiger2::new(),
				"WHIRLPOOL" => whirlpool::Whirlpool::new(),
			)?,
		})
	}

	pub fn process_string(&mut self, data: &[u8]) -> Vec<u8> {
		self.digest.update(data);
		self.digest.finalize_reset().to_vec()
	}

	pub fn read_file(
		&mut self,
		path: &Path,
	) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
		self.hash_path(Path::new(path), false)
	}

	pub fn hash_path(
		&mut self,
		path: &Path,
		use_mmap: bool,
	) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
		if use_mmap {
			let file = File::open(path)?;
			let mmap = unsafe { memmap2::MmapOptions::new().map(&file)? };
			self.digest.update(&mmap);
			return Ok(self.digest.finalize_reset().to_vec());
		}
		let mut file = File::open(path)?;
		let mut buf = [0u8; 64 * 1024];
		loop {
			let n = file.read(&mut buf)?;
			if n == 0 {
				break;
			}
			self.digest.update(&buf[..n]);
		}
		Ok(self.digest.finalize_reset().to_vec())
	}
}

