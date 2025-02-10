// SPDX-License-Identifier: MIT OR Apache-2.0
// Project: rustgenhash
// File: hash.rs
// Author: Volker Schwaberow <volker@schwaberow.de>
// Copyright (c) 2022 Volker Schwaberow

use crate::rgh::app::OutputOptions;
use argon2::{
    password_hash::{rand_core::OsRng, PasswordHasher, SaltString},
    Argon2,
};
use ascon_hash::AsconHash;
use balloon_hash::{
    password_hash::{rand_core::OsRng as BalOsRng, SaltString as BalSaltString},
    Balloon, Algorithm as BalAlgorithm, Params as BalParams,
};
use blake2::Digest;
use digest::DynDigest;
use pbkdf2::{
    password_hash::{Ident as PbIdent, SaltString as PbSaltString},
    Pbkdf2,
};
use std::collections::HashMap;
use scrypt::{password_hash::SaltString as ScSaltString, Scrypt, Params as ScParams};
use skein::{consts::U32, Skein1024, Skein256, Skein512};

#[derive(Clone, Debug)]
pub struct Argon2Config { pub mem_cost: u32, pub time_cost: u32, pub parallelism: u32 }
impl Default for Argon2Config {
    fn default() -> Self {
        Self { mem_cost: 65536, time_cost: 3, parallelism: 4 }
    }
}

#[derive(Clone, Debug)]
pub struct ScryptConfig { pub log_n: u8, pub r: u32, pub p: u32 }
impl Default for ScryptConfig {
    fn default() -> Self {
        Self { log_n: 15, r: 8, p: 1 }
    }
}

#[derive(Clone, Debug)]
pub struct BcryptConfig { pub cost: u32 }
impl Default for BcryptConfig {
    fn default() -> Self { Self { cost: 12 } }
}

#[derive(Clone, Debug)]
pub struct Pbkdf2Config { pub rounds: u32, pub output_length: usize }
impl Default for Pbkdf2Config {
    fn default() -> Self { Self { rounds: 100_000, output_length: 32 } }
}

#[derive(Clone, Debug)]
pub struct BalloonConfig { pub time_cost: u32, pub memory_cost: u32, pub parallelism: u32 }
impl Default for BalloonConfig {
    fn default() -> Self {
        Self { time_cost: 3, memory_cost: 65536, parallelism: 4 }
    }
}

macro_rules! impl_password_hash_fn {
    ($name:ident, $impl_fn:ident, $cfg:ty, $salt:expr) => {
        pub fn $name(password: &str, config: &$cfg) {
            let salt = $salt;
            let hash = match Self::$impl_fn(password, config, &salt) {
                Ok(h) => h,
                Err(e) => { println!("Error hashing password: {}", e); return; },
            };
            println!("{} {}", hash, password);
        }
    };
}

macro_rules! impl_hash_function {
    ($name:ident, $hasher:expr) => {
        pub fn $name(password: &str) {
            let result = $hasher(password.as_bytes());
            println!("{} {}", hex::encode(result), password);
        }
    };
}

pub struct PHash {}
impl PHash {
    impl_hash_function!(hash_ascon, AsconHash::digest);

    impl_password_hash_fn!(hash_argon2, hash_argon2_impl, Argon2Config, SaltString::generate(&mut OsRng));
    fn hash_argon2_impl(password: &str, cfg: &Argon2Config, salt: &SaltString)
        -> Result<String, argon2::password_hash::Error>
    {
        let argon2 = Argon2::new(
            argon2::Algorithm::Argon2id,
            argon2::Version::V0x13,
            argon2::Params::new(cfg.mem_cost, cfg.time_cost, cfg.parallelism, None).unwrap()
        );
        Ok(argon2.hash_password(password.as_bytes(), salt)?.to_string())
    }

    impl_password_hash_fn!(hash_balloon, hash_balloon_impl, BalloonConfig, BalSaltString::generate(&mut BalOsRng));
    fn hash_balloon_impl(password: &str, cfg: &BalloonConfig, salt: &BalSaltString)
        -> Result<String, balloon_hash::password_hash::Error>
    {
        let balloon = Balloon::<sha2::Sha256>::new(
            BalAlgorithm::Balloon,
            BalParams::new(cfg.time_cost, cfg.memory_cost, cfg.parallelism).unwrap(),
            None,
        );
        Ok(balloon.hash_password(password.as_bytes(), salt)?.to_string())
    }

    impl_password_hash_fn!(hash_scrypt, hash_scrypt_impl, ScryptConfig, ScSaltString::generate(&mut OsRng));
    fn hash_scrypt_impl(password: &str, cfg: &ScryptConfig, salt: &ScSaltString)
        -> Result<String, scrypt::password_hash::Error>
    {
        let params = ScParams::new(cfg.log_n, cfg.r, cfg.p).unwrap();
        Ok(Scrypt.hash_password_customized(password.as_bytes(), None, None, params, salt.as_salt())?.to_string())
    }

    pub fn hash_bcrypt(password: &str, cfg: &BcryptConfig) {
        let salt = SaltString::generate(&mut OsRng);
        let mut out = [0; 64];
        bcrypt_pbkdf::bcrypt_pbkdf(password.as_bytes(), salt.as_bytes(), cfg.cost, &mut out)
            .unwrap_or_else(|e| { eprintln!("Error: {}", e); std::process::exit(1); });
        println!("{} {}", hex::encode(out), password);
    }

    pub fn hash_sha_crypt(password: &str) {
        let params = sha_crypt::Sha512Params::new(10_000).unwrap_or_else(|e| { println!("Error: {:?}", e); std::process::exit(1); });
        let hash = sha_crypt::sha512_simple(password, &params).unwrap_or_else(|e| { println!("Error: {:?}", e); std::process::exit(1); });
        println!("{} {}", hash, password);
    }

    pub fn hash_pbkdf2(password: &str, pb_scheme: &str, cfg: &Pbkdf2Config) {
        let schemes = HashMap::from([("pbkdf2sha256", "pbkdf2-sha256"), ("pbkdf2sha512", "pbkdf2-sha512")]);
        let alg = PbIdent::new(schemes.get(pb_scheme).unwrap_or(&"NONE")).unwrap();
        let salt = PbSaltString::generate(&mut OsRng);
        let params = pbkdf2::Params { output_length: cfg.output_length, rounds: cfg.rounds };
        let hash = Pbkdf2::hash_password_customized(&Pbkdf2, password.as_bytes(), Some(alg), None, params, salt.as_salt())
            .unwrap_or_else(|_| { eprintln!("Error: Could not hash PBKDF2 password"); std::process::exit(1); });
        println!("{} {}", hash, password);
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
pub struct RHash { digest: Box<dyn DynDigest> }
impl RHash {
    pub fn new(alg: &str) -> Self {
        Self { digest: create_hasher!(alg,
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
        ) }
    }

    pub fn process_string(&mut self, data: &[u8]) -> Vec<u8> {
        self.digest.update(data);
        self.digest.finalize_reset().to_vec()
    }

    pub fn process_file(&mut self, path: &str, output: OutputOptions) -> Result<(), Box<dyn std::error::Error>> {
        let md = std::fs::metadata(path)?;
        if md.is_file() {
            let hash = self.read_file(path)?;
            self.print_hash(&self.format_hash(&hash, path, output)?);
        } else if md.is_dir() {
            for entry in std::fs::read_dir(path)? {
                let entry = entry?;
                if entry.path().is_file() {
                    let entry_path = entry.path();
                    let path = entry_path.to_str().ok_or("Invalid path")?;
                    let hash = self.read_file(path)?;
                    self.print_hash(&self.format_hash(&hash, path, output.clone())?);
                }
            }
        }
        Ok(())
    }

    fn print_hash(&self, s: &str) { println!("{}", s); }

    fn format_hash(&self, hash: &[u8], path: &str, output: OutputOptions) -> Result<String, Box<dyn std::error::Error>> {
        Ok(match output {
            OutputOptions::Base64 => format!("{} {}", base64::encode(hash), path),
            OutputOptions::Hex => format!("{} {}", hex::encode(hash), path),
            OutputOptions::HexBase64 => format!("{} {} {}", hex::encode(hash), base64::encode(hash), path),
        })
    }

    pub fn read_file(&mut self, path: &str) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
        let data = std::fs::read(path)?;
        self.digest.update(&data);
        Ok(self.digest.finalize_reset().to_vec())
    }
}
