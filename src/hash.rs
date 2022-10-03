use crate::cli::OutputOptions;
use argon2::{
    password_hash::{rand_core::OsRng, PasswordHasher, SaltString},
    Argon2,
};
use balloon_hash::{
    password_hash::{rand_core::OsRng as BalOsRng, SaltString as BalSaltString},
    Balloon,
};
use blake2::Digest;
use digest::DynDigest;
use pbkdf2::{
    password_hash::{Ident as PbIdent, SaltString as PbSaltString},
    Pbkdf2,
};
use std::io::Read;

use scrypt::{password_hash::SaltString as ScSaltString, Scrypt};

pub struct PHash {}

impl PHash {
    pub fn hash_argon2(password: &str) {
        let salt = SaltString::generate(&mut OsRng);
        let argon2 = Argon2::default();
        let password_hash = argon2
            .hash_password(password.as_bytes(), &salt)
            .unwrap()
            .to_string();
        println!("{} {}", password_hash, password);
    }

    pub fn hash_balloon(password: &str) {
        // TODO: Make Balloon hash configurable
        let salt = BalSaltString::generate(&mut BalOsRng);
        let balloon = Balloon::<sha2::Sha256>::default();
        let password_hash = balloon
            .hash_password(password.as_bytes(), &salt)
            .unwrap()
            .to_string();
        println!("{} {}", password_hash, password);
    }

    pub fn hash_pbkdf2(password: &str, pb_scheme: &str) {
        let pb_s = match pb_scheme {
            "pbkdf2sha256" => "pbkdf2-sha256",
            "pbkdf2sha512" => "pbkdf2-sha512",
            _ => "NONE",
        };

        let algorithm = PbIdent::new(pb_s).unwrap();
        let salt = PbSaltString::generate(&mut OsRng);
        let params = pbkdf2::Params {
            output_length: 32,
            rounds: 100_000,
        };
        let password_hash = pbkdf2::Pbkdf2::hash_password_customized(
            &Pbkdf2,
            password.as_bytes(),
            Some(algorithm),
            None,
            params,
            salt.as_salt(),
        )
        .unwrap()
        .to_string();
        println!("{} {}", password_hash, password);
    }

    pub fn hash_scrypt(password: &str) {
        let salt = ScSaltString::generate(&mut OsRng);
        let password_hash = Scrypt
            .hash_password(password.as_bytes(), &salt)
            .unwrap()
            .to_string();
        println!("{} {}", password_hash, password);
    }
}

#[derive(Clone)]
pub struct RHash {
    digest: Box<dyn DynDigest>,
}

impl RHash {
    pub fn new(alg: &str) -> Self {
        Self {
            digest: match alg {
                "BLAKE2B" => Box::new(blake2::Blake2b512::new()),
                "BLAKE2S" => Box::new(blake2::Blake2s256::new()),
                "GOST94" => Box::new(gost94::Gost94Test::new()),
                "GOST94UA" => Box::new(gost94::Gost94UA::new()),
                "GROESTL" => Box::new(groestl::Groestl256::new()),
                "MD2" => Box::new(md2::Md2::new()),
                "MD5" => Box::new(md5::Md5::new()),
                "MD4" => Box::new(md4::Md4::new()),
                "RIPEMD160" => Box::new(ripemd::Ripemd160::new()),
                "RIPEMD320" => Box::new(ripemd::Ripemd320::new()),
                "SHA1" => Box::new(sha1::Sha1::new()),
                "SHA224" => Box::new(sha2::Sha224::new()),
                "SHA256" => Box::new(sha2::Sha256::new()),
                "SHA384" => Box::new(sha2::Sha384::new()),
                "SHA512" => Box::new(sha2::Sha512::new()),
                "SHA3_224" => Box::new(sha3::Sha3_224::new()),
                "SHA3_256" => Box::new(sha3::Sha3_256::new()),
                "SHA3_384" => Box::new(sha3::Sha3_384::new()),
                "SHA3_512" => Box::new(sha3::Sha3_512::new()),
                "SHABAL192" => Box::new(shabal::Shabal192::new()),
                "SHABAL224" => Box::new(shabal::Shabal224::new()),
                "SHABAL256" => Box::new(shabal::Shabal256::new()),
                "SHABAL384" => Box::new(shabal::Shabal384::new()),
                "SHABAL512" => Box::new(shabal::Shabal512::new()),
                "SM3" => Box::new(sm3::Sm3::new()),
                "STREEBOG256" => Box::new(streebog::Streebog256::new()),
                "STREEBOG512" => Box::new(streebog::Streebog512::new()),
                "TIGER" => Box::new(tiger::Tiger::new()),
                "WHIRLPOOL" => Box::new(whirlpool::Whirlpool::new()),
                _ => panic!("Unknown algorithm"),
            },
        }
    }

    pub fn process_string(&mut self, data: &[u8]) -> Vec<u8> {
        self.digest.update(data);
        let b = self.digest.finalize_reset();
        b.iter().cloned().collect::<Vec<u8>>()
    }

    pub fn process_file(&mut self, file: &str, output: Option<OutputOptions>) {
        let md = std::fs::metadata(file)
            .map_err(|e| {
                eprintln!("Error: {}", e);
                std::process::exit(1);
            })
            .unwrap();
        if md.is_file() {
            self.read_buffered(file);
            match output {
                Some(OutputOptions::Base64) => {
                    println!("{} {}", base64::encode(self.read_buffered(file)), file);
                }
                Some(OutputOptions::Hex) => {
                    println!("{} {}", hex::encode(self.read_buffered(file)), file);
                }
                Some(OutputOptions::HexBase64) => {
                    println!(
                        "{} {} {}",
                        hex::encode(self.read_buffered(&file)),
                        base64::encode(self.read_buffered(file)),
                        file
                    );
                }
                None => {
                    println!("{}:", file);
                    self.read_buffered(file);
                }
            }
        } else if md.is_dir() {
            let mut files = std::fs::read_dir(file).unwrap();
            while let Some(Ok(entry)) = files.next() {
                if entry.path().is_file() {
                    match output {
                        Some(OutputOptions::Base64) => {
                            println!(
                                "{} {}",
                                base64::encode(self.read_buffered(entry.path().to_str().unwrap())),
                                entry.path().to_str().unwrap()
                            );
                        }
                        Some(OutputOptions::Hex) => {
                            println!(
                                "{} {}",
                                hex::encode(self.read_buffered(entry.path().to_str().unwrap())),
                                entry.path().to_str().unwrap()
                            );
                        }
                        Some(OutputOptions::HexBase64) => {
                            println!(
                                "{} {} {}",
                                hex::encode(self.read_buffered(entry.path().to_str().unwrap())),
                                base64::encode(self.read_buffered(entry.path().to_str().unwrap())),
                                entry.path().to_str().unwrap()
                            );
                        }
                        None => {
                            println!("{}:", entry.path().to_str().unwrap());
                            self.read_buffered(entry.path().to_str().unwrap());
                        }
                    }
                }
            }
        }
    }

    pub fn read_buffered(&mut self, file: &str) -> Vec<u8> {
        let f = std::fs::File::open(file);
        match f {
            Ok(mut f) => {
                let mut buffer = [0; 1024];
                loop {
                    let count = f
                        .read(&mut buffer)
                        .map_err(|e| {
                            println!("Error reading file: {}", e);
                            std::process::exit(1);
                        })
                        .unwrap();
                    if count == 0 {
                        break;
                    }
                    self.digest.update(&buffer[..count]);
                }
                let b = self.digest.finalize_reset();
                b.iter().cloned().collect::<Vec<u8>>()
            }
            Err(e) => {
                println!("Error opening file: {}", e);
                std::process::exit(1);
            }
        }
    }
}
