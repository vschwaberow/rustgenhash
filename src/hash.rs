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

#[test]
fn test_md2() {
    let mut hasher = RHash::new("MD2");
    let pass = "b".to_string();
    let result = hasher.process_string(pass.as_bytes());
    assert_eq!(
        result,
        vec![130, 206, 148, 11, 27, 79, 210, 236, 216, 35, 110, 129, 166, 248, 181, 203]
    );
}
#[test]
fn test_md4() {
    let mut hasher = RHash::new("MD4");
    let result = hasher.process_string(b"");
    assert_eq!(
        result,
        vec![
            0x31, 0xd6, 0xcf, 0xe0, 0xd1, 0x6a, 0xe9, 0x31, 0xb7, 0x3c, 0x59, 0xd7, 0xe0, 0xc0,
            0x89, 0xc0
        ]
    );
}
#[test]
fn test_md5() {
    let mut hasher = RHash::new("MD5");
    let data = b"";
    let result = hasher.process_string(data);
    assert_eq!(
        result,
        vec![
            0xd4, 0x1d, 0x8c, 0xd9, 0x8f, 0x00, 0xb2, 0x04, 0xe9, 0x80, 0x09, 0x98, 0xec, 0xf8,
            0x42, 0x7e
        ]
    );
}

#[test]
fn test_sha1() {
    let mut hasher = RHash::new("SHA1");
    let data = b"";
    let result = hasher.process_string(data);
    assert_eq!(
        result,
        vec![
            0xda, 0x39, 0xa3, 0xee, 0x5e, 0x6b, 0x4b, 0x0d, 0x32, 0x55, 0xbf, 0xef, 0x95, 0x60,
            0x18, 0x90, 0xaf, 0xd8, 0x07, 0x09
        ]
    );
}

#[test]
fn test_sha2() {
    let mut hasher = RHash::new("SHA256");
    let data = b"";
    let result = hasher.process_string(data);
    assert_eq!(
        result,
        vec![
            0xe3, 0xb0, 0xc4, 0x42, 0x98, 0xfc, 0x1c, 0x14, 0x9a, 0xfb, 0xf4, 0xc8, 0x99, 0x6f,
            0xb9, 0x24, 0x27, 0xae, 0x41, 0xe4, 0x64, 0x9b, 0x93, 0x4c, 0xa4, 0x95, 0x99, 0x1b,
            0x78, 0x52, 0xb8, 0x55
        ]
    );

    let mut hasher = RHash::new("SHA384");
    let data = b"";
    let result = hasher.process_string(data);
    assert_eq!(
        result,
        vec![
            0x38, 0xb0, 0x60, 0xa7, 0x51, 0xac, 0x96, 0x38, 0x4c, 0xd9, 0x32, 0x7e, 0xb1, 0xb1,
            0xe3, 0x6a, 0x21, 0xfd, 0xb7, 0x11, 0x14, 0xbe, 0x07, 0x43, 0x4c, 0x0c, 0xc7, 0xbf,
            0x63, 0xf6, 0xe1, 0xda, 0x27, 0x4e, 0xde, 0xbf, 0xe7, 0x6f, 0x65, 0xfb, 0xd5, 0x1a,
            0xd2, 0xf1, 0x48, 0x98, 0xb9, 0x5b
        ]
    );

    let mut hasher = RHash::new("SHA512");
    let data = b"";
    let result = hasher.process_string(data);
    assert_eq!(
        result,
        vec![
            0xcf, 0x83, 0xe1, 0x35, 0x7e, 0xef, 0xb8, 0xbd, 0xf1, 0x54, 0x28, 0x50, 0xd6, 0x6d,
            0x80, 0x07, 0xd6, 0x20, 0xe4, 0x05, 0x0b, 0x57, 0x15, 0xdc, 0x83, 0xf4, 0xa9, 0x21,
            0xd3, 0x6c, 0xe9, 0xce, 0x47, 0xd0, 0xd1, 0x3c, 0x5d, 0x85, 0xf2, 0xb0, 0xff, 0x83,
            0x18, 0xd2, 0x87, 0x7e, 0xec, 0x2f, 0x63, 0xb9, 0x31, 0xbd, 0x47, 0x41, 0x7a, 0x81,
            0xa5, 0x38, 0x32, 0x7a, 0xf9, 0x27, 0xda, 0x3e
        ]
    );
}

#[test]
fn test_sha3() {
    use hex_literal::hex;
    let mut hasher = RHash::new("SHA3_224");
    let data = b"";
    let result = hasher.process_string(data);
    assert_eq!(
        result,
        vec![
            0x6b, 0x4e, 0x03, 0x42, 0x36, 0x67, 0xdb, 0xb7, 0x3b, 0x6e, 0x15, 0x45, 0x4f, 0x0e,
            0xb1, 0xab, 0xd4, 0x59, 0x7f, 0x9a, 0x1b, 0x07, 0x8e, 0x3f, 0x5b, 0x5a, 0x6b, 0xc7
        ]
    );

    let mut hasher = RHash::new("SHA3_256");
    let data = b"";
    let result = hasher.process_string(data);
    assert_eq!(
        result,
        vec![
            0xa7, 0xff, 0xc6, 0xf8, 0xbf, 0x1e, 0xd7, 0x66, 0x51, 0xc1, 0x47, 0x56, 0xa0, 0x61,
            0xd6, 0x62, 0xf5, 0x80, 0xff, 0x4d, 0xe4, 0x3b, 0x49, 0xfa, 0x82, 0xd8, 0x0a, 0x4b,
            0x80, 0xf8, 0x43, 0x4a
        ]
    );

    let mut hasher = RHash::new("SHA3_384");
    let data = b"volker";
    let result = hasher.process_string(data);
    assert_eq!(result, hex!("292c5d7b7d4a9f04cc88e2b7f1c82506ff006d9415b9c96dd71faadbaf89ff9a747cd7ec0b1ae50e29b321b12b24469e"));

    let mut hasher = RHash::new("SHA3_512");
    let data = b"volker";
    let result = hasher.process_string(data);
    assert_eq!(
        result,
        hex!("2aa84199f3d2c74cd676f8a34d164536c3c71142f90f4b1410495e3147685674fe591b4dd24f4768a8839e1680e8e6e91cc4ccbfeb1fe27577be16756b4bc364")
    );
}

#[test]
fn test_gost94() {
    use hex_literal::hex;
    let mut hasher = RHash::new("GOST94");
    let data = b"volker";
    let result = hasher.process_string(data);
    assert_eq!(
        result,
        hex!("551dadd1e2f993d803a65e0e2eb71635ef9c4729be4ba60069a867416606243c")
    );

    let mut hasher = RHash::new("GOST94UA");
    let data = b"volker";
    let result = hasher.process_string(data);
    assert_eq!(
        result,
        hex!("d8439a5f1e69c451a66c0bd61ec3d2a1d72251b97795cd53b8dd12b438313c08")
    );
}

#[test]
fn test_streebog() {
    use hex_literal::hex;
    let mut hasher = RHash::new("STREEBOG256");
    let data = b"volker";
    let result = hasher.process_string(data);
    assert_eq!(
        result,
        hex!("b26f5746c682b94aae1f379adc543ab57af2705dc00b1c8ce76f339d65ab0bea")
    );

    let mut hasher = RHash::new("STREEBOG512");
    let data = b"volker";
    let result = hasher.process_string(data);
    assert_eq!(
        result,
        hex!("a46f857d0bd23dc679c69d5234e44d58069a3d50c60da5abf56fabed70e3c72b2050763e8a7bd787c76b3c17fffedd65e8e1c14e7a911ef12899da9980efd8e9")
    );
}

#[test]
fn test_shabal() {
    use hex_literal::hex;
    let mut hasher = RHash::new("SHABAL192");
    let data = b"volker";
    let result = hasher.process_string(data);
    assert_eq!(
        result,
        hex!("48ad5122b9d23c402f895587423645c0021f43f9945b5ba3")
    );

    let mut hasher = RHash::new("SHABAL224");
    let data = b"volker";
    let result = hasher.process_string(data);
    assert_eq!(
        result,
        hex!("9a90b332259c0178c4a1ed9cd254eadfc917f88edf7b3dbee8e971da")
    );

    let mut hasher = RHash::new("SHABAL256");
    let data = b"volker";
    let result = hasher.process_string(data);
    assert_eq!(
        result,
        hex!("9779f7a748b7a6087c7e0f149877e87deb42371e2a10df0fbef1a38123029b02")
    );

    let mut hasher = RHash::new("SHABAL384");
    let data = b"volker";
    let result = hasher.process_string(data);
    assert_eq!(
        result,
        hex!("4dc385ce0932123d50330e41d9bdf633e4aeb4caf52200d2f5b3843a2061118fe82188f74a44741fc4278765b2a9c5fc")
    );

    let mut hasher = RHash::new("SHABAL512");
    let data = b"volker";
    let result = hasher.process_string(data);
    assert_eq!(
        result,
        hex!("911dfa9aaed2318d28ae5a04b5584a39be27ef558845f4c8235e7e4e72c63bfaedc02dd89270b367e651dc36d3dea2c471a7de7c9df3e65522dc6e2837e38b99")
    );
}

#[test]
#[should_panic]
fn test_error_string_hash() {
    let mut _hasher = RHash::new("MICKEYMOUSE");
}
