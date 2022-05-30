use crate::cli::{Algorithm, Cmd, Mode};
use crate::hash;
use blake2::{Blake2b512, Blake2s256};
use clap::{crate_authors, crate_name, crate_version};
use clap::{CommandFactory, Parser};
use digest::Digest;
use gost94::{Gost94Test, Gost94UA};
use groestl::Groestl256;
use md2::Md2;
use md4::Md4;
use md5::Md5;
use ripemd::{Ripemd160, Ripemd320};
use sha1::Sha1;
use sha2::{Sha224, Sha256, Sha384, Sha512};
use sha3::{Sha3_224, Sha3_256, Sha3_384, Sha3_512};
use shabal::{Shabal192, Shabal224, Shabal256, Shabal384, Shabal512};
use std::io::{self, BufRead};
use std::process::exit;
use streebog::{Streebog256, Streebog512};
use tiger::Tiger;
use whirlpool::Whirlpool;

fn match_invalid_for_mode() {
    println!("This algorithm is not supported in this mode. You need to select a valid algorithm for this mode.");
    exit(1);
}

fn hash_string(algorithm: Algorithm, password: &str) {
    match algorithm {
        Algorithm::Argon2 => hash::hash_argon2(password),
        Algorithm::Blake2b => hash::hash_string(password, Blake2b512::new()),
        Algorithm::Blake2s => hash::hash_string(password, Blake2s256::new()),
        Algorithm::Gost94 => hash::hash_string(password, Gost94Test::new()),
        Algorithm::Gost94ua => hash::hash_string(password, Gost94UA::new()),
        Algorithm::Groestl => hash::hash_string(password, Groestl256::new()),
        Algorithm::Md2 => hash::hash_string(password, Md2::new()),
        Algorithm::Md4 => hash::hash_string(password, Md4::new()),
        Algorithm::Md5 => hash::hash_string(password, Md5::new()),
        Algorithm::Pbkdf2Sha256 => hash::hash_pbkdf2(password, "pbkdf2-sha256"),
        Algorithm::Pbkdf2Sha512 => hash::hash_pbkdf2(password, "pbkdf2-sha512"),
        Algorithm::Ripemd160 => hash::hash_string(password, Ripemd160::new()),
        Algorithm::Ripemd320 => hash::hash_string(password, Ripemd320::new()),
        Algorithm::Scrypt => hash::hash_scrypt(password),
        Algorithm::Sha1 => hash::hash_string(password, Sha1::new()),
        Algorithm::Sha224 => hash::hash_string(password, Sha224::new()),
        Algorithm::Sha256 => hash::hash_string(password, Sha256::new()),
        Algorithm::Sha384 => hash::hash_string(password, Sha384::new()),
        Algorithm::Sha512 => hash::hash_string(password, Sha512::new()),
        Algorithm::Sha3_224 => hash::hash_string(password, Sha3_224::new()),
        Algorithm::Sha3_256 => hash::hash_string(password, Sha3_256::new()),
        Algorithm::Sha3_384 => hash::hash_string(password, Sha3_384::new()),
        Algorithm::Sha3_512 => hash::hash_string(password, Sha3_512::new()),
        Algorithm::Shabal192 => hash::hash_string(password, Shabal192::new()),
        Algorithm::Shabal224 => hash::hash_string(password, Shabal224::new()),
        Algorithm::Shabal256 => hash::hash_string(password, Shabal256::new()),
        Algorithm::Shabal384 => hash::hash_string(password, Shabal384::new()),
        Algorithm::Shabal512 => hash::hash_string(password, Shabal512::new()),
        Algorithm::Streebog256 => hash::hash_string(password, Streebog256::new()),
        Algorithm::Streebog512 => hash::hash_string(password, Streebog512::new()),
        Algorithm::Tiger => hash::hash_string(password, Tiger::new()),
        Algorithm::Whirlpool => hash::hash_string(password, Whirlpool::new()),
    }
}

pub fn matching() {
    let cmd = Cmd::parse();
    match cmd.mode {
        Mode::GenerateCompletions { shell } => {
            let shell: clap_complete::Shell = shell.into();
            clap_complete::generate(shell, &mut Cmd::command(), crate_name!(), &mut io::stdout());
        }
        Mode::String {
            algorithm,
            password,
        } => hash_string(algorithm, &password),
        Mode::Stdio { algorithm } => {
            let stdin = std::io::stdin();
            for lines in stdin.lock().lines() {
                let password = lines.unwrap();
                hash_string(algorithm.clone(), &password);
            }
        }
        Mode::File { algorithm, input } => match algorithm {
            Algorithm::Argon2 => match_invalid_for_mode(),
            Algorithm::Blake2b => hash::hash_file(input, Blake2b512::new()),
            Algorithm::Blake2s => hash::hash_file(input, Blake2s256::new()),
            Algorithm::Gost94 => hash::hash_file(input, Gost94Test::new()),
            Algorithm::Gost94ua => hash::hash_file(input, Gost94UA::new()),
            Algorithm::Groestl => hash::hash_file(input, Groestl256::new()),
            Algorithm::Md2 => hash::hash_file(input, Md2::new()),
            Algorithm::Md4 => hash::hash_file(input, Md4::new()),
            Algorithm::Md5 => hash::hash_file(input, Md5::new()),
            Algorithm::Pbkdf2Sha256 => match_invalid_for_mode(),
            Algorithm::Pbkdf2Sha512 => match_invalid_for_mode(),
            Algorithm::Ripemd160 => hash::hash_file(input, Ripemd160::new()),
            Algorithm::Ripemd320 => hash::hash_file(input, Ripemd320::new()),
            Algorithm::Scrypt => match_invalid_for_mode(),
            Algorithm::Sha1 => hash::hash_file(input, Sha1::new()),
            Algorithm::Sha224 => hash::hash_file(input, Sha224::new()),
            Algorithm::Sha256 => hash::hash_file(input, Sha256::new()),
            Algorithm::Sha384 => hash::hash_file(input, Sha384::new()),
            Algorithm::Sha512 => hash::hash_file(input, Sha512::new()),
            Algorithm::Sha3_224 => hash::hash_file(input, Sha3_224::new()),
            Algorithm::Sha3_256 => hash::hash_file(input, Sha3_256::new()),
            Algorithm::Sha3_384 => hash::hash_file(input, Sha3_384::new()),
            Algorithm::Sha3_512 => hash::hash_file(input, Sha3_512::new()),
            Algorithm::Shabal192 => hash::hash_file(input, Shabal192::new()),
            Algorithm::Shabal224 => hash::hash_file(input, Shabal224::new()),
            Algorithm::Shabal256 => hash::hash_file(input, Shabal256::new()),
            Algorithm::Shabal384 => hash::hash_file(input, Shabal384::new()),
            Algorithm::Shabal512 => hash::hash_file(input, Shabal512::new()),
            Algorithm::Streebog256 => hash::hash_file(input, Streebog256::new()),
            Algorithm::Streebog512 => hash::hash_file(input, Streebog512::new()),
            Algorithm::Tiger => match_invalid_for_mode(),
            Algorithm::Whirlpool => hash::hash_file(input, Whirlpool::new()),
        },
    }
}

pub fn about() {
    eprintln!(
        "{} v{} by {}",
        crate_name!(),
        crate_version!(),
        crate_authors!()
    );
    eprintln!();
}
