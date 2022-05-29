use crate::hash;
use blake2::{Blake2b512, Blake2s256};
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
use std::io::BufRead;
use std::process::exit;
use streebog::{Streebog256, Streebog512};
use structopt::clap::{crate_authors, crate_name, crate_version};
use structopt::StructOpt;
use tiger::Tiger;
use whirlpool::Whirlpool;

const LONG_HELP_TXT: &str = r"A switch to provide the hash algorithm with which the provided string will be hashed. Supported are: argon2, blake2s, blake2b, gost94, gost94ua, groestl, md2, md4, md5, pbkdf2-sha256, pbkdf2-sha512, ripemd160, ripemd320, sha1, sha224, sha256, sha384, sha512, sha3-224, sha3-256, sha3-384, sha3-512, shabal192, shabal224, shabal256, shabal384, shabal512, streebog256, streebog512, tiger, whirlpool";

#[derive(StructOpt, Debug)]
#[structopt(
    name = "rustgenhash",
    about = "CLI utility to generate hashes for files and strings."
)]
pub enum Cmd {
    File {
        #[structopt(
            short,
            required = true,
            long_help = LONG_HELP_TXT,
        )]
        algorithm: String,
        #[structopt(name = "FILENAME", required = true)]
        input: String,
    },
    String {
        #[structopt(
            short,
            required = true,
            long_help = LONG_HELP_TXT,
        )]
        algorithm: String,
        #[structopt(name = "PASSWORD", required = true)]
        password: String,
    },
    Stdio {
        #[structopt(
        short,
        required = true,
        long_help = LONG_HELP_TXT,
        )]
        algorithm: String,
    },
}

fn match_invalid() {
    println!("You need to select a valid algorithm.");
    exit(1);
}

fn match_invalid_for_mode() {
    println!("This algorithm is not supported in this mode. You need to select a valid algorithm for this mode.");
    exit(1);
}

pub fn matching() {
    match Cmd::from_args() {
        Cmd::String {
            algorithm,
            password,
        } => match &algorithm as &str {
            "argon2" => hash::hash_argon2(password),
            "blake2b" => hash::hash_string(password, Blake2b512::new()),
            "blake2s" => hash::hash_string(password, Blake2s256::new()),
            "gost94" => hash::hash_string(password, Gost94Test::new()),
            "gost94ua" => hash::hash_string(password, Gost94UA::new()),
            "groestl" => hash::hash_string(password, Groestl256::new()),
            "md2" => hash::hash_string(password, Md2::new()),
            "md4" => hash::hash_string(password, Md4::new()),
            "md5" => hash::hash_string(password, Md5::new()),
            "pbkdf2-sha256" => hash::hash_pbkdf2(password, "pbkdf2-sha256"),
            "pbkdf2-sha512" => hash::hash_pbkdf2(password, "pbkdf2-sha512"),
            "ripemd160" => hash::hash_string(password, Ripemd160::new()),
            "ripemd320" => hash::hash_string(password, Ripemd320::new()),
            "scrypt" => hash::hash_scrypt(password),
            "sha1" => hash::hash_string(password, Sha1::new()),
            "sha224" => hash::hash_string(password, Sha224::new()),
            "sha256" => hash::hash_string(password, Sha256::new()),
            "sha384" => hash::hash_string(password, Sha384::new()),
            "sha512" => hash::hash_string(password, Sha512::new()),
            "sha3-224" => hash::hash_string(password, Sha3_224::new()),
            "sha3-256" => hash::hash_string(password, Sha3_256::new()),
            "sha3-384" => hash::hash_string(password, Sha3_384::new()),
            "sha3-512" => hash::hash_string(password, Sha3_512::new()),
            "shabal192" => hash::hash_string(password, Shabal192::new()),
            "shabal224" => hash::hash_string(password, Shabal224::new()),
            "shabal256" => hash::hash_string(password, Shabal256::new()),
            "shabal384" => hash::hash_string(password, Shabal384::new()),
            "shabal512" => hash::hash_string(password, Shabal512::new()),
            "streebog256" => hash::hash_string(password, Streebog256::new()),
            "streebog512" => hash::hash_string(password, Streebog512::new()),
            "tiger" => hash::hash_string(password, Tiger::new()),
            "whirlpool" => hash::hash_string(password, Whirlpool::new()),
            _ => match_invalid(),
        },

        Cmd::File { algorithm, input } => match &algorithm as &str {
            "argon2" => match_invalid_for_mode(),
            "blake2b" => hash::hash_file(input, Blake2b512::new()),
            "blake2s" => hash::hash_file(input, Blake2s256::new()),
            "gost94" => hash::hash_file(input, Gost94Test::new()),
            "gost94ua" => hash::hash_file(input, Gost94UA::new()),
            "groestl" => hash::hash_file(input, Groestl256::new()),
            "md2" => hash::hash_file(input, Md2::new()),
            "md4" => hash::hash_file(input, Md4::new()),
            "md5" => hash::hash_file(input, Md5::new()),
            "pbkdf2" => match_invalid_for_mode(),
            "pbkdf2-sha256" => match_invalid_for_mode(),
            "pbkdf2-sha512" => match_invalid_for_mode(),
            "ripemd160" => hash::hash_file(input, Ripemd160::new()),
            "ripemd320" => hash::hash_file(input, Ripemd320::new()),
            "scrypt" => match_invalid_for_mode(),
            "sha1" => hash::hash_file(input, Sha1::new()),
            "sha224" => hash::hash_file(input, Sha224::new()),
            "sha256" => hash::hash_file(input, Sha256::new()),
            "sha384" => hash::hash_file(input, Sha384::new()),
            "sha512" => hash::hash_file(input, Sha512::new()),
            "sha3-224" => hash::hash_file(input, Sha3_224::new()),
            "sha3-256" => hash::hash_file(input, Sha3_256::new()),
            "sha3-384" => hash::hash_file(input, Sha3_384::new()),
            "sha3-512" => hash::hash_file(input, Sha3_512::new()),
            "shabal192" => hash::hash_file(input, Shabal192::new()),
            "shabal224" => hash::hash_file(input, Shabal224::new()),
            "shabal256" => hash::hash_file(input, Shabal256::new()),
            "shabal384" => hash::hash_file(input, Shabal384::new()),
            "shabal512" => hash::hash_file(input, Shabal512::new()),
            "streebog256" => hash::hash_file(input, Streebog256::new()),
            "streebog512" => hash::hash_file(input, Streebog512::new()),
            "tiger" => match_invalid_for_mode(),
            "whirlpool" => hash::hash_file(input, Whirlpool::new()),
            _ => match_invalid(),
        },
        Cmd::Stdio { algorithm } => {
            let stdin = std::io::stdin();
            for lines in stdin.lock().lines() {
                let password = lines.unwrap();
                match &algorithm as &str {
                    "argon2" => hash::hash_argon2(password),
                    "blake2b" => hash::hash_string(password, Blake2b512::new()),
                    "blake2s" => hash::hash_string(password, Blake2s256::new()),
                    "gost94" => hash::hash_string(password, Gost94Test::new()),
                    "gost94ua" => hash::hash_string(password, Gost94UA::new()),
                    "groestl" => hash::hash_string(password, Groestl256::new()),
                    "md2" => hash::hash_string(password, Md2::new()),
                    "md4" => hash::hash_string(password, Md4::new()),
                    "md5" => hash::hash_string(password, Md5::new()),
                    "pbkdf2-sha256" => hash::hash_pbkdf2(password, "pbkdf2-sha256"),
                    "pbkdf2-sha512" => hash::hash_pbkdf2(password, "pbkdf2-sha512"),
                    "ripemd160" => hash::hash_string(password, Ripemd160::new()),
                    "ripemd320" => hash::hash_string(password, Ripemd320::new()),
                    "scrypt" => hash::hash_scrypt(password),
                    "sha1" => hash::hash_string(password, Sha1::new()),
                    "sha224" => hash::hash_string(password, Sha224::new()),
                    "sha256" => hash::hash_string(password, Sha256::new()),
                    "sha384" => hash::hash_string(password, Sha384::new()),
                    "sha512" => hash::hash_string(password, Sha512::new()),
                    "sha3-224" => hash::hash_string(password, Sha3_224::new()),
                    "sha3-256" => hash::hash_string(password, Sha3_256::new()),
                    "sha3-384" => hash::hash_string(password, Sha3_384::new()),
                    "sha3-512" => hash::hash_string(password, Sha3_512::new()),
                    "shabal192" => hash::hash_string(password, Shabal192::new()),
                    "shabal224" => hash::hash_string(password, Shabal224::new()),
                    "shabal256" => hash::hash_string(password, Shabal256::new()),
                    "shabal384" => hash::hash_string(password, Shabal384::new()),
                    "shabal512" => hash::hash_string(password, Shabal512::new()),
                    "streebog256" => hash::hash_string(password, Streebog256::new()),
                    "streebog512" => hash::hash_string(password, Streebog512::new()),
                    "tiger" => hash::hash_string(password, Tiger::new()),
                    "whirlpool" => hash::hash_string(password, Whirlpool::new()),
                    _ => match_invalid(),
                }
            }
        }
    }
}

pub fn about() {
    println!(
        "{} v{} by {}",
        crate_name!(),
        crate_version!(),
        crate_authors!()
    );
    println!();
}
