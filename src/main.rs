use argon2::{
    password_hash::{rand_core::OsRng, PasswordHasher, SaltString},
    Argon2,
};
use blake2::{Blake2b, Blake2s};
use digest::generic_array::ArrayLength;
use digest::Digest;
use gost94::*;
use groestl::*;
use md2::Md2;
use md4::Md4;
use md5::Md5;
use pbkdf2::{
    password_hash::{
        Ident as PbIdent, PasswordHasher as PbPasswordHasher, SaltString as PbSaltString,
    },
    Pbkdf2,
};
use ripemd160::Ripemd160;
use ripemd320::*;
use scrypt::{password_hash::SaltString as ScSaltString, Scrypt};
use sha1::Sha1;
use sha2::{Sha224, Sha256, Sha384, Sha512};
use sha3::{Sha3_224, Sha3_256, Sha3_384, Sha3_512};
use shabal::{Shabal192, Shabal224, Shabal256, Shabal384, Shabal512};
use std::io::BufRead;
use std::ops::Add;
use std::process::exit;
use std::{fs, io};
use streebog::*;
use structopt::StructOpt;
use tiger::Tiger;
use whirlpool::Whirlpool;

const LONG_HELP_TXT: &str = r"A switch to provide the hash algorithm with which the provided string will be hashed. Supported are: argon2, blake2s, blake2b, gost94, groestl, md2, md4, md5, pbkdf2-sha256, pbkdf2-sha512, ripemd160, ripemd320, sha1, sha224, sha256, sha384, sha512, sha3-224, sha3-256, sha3-384, sha3-512, shabal192, shabal224, shabal256, shabal384, shabal512, streebog256, streebog512, tiger, whirlpool";

#[derive(StructOpt, Debug)]
#[structopt(
    name = "rustgenhash",
    about = "CLI utility to generate hashes for files and strings."
)]
enum Cmd {
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

fn hash_file<D>(file: String, mut hasher: D)
where
    D: Clone,
    D: Digest,
    D: io::Write,
    D::OutputSize: Add,
    <D::OutputSize as Add>::Output: ArrayLength<u8>,
{
    let md = std::fs::metadata(&file).unwrap();

    let mut hashdir = hasher.clone();

    if md.is_file() {
        let mut input = fs::File::open(&file).expect("Unable to open the provided file.");
        io::copy(&mut input, &mut hasher).expect("io error while reading from file.");
        println!("{:x} {}", hasher.finalize(), &file);
    }

    if md.is_dir() {
        for entry in fs::read_dir(&file).expect("Error while reading dir.") {
            let entry = entry.expect("Error while reading dir.");
            let path = entry.path();
            if path.is_file() {
                let mut input = fs::File::open(&path).expect("Unable to open the provided file.");
                io::copy(&mut input, &mut hashdir).expect("io error while reading from file.");
                println!(
                    "{:x} {}",
                    &mut hashdir.finalize_reset(),
                    path.to_str().unwrap()
                );
            }
        }
    }
}

fn hash_scrypt(password: String) {
    let salt = ScSaltString::generate(&mut OsRng);
    let password_hash = Scrypt
        .hash_password(password.as_bytes(), &salt)
        .unwrap()
        .to_string();
    println!("{} {}", password_hash, password);
}

fn hash_argon2(password: String) {
    let salt = SaltString::generate(&mut OsRng);
    let argon2 = Argon2::default();
    let password_hash = argon2
        .hash_password(password.as_bytes(), &salt)
        .unwrap()
        .to_string();
    println!("{} {}", password_hash, password);
}

fn hash_pbkdf2(password: String, pb_scheme: &str) {
    let salt = PbSaltString::generate(&mut OsRng);

    let params = pbkdf2::Params {
        output_length: 32,
        rounds: 100_000,
    };

    let password_hash = Pbkdf2::hash_password(
        &Pbkdf2,
        password.as_bytes(),
        Some(PbIdent::new(pb_scheme)),
        None,
        params,
        salt.as_salt(),
    )
    .unwrap()
    .to_string();

    println!("{} {}", password_hash, password);
}

fn hash_string<D>(password: String, mut hasher: D)
where
    D: Digest,
    D::OutputSize: Add,
    <D::OutputSize as Add>::Output: ArrayLength<u8>,
{
    hasher.update(&password.as_bytes());
    println!("{:x} {}", hasher.finalize(), &password);
}

fn main() {
    println!("Rustgenhash by Volker Schwaberow <volker@schwaberow.de>");
    println!();

    match Cmd::from_args() {
        Cmd::String {
            algorithm,
            password,
        } => match &algorithm as &str {
            "argon2" => hash_argon2(password),
            "blake2b" => hash_string(password, Blake2b::new()),
            "blake2s" => hash_string(password, Blake2s::new()),
            "gost94" => hash_string(password, Gost94Test::new()),
            "groestl" => hash_string(password, Groestl256::new()),
            "md2" => hash_string(password, Md2::new()),
            "md4" => hash_string(password, Md4::new()),
            "md5" => hash_string(password, Md5::new()),
            "pbkdf2-sha256" => hash_pbkdf2(password, "pbkdf2-sha256"),
            "pbkdf2-sha512" => hash_pbkdf2(password, "pbkdf2-sha512"),
            "ripemd160" => hash_string(password, Ripemd160::new()),
            "ripemd320" => hash_string(password, Ripemd320::new()),
            "scrypt" => hash_scrypt(password),
            "sha1" => hash_string(password, Sha1::new()),
            "sha224" => hash_string(password, Sha224::new()),
            "sha256" => hash_string(password, Sha256::new()),
            "sha384" => hash_string(password, Sha384::new()),
            "sha512" => hash_string(password, Sha512::new()),
            "sha3-224" => hash_string(password, Sha3_224::new()),
            "sha3-256" => hash_string(password, Sha3_256::new()),
            "sha3-384" => hash_string(password, Sha3_384::new()),
            "sha3-512" => hash_string(password, Sha3_512::new()),
            "shabal192" => hash_string(password, Shabal192::new()),
            "shabal224" => hash_string(password, Shabal224::new()),
            "shabal256" => hash_string(password, Shabal256::new()),
            "shabal384" => hash_string(password, Shabal384::new()),
            "shabal512" => hash_string(password, Shabal512::new()),
            "streebog256" => hash_string(password, Streebog256::new()),
            "streebog512" => hash_string(password, Streebog512::new()),
            "tiger" => hash_string(password, Tiger::new()),
            "whirlpool" => hash_string(password, Whirlpool::new()),
            _ => match_invalid(),
        },

        Cmd::File { algorithm, input } => match &algorithm as &str {
            "argon2" => match_invalid_for_mode(),
            "blake2b" => hash_file(input, Blake2b::new()),
            "blake2s" => hash_file(input, Blake2s::new()),
            "gost94" => hash_file(input, Gost94Test::new()),
            "groestl" => hash_file(input, Groestl256::new()),
            "md2" => hash_file(input, Md2::new()),
            "md4" => hash_file(input, Md4::new()),
            "md5" => hash_file(input, Md5::new()),
            "pbkdf2" => match_invalid_for_mode(),
            "pbkdf2-sha256" => match_invalid_for_mode(),
            "pbkdf2-sha512" => match_invalid_for_mode(),
            "ripemd160" => hash_file(input, Ripemd160::new()),
            "ripemd320" => hash_file(input, Ripemd320::new()),
            "scrypt" => match_invalid_for_mode(),
            "sha1" => hash_file(input, Sha1::new()),
            "sha224" => hash_file(input, Sha224::new()),
            "sha256" => hash_file(input, Sha256::new()),
            "sha384" => hash_file(input, Sha384::new()),
            "sha512" => hash_file(input, Sha512::new()),
            "sha3-224" => hash_file(input, Sha3_224::new()),
            "sha3-256" => hash_file(input, Sha3_256::new()),
            "sha3-384" => hash_file(input, Sha3_384::new()),
            "sha3-512" => hash_file(input, Sha3_512::new()),
            "shabal192" => hash_file(input, Shabal192::new()),
            "shabal224" => hash_file(input, Shabal224::new()),
            "shabal256" => hash_file(input, Shabal256::new()),
            "shabal384" => hash_file(input, Shabal384::new()),
            "shabal512" => hash_file(input, Shabal512::new()),
            "streebog256" => hash_file(input, Streebog256::new()),
            "streebog512" => hash_file(input, Streebog512::new()),
            "tiger" => match_invalid_for_mode(),
            "whirlpool" => hash_file(input, Whirlpool::new()),
            _ => match_invalid(),
        },
        Cmd::Stdio { algorithm } => {
            let stdin = io::stdin();
            for lines in stdin.lock().lines() {
                let password = lines.unwrap();
                match &algorithm as &str {
                    "argon2" => hash_argon2(password),
                    "blake2b" => hash_string(password, Blake2b::new()),
                    "blake2s" => hash_string(password, Blake2s::new()),
                    "gost94" => hash_string(password, Gost94Test::new()),
                    "groestl" => hash_string(password, Groestl256::new()),
                    "md2" => hash_string(password, Md2::new()),
                    "md4" => hash_string(password, Md4::new()),
                    "md5" => hash_string(password, Md5::new()),
                    "pbkdf2-sha256" => hash_pbkdf2(password, "pbkdf2-sha256"),
                    "pbkdf2-sha512" => hash_pbkdf2(password, "pbkdf2-sha512"),
                    "ripemd160" => hash_string(password, Ripemd160::new()),
                    "ripemd320" => hash_string(password, Ripemd320::new()),
                    "scrypt" => hash_scrypt(password),
                    "sha1" => hash_string(password, Sha1::new()),
                    "sha224" => hash_string(password, Sha224::new()),
                    "sha256" => hash_string(password, Sha256::new()),
                    "sha384" => hash_string(password, Sha384::new()),
                    "sha512" => hash_string(password, Sha512::new()),
                    "sha3-224" => hash_string(password, Sha3_224::new()),
                    "sha3-256" => hash_string(password, Sha3_256::new()),
                    "sha3-384" => hash_string(password, Sha3_384::new()),
                    "sha3-512" => hash_string(password, Sha3_512::new()),
                    "shabal192" => hash_string(password, Shabal192::new()),
                    "shabal224" => hash_string(password, Shabal224::new()),
                    "shabal256" => hash_string(password, Shabal256::new()),
                    "shabal384" => hash_string(password, Shabal384::new()),
                    "shabal512" => hash_string(password, Shabal512::new()),
                    "streebog256" => hash_string(password, Streebog256::new()),
                    "streebog512" => hash_string(password, Streebog512::new()),
                    "tiger" => hash_string(password, Tiger::new()),
                    "whirlpool" => hash_string(password, Whirlpool::new()),
                    _ => match_invalid(),
                }
            }
        }
    }
}
