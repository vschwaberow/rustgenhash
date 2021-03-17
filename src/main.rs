
use std::io::BufRead;
use std::ops::Add;
use std::process::exit;

use blake2::{Blake2b, Blake2s};
use digest::Digest;
use digest::generic_array::ArrayLength;
use gost94::*;
use groestl::*;
use md2::Md2;
use md4::Md4;
use md5::Md5;
use ripemd160::Ripemd160;
use ripemd320::*;
use sha1::Sha1;
use sha2::{Sha224, Sha256, Sha384, Sha512};
use sha3::{Sha3_224, Sha3_256, Sha3_384, Sha3_512};
use shabal::{Shabal192, Shabal224, Shabal256, Shabal384, Shabal512};
use streebog::*;
use structopt::StructOpt;
use whirlpool::Whirlpool;

use crate::cmd::Cmd;

mod cmd;
mod hash;

fn main() {
    println!("Rustgenhash by Volker Schwaberow <volker@schwaberow.de>");
    println!();

    match Cmd::from_args() {
        Cmd::String {
            algorithm,
            password,
        } => match &algorithm as &str {
            "blake2b" => hash::hash_string(password, Blake2b::new()),
            "blake2s" => hash::hash_string(password, Blake2s::new()),
            "gost94" => hash::hash_string(password, Gost94Test::new()),
            "groestl" => hash::hash_string(password, Groestl256::new()),
            "md2" => hash::hash_string(password, Md2::new()),
            "md4" => hash::hash_string(password, Md4::new()),
            "md5" => hash::hash_string(password, Md5::new()),
            "ripemd160" => hash::hash_string(password, Ripemd160::new()),
            "ripemd320" => hash::hash_string(password, Ripemd320::new()),
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
            "whirlpool" => hash::hash_string(password, Whirlpool::new()),
            _ => hash::match_invalid(),
        },

        Cmd::File { algorithm, input } => match &algorithm as &str {
            "blake2b" => hash::hash_file(input, Blake2b::new()),
            "blake2s" => hash::hash_file(input, Blake2s::new()),
            "gost94" => hash::hash_file(input, Gost94Test::new()),
            "groestl" => hash::hash_file(input, Groestl256::new()),
            "md2" => hash::hash_file(input, Md2::new()),
            "md4" => hash::hash_file(input, Md4::new()),
            "md5" => hash::hash_file(input, Md5::new()),
            "ripemd160" => hash::hash_file(input, Ripemd160::new()),
            "ripemd320" => hash::hash_file(input, Ripemd320::new()),
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
            "whirlpool" => hash::hash_file(input, Whirlpool::new()),
            _ => hash::match_invalid(),
        },
        Cmd::Stdio {algorithm} => {
            let stdin = std::io::stdin();
            for lines in stdin.lock().lines() {
                let password = lines.unwrap();
                match &algorithm as &str {
                    "blake2b" => hash::hash_string(password, Blake2b::new()),
                    "blake2s" => hash::hash_string(password, Blake2s::new()),
                    "gost94" => hash::hash_string(password, Gost94Test::new()),
                    "groestl" => hash::hash_string(password, Groestl256::new()),
                    "md2" => hash::hash_string(password, Md2::new()),
                    "md4" => hash::hash_string(password, Md4::new()),
                    "md5" => hash::hash_string(password, Md5::new()),
                    "ripemd160" => hash::hash_string(password, Ripemd160::new()),
                    "ripemd320" => hash::hash_string(password, Ripemd320::new()),
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
                    "whirlpool" => hash::hash_string(password, Whirlpool::new()),
                    _ => hash::match_invalid(),
                }
            }
        },
    }
}
