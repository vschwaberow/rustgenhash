use clap::Clap;

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
use whirlpool::Whirlpool;

use crate::cmd::Opts;

mod cmd;
mod hash;




fn main() {

    let opts: Opts = cmd::Opts::parse();
    cmd::matching();

    match CmdTree::from_args() {
        CmdTree::String {
            algorithm,
            password,
        } => match &algorithm as &str {
            "blake2b" => hash::string(password, Blake2b::new()),
            "blake2s" => hash::string(password, Blake2s::new()),
            "gost94" => hash::string(password, Gost94Test::new()),
            "groestl" => hash::string(password, Groestl256::new()),
            "md2" => hash::string(password, Md2::new()),
            "md4" => hash::string(password, Md4::new()),
            "md5" => hash::string(password, Md5::new()),
            "ripemd160" => hash::string(password, Ripemd160::new()),
            "ripemd320" => hash::string(password, Ripemd320::new()),
            "sha1" => hash::string(password, Sha1::new()),
            "sha224" => hash::string(password, Sha224::new()),
            "sha256" => hash::string(password, Sha256::new()),
            "sha384" => hash::string(password, Sha384::new()),
            "sha512" => hash::string(password, Sha512::new()),
            "sha3-224" => hash::string(password, Sha3_224::new()),
            "sha3-256" => hash::string(password, Sha3_256::new()),
            "sha3-384" => hash::string(password, Sha3_384::new()),
            "sha3-512" => hash::string(password, Sha3_512::new()),
            "shabal192" => hash::string(password, Shabal192::new()),
            "shabal224" => hash::string(password, Shabal224::new()),
            "shabal256" => hash::string(password, Shabal256::new()),
            "shabal384" => hash::string(password, Shabal384::new()),
            "shabal512" => hash::string(password, Shabal512::new()),
            "streebog256" => hash::string(password, Streebog256::new()),
            "streebog512" => hash::string(password, Streebog512::new()),
            "whirlpool" => hash::string(password, Whirlpool::new()),
            _ => hash::match_invalid(),
        },

        CmdTree::File { algorithm, input } => match &algorithm as &str {
            "blake2b" => hash::file(input, Blake2b::new()),
            "blake2s" => hash::file(input, Blake2s::new()),
            "gost94" => hash::file(input, Gost94Test::new()),
            "groestl" => hash::file(input, Groestl256::new()),
            "md2" => hash::file(input, Md2::new()),
            "md4" => hash::file(input, Md4::new()),
            "md5" => hash::file(input, Md5::new()),
            "ripemd160" => hash::file(input, Ripemd160::new()),
            "ripemd320" => hash::file(input, Ripemd320::new()),
            "sha1" => hash::file(input, Sha1::new()),
            "sha224" => hash::file(input, Sha224::new()),
            "sha256" => hash::file(input, Sha256::new()),
            "sha384" => hash::file(input, Sha384::new()),
            "sha512" => hash::file(input, Sha512::new()),
            "sha3-224" => hash::file(input, Sha3_224::new()),
            "sha3-256" => hash::file(input, Sha3_256::new()),
            "sha3-384" => hash::file(input, Sha3_384::new()),
            "sha3-512" => hash::file(input, Sha3_512::new()),
            "shabal192" => hash::file(input, Shabal192::new()),
            "shabal224" => hash::file(input, Shabal224::new()),
            "shabal256" => hash::file(input, Shabal256::new()),
            "shabal384" => hash::file(input, Shabal384::new()),
            "shabal512" => hash::file(input, Shabal512::new()),
            "streebog256" => hash::file(input, Streebog256::new()),
            "streebog512" => hash::file(input, Streebog512::new()),
            "whirlpool" => hash::file(input, Whirlpool::new()),
            _ => hash::match_invalid(),
        },
        CmdTree::Stdio {algorithm} => {
            let stdin = std::io::stdin();
            for lines in stdin.lock().lines() {
                let password = lines.unwrap();
                match &algorithm as &str {
                    "blake2b" => hash::string(password, Blake2b::new()),
                    "blake2s" => hash::string(password, Blake2s::new()),
                    "gost94" => hash::string(password, Gost94Test::new()),
                    "groestl" => hash::string(password, Groestl256::new()),
                    "md2" => hash::string(password, Md2::new()),
                    "md4" => hash::string(password, Md4::new()),
                    "md5" => hash::string(password, Md5::new()),
                    "ripemd160" => hash::string(password, Ripemd160::new()),
                    "ripemd320" => hash::string(password, Ripemd320::new()),
                    "sha1" => hash::string(password, Sha1::new()),
                    "sha224" => hash::string(password, Sha224::new()),
                    "sha256" => hash::string(password, Sha256::new()),
                    "sha384" => hash::string(password, Sha384::new()),
                    "sha512" => hash::string(password, Sha512::new()),
                    "sha3-224" => hash::string(password, Sha3_224::new()),
                    "sha3-256" => hash::string(password, Sha3_256::new()),
                    "sha3-384" => hash::string(password, Sha3_384::new()),
                    "sha3-512" => hash::string(password, Sha3_512::new()),
                    "shabal192" => hash::string(password, Shabal192::new()),
                    "shabal224" => hash::string(password, Shabal224::new()),
                    "shabal256" => hash::string(password, Shabal256::new()),
                    "shabal384" => hash::string(password, Shabal384::new()),
                    "shabal512" => hash::string(password, Shabal512::new()),
                    "streebog256" => hash::string(password, Streebog256::new()),
                    "streebog512" => hash::string(password, Streebog512::new()),
                    "whirlpool" => hash::string(password, Whirlpool::new()),
                    _ => hash::match_invalid(),
                }
            }
        },
    }
}
