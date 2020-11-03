use blake2::{Blake2b, Blake2s};
use digest::Digest;
use digest::generic_array::ArrayLength;
use gost94::*;
use groestl::*;
use md2::Md2;
use md4::Md4;
use md5::Md5;
use sha1::Sha1;
use sha2::{Sha224, Sha256, Sha384, Sha512};
use sha3::{Sha3_224, Sha3_256, Sha3_384, Sha3_512};
use shabal::{Shabal192, Shabal224, Shabal256, Shabal384, Shabal512};
use std::{fs, io};
use std::ops::Add;
use std::process::exit;
use streebog::*;
use structopt::StructOpt;
use ripemd160::Ripemd160;
use ripemd320::*;
use whirlpool::Whirlpool;

#[derive(StructOpt, Debug)]
#[structopt(name = "rustgenhash", about = "CLI utility to generate hashes for files and strings.")]
enum Cmd {
    File {
        #[structopt(short, required=true)]
        algorithm: String,
        #[structopt(name="FILENAME", required=true)]
        input: String,

    },
    String {
        #[structopt(short, required=true)]
        algorithm: String,
        #[structopt(name="PASSWORD", required=true)]
        password: String,

    },
}

fn match_invalid() {
    println!("You need to select a valid algorithm.");
    exit(1);
}

fn hash_file<D>(file: String, mut hasher:D) where D: Clone, D: Digest, D: io::Write, D::OutputSize: Add,
                                                  <D::OutputSize as Add>::Output: ArrayLength<u8> {
    
    let md = std::fs::metadata(&file).unwrap();

    let mut hashdir = hasher.clone();

    if md.is_file() {
        let mut input = fs::File::open(&file)
            .expect("Unable to open the provided file.");
        io::copy(&mut input, &mut hasher)
            .expect("io error while reading from file.");
        println!("{:x} {}", hasher.finalize(), &file);
    }

    if md.is_dir() {

        for entry in fs::read_dir(&file).expect("Error while reading dir.") {
            let entry = entry.expect("Error while reading dir.");
            let path = entry.path();
            if path.is_file() {
                let mut input = fs::File::open(&path)
                    .expect("Unable to open the provided file.");
                io::copy(&mut input, &mut hashdir)
                    .expect("io error while reading from file.");
                println!("{:x} {}", &mut hashdir.finalize_reset(), path.to_str().unwrap());
            }

        }

    }

}


fn hash_string<D>(password: String, mut hasher:D) where D: Digest, D::OutputSize: Add,
                                                                      <D::OutputSize as Add>::Output: ArrayLength<u8>
{
    hasher.update(&password.as_bytes());
    println!("{:x} {}", hasher.finalize(), &password);
}

fn main() {
      println!("Rustgenhash by Volker Schwaberow <volker@schwaberow.de>");
      println!();

    match Cmd::from_args() {

        Cmd::String { algorithm, password } => {
            match &algorithm as &str {
                "blake2b" => hash_string(password, Blake2b::new()),
                "blake2s" => hash_string(password, Blake2s::new()),
                "gost94" => hash_string(password, Gost94Test::new()),
                "groestl" => hash_string(password, Groestl256::new()),
                "md2" => hash_string(password, Md2::new()),
                "md4" => hash_string(password, Md4::new()),
                "md5" => hash_string(password, Md5::new()),
                "ripemd160" => hash_string(password, Ripemd160::new()),
                "ripemd320" => hash_string(password, Ripemd320::new()),
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
                "whirlpool" => hash_string(password, Whirlpool::new()),
                _ => match_invalid(),
            }
        }

        Cmd::File { algorithm, input } => {
            match &algorithm as &str {
                "blake2b" => hash_file(input, Blake2b::new()),
                "blake2s" => hash_file(input, Blake2s::new()),
                "gost94" => hash_file(input, Gost94Test::new()),
                "groestl" => hash_file(input, Groestl256::new()),
                "md2" => hash_file(input, Md2::new()),
                "md4" => hash_file(input, Md4::new()),
                "md5" => hash_file(input, Md5::new()),
                "ripemd160" => hash_file(input, Ripemd160::new()),
                "ripemd320" => hash_file(input, Ripemd320::new()),
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
                "whirlpool" => hash_file(input, Whirlpool::new()),
                _ => match_invalid(),
            }

        }

    }
}