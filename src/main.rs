use structopt::StructOpt;
use std::process::exit;
use blake2::{Blake2b, Blake2s};
use digest::Digest;
use digest::generic_array::ArrayLength;
use md2::Md2;
use md4::Md4;
use md5::Md5;
use sha1::Sha1;
use sha2::{Sha224, Sha256, Sha384, Sha512};
use sha3::{Sha3_224, Sha3_256, Sha3_384, Sha3_512};
use std::ops::Add;
use ripemd160::Ripemd160;
use whirlpool::Whirlpool;

#[derive(Debug, StructOpt)]
struct GenCmd {
    #[structopt(
    short,
    required = true,
    long_help = r"A switch to provide the hash algorithm with which the provided string will be
    hashed. Supported are: md5, sha1, sha224, sha256, sha384, sha512, sha3-224, sha3-256, sha3-384,
    sha3-512, whirlpool, ripemd160, blake2s, blake2b"
    )]
    algorithm: String,
    #[structopt(name="PASSWORD", required = true, long_help = r"Placeholder for password to be hashed. Not required in stdio mode")]
    password: String,

}

fn match_invalid() {
    println!("You need to select a valid algorithm.");
    exit(1);
}

fn create_hash<D>(password: String, mut hasher:D, algo: String) where D: Digest, D::OutputSize: Add,
                                                                      <D::OutputSize as Add>::Output: ArrayLength<u8>
{
    hasher.update(&password.as_bytes());
    println!("{} hash is: {:x}", algo, hasher.finalize());
}

fn main() {
    println!("Rustgenhash by Volker Schwaberow <volker@schwaberow.de>");

    let args = GenCmd::from_args();

        println!("password is: {}", args.password);

        match &args.algorithm as &str {
            "blake2b" => create_hash(args.password, Blake2b::new(), "blake2b".to_string()),
            "blake2s" => create_hash(args.password, Blake2s::new(), "blake2s".to_string()),
<<<<<<< HEAD
            "md2" => create_hash(args.password, Md2::new(), "md2".to_string()),
=======
            "md4" => create_hash(args.password, Md4::new(), "md4".to_string()),
>>>>>>> feature/CR0007_md4_support
            "md5" => create_hash(args.password, Md5::new(), "md5".to_string()),
            "sha1" => create_hash(args.password, Sha1::new(), "sha1".to_string()),
            "sha224" => create_hash(args.password, Sha224::new(), "sha224".to_string()),
            "sha256" => create_hash(args.password, Sha256::new(), "sha256".to_string()),
            "sha384" => create_hash(args.password, Sha384::new(), "sha384".to_string()),
            "sha512" => create_hash(args.password, Sha512::new(), "sha512".to_string()),
            "sha3-224" => create_hash(args.password, Sha3_224::new(), "sha3-224".to_string()),
            "sha3-256" => create_hash(args.password, Sha3_256::new(), "sha3-256".to_string()),
            "sha3-384" => create_hash(args.password, Sha3_384::new(), "sha3-384".to_string()),
            "sha3-512" => create_hash(args.password, Sha3_512::new(), "sha3-512".to_string()),
            "whirlpool" => create_hash(args.password, Whirlpool::new(), "whirlpool".to_string()),
            "ripemd160" => create_hash(args.password, Ripemd160::new(), "ripemd160".to_string()),
            _ => match_invalid(),
        }

}
