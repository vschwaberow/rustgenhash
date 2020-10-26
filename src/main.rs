use structopt::StructOpt;
use crypto::digest::Digest;
use crypto::sha1::Sha1;
use crypto::sha2::{Sha224, Sha256, Sha384, Sha512};
use crypto::sha3::Sha3;
use crypto::whirlpool::Whirlpool;
use std::process::exit;
use crypto::md5::Md5;
use crypto::ripemd160::Ripemd160;


#[derive(Debug, StructOpt)]
struct GenCmd {
    #[structopt(
    short,
    required = true,
    long_help = r"A switch to provide the hash algorithm with which the provided string will be hashed. Supported are:
    md5, sha1, sha224, sha256, sha384, sha512, sha3-224, sha3-256, sha3-384, sha3-512, whirlpool,
    ripemd160"
    )]
    algorithm: String,
    #[structopt(name="PASSWORD", required = false, long_help = r"Placeholder for password to be hashed. Not required in stdio mode")]
    password: String,

}

fn match_invalid() {
    println!("You need to select a valid algorithm.");
    exit(1);
}

fn create_hash<T:Digest>(password: String, mut hasher:T, algo: String) {
    hasher.input_str(&password);
    print_hash(&algo, hasher.result_str());
}

fn print_hash(algo:&str, password: String) {
    println!("{} hash: {}", algo, password);
}

fn main() {
    println!("Rustgenhash by Volker Schwaberow <volker@schwaberow.de>");

    let args = GenCmd::from_args();

        println!("password is: {}", args.password);

        match &args.algorithm as &str {
            "md5" => create_hash(args.password, Md5::new(), "md5".to_string()),
            "sha1" => create_hash(args.password, Sha1::new(), "sha1".to_string()),
            "sha224" => create_hash(args.password, Sha224::new(), "sha224".to_string()),
            "sha256" => create_hash(args.password, Sha256::new(), "sha256".to_string()),
            "sha384" => create_hash(args.password, Sha384::new(), "sha384".to_string()),
            "sha512" => create_hash(args.password, Sha512::new(), "sha512".to_string()),
            "sha3-224" => create_hash(args.password, Sha3::sha3_224(), "sha3-224".to_string()),
            "sha3-256" => create_hash(args.password, Sha3::sha3_256(), "sha3-256".to_string()),
            "sha3-384" => create_hash(args.password, Sha3::sha3_384(), "sha3-384".to_string()),
            "sha3-512" => create_hash(args.password, Sha3::sha3_512(), "sha3-512".to_string()),
            "whirlpool" => create_hash(args.password, Whirlpool::new(), "whirlpool".to_string()),
            "ripemd160" => create_hash(args.password, Ripemd160::new(), "ripemd160".to_string()),
            _ => match_invalid(),
        }

}
