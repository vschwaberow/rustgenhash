use structopt::StructOpt;
use crypto::digest::Digest;
use crypto::sha1::Sha1;
use crypto::sha2::{Sha224, Sha256, Sha384, Sha512};
use crypto::sha3::Sha3;
use std::process::exit;
use crypto::md5::Md5;


#[derive(Debug, StructOpt)]
struct GenCmd {
    #[structopt(
    short,
    required = true,
    long_help = r"A switch to provide the hash algorithm with which the provided string will be hashed. Supported are: md5, sha1, sha224, sha256, sha384, sha512, sha3-224, sha3-256, sha3-384, sha3-512"
    )]
    algorithm: String,
    #[structopt(name="PASSWORD", required = false, long_help = r"Placeholder for password to be hashed. Not required in stdio mode")]
    password: String,

}

fn match_valid() {
    println!("You need to select a valid algorithm.");
    exit(0);
}

fn create_md5(password: String) {

    let mut hasher = Md5::new();
    hasher.input_str(&password);
    let result = hasher.result_str();
    print_hash("sha1", result);

}

fn create_sha1(password: String) {

    let mut hasher = Sha1::new();
    hasher.input_str(&password);
    let result = hasher.result_str();
    print_hash("sha1", result);

}

fn create_sha224(password: String) {

    let mut hasher = Sha224::new();
    hasher.input_str(&password);
    let result = hasher.result_str();
    print_hash("sha224", result);

}
fn create_sha256(password: String) {

    let mut hasher = Sha256::new();
    hasher.input_str(&password);
    let result = hasher.result_str();
    print_hash("sha256", result);

}

fn create_sha384(password: String) {

    let mut hasher = Sha384::new();
    hasher.input_str(&password);
    let result = hasher.result_str();
    print_hash("sha384", result);

}

fn create_sha512(password: String) {

    let mut hasher = Sha512::new();
    hasher.input_str(&password);
    let result = hasher.result_str();
    print_hash("sha512", result);

}
fn create_sha3_224(password: String) {

    let mut hasher = Sha3::sha3_224();
    hasher.input_str(&password);
    let result = hasher.result_str();
    print_hash("sha3-224", result);

}
fn create_sha3_256(password: String) {

    let mut hasher = Sha3::sha3_256();
    hasher.input_str(&password);
    let result = hasher.result_str();
    print_hash("sha3-256", result);

}
fn create_sha3_384(password: String) {

    let mut hasher = Sha3::sha3_384();
    hasher.input_str(&password);
    let result = hasher.result_str();
    print_hash("sha3-384", result);

}
fn create_sha3_512(password: String) {

    let mut hasher = Sha3::sha3_512();
    hasher.input_str(&password);
    let result = hasher.result_str();
    print_hash("sha3-512", result);

}


fn print_hash(algo:&str, password: String) {
    println!("{} hash: {}", algo, password);
}

fn main() {
    println!("Rustgenhash by Volker Schwaberow <volker@schwaberow.de>");

    let args = GenCmd::from_args();

        println!("password is: {}", args.password);

        match &args.algorithm as &str {
            "md5" => create_md5(args.password),
            "sha1" => create_sha1(args.password),
            "sha224" => create_sha224(args.password),
            "sha256" => create_sha256(args.password),
            "sha384" => create_sha384(args.password),
            "sha512" => create_sha512(args.password),
            "sha3-224" => create_sha3_224(args.password),
            "sha3-256" => create_sha3_256(args.password),
            "sha3-384" => create_sha3_384(args.password),
            "sha3-512" => create_sha3_512(args.password),
            _ => match_valid(),
        }

}
