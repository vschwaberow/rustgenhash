use blake2::{Blake2b, Blake2s};
use gost94::Gost94Test;
use hex_literal::hex;
use sha1::{Sha1, Digest};
use groestl::Groestl256;
use md2::Md2;
use md4::Md4;
use md5::Md5;
use ripemd160::Ripemd160;
use ripemd320::Ripemd320;

const PHRASE:&str = "Jeder wackere Bayer vertilgt bequem zwo Pfund Kalbshaxen.";

#[test]
fn lib_blake2b_hash() {
    let mut hasher = Blake2b::new();
    hasher.update(PHRASE.as_bytes());
    let result = hasher.finalize();
    assert_eq!(result[..], hex!("95b7ecb0d7de59820205a0a94fe3ca5ee36fd296b1a9ecaa4e01634aed9fa9505d70182c12f900b9dd95f1d5c04fe57dbc5b1e48acdf3a8bae2996f5d8f4578a"));
}

#[test]
fn lib_blake2s_hash() {
    let mut hasher = Blake2s::new();
    hasher.update(PHRASE.as_bytes());
    let result = hasher.finalize();
    assert_eq!(result[..], hex!("dbfd3f2c835adcc9fc955d812384bb3bf569de0b9613ffca0e723254c05cf497"));
}

#[test]
fn lib_gost94_hash() {
    let mut hasher = Gost94Test::new();
    hasher.update(PHRASE.as_bytes());
    let result = hasher.finalize();
    assert_eq!(result[..], hex!("1845acc06577ead1f5b671e7e452fc6064e90ab1bbb536df36a91327e40e1872"));
}

#[test]
fn lib_groestl_hash() {
    let mut hasher = Groestl256::new();
    hasher.update(PHRASE.as_bytes());
    let result = hasher.finalize();
    assert_eq!(result[..], hex!("f65cae36b7a0cb51e8ee732f4090ffacaa8f910a793596046073b8457bc4a356"));
}

#[test]
fn lib_md2_hash() {
    let mut hasher = Md2::new();
    hasher.update(PHRASE.as_bytes());
    let result = hasher.finalize();
    assert_eq!(result[..], hex!("5e5377610e6b41e7103e7fab19facc07"));
}

#[test]
fn lib_md4_hash() {
    let mut hasher = Md4::new();
    hasher.update(PHRASE.as_bytes());
    let result = hasher.finalize();
    assert_eq!(result[..], hex!("18744ab6124baa392ee1cc9b1552a403"));
}

#[test]
fn lib_md5_hash() {
    let mut hasher = Md5::new();
    hasher.update(PHRASE.as_bytes());
    let result = hasher.finalize();
    assert_eq!(result[..], hex!("ad05bcfc97af63bf7ebf568220b19d7e"));
}

#[test]
fn lib_ripemd160_hash() {
    let mut hasher = Ripemd160::new();
    hasher.update(PHRASE.as_bytes());
    let result = hasher.finalize();
    assert_eq!(result[..], hex!("85b000debad329e4738bfefb0e480d2cb32a0869"));
}

#[test]
fn lib_ripemd320_hash() {
    let mut hasher = Ripemd320::new();
    hasher.update(PHRASE.as_bytes());
    let result = hasher.finalize();
    assert_eq!(result[..], hex!("e34757b3c51470ec4a47a06a39ffbe85587f41f9711facc25bdcf5d74ebf44e59743ca07bd70ab5e"));
}

#[test]
fn lib_sha1_hash() {
    let mut hasher = Sha1::new();
    hasher.update(PHRASE.as_bytes());
    let result = hasher.finalize();
    assert_eq!(result[..], hex!("1C90817FE5067AB226A331D4E7454858F6DD966A"));
}