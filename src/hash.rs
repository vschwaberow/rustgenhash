use std::{fs, io};
use std::io::BufRead;
use std::ops::Add;
use std::process::exit;

use blake2::crypto_mac::generic_array::ArrayLength;
use blake2::Digest;

pub fn match_invalid() {
    println!("You need to select a valid algorithm.");
    exit(1);
}

pub fn hash_string<D>(password: String, mut hasher: D)
where
    D: Digest,
    D::OutputSize: Add,
    <D::OutputSize as Add>::Output: ArrayLength<u8>,
{
    hasher.update(&password.as_bytes());
    println!("{:x} {}", hasher.finalize(), &password);
}

pub fn hash_file<D>(file: String, mut hasher: D)
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
        std::io::copy(&mut input, &mut hasher).expect("io error while reading from file.");
        println!("{:x} {}", hasher.finalize(), &file);
    }

    if md.is_dir() {
        for entry in fs::read_dir(&file).expect("Error while reading dir.") {
            let entry = entry.expect("Error while reading dir.");
            let path = entry.path();
            if path.is_file() {
                let mut input = fs::File::open(&path).expect("Unable to open the provided file.");
                std::io::copy(&mut input, &mut hashdir).expect("io error while reading from file.");
                println!(
                    "{:x} {}",
                    &mut hashdir.finalize_reset(),
                    path.to_str().unwrap()
                );
            }
        }
    }
}
