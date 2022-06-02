use argon2::{
    password_hash::{rand_core::OsRng, PasswordHasher, SaltString},
    Argon2,
};
use balloon_hash::{
    password_hash::{rand_core::OsRng as BalOsRng, SaltString as BalSaltString},
    Balloon,
};
use digest::generic_array::ArrayLength;
use digest::Digest;
use pbkdf2::{
    password_hash::{Ident as PbIdent, SaltString as PbSaltString},
    Pbkdf2,
};
use scrypt::{password_hash::SaltString as ScSaltString, Scrypt};
use std::ops::Add;
use std::{fs, io};

pub fn hash_file<D>(file: String, mut hasher: D)
where
    D: Clone,
    D: Digest,
    D: io::Write,
    D::OutputSize: Add,
    <D::OutputSize as Add>::Output: ArrayLength<u8>,
    D: digest::FixedOutputReset,
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

pub fn hash_scrypt(password: &str) {
    let salt = ScSaltString::generate(&mut OsRng);
    let password_hash = Scrypt
        .hash_password(password.as_bytes(), &salt)
        .unwrap()
        .to_string();
    println!("{} {}", password_hash, password);
}

pub fn hash_argon2(password: &str) {
    let salt = SaltString::generate(&mut OsRng);
    let argon2 = Argon2::default();
    let password_hash = argon2
        .hash_password(password.as_bytes(), &salt)
        .unwrap()
        .to_string();
    println!("{} {}", password_hash, password);
}

pub fn hash_balloon(password: &str) {
    // TODO: Make Balloon hash configurable
    let salt = BalSaltString::generate(&mut BalOsRng);
    let balloon = Balloon::<sha2::Sha256>::default();
    let password_hash = balloon
        .hash_password(password.as_bytes(), &salt)
        .unwrap()
        .to_string();
    println!("{} {}", password_hash, password);
}

pub fn hash_pbkdf2(password: &str, pb_scheme: &str) {
    let algorithm = PbIdent::new(pb_scheme).unwrap();

    let salt = PbSaltString::generate(&mut OsRng);

    let params = pbkdf2::Params {
        output_length: 32,
        rounds: 100_000,
    };

    let password_hash = Pbkdf2::hash_password_customized(
        &Pbkdf2,
        password.as_bytes(),
        Some(algorithm),
        None,
        params,
        salt.as_salt(),
    )
    .unwrap()
    .to_string();

    println!("{} {}", password_hash, password);
}

pub fn hash_string<D>(password: &str, mut hasher: D)
where
    D: Digest,
    D::OutputSize: Add,
    <D::OutputSize as Add>::Output: ArrayLength<u8>,
{
    hasher.update(&password.as_bytes());
    println!("{:x} {}", hasher.finalize(), &password);
}
