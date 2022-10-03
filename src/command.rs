use crate::cli::{Algorithm, Cmd, Mode, OutputOptions};
use crate::hash::{PHash, RHash};
use clap::{crate_authors, crate_name, crate_version};
use clap::{CommandFactory, Parser};
use std::io::{self, BufRead};

fn hash_string(algor: Option<Algorithm>, password: &str, option: Option<OutputOptions>) {
    use crate::cli::Algorithm as alg;
    algor.map(|a| match a {
        alg::Argon2 => {
            PHash::hash_argon2(password);
        }
        alg::Balloon => {
            PHash::hash_balloon(password);
        }
        alg::Pbkdf2Sha256 | alg::Pbkdf2Sha512 => {
            PHash::hash_pbkdf2(password, format!("{:?}", a).to_lowercase().as_str());
        }
        alg::Scrypt => {
            PHash::hash_scrypt(password);
        }
        _ => {
            let alg_s = format!("{:?}", a).to_uppercase();
            let b = RHash::new(&alg_s).process_string(password.as_bytes());
            match option {
                Some(OutputOptions::Hex) => println!("{} {}", hex::encode(b), password),
                Some(OutputOptions::Base64) => println!("{} {}", base64::encode(b), password),
                Some(OutputOptions::HexBase64) => {
                    println!("{} {} {}", hex::encode(&b), base64::encode(&b), password);
                }
                _ => println!("{} {}", hex::encode(b), password),
            }
        }
    });
}

fn hash_file(alg: Option<Algorithm>, input: &str, option: Option<OutputOptions>) {
    use crate::cli::Algorithm as algo;
    alg.map(|a| match a {
        algo::Argon2 => {
            todo!("Argon2");
        }
        algo::Balloon => {
            todo!("Balloon hashing is not yet implemented.");
        }
        algo::Pbkdf2Sha256 | algo::Pbkdf2Sha512 => {
            todo!("Pbkdf2");
        }
        algo::Scrypt => {
            todo!("Scrypt");
        }
        _ => {
            let alg_s = format!("{:?}", a).to_uppercase();
            RHash::new(&alg_s).process_file(input, option);
        }
    });
}

pub fn matching() {
    let cmd = Cmd::parse();
    match cmd.mode {
        Mode::GenerateCompletions { shell } => {
            let shell: clap_complete::Shell = shell.into();
            clap_complete::generate(shell, &mut Cmd::command(), crate_name!(), &mut io::stdout());
        }
        Mode::String {
            algorithm,
            password,
            output,
        } => hash_string(Some(algorithm), &password, output),
        Mode::Stdio { algorithm, output } => {
            let stdin = std::io::stdin();
            let output2 = output.unwrap();
            for lines in stdin.lock().lines() {
                let password = lines.unwrap();

                hash_string(
                    Some(algorithm.clone()),
                    &password,
                    Option::from(output2.clone()),
                );
            }
        }
        Mode::File {
            algorithm,
            input,
            output,
        } => {
            hash_file(Some(algorithm), &input, output);
        }
    }
}

pub fn about() {
    eprintln!(
        "{} v{} by {}",
        crate_name!(),
        crate_version!(),
        crate_authors!()
    );
    eprintln!();
}

#[test]
fn test_function_hash_string() {
    use crate::cli::Algorithm as alg;
    use crate::cli::OutputOptions as opt;
    hash_string(Some(alg::Md5), "password", Some(opt::Hex));
    hash_string(Some(alg::Sha1), "password", Some(opt::Hex));
    hash_string(Some(alg::Sha256), "password", Some(opt::Hex));
    hash_string(Some(alg::Sha512), "password", Some(opt::Hex));
    hash_string(Some(alg::Md5), "password", Some(opt::Base64));
    hash_string(Some(alg::Sha1), "password", Some(opt::Base64));
    hash_string(Some(alg::Sha256), "password", Some(opt::Base64));
    hash_string(Some(alg::Sha512), "password", Some(opt::Base64));
}
#[test]
fn test_function_hash_file() {
    use crate::cli::Algorithm as alg;
    use crate::cli::OutputOptions as opt;
    hash_file(Some(alg::Md5), "Cargo.toml", Some(opt::Hex));
    hash_file(Some(alg::Sha1), "Cargo.toml", Some(opt::Hex));
    hash_file(Some(alg::Sha256), "Cargo.toml", Some(opt::Hex));
    hash_file(Some(alg::Sha512), "Cargo.toml", Some(opt::Hex));
    hash_file(Some(alg::Md5), "Cargo.toml", Some(opt::Base64));
    hash_file(Some(alg::Sha1), "Cargo.toml", Some(opt::Base64));
    hash_file(Some(alg::Sha256), "Cargo.toml", Some(opt::Base64));
    hash_file(Some(alg::Sha512), "Cargo.toml", Some(opt::Base64));
}
