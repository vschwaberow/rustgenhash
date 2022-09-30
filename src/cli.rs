use clap::{Parser, Subcommand};

#[derive(Parser, Debug)]
#[clap(
    name = "rustgenhash",
    about = "CLI utility to generate hashes for files and strings."
)]
pub struct Cmd {
    #[clap(subcommand)]
    pub mode: Mode,
}

#[derive(clap::ValueEnum, Debug, Clone)]
pub enum Algorithm {
    Argon2,
    Balloon,
    Blake2b,
    Blake2s,
    Gost94,
    Gost94ua,
    Groestl,
    Md2,
    Md4,
    Md5,
    Pbkdf2Sha256,
    Pbkdf2Sha512,
    Ripemd160,
    Ripemd320,
    Scrypt,
    Sha1,
    Sha224,
    Sha256,
    Sha384,
    Sha512,
    Sha3_224,
    Sha3_256,
    Sha3_384,
    Sha3_512,
    Shabal192,
    Shabal224,
    Shabal256,
    Shabal384,
    Shabal512,
    Sm3,
    Streebog256,
    Streebog512,
    Tiger,
    Whirlpool,
}

#[derive(clap::ValueEnum, Debug, Clone)]
pub enum Shell {
    Bash,
    Elvish,
    Fish,
    PowerShell,
    Zsh,
}

impl From<Shell> for clap_complete::Shell {
    fn from(shell: Shell) -> Self {
        use Shell::*;
        match shell {
            Bash => Self::Bash,
            Elvish => Self::Elvish,
            Fish => Self::Fish,
            PowerShell => Self::PowerShell,
            Zsh => Self::Zsh,
        }
    }
}

#[derive(Debug, Subcommand, Clone)]
pub enum Mode {
    File {
        #[arg(value_enum, short, required = true)]
        algorithm: Algorithm,
        #[arg(name = "FILENAME", required = true)]
        input: String,
    },
    String {
        #[arg(short, required = true)]
        algorithm: Algorithm,
        #[arg(name = "PASSWORD", required = true)]
        password: String,
    },
    Stdio {
        #[arg(short, required = true)]
        algorithm: Algorithm,
    },
    GenerateCompletions {
        #[arg(value_enum, required = true)]
        shell: Shell,
    },
}