use clap::{Parser, Subcommand};

#[derive(Parser, Debug)]
#[clap(
    name = "rustgenhash",
    about = "CLI utility to generate hashes for files and strings."
)]
pub struct Cmd {
    #[clap(subcommand, help = "The mode to run in.")]
    pub mode: Mode,
}

#[derive(clap::ValueEnum, Debug, Clone)]
pub enum OutputOptions {
    Hex,
    Base64,
    HexBase64,
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
    #[clap(about = "Generate a hash for a file or a full directory.")]
    File {
        #[arg(value_enum, short, required = true, help = "Hashing algorithm")]
        algorithm: Algorithm,
        #[arg(name = "FILENAME", required = true, help = "File to hash")]
        input: String,
        #[arg(
            short,
            long,
            value_name = "OUTPUT",
            default_value = "hex",
            help = "Output format"
        )]
        output: Option<OutputOptions>,
    },
    #[clap(about = "Generate a hash for a string.")]
    String {
        #[arg(value_enum, short, required = true, help = "Hashing algorithm")]
        algorithm: Algorithm,
        #[arg(name = "PASSWORD", required = true, help = "Password to hash")]
        password: String,
        #[arg(
            short,
            long,
            value_name = "OUTPUT",
            default_value = "hex",
            help = "Output format"
        )]
        output: Option<OutputOptions>,
    },
    #[clap(about = "Generate a hash for input from the stdio.")]
    Stdio {
        #[arg(value_enum, short, required = true, help = "Hashing algorithm")]
        algorithm: Algorithm,
        #[arg(
            short,
            long,
            value_name = "OUTPUT",
            default_value = "hex",
            help = "Output format"
        )]
        output: Option<OutputOptions>,
    },
    #[clap(about = "Generate shell completions.")]
    GenerateCompletions {
        #[arg(
            value_enum,
            required = true,
            help = "Shell to generate completions for"
        )]
        shell: Shell,
    },
}
