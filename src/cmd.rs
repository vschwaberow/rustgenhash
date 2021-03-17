
use structopt::StructOpt;

const ALGO_LONG_HELP: &str = r"A switch to provide the hash algorithm with which the provided
string will be hashed. Supported are: blake2s, blake2b, gost94,
groestl, md2, md4, md5, ripemd160, ripemd320, sha1, sha224, sha256,
sha384, sha512, sha3-224, sha3-256, sha3-384, sha3-512, shabal192,
shabal224, shabal256, shabal384, shabal512, streebog256,
streebog512, whirlpool";

#[derive(StructOpt, Debug)]
#[structopt(
    name = "rustgenhash",
    about = "CLI utility to generate hashes for files and strings."
)]
pub enum CmdTree {
    File {
        #[structopt(
            short,
            required = true,
            long_help = ALGO_LONG_HELP,
        )]
        algorithm: String,
        #[structopt(name = "FILENAME", required = true)]
        input: String,
    },
    String {
        #[structopt(
            short,
            required = true,
            long_help = ALGO_LONG_HELP,
        )]
        algorithm: String,
        #[structopt(name = "PASSWORD", required = true)]
        password: String,
    },
    Stdio {
        #[structopt(
        short,
        required = true,
        long_help = ALGO_LONG_HELP,
        )]
        algorithm: String,
    },
}
