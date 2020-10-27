# rustgenhash

rustgenhash is a tool to generate hashes on the commandline from stdio.

It can be used to generate single or multiple hashes for usage in password databases or even in penetration testing scenarios where you want to test password cracking tools.

## Install

rustgenhash is written in Rust. You can install the tool with your Rust installation using following command:

```bash
cargo install rustgenhash
```

## Usage

You can provide a text string as argument to be hashed by one of the program supported hash algorithms.

```bash
rustgenhash -a <HASH_ALGORITHM> <String>
```

You can list all algorithms over the help function.

Supported are:

* MD5 hash
* SHA-1 hash
* SHA2-224 hash
* SHA2-256 hash
* SHA2-384 hash
* SHA2-512 hash
* SHA3-224 hash
* SHA3-384 hash
* SHA3-256 hash
* SHA3-512 hash
* Whirlpool
* RipeMD160
