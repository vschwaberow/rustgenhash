# rustgenhash

rustgenhash is a tool to generate hashes on the commandline from stdio.

It can be used to generate single or multiple hashes for usage in password databases or even in penetration testing scenarios where you want to test password cracking tools. It can also help to identify the nature of a provided hash.

## Install

rustgenhash is written in Rust. You can install the tool with your Rust installation using following command:

```bash
cargo install rustgenhash
```

## Usage

Rustgenhash has a command line interface which allows you to set the utility into a specific operating mode. The current
modes are

- analyze
- random
- stdio
- string
- file

After selecting the mode you will need to provide the -a switch for selecting a suitable hashing algorithm and a string
or file to be hashed. The stdio mode allows you to pipe to the `rustgenhash` command. The tool will hash the passed
lines from the stdio (useful for hashing password lists).

The file mode supports hashing of multiple files in a directory and currently works non-recursive.

Scheme for string hashing:

```bash
rustgenhash string -a <algorithm> <string>
```

Scheme for file hashing:

```bash
rustgenhash file -a <algorithm> <filename or directory>
```

Scheme for string hashing from stdio:

```bash
cat myfile | rustgenhash stdio -a <algorithm>
```

```bash
echo "mypassword" | rustgenhash stdio -a <algorithm>
```

You can list all supported algorithms over the help function.
## Contribution 

If you want to contribute to this project, please feel free to do so. I am happy to accept pull requests. Any help is appreciated. If you have any questions, please feel free to contact me.
