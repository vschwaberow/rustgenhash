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
- benchmark
- compare-hash
- random
- stdio
- string
- file
- header
- interactive

After selecting the mode you will need to provide the -a switch for selecting a suitable hashing algorithm and a string
or file to be hashed. The stdio mode allows you to pipe to the `rgh` command. The tool will hash the passed
lines from the stdio (useful for hashing password lists).

The file mode supports hashing of multiple files in a directory and currently works non-recursive.

Scheme for string hashing:

```bash
rgh string -a <algorithm> <string>

# Suppress plaintext echoes for scripting workflows
rgh string -a <algorithm> --hash-only <string>
```

Scheme for file hashing:

```bash
rgh file -a <algorithm> <filename or directory>

# Emit only digests when listing directory contents
rgh file -a <algorithm> --hash-only <filename or directory>
```

Scheme for string hashing from stdio:

```bash
cat myfile | rgh stdio -a <algorithm>

# Hash-only mode preserves one output token per input line
cat myfile | rgh stdio -a <algorithm> --hash-only
```

```bash
echo "mypassword" | rgh stdio -a <algorithm>
```

Scheme for analyzing a hash:

```bash
rgh analyze -a <algorithm> <hash>
```

Scheme for generating a [HHHash](https://www.foo.be/2023/07/HTTP-Headers-Hashing_HHHash) of a provided url:

```bash
rgh header www.google.de
```

Scheme for comparing a hash:

```bash
rgh compare-string <hash1> <hash2>
```

Scheme for comparing hash files with each other:

```bash
rgh compare-file <file1> <file2>
```

Scheme for benchmarking a hash algorithm:

```bash
rgh benchmark -a <algorithm> -i <iterations>
```

You can list all supported algorithms over the help function.

Lastly, the tool offers the interactive mode:

```bash
rgh interactive
```

## Quality Audit

Rustgenhash ships with an automated audit harness that replays curated fixtures
across every CLI mode to guard against logical regressions.

```bash
cargo test --test audit
```

The audit produces deterministic artifacts under `target/audit/`:

- `summary.txt` — human-readable overview with status, severity, and skip notes.
- `summary.json` — machine-readable report suitable for pipelines.
- `issues/` — (populated in later phases) markdown snippets for failures.

Use `-- --case <fixture-id>` to focus on a single fixture during debugging:

```bash
cargo test --test audit -- --case string_sha256_basic
```

Fixtures that depend on non-deterministic behavior (e.g., benchmarking,
interactive flows) are marked with a skip reason and reported as `SKIP` in the
summary. When the audit fails, review the emitted severity, reproduction notes,
and the JSON payload to pinpoint the mismatch.

### Release Readiness

Release managers must complete `docs/qa/release-readiness.md` before tagging:

1. Ensure the GitHub Actions “Audit Harness” workflow passed on the target commit.
2. Run `cargo test --test audit` locally and sync failures into
   `docs/qa/logic-issues.md` via `scripts/audit/export_issue.sh`.
3. Execute `scripts/audit/check_release.sh` to confirm zero failing fixtures and
   no open issues remain.
4. Record retest evidence (commit hashes, CI artifact URLs) in the checklist and
   gather maintainer sign-offs.

## Contribution 

If you want to contribute to this project, please feel free to do so. I am happy to accept pull requests. Any help is appreciated. If you have any questions, please feel free to contact me.
