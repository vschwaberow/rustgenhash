# rustgenhash

rustgenhash is a tool to generate hashes on the commandline from stdio.

It can be used to generate single or multiple hashes for usage in password databases or even in penetration testing scenarios where you want to test password cracking tools. It can also help to identify the nature of a provided hash.

## Install

rustgenhash is written in Rust. You can install the tool with your Rust installation using following command:

```bash
cargo install rustgenhash
```

## Usage

Rustgenhash groups its command line surface into two primary families:

- `rgh digest <mode>` — deterministic hashing for strings, files, or stdin streams.
- `rgh kdf <algorithm>` — password-based key derivation with structured (JSON) metadata.

Supporting utilities remain available: `analyze`, `benchmark`, `compare-hash`, `compare-file`, `random`, `header`, and
`interactive` (a guided wizard that now branches between digest and KDF workflows).

### Digest commands

| Command | Description | Key flags |
|---------|-------------|-----------|
| `rgh digest string -a <ALG> <TEXT>` | Hash inline text with the selected algorithm. | `--output {hex,base64,hexbase64}`, `--hash-only` |
| `rgh digest file -a <ALG> <PATH>` | Hash a file or each file in a directory (non-recursive). | `--output`, `--hash-only` |
| `rgh digest stdio -a <ALG>` | Read newline-delimited input from stdin and emit one digest per line. | `--output`, `--hash-only` |

Examples:

```bash
# Digest a release tarball with SHA-256
rgh digest file -a sha256 target/release/rgh

# Compute hashes for a list while keeping one token per line
cat passwords.txt | rgh digest stdio -a sha3_512 --hash-only
```

### Password-based KDF commands

KDF subcommands produce structured JSON output by default (use `--hash-only` to emit just the derived key). Passwords can
be provided via `--password`, through the interactive prompt, or piped in using `--password-stdin` (newline trimmed).

| Command | Parameters | Output |
|---------|------------|--------|
| `rgh kdf argon2` | `--mem-cost`, `--time-cost`, `--parallelism` | PHC string with Argon2id parameters + JSON metadata |
| `rgh kdf scrypt` | `--log-n`, `--r`, `--p` | Encoded scrypt string + metadata |
| `rgh kdf pbkdf2` | `--algorithm {sha256,sha512}`, `--rounds`, `--length` | `$pbkdf2-<digest>$...` plus metadata |
| `rgh kdf bcrypt` | `--cost` | 64 byte hex digest + metadata |
| `rgh kdf balloon` | `--time-cost`, `--memory-cost`, `--parallelism` | Balloon hash string + metadata |
| `rgh kdf sha-crypt` | (rounds fixed to 10 000) | `$6$` SHA-crypt string + metadata |

Example:

```bash
# Derive an Argon2id password hash and capture the JSON payload
rgh kdf argon2 --mem-cost 131072 --time-cost 4 --parallelism 2 --password-stdin <<'EOF'
s3cret!
EOF

# Emit only the derived key for automation
rgh kdf pbkdf2 --algorithm sha512 --rounds 200000 --length 48 --hash-only --password "correct horse battery"
```

### Other utilities

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

The interactive wizard reflects the new structure:

```bash
rgh interactive
# → Choose between “Digest data” and “Derive password-based key” before drilling into specific modes.
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
