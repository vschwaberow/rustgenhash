# rustgenhash

rustgenhash is a tool to generate hashes on the commandline from stdio.

It can be used to generate single or multiple hashes for usage in password databases or even in penetration testing scenarios where you want to test password cracking tools. It can also help to identify the nature of a provided hash.

> Multihash output support follows the [multiformats Multihash specification](https://github.com/multiformats/multihash) and uses the Rust [`multihash`](https://crates.io/crates/multihash) v0.18 and [`multibase`](https://crates.io/crates/multibase) v0.9 crates for TLV encoding and base58btc emission.
> Supported multicodec mappings currently cover `sha2-256`, `sha2-512`, `blake2b-256`, and `blake3-256`. When `--format multihash` is selected, manifests record the emitted base58btc tokens verbatim.

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
| `rgh digest string -a <ALG> <TEXT>` | Hash inline text with the selected algorithm. | `--format {hex,base64,json,jsonl,csv,hashcat,multihash}`, `--hash-only` |
| `rgh digest file -a <ALG> <PATH>` | Hash files or directories (opt-in recursion, manifests, progress). | `--format`, `--recursive`, `--follow-symlinks`, `--threads`, `--mmap-threshold`, `--manifest`, `--error-strategy`, `--progress/--no-progress`, `--hash-only` |
| `rgh digest stdio -a <ALG>` | Read newline-delimited input from stdin and emit one digest per line. | `--format`, `--hash-only` |

Examples:

```bash
# Digest a release tarball with SHA-256
rgh digest file -a sha256 target/release/rgh

# Compute hashes for a list while keeping one token per line
cat passwords.txt | rgh digest stdio -a sha3_512 --hash-only

# Emit multibase multihash tokens for interoperability with CID tooling
rgh digest file -a sha256 --format multihash tests/fixtures/file/sample.txt

# Recursively hash a backup tree and write a manifest
rgh digest file -a sha256 --recursive --manifest backup-hashes.json /mnt/backups

Directory hashing options:

- `--recursive` traverses nested directories; defaults to the legacy non-recursive behaviour.
- `--follow-symlinks {never,files,all}` controls whether symbolic links are hashed or followed.
- `--threads {1|auto|N}` enables Rayon-backed parallel hashing when more than one worker is requested.
- `--mmap-threshold <SIZE|off>` switches to memory-mapped IO for large files (e.g., `64MiB`).
- `--manifest <FILE>` writes a JSON summary containing per-file digests, failures, and performance metadata (fail-fast suppresses the file to avoid partial output). When `--format multihash` is selected, the manifest preserves the emitted base58btc tokens.
- `--error-strategy {fail-fast,continue,report-only}` determines how failures affect exit codes and manifest writes:
  - `fail-fast` stops on the first unreadable entry, exits `1`, and skips manifest creation.
  - `continue` records failures, hashes readable files, and exits `2` when any recoverable errors occur.
  - `report-only` logs failures for review but exits `0` to keep downstream scripts green.
- `--progress`/`--no-progress` override adaptive stderr progress reporting (auto-disabled for `--hash-only`).

### MAC commands

`rgh mac` generates keyed message authentication codes for inline text, files, or newline-delimited stdin streams. Supply a key via `--key <PATH>` or `--key-stdin` and choose output formatting with `--hash-only` (digest only) or `--format json`.

| Algorithm | Description | Key requirements | Notes |
|-----------|-------------|------------------|-------|
| `hmac-sha1` | HMAC-SHA1 | ≥ 1 byte | ⚠ Legacy — retained for backward compatibility ([NIST SP 800-131A rev.2 §3][nist]) |
| `hmac-sha256` / `hmac-sha512` | HMAC over SHA-2 | ≥ 1 byte | [RFC 2104][rfc-2104] with FIPS 180-4 core |
| `hmac-sha3-256` / `hmac-sha3-512` | HMAC over SHA-3 | ≥ 1 byte | [FIPS 202][fips-202] sponge construction |
| `kmac128` / `kmac256` | NIST SP 800-185 KMAC | Arbitrary | cSHAKE-based MAC ([NIST SP 800-185][nist-800-185]) |
| `cmac-aes128` / `cmac-aes192` / `cmac-aes256` | AES-CMAC | 16 / 24 / 32 bytes | Deterministic CMAC per [NIST SP 800-38B][nist-800-38b] |
| `poly1305` | Poly1305 one-time MAC | 32 bytes | Warns on key reuse; follows [RFC 8439 §2.5][rfc-8439] guidance |
| `blake3-keyed` | BLAKE3 keyed mode | 32 bytes | High-speed keyed hashing ([BLAKE3 spec][blake3-spec]) |

Examples:

```bash
# CMAC over inline evidence string with 128-bit AES key
rgh mac --alg cmac-aes128 --key tests/fixtures/keys/cmac_aes128.key --input "compliance-mac"
# stdout → 3d5db00e9962fadb33cf8153f3167dae compliance-mac

# CMAC over a file with a 256-bit key
rgh mac --alg cmac-aes256 --key tests/fixtures/keys/cmac_aes256.key --file tests/fixtures/file/cmac_evidence.txt
# stdout → 3e8413cbda3fc1bd20809494a42d4a5c tests/fixtures/file/cmac_evidence.txt

# Poly1305 streaming MAC with reuse warning on the second line
printf "config\npipeline\n" | rgh mac --alg poly1305 --key tests/fixtures/keys/poly1305.key --stdin
# stderr → Poly1305 requires one-time keys; reuse detected
# stdout → 1cb7a97202776f414eae3333aefc9f57 config
#           720c7a23b362a576bb8e3cc3187c8e2b pipeline
```

#### Weak Digest Algorithms

| Algorithm | Risk | Safer alternatives | References |
|-----------|------|--------------------|------------|
| MD5 | ⚠ Weak | SHA-256, BLAKE3 | [NIST SP 800-131A rev.2 §3][nist] · [BSI TR-02102-1][bsi] |
| SHA-1 | ⚠ Weak | SHA-256, SHA-512 | [NIST SP 800-131A rev.2 §3][nist] · [BSI TR-02102-1][bsi] |
| SHA-224 | ⚠ Weak | SHA-256, SHA-512 | [NIST SP 800-131A rev.2 §3][nist] · [BSI TR-02102-1][bsi] |

⚠ entries indicate algorithms retained solely for legacy verification; automation should migrate to the recommended replacements.

#### Supported Digest Algorithms

- **SHA-2 family**: SHA-256, SHA-384, SHA-512 (recommended); SHA-224 (⚠ Weak, legacy compatibility only).
- **SHA-3 family**: SHA3-224, SHA3-256, SHA3-384, SHA3-512.
- **BLAKE family**: BLAKE2b, BLAKE2s, BLAKE3 (memory-hard friendly, modern).
- **FSB family**: FSB-160, FSB-224, FSB-256, FSB-384, FSB-512.
- **GOST & Streebog**: GOST R 34.11-94, GOST R 34.11-94-UA, Streebog-256, Streebog-512.
- **JH finalists**: JH-224, JH-256, JH-384, JH-512.
- **Skein family**: Skein-256, Skein-512, Skein-1024.
- **Shabal family**: Shabal-192, Shabal-224, Shabal-256, Shabal-384, Shabal-512.
- **RIPEMD family**: RIPEMD-160, RIPEMD-320.
- **Other classic digests**: Ascon, Belthash, Groestl, SM3, Tiger, Whirlpool.
- **Legacy MD family**: MD2, MD4, MD5 (⚠ Weak) retained for checksums and historical datasets.

The CLI exposes each algorithm via `-a/--algorithm`; `rgh digest --help` highlights weak options inline.

### Password-based KDF commands

KDF subcommands produce structured JSON output by default (use `--hash-only` to emit just the derived key). Passwords can
be provided via `--password`, through the interactive prompt, or piped in using `--password-stdin` (newline trimmed).

### MAC commands

`rgh mac` produces keyed message authentication codes for strings, files, or stdin streams.

| Identifier | Algorithm | Risk | Notes |
|------------|-----------|------|-------|
| `hmac-sha1` | HMAC-SHA1 | ⚠ Legacy | See [NIST SP 800-131A rev.2 §3][nist] · [BSI TR-02102-1][bsi]; prefer SHA-2/3 variants |
| `hmac-sha256` | HMAC-SHA256 | ✅ Recommended | [RFC 2104][rfc-2104] with SHA-2 core (FIPS 180-4) |
| `hmac-sha512` | HMAC-SHA512 | ✅ Recommended | [RFC 2104][rfc-2104] with SHA-2 core (FIPS 180-4) |
| `hmac-sha3-256` | HMAC-SHA3-256 | ✅ Recommended | HMAC over [FIPS 202][fips-202] SHA3-256 sponge |
| `hmac-sha3-512` | HMAC-SHA3-512 | ✅ Recommended | HMAC over [FIPS 202][fips-202] SHA3-512 sponge |
| `kmac128` | NIST SP 800-185 KMAC128 | ✅ Recommended | [NIST SP 800-185][nist-800-185] cSHAKE128-based MAC |
| `kmac256` | NIST SP 800-185 KMAC256 | ✅ Recommended | [NIST SP 800-185][nist-800-185] cSHAKE256-based MAC |
| `blake3-keyed` | BLAKE3 keyed hash | ✅ Recommended | [BLAKE3 specification §5][blake3-spec]; requires 32 byte key |

Examples:

```bash
# HMAC of inline text with key stored on disk
rgh mac --alg hmac-sha256 --key tests/fixtures/keys/hmac.key --input "alpha"

# KMAC256 over a file with key streamed from stdin
cat tests/fixtures/keys/kmac.key | rgh mac --alg kmac256 --key-stdin --file reports/archive.zip --hash-only

# BLAKE3 keyed MAC for stdin lines, JSON output
cat payloads.txt | rgh mac --alg blake3-keyed --key tests/fixtures/keys/blake3.key --stdin --format json
```

| Command | Parameters | Output |
|---------|------------|--------|
| `rgh kdf argon2` | `--mem-cost`, `--time-cost`, `--parallelism` | PHC string with Argon2id parameters + JSON metadata |
| `rgh kdf scrypt` | `--log-n`, `--r`, `--p`, `--salt <HEX>`, `--profile <ID>` | Encoded scrypt string + metadata |
| `rgh kdf pbkdf2` | `--algorithm {sha256,sha512}`, `--rounds`, `--length`, `--salt <HEX>`, `--profile <ID>` | `$pbkdf2-<digest>$...` plus metadata |
| `rgh kdf bcrypt` | `--cost` | 64 byte hex digest + metadata |
| `rgh kdf balloon` | `--time-cost`, `--memory-cost`, `--parallelism` | Balloon hash string + metadata |
| `rgh kdf sha-crypt` | (rounds fixed to 10 000) | `$6$` SHA-crypt string + metadata |
| `rgh kdf hkdf` | `--ikm-stdin`, `--salt <HEX>`, `--info <HEX>`, `--len <BYTES>`, `--hash {sha256,sha512,sha3-256,sha3-512,blake3}`, `--expand-only`, `--prk`, `--prk-stdin` | JSON with algorithm/hash metadata (`--hash-only` emits derived key hex) |

#### Supported Password Derivation Schemes

| Algorithm | Risk | Notes |
|-----------|------|-------|
| Argon2id | ✅ Recommended | Memory-hard PHC winner; default choice for new deployments. |
| Scrypt | ✅ Recommended | Memory-hard; tune `log_n`, `r`, `p` to meet policy requirements. |
| Balloon | ✅ Recommended | Configurable memory-hard alternative influenced by Argon2. |
| PBKDF2-SHA256 / PBKDF2-SHA512 | ⚠ Legacy | Acceptable with high iteration counts; prefer Argon2 or Scrypt when feasible. |
| Bcrypt | ⚠ Legacy | 72-byte password truncation; preserved for POSIX compatibility. |
| SHA-crypt (`sha512`) | ⚠ Legacy | Provided for Unix compatibility; migrate to memory-hard schemes. |

HKDF derives keyed material from input keying material (IKM) supplied via stdin. `--salt` and `--info` expect hex strings; omitting `--salt` in extract+expand mode defaults to an all-zero salt and prints `info: default salt = empty string` on stderr. Use `--hash` to choose the underlying digest (SHA-2, SHA-3, or `blake3`), `--len` to request the desired output length, and `--expand-only` together with `--prk <PATH>` or `--prk-stdin` when you need the RFC 5869 expand phase against an externally sourced PRK.

Example:

```bash
# Derive an Argon2id password hash and capture the JSON payload
rgh kdf argon2 --mem-cost 131072 --time-cost 4 --parallelism 2 --password-stdin <<'EOF'
s3cret!
EOF

# HKDF with the BLAKE3 variant (hash-only output for pipelines)
printf "ikm" | rgh kdf hkdf --hash blake3 --salt 73616c74 --info 696e666f --len 32 --ikm-stdin --hash-only

# HKDF expand-only mode fed by a PRK file (stderr stays silent on success)
rgh kdf hkdf --expand-only --prk tests/fixtures/keys/hkdf_prk.key --info 696e666f --len 64 --hash sha512 --hash-only

# PBKDF2 compliance preset (NIST SP 800-132) with deterministic salt for audits
printf "example-pass" | rgh kdf pbkdf2 --profile nist-sp800-132-2023 --salt 00112233445566778899aabbccddeeff --password-stdin

# Scrypt compliance preset (OWASP 2024) sharing the same fixed salt
printf "example-pass" | rgh kdf scrypt --profile owasp-2024 --salt 00112233445566778899aabbccddeeff --password-stdin --hash-only
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

Scheme for comparing hashes across manifests or digest lists:

```bash
rgh compare-file --manifest reference.json --against current.json

# Legacy digest lists remain supported
rgh compare-file baseline.txt candidate.txt
```

*Exit codes*: `0` identical, `1` differences detected, `2` comparison incomplete when manifests recorded failures.

Scheme for benchmarking a hash algorithm:

```bash
rgh benchmark -a <algorithm> -i <iterations>
```

## Performance Profile

- Assembly-optimized code paths (`asm-accel` feature) are enabled by default for SHA-1, SHA-2, MD5, and Whirlpool on x86_64 and Apple Silicon (aarch64) targets. Unsupported targets automatically fall back to portable implementations.
- Benchmark output includes an `asm_enabled` flag; use `scripts/benchmark/run.sh --mode baseline|optimized` to capture reproducible measurements and emit artifacts under `target/audit/`.
- To opt out (e.g., deterministic builds or restricted environments), run with `--no-default-features --features portable-only` or set the same flags in `Cargo.toml`.
- CI builds exercise wasm32 portable fallback and native macOS/Windows targets (`.github/workflows/build.yml`) to guarantee cross-platform coverage.
- Observed SHA-256 speedup on a Ryzen 5 4600H host: baseline `0.001035 ms/op` → optimized `0.000989 ms/op` (~4.4% faster). Throughput gains vary by CPU and governor settings.

The interactive wizard reflects the new structure:

```bash
rgh interactive
# → Choose between “Digest data” and “Derive password-based key” before drilling into specific modes.
# → Select CMAC or Poly1305 to see key length guidance and confirmation prompts.
```

- CMAC selection enforces 16/24/32-byte AES keys before execution.
- Poly1305 selection requires a one-time 32-byte key confirmation and surfaces reuse warnings.

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

[nist]: https://doi.org/10.6028/NIST.SP.800-131Ar2
[bsi]: https://www.bsi.bund.de/SharedDocs/Downloads/EN/BSI/Publications/TechGuidelines/TG02102/BSI-TR-02102-1.pdf
[rfc-2104]: https://www.rfc-editor.org/rfc/rfc2104
[fips-202]: https://doi.org/10.6028/NIST.FIPS.202
[nist-800-185]: https://doi.org/10.6028/NIST.SP.800-185
[nist-800-38b]: https://doi.org/10.6028/NIST.SP.800-38B
[rfc-8439]: https://www.rfc-editor.org/rfc/rfc8439
[blake3-spec]: https://github.com/BLAKE3-team/BLAKE3-specs
