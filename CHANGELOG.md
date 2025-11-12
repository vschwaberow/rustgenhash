# Changelog

## 0.12.1 - 2025-11-12

- Added replay shortcuts to `rgh console`: `!!` replays the last command, while `replay <index>` / `!<index>` re-run any numbered history entry with optional edit prompts, redacted literal re-entry, persisted indicators, and `history --export csv <FILE>` for sanitized audit logs.

## 0.12.0 — 2025-11-09

- Introduced `rgh digest` and `rgh kdf` command families; `rgh string`, `rgh file`, and `rgh stdio` now emit deprecation warnings.
- Added structured JSON output for password-based KDF commands (`argon2`, `scrypt`, `pbkdf2`, `bcrypt`, `balloon`, `sha-crypt`).
- Updated interactive wizard to branch between digest and KDF flows before presenting mode-specific prompts.
- Enabled `asm-accel` feature by default for SHA-1/SHA-2/MD5/Whirlpool crates; added `portable-only` opt-out for restricted targets.
- `rgh benchmark` now reports `asm_enabled` metadata and ships a SHA-256 fixture (`tests/fixtures/benchmark/sha256_asm.json`).
- Recorded baseline/optimized artifacts in `target/audit/` and refreshed release documentation (README, docs/qa/performance-summary.md).
- CI matrix extended (`.github/workflows/build.yml`) to validate wasm32 portable fallback plus native macOS ARM and Windows builds.
- Added opt-in console history persistence via new clap flags (`--history-file`, `--history-retention`, `--force-script-history`) plus automatic load/save wiring in `ConsoleSession`. Sanitized retention is the default for interactive runs; verbatim mode requires confirmation.
- Introduced manual history management builtins (`history save <FILE>`, `history load <FILE>`, `history clear`, `show history`) and deterministic fixtures/transcripts to prove sanitized vs verbatim behavior.
- Implemented `export vars <FILE> [--format json|yaml] [--include-secrets --yes]`, enabling operators to write masked JSON manifests or YAML files with secrets when explicitly requested. Variable metadata now tracks insertion order and creation timestamps for reproducible exports.
- Added the `src/rgh/console/history.rs` and `src/rgh/console/export.rs` helpers plus comprehensive integration tests in `tests/interactive_console.rs`, alongside new scripts/fixtures under `tests/fixtures/interactive/`.
- Updated README/quickstart to document the new persistence/export workflows, and ensured `cargo test --test interactive_console` covers the added scenarios.

## 0.11.0 — 2025-10-19

- Dependency refresh and version bump to keep the digest/KDF stack current.

## 0.10.2 — 2025-02-10

- Maintenance release updating the crate version (`Cargo.toml`/`Cargo.lock`) to align with dependency bumps.

## 0.10.1 — 2025-01-27

- Follow-up release adjusting metadata and versioning after the 0.10.0 refactor.

## 0.10.0 — 2024-09-03

- Major version bump capturing assorted dependency changes and CLI polish.

## 0.9.7 — 2024-08-25

- Added another automation-friendly feature (see PR #97) while keeping fixtures in sync.

## 0.9.6 — 2024-06-08

- Routine dependency updates plus version bump to 0.9.6.

## 0.9.5 — 2024-04-12

- Updated libraries and crate metadata.

## 0.9.4 — 2024-03-10

- Introduced Blake3 support across the CLI (`rgh digest string/file/stdio`).

## 0.9.3 — 2024-03-05

- README refresh and package updates.

## 0.9.2 — 2024-02-19

- Added `rgh compare-file --manifest` to diff canonical manifests.

## 0.9.1 — 2024-02-08

- Minor CLI/docs adjustments for the 0.9.1 refresh.

## 0.9.0 — 2023-12-19

- Refactored project structure, modernized dependencies, and tightened audit coverage.

## 0.8.5 — 2023-12-04

- Incremental improvements and dependency bumps.

## 0.8.4 — 2023-11-30

- Maintenance release focused on docs and crate updates.

## 0.8.3 — 2023-11-20

- Added Ascon hash handling throughout the CLI.

## 0.8.2 — 2023-11-10

- Fixed HHHash URL handling edge cases.

## 0.8.1 — 2023-09-10

- Development housekeeping for the 0.8.1 cut.

## 0.8.0 — 2023-07-20

- Added new hash families and aligned fixtures/audit harness accordingly.

## 0.7.1 — 2023-06-23

- Quick follow-up release to 0.7.0.

## 0.7.0 — 2023-02-26

- Introduced the `rgh analyze` mode for hash introspection (PR #70).

## 0.6.3 — 2023-02-20

- Added UUIDv4 helper to the CLI.

## 0.6.2 — 2023-02-12

- Tweaked buffered IO helpers for better streaming performance.

## 0.6.1 — 2022-12-30

- Documentation and dependency update following the random string work.

## 0.6.0 — 2022-12-29

- Added random string generation utilities to the CLI.

## 0.5.14 — 2022-12-11

- Several incremental improvements and bug fixes.

## 0.5.13 — 2022-10-09

- Continued CLI/README maintenance.

## 0.5.12 — 2022-10-08

- Fixed TAB completion regressions.

## 0.5.11 — 2022-10-08

- Multiple enhancements across digest/KDF helpers (see PR #62).

## 0.5.10 — 2022-10-03

- Bugfix rollup for 0.5.10.

## 0.5.9 — 2022-10-03

- Cargo packaging tweaks prior to the 0.5.10 fix.

## 0.5.8 — 2022-09-30

- More dependency bumps and README polish.

## 0.5.7 — 2022-09-23

- Upgraded `clap` and aligned CLI help output (PR #40).

## 0.5.6 — 2022-09-17

- Updated dependencies for the September release.

## 0.5.5 — 2022-09-13

- Miscellaneous updates (PR #38).

## 0.5.3 — 2022-06-02

- Added Balloon hashing improvements (PR #36).

## 0.5.2 — 2022-05-??

- Move-to-clap modernization and digest UX improvements.

## 0.5.1 — 2022-05-??

- Initial clap migration groundwork (PR #32).

## 0.5.0 — 2022-05-29

- Added GOST94-UA support and refreshed crypto dependencies.

## 0.4.2 — 2021-12-22

- Quick corrections following the v0.4.y series.

## 0.4.1 — 2021-12-22

- Added more hash algorithms (PR #29).

## 0.4.0 — 2021-12-21

- README cleanup plus CLI contract fixes (PR #28).

## 0.3.1 — 2021-09-26

- Minor maintenance release.

## 0.3.0 — 2021-03-15

- Added stdio digest support (`rgh digest stdio ...`) and fixtures.

## 0.2.2 — 2020-11-04

- Help text/cosmetic fixes (PR #23).

## 0.2.1 — 2020-11-03

- README update after the file-hash feature landed.

## 0.2.0 — 2020-11-02

- Added file hashing (`rgh digest file ...`) and supporting manifests (PR #20).

## 0.1.9 — 2020-10-30

- Dependency/metadata update.

## 0.1.8 — 2020-10-??

- Lockfile/metadata refresh.

## 0.1.7 — 2020-10-??

- Additional `Cargo.toml` / `Cargo.lock` updates.

## 0.1.6 — 2020-10-28

- Lockfile sync with upstream crates.

## 0.1.5 — 2020-10-??

- Incremental metadata update.

## 0.1.4 — 2020-10-??

- Added `categories` metadata on crates.io.

## 0.1.3 — 2020-10-??

- Switched to RustCrypto digest stacks (PR #4).

## 0.1.2 — 2020-10-26

- Added `Cargo.lock` to the repository for reproducible builds.

## 0.1.1 — 2020-10-26

- Initial CI workflow (`rust.yml`) while bootstrapping the project.

## 0.11.0 — 2025-10-19

- Dependency refresh and bug fixes prior to the console refactor.

## 0.10.2 — 2025-02-10

- Maintenance release aligning crate metadata with dependency updates.

## 0.10.1 — 2025-01-27

- Follow-up refinements after the 0.10.0 refactor (docs/tests).

## 0.10.0 — 2024-09-03

- Major project refactor; reorganized modules, updated deps, and improved CLI UX.

## 0.9.7 — 2024-08-25

- Feature highlight: automation-friendly additions referenced in PR #97.

## 0.9.6 — 2024-06-08

- Dependency bumps and version update.

## 0.9.5 — 2024-04-12

- Library updates and metadata refresh.

## 0.9.4 — 2024-03-10

- Added BLAKE3 support to digest commands.

## 0.9.3 — 2024-03-05

- Polished README and aligned packages.

## 0.9.2 — 2024-02-19

- Introduced compare-file manifest diffing.

## 0.9.1 — 2024-02-08

- Minor CLI/doc adjustments.

## 0.9.0 — 2023-12-19

- Large refactor with updated dependencies and tightened audit coverage.

## 0.8.5 — 2023-12-04

- Incremental improvements and dependency bumps.

## 0.8.4 — 2023-11-30

- Docs/metadata maintenance.

## 0.8.3 — 2023-11-20

- Added Ascon hash handling.

## 0.8.2 — 2023-11-10

- Fix for HHHash URL edge cases.

## 0.8.1 — 2023-09-10

- General housekeeping for CLI and deps.

## 0.8.0 — 2023-07-20

- Introduced new hash families and fixtures.

## 0.7.1 — 2023-06-23

- Maintenance release following `rgh analyze`.

## 0.7.0 — 2023-02-26

- Added `rgh analyze` mode for hash introspection.

## 0.6.3 — 2023-02-20

- Added UUIDv4 helper.

## 0.6.2 — 2023-02-12

- Buffered IO enhancements.

## 0.6.1 — 2022-12-30

- Docs/dependency refresh.

## 0.6.0 — 2022-12-29

- Random string generation utilities.

## 0.5.14 — 2022-12-11

- Several incremental fixes.

## 0.5.13 — 2022-10-09

- Ongoing CLI maintenance.

## 0.5.12 — 2022-10-08

- TAB completion fix.

## 0.5.11 — 2022-10-08

- Enhancements across digest/KDF helpers.

## 0.5.10 — 2022-10-03

- Bugfix rollup after Cargo packaging tweaks.

## 0.5.9 — 2022-10-03

- Prep release ahead of 0.5.10 fix.

## 0.5.8 — 2022-09-30

- Dependency/README updates.

## 0.5.7 — 2022-09-23

- Clap upgrade and CLI help alignment.

## 0.5.6 — 2022-09-17

- Dependency update.

## 0.5.5 — 2022-09-13

- Incremental update (PR #38).

## 0.5.3 — 2022-06-02

- Balloon hashing improvements.

## 0.5.2 — 2022-05-??

- Move-to-clap modernization.

## 0.5.1 — 2022-05-??

- Initial clap migration groundwork.

## 0.5.0 — 2022-05-29

- Added GOST94-UA support.

## 0.4.2 — 2021-12-22

- Quick corrections post-v0.4.1 update.

## 0.4.1 — 2021-12-22

- More hash algorithms added.

## 0.4.0 — 2021-12-21

- README/CLI contract fixes.

## 0.3.1 — 2021-09-26

- Minor maintenance release.

## 0.3.0 — 2021-03-15

- Added `rgh digest stdio` and fixtures.

## 0.2.2 — 2020-11-04

- Help text and cosmetic fixes.

## 0.2.1 — 2020-11-03

- README update after new file hashing support.

## 0.2.0 — 2020-11-02

- Introduced file hashing (`rgh digest file`).

## 0.1.9 — 2020-10-30

- Dependency/metadata updates.

## 0.1.8 — 2020-10-??

- Lockfile/metadata refresh.

## 0.1.7 — 2020-10-??

- Additional Cargo lockfile updates.

## 0.1.6 — 2020-10-28

- Lockfile synchronization.

## 0.1.5 — 2020-10-??

- Minor version bump.

## 0.1.4 — 2020-10-??

- Added crates.io categories metadata.

## 0.1.3 — 2020-10-??

- Switched to RustCrypto digest stacks.

## 0.1.2 — 2020-10-26

- Added Cargo.lock to repo.

## 0.1.1 — 2020-10-26

- Bootstrap CI workflow.
