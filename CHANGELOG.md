# Changelog

## Unreleased

- Introduced `rgh digest` and `rgh kdf` command families; `rgh string`, `rgh file`, and `rgh stdio` now emit deprecation warnings.
- Added structured JSON output for password-based KDF commands (`argon2`, `scrypt`, `pbkdf2`, `bcrypt`, `balloon`, `sha-crypt`).
- Updated interactive wizard to branch between digest and KDF flows before presenting mode-specific prompts.
- Enabled `asm-accel` feature by default for SHA-1/SHA-2/MD5/Whirlpool crates; added `portable-only` opt-out for restricted targets.
- `rgh benchmark` now reports `asm_enabled` metadata and ships a SHA-256 fixture (`tests/fixtures/benchmark/sha256_asm.json`).
- Recorded baseline/optimized artifacts in `target/audit/` and refreshed release documentation (README, docs/qa/performance-summary.md).
- CI matrix extended (`.github/workflows/build.yml`) to validate wasm32 portable fallback plus native macOS ARM and Windows builds.
