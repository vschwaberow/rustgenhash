# Changelog

## Unreleased

- Introduced `rgh digest` and `rgh kdf` command families; `rgh string`, `rgh file`, and `rgh stdio` now emit deprecation warnings.
- Added structured JSON output for password-based KDF commands (`argon2`, `scrypt`, `pbkdf2`, `bcrypt`, `balloon`, `sha-crypt`).
- Updated interactive wizard to branch between digest and KDF flows before presenting mode-specific prompts.
