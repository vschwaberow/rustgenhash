# KDF Fixtures

Canonical fixtures for `rgh kdf` commands. Include parameter sets (memory, time, cost, output length), salts, and expected derived keys for each supported algorithm.

- `hkdf_sha256_basic.json`: HKDF using SHA-256 with inline text IKM and short salt/info.
- `hkdf_sha512_info.json`: HKDF using SHA-512 with explicit salt/info vectors and 64-byte output.
- `kdf_hkdf_blake3_basic.json`: HKDF using BLAKE3 for both extract and expand with stdin IKM.
- `kdf_hkdf_expand_only.json`: HKDF expand-only vectors covering PRK-supplied success and missing PRK error cases.
- `kdf_pbkdf2_profile_nist_sp800132.json`: PBKDF2 derived key using the NIST SP 800-132 2023 preset.
- `kdf_scrypt_profile_owasp.json`: scrypt derived key based on OWASP 2024 recommended parameters.
