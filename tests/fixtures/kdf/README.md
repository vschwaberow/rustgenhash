# KDF Fixtures

Canonical fixtures for `rgh kdf` commands. Include parameter sets (memory, time, cost, output length), salts, and expected derived keys for each supported algorithm.

- `hkdf_sha256_basic.json`: HKDF using SHA-256 with inline text IKM and short salt/info.
- `hkdf_sha512_info.json`: HKDF using SHA-512 with explicit salt/info vectors and 64-byte output.
