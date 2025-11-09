# MAC Fixtures

This directory contains canonical message authentication code (MAC) fixtures used by the audit harness.

Each JSON file captures:
- `id` describing the scenario (string/file/stdio)
- Algorithm identifier (e.g., `hmac-sha256`, `kmac256`, `blake3-keyed`)
- Input payload metadata
- Expected digest output and exit code

Add new fixtures alongside published test vectors to ensure deterministic regression coverage.

Recent additions:
- `mac_poly1305_mismatched_key.json`: Verifies oversized Poly1305 keys exit with RFC 8439 guidance and exit code `2`.
- `mac_cmac_padding_mismatch.json`: Validates CMAC key length enforcement (invalid 12-byte key) with exit code `2` and actionable error text.
