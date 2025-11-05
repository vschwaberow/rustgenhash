# MAC Fixtures

This directory contains canonical message authentication code (MAC) fixtures used by the audit harness.

Each JSON file captures:
- `id` describing the scenario (string/file/stdio)
- Algorithm identifier (e.g., `hmac-sha256`, `kmac256`, `blake3-keyed`)
- Input payload metadata
- Expected digest output and exit code

Add new fixtures alongside published test vectors to ensure deterministic regression coverage.
