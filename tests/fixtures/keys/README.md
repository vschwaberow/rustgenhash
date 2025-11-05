# Fixture Key Material

Store non-sensitive sample keys used by MAC fixtures here. Keys should be short binary blobs generated specifically for testing (never production secrets).

Guidelines:
- Name files descriptively (e.g., `hmac.key`, `kmac.key`).
- Keep key sizes aligned with algorithm requirements (32 bytes for BLAKE3 keyed mode, etc.).
- Track provenance in fixture notes so auditors can reproduce the vectors.
