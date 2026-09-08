# Digest Fixtures

Canonical fixtures for `rgh digest` commands live here.

## Known-answer tests (`kats/`)

Every algorithm in `DIGEST_ALGORITHMS` (`src/rgh/hash.rs`) must have at least one JSON file under `kats/` with:

- `algorithm` — canonical ID (e.g. `SHA256`, `SKEIN512`)
- `input.encoding` — `utf8` or `hex`
- `input.value` — message
- `expected_hex` — digest hex
- `source.title` / `source.url` — external specification or published KAT suite

Coverage is enforced by `tests/digest_kats.rs`. Adding a digest algorithm without a sourced fixture fails CI.

Operational fixtures (stdio, manifests, warnings) stay in this directory beside `kats/`.
