# Rustgenhash Audit Fixtures

Each JSON file in this directory represents a single deterministic audit case.

```json
{
  "id": "string_sha256_basic",
  "mode": "string",
  "algorithm": "SHA256",
  "input": {
    "value": "hello world"
  },
  "expected_output": {
    "digest": "b94d27b9934d3e08a52e52d7da7dabfad5edc1b6...",
    "format": "hex"
  },
  "metadata": {
    "severity": "high",
    "notes": "Verifies lowercase hexadecimal formatting",
    "skip_reason": null
  }
}
```

## Required Properties
- `id`: Stable identifier combining the CLI mode and a descriptive case name.
- `mode`: One of `string`, `file`, `stdio`, `header`, `analyze`, `random`, `benchmark`, `interactive`, or `compare`.
- `algorithm`: Hashing algorithm, analyzer, or mode-specific label.
- `input`: Object describing how to invoke the CLI (e.g., literal text, file path, header URL, random seed).
- `expected_output`: Object encoding the deterministic result (digest, analyzer classification, benchmark metrics, etc.).

## Optional Metadata
- `metadata.severity`: Impact level when this case fails (`critical`, `high`, `medium`, `low`).
- `metadata.notes`: Free-form context for maintainers.
- `metadata.skip_reason`: Explanation when a case cannot run on the current platform (null when runnable).

## Directory Layout
- `tests/fixtures/<mode>/` contains only JSON files for that CLI mode.
- `.gitkeep` placeholders preserve empty directories until fixtures are added.

Keep fixtures small and deterministic. For large input coverage, store representative samples or instructions for regenerating data.

## Digest Boundary Cases
- Track fixtures covering empty input, large streaming inputs, and other edge conditions under `tests/fixtures/digest/`.
- Large streaming fixtures should reference runtime-generated data (see `target/audit/large-stream/`).

## Negative Policy Fixtures (MAC & KDF)
- Document fixtures that intentionally fail policy checks (e.g., Poly1305 key length, PBKDF2 iteration floors, zero-length secrets).
- Each negative fixture should cite the governing specification in `metadata.notes` and expect exit code `2`.
