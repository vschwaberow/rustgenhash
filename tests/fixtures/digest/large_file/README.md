# Large File Fixture Guidance

Use the helper script `scripts/fixtures/make_large_file.sh` (to be added) or run the command below to generate a deterministic sparse file for mmap tests:

```bash
mkdir -p tests/fixtures/digest/large_file
python3 - <<'PY'
from pathlib import Path
path = Path('tests/fixtures/digest/large_file/sample_128mb.bin')
chunk = b'0123456789abcdef' * 4096  # 64 KiB
with path.open('wb') as fh:
    for _ in range((128 * 1024 * 1024) // len(chunk)):
        fh.write(chunk)
PY
```

Do not commit the generated binary. The audit fixture references this path only when the test harness provisions it locally.
