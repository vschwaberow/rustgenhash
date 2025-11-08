> === Benchmark Summary: MAC ===
> Mode: mac · Duration: 5s · Iterations: auto
> Created at 2025-11-10T12:00:00Z
> Planned 5s · Actual 5.4s (+0.4s)

| Algorithm | Profile | Ops/sec (kops) | Median ms | P95 ms | Samples | Status | Notes |
|-----------|---------|----------------|-----------|--------|---------|--------|-------|
| poly1305 | — | 4.20 kops/s | 0.25 ms | 0.30 ms | 64 | ✅ PASS | payload 1KiB |
| hmac-sha1 | — | 0.48 kops/s | 6.90 ms | 8.10 ms | 32 | ⚠ WARN | legacy throughput sample |

### Warnings
- hmac-sha1: ⚠ Legacy per NIST SP 800-131A rev.2 §3; Prefer SHA-2/3; Only 32 samples collected (< 30 target)
