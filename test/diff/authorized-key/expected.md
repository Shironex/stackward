# stackward diff

- **Host:** sha256:0123456789abcdef
- **Baseline:** 2026-10-01T12:00:00Z (stackward test, profile public-web, root)
- **New:** 2026-11-01T12:00:00Z (stackward test, profile public-web, root)

## Summary

| Change | Count |
|---|---|
| drift | 3 |
| drift checks that lost coverage | 0 |
| added | 0 |
| removed | 0 |
| changed | 0 |
| new findings | 0 |

## Drift

| Kind | Check | Subject | What | Detail |
|---|---|---|---|---|
| authorized key | [SSH-014](https://github.com/Shironex/stackward/blob/main/docs/checks/SSH-014.md) | `user:alice` | `SHA256:YW5vdGhlciB0ZXN0IGZpbmdlcnByaW50LCBub3QgYSBr` | new authorized key for alice |
| authorized key | [SSH-014](https://github.com/Shironex/stackward/blob/main/docs/checks/SSH-014.md) | `user:bob` | ` ` | bob has 2 authorized keys, was 1 (a report has no fingerprints to compare) |
| authorized key | [SSH-014](https://github.com/Shironex/stackward/blob/main/docs/checks/SSH-014.md) | `user:deploy` | `SHA256:Zm9yIGEgZ29sZGVuIHRlc3Qgb25seSwgbm90IGEga2V5` | new authorized key for deploy |
