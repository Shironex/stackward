# stackward diff

- **Host:** sha256:0123456789abcdef
- **Baseline:** 2026-10-01T12:00:00Z (stackward test, profile public-web, root)
- **New:** 2026-11-01T12:00:00Z (stackward test, profile public-web, root)

## Summary

| Change | Count |
|---|---|
| drift | 2 |
| drift checks that lost coverage | 0 |
| added | 1 |
| removed | 0 |
| changed | 1 |
| new findings | 2 |

## Drift

| Kind | Check | Subject | What | Detail |
|---|---|---|---|---|
| listener | [NET-004](https://github.com/Shironex/stackward/blob/main/docs/checks/NET-004.md) | `port:tcp/5432` | `tcp/5432` | now listens on wildcard addresses (postgres), was loopback |
| listener | [NET-004](https://github.com/Shironex/stackward/blob/main/docs/checks/NET-004.md) | `port:tcp/8080` | `tcp/8080` | new listener on wildcard addresses (node) |

## Added

| Check | Level | Subject | New finding | What happened |
|---|---|---|---|---|
| [NET-004](https://github.com/Shironex/stackward/blob/main/docs/checks/NET-004.md) | warn | `port:tcp/8080` | yes | new: tcp/8080 (node) is open from anywhere |

## Changed

| Check | Level | Subject | New finding | What happened |
|---|---|---|---|---|
| [NET-004](https://github.com/Shironex/stackward/blob/main/docs/checks/NET-004.md) | warn | `port:tcp/5432` | yes | info to warn: tcp/5432 (postgres) is open from anywhere |
