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
| root container | [DKR-020](https://github.com/Shironex/stackward/blob/main/docs/checks/DKR-020.md) | `container:db/postgres` | `postgres` | postgres runs as root (reachable from outside) |
| root container | [DKR-020](https://github.com/Shironex/stackward/blob/main/docs/checks/DKR-020.md) | `container:web/app` | `app` | app runs as root now, and did not |

## Added

| Check | Level | Subject | New finding | What happened |
|---|---|---|---|---|
| [DKR-020](https://github.com/Shironex/stackward/blob/main/docs/checks/DKR-020.md) | fail | `container:db/postgres` | yes | new: db/postgres runs as root |

## Changed

| Check | Level | Subject | New finding | What happened |
|---|---|---|---|---|
| [DKR-020](https://github.com/Shironex/stackward/blob/main/docs/checks/DKR-020.md) | warn | `container:web/app` | yes | pass to warn: web/app runs as root |
