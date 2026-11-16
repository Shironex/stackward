# stackward diff

- **Host:** sha256:0123456789abcdef
- **Baseline:** 2026-10-01T12:00:00Z (stackward test, profile public-web, root)
- **New:** 2026-11-01T12:00:00Z (stackward test, profile public-web, root)

## Summary

| Change | Count |
|---|---|
| drift | 0 |
| drift checks that lost coverage | 2 |
| added | 1 |
| removed | 0 |
| changed | 0 |
| new findings | 0 |

## Lost coverage

| Check | Now | Detail |
|---|---|---|
| [NET-004](https://github.com/Shironex/stackward/blob/main/docs/checks/NET-004.md) | unknown | NET-004 judged the baseline and is unknown now: a new listener would not show |
| [DKR-020](https://github.com/Shironex/stackward/blob/main/docs/checks/DKR-020.md) | skip | DKR-020 judged the baseline and is skip now: a new root container would not show |

## Added

| Check | Level | Subject | New finding | What happened |
|---|---|---|---|---|
| [NET-004](https://github.com/Shironex/stackward/blob/main/docs/checks/NET-004.md) | unknown | `host` |  | new: listeners not inspected: ss failed |
