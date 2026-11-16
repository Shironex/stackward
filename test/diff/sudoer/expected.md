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
| changed | 0 |
| new findings | 1 |

## Drift

| Kind | Check | Subject | What | Detail |
|---|---|---|---|---|
| sudoer | [USR-004](https://github.com/Shironex/stackward/blob/main/docs/checks/USR-004.md) | `file:/etc/sudoers.d/ci` | `%ops` | new NOPASSWD sudo rule for %ops in /etc/sudoers.d/ci |
| sudoer | [USR-004](https://github.com/Shironex/stackward/blob/main/docs/checks/USR-004.md) | `file:/etc/sudoers.d/ci` | `ci` | new NOPASSWD sudo rule for ci in /etc/sudoers.d/ci |

## Added

| Check | Level | Subject | New finding | What happened |
|---|---|---|---|---|
| [USR-004](https://github.com/Shironex/stackward/blob/main/docs/checks/USR-004.md) | warn | `file:/etc/sudoers.d/ci` | yes | new: NOPASSWD sudo for ci (line 1), %ops (line 2) |
