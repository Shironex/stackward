# stackward diff

- **Host:** sha256:0123456789abcdef
- **Baseline:** 2026-10-01T12:00:00Z (stackward test, profile public-web, root)
- **New:** 2026-11-01T12:00:00Z (stackward test, profile public-web, root)

## Summary

| Change | Count |
|---|---|
| drift | 0 |
| drift checks that lost coverage | 0 |
| added | 0 |
| removed | 1 |
| changed | 5 |
| new findings | 1 |

## Removed

| Check | Level | Subject | New finding | What happened |
|---|---|---|---|---|
| [USR-006](https://github.com/Shironex/stackward/blob/main/docs/checks/USR-006.md) | warn (accepted) | `user:gone` |  | no longer reported (was warn (accepted): login account gone has not logged in for 200 days) |

## Changed

| Check | Level | Subject | New finding | What happened |
|---|---|---|---|---|
| [USR-005](https://github.com/Shironex/stackward/blob/main/docs/checks/USR-005.md) | warn (accepted) | `user:deploy` |  | now accepted by a waiver until 2027-01-31, still warn: deploy is in the docker group |
| [USR-006](https://github.com/Shironex/stackward/blob/main/docs/checks/USR-006.md) | pass | `user:legacy` |  | warn to pass, fixed; no waiver matches it any more: login account legacy logged in recently |
| [USR-006](https://github.com/Shironex/stackward/blob/main/docs/checks/USR-006.md) | warn (accepted) | `user:old` |  | waiver renewed until 2027-03-31 (was 2026-12-31): login account old has not logged in for 150 days |
| [NET-003](https://github.com/Shironex/stackward/blob/main/docs/checks/NET-003.md) | pass | `host` |  | fail to pass, fixed: SSH is reachable only over the tailnet |
| [DKR-021](https://github.com/Shironex/stackward/blob/main/docs/checks/DKR-021.md) | fail | `container:ci/runner` | yes | waiver expired after 2026-10-15, the finding counts again: runner is privileged |
