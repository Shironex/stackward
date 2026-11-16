# Contributing

Thanks for helping. stackward is small on purpose; please read
[docs/architecture.md](docs/architecture.md) before adding a collector or a
check.

Please use the issue forms: [bug report, false positive, check request or docs
issue](https://github.com/Shironex/stackward/issues/new/choose). Security
problems go through the private report described in [SECURITY.md](SECURITY.md).
Everyone taking part follows the [code of conduct](CODE_OF_CONDUCT.md).

## Ground rules

- **Read only.** Collectors use `facts.System`, which has no write method.
  Never write files, never send anything but GET to Docker, never run a
  command that changes state, never read secret file contents.
- **Unknown is never pass.** If a check cannot see what it needs, it returns
  `unknown` with a reason.
- **No real infrastructure in the repo.** Fixtures and docs use
  `example.com`, the documentation ranges 192.0.2.0/24, 198.51.100.0/24,
  203.0.113.0/24 and 2001:db8::/32, and 100.64.0.0/10 for tailnet examples.
- **Minimal dependencies.** Users run this as root. Justify every new module
  in the pull request.
- **Check ids are forever.** A retired id is never reused.

## Workflow

```sh
gofmt -l .                 # must print nothing
go vet ./...
golangci-lint run          # v2, config in .golangci.yml
go test -race ./...
go test ./test/ -update    # after an intended report change; review the diff
```

The live host scenarios under `test/scenarios/` run the real binary on a
GitHub runner, and the VM matrix under `test/vm/` runs apply over SSH in
Ubuntu and Debian VMs; [docs/testing.md](docs/testing.md) explains both and how
to run them in a throwaway VM. Never run `stackward apply` on your own
machine.

## Code limits and guardrails

CI enforces these, so the code stays small enough to review and the safety
promise stays checkable. Configuration is in `.golangci.yml`.

| Limit | Value | Where |
|---|---|---|
| File length | 800 lines of code (comments and blank lines do not count) | revive `file-length-limit` |
| Test file length | 1000 lines of code | `stackward-guard` (below) |
| Function length | 100 lines or 70 statements | funlen |
| Cognitive complexity | 35 | gocognit |
| Nested `if` complexity | 6 | nestif |
| Maintainability index | 20 | maintidx |
| Duplicated code | 150 tokens | dupl |
| Function arguments, results | 7, 4 | revive `argument-limit`, `function-result-limit` |

Test files are exempt from the function and duplication limits; table
tests are long by nature. **Soft target:** consider splitting a file past
500 lines, along the seams of its checks or collector parts. CI does not
enforce it.

Package layering (depguard, from [docs/architecture.md](docs/architecture.md)):

- `internal/checks` is pure: it must not import `cli`, `tui`, `report`,
  `plan`, `apply`, `probe`, `audit`, `sandbox` or `net/http`.
- `internal/facts` collectors must not import `checks`, `profile`,
  `report`, `plan`, `apply`, `probe`, `audit`, `cli` or `tui`.
- `internal/plan`, `internal/apply` and `internal/report` never import
  `cli` or `tui` (plan also not `apply`; apply not `probe`; report not
  `plan` or `apply`).
- `internal/tui` only browses a `report.Report`: no `facts`, `plan` or
  `apply`.
- `internal/diff` only compares two `report.Report` values: no `cli`,
  `tui`, `plan`, `apply`, `probe`, `audit`, `sandbox` or `provider`.
- `redact`, `catalog`, `sandbox`, `schemacheck`, `version`, `waiver` and
  the root `schema` package (the embedded JSON contracts) import nothing
  else from this module.
- `os/exec` is imported only by `internal/apply`,
  `internal/facts/system.go` and `internal/fleet/ssh.go` (the user's ssh for
  `audit --ssh`).
- `internal/fleet` never imports `cli`, `tui`, `plan`, `apply`, `probe`,
  `audit`, `provider` or `net/http`.

`stackward-guard` (`internal/lint/guard`) enforces the safety model in code:
any call that writes to the filesystem, starts a program, uses the network
or makes a raw system call must sit in a package listed in
`internal/lint/guard/allowlist.go`, where every entry says why. Test files
are skipped. A finding means the code does something a read only audit tool
should not, so the fix is almost never a new allowlist entry; if one is
really needed, justify it in the pull request. The same tool caps test
files at 1000 lines of code.

Run everything locally:

```sh
go run ./internal/lint/guard/cmd ./...    # stackward-guard
golangci-lint run                         # v2, same version as CI
```

When a limit trips on old code that cannot be fixed in the same pull
request, add a narrow path exclusion to `.golangci.yml` with a comment and a
follow-up issue; never raise a limit to make code pass.

## Check pages

`docs/checks/` is generated from the check catalog. After adding or editing a
catalog entry, regenerate it and commit the result:

```sh
go run ./cmd/docgen
```

`go test ./...` fails with the same command in its message when the committed
pages are stale. Never edit the pages by hand.

Commits follow `type(scope): lowercase summary`, for example
`feat(checks): add ssh password auth check`. Scopes: cli, facts, checks,
catalog, report, probe, tui, sandbox, redact, schema, docs, ci, build, deps,
repo, test.

## Turning a bug report into a fixture

Ask the reporter for `stackward audit --dump-facts` (redacted, hostname
hashed). Replace anything that still looks like real infrastructure with
documentation values, save it as `test/fixtures/<scenario>/facts.json`, run
`go test ./test/ -update` and review `expected.json`.

## Labels

Issues and pull requests carry a type label (`bug`, `enhancement`,
`documentation`, `security`, `chore`, `ci`, `dependencies`, `question`,
`breaking change`), one or more `area:*` labels naming the code domain
(`area:ssh`, `area:docker`, `area:catalog` and so on) and a `phase:v0.x`
label for the release it is planned for. `check-request` and `false-positive`
mark the two report kinds, `good first issue` and `help wanted` mark where
help is welcome. Pull requests from this repository get `area:*` labels
automatically from the changed paths; maintainers set the rest.
