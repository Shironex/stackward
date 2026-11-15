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
