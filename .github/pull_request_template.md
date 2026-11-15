## Summary

<!-- What changes and why. -->

## Checklist

- [ ] New or changed checks have a catalog entry, unit tests (pass, warn or fail, unknown) and a golden fixture
- [ ] `go run ./cmd/docgen` run and `docs/checks/` committed with the catalog change
- [ ] Read only promise kept: no writes, no non GET to Docker, no state changing command, no secret file contents
- [ ] Commands the change runs on the host (so the promise can be reviewed):
- [ ] Fixtures and docs use only documentation ranges and example.com
- [ ] Commit messages follow `type(scope): lowercase summary`

## Test plan

<!-- Paste real output of gofmt, go vet, golangci-lint and go test -race ./... -->
