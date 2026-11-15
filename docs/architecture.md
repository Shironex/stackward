# Architecture

stackward is a pipeline with one rule per stage:

```
collectors (read the host)  ->  Facts (JSON serializable)  ->  checks (pure)
    ->  results  ->  report (catalog folded in, redacted)  ->  text / JSON
```

- **Collectors** read the host through `facts.System` and fill one part of
  `facts.Facts`. They are the only code that touches the system.
- **Checks** are pure functions `checks.Input -> []checks.Result`. They never
  touch the host, the clock or the network; "now" is `Facts.CollectedAt`.
- **The catalog** describes every check (title, severity, rationale, verify,
  fix, breaks, docs) in embedded JSON.
- **The report** joins results with the catalog, redacts every free text
  field, and renders text or `report.v1` JSON.

Because checks only see `Facts`, a facts file (`--dump-facts`) reproduces a
report exactly. That is how bug reports become golden test fixtures.

## Packages

| Package | Role |
|---|---|
| `cmd/stackward` | `main`, calls `cli.Run` |
| `internal/cli` | flags (stdlib `flag`), subcommands, output file, sandbox order |
| `internal/audit` | the one facts to report pipeline (`Evaluate`, `DumpFacts`) shared by CLI, golden tests and the future TUI |
| `internal/facts` | `Facts` model, `System`, `Collector`, registry, runner, collectors |
| `internal/checks` | `Check`, `Result`, levels, registry, `Evaluate`, one file per group |
| `internal/catalog` | embedded `data/<group>.json`, loader, group order |
| `internal/profile` | ingress profile names, `--profile` parsing, `Infer` (from listeners, firewall, tunnel, tailnet and PaaS panel facts) |
| `internal/report` | `report.v1` types, `Build`, text and JSON renderers, exit codes |
| `internal/tui` | `stackward tui`: Bubble Tea findings browser over a `report.Report` (reads only; OSC 52 copy on a key press) |
| `internal/redact` | secret masking for strings and decoded JSON |
| `internal/sandbox` | Landlock self sandbox on Linux, no-op elsewhere |
| `internal/probe` | `stackward probe`: target parsing, consent guard, TCP, banner and HTTP probes into probe `Facts`, and the PRB checks in their own registry (see below) |
| `internal/schemacheck` | tiny JSON Schema subset validator used by tests |
| `internal/version` | link time version (`-X .../internal/version.Version=v0.1.0`) |
| `schema/report.v1.json` | the JSON contract |
| `test/` | golden tests over `test/fixtures/<scenario>/` |

## Levels, severity, exit codes

Levels (`checks.Level`): `pass`, `warn`, `fail`, `unknown` (could not
inspect, never a pass), `skip` (not applicable), `info` (no judgement).
Severity comes from the catalog, never from the check: `critical`, `high`,
`moderate`, `low`, `info`.

`stackward audit` exits `0` when no result reaches `--fail-on` (default
`fail`; `warn` also counts warnings; `never` always exits 0), `1` when one
does, `2` when the tool itself failed. Unknown never trips the threshold.

## Add a collector

1. Pick the domain field in `facts.Facts` (`internal/facts/model.go`). Every
   domain is already declared there as a pointer to a placeholder type in its
   own file (`ssh.go`, `docker.go`, ...). **Do not edit `model.go`**; replace
   the placeholder struct in your domain file instead. If you truly need a new
   top level field, say so in your PR, because every slice shares that file.
2. In the same file, define the collector and register it from `init`:

   ```go
   type sshCollector struct{}

   func init() { Register(sshCollector{}) }

   func (sshCollector) Name() string    { return "ssh" }   // stable, lower case
   func (sshCollector) NeedsRoot() bool { return false }   // see below
   func (sshCollector) Collect(ctx context.Context, sys System, out *Facts) error {
       res, err := sys.Run(ctx, "sshd", "-T")
       ...
       out.SSH = &SSH{...}
       return errors.Join(errs...) // data plus error = partial, kept
   }
   ```

3. Rules:
   - Touch the host only through `sys` (`ReadFile`, `ReadDir`, `Meta`, `Run`,
     `LookPath`, `Identity`). `Run` takes a bare command name, uses a fixed
     PATH and the C locale, no shell, and caps output. Only inspection
     commands; list every command you run in your PR description.
   - Write only your own domain field(s) of `out`. The runner merges each
     collector's private `Facts` and fails a collector that sets a field
     another collector already set.
   - `NeedsRoot() true` makes the runner skip you without root (status
     `skipped`, reason "needs root; run with sudo for full coverage"). If you
     can degrade instead (for example parse config files when `sshd -T` is
     denied), return false and record in your domain how you got the data
     (for example `Source: "files"`), so checks can say `unknown` where the
     fallback is not good enough.
   - Record absence explicitly (`Installed: false`) rather than leaving the
     domain nil: nil means "not inspected", which checks report as unknown.
   - Honour `ctx`; the default per collector timeout is 15 s (`--timeout`).
   - Never read secret contents (use `sys.Meta`); strip secrets at the source
     (Docker `Config.Env`, `Cmd`, cloudflared `--token`). Redaction on output
     is a safety net only.
   - Heavy parsers may live in a leaf subpackage (`internal/facts/dockerapi`,
     `internal/facts/paas`). A subpackage must not import `facts` (cycle);
     it returns its own types, which the domain struct can embed or copy.
4. Test with `fakeSystem` (`internal/facts/fake_test.go`): an in memory tree
   plus canned command results keyed by `"name arg1 arg2"`.

## Add a check

1. Add the catalog entry first, in `internal/catalog/data/<group>.json`
   (`ssh.json` for group `SSH`; create the file if your group has none yet,
   with `{"group": "SSH", "checks": [...]}`). Required: `id`, `title`,
   `severity`, `rationale`, `fix`. Optional: `verify`, `breaks`, `docs`,
   `needs_root`. Unknown fields fail the loader. Ids match
   `^[A-Z]{2,4}-[0-9]{3}$` and are never reused. All groups are already
   declared in `catalog.Groups`; do not edit that list.
2. Add the check to `internal/checks/<group>.go` (one file per group, for
   example `ssh.go`, `net.go`, `dkr.go`) and register it from `init`:

   ```go
   func init() { Register(Check{ID: "SSH-001", Run: checkPasswordAuth}) }

   func checkPasswordAuth(in Input) []Result {
       s := in.Facts.SSH
       if s == nil {
           return []Result{NotInspected(in.Facts, "ssh")}
       }
       ...
       return One(Fail, "password authentication is enabled", map[string]any{"passwordauthentication": "yes"})
   }
   ```

3. Rules:
   - Missing facts return `NotInspected(f, "<collector>")`: it explains
     skipped (needs root), failed and missing collectors in words.
   - Return at least one result. One result per subject: `host` (default),
     `container:<project>/<service>`, `port:<proto>/<port>`, `file:<path>`,
     `user:<name>`. Evaluate sorts by group, id, subject.
   - Evidence keeps a fixed set of keys per check id, values that encode to
     JSON. No secrets.
   - Use `in.Profile` for profile dependent rules; `profile.Unknown` must not
     turn into a pass.
   - No clock: compare against `in.Facts.CollectedAt`.
4. `TestCatalogMatchesRegistry` fails until the check and its entry both
   exist; `TestNilFactsNeverPass` fails if your check passes on empty facts.
   Write a table test next to the check (`<group>_test.go`).

## Add a fixture

1. `mkdir test/fixtures/<scenario>` and write `facts.json` (shape of
   `facts.Facts`; `stackward audit --dump-facts` produces it). Use only
   `example.com` names and documentation addresses. `collected_at` is fixed,
   so time based checks are stable.
2. `go test ./test/ -update` writes `expected.json`. Review it line by line.
3. `go test ./test/` compares byte for byte and validates against
   `schema/report.v1.json`.

Name scenarios after what they show (`docker-public-redis`,
`tailscale-needs-login`), and prefer one new fixture per behaviour over
editing someone else's.

## Probe and the PRB checks

`stackward probe` runs on another machine, so it has no host `Facts`. It
fills `probe.Facts` (resolved addresses per family, every TCP connect, SSH
banners, raw IP HTTP answers, the `--hostname` redirect chain) and judges
them with the PRB checks from `probe.Checks()`. Those are deliberately not in
`checks.Register`: an audit can never see probe facts, so listing PRB in every
audit report would only add unknown rows and change every golden fixture.
They still return `checks.Result` and go through `checks.EvaluateChecks` and
`report.Build`, so probe reports use the same levels, renderers and
`report.v1` schema; the optional `probe` object in the report says what was
probed. When a resolved address is loopback or one of this machine's own
interface addresses (`probe.Options.LocalAddrs` is the test seam), probe
warns before probing and sets the optional `probe.self_target` field. Probe golden scenarios live in `internal/probe/testdata/<scenario>/`
(`go test ./internal/probe -update`).

## Report contract

`schema/report.v1.json` is the contract for consumers (CI, other tools).
Adding an optional field is fine; renaming or removing one, or changing its
meaning, needs `report.v2`. When you change `internal/report` types, change
the schema in the same commit; `TestJSONMatchesSchema` and the golden tests
validate both ways (the validator rejects unknown keywords, so the schema
cannot drift beyond what is checked).

The hostname is hashed (`sha256:` plus 16 hex digits) unless
`--show-hostname`. `coverage` counts results (not checks) as checked
(pass, warn, fail, info), unknown and skipped, plus `root`, the sandbox
state and every collector's status.

## Sandbox

The run order of `audit` (also with `--dump-facts`) and `tui`:

1. Parse flags; open `--out` (and for `tui` the terminal); read `--facts`
   or `--report`.
2. For a live audit with the sandbox on, take the socket ownership
   snapshot (`facts.SnapshotSocketOwners`, read only, bounded) and attach
   it to the host System (`facts.WithSocketOwners`).
3. `sandbox.Apply`.
4. Run the collectors; the listeners collector joins socket inodes to the
   snapshot (it asks for it through `facts.SocketOwnerSource`, which test
   fakes simply do not implement).
5. Evaluate checks and write the report.

The snapshot exists because the sandbox scopes ptrace access, which reading
another process's `/proc/<pid>/fd` needs, so after step 3 no socket owner
can be named. [safety.md](safety.md#read-before-the-sandbox) describes what
it reads.

`sandbox.Apply` runs after the CLI has opened `--out` and read `--facts`, and
before any collector. On Linux with Landlock it removes every filesystem write
right (except writing `/dev/null`) from all threads and child processes, and on
Landlock ABI 4+ denies TCP bind and connect. Unix sockets (Docker, Tailscale)
keep working. It needs a cgo free build (`CGO_ENABLED=0`, as released); a cgo
build reports `unavailable`. A collector whose command needs to write
somewhere will fail under the sandbox and report that, which is the point.

Tests must never call `Apply` in the test process (it cannot be undone):
CLI tests pass `--no-sandbox`, and the sandbox test re-executes itself.

## Redaction

`report.Build` passes every message, subject, evidence value and collector
error through `redact`; `audit.DumpFacts` redacts the whole facts document
and hashes the hostname. Add a pattern to `internal/redact` with a test
that plants a fake secret assembled at run time (so secret scanners do not
flag the source).

## Who owns what (wave 1)

| Slice | Files it owns |
|---|---|
| SSH | `internal/facts/ssh.go`, `internal/checks/ssh.go`, `internal/catalog/data/ssh.json` |
| Firewall and exposure | `internal/facts/firewall.go`, `internal/facts/listeners.go`, `internal/profile/` (`Infer`), `internal/checks/net.go`, `internal/catalog/data/net.json` |
| Docker | `internal/facts/docker.go` (+ `internal/facts/dockerapi/`), `internal/checks/dkr.go`, `internal/catalog/data/dkr.json` |
| Users, updates, kernel, journald, time, disk | `internal/facts/{users,updates,sysctl,journal,clock,disk}.go`, `internal/checks/{usr,upd,krn,log}.go`, SYS-004 and SYS-005 in a new `internal/checks/sys_host.go` plus entries appended to `internal/catalog/data/sys.json` |
| Tailscale, cloudflared, CrowdSec, fail2ban | `internal/facts/{tailscale,cloudflared,crowdsec,fail2ban}.go`, `internal/checks/{ts,cf,cs}.go`, `internal/catalog/data/{ts,cf,cs}.json` |
| PaaS and secrets | `internal/facts/{paas,secrets}.go` (+ `internal/facts/paas/`), `internal/checks/{paas,sec,bak}.go`, `internal/catalog/data/{paas,sec,bak}.json` |
| Release pipeline | `.goreleaser.yaml`, `.github/workflows/release.yml`, `scripts/get.sh`; sets `internal/version.Version` via ldflags |
| Docs | `docs/` (threat model, generated check pages), catalog prose fields |

Everyone may add fixtures under `test/fixtures/<new-scenario>/`. Shared files
that should not need edits: `internal/facts/model.go`, `collector.go`,
`system.go`, `internal/checks/check.go`, `internal/catalog/catalog.go`,
`internal/report/*`, `schema/report.v1.json`, `.github/workflows/ci.yml`.
