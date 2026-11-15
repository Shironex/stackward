# stackward

stackward audits a self hosted Linux server the way it is actually run in
practice: Docker, a PaaS such as Coolify or Dokploy, Traefik, a Cloudflare
Tunnel or Tailscale in front, and CrowdSec or fail2ban on top. It answers
"what is actually exposed and what is misconfigured" with a stable check id
and evidence for every finding.

**Status: pre-alpha.** The skeleton is in place (CLI, facts model, check
registry, catalog, report format, sandbox, golden tests) with a handful of
system checks. The SSH, firewall, Docker, Tailscale, tunnel, CrowdSec and PaaS
checks are being built. Do not rely on it yet.

## The read only promise

Version 0.1 only reads. stackward:

- writes no file except the report you ask for with `--out`;
- confines itself with a Landlock sandbox where the kernel supports it
  (Linux 5.13+): no file writes, and no TCP connections on newer kernels.
  The report header says whether the sandbox was applied;
- talks to Docker over its Unix socket with GET requests only;
- never runs a command that changes state;
- never reads the contents of secret files, only their permissions;
- redacts secret shaped values from everything it prints or dumps;
- sends nothing anywhere. No telemetry, ever.

`unknown` results mean "could not inspect" and are never counted as a pass.
Run without root for partial coverage; `sudo` gives full coverage.

What it reads, what it never does and what it does not cover:
[docs/threat-model.md](docs/threat-model.md). The plan for changing things
safely in a later version: [docs/safety.md](docs/safety.md).

## Build from source

Requires Go 1.26 or later.

```sh
git clone https://github.com/Shironex/stackward
cd stackward
CGO_ENABLED=0 go build -trimpath -o stackward ./cmd/stackward
./stackward audit
sudo ./stackward audit --json --out report.json
./stackward explain SYS-002
```

Build with `CGO_ENABLED=0`: the Landlock sandbox needs a cgo free binary.
Signed release binaries will follow.

## Usage

```
stackward audit [--json | --md] [--out FILE] [--fail-on fail|warn|never] [--all]
stackward audit --md --out report.md  Markdown for an issue or handover note
stackward audit --dump-facts          redacted facts, for bug reports
stackward audit --facts FILE          evaluate a saved facts file
stackward explain [id]                explain a check, or list them all
stackward tui [--report FILE | --facts FILE]
                                      browse the findings in the terminal
stackward version
```

Exit codes: `0` no finding at or above `--fail-on` (default `fail`), `1`
findings, `2` the tool itself failed.

The JSON report follows [schema/report.v1.json](schema/report.v1.json).

### Browsing findings

`stackward tui` runs the same audit as `stackward audit` (same flags, same
sandbox, same read only promise) and opens a findings browser: results by
group, worst first, with the full explanation, fix and verify steps of the
selected check beside them. `--report report.json` browses a saved
`--json` report instead, `--facts facts.json` a saved facts file.

Keys: arrows or `j`/`k` move, `tab` switches between the list and the
detail pane, `/` filters, `l` cycles the level, `a` shows passing and
skipped results, `g` jumps to the next group, `y` copies the fix, `?` lists
every key, `q` quits. Copying uses the terminal clipboard sequence (OSC 52)
and only happens when you press `y`; the browser writes no file. It needs
at least 60x16 and is laid out for 80x24. `NO_COLOR` turns colors off.

### Reading a report

Every result is `pass`, `warn`, `fail`, `unknown` (could not inspect, never a
pass), `skip` (does not apply) or `info`. There is no score: read the counts
and the coverage block, which says how many checks were unknown, whether root
was available and whether the sandbox was applied. Fix the highest severity
`fail` results first.

Each check has a stable id. `stackward explain SYS-002` prints why it matters,
how to verify it by hand, how to fix it and what the fix can break. The same
text is in the [check pages](docs/checks/index.md).

Share a report or a `--dump-facts` file in a bug report only after reading
it. Secret shaped values are masked and the hostname is hashed by default,
but you are the last reviewer.

## Contributing and security

See [CONTRIBUTING.md](CONTRIBUTING.md) and
[docs/architecture.md](docs/architecture.md); the
[threat model](docs/threat-model.md) explains the safety rules. Report vulnerabilities privately
as described in [SECURITY.md](SECURITY.md).

Report a wrong verdict or propose a check with the
[issue forms](https://github.com/Shironex/stackward/issues/new/choose).
Participation is covered by the [code of conduct](CODE_OF_CONDUCT.md).

Licensed under the [Apache License 2.0](LICENSE).
