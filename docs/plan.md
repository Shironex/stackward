# stackward plan

`stackward plan` writes down the exact changes that would fix the audit's
findings, and changes nothing. It is part of the upcoming 0.2 and is not in a
release yet; `stackward apply`, which will run a plan, does not exist yet.

```
stackward plan [--out FILE] [--json | --emit-script]
stackward plan --facts FILE           plan from a saved facts file
stackward plan --report FILE --facts FILE
                                      plan from a saved report and the facts of the same audit
```

```sh
sudo stackward plan                        # audit this host, print the summary
sudo stackward plan --out plan.json        # also save the plan.v1 JSON
sudo stackward plan --emit-script > fix.sh # the same plan as a shell script
```

## What it does

1. It runs the same audit as `stackward audit` (same flags: `--profile`,
   `--timeout`, `--show-hostname`, `--no-sandbox`), under the same Landlock
   sandbox, or reads a saved facts file or report instead.
2. Every step generator looks at the check results and the facts and either
   plans a step or says why not.
3. It prints a summary (default), the plan JSON (`--json`) or a shell script
   (`--emit-script`), and writes the plan JSON to `--out` when given.

The only file it writes is `--out`, opened before the sandbox, with mode 0600,
never through a symlink. Steps whose checks already pass are left out of
`steps` and listed in `skipped`.

| Flag | Meaning |
|---|---|
| `--out FILE` | write the plan.v1 JSON to FILE |
| `--json` | print the plan JSON instead of the summary |
| `--emit-script` | print the plan as a shell script (see below) |
| `--facts FILE` | plan from a saved facts file (`stackward audit --dump-facts`) |
| `--report FILE` | plan from a saved report.v1 JSON file |
| `--profile P` | ingress profile, as for audit (not with `--report`) |
| `--show-hostname` | show the hostname instead of its hash |
| `--no-sandbox` | do not apply the Landlock sandbox (debugging only) |

Exit codes: 0 when the plan was written, 2 on an error.

### Planning from a report

A report says what is wrong but holds no file contents, so a report alone
plans nothing: every step is skipped as `unknown`. Give the facts of the same
audit with `--facts` to get the steps. stackward refuses a report and a
facts file that come from different audits (another time or another host).

## Risk classes

Every step has one of three risk classes.

| Class | What it means | Example |
|---|---|---|
| `safe` | Changes a setting that cannot cut you off or stop your services; may restart a logging daemon. | journald size cap, sysctl hardening drop-in |
| `networking` | Can interrupt traffic: restarts Docker, so containers stop and start. Always says what it restarts. | Docker log rotation in `daemon.json` |
| `access-critical` | Touches SSH, the firewall or users, where a mistake can lock you out. Apply will run these only inside a transaction with a rollback timer and a confirm from a new SSH session. | none yet |

Some steps are **opt in** (`opt_in: true`): apply will run them only when you
select them by id. The Docker step is opt in because of its restart.

## Steps in this version

| Step id | Fixes | Class | What it changes |
|---|---|---|---|
| `journald-cap` | LOG-001 | safe | creates `/etc/systemd/journald.conf.d/90-stackward-journal-cap.conf` with `SystemMaxUse=1G`, restarts systemd-journald |
| `sysctl-hardening` | KRN-002, KRN-003, KRN-004 | safe | creates `/etc/sysctl.d/90-stackward-hardening.conf` with only the values the checks find off baseline, loads that file with `sysctl -p` |
| `docker-log-rotation` | DKR-031 | networking, opt in | merges `log-driver` and `log-opts` (`max-size` 10m, `max-file` 3) into `/etc/docker/daemon.json`, keeping every other key, checks the result with `dockerd --validate`, restarts Docker |

Rules they follow:

- The main configuration files are never edited where a drop-in exists.
  Docker reads no drop-ins, so `daemon.json` is merged: keys stackward does
  not set keep their order and formatting, an existing `max-file` is kept,
  and a file that is not valid JSON or has a duplicate key is left for you
  to fix (`manual`).
- `net.ipv4.ip_forward` and the other settings Docker needs are never set.
  `/etc/ufw/sysctl.conf` and `/etc/sysctl.conf` are never edited; when they
  would undo a value, the step says so in a note.
- `kernel.unprivileged_bpf_disabled = 1` cannot be lowered again without a
  reboot; the step says so and its undo does not try.

## The plan file (plan.v1)

The JSON contract is [schema/plan.v1.json](../schema/plan.v1.json). Adding an
optional field keeps `plan.v1`; renaming or removing one, or changing its
meaning, needs `plan.v2`.

```json
{
  "schema": "stackward.plan.v1",
  "tool": { "name": "stackward", "version": "..." },
  "generated_at": "2026-03-01T12:00:00Z",
  "host": { "hostname_hash": "sha256:...", "os": "Ubuntu 24.04.1 LTS" },
  "source": { "kind": "live", "facts": true, "report": { "schema": "stackward.report.v1", "tool_version": "...", "generated_at": "...", "profile": {...}, "summary": {...} } },
  "sandbox": { "state": "landlock", "abi": 4, "network": true },
  "summary": { "steps": 3, "safe": 2, "networking": 1, "access_critical": 0, "opt_in": 1, "restarts": ["systemd-journald", "docker"], "skipped": 0 },
  "steps": [ ... ],
  "skipped": [ { "id": "...", "title": "...", "fixes": ["..."], "kind": "passing", "reason": "..." } ]
}
```

- `generated_at` is when the facts were collected, so the same input always
  gives the same plan. The hostname is hashed unless `--show-hostname`, as in
  the report.
- `source` names what the plan was made from and the report it answers: its
  schema, the stackward version that wrote it, its time, profile and summary.
- `steps` are ordered by risk class (safe first), then id.
- `skipped` kinds: `passing` (the checks pass or do not apply), `unknown`
  (facts or results missing), `manual` (a step would not fix it; a person
  has to look), `refused` (a policy vetoed the step).

Each step:

| Field | Meaning |
|---|---|
| `id` | stable step id, the same across runs and releases |
| `fixes` | the check ids it makes pass |
| `risk`, `opt_in` | risk class; whether apply runs it only when selected |
| `restarts` | services it restarts, in order |
| `touches` | everything it changes, as `file:`, `sysctl:`, `service:` or `docker-daemon:` targets |
| `edits` | file changes, applied in order before `commands` |
| `commands` | programs it runs, as argument vectors (no shell), each with a `why` |
| `undo` | how to reverse it by hand, with commands |
| `notes` | caveats to read first |

Each edit has `path`, `action` (`create`: the file must not exist; `replace`:
the file must still hold exactly what the audit saw), `old` and `new`
content, their SHA-256 (`old_sha256`, `new_sha256`), a unified `diff`, the
`mode` of a created file, and optionally `validate`, a command that checks
the staged new file before it replaces the old one.

The old content and its hash are a precondition: the script below (and apply,
later) refuses to touch a file that changed since the audit.

### Redaction

A plan goes through the same redaction as the report: secret shaped values
are masked in every message, command and file content. The hashes are taken
before redaction, so they still say what the host holds. An edit where
something was masked is marked `"redacted": true`; such a plan cannot be
applied from its own text (the script refuses that step), so plan again on
the host and look at the file yourself.

## The script (`--emit-script`)

The script is the plan written as POSIX shell, for people who prefer to read
and run the commands themselves. stackward never runs it. It:

- starts with `set -eu` and a comment block per step: id, risk class, the
  checks it fixes, restarts, notes and the undo;
- has one function per step, in plan order, called at the end; opt in steps
  are commented out there, so you choose them by removing the `# `;
- refuses to create a file that exists, and refuses to replace a file whose
  SHA-256 is no longer the one in the plan;
- keeps `FILE.orig` the first time it replaces a file, writes the new content
  to `FILE.stackward-new` with a quoted here document (no expansion),
  validates it where the step says how, and only then moves it into place.

Run it as root on the host it was planned for, and read it first.
