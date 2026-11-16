# Drift: diff and --baseline

A server that was fine last month may not be fine now, and one audit cannot
show what changed. `stackward diff` compares two saved reports of one host;
`stackward audit --baseline` audits and compares the result with a saved
report in one step, with an exit code for CI.

```sh
sudo stackward audit --json --out base.json        # once, when the host is as it should be
sudo stackward audit --json --out now.json         # later
stackward diff base.json now.json                  # text; --json or --md for the other formats

sudo stackward audit --baseline base.json          # audit and diff in one run (CI)
```

## What a diff shows

Results are matched across the two reports by check id and subject (the
n-th result with a check and subject in one report with the n-th in the
other). The diff lists:

- **Drift**: changes on the host that matter whatever their level.
- **Added**: a result in the new report only.
- **Removed**: a result in the baseline only. It reads "no longer
  reported", never "fixed": the container or user may simply be gone.
- **Changed**: a result in both whose level changed, or whose waiver state
  changed (accepted, expired, level-exceeded, renewed, or no waiver any
  more). A result whose level becomes `pass` is the only one described as
  fixed.

A result appearing or disappearing is listed only when it is a `fail`,
`warn` or `unknown`, or a waiver matched it; a new container's passing
checks are not news. For the same reason a level change between `pass`,
`info` and `skip` is not listed.

A change is a **new finding** when the result is an open `fail` or `warn`
now (no waiver accepts it) and was not open in the baseline, or was open at a
milder level (a `warn` that became a `fail`). A waiver that expired makes
its finding new again.

### Waivers

A waiver never makes a finding look fixed. When a finding becomes accepted,
the diff says "now accepted by a waiver until DATE, still warn"; the level
stays the real one in every format, and an accepted finding is never a new
finding. When the waiver expires the finding is back, listed as a change of
waiver state and counted as a new finding. Renewing a waiver (a later
expiry) is listed too, so the decision shows in the diff.

## Drift kinds

Drift is read from the evidence of four checks, the same evidence the
report prints:

| Kind | Check | Drift when |
|---|---|---|
| `listener` | NET-004 | a port listens beyond loopback (`class` is not `loopback`) and the baseline had no result for it, or it now listens on a wildcard or public address and did not before. A loopback only listener is reachable from the host alone and is not drift. |
| `authorized-key` | SSH-014 | a user's `fingerprints` holds a fingerprint the baseline did not have for that user. If either report has no fingerprints (a report from an older stackward), a `keys` count that grew is reported instead. |
| `sudoer` | USR-004 | a principal in a `nopasswd` list that no sudoers file of the baseline had. Moving a rule to another line or file is not drift. |
| `root-container` | DKR-020 | a container whose `root` is true and was false, or is new. |

Fingerprints are the OpenSSH `SHA256:` fingerprints `ssh-keygen -l`
prints; stackward keeps them, never the key or its comment.

A waiver does not silence drift. To accept a change, make the current report
the new baseline.

### Lost coverage

Drift can only be seen where the drift checks can look. When one of the four
checks judged the baseline (a `pass`, `info`, `warn` or `fail` result) and
in the new report has only `unknown` or `skip` results, or none, the diff
lists it under **Lost coverage** (`coverage_lost` in JSON): a new listener,
key, sudoer or root container of that kind would not show. Running without
root, a collector that failed and Docker becoming unreachable are the usual
causes. Lost coverage trips `--fail-on-drift` like drift does. It is judged per check,
not per subject: a check that still judges some subjects (one user's keys
readable, another's not) has not lost coverage, and the subjects it cannot
read show as `unknown` results in the changes.

**Limits.** USR-004 reports NOPASSWD rules, so a new sudoer with a password
(a user added to the `sudo` group) is not drift; it shows only if another
check reports it. A run without root sees less than one with root: the
diff notes when only one side ran as root, because results can then come
and go because of visibility, not change.

**Identity.** Drift follows the subject a check gives. A listener is
tracked by protocol and port, so a different program on a port that was
already listening is not a new listener (its process shows in the report).
A container is tracked by its project and service name, so a container
replaced under the same name is the same container: it becomes drift only
when it starts running as root. An authorized key is tracked by user and
fingerprint, and a sudoer by principal across all sudoers files.

## Commands and flags

```
stackward diff [flags] OLD.json NEW.json
stackward audit --baseline OLD.json [--fail-on-drift any] [audit flags]
```

| Flag | Meaning |
|---|---|
| `--format text\|json\|md`, `--json`, `--md` | Output format. JSON follows [schema/diff.v1.json](../schema/diff.v1.json). |
| `--out FILE` | Write the diff to FILE instead of stdout. A FILE that is one of the reports (or the `--baseline`) is refused before anything is truncated. |
| `--fail-on-drift any\|fail\|drift\|never` | When to exit 1. `any` (default): a new `fail` or `warn` finding, any drift, or lost coverage. `fail`: a new `fail` finding, any drift, or lost coverage. `drift`: drift or lost coverage only. `never`: always 0. |
| `--force-host` | Compare reports whose hostname hashes differ, or where one has none. |
| `--no-sandbox` | `diff` only: do not apply the Landlock sandbox (debugging only). |

With `--baseline`, `audit` prints the diff instead of the report, in the
format `--format` names, to stdout or `--out`; `--textfile` still writes the
metric of the new report. To keep the new report as the next baseline, run
`stackward audit --json --out FILE` as well. The text layout flags of the
report (`--all`, `--info`, `--group`, `--plain`) do not apply to the diff. `--baseline`
does not go with `--ssh`: one baseline names one host. For a fleet, save
each host's report and run `stackward diff` per host.

### Exit codes

| Command | 0 | 1 | 2 |
|---|---|---|---|
| `stackward diff` | nothing reaches `--fail-on-drift` | drift, lost coverage or a new finding reaches it | error: bad flags, an unreadable or invalid report, reports from different hosts without `--force-host` |
| `stackward audit --baseline` | nothing reaches `--fail-on-drift`, and no result reaches `--fail-on` if `--fail-on` was given | either of those | error, as for `diff` and `audit` |

Without an explicit `--fail-on`, `audit --baseline` ignores findings that
were already in the baseline: that is what a baseline is for. Give
`--fail-on fail` to fail on every open `fail` as well.

A CI job that fails when the host drifts:

```sh
sudo stackward audit --baseline /var/lib/stackward/base.json --md --out drift.md
```

## Safety

The two reports are untrusted input. A report can come from another
machine, an old artifact store or a shared directory, and its text ends up
in a terminal, a CI log or a Markdown issue.

- `diff` reads only the two files and writes only `--out`: no host access,
  no network, no command. Both files and `--out` are opened first, then the
  Landlock sandbox is applied, like the other offline commands.
- A report file is opened without blocking and must be a regular file, so a
  FIFO or a device cannot hang the run. It is read up to 32 MiB.
- It must be one JSON document that validates against
  [schema/report.v1.json](../schema/report.v1.json) (embedded in the
  binary): unknown fields, wrong types and check ids that do not match
  `^[A-Z]{2,4}-[0-9]{3}$` are refused. Facts files, plans and probe reports
  are refused with a message that names them.
- Every string in it, object keys included, is cleaned of control
  characters, invisible format characters (Unicode Cf, such as bidi
  overrides) and line separators, which become U+FFFD, and then goes
  through the same secret redaction as a report. A terminal escape in a
  container name cannot reach your terminal.
- Markdown escapes free text (an `@name` too, so a pasted diff notifies
  nobody) and keeps subjects and values in code spans, as the report
  renderer does; check ids are links only because the schema
  pinned their shape.
- Reports from different hosts (by hostname hash) are refused unless
  `--force-host` is given. A report written with `--show-hostname` is
  matched by the hash of its hostname, and the diff prints only the hash.
- The diff can be only as trustworthy as the baseline: anyone who can
  rewrite it can hide drift. Keep it where only the CI job or root can
  write it.
