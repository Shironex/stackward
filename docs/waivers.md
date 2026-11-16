# Waivers

Some findings are accepted on purpose: a web server that is public by
design, a sudoer the team knows about. Left alone they show up as warnings
on every run, and a report where the same rows are always red teaches its
readers to stop reading it. A waiver records the decision instead: this
check, on this subject, is accepted, for this reason, until this date.

A waiver never hides a finding and never changes its evidence. It only
changes how the finding is counted and shown.

## The file

`stackward audit` and `stackward tui` read `.stackward.yml` from the working
directory when it exists, or the file named with `--waivers FILE` (which must
exist).

```yaml
version: 1
waivers:
  - check: NET-004
    subject: port:tcp/443
    reason: public web server by design, behind the CDN since 2026-01
    expires: 2027-01-31
  - check: USR-005
    subject: user:deploy
    reason: "the CI deploy user needs Docker; reviewed in OPS-12"
    expires: 2026-12-31
  - check: USR-004
    subject: file:/etc/sudoers.d/deploy
    reason: the deploy tool rewrites it; fix tracked in OPS-14
    expires: 2026-04-30
    level: fail
```

Every waiver needs the first four keys; `level` is optional:

| Key | What it is |
|---|---|
| `check` | The check id, as `stackward explain` lists it. |
| `subject` | The exact subject of the result: `host`, `port:tcp/443`, `container:<project>/<service>`, `file:<path>`, `user:<name>`. Copy it from the JSON report or the meta line under the result. There are no wildcards: a waiver accepts one result, not a class of them. |
| `reason` | Why the finding is accepted. It is printed next to the finding, so write it for the next reader. |
| `expires` | The last day the waiver holds, as `YYYY-MM-DD` (UTC). |
| `level` | The worst result the waiver accepts: `warn` (the default) or `fail`. |

Two waivers for the same check and subject are an error.

### Why there is a level

A check can find more than one problem on the same subject. USR-004 warns
about a NOPASSWD line in a sudoers file, and fails when the same file
becomes writable by others, which is a root escalation. A waiver written
for the warning must not quietly accept the fail that appears later, or a
CI job stays green through the worst change. So a waiver accepts warnings
only, unless it says `level: fail`. A fail under a waiver for a warning
counts as a fail, trips `--fail-on`, carries a note that its waiver does
not cover it, and the waiver is listed for review as `level-exceeded`.

## What a waiver does

Only `fail` and `warn` results can be accepted, and only up to the
waiver's level. A waiver matches the result with its check id and the exact
subject the check produced (before secret redaction, so two subjects that
redact to the same text never share a waiver). A matching result:

- keeps its level, severity, message and evidence in every output;
- is shown as **accepted**, with the reason and the expiry: in its own
  `ACCEPTED` section of the text report, an `Accepted` table in Markdown, an
  `ACCEPTED` row in `stackward tui` and a `waiver` object on the result in
  JSON;
- is counted as `accepted` in the summary instead of `fail` or `warn`, so it
  no longer trips `--fail-on`; the coverage line still counts it as checked
  and says how many results a waiver accepted.

The expiry is judged against the time the facts were collected, so replaying
a facts file with `--facts` gives the same answer on any day.

## Waivers that do not apply

A waiver that does not apply is reported, never ignored. The header names
how many waivers are in each state and a `WAIVERS TO REVIEW` section (text),
a `Waivers to review` table (Markdown) or the header line of `stackward tui`
lists them:

| State | Meaning | What to do |
|---|---|---|
| `long-lived` | It still applies, but expires more than a year after the audit. | Check the date is meant; a shorter one gets the decision looked at again sooner. |
| `expired` | The date has passed. The finding is back at its real level and carries a note that its waiver expired. | Fix the finding, or decide again and set a new date. |
| `level-exceeded` | The result is a fail and the waiver accepts warnings only. The fail counts. | Fix the fail, or add `level: fail` if the fail is accepted too. |
| `stale` | The check is known but no `fail` or `warn` result has this subject: the finding was fixed, or the subject is wrong. | Remove the waiver, or correct the subject. |
| `ambiguous` | More than one result has this check and subject, so the waiver accepts none of them. | Report it: a check should give one result per subject. |
| `unknown-check` | No check has this id. | Correct the id. |

## Why waivers have to expire

A waiver is a decision made under the conditions of the day: the service was
meant to be public, the account was needed, the fix was planned for next
quarter. Conditions change and nobody revisits a decision that never comes
back. A waiver without an end date turns into a permanent blind spot, which
is the noise problem again with the signal removed.

An expiry date forces the question back onto the report: when the date
passes, the finding returns at full strength and the waiver is listed for
review. Renewing it is one edit, made by someone who looked at it again.
Pick a date that matches how fast the reason can change: weeks for "fix
planned", months for "public by design". There is no hard limit, but a
waiver that expires more than a year after the audit is listed for review
as `long-lived` on every run, so a date far in the future does not go
unnoticed.

## Safety

The waivers file decides how findings are counted and so the exit code a CI
job sees, so stackward treats it as untrusted input:

- It is read before the Landlock sandbox is applied, like every other file
  stackward opens, and nothing is written.
- It is opened without following a symlink and without blocking (so a FIFO
  cannot hang the run); a symlink is refused. The opened file must be a
  regular file and not writable by group or others.
- It must be owned by the user running stackward, by root, or, when
  stackward runs as root under `sudo`, by the user who ran sudo (the uid in
  `SUDO_UID`, used only when it is a positive number). The same rule holds
  for the default `.stackward.yml` and for a file named with `--waivers`.
  Otherwise anyone who can write a file where root runs an audit (a shared
  checkout, a predictable `/tmp` path) could accept findings for it.
- It is read by a strict parser for exactly this shape, not by a general YAML
  library: block mappings and one list, plain or quoted single line values
  and comments. Anchors, aliases, tags, flow collections (`{}`, `[]` other
  than `waivers: []`), multi line values, more than one document, unknown
  keys and duplicate keys are refused with the line they are on. Control
  characters, invisible format characters (Unicode category Cf, such as bidi
  overrides and zero width joiners) and line or paragraph separators (Zl,
  Zp) are refused anywhere in the file, so a reason cannot read differently
  from what it is. The file is capped at 64 KiB, 500 waivers and 1024 bytes
  a line.
- Error messages name the line and the key, never the value.
- A subject that secret redaction would change is refused: a waiver never
  names a secret, and the report only ever prints redacted subjects.
- Any problem with the file is an error (exit code 2) that names the file and
  the line. A malformed waivers file never silently turns into no waivers.
- Reasons and subjects go through the same secret redaction as every other
  free text field of the report.
- `--dump-facts` does not read the waivers file, so a broken one never blocks
  a bug report.

### Running with sudo from your own checkout

If you keep `.stackward.yml` in a directory you own and run
`sudo stackward audit` there, the file belongs to you, the user who ran
sudo, and stackward reads it: sudo sets `SUDO_UID` to your uid, and a file
owned by that uid is accepted in a run as root.

A file owned by anyone else (another user, or a service account) is refused
whether it is the default file or named with `--waivers`. Make root or
yourself its owner with `chown`, if it really is meant for this run. If you
switch to another user with `sudo -u`, stackward does not run as root and
only accepts files owned by that user or by root. In every case the file
must not be writable by group or others.

`SUDO_UID` is trusted only because the effective user is root, which means
sudo set it. Never install stackward setuid or with file capabilities: then
any user could set `SUDO_UID` and have their own file accepted.

doas, run0 and pkexec do not set `SUDO_UID`, so under them a file owned by
the user who ran them is refused; chown it to root or name a root owned
copy with `--waivers`.

## In the JSON report

Waivers extend `report.v1` with optional fields only; a report without a
waivers file has exactly the shape it had before.

- `results[].waiver`: `{"status": "accepted" | "expired" | "level-exceeded",
  "level", "reason", "expires"}` on the `fail` or `warn` result a waiver
  matches. The result's `level` and `evidence` stay the real ones; `status`
  is what to read for the accepted state, and only `accepted` changes how
  the result is counted.
- `summary.accepted`: results counted as accepted instead of `fail` or
  `warn`.
- `coverage.accepted`: the same results, also counted in `coverage.checked`.
- `waivers`: every entry of the file in file order, with its `level`,
  `status` (`applied`, `long-lived`, `expired`, `level-exceeded`, `stale`,
  `ambiguous` or `unknown-check`) and `results`, the number of results with
  its check and subject at any level.

See [schema/report.v1.json](../schema/report.v1.json).
