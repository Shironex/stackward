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
```

Every waiver needs all four keys:

| Key | What it is |
|---|---|
| `check` | The check id, as `stackward explain` lists it. |
| `subject` | The exact subject of the result: `host`, `port:tcp/443`, `container:<project>/<service>`, `file:<path>`, `user:<name>`. Copy it from the JSON report or the meta line under the result. There are no wildcards: a waiver accepts one result, not a class of them. |
| `reason` | Why the finding is accepted. It is printed next to the finding, so write it for the next reader. |
| `expires` | The last day the waiver holds, as `YYYY-MM-DD` (UTC). |

Two waivers for the same check and subject are an error.

## What a waiver does

Only `fail` and `warn` results can be accepted. A matching result:

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
| `expired` | The date has passed. The finding is back at its real level and carries a note that its waiver expired. | Fix the finding, or decide again and set a new date. |
| `stale` | The check is known but no `fail` or `warn` result has this subject: the finding was fixed, or the subject is wrong. | Remove the waiver, or correct the subject. |
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
planned", months for "public by design".

## Safety

The waivers file decides how findings are counted and so the exit code a CI
job sees, so stackward treats it as untrusted input:

- It is read before the Landlock sandbox is applied, like every other file
  stackward opens, and nothing is written.
- It must be a regular file owned by the user running stackward or by root,
  and not writable by group or others. Otherwise anyone who can drop a
  `.stackward.yml` where root runs an audit could accept findings for it.
- It is read by a strict parser for exactly this shape, not by a general YAML
  library: block mappings and one list, plain or quoted single line values
  and comments. Anchors, aliases, tags, flow collections (`{}`, `[]` other
  than `waivers: []`), multi line values, more than one document, unknown
  keys and duplicate keys are refused with the line they are on. The file is
  capped at 64 KiB, 500 waivers and 1024 bytes a line.
- Any problem with the file is an error (exit code 2) that names the file and
  the line. A malformed waivers file never silently turns into no waivers.
- Reasons and subjects go through the same secret redaction as every other
  free text field of the report.
- `--dump-facts` does not read the waivers file, so a broken one never blocks
  a bug report.

## In the JSON report

Waivers extend `report.v1` with optional fields only; a report without a
waivers file has exactly the shape it had before.

- `results[].waiver`: `{"status": "accepted" | "expired", "reason", "expires"}`
  on every `fail` or `warn` result a waiver matches. `level` and `evidence`
  stay the real ones; `status` is what to read for the accepted state.
- `summary.accepted`: results counted as accepted instead of `fail` or
  `warn`.
- `coverage.accepted`: the same results, also counted in `coverage.checked`.
- `waivers`: every entry of the file in file order, with `status` (`applied`,
  `expired`, `stale` or `unknown-check`) and `results`, the number of
  `fail` or `warn` results it matched.

See [schema/report.v1.json](../schema/report.v1.json).
