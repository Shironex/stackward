# Design: audit over ssh

Status: built (issue #36). The user facing safety story is in
[threat-model.md](../threat-model.md#auditing-other-hosts-over-ssh).

## Problem

Auditing several servers means logging into each one, copying the binary,
running it and collecting the output by hand. `stackward audit --ssh` does
that for one host or many and prints one fleet report.

## Shape

```
stackward audit --ssh [audit flags] [--ssh-sudo] [--ssh-binary PATH]... \
    [--ssh-parallel N] [--ssh-timeout D] [--] HOST...
stackward audit --ssh-hosts FILE [flags]
```

Hosts come after the flags (the standard `flag` package stops at the first
argument), or from a file with one host per line and `#` comments. Both can
be combined; duplicates keep their first place. `--json`, `--md`, `--out`,
`--fail-on`, `--profile`, `--timeout`, `--show-hostname`, `--all`, `--info`,
`--group` and `--plain` keep their meaning. `--facts`, `--dump-facts`,
`--provider` and `--no-sandbox` are refused with `--ssh`.

Exit codes: 2 when any host could not be audited, otherwise the worst code of
the hosts' reports for `--fail-on`.

## Decisions

- **Use the user's ssh, no library.** An embedded SSH client would mean
  handling keys, agents, known hosts and jump hosts, and would be a large new
  dependency in a tool users run as root. The `ssh` binary on `PATH` already
  does all of it with the user's config. stackward never sees a secret.
- **Batch mode and no forwarding.** `-T -a -x -o BatchMode=yes -o
  ClearAllForwardings=yes -o ConnectTimeout=15` are forced on top of the
  config: no prompts (parallel prompts cannot be answered, and a password
  would pass through our process), unknown host keys fail, nothing from this
  machine is forwarded to the audited host.
- **One stream, not scp.** The binary is streamed on ssh's standard input
  into `cat` on the remote side. No second tool, no remote path chosen by
  this side, and the script that creates the directory is the one that
  removes it. The remote command is `sh -c '<one line>'`: one line with no
  single quote, so any login shell (sh, bash, zsh, fish, csh) hands it to
  `sh` unchanged.
- **Architecture first.** `uname -m` runs before anything is copied; it is
  also the connection test. The binary's architecture is read from its ELF
  header, so a darwin build is never copied and a mixed fleet can pass
  `--ssh-binary` once per architecture. A mismatch names the release
  archive, for example `stackward_0.4.0_linux_arm64.tar.gz`.
- **Cleanup twice.** The remote `EXIT` trap removes the directory however
  the script ends; HUP, INT, TERM and PIPE are turned into an exit so the
  trap runs when the connection drops. The script prints the directory on
  stderr; when the run fails, the local side opens one more connection and
  removes it (only a path of the form `/.../stackward.XXXXXXXXXX`), with its
  own 30 second limit, also after Ctrl-C.
- **sudo only on request.** `--ssh-sudo` runs `sudo -n`: no password prompt,
  so it works only where sudoers allows it, and fails with a clear error
  elsewhere. Without it the remote audit runs as the login user and the
  report says which checks needed root, as any non root audit does.
- **The report is data from another machine.** It is parsed as
  `report.v1` with a size cap, and every string is stripped of control and
  bidi characters before rendering. The remote audit already redacted it.
- **No local sandbox.** ssh needs the network and writes its own files, so
  the fleet side cannot run under Landlock. It collects nothing locally.
- **Guard entry.** `internal/fleet/ssh.go` is the one new place allowed to
  start a program (`stackward-guard` allowlist and the depguard `os/exec`
  rule). Everything else in `internal/fleet` is plain Go.

## Package layout

| File | Role |
|---|---|
| `internal/fleet/hosts.go` | host validation, hosts file, dedup, the 256 host cap |
| `internal/fleet/arch.go` | `uname -m` and ELF architecture, binary choice, release asset name |
| `internal/fleet/script.go` | the remote script, the remote arguments, the cleanup command |
| `internal/fleet/ssh.go` | the only exec: `ssh <fixed options> -- HOST COMMAND` |
| `internal/fleet/fleet.go` | per host flow, bounded parallelism, error wording, caps |
| `internal/fleet/sanitize.go` | cleaning strings that came back from a host |
| `internal/report/fleet.go` | `fleet.v1` type and the text, Markdown and JSON renderers |
| `internal/cli/fleet.go` | the `--ssh` flags and the run |

Tests put `internal/fleet/testdata/fakessh.sh` on `PATH` as `ssh`: it plays
the remote host by running the remote command through `sh -c` with its own
`TMPDIR`, so the real script (mktemp, trap, upload, cleanup) runs in the
tests.

## Open questions and the answers chosen

- A `noexec` `/tmp` on the host makes the copied binary fail to start. The
  error says so; a flag for another remote directory can follow if users hit
  it. Chosen: no flag yet, keep the one remote path decided by `mktemp`.
- Exit code when some hosts fail and others have findings: 2 (an error wins),
  so a cron job notices a host that was not audited.
- The host label in the report is the name as given to ssh (an alias or
  `user@host`), not the remote hostname, which stays hashed unless
  `--show-hostname`.
