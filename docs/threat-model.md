# Threat model

This page says what stackward reads, what it never does, what it does not
cover, and why it hands you findings instead of a score. It describes
version 0.1, which only audits. For the plan to change things in a later
version, see [safety](safety.md).

## Who this is for

A person running one to ten Linux servers with Docker, often with a platform
such as Coolify or Dokploy, a reverse proxy such as Traefik, a Cloudflare
Tunnel or Tailscale in front, and CrowdSec or fail2ban on top. You want an
honest answer to "what is actually exposed and what is misconfigured", and
you want to be able to run the tool on a production box without worrying
about what it does there.

## What stackward reads

Everything is read through one small interface that has no write method.

- **Files.** System configuration and state, for example `/etc/os-release`,
  the SSH server configuration, firewall rule files, sysctl settings and
  files under `/proc`. Reads have a size cap.
- **Metadata of secret files.** For files that hold secrets (platform
  `.env` files, private keys, registry credentials) stackward looks only at
  the owner, group and permission bits. It never opens them to read the
  contents.
- **Inspection commands.** Read only commands such as `sshd -T`, `ss`,
  `tailscale status` or `cscli bouncers list`. They run without a shell, with
  a fixed `PATH` and the C locale, and with capped output. Every command a
  collector runs is listed in the pull request that adds it, so the list can
  be reviewed.
- **Docker, through its Unix socket, with GET requests only.** Container
  environment variables, command lines and arguments are dropped before
  parsing, because they can hold passwords and tokens. Without access to the
  socket, every Docker check reports `unknown`.

- **The waivers file, as untrusted input.** `.stackward.yml` (or
  `--waivers FILE`) is read before the sandbox by a strict parser for its one
  shape, size capped, never through a symlink, and only if it is a regular
  file not writable by others and owned by the user running stackward, by
  root, or under sudo by the user who ran it (`SUDO_UID`), whether it is the
  default file or named with `--waivers`. A waiver accepts warnings unless it says
  `level: fail`, and matches the raw subject, so redaction cannot merge two
  subjects. A malformed file
  is an error, never ignored ([waivers.md](waivers.md#safety)).

Without root, checks that need root report `unknown` and the report says so.
Run with `sudo` for full coverage; the promises below hold either way.

## What stackward never does

In version 0.1 stackward:

- **writes nothing** to the system it audits. The only files it creates are
  the report you ask for with `--out` and the metric you ask for with
  `--textfile`;
- **makes no network calls during `audit`.** No telemetry, no update check,
  no lookups, no uploads. Only `probe`, which you run from another machine,
  touches the network (see below), the provider firewall fetch when you
  opt in with `--provider` (see [below](#the-provider-firewall-fetch)),
  and `audit --ssh`, which runs the audit on hosts you name through your own
  ssh client (see [below](#auditing-other-hosts-over-ssh));
- **never sends a non-GET request to Docker.** It cannot start, stop, create
  or remove anything;
- **never runs a command that changes state;**
- **never reads the contents of secret files**, only their metadata;
- **never prints raw secrets.** Anything printed or dumped passes through a
  redaction step that masks secret shaped values. This is a safety net: the
  collectors already avoid collecting secrets in the first place.

## The Landlock sandbox

The promises above should not rest on code review alone, so on Linux
5.13 and later stackward confines itself with Landlock before it collects
anything. Landlock removes every filesystem write right from the process and
all of its children, except writing to `/dev/null`. On kernels with Landlock
ABI 4 (Linux 6.7) or later, it also denies TCP bind and connect. Unix
sockets, such as the Docker socket, keep working.

This means a bug in a collector cannot turn into a write to your system:
the kernel refuses it. The report header always says what happened, as
`sandbox: landlock`, or one of `unavailable` (older kernel or another
operating system), `disabled` (you passed `--no-sandbox`) or `failed`. When
the sandbox is not active the tool is still read only by construction, but
you get less protection against mistakes, and the report tells you.

The sandbox needs the released build, which is made with `CGO_ENABLED=0`.

## What `probe` does on the network

`stackward probe <host>` is the outside view, run from a laptop or another
server. It is the only command that opens network connections, and it keeps
them to one host:

- it refuses CIDR blocks, ranges, lists and URLs: one host name or one IP
  address only;
- it resolves the name over IPv4 and IPv6 (at most four addresses per
  family) and makes plain TCP connects to a short fixed port list, plus at
  most 16 ports you add with `--ports`;
- it reads the first line an SSH server sends (at most 256 bytes) and sends
  one `GET /` to the raw IP on 80 and 443, without following redirects.
  That raw IP HTTPS request skips certificate verification, because an IP
  has no certificate name to match; the report says so;
- with `--hostname` it requests `https://<hostname>/` with normal
  verification and follows redirects on that same hostname only;
- it ignores proxy settings from the environment, so the answers come from
  the target itself;
- it prints that probing a host you do not own may be illegal, and needs a
  `y` on an interactive terminal or `--i-own-this` otherwise;
- it warns on stderr, before probing, when the target resolves to loopback
  (127.0.0.0/8, `::1`) or to an address of one of this machine's own
  interfaces. The run then goes ahead, but it is not an outside view, and the
  report carries `probe.self_target: true` and a note saying so.

On Linux the same Landlock sandbox applies, with TCP left allowed: probe
still cannot write anything but `--out`.

## The provider firewall fetch

`stackward audit --provider hetzner` or `--provider ovh` (and `plan` with
the same flag) reads
the cloud provider's firewall over its API ([provider-firewall.md](provider-firewall.md)).
It is the one exception to "no network during `audit`", and only when asked
for:

- without `--provider` no request is sent, and the PFW checks say the module
  was not requested;
- the client can only build GET requests, to a fixed list of provider API
  hosts (`api.hetzner.cloud`, `eu.api.ovh.com`, `ca.api.ovh.com`,
  `api.us.ovhcloud.com`), over HTTPS; any other host is refused before
  a connection is made, redirects are never followed and proxy variables are
  ignored, so only the provider sees the credential;
- every answer is capped at 1 MiB and the whole fetch has one 10 second
  timeout; a failure becomes `unknown`, never a pass and never a failed
  audit;
- the credential comes from an environment variable or a file per run,
  never from argv (no `--token` flag); a file must be a regular file owned by
  the user running the audit with mode 600 or stricter. It is not kept in
  facts, reports, dumps or logs, and the redaction pass masks it as a
  literal value as a safety net;
- the TLS stack honours `SSL_CERT_FILE`, `SSL_CERT_DIR` and `GODEBUG` from
  root's environment, so whoever controls those can redirect trust; see
  [provider-firewall.md](provider-firewall.md#tls-and-roots-environment);
- `stackward-guard` allows the network in one file of one package
  (`internal/provider/http.go`) for this.

**The fetch is not sandboxed.** Landlock denies TCP connect and cannot be
loosened once applied, so the fetch runs before the sandbox, in the same
window where `--out` is opened and the socket ownership snapshot is taken.
A bug in the client therefore runs without Landlock's protection. What
carries that risk instead is the client's small surface: GET only, fixed
hosts, no redirects, capped reads, no writes. The host collectors still run
after the sandbox is applied, so the rest of the audit keeps the full
protection, including the TCP connect denial. The alternative (leaving TCP
open for the whole audit, as `probe` does) would weaken every collector and
was rejected. If this trade is not acceptable to you, do not pass
`--provider`; a separate command that only fetches and writes facts for
`audit --facts` remains an option if a review asks for it.

## Scheduled runs

`stackward schedule --print` only prints a systemd service and timer; it
writes, enables and contacts nothing, so a bug in it can at worst print a
wrong unit, which you read before you install it. The risk it guards against
is a unit that does more than you asked: every value that reaches a unit is
refused when it holds a newline, a control character, a `%` (a systemd
specifier) or a backslash, paths are limited to a small character set and
may not be a system directory, and audit flags are parsed like audit's own,
then quoted with `$` escaped. The printed service makes the file system read
only except the two output directories, blocks IP traffic, filters mount,
module, reboot, clock, raw I/O and ptrace system calls, and keeps only
`CAP_DAC_READ_SEARCH`, `CAP_NET_ADMIN`, `CAP_NET_RAW` and `CAP_SYS_PTRACE`.
This hardening does not contain a compromised root audit: treat one as
full root. The audit connects to root daemons' UNIX sockets (Docker,
systemd and D-Bus, tailscaled) to read them, those daemons trust uid 0, and
nothing in the unit, the capability set or Landlock stops `connect()` to a
socket file; hiding the sockets would blind the checks that read them.
`CAP_NET_ADMIN` can change the firewall as well as read it, uid 0 can signal
other root processes, and without Landlock `CAP_SYS_PTRACE` can write other
processes' memory through `/proc/<pid>/mem` and their files through
`/proc/<pid>/root`. [schedule.md](schedule.md#what-a-compromised-root-run-can-do)
spells this out; running the audit as an account is the way to avoid it. The rename of each output into place is done by `mv` in the
unit, so the audit process keeps its Landlock sandbox unchanged.

## Auditing other hosts over ssh

`stackward audit --ssh HOST...` (or `--ssh-hosts FILE`) runs the same read
only audit on other machines and prints one fleet report. It is the only
part of `audit` that starts another program on the machine you run it from,
and the only time stackward writes to an audited host.

- **Your ssh, your config.** stackward starts the `ssh` on your `PATH`
  without a shell. It embeds no SSH library and never sees a key, a
  passphrase or a password: your ssh config, agent and known hosts decide how
  to log in. ssh runs with `BatchMode=yes`, so it never prompts, and an
  unknown host key fails instead of being accepted. It also runs with `-T -a
  -x` and `ClearAllForwardings=yes`: no TTY, no agent or X11 forwarding and
  no port forwards, whatever the config says, so the audited host gets
  nothing back from your machine.
- **Host names cannot become options or code.** A host is a name from your
  ssh config, `user@name` or an address: letters, digits, `.`, `-`, `_` and
  `:`, never starting with `-`, at most 256 per run. An IPv6 address must
  start with a hex digit (`2001:db8::1`); one that starts with a colon, such
  as `::1`, is refused, so give it an alias in your ssh config. It is passed after `--`.
  Anything else is refused before ssh starts. Every remote command is a fixed
  string of this program; the only flags passed on are `--profile` (checked
  against the known names), `--timeout` and `--show-hostname`. `--provider`
  is refused with `--ssh`, so no credential ever goes to a host.
- **The one write.** Per host, a first connection runs `uname -m`. When the
  binary to copy (this one, or one given with `--ssh-binary`, checked from its
  ELF header) does not match, nothing is copied and the error names the
  release archive to download. Otherwise a second connection runs a one line
  POSIX `sh` script: `umask 077`, `mktemp -d` (a new directory only your
  user can enter, mode 700, under `$TMPDIR` or `/tmp`), an `EXIT` trap that removes it however the
  script ends, the binary streamed in on standard input (the only file
  written), then `stackward audit --json` from there, under `sudo -n` only
  with `--ssh-sudo`. With `--ssh-sudo` the directory is always made under
  `/tmp`, never `$TMPDIR`, and the script refuses to run unless `/tmp` is
  owned by root and has the sticky bit: in a parent that other users may
  write without the sticky bit, they could rename the directory away and
  plant a binary that root would then run. The remote audit applies its own
  Landlock sandbox, as any audit does. If the run fails before the trap could run (a broken
  connection, a timeout, a killed process), a third connection removes the
  directory the script announced, after checking it has the expected
  `.../stackward.XXXXXXXXXX` form; when that cannot be confirmed the report
  says so and names the path.
- **What comes back is not trusted.** The report is read from standard
  output with an 8 MiB cap and must be a `stackward.report.v1` document. It
  is then rebuilt against this binary's own check catalog: a result is kept
  only when its check id is in the catalog and its level is a known one, and
  its title, severity, group and fix hint come from the local catalog, never
  from the host, because the renderers print those as trusted text (check
  links, fix hints). Dropped results are counted in a note beside the host
  ("unknown results dropped: N"). The summary, the coverage counts, the
  fleet totals and the exit code are recomputed from the kept results, not
  read from the host. The hostname hash, hostname, tool version and
  collection time must have their expected shape, or they are replaced with
  a note; the check count is kept between the checks that left a result and
  the size of the catalog. Everything else the host supplies (subject,
  message, evidence, OS, kernel, sandbox and collector text, error output)
  has control characters and bidirectional overrides replaced, is cut to a
  size limit (2 KiB per subject or message, 8 KiB of evidence per result and
  256 KiB per host, at most 5000 results, each with a note), and in the
  Markdown fleet report is always shown inside a code span, which Markdown
  never turns into a link, an autolinked bare URL or email address, an
  image, HTML, a heading or a table row. Inside a table cell a host's `|`
  is replaced by U+2223 (`∣`, a look-alike) rather than escaped, because a
  backslash the host puts before it would undo the escape and end the cell.
  So a compromised host cannot send escape sequences to your terminal, add
  links, images or rows to the Markdown report, or forge another host's
  section. Error output is also redacted.
- **No local trace.** Host names appear only in the report you asked for
  (stdout or `--out`); nothing else is written on your machine by stackward
  (ssh keeps its own files, such as known hosts, as usual).
- **One host never stops the others.** Hosts run in parallel
  (`--ssh-parallel`, default 4, at most 32), each with its own time limit
  (`--ssh-timeout`, default 10 minutes). A host that fails is listed with its
  error and the run exits 2.

**ControlPersist.** With `ControlMaster` and `ControlPersist` in your ssh
config, the first connection may start a background master that keeps the
standard error pipe open after ssh itself exited. stackward closes the
pipes 5 seconds after ssh exits and keeps the exit code, so such a host
takes up to 5 seconds longer per connection; the output is complete by then.

**The local side is not sandboxed.** Landlock would forbid ssh its network
connection and its own files (known hosts, control sockets), so the fleet
run applies no sandbox on your machine. It collects nothing there either:
it only starts ssh, reads the binary and writes `--out`. `stackward-guard`
allows starting a program in one file of one package for this
(`internal/fleet/ssh.go`), and the `os/exec` import rule lists the same
file.

## What is out of scope

stackward looks at the configuration of one host. It does not and cannot
tell you about:

- **Vulnerabilities in your applications.** A perfectly configured server
  can run a vulnerable web app. Use your usual dependency and image
  scanners.
- **Kernel exploits and unpatched software in general.** It checks that
  updates are applied and reboots are not overdue, not that every package is
  free of known flaws.
- **Your cloud account.** Provider consoles, API tokens and billing are
  invisible from inside the server. The provider's network firewall is too,
  unless you opt in with `--provider` and a read only token; without it a
  check says so explicitly rather than guessing.
- **Your Cloudflare account.** DNS records, access policies and zone
  settings are not read in version 0.1.
- **Things on other machines**, and anything that happened before you ran
  it. It is a snapshot of now, not an intrusion detector.

A report with no findings means "none of these checks found a problem on
what could be inspected". It does not mean the server is secure.

## Why there is no score

A single number or grade invites false confidence: one critical hole can
hide behind ninety passing checks, and a green badge makes people stop
looking. stackward gives you counts per result and a coverage line instead:
how many checks ran, how many were `unknown`, whether root and the sandbox
were available. Fixing the highest severity findings first is better advice
than chasing a number.

## Unknown is never a pass

Each check ends in one of `pass`, `warn`, `fail`, `unknown` or `skip`.

- `unknown` means stackward could not inspect the thing: no root, a missing
  tool, a collector that timed out, a layout it does not recognise. It is
  never counted as a pass and never trips `--fail-on`, but it is always
  shown, with the reason.
- `skip` means the check does not apply, for example a Tailscale check on a
  host without Tailscale.

Most scripts print "OK" when a command failed or lacked permission. stackward
treats "could not look" and "looked and found nothing" as different answers.

## If you find a hole

If you find a way to make stackward write to a system, leak a secret,
contact a network during `audit` or contact anything beyond the target
during `probe`, that is a security bug. Report it privately as described
in [SECURITY.md](../SECURITY.md).
