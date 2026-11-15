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

Without root, checks that need root report `unknown` and the report says so.
Run with `sudo` for full coverage; the promises below hold either way.

## What stackward never does

In version 0.1 stackward:

- **writes nothing** to the system it audits. The only file it creates is the
  report you ask for with `--out`;
- **makes no network calls during `audit`.** No telemetry, no update check,
  no lookups, no uploads. Only `probe`, which you run from another machine,
  touches the network (see below);
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
  `y` on an interactive terminal or `--i-own-this` otherwise.

On Linux the same Landlock sandbox applies, with TCP left allowed: probe
still cannot write anything but `--out`.

## What is out of scope

stackward looks at the configuration of one host. It does not and cannot
tell you about:

- **Vulnerabilities in your applications.** A perfectly configured server
  can run a vulnerable web app. Use your usual dependency and image
  scanners.
- **Kernel exploits and unpatched software in general.** It checks that
  updates are applied and reboots are not overdue, not that every package is
  free of known flaws.
- **Your cloud account.** Provider consoles, API tokens, billing and the
  provider's network firewall are invisible from inside the server. A check
  says so explicitly rather than guessing.
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
