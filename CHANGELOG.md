# Changelog

All notable changes to stackward are listed here, newest first. The section
for a tag is used as the notes of its GitHub release. Versions follow
[semantic versioning](https://semver.org/); a version with a suffix such as
`-rc.1` is a pre-release.

## 0.2.0-rc.1 (2026-11-16)

The first pre-release of 0.2: stackward can now fix what it finds. It writes
a plan you can read, applies only the steps you choose, keeps backups and a
journal, and undoes any run. This is a release candidate for testing on a
throwaway server; `install.sh` keeps installing 0.1.2 unless you pass
`--version v0.2.0-rc.1`. Audit, probe and tui stay read only.

### Added

- `stackward plan`: writes the changes that would fix the findings, as file
  diffs and commands with a risk class (safe, networking, access-critical)
  and an undo for every step. Nothing on the host changes. `--out` saves the
  plan.v1 JSON, `--emit-script` prints it as a script to read.
- `stackward apply`: applies the steps you name from a saved plan. Every file
  is checked against the plan first, every overwrite is backed up under
  `/var/backups/stackward/<run-id>/`, writes are atomic, and a run journal
  records everything. One lock covers apply and undo.
- `stackward undo --run ID`: reverses a run from its journal. A file that
  changed after the run is left alone.
- Access-critical steps (SSH, firewall, accounts) run alone inside a
  transaction: a systemd timer and a boot unit roll them back unless
  `stackward confirm` runs from a new SSH session before the deadline
  (`--confirm-within`, 5 minutes by default; `--console` for the provider
  console).
- The lockout guard: before a step narrows a way in, stackward proves from
  the live host that a second way in stays open for the session applying it,
  at plan time and again at apply time. It refuses when it cannot prove it.
- The never touched list: things no step may change (Docker's data root, the
  data directories and SSH keys of Coolify and Dokploy, and more), checked at
  plan, apply and undo time.
- Steps: journald size cap, kernel sysctls, Docker log rotation, the
  admin-user and paas-user accounts, lock-default-user, sshd hardening,
  unattended upgrades, fail2ban for sshd, a default deny UFW policy, and the
  opt in ufw-docker, unattended-upgrades reboot and paas-env-perms (a timer
  that keeps Coolify and Dokploy `.env` files closed) steps.
- `stackward tui --plan plan.json`: a guided step list grouped by risk class,
  with each step's change, the checks it fixes, its undo and the guard's
  proof. It applies through `stackward apply` after a review screen.
- `install.sh`: guided install, update and uninstall.

### Changed

- Apply refuses to run in a CI job unless the job declares a throwaway VM
  (`STACKWARD_CI_APPLY=throwaway-vm`). Undo and confirm are never refused.
- USR-004 reports the sudoers drop-in stackward wrote as info, when it
  matches what stackward writes byte for byte.

### Fixed

- CF-003 and NET-004 judge published ports through Docker's forward filter.
- Probe warns before probing the machine it runs on.

### Testing

- A VM matrix boots Ubuntu 22.04 and 24.04 and Debian 12 and 13 and checks
  rollback, confirm, a guard refusal and the account steps over real SSH.

## 0.1.2 (2026-11-15)

A patch release: an easier to read text report, and three fixes found while
running 0.1.1 on a real server. Still read only; nothing new changes the
host.

### Added

- `audit --plain` (and `probe --plain`): no colors, Unicode or box lines, the
  same output as when piped. `NO_COLOR` still drops only the colors.
- `audit --info`: list every info result in full instead of one line each.
- `audit --group`: lay results out by check group instead of by level.

### Changed

- The text report starts with a summary: counts per level, the fails with
  the most severe first, and the commands to dig in (in a box on a
  terminal). Results follow,
  ordered fail, warn, unknown, info. Each result leads with what was found;
  the check title is shown as `rule`, as in the TUI. Info results take one
  line each unless `--info` or `--all` is given.
- The text report fits the terminal width (or `COLUMNS`); a pipe or an
  `--out` file gets 100 columns.

### Fixed

- LOG-004 now counts a metrics agent (node_exporter, Alloy, Grafana Agent and
  others) that runs in a container or is found by its process name, not only
  one installed from a package.
- The USR-007 message no longer comes out half masked by secret redaction.
- `install.sh` asks again on an answer it does not know instead of taking
  the default, and after `uninstall` it reminds you to run `hash -r` or open a
  new shell, since the shell may still remember the old path.

## 0.1.1 (2026-11-15)

A patch release: an installer, clearer findings in the terminal browser, and
two fixes found while running 0.1.0 on real servers. Still read only; nothing
new changes the host.

### Added

- `install.sh`, a guided installer with `install` (the default), `update` and
  `uninstall`. It detects the OS and CPU, installs the `.deb` with apt on
  Debian and Ubuntu (so `apt remove` works too) and the binary elsewhere,
  checks the SHA-256 every time and the cosign signature when cosign is
  installed, and stops before changing anything when a check fails. On a
  terminal it shows each step with a spinner and ends with a summary; through
  a pipe it prints plain lines. `update` installs only a newer stable
  release, and `uninstall` removes only what the installer added. `get.sh`
  stays as the download only option. See `docs/install.md`.
- `probe` warns when the target is the machine it runs on (loopback or one of
  its own addresses), because services bound to loopback then answer and the
  result is not an outside view. The warning goes to stderr before probing,
  the text report gets a `WARNING:` line, and the JSON report sets the new
  optional `probe.self_target` field.

### Changed

- `stackward tui`: a finding row now shows what was found (for example
  "coolify-proxy mounts the Docker socket") instead of the check title, which
  states the good state and read like the opposite next to FAIL; the title is
  shown in the detail pane as `rule`. A row no longer repeats the subject when
  the message names it.
- `stackward tui`: the ROOT note says the check had root when the run did,
  instead of asking for sudo; empty evidence values are hidden; the header
  keeps its right label whole at any width.
- The install guide leads with the install script and gives copy paste steps
  for the `.deb`, including why apt may print a harmless `_apt` notice.

### Fixed

- `CF-003` and `NET-004` now judge published container ports the same way as
  `DKR-001` (ufw-docker, `DOCKER-USER`, the nftables backend and Docker with
  iptables off), so one report no longer disagrees with itself. A published
  port with nothing filtering forwarded traffic is reported as open even
  without the Docker API; it stays `unknown` only when filtering rules exist
  that cannot be matched.
- GitHub releases now carry their `CHANGELOG.md` section as the release body
  (0.1.0 and 0.1.0-rc.1 were published with an empty body and fixed by hand),
  and the release workflow fails when the body does not match.

Full changelog: https://github.com/Shironex/stackward/compare/v0.1.0...v0.1.1

## 0.1.0 (2026-11-15)


The first stable release. stackward is a read only security audit for a self
hosted Linux server: the kind that runs Docker, often under Coolify or
Dokploy, with a reverse proxy in front and a Cloudflare Tunnel or Tailscale
for the way in. It answers two questions: what is really exposed, and what is
misconfigured. Every finding has a stable check id, the evidence it saw and
the fix. Anything it could not inspect is reported as `unknown`, never as a
pass.

Nothing functional changed since 0.1.0-rc.1: this is the release candidate
promoted after it was tested on three real Ubuntu 24.04 servers (amd64 and
arm64). The checksum checked install with `get.sh`, a root audit under the
sandbox, the Markdown report and `probe` all worked there. Read the report
before acting on it, and see the known limits below.

### Highlights

- 104 audit checks in 14 groups, and 6 outside view checks in `probe`.
- A terminal browser for the findings (`stackward tui`), Markdown and JSON
  reports, and `stackward explain` for any check.
- Read only by design, enforced by a Landlock sandbox where the kernel
  supports it.
- Signed release: SHA-256 checksums, a keyless cosign signature, GitHub build
  provenance and an SBOM per archive.

### What it audits

| Group | Checks | Covers |
|---|---:|---|
| `SYS` System | 5 | tested distribution, pending reboot, kernel, clock sync, disk space |
| `SSH` SSH | 16 | the effective config from `sshd -T`, root and password login, keys, algorithms |
| `USR` Users and privilege | 7 | extra uid 0 accounts, empty passwords, sudoers, docker group |
| `NET` Firewall and exposure | 9 | UFW, every listening socket, `DOCKER-USER`, ufw-docker |
| `DKR` Docker | 16 | API on TCP, socket mounts, privileged and root containers, published ports, log rotation, pinned images |
| `UPD` Updates | 6 | automatic security updates, pending updates, release support, reboot policy |
| `KRN` Kernel settings | 5 | forwarding, reverse path filter, hardening sysctls |
| `LOG` Logs and monitoring | 5 | journal size and persistence, proxy log rotation, a metrics agent |
| `SEC` Secrets on disk | 7 | permissions only: platform `.env` files, SSH key folders, private keys, Docker client config |
| `PAAS` Coolify and Dokploy | 6 | panel and proxy ports, published platform databases, Swarm ports |
| `BAK` Backups | 2 | platform database backups, backup tools |
| `TS` Tailscale | 5 | login state, key expiry, Funnel and Serve, firewall rules, Tailnet Lock |
| `CF` Cloudflare Tunnel | 5 | tunnel and connectors, proxy reachable on a public address, token on the command line |
| `CS` CrowdSec and fail2ban | 10 | running, bouncers, whitelists, log acquisition, SSH brute force protection |
| `PRB` Outside view | 6 | run by `probe` from another machine: SSH, web ports, Docker API, panels, databases, the app hostname |

All 110 checks have a page in the checks catalog (`docs/checks/`) and in
`stackward explain`.

### Commands

- `stackward audit` runs the audit on the server. Output as text, `--md`
  (for an issue or a handover note) or `--json` (schema in `schema/`), with
  `--out FILE`, `--fail-on` for CI, and `--all` to list passing results.
- `stackward audit --dump-facts` writes the redacted facts for a bug report;
  `--facts FILE` evaluates a saved facts file.
- `stackward tui` browses the same findings in the terminal.
- `stackward probe HOST` checks from another machine what actually gets
  through the provider firewall. It asks for consent before probing and
  connects only to the host you name.
- `stackward explain [id]` says why a check matters, how to verify it and how
  to fix it.

### Read only guarantees

- Writes nothing except the report file you ask for with `--out`.
- A Landlock sandbox (Linux 5.13 and later) blocks file writes, and TCP
  connections on Linux 6.7 and later. The report header says whether the
  sandbox was applied.
- Talks to Docker over its Unix socket with GET requests only.
- Never runs a command that changes state, and never reads the contents of
  secret files, only their permissions.
- Redacts secret shaped values from everything it prints or dumps, and hashes
  the hostname unless you pass `--show-hostname`.
- No telemetry and no network calls during `audit`.

See `docs/safety.md` and `docs/threat-model.md` for the exact commands it runs
and what it does not cover.

### Install and verify

Download the archive for your server from this release, check it, and run it:

```sh
VERSION=v0.1.0
ARCH=amd64   # or arm64
BASE=https://github.com/Shironex/stackward/releases/download/$VERSION
curl -fsSLO "$BASE/stackward_${VERSION#v}_linux_$ARCH.tar.gz"
curl -fsSLO "$BASE/checksums.txt"
curl -fsSLO "$BASE/checksums.txt.sigstore.json"
grep " stackward_${VERSION#v}_linux_$ARCH.tar.gz\$" checksums.txt | sha256sum -c -
cosign verify-blob \
  --bundle checksums.txt.sigstore.json \
  --certificate-identity "https://github.com/Shironex/stackward/.github/workflows/release.yml@refs/tags/$VERSION" \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com \
  checksums.txt
gh attestation verify "stackward_${VERSION#v}_linux_$ARCH.tar.gz" --repo Shironex/stackward
tar -xzf "stackward_${VERSION#v}_linux_$ARCH.tar.gz" stackward
./stackward version
```

Or use `get.sh`, which installs the latest stable release, checks the SHA-256
(and the cosign signature when cosign is installed) and never runs the binary:
`sh get.sh -d "$HOME/.local/bin"`. A `.deb` for amd64 and
arm64, and archives for macOS and Windows (for `probe` on a laptop), are in
the release as well. All install options: `docs/install.md`.

### Known limits

- Root matters. 53 of the 104 audit checks need root to read what they judge.
  Without root they report `unknown` with the reason; run with `sudo` for full
  coverage.
- The provider firewall (cloud security groups) is invisible from inside the
  host. `NET-009` says so on every run; use `stackward probe` from another
  machine.
- It is a snapshot of configuration: no application or image vulnerability
  scan, no cloud account access, not an intrusion detector.
- Tested on Ubuntu 22.04 and 24.04. Debian 12 and later is supported by
  design but not covered by the live scenarios. Other distributions work with
  more `unknown` results; `SYS-001` tells you.
- A report with no findings does not mean the server is secure.
- 0.1 only reports. It does not change anything; `plan` and `apply` are the
  next milestone, 0.2 (`docs/roadmap.md`).

Full changelog: https://github.com/Shironex/stackward/compare/v0.1.0-rc.1...v0.1.0

## 0.1.0-rc.1 (2026-11-15)

The first pre-release. stackward is a read only security audit for a self
hosted Linux server: the kind that runs Docker, often under Coolify or
Dokploy, with a reverse proxy in front and a Cloudflare Tunnel or Tailscale
for the way in. It answers two questions: what is really exposed, and what is
misconfigured. Every finding has a stable check id, the evidence it saw and
the fix. Anything it could not inspect is reported as `unknown`, never as a
pass.

This is a release candidate. The checks are tested against saved facts and on
real Ubuntu hosts in CI, but the output may still change before 0.1.0.
Read the report before acting on it.

### Highlights

- 104 audit checks in 14 groups, and 6 outside view checks in `probe`.
- A terminal browser for the findings (`stackward tui`), Markdown and JSON
  reports, and `stackward explain` for any check.
- Read only by design, enforced by a Landlock sandbox where the kernel
  supports it.
- Signed release: SHA-256 checksums, a keyless cosign signature, GitHub build
  provenance and an SBOM per archive.

### What it audits

| Group | Checks | Covers |
|---|---:|---|
| `SYS` System | 5 | tested distribution, pending reboot, kernel, clock sync, disk space |
| `SSH` SSH | 16 | the effective config from `sshd -T`, root and password login, keys, algorithms |
| `USR` Users and privilege | 7 | extra uid 0 accounts, empty passwords, sudoers, docker group |
| `NET` Firewall and exposure | 9 | UFW, every listening socket, `DOCKER-USER`, ufw-docker |
| `DKR` Docker | 16 | API on TCP, socket mounts, privileged and root containers, published ports, log rotation, pinned images |
| `UPD` Updates | 6 | automatic security updates, pending updates, release support, reboot policy |
| `KRN` Kernel settings | 5 | forwarding, reverse path filter, hardening sysctls |
| `LOG` Logs and monitoring | 5 | journal size and persistence, proxy log rotation, a metrics agent |
| `SEC` Secrets on disk | 7 | permissions only: platform `.env` files, SSH key folders, private keys, Docker client config |
| `PAAS` Coolify and Dokploy | 6 | panel and proxy ports, published platform databases, Swarm ports |
| `BAK` Backups | 2 | platform database backups, backup tools |
| `TS` Tailscale | 5 | login state, key expiry, Funnel and Serve, firewall rules, Tailnet Lock |
| `CF` Cloudflare Tunnel | 5 | tunnel and connectors, proxy reachable on a public address, token on the command line |
| `CS` CrowdSec and fail2ban | 10 | running, bouncers, whitelists, log acquisition, SSH brute force protection |
| `PRB` Outside view | 6 | run by `probe` from another machine: SSH, web ports, Docker API, panels, databases, the app hostname |

All 110 checks have a page in the checks catalog (`docs/checks/`) and in
`stackward explain`.

### Commands

- `stackward audit` runs the audit on the server. Output as text, `--md`
  (for an issue or a handover note) or `--json` (schema in `schema/`), with
  `--out FILE`, `--fail-on` for CI, and `--all` to list passing results.
- `stackward audit --dump-facts` writes the redacted facts for a bug report;
  `--facts FILE` evaluates a saved facts file.
- `stackward tui` browses the same findings in the terminal.
- `stackward probe HOST` checks from another machine what actually gets
  through the provider firewall. It asks for consent before probing and
  connects only to the host you name.
- `stackward explain [id]` says why a check matters, how to verify it and how
  to fix it.

### Read only guarantees

- Writes nothing except the report file you ask for with `--out`.
- A Landlock sandbox (Linux 5.13 and later) blocks file writes, and TCP
  connections on Linux 6.7 and later. The report header says whether the
  sandbox was applied.
- Talks to Docker over its Unix socket with GET requests only.
- Never runs a command that changes state, and never reads the contents of
  secret files, only their permissions.
- Redacts secret shaped values from everything it prints or dumps, and hashes
  the hostname unless you pass `--show-hostname`.
- No telemetry and no network calls during `audit`.

See `docs/safety.md` and `docs/threat-model.md` for the exact commands it runs
and what it does not cover.

### Install and verify

Download the archive for your server from this release, check it, and run it:

```sh
VERSION=v0.1.0-rc.1
ARCH=amd64   # or arm64
BASE=https://github.com/Shironex/stackward/releases/download/$VERSION
curl -fsSLO "$BASE/stackward_${VERSION#v}_linux_$ARCH.tar.gz"
curl -fsSLO "$BASE/checksums.txt"
curl -fsSLO "$BASE/checksums.txt.sigstore.json"
grep " stackward_${VERSION#v}_linux_$ARCH.tar.gz\$" checksums.txt | sha256sum -c -
cosign verify-blob \
  --bundle checksums.txt.sigstore.json \
  --certificate-identity "https://github.com/Shironex/stackward/.github/workflows/release.yml@refs/tags/$VERSION" \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com \
  checksums.txt
gh attestation verify "stackward_${VERSION#v}_linux_$ARCH.tar.gz" --repo Shironex/stackward
tar -xzf "stackward_${VERSION#v}_linux_$ARCH.tar.gz" stackward
./stackward version
```

Or use `get.sh`, which checks the SHA-256 (and the cosign signature when
cosign is installed) and never runs the binary:
`sh get.sh -v v0.1.0-rc.1 -d "$HOME/.local/bin"`. A `.deb` for amd64 and
arm64, and archives for macOS and Windows (for `probe` on a laptop), are in
the release as well. All install options: `docs/install.md`.

### Known limits

- Root matters. 53 of the 104 audit checks need root to read what they judge.
  Without root they report `unknown` with the reason; run with `sudo` for full
  coverage.
- The provider firewall (cloud security groups) is invisible from inside the
  host. `NET-009` says so on every run; use `stackward probe` from another
  machine.
- It is a snapshot of configuration: no application or image vulnerability
  scan, no cloud account access, not an intrusion detector.
- Tested on Ubuntu 22.04 and 24.04. Debian 12 and later is supported by
  design but not covered by the live scenarios. Other distributions work with
  more `unknown` results; `SYS-001` tells you.
- A report with no findings does not mean the server is secure.
