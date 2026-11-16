# Changelog

All notable changes to stackward are listed here, newest first. The section
for a tag is used as the notes of its GitHub release. Versions follow
[semantic versioning](https://semver.org/); a version with a suffix such as
`-rc.1` is a pre-release.

## 0.4.0 (2026-11-16)

A minor release: stackward becomes something you repeat. You can accept a
finding on purpose with a waiver, compare two reports to spot drift, audit
several hosts over your own ssh, and print a systemd timer that writes a
Prometheus metric. Nothing here changes what a plain `audit` does without the
new flags. `install.sh` now installs 0.4.0.

### Added

- Waivers (#111). `audit` and `tui` read `.stackward.yml` from the working
  directory, or the file named with `--waivers FILE` (which must exist). A
  waiver names a check id, the exact subject of a result, a reason and an
  expiry date (`YYYY-MM-DD`, judged against the time of the run), and has an
  optional `level: warn|fail` (default `warn`). A matching result is shown as
  accepted with its reason and expiry in text, JSON, Markdown and the TUI. It
  is never hidden and its level and evidence never change. An accepted result
  counts in `summary.accepted` instead of `fail` or `warn`, so it does not
  trip `--fail-on`. An expired waiver puts the finding back at its real level.
  A waiver for an unknown check, a subject that no longer matches, a result
  above its level, or one that matches several results is listed under
  waivers to review (`unknown-check`, `stale`, `expired`, `level-exceeded`,
  `ambiguous`, `long-lived`). The report stays `report.v1`: the new fields
  are optional, and a report without a waivers file is byte for byte as
  before. See [docs/waivers.md](docs/waivers.md).
- `stackward diff [flags] OLD.json NEW.json` (#116) compares two saved
  reports of one host and prints the drift and the findings that were added,
  removed or changed, in text, Markdown or JSON (new `schema/diff.v1.json`).
  `stackward audit --baseline OLD.json` audits and prints the diff against
  the baseline instead of the report. Drift is read from report evidence: a
  new or newly public listener (NET-004), a new authorized key for a user
  (SSH-014), a new NOPASSWD sudoer (USR-004) and a container that now runs as
  root (DKR-020). A drift check that judged the baseline and is now only
  `unknown` or `skip`, or missing, is listed as lost coverage, so a blind spot
  never passes as "no drift". An accepted finding is never reported as fixed
  or as new, and a waiver never silences drift. See
  [docs/diff.md](docs/diff.md).
- `--fail-on-drift any|fail|drift|never` (default `any`) sets the exit code of
  `diff` and `audit --baseline`: 0 when nothing reaches it, 1 when drift, lost
  coverage or a new finding does, 2 on an error (bad flags, an unreadable or
  invalid report, reports of different hosts without `--force-host`). On
  `audit --baseline` an explicit `--fail-on` also counts; the default one does
  not, because old findings are what a baseline is for.
- `stackward audit --ssh [flags] [--] HOST...` and `--ssh-hosts FILE` (#112)
  run the same read only audit on one or several other machines through your
  own `ssh`, and print one fleet report (text, `--md` or `--json`) with each
  host's counts and coverage line, then each host's full report. The binary is
  copied to a private `mktemp` directory, run, and removed again, even when
  the run fails (a second connection removes what a failed run left). The
  binary is this executable or `--ssh-binary PATH` (repeatable, one per
  architecture), checked from its ELF header; a mismatch copies nothing and
  names the release asset to use. `--ssh-sudo` runs it with `sudo -n`,
  `--ssh-parallel` (default 4, at most 32) bounds the parallelism and
  `--ssh-timeout` (default 10m) the time per host. One failing host never
  stops the others: exit 2 when any host could not be audited, otherwise the
  worst code for `--fail-on`. New `schema/fleet.v1.json`; each audited host
  carries its `report.v1`.
- `stackward schedule --print` (#110) prints a hardened systemd service and
  timer unit. It writes no file, creates no directory, enables nothing and
  contacts nothing; without `--print` it refuses. Flags: `--on-calendar`
  (default `daily`), `--randomized-delay` (default 1h), `--user` (default
  `root`), and the audit flags after `--`. The unit runs the audit, then
  renames the report and the metric into place only after a successful run, so
  a failed run leaves the old files and the last run timestamp stops moving.
  See [docs/schedule.md](docs/schedule.md), which also has the metric names
  and Prometheus alert rules.
- `stackward audit --textfile DIR/NAME.prom.tmp` (#110) writes a Prometheus
  textfile metric next to the report: `stackward_results{level}`,
  `stackward_last_run_timestamp_seconds`, `stackward_coverage_ratio`,
  `stackward_run_as_root`, `stackward_sandbox_confined`,
  `stackward_collectors{status}` and `stackward_info{version,profile}`. It
  carries counts only: no hostname, subject or message.
- SSH-014 evidence now carries `fingerprints`, the sorted OpenSSH `SHA256:`
  fingerprints of the authorized keys (never key material). Drift needs them
  to tell one key from another; a report without them falls back to a growing
  key count.

### Changed

- DKR-010 honours a mask over the Docker socket (#109). A container that binds
  `/` or `/var` but covers the socket folder `<target>/run` with a tmpfs (compose
  `tmpfs:`, `docker run --tmpfs`) or a volume no longer fails: it passes with
  the mask named, and `masked_socket_mounts` appears in the evidence only when
  present. A bind of `/run`, `/var/run` or the socket file is never treated as
  masked, and a bind of part of `/run` beneath the cover cancels the mask.
  Compose `tmpfs:` entries are now read into the facts as tmpfs mounts.
- `--out` that is one of the input reports or the `--baseline` is refused
  before the file is truncated. The output files of `audit` are opened as
  regular files only (a symlink, FIFO, device or hard link is refused), and the
  textfile path is unlinked first and created with `O_EXCL`.
- The report schema `report.v1` is unchanged. `--baseline`, `--waivers` and
  `--textfile` are refused together with `--ssh`, because they name one host.

### Fixed

- Free text in Markdown reports escapes `@`, so a pasted report or diff
  mentions nobody.
- Redaction no longer masks a SHA256 key fingerprint as a token. The
  structural rules (private key blocks, URL passwords, Authorization headers)
  still run over the whole string first, and a fingerprint is kept only when it
  stands alone, so a token glued to one is still masked.

### Security and privacy

- `diff` and `audit --baseline` treat both report files as untrusted. They are
  opened (with `--out`) before the Landlock sandbox is applied, must be regular
  files of at most 32 MiB holding one JSON value that validates against the
  embedded `report.v1` schema, and every string in them is cleaned of control,
  bidi and zero width characters and redacted before it is shown. Reports of
  different hosts (by hostname hash) are refused unless `--force-host`.
  Someone who can rewrite the baseline can still hide drift; the docs say so.
- Fingerprints are public identifiers, not secrets, but they say which key is
  authorized. They appear in reports and in `--dump-facts` from now on.
- `audit --ssh` uses no SSH library and handles no key or password. `ssh`
  runs without a shell, with `BatchMode=yes`, no forwarding and no agent.
  Host names are validated and passed after `--`, every remote command is a
  constant of stackward, and `--no-sandbox`, `--provider`, `--facts` and
  `--dump-facts` are refused with `--ssh`, so no provider credential goes to a
  host. A host's report is capped at 32 MiB and cleaned before rendering. The
  fleet side applies no Landlock sandbox, because ssh needs the network; the
  remote audit is sandboxed as usual. `audit --ssh` is the one way the audit
  writes to a host: the copied binary, in a private directory. See
  [docs/threat-model.md](docs/threat-model.md#auditing-other-hosts-over-ssh).
- `schedule --print` refuses control characters, `%` and backslash in every
  value it prints, requires clean absolute paths for the binary and output
  directories, and refuses audit flags the unit owns or a scheduled run must
  not have. The textfile is world readable by design and holds counts only.
  The docs say plainly what a compromised audit run as root can do and
  suggest `--user` for a smaller blast radius.
- The waivers file is opened without following a symlink and must be a regular
  file with a safe owner and mode. A parse error names the line and key, never
  a value.

### Known limits

- DKR-010: a bind of a `/proc` source beneath the cover, and a named volume
  whose driver options bind host `/run`, can still count as a mask (#113).
- Waivers are not pinned to evidence: a waiver can still accept a changed
  result on the same subject (#114).
- Markdown renders catalog placeholders such as `<container-port>` as HTML,
  one `audit --ssh` wait path has no test, and a hostile host can name itself
  inside its own section (#115).
- `audit --facts F --out F` truncates F before it is read, and the order of the
  redaction rules is not pinned by a test (#117).

## 0.3.0 (2026-11-16)

A minor release: stackward can now read your cloud provider's firewall, which
the host cannot see. Everything is opt in. Without `--provider` stackward
sends no network request, and the audit judges the host exactly as in 0.2.0.
`install.sh` now installs 0.3.0.

### Added

- `--provider hetzner|ovh|auto` on `audit` (and so on `plan`, which audits
  first): reads the provider's firewall over its API and judges it next to
  the host firewall. `--provider-ip ADDR` names the public address when it is
  not on one of the host's interfaces (NAT). Hetzner Cloud Firewall (stateful,
  IPv4 and IPv6) and the OVHcloud Edge Network Firewall (stateless, ordered,
  IPv4 only) are supported. `auto` picks the provider whose credentials are
  set and refuses when both are; it never probes the network.
- The PFW checks (provider firewall group, 8 checks) judge what the provider
  firewall lets in before traffic reaches the host and Docker:
  - PFW-001: a provider firewall is attached and in force. Without
    `--provider` it is one `skip` row saying the provider firewall was not
    checked, and the other PFW checks leave no row.
  - PFW-002: inbound traffic is denied by default at the provider.
  - PFW-003: no provider rule allows all UDP from anywhere.
  - PFW-004: every port the provider allows has a service behind it.
  - PFW-005: SSH is not open to anywhere at the provider.
  - PFW-006: IPv6 is covered by the provider or the host firewall.
  - PFW-007: a stateless provider firewall lets return traffic in.
  - PFW-008: what the provider firewall allows, as info.
  Anything the API could not answer is `unknown` with the reason, never a
  pass.
- The facts model gains `provider_firewall` (normalised rules only: no names,
  labels, server, firewall, project or account ids). `--dump-facts` masks the
  matched address to its first three octets, every IPv4 address in a reason
  and every rule network, and the redaction pass masks a registered token as
  a literal value wherever it could appear.
- [docs/provider-firewall.md](docs/provider-firewall.md): the guide, with the
  exact requests sent, and a design note in `docs/design/`.

### Security and privacy

- `--provider` makes outbound HTTPS calls to the provider API only when you
  ask for it. Hetzner requests go to `api.hetzner.cloud`; OVH requests go to
  the regional host (`eu.api.ovh.com`, `ca.api.ovh.com` or
  `api.us.ovhcloud.com`). Nothing else is contacted.
- The client can only build GET requests, refuses any other host, never
  follows a redirect, ignores proxy variables, caps every answer at 1 MiB and
  gives the whole fetch 10 seconds. A slow or failing API never fails the
  audit; the checks say `unknown`.
- Credentials come from the environment or a file only, never from the
  command line (there is no `--token` flag, because argv shows in `ps` and in
  shell history). Hetzner: `STACKWARD_HETZNER_TOKEN` or
  `STACKWARD_HETZNER_TOKEN_FILE`. OVH: `STACKWARD_OVH_APPLICATION_KEY`,
  `STACKWARD_OVH_APPLICATION_SECRET`, `STACKWARD_OVH_CONSUMER_KEY` and
  `STACKWARD_OVH_ENDPOINT`, or `STACKWARD_OVH_CREDENTIALS_FILE`. A credential
  file must be a regular file (a symlink is refused), owned by the user
  running the audit, mode 0600 or stricter, and is capped at 4 KiB.
- Credentials are never stored: not in the facts, the report, `--dump-facts`
  or any log. Create the Hetzner token with permission Read and limit the OVH
  consumer key to `GET /ip` and `GET /ip/*`. stackward only sends GET
  requests.
- The fetch runs before the Landlock sandbox, which denies TCP connect and
  cannot be loosened afterwards, so it is the only code that touches the
  network. The sandbox is unchanged. See
  [docs/threat-model.md](docs/threat-model.md#the-provider-firewall-fetch).

### Changed

- The install guide in `docs/install.md` is a step by step guide, and the
  README install section points at it.
- Internal: long functions in the CLI, facts and checks packages were split
  under the funlen and gocognit limits, with no change in behaviour.

## 0.2.0 (2026-11-16)

stackward can now fix what it finds. 0.1.2 only reported; 0.2 adds a plan you
can read, applies only the steps you choose, keeps backups and a journal, and
undoes any run. `audit`, `probe`, `explain` and `tui` stay read only, and
`plan` changes nothing. `install.sh` now installs 0.2.0.

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
  changed after the run is left alone, and a purge or account removal for
  something that never came to be is skipped, with the reason in the
  journal. Directories apply created for a new file are removed while they
  are empty.
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
- `--admin-keys-from root` works on a server where root is the only account:
  admin-user copies `/root/.ssh/authorized_keys` to the new account, and the
  plan says where the keys came from and that sshd-hardening turns root login
  off once the new account is confirmed.
- `stackward tui --plan plan.json`: a guided step list grouped by risk class,
  with each step's change, the checks it fixes, its undo and the guard's
  proof. It applies through `stackward apply` after a review screen.
- `install.sh`: guided install, update and uninstall, and it names
  `stackward plan` among the next steps.

### Changed

- Apply refuses to run in a CI job unless the job declares a throwaway VM
  (`STACKWARD_CI_APPLY=throwaway-vm`). Undo and confirm are never refused.
- A step that installs a package (fail2ban-sshd, unattended-upgrades-install)
  installs it before writing any file, so a failed install leaves nothing
  behind and ends the transaction `rolled-back`. When the audit saw the
  package lists empty (a fresh cloud image) or older than 3 days,
  `apt-get update` runs first, named in the plan with a note.
- USR-004 reports the sudoers drop-in stackward wrote as info, when it
  matches what stackward writes byte for byte.
- When CS-010 or SSH-011 cannot tell whether SSH is protected, the message
  names what could not be read, and says to run with sudo only when the
  audit did not run as root.

### Fixed

- CF-003 and NET-004 judge published ports through Docker's forward filter.
- Probe warns before probing the machine it runs on.
- A step that was rolled back or undone no longer leaves a pending restart
  for the next apply.
- A leftover `/etc/fail2ban` without the fail2ban program no longer counts
  as fail2ban being installed.

### Testing

- Verified end to end on a real Ubuntu 24.04 VPS and by the CI VM matrix
  (Ubuntu 22.04 and 24.04, Debian 12 and 13), which checks rollback,
  confirm, a guard refusal, the account steps and a root only server over
  real SSH.

## 0.2.0-rc.2 (2026-11-16)

The second pre-release of 0.2, with the fixes from testing 0.2.0-rc.1 on a
throwaway server. `install.sh` keeps installing 0.1.2 unless you pass
`--version v0.2.0-rc.2`.

### Fixed

- `--admin-keys-from root` works on a server where root is the only
  account: admin-user copies `/root/.ssh/authorized_keys` to the new
  account, and the plan says where the keys came from and that
  sshd-hardening turns root login off once the new account is confirmed.
  The key source is checked apart from the new account's name, so root is
  still refused as the account to create.
- A step that installs a package (fail2ban-sshd, unattended-upgrades-install)
  installs it before writing any file, so a failed install leaves nothing
  behind. When the audit saw the package lists empty (a fresh cloud image)
  or older than 3 days, `apt-get update` runs first, named in the plan with
  a note. The audit records the state of the lists.
- Undo no longer fails on a package or account that never came to be: a
  purge of a package dpkg has no record of, or a `userdel` of an account
  `useradd` never created, is skipped and the journal says why. A failed
  install now ends a transaction `rolled-back`, not `rollback-failed`.
- Undo removes the directories apply created for a new file (such as
  `/etc/fail2ban/jail.d`) while they are empty.
- A step that was rolled back or undone no longer leaves a pending restart
  for the next apply.
- A leftover `/etc/fail2ban` without the fail2ban program no longer counts
  as fail2ban being installed.
- When CS-010 or SSH-011 cannot tell whether SSH is protected, the message
  names what could not be read, and says to run with sudo only when the
  audit did not run as root.
- `install.sh` names `stackward plan` among the next steps after installing
  0.2.

### Testing

- The VM matrix adds a root only server: admin-user from root's keys, and a
  fail2ban install on empty package lists that fails, rolls back cleanly and
  then succeeds.

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
