# Safety

## Version 0.1: read only

Version 0.1 audits. It does not change your server, so it cannot lock you
out or break a service. From 0.2 on the same holds for `audit`, `probe`,
`tui` and `plan`; only `apply`, `undo` and `confirm` write, and only what the
plan's selected steps say (the step list of `tui --plan` writes only by
running apply's code on the steps you confirm) (see [below](#apply-rules)). The promise, enforced by
design and, on supported kernels, by the Landlock sandbox described in the
[threat model](threat-model.md):

- no file writes except the report you ask for with `--out`;
- no network calls during `audit` (only `probe`, run from another machine,
  connects to the one host you name);
- Docker is only ever sent GET requests;
- no command that changes state;
- secret file contents are never read, only their permissions;
- secret shaped values are masked in everything printed or dumped.

You can check the promise yourself. Run the audit as an unprivileged user
first, read the report header (`sandbox: landlock`), and look at the
`Run` calls in the collector code: they are the only way stackward starts
another program.

## Read before the sandbox

The audit opens `--out`, reads `--facts`, and then applies the sandbox
before any collector runs. One more thing is read in that window: which
process holds which socket.

Naming the process behind a listening socket means reading the links in
`/proc/<pid>/fd` of every process, and the kernel allows that only with
ptrace read access. Landlock scopes ptrace to processes inside the
sandbox, so once it is on neither stackward nor the `ss` it starts can name
a single owner. Without owners, checks fall back to weaker guesses: SSH is
assumed on port 22, cloudflared and tailscaled cannot be told apart from
other listeners (profile inference and the UDP client sockets in NET-004),
and NET-004 shows no process names.

So right before the sandbox, stackward takes a snapshot:

- it lists `/proc`, and for each process reads `/proc/<pid>/comm` (the
  short name `ss -p` prints) and the link targets in `/proc/<pid>/fd`,
  keeping only targets of the form `socket:[inode]`;
- it keeps a map of socket inode to process names, nothing else: no
  command lines, no file paths, no other descriptors;
- it opens files and directories read only, starts no command and sends
  nothing anywhere;
- it is bounded: at most 16384 processes, 1048576 descriptors and 3
  seconds; a process that exits or denies access is skipped, and a walk a
  limit cut short counts as incomplete.

The listeners collector then joins the inodes `ss -e` prints (or the inode
column of `/proc/net/tcp`, `tcp6`, `udp` and `udp6` without ss) to the
snapshot. The facts record how owners were named in
`listeners.owners_source`: `snapshot`, `ss` (with `--no-sandbox`, where
ss names them itself and no snapshot is taken) or `none`.
`processes_visible` is true only when the audit runs as root and owners
were named; a snapshot cut short by a limit leaves it false, so a socket
without a name still proves nothing. A socket opened between the snapshot
and the collector has no name.

## Commands stackward runs

Every program the audit starts is listed here, with what it touches. None
of them writes a file, which matters twice: it is the read only promise, and
under the Landlock sandbox (no file writes, no TCP on ABI 4+) a command that
tries to write fails, its collector ends `partial`, and the checks that need
it say `unknown`. CI runs the real binary as root with the sandbox on and
fails when a collector reports a command that exited non zero under it.
The [live host scenarios](testing.md#the-read-only-check) go further: they
trace a whole audit and every command it starts with strace, with and
without the sandbox, and fail on any write attempt outside `--out`.
`TestCommandTableListsEveryCommand` fails when a collector runs a command
this table does not list.

| Command | Collector | Writes? | Notes |
|---|---|---|---|
| `nft -j list ruleset` | firewall | no | netlink read only (root) |
| `iptables -V` | firewall | no | prints the version |
| `iptables -S` | firewall | no | iptables-nft (Ubuntu 22.04+, Debian 11+) takes no lock. iptables-legacy opens `/run/xtables.lock` to take a shared flock: that works under the sandbox while the file exists (Docker and UFW create it at boot) and fails if nothing created it since boot |
| `firewall-cmd --state` | firewall | no | D-Bus query |
| `ss -Htulnpe`, `ss -Htln` | listeners, ssh | no | sock_diag netlink and `/proc`. Under the sandbox ss names no owning process: Landlock scopes ptrace access, which reading another process's `/proc/<pid>/fd` needs. `-e` adds each socket's inode, which the listeners collector joins to the [ownership snapshot](#read-before-the-sandbox) taken before the sandbox. Without a snapshot stackward marks process names as not visible and recognises published container ports through the Docker API |
| `ip -j addr show` | listeners | no | netlink |
| `sshd -T` | ssh | no | parses the config and host keys; checks `/run/sshd` exists, does not create it |
| `systemctl show`, `systemctl is-active`, `systemctl is-enabled` | ssh, updates, tailscale, cloudflared | no | D-Bus queries to systemd |
| `timedatectl show` | clock | no | D-Bus query. When systemd-timedated is not running, the query starts it on demand and it exits again when idle; systemd gives it private temporary directories meanwhile |
| `df -P -k` | disk | no | statfs |
| `journalctl --disk-usage` | journal | no | reads the journal directory sizes |
| `passwd -S -a` | users | no | reads `/etc/shadow` (root); the status option takes no lock |
| `lastlog` | users | no | reads `/var/log/lastlog` |
| `dpkg-query -W` | updates | no | reads the dpkg database without its lock |
| `apt-get -s -o Debug::NoLocking=true -o Dir::Cache::pkgcache= -o Dir::Log::Planner= upgrade` | updates | no | simulation without the dpkg lock; the empty pkgcache builds the status cache in memory instead of rewriting `/var/cache/apt/pkgcache.bin`, and the empty planner log keeps apt from replacing `/var/log/apt/eipp.log.xz`, which it otherwise does even when it only simulates. It reuses `srcpkgcache.bin`; when that is stale (the lists changed and nothing rebuilt it), apt reparses the lists and needs a temporary file per signed InRelease, which the sandbox refuses, so the collector ends partial and says so until the next `apt update` or `apt-cache gencaches`. apt 2.4 (Ubuntu 22.04) also splits each signed InRelease into a temporary file in `/tmp` that it removes at once, even with current caches; the sandbox refuses it and apt gives the same answer without it, and apt 2.7 (Ubuntu 24.04) no longer does it |
| `apt-config dump` | updates | no | prints the configuration |
| `tailscale status --json`, `tailscale serve status --json`, `tailscale lock status --json`, `tailscale debug prefs` | tailscale | no | local API over the tailscaled Unix socket |
| `cscli version`, `cscli bouncers list -o json`, `cscli config show --key ...`, `cscli <kind> list -o json` | crowdsec | no | reads the config, the hub index and the local database. A SQLite database that cannot be opened for writing is opened read only. A PostgreSQL or MySQL database over TCP is refused by the sandbox on Landlock ABI 4+ (run with `--no-sandbox` there) |
| `fail2ban-client status` | fail2ban | no | asks the server over its Unix socket |

stackward never runs `ufw`: even `ufw status` opens `/run/ufw.lock` for
writing, so it dies under the sandbox. The firewall collector reads
`/etc/ufw/ufw.conf`, `/etc/default/ufw` and `/etc/ufw/user.rules` (and
`user6.rules`), which is what `ufw status` prints, and takes the loaded
state from the listed ruleset (UFW's `ufw-user-input` chain exists only while
UFW is loaded).

Docker is read through its Unix socket with GET requests only; no `docker`
command is run.

## Version 0.2: plan and apply

`stackward plan` and `stackward apply` exist now (in 0.2), and so does the access-critical transaction below: an
access-critical step runs only inside it. The access-critical steps create
an admin or PaaS account, write an sshd drop-in and lock the cloud image's
default account ([plan.md](plan.md#steps-in-this-version)); the transaction
is also tested with steps that exist only in test builds. The
[lockout guard](#lockout-guard) and the [never touched list](#never-touched)
below exist too, tested the same way. All of it is in place before any real
step changes SSH, the firewall or users.

Fixing a finding on a remote machine is riskier than finding it. A wrong SSH
or firewall change can lock you out, and a hardening profile can break
Docker networking. So version 0.2 separates looking from changing.

### Plan first, nothing changes

`stackward plan` writes a plan and changes nothing. It runs the same audit as
`stackward audit`, under the same Landlock sandbox, and the only file it
writes is the `--out` file it was given, opened before the sandbox. It starts
no command of its own beyond the audit's (the table above). Each step lists:

- the checks it fixes;
- the exact edits, as old and new content with their SHA-256 and a diff, and
  any commands;
- a risk class: `safe`, `networking` (can restart Docker) or
  `access-critical` (SSH, firewall, users), and whether it is opt in;
- the services it restarts;
- how to undo it.

Steps whose checks already pass are left out and listed as skipped, with the
reason. The plan goes through the same redaction as the report and hashes
the hostname. `--emit-script` prints the same plan as a shell script for
people who prefer to read and run it themselves; stackward never runs it, and
the script refuses to overwrite a file that changed since the audit. The
format, the risk classes and the steps are described in [plan.md](plan.md).

You read the plan, remove what you do not want, and only then apply it.
This version ships `safe` steps, one opt in `networking` step (Docker log
rotation) and four `access-critical` steps for accounts and sshd; no step
touches the firewall yet.

### Apply rules

`stackward apply plan.json` follows these rules; [apply.md](apply.md) has the
details.

- **Root, Linux, this host.** Apply refuses without root (effective uid 0)
  and says why, and refuses a plan whose hostname hash is not this host's or
  whose schema is not `stackward.plan.v1`. There is no override.
- **You choose.** Nothing runs unless selected: `--step ID` or
  `--all-safe` (safe steps that are not opt in). Opt in and `networking`
  steps run only when named. `access-critical` steps run only when named,
  in a run of their own, inside the [transaction](#access-critical-changes-rollback-timer-and-second-session-confirm).
  Apply prints every step, file, command and restart, then asks `[y/N]` on
  a terminal (or needs `--yes`).
- **A plan file is not trusted.** Every step is re-derived from the code of
  the generator that owns its id: a hand edited plan cannot name another
  path, other content, another command or another undo command. Commands
  run as argument vectors, without a shell, with a fixed `PATH`. An edit
  whose content was redacted in the plan is refused.
- **One run at a time.** Apply, undo, confirm and the rollback timer hold
  an exclusive lock (`/run/stackward/apply.lock`) for the whole run; a
  second run is refused with the holder's run id (the rollback timer waits
  for it instead). A dead run releases it.
- **Undo values are pinned.** The value a `sysctl -w` undo restores must be
  the key's running value on this host (the one the audit recorded), so a
  hand edited plan cannot choose it.
- **Pending restarts are finished first.** A step whose file was written
  but whose restart did not run or failed is marked in the journal, and the
  next apply says so and runs the restart before anything else. A step that
  was undone or rolled back has nothing left to restart.
- **No blind overwrites.** A file whose content no longer matches
  `old_sha256` (or that exists when the plan creates it) is not touched;
  plan again. Symlinks are never written through.
- **Validate before the move.** The new content is written to a temporary
  file in the same directory with the right mode and owner, synced,
  checked with the step's validation command (`dockerd --validate` for
  `daemon.json`), and only then renamed into place. A failed check leaves
  the file untouched.
- **Backups.** The first time a file is replaced, a `FILE.orig` copy is
  kept and never replaced. Every overwrite is also copied, with its mode and
  owner, to `/var/backups/stackward/<run-id>/<path>`.
- **A journal.** `/var/backups/stackward/<run-id>/journal.json` (0600)
  records the old and new values (redacted), every command with its exit
  code, and the timings, and is saved after every change.
- **Idempotent.** Each step's check decides whether it is already in place;
  a second run changes nothing, restarts nothing and says so.
- **Stop on failure.** The first failure stops the run and prints how to
  undo it from the journal: `stackward undo --run RUN_ID`, and the same as
  plain commands.
- **No sandbox.** The Landlock sandbox forbids writes, so apply and undo do
  not apply it; their header says so.
- **Never touched.** No step may change anything on the
  [never touched list](#never-touched): plan refuses such a step (listed as
  skipped, `refused`, with the reason) and apply and undo refuse it again,
  so a hand edited plan cannot slip one in.

#### Commands apply runs

Apply and undo start no program but these, each only as part of a step you
selected (or of the run you undo):

| Command | Step | When |
|---|---|---|
| `systemctl restart systemd-journald` | journald-cap | after the drop-in is written; undo |
| `sysctl -p /etc/sysctl.d/90-stackward-hardening.conf` | sysctl-hardening | when the step is not already applied |
| `sysctl -w KEY=VALUE` | sysctl-hardening | undo only: the running values the audit saw |
| `dockerd --validate --config-file <staged file>` | docker-log-rotation | before the new `daemon.json` is moved into place |
| `systemctl restart docker` | docker-log-rotation | after `daemon.json` changed; undo |
| `visudo -c -f <staged file>` | admin-user, paas-user | before the sudoers drop-in is moved into place |
| `useradd --create-home --home-dir /home/NAME --user-group --shell /bin/bash NAME` | admin-user, paas-user | after the drop-in is written |
| `install -d -m 0700 -o NAME -g NAME /home/NAME/.ssh` | admin-user, paas-user | after `useradd` |
| `install -m 0600 -o NAME -g NAME /home/USER/.ssh/authorized_keys /home/NAME/.ssh/authorized_keys` | admin-user | copies the keys on the host; with `--admin-keys-from root` the source is `/root/.ssh/authorized_keys`, which is only read |
| `userdel --remove NAME` | admin-user, paas-user | undo only |
| `sshd -t -f <staged file>` | sshd-hardening | before the drop-in is moved into place |
| `systemctl try-reload-or-restart ssh.service` | sshd-hardening | after the drop-in changed; undo |
| `usermod --shell /usr/sbin/nologin USER`, `usermod --lock USER` | lock-default-user | the lock (`--lock` only for a usable password) |
| `mv -T /home/USER/.ssh/authorized_keys /home/USER/.ssh/authorized_keys.stackward-locked` | lock-default-user | the lock; undo moves it back |
| `usermod --unlock USER`, `usermod --shell SHELL USER` | lock-default-user | undo only: the password lock and the shell the audit saw |
| `apt-config dump -c <staged file>` | unattended-upgrades, unattended-upgrades-install, unattended-upgrades-reboot | before the apt.conf.d drop-in is moved into place |
| `systemctl enable apt-daily-upgrade.timer`, `systemctl start apt-daily-upgrade.timer` | unattended-upgrades, unattended-upgrades-install | only when the audit saw the timer disabled (start only when it was also stopped); undo: `systemctl stop`, `systemctl disable` |
| `env DEBIAN_FRONTEND=noninteractive apt-get -o DPkg::Lock::Timeout=120 update` | unattended-upgrades-install, fail2ban-sshd | first, only when the audit saw the package lists empty (a fresh cloud image) or older than 3 days; it refreshes the lists and upgrades nothing |
| `env DEBIAN_FRONTEND=noninteractive apt-get -o DPkg::Lock::Timeout=120 install -y unattended-upgrades` | unattended-upgrades-install (opt in) | when the step is not already applied, before the drop-in is written; undo: the same with `purge -y`, skipped when dpkg has no record of the package |
| `env DEBIAN_FRONTEND=noninteractive apt-get -o DPkg::Lock::Timeout=120 install -y fail2ban` | fail2ban-sshd (access-critical) when fail2ban is missing | before the jail is written, so a failed install writes nothing; undo: the same with `purge -y`, skipped when dpkg has no record of the package |
| `fail2ban-client -t` | fail2ban-sshd | after the jail is written, before fail2ban loads it |
| `systemctl reload fail2ban` (`restart` right after an install) | fail2ban-sshd | after the configuration test; undo |
| `iptables-restore --test --noflush <staged file>`, `ip6tables-restore --test --noflush <staged file>` | ufw-policy, ufw-docker | before a UFW rules file is moved into place; loads nothing |
| `ufw --force enable` | ufw-policy | after every UFW file is in place, when UFW was off |
| `ufw disable` | ufw-policy | undo only, when the step turned UFW on |
| `ufw reload` | ufw-policy (UFW already on), ufw-docker | after the files changed; undo |
| `iptables -F DOCKER-USER`, `iptables -A DOCKER-USER -j RETURN` | ufw-docker | undo only: Docker's own chain as the audit saw it |
| `iptables -F ufw-docker-logging-deny`, `iptables -X ufw-docker-logging-deny` | ufw-docker | undo only, after UFW reloaded the old rules |
| `systemctl daemon-reload` | paas-env-perms (opt in) | after the three units are written; undo, after they are removed |
| `systemctl start stackward-paas-env-perms.service` | paas-env-perms | once, right after the reload: closes the open `.env` files now (its `find` and `chmod` run inside the unit, see [plan.md](plan.md)) |
| `systemctl start stackward-paas-env-perms.timer` | paas-env-perms | after the service ran; undo: `systemctl stop` |

No step reboots the host. `unattended-upgrades-reboot` only writes the
setting that lets unattended-upgrades reboot at its window (04:00 host
time) after a run that leaves `/var/run/reboot-required`.

An access-critical transaction also runs these, around its steps (see
below):

| Command | When |
|---|---|
| `systemd-run --version` | preflight, before anything changes |
| `sshd -t`, `sshd -T`, `ss -Htln` | preflight, and again after the steps (the validation) |
| `systemd-run --quiet --collect --wait --unit=stackward-check-ID /var/lib/stackward/transactions/ID/stackward version` | before anything changes: the copy the timer will run starts as a systemd service |
| `systemd-run --quiet --collect --unit=stackward-rollback-ID --on-active=Ns ... /var/lib/stackward/transactions/ID/stackward undo --transaction ID --yes --by-timer` | arms the rollback timer, before the steps |
| `systemctl is-active stackward-rollback-ID.timer` (and `.service`) | checks the timer is armed, or stopped |
| `systemctl stop stackward-rollback-ID.timer stackward-rollback-ID.service` | confirm, an immediate rollback, `undo --transaction` |
| `systemctl enable stackward-boot-rollback-ID.service` | after the unit file is written, before the steps: links the boot unit into `sysinit.target.wants` |
| `systemctl daemon-reload` | after the boot unit and its link are removed (confirm, every rollback, the boot unit itself) |

Before a step that closes or narrows a way in, or starts banning SSH
clients, the [lockout guard](#lockout-guard) reads this host's state again with the
audit's own collectors (`ssh`, `users`, `tailscale`, `listeners`,
`firewall`): the read only commands of the [audit table](#commands-stackward-runs)
above, nothing else. Apply runs them without the Landlock sandbox, because
apply writes, but they only read.

The transaction writes one file outside the steps, the backups, the
journal and its own state: the boot unit
`/etc/systemd/system/stackward-boot-rollback-ID.service` (0644, root),
which it removes again.

### Access critical changes: rollback timer and second session confirm

Changes to SSH, the firewall and users run as a transaction. A step is
access-critical by its own code (the registry), not by the plan file. It
runs only when named with `--step`, never with `--all-safe` and never in
the same run as a safe or networking step, so the rollback undoes exactly
the access changes. [apply.md](apply.md#the-access-critical-transaction)
has the details; in order:

1. **The provider console reminder** is printed before anything about the
   steps: the web or serial console of your hosting provider is the way in
   when SSH is gone.
2. **Refusals that change nothing.** Another transaction is open, or a
   rollback that fired has not been acknowledged; the
   [lockout guard](#lockout-guard) cannot prove a second way in from the
   live host; `systemd-run` is missing;
   `sshd -t` already fails; nothing listens on sshd's port; the copy of
   stackward the timer would run does not start as a systemd service (a
   `noexec` mount, for example).
3. **Snapshot.** Every file the steps touch is backed up as in any apply:
   `FILE.orig` and `/var/backups/stackward/<run-id>/`, with a journal.
4. **Arm the rollback timer** before any change: a transient systemd timer
   and service (`systemd-run`, unit `stackward-rollback-<run-id>`) that run
   a root only copy of the stackward binary
   (`/var/lib/stackward/transactions/<run-id>/stackward`, directory and file
   0700) with `undo --transaction <run-id>`. systemd runs it, so a dropped
   SSH session, a killed terminal or a dead stackward cannot stop it. The
   deadline is `--confirm-within` (default 5 minutes, 30 seconds to 30
   minutes). The state file `/var/lib/stackward/transaction.json` (0600)
   says `open` before the timer can fire.
   A transient timer does not survive a reboot, so the transaction also
   installs a **boot unit**: a persistent oneshot service,
   `/etc/systemd/system/stackward-boot-rollback-<run-id>.service`, enabled
   for `sysinit.target`, that runs the same copy with `undo --transaction
   <run-id> --by-boot`. If the host boots while the transaction is open (a
   reboot from the provider panel is the usual way out of a lockout), it
   rolls the change back early, after the local file systems and **before
   `ssh.service`, `sshd.service`, `ssh.socket` and `sshd.socket`**, so sshd
   starts with the restored configuration. It acts only while the state is
   still `open`, then removes itself. If the timer or the boot unit cannot
   be set up, nothing changes.
   The timer and the boot unit do **not** check the hostname, as a person's
   `stackward undo` does: at early boot the hostname can be unset or the
   image default, cloud-init can rename a host, and you may rename it
   while locked out, and none of that may keep the lockout in place. They
   need no such check, because the state, the journal and the binary copy
   are root-only files stackward wrote on this machine. They record the
   hostname hash they ran under in the state (`rollback_host`), and a
   `host_note` when it differs from the one that applied.
5. **Apply** the steps.
6. **Validate**: `sshd -t` passes, `sshd -T` shows every setting the
   steps mean to leave in place (from the step's own code), and something
   listens on each of sshd's ports, including every port it listened on
   before. A failed step or a failed check **rolls back at once**, stops the
   timer and exits 1; you watched it, so it needs no acknowledgement.
7. **Wait for `stackward confirm ID`**, which must run from a **new** SSH
   session: the same session is refused, because a session that survived the
   change proves nothing about a fresh login. When a step closed public
   SSH, the new session must also come over the way the lockout guard
   proved (from the tailnet, or from the allowed source). `--console` is
   the one way around both rules, for the provider console. Confirm removes the boot
   unit, stops the timer and marks the transaction confirmed.
8. **No confirm before the deadline**: the timer restores the snapshot (the
   same undo as `stackward undo`), reloads what the steps reloaded, and marks
   the transaction rolled back. A reboot before the confirm does the same at
   boot through the boot unit. Access-critical steps then stay refused
   until `stackward confirm --ack-rollback ID`, so a rollback you did not
   see cannot go unnoticed. Safe and networking steps are not affected.
   Every rollback (timer, boot, a failed check, `undo --transaction`)
   removes the boot unit. Apply refuses access steps while a boot unit is
   left over without an open transaction of its own, and prints the
   commands that remove it.

Only one transaction can be open at a time: the state file is read and
written only under the run lock, and apply refuses a second one.

How confirm tells sessions apart: it compares four facts of the session
that applied with its own. Any fact both have that is equal means the same
session; at least one must differ; a session that shares no fact to compare
is refused, never assumed new; a confirm that does not run over SSH needs
`--console`.

| Fact | Where it comes from | What it catches |
|---|---|---|
| audit session id | `/proc/self/sessionid`, set by `pam_loginuid` at login and kept across `sudo` and `su` | the same login, also from a `tmux` or `screen` window started in it |
| sshd session process | the first `sshd` (or `sshd-session`) above stackward in the process tree, with its start time | the same SSH connection |
| SSH connection | `SSH_CONNECTION` (client address and port), from the environment or from the login shell when `sudo` dropped it | the same TCP connection, including a multiplexed `ControlMaster` channel |
| logind session | `XDG_SESSION_ID`, the same way | the same login |

The limits, honestly:

- A confirm from a `tmux` or `screen` window that was started in the
  applying session is refused (same audit session), even if you reattached
  from a new connection. Confirm from a plain new login.
- `ssh` with connection sharing (`ControlMaster`) reuses the old
  connection: refused. Use `ssh -o ControlPath=none`.
- Without `pam_loginuid` (some containers) the audit session id is absent,
  and the check rests on the sshd process and `SSH_CONNECTION`.
- The check proves that a new SSH session reached a shell and `sudo`, not
  that every way in works (another user, another key, another address). It
  is a strong signal, not a proof of every path; the
  [lockout guard](#lockout-guard) adds the checks on the second way in.
- The boot rollback runs only if the host boots normally into a target
  that pulls in `sysinit.target` (the default and rescue targets do; an
  emergency shell does not), with `/var` mounted. If it cannot run, the
  transaction shows as `open` past its deadline and
  `sudo stackward undo --transaction ID` rolls it back by hand.
- The rollback waits up to 10 minutes for the run lock when an apply or a
  confirm holds it, and then gives up; the transaction then shows as open
  past its deadline.
- A rollback restores files only while they still hold what the
  transaction wrote; a file you edited in the window is left alone, the
  transaction is marked `rollback-failed`, and you restore it from the
  backup by hand.

### Lockout guard

Before a step may close or narrow a way in, stackward proves that a second
way in survives it. A step narrows a way in when it sets who may log in,
how or where (password, keyboard-interactive or public key
authentication, root login, `AuthenticationMethods`, `AuthorizedKeysFile`,
`MaxAuthTries`, the port, the listen addresses, `AllowUsers`,
`AllowGroups`, `DenyUsers`, `DenyGroups`, PAM), closes public SSH (a
firewall rule that drops public 22, sshd only on private addresses),
disables an account or removes an account's keys. What a step does to
access comes from the step's own code, never from the plan file. An
access-critical step that does not say what it does is treated as
narrowing everything.

The proofs:

| The step | The second way in that must survive it |
|---|---|
| keeps public SSH open (password auth off, root login off, AllowUsers, a new port, ...) | a non-root account with sudo and a usable authorized key logs in with that key under the sshd configuration the step leaves behind: AllowUsers and AllowGroups, DenyUsers and DenyGroups, `PubkeyAuthentication`, `AuthenticationMethods` (some list a key alone satisfies), `AuthorizedKeysFile` and every Match block, evaluated for that account and the session's source address. A new port must be let in by UFW from anywhere |
| closes public SSH | the same account logs in over the tailnet: Tailscale is `Running`, the node's key expiry is off, sshd listens on a wildcard or tailnet address, and a firewall rule lets the tailnet reach sshd (on `tailscale0` or from `100.64.0.0/10`), or the step adds one. Or: the step still lets a network reach sshd, the session that plans or applies comes from it, and the account logs in from there |
| disables an account or removes its keys | another account passes the first row; the account that applies is never disabled |
| changes the firewall (`ufw-policy`, `ufw-docker`) | SSH stays reachable for the session that applies: for every port sshd listens on (from sshd's facts; with none known the proof fails, it never assumes 22), UFW's live rules plus the ones the step adds, walked in order, let the session's source in (from anywhere, from a network holding it, or on `tailscale0` for a tailnet source) before any deny that could match it. UFW's state must be what the step expects (off for a step that turns it on), and an IPv6 session needs `IPV6=yes`. When the rules only let some networks in, the confirm must come from one of them. A session with no known source passes only a rule from anywhere |
| starts banning SSH clients (the fail2ban sshd jail) | nothing to prove about a second way in, but the session that plans or applies must come from an address the jail ignores (loopback, the jail's own `ignoreip`, the tailnet when Tailscale is installed, the planning session's address), so a failed test login cannot ban the owner. A session with no known source (the provider console) passes |

From this follow the three rules: public SSH never closes without the
tailnet path (or the allowed source) proven; the last admin key is never
removed; password authentication is never turned off for the only user
without a key.

A sudo right counts when sudoers names the account, `ALL`, or `%GROUP`
for one of its groups. A key counts when it sits in a file sshd would read
for that account and current OpenSSH still accepts it (no DSA, no RSA
under 1024 bits).

When and from what:

1. **At plan time**, from the audit's facts and the planning session's
   source address (live plans only). A step without a proof is not
   planned: it is listed as skipped, kind `refused`, with the missing
   piece, for example `no second way in exists: it needs a non-root sudo
   user with an authorized key (alice: no usable authorized key (it would
   log in with a password only))`.
2. **At apply time, again**, from facts read from the live host right
   before the transaction opens (the plan's facts may be hours old) and the
   applying session. A failed proof refuses the run before anything
   changes, with the same kind of reason.
3. **At confirm time**, the new session stays the final proof. When the
   step closed public SSH, the transaction records the networks the guard
   proved (`confirm_from` in the state) and `stackward confirm` refuses a
   session whose client address is not in one of them: a confirm over
   public SSH proves nothing about the tailnet. `--console` is not
   checked.

The guard fails closed: a setting it cannot read (no root, so no `sshd
-T`), a sudoers file it cannot read, a Match block with an unreadable
include, or a source it does not know counts against the proof. A Match
block whose criteria it cannot decide (an unknown source address, `Host`,
`LocalAddress`, `RDomain`) is tried both ways, and the login must work
either way.

The limits, honestly:

- It proves from facts, not by logging in. The confirm from a new session
  is what proves a login works; the guard makes sure there is something to
  log in with before anything changes.
- It does not evaluate `AuthorizedKeysCommand`, sudo aliases
  (`User_Alias`), `#uid` sudoers principals, key options in
  `authorized_keys` (`from=`, `restrict`) or Tailscale ACLs. Keys from a
  command and sudo rights through an alias do not count.
- `AuthenticationMethods` that need a second factor next to the key
  (`publickey,keyboard-interactive`) fail the proof, even when the second
  factor works.
- Hostnames in `AllowUsers user@host` and in Match `Address` are not
  resolved; they count as not matching (allow) or possibly matching
  (deny).
- Firewalls other than UFW are not analysed rule by rule: when one drops
  incoming traffic, a new port or a tailnet rule cannot be proven.
- UFW rules on an interface other than `tailscale0` count as possibly
  matching: an allow on one does not prove SSH, a deny on one refuses.
- Tailscale SSH (`tailscale set --ssh`) does not count as a way in: its
  access is decided by tailnet ACLs, which stackward cannot read.

### Never touched

No step may change these, whatever it fixes. Plan judges every step by its
targets: the targets it declares (`touches`), every file it edits, and
every program its commands run with their arguments (an undo counts only
for the files it names, because it only reverses its own step). A step
that reaches an entry is refused at plan time (skipped, kind `refused`,
with the entry and the reason) and again by apply and undo, so dropping a
target from a hand edited plan does not help. The list is fixed in the code
(`internal/plan/nevertouched.go`) and a test keeps this table in step with
it.

| Entry | What | Why |
|---|---|---|
| `network-config` | the provider's network configuration: `/etc/netplan`, `/etc/network/interfaces`, cloud-init's network config, `/etc/systemd/network`, `netplan` | a wrong address, route or renderer takes the host off the network at the next apply or boot, and only the provider console can bring it back |
| `tailscale` | Tailscale's state and the settings the tailnet ACLs see: `/var/lib/tailscale`, `/etc/default/tailscaled`, `tailscaled`, any `tailscale` command | the tailnet is the second way in the lockout guard proves; a logout, a new node key or a changed tag can cut it silently |
| `cloudflared` | cloudflared's configuration and tunnel credentials (`/etc/cloudflared`, `~/.cloudflared`) | the tunnel is a tunnel host's public ingress, and its credentials are secrets stackward never reads |
| `paas-data` | the data directories of Coolify (`/data/coolify`) and Dokploy (`/etc/dokploy`), their SSH keys included | the platform owns and rewrites them; its SSH keys are how it reaches this and every other managed server |
| `docker-data` | Docker's data root (`/var/lib/docker`, `/var/lib/containerd`, `data-root`) | it holds every image, container and volume |
| `docker-firewall` | Docker daemon firewall settings (`iptables`, `ip6tables`, `ip-forward`, `ip-masq`, `firewall-backend`) | Docker programs the NAT and forwarding rules its containers and the `DOCKER-USER` chain need |
| `ip-forward` | kernel forwarding (`net.ipv4.ip_forward`, every `forwarding` setting) | Docker and Tailscale routing need it; hardening profiles that turn it off break both |
| `provider-firewall` | the provider's network firewall | it sits outside the host, stackward cannot see it, and it still holds when the host firewall is wrong |
| `boot` | `/boot` and the bootloader (GRUB configuration, kernel command line, initramfs, EFI entries) | a host that does not boot can only be repaired from rescue mode |
| `root-password` | root's password, and `/etc/shadow`, `/etc/passwd`, `/etc/group` edited by hand | root's password is the console login of last resort; account files are changed only through the account tools |
| `root-keys` | root's `authorized_keys` | platforms and recovery tooling log in as root with a key; root login is turned off in sshd instead |
| `pam` | PAM (`/etc/pam.d`, `/etc/pam.conf`, `/etc/security`) | one wrong line refuses every login, the console included, or lets anyone in |
| `admin-sudo` | sudo rights of existing accounts: `/etc/sudoers` itself, revoking anyone's sudo, deleting accounts | removing the current admin's sudo leaves nobody to undo the change; stackward only adds sudoers drop-ins and locks accounts |

A step that needs one narrow thing an entry covers gets an exception of
its own: one step id and exact targets, never a pattern, so it cannot grow
into a wider hole. Every other step is still refused there, and so is this
step for anything else the entry covers.

| Step | Entry | What it may do | Exact targets |
|---|---|---|---|
| `paas-env-perms` | `paas-data` | remove the group and other permission bits (`chmod` only) of the platform's `.env` files, from a timer, because the platform rewrites them loose on every deploy; never their content, never their owner | the `.env` files under `/data/coolify/applications`, `/data/coolify/services`, `/etc/dokploy/applications` and `/etc/dokploy/compose`, and `/data/coolify/source/.env` |
| `admin-user` | `root-keys` | read root's `authorized_keys` as the source of the new admin account's keys (`--admin-keys-from root`, on an image with root only); `install` copies it into the new account's home and never changes root's file | `file:/root/.ssh/authorized_keys` (read only) |

### What will still go wrong

No design removes all risk. Keep provider console access, keep a second
session open while you work, and read the plan. Apply is tested on
disposable VMs only (the `apply` and `transaction` scenarios on GitHub
runner VMs, and the [VM matrix](testing.md#vm-matrix) over real SSH on
Ubuntu and Debian cloud images), never on a developer's own machine, and
not on your production server first. It refuses to run in any other CI job
([testing.md](testing.md#apply-refuses-in-ci)).
