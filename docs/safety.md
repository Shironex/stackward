# Safety

## Version 0.1: read only

Version 0.1 audits. It does not change your server, so it cannot lock you
out or break a service. From 0.2 on the same holds for `audit`, `probe`,
`tui` and `plan`; only `apply`, `undo` and `confirm` write, and only what the
plan's selected steps say (see [below](#apply-rules)). The promise, enforced by
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

`stackward plan` and `stackward apply` exist now (in the upcoming 0.2, not yet
released), and so does the access-critical transaction below: an
access-critical step runs only inside it. No step of this version is
access-critical yet (the first ones, for accounts and sshd, are
[#28](https://github.com/Shironex/stackward/issues/28)); the transaction is
tested with steps that exist only in test builds. The lockout guard below is
still a design ([#27](https://github.com/Shironex/stackward/issues/27)). Both
are written down before any real step changes SSH, the firewall or users.

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
This version ships only `safe` steps and one opt in `networking` step (Docker
log rotation); no step touches SSH, the firewall or users yet.

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
  next apply says so and runs the restart before anything else.
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
- **Never touched.** No step can reach the kernel setting `ip_forward`,
  Docker daemon firewall settings, files managed by your platform or the
  provider firewall: no generator produces such a change and apply refuses
  anything a generator would not produce. The explicit list, checked at
  plan time, is [#27](https://github.com/Shironex/stackward/issues/27).

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
   rollback that fired has not been acknowledged; `systemd-run` is missing;
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
5. **Apply** the steps.
6. **Validate**: `sshd -t` passes, `sshd -T` shows every setting the
   steps mean to leave in place (from the step's own code), and something
   listens on each of sshd's ports, including every port it listened on
   before. A failed step or a failed check **rolls back at once**, stops the
   timer and exits 1; you watched it, so it needs no acknowledgement.
7. **Wait for `stackward confirm ID`**, which must run from a **new** SSH
   session: the same session is refused, because a session that survived the
   change proves nothing about a fresh login. `--console` is the one way
   around that rule, for the provider console. Confirm stops the timer and
   marks the transaction confirmed.
8. **No confirm before the deadline**: the timer restores the snapshot (the
   same undo as `stackward undo`), reloads what the steps reloaded, and marks
   the transaction rolled back. Access-critical steps then stay refused
   until `stackward confirm --ack-rollback ID`, so a rollback you did not
   see cannot go unnoticed. Safe and networking steps are not affected.

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
  is a strong signal, not a proof of every path; the lockout guard (#27)
  adds the checks on the second way in.
- Transient units do not survive a reboot. If the host reboots before the
  deadline, the timer is gone: the transaction stays `open` with its
  deadline passed, every access step and every confirm is refused, and
  `sudo stackward undo --transaction ID` rolls it back by hand (from SSH if
  it still works, otherwise from the provider console).
- The rollback waits up to 10 minutes for the run lock when an apply or a
  confirm holds it, and then gives up; the transaction then shows as open
  past its deadline, as after a reboot.
- A rollback restores files only while they still hold what the
  transaction wrote; a file you edited in the window is left alone, the
  transaction is marked `rollback-failed`, and you restore it from the
  backup by hand.

### Lockout guard

stackward will refuse to close public SSH unless another way in is proven:
Tailscale is running with key expiry off and the confirming session arrived
over the tailnet, or an explicit allowed source exists and the confirming
session came from it. Before any access step it already reminds you of your
provider console, because that is the recovery path of last resort.

### What will still go wrong

No design removes all risk. Keep provider console access, keep a second
session open while you work, and read the plan. Apply is tested on
disposable GitHub runner VMs (the `apply` and `transaction` scenarios in
[testing.md](testing.md)), never on a developer's own machine, and not on
your production server first.
