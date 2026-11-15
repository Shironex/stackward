# Safety

## Version 0.1: read only

Version 0.1 audits. It does not change your server, so it cannot lock you
out or break a service. The promise, enforced by design and, on supported
kernels, by the Landlock sandbox described in the
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

`stackward plan` exists now (in the upcoming 0.2, not yet released). Everything
from "Apply rules" on is still a design, not something you can run today. It
is written down now so the safety rules are settled before any code changes a
server.

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

### Apply rules (planned)

`stackward apply plan.json` will follow these rules:

- **Idempotent.** A step whose check already passes is skipped.
- **No blind overwrites.** A file whose content no longer matches the hash
  in the plan is not touched; plan again.
- **Backups.** The first time a file is changed, a `FILE.orig` copy is kept.
  Every overwrite is also copied to a per run backup directory, and a run
  journal records the old and new values, so you always have a change log.
- **Never touched.** The kernel setting `ip_forward`, Docker daemon firewall
  settings, files managed by your platform (other than an opt in permission
  fix) and the provider firewall.

### Access critical changes: rollback timer and second session confirm

Changes to SSH, the firewall and users run as a transaction:

1. Take a snapshot of what will change.
2. Arm a rollback timer in `systemd` that runs independently of your SSH
   session, so a dropped connection cannot stop it.
3. Apply the change.
4. Validate it: `sshd -t`, the effective `sshd -T` values, and that the
   listeners match what the configuration says.
5. Wait for `stackward confirm`, which must be run from a **new** SSH
   session (a different session id and source port). The same session is
   refused, because a session that survived the change proves nothing about
   a fresh login.
6. If no confirmation arrives before the deadline, the timer restores the
   snapshot automatically.

Only one transaction can be open at a time, and a rollback that fired blocks
further access changes until you acknowledge it.

### Lockout guard

stackward will refuse to close public SSH unless another way in is proven:
Tailscale is running with key expiry off and the confirming session arrived
over the tailnet, or an explicit allowed source exists and the confirming
session came from it. Before any access step it will remind you where your
provider console is, because that is the recovery path of last resort.

### What will still go wrong

No design removes all risk. Keep provider console access, keep a second
session open while you work, and read the plan. These steps are tested in
virtual machines, not on your production server first.
