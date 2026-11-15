# Testing

stackward has three layers of tests. Each catches a class of bug the
others miss.

| Layer | Where | What it proves |
|---|---|---|
| Unit tests | `internal/**/*_test.go` | collectors parse what the host prints, checks judge fake facts right (pass, warn or fail, unknown) |
| Golden fixtures | `test/fixtures/<scenario>/` | a saved facts file gives exactly the expected report, valid against `schema/report.v1.json`; a few fixtures also pin the Markdown (`expected.md`) and the text report (`expected-*.txt`: terminal at 80 and 120 columns, plain, grouped, `--all`) |
| Live host scenarios | `test/scenarios/` | the real binary, as root, under the Landlock sandbox, on a real Ubuntu host with real containers, firewall and sshd, reports what it should, and writes nothing; `apply` and `undo` change exactly what the plan says, and the access-critical transaction rolls back by itself |

The first two run with `go test ./...`. See [architecture.md](architecture.md)
for how to add a fixture. `go test ./...` never changes the machine it runs
on: the apply and undo tests write only under `t.TempDir()` through the
`apply.Host` seam and start no program (a fake runner records the
commands), even when the tests run as root. Apply on a real host is tested
only by the `apply` scenario, on a disposable runner VM.

## Live host scenarios

Fixtures start from facts, so they cannot catch a collector that never
gets those facts on a real machine: a command that needs to write and dies
under the sandbox, or a real container that a check misreads. The
scenarios close that gap. Each one sets up a host state, runs
`sudo stackward audit --json` with the sandbox on, and asserts the level of
specific checks and subjects.

| Scenario | Host state | Asserts |
|---|---|---|
| `bad-docker` | Redis published on 0.0.0.0, a container mounting the Docker socket, a privileged root container with SYS_ADMIN, two compose projects sharing a network with a database | DKR-001, DKR-010, DKR-020, DKR-021, DKR-022 and DKR-030 fail on those containers |
| `hardened-docker` | the same services on 127.0.0.1 or behind a DOCKER-USER drop rule, non-root users, no socket, one network per project | the same checks pass |
| `socket-proxy` | a read only Docker socket proxy on 127.0.0.1:2375 | DKR-002 is info (not a raw daemon on TCP), DKR-011 passes |
| `ufw` | UFW deny by default, SSH allowed only from 192.0.2.0/24, a published container port | the firewall collector is ok under the sandbox, NET-001 passes, NET-002 to NET-008 are judged (not unknown), DKR-001 fails on the published port |
| `ufw-docker` | UFW active with the DOCKER-USER block of a standard ufw-docker install in `/etc/ufw/after.rules`, containers publishing 443 and 8000, and a `ufw route allow` rule for 443 only | the chain is recognised: NET-004 says 443 is public by design and 8000 passes, the inferred profile is public-web, DKR-001 passes on both containers |
| `ssh` | an sshd drop-in with `PasswordAuthentication yes`, then a hardened one | SSH-001 fails, then passes; the drop-in is removed afterwards |
| `read-only` | the `bad-docker` containers, UFW active and a process listening on a custom port | nothing changes on the host during an audit with and without the sandbox, strace sees no write attempt outside `--out` (the socket ownership snapshot taken before the sandbox included), and under the sandbox the snapshot names the owner of the custom port |
| `non-root` | the `bad-docker` containers | as a user, no collector crashes and the report says it ran without root; as a user with no groups, no check marked `needs_root` passes blind: a pass without root must not be a fail or warn in a root audit of the same host, nor say "not inspected" |
| `apply` | kernel values off baseline, a persistent journal without a cap, a `daemon.json` without log rotation | stackward changes the host here (as in `transaction` and `updates`): `plan`, then `apply` without root is refused; `apply --all-safe --step docker-log-rotation` writes exactly the planned files, keeps the mode of `daemon.json`, writes `daemon.json.orig` and the run backup, a journal with status ok (0600), changes the running values and leaves Docker up with json-file logs; nothing else under `/etc` changes; a second apply says nothing to do, writes no run, changes no file and does not restart Docker; a new audit passes DKR-031 and KRN-004; `undo --run` restores `/etc` (except `daemon.json.orig`) and the running value |
| `transaction` | the runner's own sshd, the scenario binary (`-tags stackward_scenario`) with the test-only access-critical steps, and no SSH session (as after a dropped connection) | plan refuses `txn-test-close-public` with the lockout guard's reason (the runner has no tailnet); a step `sshd -t` refuses rolls back at once (exit 1, file gone, no timer, not blocking); `txn-test-sshd` with `--confirm-within 30s` arms `stackward-rollback-ID.timer`, `sshd -T` shows `logingracetime 60`, a second transaction and a confirm without `--console` are refused; nobody confirms, the timer rolls back (file gone, `sshd -t` passes, port 22 listened on, `ssh.service` active, journal undone), access steps stay refused until `confirm --ack-rollback`; the boot unit `stackward-boot-rollback-ID.service` is enabled while open, passes `systemd-analyze verify` and is removed by the timer's rollback; a second transaction confirmed with `--console` stops the timer, removes the boot unit and keeps the drop-in past the deadline; a reboot is replayed by stopping the transient timer and sshd, then starting the boot unit and `ssh.service` together, so the ordering makes sshd wait: it rolls back before sshd starts (`cause: boot`), removes itself, `sshd -t` passes, `ssh.service` runs with `logingracetime 120` again, and access steps wait for `confirm --ack-rollback`; a left over boot unit makes apply refuse access steps with the fix printed |
| `updates` | unattended-upgrades installed but off, `apt-daily-upgrade.timer` enabled but stopped (so no run, and no reboot, can start), fail2ban absent, the runner's sshd reachable from anywhere | plan holds `unattended-upgrades`, the opt in `unattended-upgrades-reboot` and the opt in, access-critical `fail2ban-sshd` with its install as a named command; applying the first two writes exactly the planned drop-ins, `apt-config` shows the values, nothing reboots, a second apply says nothing to do, UPD-001 passes, `undo --run` restores every file under `/etc`; `fail2ban-sshd` runs as a transaction with no SSH session, installs fail2ban, passes `fail2ban-client -t`, the sshd jail runs and ignores loopback, `confirm --console` keeps it, a second apply says nothing to do, CS-010 passes, and `undo --run` removes the jail and purges fail2ban |

CI runs every scenario on `ubuntu-24.04` and `ubuntu-22.04` runners
(`.github/workflows/scenarios.yml`) for pull requests that touch `internal/`,
`cmd/` or `test/scenarios/`, on main, and on demand. A failing assertion is
listed in the job summary and as an annotation, with the expected and the
actual level and the check's message, and the reports, traces and diffs are
uploaded as an artifact.

### The non-root rule

`needs_root` in the catalog means a check "may report unknown without
root", not "can never pass". Some runner images make every sshd file
readable by any user, so SSH-001 can pass from the files, and USR-003 passes
when no default cloud account exists, which `/etc/passwd` shows to everyone.
The scenario therefore tests the real promise, that no check passes without
having inspected what it needs, by running a root audit of the same host
beside the one for the user with no groups (`assert.sh nofalsepass`). A pass
without root is a false pass when the root audit judges the same id and
subject fail or warn, or when its message says "not inspected". The summary
line counts the passes compared and names any false pass with its root
level. There are no per check exemptions.

### The read-only check

The `read-only` scenario backs the promise in [safety.md](safety.md) with
two independent observations:

- `test/scenarios/snapshot.sh` lists every entry of `/etc` with its content
  hash, Docker's metadata under `/var/lib/docker`, the lock files and apt
  caches the audit's commands know about, `/run/sshd`, `lastlog`, and the
  names in `/tmp`, `/var/tmp` and `/dev/shm`. It runs before and after an
  audit with the sandbox and one with `--no-sandbox`; any difference fails.
  Left out on purpose: Docker's layer contents (`overlay2`, written by the
  processes inside running containers), container json logs (container
  output, written by dockerd), and the mtimes of the temporary directories
  (other processes use them). stackward reads none of those.
- Both audits run under `strace -f`, which follows every command stackward
  starts. Any open with a write flag outside the `--out` file and
  `/dev/null`, and any call that creates, removes, renames or changes the
  mode, owner or times of a file, fails, including attempts the sandbox
  refused. The `--no-sandbox` run is what a kernel without Landlock gets,
  where nothing else stops a write.

### Run a scenario yourself

Scenarios change the machine they run on: they start containers, enable
UFW, edit the sshd configuration, insert iptables rules and add a system
user. **Run them only in a throwaway VM, never on a production host**, not
even one you are about to rebuild. Each scenario undoes its setup when it
ends, but a scenario that is interrupted can leave UFW enabled or a drop-in
in place.

A fresh Ubuntu 24.04 or 22.04 VM works. With Multipass, for example:

```sh
multipass launch 24.04 --name stackward-scenarios --cpus 2 --memory 4G --disk 15G
multipass shell stackward-scenarios
```

Inside the VM (passwordless sudo is required):

```sh
sudo apt-get update
sudo apt-get install -y docker.io docker-compose-v2 jq ufw openssh-server strace git golang-go
sudo usermod -aG docker "$USER" && newgrp docker

git clone https://github.com/Shironex/stackward.git && cd stackward
CGO_ENABLED=0 go build -trimpath -o stackward ./cmd/stackward

test/scenarios/run.sh list
STACKWARD=$PWD/stackward test/scenarios/run.sh bad-docker
```

The `transaction` scenario needs the scenario binary, the only build with
the test-only access-critical steps:

```sh
CGO_ENABLED=0 go build -trimpath -tags stackward_scenario -o stackward-scenario ./cmd/stackward
STACKWARD=$PWD/stackward-scenario test/scenarios/run.sh transaction
```

Reports, traces and the assertion log land in `./scenario-out` (set `OUT` to
change it). The distribution's Go may be older than `go.mod` asks for; if
the build fails, install Go from go.dev or build on another machine with
`GOOS=linux GOARCH=amd64 CGO_ENABLED=0` and copy the binary in.

When you are done, delete the VM (`multipass delete --purge
stackward-scenarios`) rather than reusing it for anything else.

### Add a scenario

1. Write `test/scenarios/<name>.sh` with three functions:
   `scenario_setup` (idempotent: remove what a previous run left first),
   `scenario_verify` (call `audit <report-name>`, then `expect ...`) and
   `scenario_cleanup`. Name containers `sw-*` and compose projects `sw*`
   so cleanup never touches anything else, and use only documentation
   ranges and `example.com`.
2. Assert with `expect check "$REPORT" ID SUBJECT LEVELS`, where SUBJECT
   is a regular expression over the whole subject and LEVELS a list such as
   `fail`, `pass|info` or `!unknown`. `test/scenarios/assert.sh` documents
   the other forms (`collector`, `sandbox`, `none`, `field`).
3. Add the name to `SCENARIOS` in `run.sh` and to the matrix in
   `.github/workflows/scenarios.yml`.

Scenarios are live host only: they never write golden fixtures. When a
scenario finds a bug, fix it with a unit test, and add a fixture from
`stackward audit --dump-facts` if the facts show a new shape.

## Install script

`scripts/install.sh` is tested by `test/install/run.sh` (workflow
`install-script`, on Ubuntu 24.04, 22.04 and 24.04 arm64). A python3 http
server on 127.0.0.1 plays the release URLs (`STACKWARD_BASE_URL` points at
it) and serves several fake releases with a stub `stackward`, a built `.deb`,
archives and a `checksums.txt`, so nothing real is downloaded or installed.
The scenarios cover install (also piped into `sh`, the one-line form),
re-install, update when current and from an older version, no downgrade on
update, uninstall that leaves nothing, files the script did not add left alone,
a tampered checksum that writes nothing, a passing and a failing cosign stub,
`--dry-run`, `--no-sudo`, plain output without escape codes, terminal output
recorded with `script`, wget as the downloader, and the apt path with the fake
package (including that apt prints no `_apt` notice).

The binary scenarios write only under a temp directory and run anywhere. The
apt scenarios install and remove a fake `stackward` package, so they run only
with `STACKWARD_TEST_DEB=1`, which CI sets on its disposable runner. Never set
it on a machine you use.
