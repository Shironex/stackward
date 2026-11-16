# Testing

stackward has four layers of tests. Each catches a class of bug the
others miss.

| Layer | Where | What it proves |
|---|---|---|
| Unit tests | `internal/**/*_test.go` | collectors parse what the host prints, checks judge fake facts right (pass, warn or fail, unknown) |
| Golden fixtures | `test/fixtures/<scenario>/` | a saved facts file gives exactly the expected report, valid against `schema/report.v1.json`; a few fixtures also pin the Markdown (`expected.md`) and the text report (`expected-*.txt`: terminal at 80 and 120 columns, plain, grouped, `--all`) |
| Live host scenarios | `test/scenarios/` | the real binary, as root, under the Landlock sandbox, on a real Ubuntu host with real containers, firewall and sshd, reports what it should, and writes nothing; `apply` and `undo` change exactly what the plan says, and the access-critical transaction rolls back by itself |
| VM matrix | `test/vm/` | on official Ubuntu 22.04 and 24.04 and Debian 12 and 13 cloud images, booted in QEMU, apply over real SSH sessions: a rollback by the timer gives back the access the change took, a confirm from a second session keeps the change past the deadline and a reboot, the lockout guard refuses a change that would lock the session out, and the account steps undo byte for byte |

The first two run with `go test ./...`. See [architecture.md](architecture.md)
for how to add a fixture. `go test ./...` never changes the machine it runs
on: the apply and undo tests write only under `t.TempDir()` through the
`apply.Host` seam and start no program (a fake runner records the
commands), even when the tests run as root. Apply on a real host is tested
only by the scenarios and the VM matrix, on disposable VMs, and refuses to
run in any other CI job (see [Apply refuses in CI](#apply-refuses-in-ci)).

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
| `updates` | unattended-upgrades installed but off, `apt-daily-upgrade.timer` enabled but stopped (so no run, and no reboot, can start), fail2ban absent, the runner's sshd reachable from anywhere | plan holds `unattended-upgrades`, the opt in `unattended-upgrades-reboot` and the opt in, access-critical `fail2ban-sshd` with its install as a named command run before the jail is written; applying the first two writes exactly the planned drop-ins, `apt-config` shows the values, nothing reboots, a second apply says nothing to do, UPD-001 passes, `undo --run` restores every file under `/etc`; `fail2ban-sshd` runs as a transaction with no SSH session, installs fail2ban, passes `fail2ban-client -t`, the sshd jail runs and ignores loopback, `confirm --console` keeps it, a second apply says nothing to do, CS-010 passes, and `undo --run` removes the jail and purges fail2ban |
| `paas-env` | a Coolify layout without Coolify (`/data/coolify` owned by `9999:root`, folders 0700): an app and a service `.env` and the main `.env` at 0644 owned by uid 9999, an `.env.production` owned by uid 1000 and an `.env.example`, both 0644 | plan holds the opt in `paas-env-perms`; apply writes exactly the three planned units, `systemd-analyze verify` accepts them, the timer is active and the service succeeded: the app and service `.env` are 0600, the main `.env` 0640, the uid 1000 file and the template stay 0644, no owner and no byte of content changes; after a "deploy" reopens an `.env` and adds a new one, the timer (not apply) closes both within 100 seconds; a second apply says nothing to do, SEC-002 passes, the unit's journal holds no `.env` value; `undo --run` removes the three units, systemd no longer knows the timer, every file under `/etc` is byte for byte as before and the closed modes stay closed |
| `firewall` | UFW installed, stock and off, the runner's sshd on 22, a host service on `0.0.0.0:8090`, a container publishing 8080, and a network namespace on a veth pair as an outside client (198.51.100.2), so reachability is tested without touching the runner's own network | `plan --profile tunnel` holds `ufw-policy` and holds back `ufw-docker` until UFW is on; `ufw-policy` runs as a transaction with no SSH session: UFW is active with a default deny, SSH stays reachable from the client, 8090 closes, 8080 stays reachable (Docker forwards past UFW), `confirm --console` keeps it, a second apply says nothing to do, NET-001 passes; `ufw-docker` from a new plan writes the block to `after.rules`, closes 8080 from the client with SSH still reachable, a second apply says nothing to do, DKR-001 passes; undoing both brings 8080 and 8090 back, `DOCKER-USER` as Docker had it, the logging chain gone, UFW off and every UFW file byte for byte as before |

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

## VM matrix

The live host scenarios run on the runner itself, which is always Ubuntu,
and with no SSH session (as after a dropped connection). The VM matrix
(`.github/workflows/vm-matrix.yml`, scripts in `test/vm/`) covers what they
cannot: other distributions, and the transaction as an owner meets it,
through SSH. Each job boots one official cloud image in QEMU on a GitHub
hosted runner (KVM when the runner exposes `/dev/kvm`, which standard Linux
runners do; TCG otherwise, with every timeout sized for it). cloud-init
seeds an account and an SSH key, stackward is built once and copied in,
and from then on the runner only talks to the VM over SSH on `127.0.0.1`.
Every command is a new SSH session, as a second terminal would be.

| Scenario | Seed | What it proves |
|---|---|---|
| `rollback` | `users` | `sshd-hardening` with `--confirm-within 60s`, applied over SSH, the session then gone: while open, `sshd -T` shows every planned setting and a new password login is refused (the change took a way in away); nobody confirms, the timer fires (`rolled-back`, `timer`), the drop-in is gone and a new password login works again: the rollback gave the access back. Then `ufw-policy` the same way: while open UFW is active with a default deny and port 8090 is closed from outside while a new SSH login works; after the timer UFW is off and 8090 answers again |
| `confirm` | `users` | a confirm from the session that applied is refused; one from a new session keeps `sshd-hardening` (`confirmed`, `new-ssh-session`), stops the timer and removes the boot unit; past the deadline the drop-in and its `sshd -T` settings stay and a password login stays refused. `ufw-policy` confirmed the same way stays active with 8090 closed. After a reboot both are still in effect and no rollback unit exists |
| `guard` | `users` | apply refuses in CI without the flag, even under `sudo` (exit 2, nothing changed), and goes past the gate with it. Then the only account that can sudo logs in with a password: plan lists `sshd-hardening` as refused by the lockout guard, and apply of a plan made before that refuses from the live host, exit 2: no drop-in, no transaction, no timer, password login still works |
| `accounts` | `accounts` | as the image's default account (`ubuntu`, `debian`): `admin-user` with `--admin-keys-from`, a login as the new account with the copied key, which confirms; from that account `sshd-hardening` and `lock-default-user`, each confirmed from a new session; the default account can no longer log in; then undo, newest first, and `passwd`, `group`, `shadow`, `gshadow`, `subuid`, `subgid` and the default account's `authorized_keys` are byte for byte as before |
| `rootonly` | `root` | with no account but root, as some providers hand a server out: `admin-user` with `--admin-keys-from root`, the plan naming `/root/.ssh/authorized_keys` and pointing at `sshd-hardening`, a login as the new account with root's key, which confirms; undo, and the account files and root's `authorized_keys` are byte for byte as before. Then the package lists emptied as on a fresh image: plan holds `fail2ban-sshd` with `apt-get update` named before the install; with the apt sources moved aside the install fails and the transaction ends `rolled-back` (not `rollback-failed`), with no `/etc/fail2ban` and no pending restart; with the sources back a new plan still offers it, and it installs, runs, confirms and undoes cleanly |

Assertions check the outcome, not just exit codes: `sshd -T` in the VM,
`ufw status verbose`, an HTTP request to the VM's port 8090 through the
forwarded port, and brand new key and password logins. The password login
uses `SSH_ASKPASS`, so no `sshpass` is needed. Failures are listed in the
job summary and annotated like the scenarios', and the results, the VM's
serial console and cloud-init's status are uploaded.

It runs on pull requests that touch `internal/apply/`, `internal/plan/`,
the apply, transaction and plan commands, `cmd/`, `test/vm/`,
`test/scenarios/` or the workflow, every Monday, and on demand. Each
distribution and scenario is its own job, so they run in parallel and one
failure does not cancel the others; the images are cached by their
published checksum. When the weekly run fails, its last job opens an issue
titled "Weekly VM matrix failed", or comments on the one already open; it is
the only job with `issues: write`.

### Apply refuses in CI

Apply changes SSH, the firewall and accounts. On a shared or self hosted
CI runner a mistake would lock that runner out or leave it changed for the
next job, so `stackward apply` refuses, exit 2 and nothing changed, when it
finds a CI environment (`CI`, `GITHUB_ACTIONS`, `GITLAB_CI`, `JENKINS_URL`
and the other variables CI systems set; `CI=false` does not count), unless
the job sets `STACKWARD_CI_APPLY=throwaway-vm`. `sudo` drops the caller's
environment, so apply also reads the environment of every process above it
(the job's shell still holds the variables). The step list of
`stackward tui --plan` applies through the same code and refuses the same
way. `undo` and `confirm` are not gated: they only reverse or keep what an
apply did, and the rollback timer must never be refused.

Two jobs set the flag, and both own a throwaway VM: the scenario jobs of
`scenarios.yml` (a GitHub hosted runner is a fresh VM for that job alone,
deleted after it) and the VM matrix. In the matrix, apply runs inside the
QEMU VM, where no CI variable reaches it over SSH, and the `guard`
scenario sets `GITHUB_ACTIONS` there itself to test the refusal. The `test`
job of `ci.yml` checks that apply refuses on its runner, with and without
`sudo`, using a plan file that does not exist, so even a broken gate could
not change that runner. Never set the flag anywhere else.

### Run the matrix yourself

**Never run apply on your own machine**, not even to try a step: it rewrites
sshd's configuration, turns on a firewall, creates and locks accounts and
arms timers that roll back as root, all on the machine it runs on. A
laptop or desktop is not what the plan was made for, its rollback and boot
units would stay behind, and a lockout there has no provider console. The
matrix exists so nobody has to: everything below runs apply only inside a
VM that `vm.sh` boots from a fresh copy of the image.

On Linux (x86_64 or arm64), with QEMU:

```sh
sudo apt-get install -y qemu-system-x86 qemu-utils cloud-image-utils jq curl
# arm64 hosts: qemu-system-arm qemu-efi-aarch64 instead of qemu-system-x86
CGO_ENABLED=0 go build -trimpath -o stackward ./cmd/stackward

STACKWARD=$PWD/stackward test/vm/vm.sh boot debian-12 users
test/vm/run.sh rollback
test/vm/vm.sh stop
```

`vm.sh` uses KVM when `/dev/kvm` is readable and writable by you (add
yourself to the `kvm` group), and TCG otherwise, which works but takes
several minutes per boot. The image is cached in `~/.cache/stackward-vm`
(`VM_CACHE`), checked against the distribution's published checksum; the
VM writes only to an overlay in `./vm-out` (`VM_DIR`). The `accounts`
scenario needs the `accounts` seed (`vm.sh boot ubuntu-24.04 accounts`),
and `rootonly` the `root` seed (`vm.sh boot ubuntu-24.04 root`);
`run.sh list` names each scenario's seed. Boot a fresh VM for every
scenario: they change the VM and do not undo everything. `vm.sh ssh` opens
a shell in it. Results land in `./vm-scenario-out` (`OUT`). SSH and the
test port are forwarded on `127.0.0.1:2222` and `127.0.0.1:8090`
(`VM_SSH_PORT`, `VM_HTTP_PORT`).

On macOS, run the same commands inside a Linux VM made with
[Lima](https://lima-vm.io), so QEMU, the images and apply all stay inside
it:

```sh
brew install lima
# Apple M3 or later on macOS 15 or later can pass KVM through:
limactl start --name=stackward-matrix --set '.nestedVirtualization=true' template://ubuntu-24.04
# older Macs: limactl start --name=stackward-matrix template://ubuntu-24.04 (the VM then runs under TCG)
GOOS=linux GOARCH=arm64 CGO_ENABLED=0 go build -trimpath -o stackward-linux-arm64 ./cmd/stackward
limactl shell stackward-matrix
```

Inside the Lima VM (it mounts your home directory, so the checkout and the
binary are there):

```sh
sudo apt-get install -y qemu-system-arm qemu-efi-aarch64 qemu-utils cloud-image-utils jq curl
STACKWARD=$PWD/stackward-linux-arm64 VM_DIR=/tmp/vm test/vm/vm.sh boot ubuntu-24.04 users
VM_DIR=/tmp/vm OUT=/tmp/vm-out test/vm/run.sh confirm
VM_DIR=/tmp/vm test/vm/vm.sh stop
```

On an Apple Silicon Mac, `vm.sh` boots the arm64 images; CI tests the
amd64 ones. Delete the Lima VM (`limactl delete -f stackward-matrix`) when
you are done.

### Add a VM scenario

1. Write `test/vm/<name>.sh` with a `scenario_verify` function. Reach the
   VM only through the helpers in `test/vm/lib.sh` (`vm`, `ssh_as`, `pw`,
   `apply_as`, `confirm_as`, `plan_as`), so every command is a new SSH
   session, and assert outcomes (`expect_sshd`, `expect_http`,
   `expect_key_login`, `expect_password_login`, `note`).
2. Add `<name>:<seed>` to `SCENARIOS` in `test/vm/run.sh`, and the name to
   the matrix in `.github/workflows/vm-matrix.yml`.
3. Use only `127.0.0.1` and documentation addresses; the scripts never
   reach anything but the VM they booted.

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
