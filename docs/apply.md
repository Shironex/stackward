# stackward apply

`stackward apply` runs the steps of a plan you choose on the host the plan
was made for, with backups and a run journal. `stackward undo` reverses a
run from its journal. Access-critical steps run inside a
[transaction](#the-access-critical-transaction) that `stackward confirm`
keeps. All three are part of the upcoming 0.2 and are not in a release yet.
They are the only commands that change a system: `audit`, `probe`, `tui`
and `plan` stay read only.

```
stackward apply [--step ID]... [--all-safe] [--confirm-within 5m] [--yes] PLAN.json
stackward undo --run RUN_ID [--yes]
stackward undo --transaction ID [--yes]
stackward confirm [--console] ID
stackward confirm --ack-rollback ID
stackward confirm
```

```sh
sudo stackward plan --out plan.json            # read it first
sudo stackward apply --all-safe plan.json      # every safe step that is not opt in
sudo stackward apply --step docker-log-rotation plan.json
sudo stackward apply --all-safe plan.json      # again: nothing to do
sudo stackward undo --run 20260301T120000Z-1a2b3c
```

| Flag | Meaning |
|---|---|
| `--step ID` | apply this step (repeatable) |
| `--all-safe` | apply every `safe` step that is not opt in |
| `--yes` | do not ask; needed when stdin is not a terminal |
| `--confirm-within D` | access-critical steps: the deadline of the rollback timer (default `5m`, from `30s` to `30m`) |
| `--run RUN_ID` | (undo) the run to reverse, as apply printed it |
| `--transaction ID` | (undo) roll back an open transaction now and stop its timer |
| `--console` | (confirm) confirm from the provider console: skip the new SSH session check |
| `--ack-rollback ID` | (confirm) acknowledge a rollback, so access-critical steps may run again |

Exit codes: `0` applied, undone, confirmed or nothing to do (a transaction:
applied, validated and waiting for confirm); `1` a step failed part way (the
journal and the undo are printed) or a transaction rolled back at once; `2`
refused or an error before anything changed.

## What runs

Nothing runs unless you select it. `--step` names steps, `--all-safe` takes
every `safe` step that is not opt in, and both can be given together.

| Risk class | How it runs |
|---|---|
| `safe` | with `--all-safe` or `--step` |
| `networking` | only with `--step ID`: it restarts Docker, so containers stop and start |
| opt in | only with `--step ID` |
| `access-critical` | only with `--step ID`, in a run of its own (never with `--all-safe` or another step), inside the [transaction](#the-access-critical-transaction) |

The risk class and opt in come from the step's own code, not from the plan
file, so a plan that relabels a step cannot change how it is selected.

Before it asks, apply prints every step it will run with the files it
creates or replaces, the commands, the services it restarts and the notes,
then the steps already applied and the steps not selected. On a terminal it
asks `[y/N]`; without a terminal it refuses unless `--yes` is given.

## Before anything changes

Apply refuses, with the reason and without changing anything, when:

- it is not running as root (effective uid 0), or not on Linux;
- the plan file is not `stackward.plan.v1`, has a field this version does
  not know, or breaks the plan's own invariants (hashes, known step ids);
- the plan is for another host: the hostname hash in the plan must be this
  host's. There is no override; plan again on the host;
- a selected step id is not in the plan, or an access-critical step is
  selected together with `--all-safe` or a step that is not access-critical;
- a step is not one its generator would produce: an edit of a path the
  step does not own, new content it would not write, a command, validate
  command or undo command it would not run (see below);
- an edit's content was redacted in the plan;
- another apply or undo is running: every run takes an exclusive lock first
  (see [One run at a time](#one-run-at-a-time));
- a restart from an earlier run is still pending and you do not confirm
  finishing it (see [Pending restarts](#pending-restarts));
- a sysctl undo value is not the value the host holds now (see below);
- a file changed since the audit: for `replace` it must still hash to
  `old_sha256`, for `create` it must be absent (a file that already holds
  exactly the new content counts as done). A symlink or a non regular file
  is refused.

### A plan file is not trusted

A plan is a JSON file that anyone with write access to it could edit, and
apply runs as root. So every selected step is re-derived from the code of
its generator (`plan.Authorize`) before anything runs:

| Step | What apply accepts |
|---|---|
| `journald-cap` | one created file, `/etc/systemd/journald.conf.d/90-stackward-journal-cap.conf`, mode 0644, with exactly the content stackward writes; `systemctl restart systemd-journald`; undo `rm -f` of that file and the restart |
| `sysctl-hardening` | one created file, `/etc/sysctl.d/90-stackward-hardening.conf`, mode 0644, holding only keys of the hardening baseline at the value the checks want (never `net.ipv4.ip_forward`), rendered again from those keys and compared byte for byte; `sysctl -p` of that file; undo `rm -f` of it and `sysctl -w KEY=NUMBER` for each key it sets |
| `docker-log-rotation` | `/etc/docker/daemon.json` created or replaced with exactly what merging the rotation keys into the plan's old content gives (the old content itself is pinned by `old_sha256` and the file on the host); validated with `dockerd --validate --config-file`; `systemctl restart docker`; undo the restart (and `rm -f` when it created the file) |

`sysctl-hardening` has one more rule, because its undo restores values the
plan only states: the plan carries no copy of the audit's facts, so before a
step runs, `sysctl -w KEY=NUMBER` in its undo must name the value `KEY` has
on this host now (`/proc/sys`). That is the value the audit recorded, so a
plan cannot choose what undo sets a key to; a different number, or a value
that changed since the audit, is refused and the plan must be made again.
(`kernel.unprivileged_bpf_disabled` has no undo value and is not checked.)

Commands always run as an argument vector, never through a shell, with a
fixed `PATH` and the C locale.

## One run at a time

`apply` and `undo` take an exclusive `flock` on `/run/stackward/apply.lock`
(created 0600, directory 0700) before they read anything a run depends on,
without waiting, and hold it until they exit. The lock file holds the run id
of its holder (an undo writes `undo of RUN_ID`). A second run is refused,
changing nothing, with that id:

    stackward apply: another stackward run holds the lock /run/stackward/apply.lock (run 20260301T120000Z-1a2b3c); wait for it to finish; nothing was changed

Two runs could otherwise both read the same old file, both pass its SHA-256
precondition and interleave writes and journals. The lock belongs to the
open file, so a run that dies releases it, and a file left behind with no
live lock is taken over. It is `apply.AcquireRunLock` over the `Host` seam.
`confirm` and `undo --transaction` take it too, and the transaction state is
only read and written under it, which is what keeps one transaction open at
a time. The rollback timer waits for it (up to 10 minutes, trying every 2
seconds) instead of giving up.

## How a step runs

Steps run in plan order. For each step:

1. **Check.** The step's check reads the host. When the change is already
   in place, the step is skipped as `already`, so a second run changes
   nothing and says so. `journald-cap` and `docker-log-rotation` are in
   place when the file holds the planned content; `sysctl-hardening` when
   the drop-in holds it and every running value matches.
2. **Edits.** For each file, the precondition is checked again, then:
   - `replace`: `FILE.orig` is written the first time stackward replaces
     the file and never replaced after; the current file is copied to
     `/var/backups/stackward/<run-id>/<path>`; mode and owner are kept;
   - `create`: missing directories are created (0755) and the file gets the
     plan's mode;
   - the new content is written to a temporary file in the same directory,
     with its mode and owner, and synced;
   - the step's `validate` command runs on that staged file; a failure
     removes it and leaves the real file untouched;
   - the staged file is renamed over the real one and the directory synced;
   - the file must then hash to `new_sha256`.
3. **Commands.** They run after the edits. The restart of journald and of
   Docker runs only when the run changed the file; `sysctl -p` runs
   whenever the step is not already applied (the file can be in place with
   the running values still off).

### Pending restarts

When a step writes its file, the journal marks the step `restart_pending`;
the mark is cleared when its commands have run. If the restart fails, or the
run dies between the write and the restart, the file is in place but the
service still runs the old settings, and the step's check would call it
applied. So the next `apply`, before it loads your plan, looks through the
journals under `/var/backups/stackward` for steps still pending (undone runs
are skipped), prints them under `Pending restarts:`, asks `[y/N]` (or needs
`--yes`) and runs their commands first, recording them in the journal of the
run they belong to. Each step is authorized again, and its files must still
hold what the run wrote; if one changed since, the restart is dropped and
apply says so. A restart that fails again stops apply (exit 1) with the step
still pending, before any other step runs. `undo` clears the mark.

The first failure stops the run. Later steps are marked `not-run`, the
journal is saved, and apply prints the journal path, `stackward undo --run`
and the exact commands to undo by hand.

## The access-critical transaction

A step that touches SSH, the firewall or users is `access-critical` in its
own code. No step of this version is; the first ones come with
[#28](https://github.com/Shironex/stackward/issues/28). The transaction is
tested now with two steps that exist only in test builds (see
[Tests](#tests)). When the selection holds access-critical steps, apply:

1. prints the **provider console reminder**, then the preview;
2. refuses, changing nothing, when the state file says a transaction is
   open, or rolled back without an acknowledgement (see the states below);
3. runs the **preflight**, which only reads: `systemd-run --version`;
   `sshd -t` must pass now (otherwise a failure after the change could not
   be blamed on the change); `sshd -T` gives sshd's ports and `ss -Htln`
   must show something listening on at least one of them;
4. asks `[y/N]` (or needs `--yes`), then records the **session** that
   applies (see [confirm](#confirm));
5. copies the running binary to
   `/var/lib/stackward/transactions/<run-id>/stackward` (directory and file
   0700, owned by root) and runs that copy once as a systemd service
   (`systemd-run --wait ... version`), so a copy that systemd cannot start
   is found now;
6. writes `/var/lib/stackward/transaction.json` (0600,
   [schema/transaction.v1.json](../schema/transaction.v1.json)) with status
   `open` and the deadline, then **arms the timer**:
   `systemd-run --unit=stackward-rollback-<run-id> --on-active=<seconds>s
   --timer-property=AccuracySec=1s --timer-property=RemainAfterElapse=no
   --collect` with the copy and `undo --transaction <run-id> --yes
   --by-timer`, and checks that the `.timer` is active. If arming fails, the
   transaction is `aborted` and nothing changed;
7. applies the steps exactly as any apply does (backups, `FILE.orig`, the
   journal, which now carries a `transaction` object);
8. **validates**: `sshd -t`; `sshd -T` shows every setting the steps mean to
   leave (each step's generator states them, as `sshd -T` prints them); `ss
   -Htln` shows something on every port in `sshd -T` and every port that was
   listened on before (unless a step sets the port). The commands and their
   output go into the journal as `check` commands;
9. on a failed step or a failed check, **rolls back at once** (the same
   undo as `stackward undo`), then stops the timer, and exits 1. Otherwise it
   prints how to confirm and exits 0 with the timer armed.

Why a copy of the binary and not a shell script with the restore commands:
the rollback is the same code as `stackward undo` (it authorizes every step
again, refuses to overwrite a file that changed after the run, runs the
steps' own undo commands and updates the journal and the state), so there
is one rollback to test, not two. The copy is root only, so nobody else can
change what root will run, and it does not depend on the binary you started
staying where it is, unchanged, until the deadline. It is removed once
nothing will run it (after a confirm, an immediate rollback or an
acknowledgement).

### States

| Status | Means | Access steps |
|---|---|---|
| `open` | applied and validated; the timer fires at `deadline` | refused (one at a time) |
| `confirmed` | `stackward confirm` kept it | allowed |
| `rolled-back` | undone: by the timer (`cause: timer`), a failed check (`validation`), a failed step (`apply-failed`) or `undo --transaction` (`manual`) | refused after a timer rollback until `confirm --ack-rollback`; the others are acknowledged when they happen, because you watched them |
| `rollback-failed` | the undo itself failed part way (a file changed in the window, a reload failed) | refused until `confirm --ack-rollback`; check the files by hand |
| `aborted` | the timer could not be armed; nothing changed | allowed |

An `open` transaction whose deadline passed (the timer is gone after a
reboot, or it gave up waiting for the lock) refuses every access step and
every confirm, and says to run `sudo stackward undo --transaction ID`.

### Confirm

`sudo stackward confirm ID` keeps the change: it refuses when the deadline
has passed, compares the sessions, stops both transient units
(`systemctl stop`, then `systemctl is-active` must not say active), and
only then marks the transaction `confirmed` in the state and the journal.
If the timer cannot be stopped, nothing is marked and the rollback still
happens.

It must run from a **new SSH session**. The session that applied recorded
its audit session id (`/proc/self/sessionid`), its sshd session process
(pid and start time, from the process tree), `SSH_CONNECTION` and
`XDG_SESSION_ID` (from the login shell's environment when `sudo` dropped
them), and confirm compares its own:

- not over SSH at all (no sshd above it, no `SSH_CONNECTION`): refused,
  pointing at `--console`;
- any fact both sessions have that is equal: refused as the same session;
- applied outside SSH: any SSH session is new;
- otherwise at least one fact both have must differ; sessions that share no
  fact are refused.

`--console` skips the comparison. It is the path for the provider console,
where there is no SSH session to compare. The limits of the comparison
(tmux, `ControlMaster`, containers without `pam_loginuid`) are in
[safety.md](safety.md#access-critical-changes-rollback-timer-and-second-session-confirm).

`stackward confirm` without an id prints the current transaction.
`stackward confirm --ack-rollback ID` acknowledges a rollback.

### The rollback

The timer runs `undo --transaction ID --yes --by-timer` as root, with no
session. It waits for the run lock, does nothing unless the transaction is
still `open` (a confirm that came first wins), checks the host, then undoes
the run from its journal: files restored or removed, the steps' undo
commands run (the reload). The state says `rolled-back` with `cause: timer`
and stays unacknowledged. `sudo stackward undo --transaction ID` does the
same by hand, at once, and stops the timer. `stackward undo --run` refuses
a run that is an open transaction.

## The run journal

Every run that changes something writes
`/var/backups/stackward/<run-id>/journal.json` (directory 0700, file 0600),
rewritten atomically after every file and command, so a run that dies still
leaves a journal (with status `running`). A run with nothing to do writes no
journal and no backup directory. The format is
[schema/journal.v1.json](../schema/journal.v1.json):

- the run id (UTC start time and six random hex digits), status (`running`,
  `ok`, `failed`, `undone`), start and end times, the hostname hash;
- the plan file applied, with its SHA-256, schema and the version that
  wrote it;
- per step: its status (`applied`, `failed`, `already`, `not-run`), the plan
  step as applied, with old and new content redacted; `restart_pending`
  while its restart is undone; every file with its
  hashes, the mode and owner it was written with, its backup and whether
  this run wrote `FILE.orig`; every command (validate, command, undo) with
  its exit code, duration and redacted output.

## Undo

`stackward undo --run RUN_ID` reverses a run from its journal, newest change
first: each file the run replaced is restored from its backup with the mode
and owner it had, each file it created is removed, and then each step's own
undo commands run (the restarts, `sysctl -w` of the old running values).
`FILE.orig` copies stay. It refuses, changing nothing, when:

- not root, not Linux, or the run id is not one apply gave;
- the journal is for another host or the run was already undone;
- a step in the journal is not one its generator would produce (the same
  check as apply);
- a file no longer holds what the run wrote, or a backup no longer holds
  what the file held before; restore those by hand.

`kernel.unprivileged_bpf_disabled = 1` cannot be lowered again without a
reboot, and journal files vacuumed by the cap are gone; undo does not
pretend otherwise.

## No sandbox

The Landlock sandbox of `audit`, `probe` and `plan` forbids writing files,
so apply and undo do not apply it; their header says so. Their reach is
bounded instead by the rules above: only the selected steps, only the paths
and commands each step's own code produces, and only after every
precondition holds.

## Tests

Unit tests run apply and undo against a temporary directory with a fake
command runner (`internal/apply/applytest`), so `go test ./...` never writes
outside its temporary directory or starts a program, even as root. For the
transaction, `applytest.System` fakes `systemd-run`, `systemctl`, `sshd -t`,
`sshd -T` and `ss`, the session facts are injected, and a test "fires" the
timer by running the command it was given, with no session. The
`apply` [live host scenario](testing.md#live-host-scenarios) runs the real
binary as root on a disposable GitHub runner VM: plan, apply, apply again,
undo. The `transaction` scenario runs a real timer there with the test-only
access-critical steps of `internal/plan/txntest`, which only the scenario
binary carries (`go build -tags stackward_scenario`); released builds do not
contain them, and a test in `cmd/stackward` proves it.
