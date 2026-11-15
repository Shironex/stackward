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

## Version 0.2: plan and apply (planned)

Everything below is a design, not something you can run today. It is written
down now so the safety rules are settled before any code changes a server.

Fixing a finding on a remote machine is riskier than finding it. A wrong SSH
or firewall change can lock you out, and a hardening profile can break
Docker networking. So version 0.2 will separate looking from changing.

### Plan first, nothing changes

`stackward plan` will write a plan file and change nothing. Each step lists:

- the failing check it fixes;
- the exact edits, as a diff of old and new content, and any commands;
- a risk class: `safe`, `access-critical` (SSH, firewall, users) or
  `networking` (can restart Docker);
- how to undo it.

You read the plan, remove what you do not want, and only then apply it.
`--emit-script` will print an equivalent shell script for people who prefer
to read and run it themselves.

### Apply rules

`stackward apply plan.json` will follow these rules:

- **Idempotent.** A step whose check already passes is skipped.
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
