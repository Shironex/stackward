# Scheduled audits

An audit you ran once tells you how the server looked that day. To catch
drift, run it on a schedule and alert on the result. stackward never installs
anything itself, so it does not set up a timer for you: `stackward schedule
--print` prints a systemd service and timer unit, and you install them by
hand. The scheduled run writes the JSON report and a Prometheus textfile
metric that node_exporter picks up.

## What `schedule --print` does

It prints two units to stdout and exits. It writes no file, creates no
directory, enables nothing and talks to no service (systemd included). Run
without `--print` it refuses. A test runs it in an empty directory and fails
if anything appears there.

```sh
stackward schedule --print > stackward-audit.units
less stackward-audit.units        # read what you are about to install
```

The output is the service unit, then the timer unit, each headed by a
comment that names the file it belongs in.

| Flag | Default | Meaning |
|---|---|---|
| `--print` | (required) | print the units |
| `--on-calendar` | `daily` | when to run, a systemd `OnCalendar` expression. Check it with `systemd-analyze calendar 'Mon *-*-* 03:00'` |
| `--randomized-delay` | `1h` | spread the start over up to this long, so a fleet of servers does not audit at the same second; `0` for none, otherwise whole seconds and at least `1s` |
| `--user` | `root` | the account the audit runs as (see [the account](#the-account)) |
| `--report-dir` | `/var/lib/stackward` | where `report.json` goes |
| `--textfile-dir` | `/var/lib/prometheus/node-exporter` | the node_exporter textfile directory, where `stackward.prom` goes; empty for no metric |

The unit makes both output directories writable, so neither may be a top
level directory (`/var`, `/srv`) or lie in `/etc`, `/usr`, `/boot`, `/root`,
`/bin`, `/sbin`, any `/lib*`, `/proc`, `/sys` or `/dev`.
| `--binary` | this binary | absolute path of the stackward the unit runs |

Audit flags after `--` are added to the scheduled audit:

```sh
stackward schedule --print -- --profile tunnel --timeout 30s
```

They are parsed and checked like `stackward audit`'s own flags, so a typo
fails now and not at 3 in the morning. The unit sets `--format json`,
`--out`, `--textfile` and `--fail-on never` itself, so those are refused
after `--`, and so are `--facts`, `--dump-facts` and `--no-sandbox` (a
scheduled run audits the live host inside the sandbox).

### Nothing can be smuggled into the unit

Every value that ends up in a unit is checked first. A newline or other
control character would start a new directive, a `%` is a systemd specifier
and a backslash is an escape (or a line continuation at the end of a line),
so all of them are refused in `--on-calendar` and in every audit flag; paths
must be clean absolute paths of letters, digits and `. _ / @ + -`; `--user`
must be a plain account name. Audit flags are then printed quoted where
needed, with `$` escaped (and `%`, as a second line of defence), so systemd
neither expands a specifier nor a variable in `ExecStart`.

## What the scheduled run does

```
ExecStart=/usr/local/bin/stackward audit --format json --fail-on never \
  --out /var/lib/stackward/report.json.tmp \
  --textfile /var/lib/prometheus/node-exporter/stackward.prom.tmp
ExecStartPost=/bin/mv -fT /var/lib/stackward/report.json.tmp /var/lib/stackward/report.json
ExecStartPost=/bin/mv -fT /var/lib/prometheus/node-exporter/stackward.prom.tmp /var/lib/prometheus/node-exporter/stackward.prom
TimeoutStartSec=30min
```

- The audit is the ordinary read only audit, with the Landlock sandbox on.
  It writes the report (mode 0600) and the metric (mode 0644, so a
  node_exporter running as its own user can read it) to temporary names.
- Output paths are opened without following a symlink and must turn out to
  be a regular file with a single link: a hard link to another file, a FIFO
  (which would block the run) or a device is refused. The textfile
  directory is often shared with other programs, so whatever sits at
  `stackward.prom.tmp` is unlinked first (its target is left alone) and the
  file is created fresh.
- `ExecStartPost` renames each file into place. A rename within a directory
  is atomic: readers see the old file or the new one, never half of one.
  `-T` makes `mv` refuse to move the file into a directory planted at the
  final name. node_exporter only reads `*.prom`, so it ignores the
  temporary file.
- A run that hangs is stopped after 30 minutes (`TimeoutStartSec`) and
  counts as failed.
- The renames run only when the audit succeeded. When it fails (exit 2) the
  previous files stay, the unit is marked failed, and the timestamp in the
  metric stops moving, which is what the [stale run alert](#alerting) catches.
- `--fail-on never` keeps findings from failing the unit: findings are the
  report's job, the unit fails only when stackward itself failed.

The rename is done by `mv` in the unit and not by stackward: under the
Landlock sandbox the audit process can no longer create, rename or remove a
file, and that promise stays as it is. Opening `--out` and `--textfile`
before the sandbox is how it writes them, as `--out` always did.

### Hardening

The service is confined by systemd on top of stackward's own sandbox. The
whole file system is read only except the two output directories
(`ProtectSystem=strict` and `ReadWritePaths`), home directories are read only,
`/tmp` is private, `NoNewPrivileges`, no new namespaces, no realtime, no
SUID files, kernel tunables, modules, logs, control groups and the clock are
protected, and `IPAddressDeny=any` blocks all IP traffic (the audit makes
none). `SystemCallFilter=~@mount @module @reboot @swap @clock @cpu-emulation
@obsolete @raw-io @debug` makes those system calls fail with `EPERM`: no
collector mounts, loads a module, reboots, sets the clock, does raw I/O or
traces a process (`@debug` holds `ptrace` and `process_vm_writev`). Nothing
in it hides what the audit inspects: there is no `PrivateNetwork` (the audit
reads the host's listeners), no `PrivateDevices` and no `ProtectProc`.

With `--provider` among the audit flags, `IPAddressDeny` is left out, because
the provider firewall is read over HTTPS. Give the credentials in a file
named by the `STACKWARD_*_FILE` variables, set with `Environment=` or
`EnvironmentFile=` in a drop in (`systemctl edit stackward-audit.service`),
never in `ExecStart` (see [provider-firewall.md](provider-firewall.md)).

### The account

Full coverage needs root: some checks read the firewall ruleset, files root
does not own or which process owns a socket. As root, the unit keeps only
these capabilities (`CapabilityBoundingSet`). Each one was measured: in a
Debian 12 container running systemd, with nftables, iptables-legacy, sshd, a
listener owned by another user and an account's `.ssh` at mode 0700, the
printed unit gave the same results as an unconfined `sudo stackward audit`,
and dropping each capability changed them as the table says.

| Capability | What the audit uses it for | Without it | What else it allows |
|---|---|---|---|
| `CAP_NET_ADMIN` | the kernel asks for it before it lists the nftables ruleset at all, read or write (`nft list ruleset`, `iptables-nft -S`) | the firewall collector ends partial, NET-001 and the checks that build on it say `unknown` | changing the firewall, routes and links over netlink |
| `CAP_NET_RAW` | `iptables-legacy -S` opens a raw socket to read the tables | the same, on hosts that use iptables-legacy | sending raw packets (but `IPAddressDeny=any` drops IP traffic) |
| `CAP_SYS_PTRACE` | read other processes' `/proc/<pid>/fd` for the socket owner snapshot ([safety.md](safety.md#read-before-the-sandbox)) | listeners lose their process names (NET-004 and the checks that infer SSH, cloudflared or tailscaled from them fall back to weaker guesses) | reaching other processes' files through `/proc/<pid>/root`, which sits outside the read only mounts. The `ptrace` system call itself is filtered (`@debug`) |
| `CAP_DAC_READ_SEARCH` | look into directories root does not own, such as an account's `~/.ssh` for `authorized_keys` | those accounts' key files cannot be seen | reading any file |

`CAP_DAC_OVERRIDE` is left out on purpose: the audit only reads, and
without it a root run cannot write a file it does not own. The output
directories must therefore be owned by root, as `/var/lib/stackward` and
the Debian and Ubuntu package's `/var/lib/prometheus/node-exporter`
(root:root 0755) are. If your textfile directory belongs to another user,
the unit fails with `--textfile: ... permission denied`; give it to root
(`chown root: DIR`, node_exporter only needs to read it).

What a root run can still do, should stackward or a command it starts be
compromised, is what the kept capabilities and uid 0 allow:

- change the firewall, routes and links (`CAP_NET_ADMIN`; there is no way to
  grant only the read half);
- send signals to other root processes (uid 0 needs no capability for that);
- read any file (`CAP_DAC_READ_SEARCH`);
- write files root owns, outside the read only mounts, through another
  process's `/proc/<pid>/root` (`CAP_SYS_PTRACE`).

On a kernel with Landlock (5.13 and later; the report and the
`stackward_sandbox_confined` metric say so) the audit process and every
command it starts hold no file write right anywhere, so the last point
falls away; the first two remain either way. If you would rather trade the
process names for a smaller root, drop `CAP_SYS_PTRACE` with a drop in:

```sh
systemctl edit stackward-audit.service
# [Service]
# CapabilityBoundingSet=
# CapabilityBoundingSet=CAP_DAC_READ_SEARCH CAP_NET_ADMIN CAP_NET_RAW
```

With `--user NAME` the audit runs as that account with no capabilities at
all. Checks that need root then say `unknown` (the report and the
`stackward_run_as_root` metric show it), and the account must be able to
write both output directories. A dynamic user (`DynamicUser=`) is not
offered: it can read even less and cannot own a textfile directory that
node_exporter shares.

## Install by hand

As root, from the directory where you saved the output:

```sh
# 1. split the output into the two unit files and read them
stackward schedule --print > units
sed -n '1,/^# \/etc\/systemd\/system\/stackward-audit.timer/p' units | sed '$d' > stackward-audit.service
sed -n '/^# \/etc\/systemd\/system\/stackward-audit.timer/,$p' units > stackward-audit.timer

# 2. create the output directories (ReadWritePaths needs them to exist)
install -d -m 0750 /var/lib/stackward
install -d -m 0755 /var/lib/prometheus/node-exporter   # owned by root (see "The account")

# 3. install the units, check them, start the timer
install -m 0644 stackward-audit.service stackward-audit.timer /etc/systemd/system/
systemd-analyze verify /etc/systemd/system/stackward-audit.service /etc/systemd/system/stackward-audit.timer
systemctl daemon-reload
systemctl enable --now stackward-audit.timer

# 4. run it once now and look at the result
systemctl start stackward-audit.service
systemctl status stackward-audit.service
cat /var/lib/prometheus/node-exporter/stackward.prom
systemctl list-timers stackward-audit.timer
```

node_exporter must run with the textfile collector pointed at the same
directory (`--collector.textfile.directory`). The Debian and Ubuntu
`prometheus-node-exporter` package already reads
`/var/lib/prometheus/node-exporter`.

After upgrading stackward, print the units again and compare: `diff
<(stackward schedule --print) <(cat /etc/systemd/system/stackward-audit.{service,timer})`.

## Remove by hand

```sh
systemctl disable --now stackward-audit.timer
rm /etc/systemd/system/stackward-audit.service /etc/systemd/system/stackward-audit.timer
systemctl daemon-reload
systemctl reset-failed stackward-audit.service 2>/dev/null
# optional: the last report and metric
rm -f /var/lib/prometheus/node-exporter/stackward.prom /var/lib/prometheus/node-exporter/stackward.prom.tmp
rm -rf /var/lib/stackward
```

Remove the metric file too, or Prometheus keeps scraping the last values and
the stale run alert fires.

## The metric

`stackward.prom` holds counts and states only: no hostname (node_exporter's
`instance` label says which host), no check subject, no message, nothing
redaction would need to mask. Every series is a gauge and every labelled
series is written on every run, also when its value is 0, so an alert on it
never silently stops. The names and labels below are stable: a name is never
renamed or given a new meaning, and new series may be added.

| Metric | Labels | Meaning |
|---|---|---|
| `stackward_results` | `level`: `fail`, `warn`, `unknown`, `info`, `pass`, `skip` | results of the last audit by level. A check gives one result per subject (a container, a port), so these are results, not checks |
| `stackward_last_run_timestamp_seconds` | | Unix time at which the last audit collected its facts |
| `stackward_coverage_ratio` | | share of results that could be judged: checked (pass, warn, fail, info) over checked plus unknown, from 0 to 1. Skipped results do not count |
| `stackward_run_as_root` | | 1 when the last audit ran as root, else 0 |
| `stackward_sandbox_confined` | | 1 when the Landlock sandbox confined the last audit, else 0 |
| `stackward_collectors` | `status`: `ok`, `partial`, `failed`, `timeout`, `skipped` | collectors of the last audit by how they ended |
| `stackward_info` | `version`, `profile` | always 1; the stackward version and the ingress profile the audit used |

Example:

```
# HELP stackward_results Results of the last stackward audit, by level (a check gives one result per subject).
# TYPE stackward_results gauge
stackward_results{level="fail"} 2
stackward_results{level="warn"} 4
...
stackward_last_run_timestamp_seconds 1794847044
stackward_coverage_ratio 0.8438
stackward_run_as_root 1
stackward_sandbox_confined 1
```

`stackward audit --textfile FILE` writes the same metric from any audit, not
only a scheduled one. Prefer a temporary name and a rename, as the unit does.

## Alerting

Prometheus alerting rules to start from; tune the thresholds to your
schedule and taste.

```yaml
groups:
  - name: stackward
    rules:
      - alert: StackwardAuditStale
        # no successful audit for two days (daily timer plus slack)
        expr: time() - stackward_last_run_timestamp_seconds > 2 * 86400
        labels: {severity: warning}
        annotations:
          summary: "stackward has not audited {{ $labels.instance }} for 2 days"
          description: "Check: systemctl status stackward-audit.service"

      - alert: StackwardFindings
        expr: stackward_results{level="fail"} > 0
        labels: {severity: warning}
        annotations:
          summary: "stackward reports {{ $value }} failing results on {{ $labels.instance }}"
          description: "Read /var/lib/stackward/report.json or run: sudo stackward audit"

      - alert: StackwardNewFindings
        # more failing results than a day ago
        expr: stackward_results{level="fail"} > stackward_results{level="fail"} offset 1d
        labels: {severity: warning}

      - alert: StackwardCoverageDropped
        # the audit could judge less than before: a collector broke or root was lost
        expr: stackward_coverage_ratio < 0.8 or stackward_run_as_root == 0
        labels: {severity: info}

      - alert: StackwardNotSandboxed
        expr: stackward_sandbox_confined == 0
        labels: {severity: info}
```

`node_systemd_unit_state{name="stackward-audit.service",state="failed"}`
(node_exporter's systemd collector, off by default) is another way to see a
failed run.
