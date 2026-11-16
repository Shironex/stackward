# Roadmap

This is the public plan for stackward. Each milestone below is a GitHub milestone, and each item links to its issue. Dates are not promised; the order inside a milestone is the order of work.

Version 0.1 is released (`v0.1.0` on 2026-11-15, patches `v0.1.1` and `v0.1.2` the same day): the read only audit, `probe`, `explain`, the TUI and signed releases.

Version 0.2 is released (`v0.2.0` on 2026-11-16): `plan`, `apply`, `undo` and `confirm`, and the guided step list in the TUI.

Version 0.3 is released (`v0.3.0` on 2026-11-16) with the opt in provider firewall audit (`--provider hetzner|ovh`, the PFW checks), the first part of the provider firewall item (#41).

Version 0.4 is released (`v0.4.0` on 2026-11-16): the waivers file, `stackward diff` and `audit --baseline`, `audit --ssh` for several hosts and `schedule --print` with a Prometheus textfile (#34, #35, #36, #37). The GitHub milestones keep their names for now.

## v0.2: Harden with plan and apply (released)

`stackward plan` writes down every change with a diff, a risk class and an undo, and changes nothing. `stackward apply` runs the steps you pick, with backups and a journal. Changes to SSH, the firewall and users run in a transaction with a rollback timer that only a new SSH session can confirm, and public SSH is never closed without a proven second way in. The safety rules are in [safety.md](safety.md).

- [Add stackward plan, a plan file that changes nothing](https://github.com/Shironex/stackward/issues/23) (#23)
- [Add stackward apply with idempotent steps, backups and a run journal](https://github.com/Shironex/stackward/issues/24) (#24)
- [Add the guided step list to stackward tui](https://github.com/Shironex/stackward/issues/25) (#25)
- [Add the access-critical transaction with a rollback timer and stackward confirm](https://github.com/Shironex/stackward/issues/26) (#26)
- [Add the lockout guard and the never touched list](https://github.com/Shironex/stackward/issues/27) (#27)
- [Add account and SSH steps: admin user, PaaS user, lock default cloud user, sshd drop-in](https://github.com/Shironex/stackward/issues/28) (#28)
- [Add firewall steps: UFW policy and ufw-docker](https://github.com/Shironex/stackward/issues/29) (#29)
- [Add update and intrusion steps: unattended-upgrades, reboot decision, fail2ban sshd jail](https://github.com/Shironex/stackward/issues/30) (#30)
- [Add host setting steps: sysctl drop-in, journald cap, Docker log rotation](https://github.com/Shironex/stackward/issues/31) (#31)
- [Add the opt in PaaS .env permission timer step](https://github.com/Shironex/stackward/issues/32) (#32)
- [Add a VM only test matrix for apply](https://github.com/Shironex/stackward/issues/33) (#33)

[Milestone on GitHub](https://github.com/Shironex/stackward/milestone/1)

## v0.4: Make it a habit (released, planned as v0.3 on GitHub)

Audits become something you repeat. Waivers come first, so an accepted finding stops being noise without being hidden. All four items are in `v0.4.0`; the follow-ups found in review are #113, #114, #115 and #117.

- [Add a waivers file so accepted findings stay accepted](https://github.com/Shironex/stackward/issues/34) (#34)
- [Add stackward diff and --baseline to spot drift](https://github.com/Shironex/stackward/issues/35) (#35)
- [Add stackward audit --ssh for one host or several](https://github.com/Shironex/stackward/issues/36) (#36)
- [Add stackward schedule --print for a systemd timer](https://github.com/Shironex/stackward/issues/37) (#37)

[Milestone on GitHub](https://github.com/Shironex/stackward/milestone/2)

## Next minor (planned as v0.4 on GitHub): Beyond the box

Read only API modules for things the host cannot see. Each needs a token you provide per run with read scopes only; the token is never stored, and without one the checks say `unknown`.

- [Add a read only Cloudflare module](https://github.com/Shironex/stackward/issues/38) (#38)
- [Add a read only Tailscale module](https://github.com/Shironex/stackward/issues/39) (#39)
- [Add Coolify and Dokploy API modules](https://github.com/Shironex/stackward/issues/40) (#40)
- [Add provider firewall modules to answer NET-009](https://github.com/Shironex/stackward/issues/41) (#41)

[Milestone on GitHub](https://github.com/Shironex/stackward/milestone/3)

## Later

Ideas without a date or an order.

- [Support Debian 12 and 13 in CI, then the RHEL family with firewalld](https://github.com/Shironex/stackward/issues/42) (#42)
- [Detect more platforms: Dokku, CapRover, Portainer, plain Compose stacks and later k3s](https://github.com/Shironex/stackward/issues/43) (#43)
- [Add a static repo mode with a GitHub Action and SARIF output](https://github.com/Shironex/stackward/issues/44) (#44)
- [Add learning features: TUI learn key and a self contained HTML report](https://github.com/Shironex/stackward/issues/45) (#45)
- [Map every check to CIS Ubuntu and CIS Docker benchmark ids](https://github.com/Shironex/stackward/issues/46) (#46)
- [Add an optional --push to an external dashboard](https://github.com/Shironex/stackward/issues/47) (#47)

[Milestone on GitHub](https://github.com/Shironex/stackward/milestone/4)

## Non-goals

- **No single security score.** A number can hide one critical finding. Reports show counts and a coverage line instead.
- **No image CVE scanning.** Other tools do that well. stackward reads their results where a platform exposes them, and does not compete.
- **Never auto-install, never phone home.** stackward installs nothing by itself (`schedule --print` only prints a unit) and sends no telemetry. The only network use is what you ask for: `probe` against the host you name, and API modules with a token you provide.

## Suggest a change

Open an issue with the [issue forms](https://github.com/Shironex/stackward/issues/new/choose). Check requests and false positives are welcome too.
