# Changelog

All notable changes to stackward are listed here, newest first. The section
for a tag is used as the notes of its GitHub release. Versions follow
[semantic versioning](https://semver.org/); a version with a suffix such as
`-rc.1` is a pre-release.

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
