# stackward test audit

- **Host:** sha256:82c1a34869ebe223
- **OS:** -, kernel -
- **Collected:** 2026-03-01T12:00:00Z
- **Profile:** public-web (inferred)
- **Root:** yes
- **Sandbox:** unavailable (golden test)
- **Coverage:** 104 checks, 108 results: 8 checked, 96 unknown, 4 skipped, root: yes

## Summary

| Level | Count |
|---|---|
| fail | 2 |
| warn | 3 |
| unknown | 96 |
| info | 3 |
| pass | 0 |
| skip | 4 |

## NET: Firewall and exposure

### FAIL high: [NET-001](https://github.com/Shironex/stackward/blob/main/docs/checks/NET-001.md) A host firewall is active and denies incoming traffic by default

- **Subject:** `host`
- **Result:** UFW is inactive and no other firewall drops incoming traffic
- **Fix:** Allow SSH first (ufw allow in on tailscale0 to any port 22, or from one source), then: ufw default deny incoming; ufw enable

<details><summary>Evidence</summary>

- `denies_incoming`: `no`
- `iptables_backend`: `nf_tables`
- `iptables_input_policy`: `ACCEPT`
- `mechanism`: ` `
- `nft_listed`: `true`
- `ufw_default_incoming`: `deny`
- `ufw_source`: `status`
- `ufw_status`: `inactive`

</details>

### FAIL high: [NET-002](https://github.com/Shironex/stackward/blob/main/docs/checks/NET-002.md) UFW filters IPv6 when the host has a global IPv6 address

- **Subject:** `host`
- **Result:** UFW has IPV6=no while the host has a global IPv6 address: IPv6 traffic is not filtered
- **Fix:** Set IPV6=yes in /etc/default/ufw, then ufw reload

<details><summary>Evidence</summary>

- `global_ipv6`: `true`
- `ipv6`: `no`

</details>

### WARN moderate: [NET-004](https://github.com/Shironex/stackward/blob/main/docs/checks/NET-004.md) Exposure: every listening socket and who can reach it

- **Subject:** `port:tcp/22`
- **Result:** tcp/22 (sshd) listens on wildcard and nothing filters it: UFW is inactive and no other firewall drops incoming traffic
- **Fix:** Bind services to 127.0.0.1 or the tailnet address instead of 0.0.0.0, or filter the port in the host firewall

<details><summary>Evidence</summary>

- `binds`: `["0.0.0.0","::"]`
- `class`: `wildcard`
- `open_from_anywhere`: `yes`
- `processes`: `["sshd"]`
- `processes_visible`: `true`

</details>

### WARN moderate: [NET-004](https://github.com/Shironex/stackward/blob/main/docs/checks/NET-004.md) Exposure: every listening socket and who can reach it

- **Subject:** `port:tcp/443`
- **Result:** tcp/443 (nginx) listens on wildcard and nothing filters it: UFW is inactive and no other firewall drops incoming traffic
- **Fix:** Bind services to 127.0.0.1 or the tailnet address instead of 0.0.0.0, or filter the port in the host firewall

<details><summary>Evidence</summary>

- `binds`: `["0.0.0.0","::"]`
- `class`: `wildcard`
- `open_from_anywhere`: `yes`
- `processes`: `["nginx"]`
- `processes_visible`: `true`

</details>

### WARN moderate: [NET-004](https://github.com/Shironex/stackward/blob/main/docs/checks/NET-004.md) Exposure: every listening socket and who can reach it

- **Subject:** `port:tcp/6379`
- **Result:** tcp/6379 is a published container port on wildcard and nothing filters it: DOCKER-USER has no filtering rules (see DKR-001)
- **Fix:** Bind services to 127.0.0.1 or the tailnet address instead of 0.0.0.0, or filter the port in the host firewall

<details><summary>Evidence</summary>

- `binds`: `["0.0.0.0"]`
- `class`: `wildcard`
- `open_from_anywhere`: `yes`
- `processes`: `["docker-proxy"]`
- `processes_visible`: `true`

</details>

## Notes

**NET: Firewall and exposure**

| Check | Title | Subject | Result |
|---|---|---|---|
| [NET-004](https://github.com/Shironex/stackward/blob/main/docs/checks/NET-004.md) | Exposure: every listening socket and who can reach it | `port:tcp/5432` | tcp/5432 (postgres) listens on loopback addresses only |
| [NET-004](https://github.com/Shironex/stackward/blob/main/docs/checks/NET-004.md) | Exposure: every listening socket and who can reach it | `port:udp/68` | udp/68 (systemd-network) is a DHCP client socket |
| [NET-006](https://github.com/Shironex/stackward/blob/main/docs/checks/NET-006.md) | DOCKER-USER chain state | `host` | DOCKER-USER exists with no filtering rules: published ports are not filtered by the host firewall |

## Not inspected

<details><summary>96 checks not inspected</summary>

**SYS: System**

| Check | Title | Subject | Reason |
|---|---|---|---|
| [SYS-001](https://github.com/Shironex/stackward/blob/main/docs/checks/SYS-001.md) | Distribution is one stackward is tested on | `host` | not inspected: the os collector did not run |
| [SYS-002](https://github.com/Shironex/stackward/blob/main/docs/checks/SYS-002.md) | No reboot pending | `host` | not inspected: the os collector did not run |
| [SYS-003](https://github.com/Shironex/stackward/blob/main/docs/checks/SYS-003.md) | Running kernel is the newest installed | `host` | not inspected: the os collector did not run |
| [SYS-004](https://github.com/Shironex/stackward/blob/main/docs/checks/SYS-004.md) | Clock is synchronized | `host` | not inspected: the clock collector did not run |
| [SYS-005](https://github.com/Shironex/stackward/blob/main/docs/checks/SYS-005.md) | Disks have free space | `host` | not inspected: the disk collector did not run |

**SSH: SSH**

| Check | Title | Subject | Reason |
|---|---|---|---|
| [SSH-001](https://github.com/Shironex/stackward/blob/main/docs/checks/SSH-001.md) | Password authentication is off | `host` | not inspected: the ssh collector did not run |
| [SSH-002](https://github.com/Shironex/stackward/blob/main/docs/checks/SSH-002.md) | Keyboard-interactive authentication is off | `host` | not inspected: the ssh collector did not run |
| [SSH-003](https://github.com/Shironex/stackward/blob/main/docs/checks/SSH-003.md) | Root cannot log in over SSH | `host` | not inspected: the ssh collector did not run |
| [SSH-004](https://github.com/Shironex/stackward/blob/main/docs/checks/SSH-004.md) | Empty passwords are refused | `host` | not inspected: the ssh collector did not run |
| [SSH-005](https://github.com/Shironex/stackward/blob/main/docs/checks/SSH-005.md) | MaxAuthTries is low | `host` | not inspected: the ssh collector did not run |
| [SSH-006](https://github.com/Shironex/stackward/blob/main/docs/checks/SSH-006.md) | Logins are limited with AllowUsers or AllowGroups | `host` | not inspected: the ssh collector did not run |
| [SSH-007](https://github.com/Shironex/stackward/blob/main/docs/checks/SSH-007.md) | X11 and agent forwarding are off | `host` | not inspected: the ssh collector did not run |
| [SSH-008](https://github.com/Shironex/stackward/blob/main/docs/checks/SSH-008.md) | No early drop-in shadows a later hardening setting | `host` | not inspected: the ssh collector did not run |
| [SSH-009](https://github.com/Shironex/stackward/blob/main/docs/checks/SSH-009.md) | Effective SSH configuration fully confirmed | `host` | not inspected: the ssh collector did not run |
| [SSH-010](https://github.com/Shironex/stackward/blob/main/docs/checks/SSH-010.md) | sshd listens where it is configured to | `host` | not inspected: the ssh collector did not run |
| [SSH-011](https://github.com/Shironex/stackward/blob/main/docs/checks/SSH-011.md) | sshd reachable from anywhere takes keys only and bans brute force | `host` | not inspected: the ssh collector did not run |
| [SSH-012](https://github.com/Shironex/stackward/blob/main/docs/checks/SSH-012.md) | Host keys are strong and private | `host` | not inspected: the ssh collector did not run |
| [SSH-013](https://github.com/Shironex/stackward/blob/main/docs/checks/SSH-013.md) | Home, \~/.ssh and authorized\_keys are not writable by others | `host` | not inspected: the ssh collector did not run |
| [SSH-014](https://github.com/Shironex/stackward/blob/main/docs/checks/SSH-014.md) | Authorized keys are strong and not stale | `host` | not inspected: the ssh collector did not run |
| [SSH-015](https://github.com/Shironex/stackward/blob/main/docs/checks/SSH-015.md) | No weak key exchange, cipher or MAC algorithms | `host` | not inspected: the ssh collector did not run |
| [SSH-016](https://github.com/Shironex/stackward/blob/main/docs/checks/SSH-016.md) | Tailscale SSH and OpenSSH are not both serving | `host` | not inspected: the tailscale collector did not run |

**USR: Users and privilege**

| Check | Title | Subject | Reason |
|---|---|---|---|
| [USR-001](https://github.com/Shironex/stackward/blob/main/docs/checks/USR-001.md) | Only root has uid 0 | `host` | not inspected: the users collector did not run |
| [USR-002](https://github.com/Shironex/stackward/blob/main/docs/checks/USR-002.md) | No login account has an empty password | `host` | not inspected: the users collector did not run |
| [USR-003](https://github.com/Shironex/stackward/blob/main/docs/checks/USR-003.md) | Cloud default account is locked down | `host` | not inspected: the users collector did not run |
| [USR-004](https://github.com/Shironex/stackward/blob/main/docs/checks/USR-004.md) | sudoers is root owned and NOPASSWD entries are deliberate | `host` | not inspected: the users collector did not run |
| [USR-005](https://github.com/Shironex/stackward/blob/main/docs/checks/USR-005.md) | Docker group has no extra members | `host` | not inspected: the users collector did not run |
| [USR-006](https://github.com/Shironex/stackward/blob/main/docs/checks/USR-006.md) | Login accounts are used | `host` | not inspected: the users collector did not run |
| [USR-007](https://github.com/Shironex/stackward/blob/main/docs/checks/USR-007.md) | Root recovery path is known | `host` | not inspected: the users collector did not run |

**NET: Firewall and exposure**

| Check | Title | Subject | Reason |
|---|---|---|---|
| [NET-003](https://github.com/Shironex/stackward/blob/main/docs/checks/NET-003.md) | SSH is not open to anywhere when a private path exists | `host` | SSH is open to anywhere on tcp/22; Tailscale facts are missing, so whether a private path exists is unknown |
| [NET-009](https://github.com/Shironex/stackward/blob/main/docs/checks/NET-009.md) | Provider firewall (outside view) | `host` | the provider firewall cannot be seen from inside the host; run \`stackward probe\` from another machine to see what is reachable |

**DKR: Docker**

| Check | Title | Subject | Reason |
|---|---|---|---|
| [DKR-001](https://github.com/Shironex/stackward/blob/main/docs/checks/DKR-001.md) | Published container ports do not bypass the host firewall | `host` | not inspected: the docker collector did not run |
| [DKR-002](https://github.com/Shironex/stackward/blob/main/docs/checks/DKR-002.md) | Docker API is not on TCP without TLS | `host` | not inspected: the docker collector did not run |
| [DKR-003](https://github.com/Shironex/stackward/blob/main/docs/checks/DKR-003.md) | Docker socket is not world writable | `host` | not inspected: the docker collector did not run |
| [DKR-010](https://github.com/Shironex/stackward/blob/main/docs/checks/DKR-010.md) | No container mounts the Docker socket | `host` | not inspected: the docker collector did not run |
| [DKR-011](https://github.com/Shironex/stackward/blob/main/docs/checks/DKR-011.md) | Socket proxies do not allow writes | `host` | not inspected: the docker collector did not run |
| [DKR-012](https://github.com/Shironex/stackward/blob/main/docs/checks/DKR-012.md) | No container mounts a sensitive host path | `host` | not inspected: the docker collector did not run |
| [DKR-020](https://github.com/Shironex/stackward/blob/main/docs/checks/DKR-020.md) | Containers do not run as root | `host` | not inspected: the docker collector did not run |
| [DKR-021](https://github.com/Shironex/stackward/blob/main/docs/checks/DKR-021.md) | No privileged containers | `host` | not inspected: the docker collector did not run |
| [DKR-022](https://github.com/Shironex/stackward/blob/main/docs/checks/DKR-022.md) | No dangerous added capabilities | `host` | not inspected: the docker collector did not run |
| [DKR-023](https://github.com/Shironex/stackward/blob/main/docs/checks/DKR-023.md) | No host network, PID or IPC namespace | `host` | not inspected: the docker collector did not run |
| [DKR-024](https://github.com/Shironex/stackward/blob/main/docs/checks/DKR-024.md) | Containers keep seccomp and AppArmor, and public ones set no-new-privileges | `host` | not inspected: the docker collector did not run |
| [DKR-030](https://github.com/Shironex/stackward/blob/main/docs/checks/DKR-030.md) | Projects do not share networks | `host` | not inspected: the docker collector did not run |
| [DKR-031](https://github.com/Shironex/stackward/blob/main/docs/checks/DKR-031.md) | Container logs rotate | `host` | not inspected: the docker collector did not run |
| [DKR-032](https://github.com/Shironex/stackward/blob/main/docs/checks/DKR-032.md) | Infrastructure containers run pinned images | `host` | not inspected: the docker collector did not run |
| [DKR-033](https://github.com/Shironex/stackward/blob/main/docs/checks/DKR-033.md) | Docker manages the firewall | `host` | not inspected: the docker collector did not run |
| [DKR-034](https://github.com/Shironex/stackward/blob/main/docs/checks/DKR-034.md) | Docker Engine is supported upstream | `host` | not inspected: the docker collector did not run |

**TS: Tailscale**

| Check | Title | Subject | Reason |
|---|---|---|---|
| [TS-001](https://github.com/Shironex/stackward/blob/main/docs/checks/TS-001.md) | Tailscale is logged in and Running when installed | `host` | not inspected: the tailscale collector did not run |
| [TS-002](https://github.com/Shironex/stackward/blob/main/docs/checks/TS-002.md) | Node key expiry is disabled on server nodes | `host` | not inspected: the tailscale collector did not run |
| [TS-003](https://github.com/Shironex/stackward/blob/main/docs/checks/TS-003.md) | Tailscale Funnel and Serve expose only what is intended | `host` | not inspected: the tailscale collector did not run |
| [TS-005](https://github.com/Shironex/stackward/blob/main/docs/checks/TS-005.md) | Tailnet Lock state | `host` | not inspected: the tailscale collector did not run |

**CF: Cloudflare Tunnel**

| Check | Title | Subject | Reason |
|---|---|---|---|
| [CF-001](https://github.com/Shironex/stackward/blob/main/docs/checks/CF-001.md) | Cloudflare Tunnel presence | `host` | not inspected: the cloudflared collector did not run |
| [CF-002](https://github.com/Shironex/stackward/blob/main/docs/checks/CF-002.md) | The tunnel runs more than one connector | `host` | not inspected: the cloudflared collector did not run |
| [CF-003](https://github.com/Shironex/stackward/blob/main/docs/checks/CF-003.md) | The proxy is not reachable on a public address while ingress is the tunnel | `host` | not inspected: the cloudflared collector did not run |
| [CF-004](https://github.com/Shironex/stackward/blob/main/docs/checks/CF-004.md) | The tunnel token is not a command line argument | `host` | not inspected: the cloudflared collector did not run |
| [CF-005](https://github.com/Shironex/stackward/blob/main/docs/checks/CF-005.md) | The origin IP does not answer on 80/443 from outside (probe) | `host` | not inspected: the cloudflared collector did not run |

**CS: CrowdSec and fail2ban**

| Check | Title | Subject | Reason |
|---|---|---|---|
| [CS-001](https://github.com/Shironex/stackward/blob/main/docs/checks/CS-001.md) | CrowdSec runs when installed | `host` | not inspected: the crowdsec collector did not run |
| [CS-002](https://github.com/Shironex/stackward/blob/main/docs/checks/CS-002.md) | A bouncer is registered and pulling decisions | `host` | not inspected: the crowdsec collector did not run |
| [CS-003](https://github.com/Shironex/stackward/blob/main/docs/checks/CS-003.md) | Behind a tunnel, an L7 bouncer enforces bans | `host` | not inspected: the crowdsec collector did not run |
| [CS-004](https://github.com/Shironex/stackward/blob/main/docs/checks/CS-004.md) | Private range whitelists do not swallow tunnel traffic | `host` | not inspected: the crowdsec collector did not run |
| [CS-005](https://github.com/Shironex/stackward/blob/main/docs/checks/CS-005.md) | The proxy access log is acquired | `host` | not inspected: the crowdsec collector did not run |
| [CS-006](https://github.com/Shironex/stackward/blob/main/docs/checks/CS-006.md) | The CrowdSec local API is not on a wildcard address | `host` | not inspected: the crowdsec collector did not run |
| [CS-007](https://github.com/Shironex/stackward/blob/main/docs/checks/CS-007.md) | The firewall bouncer also protects Docker published ports | `host` | not inspected: the crowdsec collector did not run |
| [CS-008](https://github.com/Shironex/stackward/blob/main/docs/checks/CS-008.md) | The proxy bouncer refreshes decisions often | `host` | not inspected: the crowdsec collector did not run |
| [CS-010](https://github.com/Shironex/stackward/blob/main/docs/checks/CS-010.md) | Public SSH has brute force protection on the right port | `host` | SSH is public; whether fail2ban or CrowdSec protects it could not be read: the CrowdSec facts are missing; the fail2ban facts are missing |
| [CS-011](https://github.com/Shironex/stackward/blob/main/docs/checks/CS-011.md) | fail2ban ignores the tailnet range when Tailscale is used | `host` | not inspected: the fail2ban collector did not run |

**UPD: Updates**

| Check | Title | Subject | Reason |
|---|---|---|---|
| [UPD-001](https://github.com/Shironex/stackward/blob/main/docs/checks/UPD-001.md) | Automatic security updates are enabled | `host` | not inspected: the updates collector did not run |
| [UPD-002](https://github.com/Shironex/stackward/blob/main/docs/checks/UPD-002.md) | Unattended upgrades ran recently | `host` | not inspected: the updates collector did not run |
| [UPD-003](https://github.com/Shironex/stackward/blob/main/docs/checks/UPD-003.md) | Unattended upgrades include the security pocket | `host` | not inspected: the updates collector did not run |
| [UPD-004](https://github.com/Shironex/stackward/blob/main/docs/checks/UPD-004.md) | Reboot policy is a decision | `host` | not inspected: the updates collector did not run |
| [UPD-005](https://github.com/Shironex/stackward/blob/main/docs/checks/UPD-005.md) | Release is within standard support | `host` | not inspected: the os collector did not run |
| [UPD-006](https://github.com/Shironex/stackward/blob/main/docs/checks/UPD-006.md) | No pending security updates | `host` | not inspected: the updates collector did not run |

**KRN: Kernel settings**

| Check | Title | Subject | Reason |
|---|---|---|---|
| [KRN-001](https://github.com/Shironex/stackward/blob/main/docs/checks/KRN-001.md) | IPv4 forwarding is on where Docker runs | `host` | not inspected: the sysctl collector did not run |
| [KRN-002](https://github.com/Shironex/stackward/blob/main/docs/checks/KRN-002.md) | Reverse path filter is loose where Docker or Tailscale run | `host` | not inspected: the sysctl collector did not run |
| [KRN-003](https://github.com/Shironex/stackward/blob/main/docs/checks/KRN-003.md) | Network sysctls match the hardening baseline | `host` | not inspected: the sysctl collector did not run |
| [KRN-004](https://github.com/Shironex/stackward/blob/main/docs/checks/KRN-004.md) | Kernel hardening sysctls match the baseline | `host` | not inspected: the sysctl collector did not run |
| [KRN-005](https://github.com/Shironex/stackward/blob/main/docs/checks/KRN-005.md) | IPv6 router advertisements are not switched off by a profile | `host` | not inspected: the sysctl collector did not run |

**LOG: Logs and monitoring**

| Check | Title | Subject | Reason |
|---|---|---|---|
| [LOG-001](https://github.com/Shironex/stackward/blob/main/docs/checks/LOG-001.md) | journald has a size cap | `host` | not inspected: the journal collector did not run |
| [LOG-002](https://github.com/Shironex/stackward/blob/main/docs/checks/LOG-002.md) | Proxy access logs are rotated | `host` | not inspected: the journal collector did not run |
| [LOG-003](https://github.com/Shironex/stackward/blob/main/docs/checks/LOG-003.md) | Journal disk use | `host` | not inspected: the journal collector did not run |
| [LOG-004](https://github.com/Shironex/stackward/blob/main/docs/checks/LOG-004.md) | A metrics agent is present | `host` | not inspected: the journal collector did not run |
| [LOG-005](https://github.com/Shironex/stackward/blob/main/docs/checks/LOG-005.md) | The journal survives a reboot | `host` | not inspected: the journal collector did not run |

**SEC: Secrets on disk**

| Check | Title | Subject | Reason |
|---|---|---|---|
| [SEC-001](https://github.com/Shironex/stackward/blob/main/docs/checks/SEC-001.md) | Platform app .env files are readable by their owner only | `host` | not inspected: the secrets collector did not run |
| [SEC-002](https://github.com/Shironex/stackward/blob/main/docs/checks/SEC-002.md) | Platform main .env is not world readable | `host` | not inspected: the secrets collector did not run |
| [SEC-003](https://github.com/Shironex/stackward/blob/main/docs/checks/SEC-003.md) | Platform SSH key folder is closed to other users | `host` | not inspected: the secrets collector did not run |
| [SEC-004](https://github.com/Shironex/stackward/blob/main/docs/checks/SEC-004.md) | No stray backup files in the proxy dynamic config folder | `host` | not inspected: the secrets collector did not run |
| [SEC-005](https://github.com/Shironex/stackward/blob/main/docs/checks/SEC-005.md) | Private keys are readable by their owner only | `host` | not inspected: the secrets collector did not run |
| [SEC-006](https://github.com/Shironex/stackward/blob/main/docs/checks/SEC-006.md) | Docker client config is readable by its owner only | `host` | not inspected: the secrets collector did not run |
| [SEC-007](https://github.com/Shironex/stackward/blob/main/docs/checks/SEC-007.md) | No world writable folders under the platform data root | `host` | not inspected: the secrets collector did not run |

**PAAS: Coolify and Dokploy**

| Check | Title | Subject | Reason |
|---|---|---|---|
| [PAAS-001](https://github.com/Shironex/stackward/blob/main/docs/checks/PAAS-001.md) | Self hosted platform detected | `host` | not inspected: the paas collector did not run |
| [PAAS-002](https://github.com/Shironex/stackward/blob/main/docs/checks/PAAS-002.md) | Platform proxy is not published on all interfaces behind a tunnel | `host` | not inspected: the paas collector did not run |
| [PAAS-003](https://github.com/Shironex/stackward/blob/main/docs/checks/PAAS-003.md) | Platform panel ports are not open to the world | `host` | not inspected: the paas collector did not run |
| [PAAS-004](https://github.com/Shironex/stackward/blob/main/docs/checks/PAAS-004.md) | No platform database is published publicly | `host` | not inspected: the paas collector did not run |
| [PAAS-005](https://github.com/Shironex/stackward/blob/main/docs/checks/PAAS-005.md) | Projects do not share the platform default network | `host` | not inspected: the paas collector did not run |
| [PAAS-008](https://github.com/Shironex/stackward/blob/main/docs/checks/PAAS-008.md) | Docker Swarm ports are restricted to cluster peers | `host` | not inspected: the paas collector did not run |

**BAK: Backups**

| Check | Title | Subject | Reason |
|---|---|---|---|
| [BAK-001](https://github.com/Shironex/stackward/blob/main/docs/checks/BAK-001.md) | Platform database backups on the host | `host` | not inspected: the paas collector did not run |
| [BAK-002](https://github.com/Shironex/stackward/blob/main/docs/checks/BAK-002.md) | Backup tools present | `host` | not inspected: the secrets collector did not run |

</details>

Explain any check with `stackward explain <id>`.
