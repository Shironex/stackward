# Provider firewall audit

A cloud provider's network firewall drops traffic before it reaches the host
and before Docker's iptables rules. The host cannot see it, so by default
`NET-009` says so and the `PFW` checks are `unknown`. With `--provider`,
`stackward audit` (and `stackward plan`, which audits first) reads that
firewall over the provider's API and judges it next to the host firewall.

It is opt in, read only and never stores a credential. Without `--provider`
no request is sent.

Supported: **Hetzner Cloud Firewall**. The OVHcloud Edge Network Firewall
follows in a later release; the checks already handle a stateless, ordered,
IPv4 only firewall like it.

## Run it

```sh
# a token with permission Read, in a file only root can read (the audit
# runs as root, and the file must belong to the user running it)
sudo install -m 600 -o root -g root /dev/null /root/stackward-hetzner-token
sudo nano /root/stackward-hetzner-token    # paste the token, save
sudo STACKWARD_HETZNER_TOKEN_FILE=/root/stackward-hetzner-token \
  stackward audit --provider hetzner
```

`--provider auto` picks the provider whose credentials are set; it is not a
network probe. When the public address the provider knows is not on one of
the host's interfaces (NAT), pass it with `--provider-ip 203.0.113.10`.

## Credentials

- **Never on the command line.** There is no `--token` flag: argv shows in
  `ps` and in shell history.
- **From the environment or a file, per run.**
  - `STACKWARD_HETZNER_TOKEN`, or `STACKWARD_HETZNER_TOKEN_FILE` naming a
    file that holds the token alone.
  - stackward uses its own variable names, not the vendor's (`HCLOUD_TOKEN`),
    so a token set for another tool is never picked up by accident.
- **A token file** must be a regular file (a symlink is refused), owned by
  the user running the audit, and mode `0600` or stricter. It is read once,
  capped at 4 KiB, before the sandbox.
- **Read only.** Create the Hetzner token with permission **Read**. The API
  cannot tell stackward what a token may do, so a Read & Write token also
  works; stackward only ever sends GET requests, but a leaked Read token
  can do less harm.
- **Never stored.** The token is not in the facts, the report,
  `--dump-facts` or any log. The redaction pass also masks it as a literal
  value wherever it could appear.

## What is sent

For each public IPv4 address on the host's interfaces (or `--provider-ip`):

| Request | Why |
|---|---|
| `GET /v1/primary_ips?ip=ADDR` | which server holds the address |
| `GET /v1/floating_ips?page=N` | only when no primary IP matched; the list has no address filter, so it is paged and matched exactly |
| `GET /v1/servers/ID` | the firewalls applied to the server (directly or through a label selector) |
| `GET /v1/firewalls/ID` | the rules of each of them |

All of them go to `api.hetzner.cloud` over HTTPS. The client can only build
GET requests, refuses any other host, never follows a redirect, ignores proxy
variables (a proxy would see the token), caps every answer at 1 MiB and gives
the whole fetch 10 seconds. A slow or failing API never fails the audit: the
checks say `unknown` with the reason.

The fetch runs before the Landlock sandbox, because the sandbox denies TCP
connect and cannot be loosened afterwards (see
[threat-model.md](threat-model.md#the-provider-firewall-fetch)).

## What is kept

`facts.provider_firewall` holds, per address: whether a firewall is attached
and in force, the state, how many firewalls, and the normalised rules
(direction, action, protocol, sources, ports). Names, descriptions, labels,
server, firewall, project and account ids are never kept, because facts files
are attached to bug reports. `--dump-facts` also masks the last octet of the
matched address (`203.0.113.x`).

## The checks

| Id | Question |
|---|---|
| [PFW-001](checks/PFW-001.md) | A provider firewall is attached and in force |
| [PFW-002](checks/PFW-002.md) | Inbound traffic is denied by default at the provider |
| [PFW-003](checks/PFW-003.md) | No provider rule allows all UDP from anywhere |
| [PFW-004](checks/PFW-004.md) | Every port the provider allows has a service behind it |
| [PFW-005](checks/PFW-005.md) | SSH is not open to anywhere at the provider |
| [PFW-006](checks/PFW-006.md) | IPv6 is covered by the provider or the host firewall |
| [PFW-007](checks/PFW-007.md) | A stateless provider firewall lets return traffic in |
| [PFW-008](checks/PFW-008.md) | What the provider firewall allows, one row per rule |

How they read the rules:

- Several firewalls on one Hetzner server combine: a rule counts if any of
  them has it. A firewall whose status is `pending` is not in force yet.
- On an ordered firewall (OVH) the first matching rule wins, so a deny
  before a permit makes the permit dead and the other way round.
- A source of a /8 or wider counts as anywhere.
- Rules for ICMP, ESP, GRE, AH or every IPv4 packet are listed in PFW-008
  but take no part in the port checks.
- `no_match` (no server of this project has the address) is `unknown`, not a
  finding: the address may belong to another project or account.

`NET-009` reads the result too: after a successful read it says how many
firewalls and rules were read, and still points at `stackward probe` for the
end to end view.
