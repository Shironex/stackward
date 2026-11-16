# Provider firewall audit

A cloud provider's network firewall drops traffic before it reaches the host
and before Docker's iptables rules. The host cannot see it, so by default
`NET-009` says so and `PFW-001` reports one `skip` row saying the provider
firewall was not checked (the other PFW checks leave no row). With `--provider`,
`stackward audit` (and `stackward plan`, which audits first) reads that
firewall over the provider's API and judges it next to the host firewall.

It is opt in, read only and never stores a credential. Without `--provider`
no request is sent.

Supported: **Hetzner Cloud Firewall** (stateful, IPv4 and IPv6) and the
**OVHcloud Edge Network Firewall** (stateless, ordered, IPv4 only). The
checks read what the provider can do from the facts, not from its name.

## Run it

```sh
# a token with permission Read, in a file only root can read (the audit
# runs as root, and the file must belong to the user running it)
sudo install -m 600 -o root -g root /dev/null /root/stackward-hetzner-token
sudo nano /root/stackward-hetzner-token    # paste the token, save
sudo STACKWARD_HETZNER_TOKEN_FILE=/root/stackward-hetzner-token \
  stackward audit --provider hetzner
```

For OVH, put the four values in a root owned file with mode 600:

```sh
sudo install -m 600 -o root -g root /dev/null /root/stackward-ovh
sudo nano /root/stackward-ovh
# STACKWARD_OVH_APPLICATION_KEY=...
# STACKWARD_OVH_APPLICATION_SECRET=...
# STACKWARD_OVH_CONSUMER_KEY=...
# STACKWARD_OVH_ENDPOINT=ovh-eu
sudo STACKWARD_OVH_CREDENTIALS_FILE=/root/stackward-ovh stackward audit --provider ovh
```

`--provider auto` picks the provider whose credentials are set (and refuses
when both are); it is not a
network probe. When the public address the provider knows is not on one of
the host's interfaces (NAT), pass it with `--provider-ip 203.0.113.10`.

## Credentials

- **Never on the command line.** There is no `--token` flag: argv shows in
  `ps` and in shell history.
- **From the environment or a file, per run.**
  - `STACKWARD_HETZNER_TOKEN`, or `STACKWARD_HETZNER_TOKEN_FILE` naming a
    file that holds the token alone.
  - `STACKWARD_OVH_APPLICATION_KEY`, `STACKWARD_OVH_APPLICATION_SECRET`,
    `STACKWARD_OVH_CONSUMER_KEY` and `STACKWARD_OVH_ENDPOINT` (`ovh-eu`,
    `ovh-ca` or `ovh-us`, default `ovh-eu`), or
    `STACKWARD_OVH_CREDENTIALS_FILE` naming a file with the same names as
    `KEY=VALUE` lines (blank lines and `#` comments allowed, nothing else).
  - stackward uses its own variable names, not the vendor's (`HCLOUD_TOKEN`),
    so a token set for another tool is never picked up by accident.
- **A token file** must be a regular file (a symlink is refused), owned by
  the user running the audit, and mode `0600` or stricter. It is read once,
  capped at 4 KiB, before the sandbox.
- **Read only.** Create the Hetzner token with permission **Read**. The API
  cannot tell stackward what a token may do, so a Read & Write token also
  works; stackward only ever sends GET requests, but a leaked Read token
  can do less harm. For OVH, create the consumer key with access rules
  limited to `GET /ip` and `GET /ip/*` (or an IAM policy with
  `ip:apiovh:get`, `ip:apiovh:firewall/get` and
  `ip:apiovh:firewall/rule/get`).
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

For OVH:

| Request | Why |
|---|---|
| `GET /1.0/auth/time` | the server time for the request signature (sent without credentials) |
| `GET /1.0/ip?ip=ADDR` | the IP blocks that hold the address; the filter is "contains or equals", so the narrowest block that really contains it is used |
| `GET /1.0/ip/{block}/firewall` | whether the address is on the Edge Network Firewall |
| `GET /1.0/ip/{block}/firewall/{ip}` | enabled and state |
| `GET /1.0/ip/{block}/firewall/{ip}/rule`, then one per sequence | the rules, at most 20 |

OVH signs each request with SHA-1 over the application secret, the consumer
key, the method, the URL, the body and the server time. That is the vendor's
scheme, not a choice.

Hetzner requests go to `api.hetzner.cloud`, OVH requests to the regional host
(`eu.api.ovh.com`, `ca.api.ovh.com` or `api.us.ovhcloud.com`), over HTTPS. The client can only build
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
are attached to bug reports. `--dump-facts` also masks, in
`provider_firewall` only:

- the matched address, to its first three octets (`203.0.113.x`);
- every IPv4 address in a reason (a failed request's URL carries one);
- every rule network, which keeps its prefix length but loses its host bits
  past the first three octets (IPv4) or the first 64 bits (IPv6), so
  `198.51.100.7/32` becomes `198.51.100.0/32` and the checks still see how
  wide it is; a network that does not parse becomes `unparsed`, which a
  replay judges the same way.

The interface addresses in `listeners.addresses` are not masked; that is a
decision for the whole dump, not for this module. The live report keeps
every value in full.

## TLS and root's environment

The client uses Go's TLS stack with the system certificate store. Like any
Go program, it honours `SSL_CERT_FILE` and `SSL_CERT_DIR` (which change the
trusted certificate authorities) and `GODEBUG` (which can change TLS
behaviour) in the environment it runs in. Under `sudo` that is root's
environment after sudo's `env_reset`. Anyone who can set those variables for
root can make the client trust another server, and it would then send that
server the credential. Keep them unset for root unless you mean them.

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
  them has it. A firewall whose status is `pending` is not in force yet, so
  the checks skip when no applied firewall is left.
- A pending rule (being created, being removed, or a rule of a firewall
  still being applied next to an applied one) is read, per check, in the
  direction that leans toward that check's finding. In PFW-002 to PFW-005 a
  pending permit counts as in force and a pending deny does not. In
  PFW-007, where a dropped reply is the finding, a pending deny counts and
  a pending permit does not.
- A firewall that is still being enabled (`enableFirewallPending`) is not
  in force yet, so PFW-007 skips with the other checks until it is; the
  replies it will drop are judged once it filters.
- On a stateless firewall a sender picks its own source port, so every
  "from anywhere" question is also asked from the edges of every source
  port range the rules name (its first and last port and the ports just
  outside it): `permit tcp from any source port 443` before the final deny
  opens every TCP port, SSH included (PFW-002 and PFW-005 fail), and so
  does `permit tcp source port 1000-2000` behind `deny tcp source port
  1000`, from port 1001.
- Sources are read, per check, in the direction that leans toward that
  check's finding. There are two readings: loose (the source is empty, a
  /8 or wider, or does not parse) and exact (the source is empty,
  `0.0.0.0/0` or `::ffff:0.0.0.0/96`; the simulated packets are IPv4, so
  `::/0` alone does not count).
  - Where a packet getting in is the finding (PFW-002 to PFW-005), a permit
    counts when its source is loose and a deny only when it is exact. So
    `deny ipv4 from 0.0.0.0/1` or `from ::/0` is not a catch-all.
  - Where a reply being dropped is the finding (PFW-007), the two swap: a
    deny counts when its source is loose and a permit only when it is
    exact. So `deny ipv4 from 0.0.0.0/1` before `permit tcp established`
    fails PFW-007, and `permit tcp established from 10.0.0.0/8` does not
    let replies in from anywhere. A deny whose sources all lie in reserved
    space (`0.0.0.0/8`, `10.0.0.0/8`, `100.64.0.0/10`, `127.0.0.0/8`,
    `169.254.0.0/16`, `172.16.0.0/12`, `192.168.0.0/16`, `224.0.0.0/4`,
    `240.0.0.0/4`) does not count there: no internet reply comes from it.
  - IPv4-mapped IPv6 sources are unmapped before their width is judged.
- A rule network that does not parse is refused by the client, so the rule
  read becomes partial and the checks say `unknown`. The rules above only
  apply to a hand edited facts file.
- An OVH rule source `any` means any source, and a bare IPv4 address
  becomes a `/32` (a bare `0.0.0.0` too: one host, not every one). The Edge
  Network Firewall filters IPv4 only, so an IPv6 or IPv4-mapped source is
  refused and the rule read becomes partial.
- On an ordered firewall (OVH) the first matching rule wins, so a deny
  before a permit makes the permit dead and the other way round.
- Rules for ICMP, ESP, GRE, AH or every IPv4 packet are listed in PFW-008
  but take no part in the port checks.
- `no_match` (no server of this project has the address) is `unknown`, not a
  finding: the address may belong to another project or account.

`NET-009` reads the result too: after a successful read it says how many
firewalls and rules were read, and still points at `stackward probe` for the
end to end view.
