# Design: provider firewall audit

Status: the facts shape, the PFW checks and the Hetzner and OVH clients are
built (issue #41). The answers chosen for the open
questions are listed at the end of this page. The user guide is
[provider-firewall.md](../provider-firewall.md).

## Problem

A cloud provider's network firewall acts before traffic reaches the host and
before Docker's iptables rules. It is the best second layer, and the host
cannot see it. Today NET-009 says so and is always `unknown`; the only answer
is `stackward probe` from another machine, which shows what is reachable but
not why, and cannot tell a missing rule from a rule that is there.

The goal is an opt in audit that reads the provider's firewall through its API,
read only, and reports findings next to the host firewall ones:

- the provider firewall is off, or none is attached to this host
- it allows all UDP
- it allows ports the host does not serve
- SSH is open to the world
- IPv6 is not covered
- a stateless firewall lacks the rules that return traffic needs, which can cut
  the host off

The first two providers are Hetzner Cloud Firewall and OVHcloud Edge Network
Firewall. They differ enough (stateful and both address families against
stateless and IPv4 only) that the model has to cover both without pretending
they are alike.

## Non goals

- Changing a provider firewall. There is no write path and none is planned;
  `plan` may later print the rule to add as text, like any other step it only
  describes.
- Storing a token, a provider account id or any provider object beyond what a
  check needs.
- Discovering the host's public address by asking an outside service. That is
  phoning home, which the roadmap rules out.
- Per provider fix automation, and providers beyond these two (see open
  questions).

## What the providers expose

Checked against the public OpenAPI description of the Hetzner Cloud API
(`docs.hetzner.cloud`), the OVHcloud API schema (`eu.api.ovh.com/1.0/ip.json`)
and the two vendors' firewall guides, on 2026-11-16. Re-check before building:
this page is a design, the vendors change their APIs.

### Hetzner Cloud Firewall

| Need | Request (GET only) | Fields used |
|---|---|---|
| host to resource | `/v1/primary_ips?ip=ADDR` | `assignee_type`, `assignee_id` |
| firewalls on it | `/v1/servers/ID` | `public_net.firewalls[].id`, `.status` (`applied` or `pending`), `public_net.ipv4.ip`, `public_net.ipv6` |
| the rules | `/v1/firewalls/ID` | `rules[]`: `direction`, `protocol` (`tcp`, `udp`, `icmp`, `esp`, `gre`), `port` (single or range), `source_ips`, `destination_ips`; `applied_to[]` |

Facts that shape the checks:

- Stateful: replies to connections the server opened need no inbound rule.
  Hetzner says so in its firewall FAQ. DHCP, ARP, some ICMPv6 types needed for
  NDP, the metadata server and DNS resolver traffic of Hetzner's own services
  are never filtered. So the "stateless needs return rules" finding does not
  apply to Hetzner.
- With no rule at all, inbound is blocked and outbound is allowed. A firewall
  with only inbound rules leaves outbound open; outbound filtering starts with
  the first outbound rule.
- One rule list holds IPv4 and IPv6 sources (`0.0.0.0/0` and `::/0`), so the
  firewall covers both families. An IPv6 rule is only needed where the owner
  wants IPv6 traffic.
- A firewall is applied to a server directly or through a label selector; the
  server's `public_net.firewalls` already lists the result, so the module does
  not evaluate selectors itself. Several firewalls on one server combine: the
  rules of all of them apply together.
- Private networks are not filtered by the firewall. The audit says so in the
  result instead of staying silent.
- Limits: 3600 requests per hour per project (`RateLimit-*` headers), at most 5
  firewalls per server, 50 rules each. The module needs three to five requests.
- A token is created per project with permission **Read** (only GET requests)
  or **Read & Write**. Read is the one stackward asks for.

### OVHcloud Edge Network Firewall

| Need | Request (GET only) | Fields used |
|---|---|---|
| host to IP object | `/1.0/ip?ip=ADDR` | the block that holds the address |
| is it firewalled | `/1.0/ip/{block}/firewall` then `/1.0/ip/{block}/firewall/{ip}` | `enabled`, `state` (`ok`, `enableFirewallPending`, `disableFirewallPending`) |
| the rules | `/1.0/ip/{block}/firewall/{ip}/rule`, then one request per `.../rule/{sequence}` | `sequence`, `action` (`permit`, `deny`), `protocol` (`ah`, `esp`, `gre`, `icmp`, `ipv4`, `tcp`, `udp`), `source`, `sourcePort`, `destination`, `destinationPort`, `tcpOption` (`established`, `syn`), `fragments`, `state` |

Facts that shape the checks:

- Stateless. OVH's guide says the Edge Network Firewall is a stateless filter
  in the anti-DDoS infrastructure, and its own example starts with "authorise
  TCP established", then UDP source port 53 and ICMP, and ends with "refuse
  IPv4". Without those first rules, a final deny rule drops the replies to
  everything the server started.
- Up to 20 rules per IP, sequence 0 to 19, evaluated in order, first match
  wins. When no rule matches, the packet is allowed: the firewall is default
  allow, and a deny rule at the end is how it becomes default deny.
- IPv4 only. The API object `ipOnFirewall` is typed `ipv4`, and the guide says
  the feature is only available for IPv4 addresses. IPv6 traffic is never
  filtered by it, so a host with a global IPv6 address is open on IPv6 as far as
  this firewall goes. The host firewall is then the only layer for IPv6.
- It only handles traffic that comes from outside the OVHcloud network. Traffic
  that starts inside it (for example the provider's own DHCP or resolvers) is
  not filtered, so the DHCP part of the stateless list is likely not needed on
  OVH. This needs confirming on a real host (open question 4).
- Port ranges in rules arrived in March 2026; before that, one rule per port.
- It can be on or off by the owner, but it is switched on automatically during
  a detected DDoS attack and cannot be turned off until the attack ends. A rule
  set can be created and left disabled to act only during an attack. So
  "disabled with rules present" is a state of its own, not the same as "no
  firewall".
- The guide says QUIC is dropped at the OVH network edge regardless of the
  settings. That bears on a Cloudflare Tunnel that uses QUIC (open question 5).
- Authentication is an application key, an application secret and a consumer
  key, with the request signed. A consumer key can be limited to chosen methods
  and paths, and IAM policy actions exist for exactly the reads needed
  (`ip:apiovh:get`, `ip:apiovh:firewall/get`, `ip:apiovh:firewall/rule/get`).
  The API is regional (`ovh-eu`, `ovh-ca`, `ovh-us`).

## How it fits the pipeline

The rule from [architecture.md](../architecture.md) stays: checks are pure over
`Facts`, collectors fill `Facts`. The provider data becomes a new facts domain,
so everything downstream (checks, report, golden tests, `--dump-facts`,
`--facts`) works as it does today.

```
credentials (env or file, per run)
    -> provider client (GET only, fixed host list)  ->  Facts.ProviderFirewall
    ->  PFW checks (pure, also read Facts.Listeners, Firewall, SSH)  ->  report
```

Pieces:

1. **`facts.ProviderFirewall`** (new top level field, so it is called out in
   the PR as `model.go` asks). Plain data:
   - `Provider`: `hetzner` or `ovh`
   - `Status`: `ok`, `no_credentials`, `denied` (401 or 403), `no_match` (no
     resource has this address), `unreachable`, `error`; with `Reason`
   - `Address`: the public address that was matched
   - `Attached`: whether a firewall filters it; `Enabled` and `State` for OVH
   - `Stateful`, `IPv6Filtered`: what the provider can do, set by the client, so
     checks do not hard code provider names
   - `Rules`: normalised rules, `direction`, `action`, `protocol`, `dst_ports`,
     `src_ports`, `sources`, `tcp_established`, `order` (Hetzner has none;
     OVH has its sequence)
   Names, descriptions, labels, account and project ids and the firewall id are
   not stored: a facts file is attached to bug reports (see the fixture rules in
   CONTRIBUTING.md) and the rule descriptions are free text.

2. **The client**, a new leaf package (working name `internal/provider`),
   imported by the CLI the way `internal/probe` is. It is the only code that
   dials out for this feature, so it gets one stackward-guard allowlist entry
   with `Net` and a why, like the Docker socket client. It has one HTTP helper
   that can only build GET requests, a fixed list of API hosts (the Hetzner API
   host and the OVH regional hosts, no redirects followed to another host), a
   size cap on responses, and a timeout. A test asserts through a recording
   server that every request is a GET and that the token never appears in a
   URL or a log line. It does not live in `internal/facts` because collectors
   there read the host through `System`; this reads a remote API and is opt in.

3. **The CLI**. Opt in flags on `audit` (and `plan`, which audits first):
   `--provider hetzner|ovh|auto` and, when the matching address is not the one
   the host shows, `--provider-ip ADDR`. No flag: the module does not run, no
   request is sent, and every PFW check is `unknown` with the reason "provider
   firewall not requested". `auto` is not a network probe: it only chooses by
   which credentials are set.

4. **Order with the sandbox.** The Landlock self sandbox cannot be loosened
   after it is applied, and the audit applies it without network. The provider
   fetch therefore runs before `sandbox.Apply`, like the output file and the
   facts file are opened before it today: the credential file is read and the
   requests are made first, then the sandbox is applied and the host collectors
   run. This means the fetch is not itself sandboxed, which the threat model has
   to state and the client's small surface (GET, fixed hosts) has to carry. The
   alternative, `probe`'s `AllowNetwork`, would leave outbound TCP open for every
   host collector too, and is worse.

## Credentials

- Read only credentials, asked for in the docs and refused where checkable.
  Hetzner: a token with permission Read. OVH: a consumer key limited to
  `GET /ip/*` (or an IAM policy with the three read actions).
- Never on the command line: argv shows in `ps` and in shell history, which is
  the same reason CF-004 flags tunnel tokens. There is no `--token VALUE`.
- From the environment per run, or from a file:
  - Hetzner: `STACKWARD_HETZNER_TOKEN`, or `STACKWARD_HETZNER_TOKEN_FILE`
  - OVH: `STACKWARD_OVH_APPLICATION_KEY`, `STACKWARD_OVH_APPLICATION_SECRET`,
    `STACKWARD_OVH_CONSUMER_KEY` and `STACKWARD_OVH_ENDPOINT` (default
    `ovh-eu`), or `STACKWARD_OVH_CREDENTIALS_FILE` holding the same four values
  - Provider specific variable names, not the vendors' own (`HCLOUD_TOKEN`), so
    that a token set for another tool is never picked up by accident.
- A file must be a regular file, not a symlink, mode `0600` or stricter,
  and owned by the user running the audit, or it is refused with the fix
  printed. It is read once, before the sandbox, and only a size capped read.
- Never stored: no cache, no state file, not in facts, reports, `--dump-facts`
  or logs. The report only says which provider was asked and with what outcome.
  The redaction pass gets the token and every part of the OVH credentials as
  literal values to mask, as a safety net on top of never holding them in a
  struct that is printed.
- Hetzner cannot be asked what scope a token has. A Read & Write token works
  and the module only sends GET, but the docs must say that a Read token is the
  right one and the audit cannot tell the difference (open question 2).
- OVH signs each request with SHA-1 over the secret, consumer key, method, URL,
  body and a server time (from the unauthenticated time endpoint). That is the
  vendor's scheme, not a choice; the code carries a `gosec` note saying so.

## Matching the host to the provider resource

The key is the public IPv4 address, because both providers address resources by
it and it is already in the facts.

1. Candidate addresses come from `Facts.Listeners.Addresses` (interface
   addresses, global scope, not private, loopback or link local), or
   `--provider-ip` when given. A host with several public addresses asks about
   each, and a finding names the address it is about.
2. Hetzner: `primary_ips?ip=` gives the assignee. If the assignee is a server,
   fetch it and read its firewalls. An address that is a floating IP is not a
   primary IP; the module asks `floating_ips` only if the primary lookup finds
   nothing, and reads the server it is assigned to.
3. OVH: `ip?ip=` finds the block; then the firewall object for that address.
   The `ip` filter is documented as "contains or equals", so the result is
   verified against the exact address before use.
4. No match is a result, not a failure: `no_match` becomes `unknown` with
   "no resource of this account has this address". It is not a pass, and it is
   not a finding that no firewall exists, because the address may belong to a
   different account or project.

## Checks

A new group `PFW` (provider firewall) keeps the NET group about the host.
Ids follow the existing scheme, are forever, and are never reused. Severity
lives in the catalog; the values below are the proposed starting point.

| Id | Question | Level when it goes wrong | Severity |
|---|---|---|---|
| PFW-001 | A provider firewall is attached and active for this address | `fail` when none (OVH: none or disabled; Hetzner: none), `warn` when OVH rules exist but the firewall is off (attack-only mode, see above), `unknown` on any non `ok` status | high |
| PFW-002 | Inbound is default deny (Hetzner: always, once a firewall is attached; OVH: a deny rule covers the rest) | `fail` when OVH has no catch-all deny, so unmatched traffic is allowed | high |
| PFW-003 | No inbound rule allows all UDP from the world | `fail` for UDP with no port limit from `0.0.0.0/0` or `::/0`; `warn` for a wide UDP range | high |
| PFW-004 | Every inbound allow rule has a service behind it on the host | `warn` for each permitted port with no listener in `Facts.Listeners` (a stale rule, or a service that is down), `info` when the listener could not be read | moderate |
| PFW-005 | SSH is not open to the world at the provider | `fail` when the sshd port(s) in `Facts.SSH` are permitted from `0.0.0.0/0` or `::/0` while a private path (tunnel, tailnet) exists, `warn` otherwise, like NET-003 | high |
| PFW-006 | IPv6 is covered | `fail` when the host has a global IPv6 address and the provider firewall cannot filter it (always so on OVH) and the host firewall does not either (NET-002 is not a pass); `pass` on Hetzner with a firewall attached, unless a rule opens `::/0` (then PFW-003 to PFW-005 see it) | high |
| PFW-007 | A stateless firewall lets return traffic in | `fail` when OVH has a deny rule that comes before any `tcp established` permit; `warn` when the host resolves names through a non local resolver and UDP source port 53 is not permitted, or time sync is on and UDP source port 123 is not; `warn` when a QUIC Cloudflare Tunnel runs and the replies are not permitted. `skip` on a stateful firewall | high |
| PFW-008 | What the provider firewall allows, one row per rule (like NET-004) | `info` | info |

NET-009 stays. When the module ran and has an `ok` result, NET-009 reads it:
instead of "cannot be seen from inside" it says how many firewalls and rules
were read and that PFW checks carry the judgement, and it keeps the note about
`stackward probe`, as issue #41 asks. With no module result it stays exactly as
it is now. PRB checks stay in their own registry; the probe remains the way to
see the whole path.

Rules the checks must get right, each a test case:

- Order matters on OVH: the first matching rule wins, so a `deny` for all that
  comes before a `permit tcp 22` makes that permit dead, and a `permit` before
  a deny of the same traffic makes the deny dead. The checks evaluate in
  sequence order, they do not look at rules one by one.
- A rule that is `creationPending` or `removalPending` is not yet in force; it
  is judged as absent and the result says a change is pending. A Hetzner
  firewall with status `pending` on the server is the same.
- Hetzner combines several firewalls, so a rule counts if any attached firewall
  has it.
- Sources: any source means `0.0.0.0/0` or `::/0`; a /8 or wider counts as the
  world for SSH, a single address or a small range does not. The threshold is
  a constant in one place.
- "Services the host runs" comes from listeners that are not loopback. A port
  that Docker publishes is a service. Without root the listeners may be
  partial; then the answer is `info`, not `warn`, because unknown is never a
  verdict.
- A rule for `esp`, `gre`, `ah`, `ipv4` or ICMP is shown in PFW-008 but does
  not take part in the port checks.

## Testing offline

Like the rest of the audit, nothing needs a network or an account.

1. **Client tests** against an `httptest` server that replays recorded, edited
   responses from `internal/provider/testdata/<provider>/`. Fixtures use
   documentation addresses (192.0.2.0/24, 198.51.100.0/24, 203.0.113.0/24,
   2001:db8::/32), made up ids and `example.com`, never a real project. Cases:
   token rejected (401), forbidden (403), rate limited (429), no match, one
   firewall, several, label selector attachment, pending state, paging, a
   response over the size cap, a redirect to another host (refused). A recording
   handler asserts every request is a GET and no token reaches a URL, a log or
   a report.
2. **Check tests** next to the checks (`pfw_test.go`), table driven over
   hand built `facts.ProviderFirewall` values, including the cases
   `TestNilFactsNeverPass` demands (empty or `no_credentials` facts never pass).
3. **Golden fixtures** `test/fixtures/pfw-<scenario>/facts.json` carrying the
   `provider_firewall` domain, so `stackward audit --facts` reproduces the
   report offline, byte for byte, and bug reports can ship the facts file.
   Planned scenarios: `pfw-hetzner-ok`, `pfw-hetzner-open-ssh-udp`,
   `pfw-ovh-no-established`, `pfw-ovh-ipv6-open`, `pfw-no-credentials`,
   `pfw-no-match`.
4. **Catalog**: the entries and `docs/checks/` pages come from `go run
   ./cmd/docgen`, as for every check.
5. **Live provider tests are not part of CI.** A maintainer run against a
   throwaway project is a manual checklist in `docs/testing.md`, never a job
   that holds a token.
6. **Guard**: the stackward-guard allowlist test shows the one new `Net` entry
   and nothing else; the depguard rule keeps `internal/checks` free of
   `net/http`.

## Failure behaviour

- Never a pass on a failure: any non `ok` status leaves PFW checks `unknown`
  with the reason (no credentials, denied, no match, unreachable, rate
  limited). The exit code is not affected by `unknown`.
- A provider outage or a slow API must not make the audit fail or hang: the
  fetch has its own timeout (default 10 s, one value for all requests) and
  never delays the host collectors beyond it.
- A partial read (the firewall found, one rule request failed) is `unknown` for
  the checks that need all rules, not a judgement from half of them.

## Open questions

1. **Check group.** A new `PFW` group, or NET-010 and up? A new group keeps
   NET about the host and needs a catalog group entry and an order slot; NET
   numbers are shorter and sit where people already look. Recommendation: `PFW`.
2. **Token scope.** The audit cannot tell a Hetzner Read token from a Read &
   Write one. Is documentation enough, or should the audit warn when it can
   tell (it cannot today), or refuse a token that has write power once the API
   offers a way to ask? Recommendation: document, and print the Read
   requirement in `--help`.
3. **Fetch before the sandbox.** The fetch runs unsandboxed because Landlock
   cannot be loosened later. Acceptable with a GET only client and a fixed host
   list, or should the fetch be a separate command (`stackward provider-facts`)
   whose output is fed to `audit --facts`? A separate command keeps `audit`
   itself network free. Recommendation: start inside `audit` with the opt in
   flag; move to a separate command if the threat model review objects.
4. **OVH and DHCP.** DHCP replies are the usual example of a rule a stateless
   firewall needs. OVH's guide says the Edge Network Firewall only
   handles traffic coming from outside the OVH network, which would make DHCP,
   the provider's resolvers and its time servers unaffected. Confirm on a real
   OVH host before PFW-007 either requires or ignores DHCP, DNS and NTP rules.
   Until confirmed, PFW-007 treats UDP source ports 53 and 123 as `warn`, not
   `fail`.
5. **QUIC and tunnels.** OVH documents that QUIC is dropped at its edge
   regardless of settings. Does that cover the QUIC a `cloudflared` tunnel
   opens outward (UDP, replies from source port 7844), or only inbound HTTP/3?
   If it covers it, a tunnel host on OVH falls back to HTTP/2 over TCP and the
   QUIC rule is moot; if not, the reply rule is needed. Needs a real test, and
   the answer decides the third clause of PFW-007.
6. **Source port only rules.** OVH's own example allows UDP source port 53 to
   any destination port. That reaches every UDP port from any sender that picks
   source port 53. Flag it under PFW-003, or leave it as the vendor's advice?
7. **Disabled with rules (OVH).** The attack-only mode is deliberate. Is that a
   `warn`, an `info`, or a pass when the host profile says a tunnel is the
   ingress? Recommendation: `info` with a note, because the owner chose it.
8. **Public address discovery.** Interface addresses work where the public
   address is on the host (Hetzner, OVH dedicated and VPS). A NAT'd provider
   needs `--provider-ip`. Is that enough for the first version?
9. **What a facts dump holds.** The matched public address is in the facts. The
   dump already hashes the hostname; should it hash or mask this address too,
   given that facts files are posted in bug reports? Recommendation: mask the
   last octet in dumps and keep the full address only in memory.
10. **Cost of N plus 1 on OVH.** The rule list returns sequence numbers, so each
    rule is its own request (at most 20). Acceptable, or fetch lazily only for
    firewalls that are enabled?
11. **More providers.** DigitalOcean, Vultr, Scaleway and AWS security groups
    are the likely next ones. The facts shape above is provider neutral on
    purpose (`Stateful`, `IPv6Filtered`, normalised rules); a third provider
    should need a client and fixtures, not new checks. Worth a design review
    after the second client exists, before the third.
12. **Release.** Issue #41 is planned for v0.4 with the other API modules, and
    the roadmap lists it there. This design is v0.3 groundwork only: the doc,
    the facts shape and the fixtures can land before the module does.

## Answers chosen for the first build

The conservative choice for each open question, until a real host or a
review says otherwise:

1. A new `PFW` group, between NET and DKR in report order.
2. Documented, and the Read requirement printed in `audit -h` and
   `plan -h`; the audit cannot tell the scopes apart.
3. The fetch runs inside `audit` and `plan`, before the sandbox, behind
   `--provider`. The threat model states that it is unsandboxed.
4. PFW-007 treats missing UDP source port 53 and 123 replies as `warn`, never
   `fail`, and does not ask for DHCP (source port 67).
5. A running Cloudflare Tunnel without a UDP source port 7844 rule is a
   `warn` in PFW-007; QUIC at the OVH edge is still unconfirmed.
6. A UDP rule that matches only a source port is flagged under PFW-003 as
   `warn`, not `fail`, because it is the vendor's own advice.
7. OVH disabled with rules (attack-only mode) is `warn` in PFW-001, so the
   choice stays visible in every report.
8. Interface addresses plus `--provider-ip` for NAT.
9. `--dump-facts` masks the last octet of the matched address and of every
   IPv4 address in a reason, and zeroes the host bits of rule networks past
   /24 (IPv6: /64) while keeping their prefix length. The interface
   addresses in `listeners.addresses` are not masked yet; a dump wide
   decision is left to a later change.
10. OVH: one request per rule, at most 20, for every address that has a
    firewall object, enabled or not (a disabled firewall with rules is the
    attack-only mode PFW-001 reports). Port strings in rule answers are
    parsed from the forms `53`, `eq 53`, `1000-2000`, `range 1000 2000`,
    `gt N` and `lt N`; any other form makes the rule read partial
    (`unknown`), never a guess.
11. The facts shape stays provider neutral; no change.
12. Not answered here; the release is the maintainer's call.

After the gate review: without `--provider`, only PFW-001 reports, with one
`skip` row saying the module was not requested and how to enable it (the
other PFW checks leave no row, through `checks.Check.Absent`), instead of
eight `unknown` rows. Pending permits count as in force and pending denies
do not, rather than every pending rule being ignored. Every "from anywhere"
question is also asked for each source port a source-port-only permit names,
because a stateless filter cannot tell a crafted packet from a reply.

After the second gate review: permits and denies read sources in opposite
directions (a permit from /8 or wider or from an unparsable source reaches
anywhere; a deny only blocks anywhere from an empty source or a true /0),
and crafted source ports are tried at both edges of every source port range,
not only at its first port. After the third: the reply checks of PFW-007,
whose finding is a dropped packet, swap the two readings (a deny from a wide
or unparsable source counts, a permit only from an empty or true /0 source),
and only an IPv4 /0 (or `::ffff:0.0.0.0/96`) counts as every IPv4 sender.
After the fourth: pending rules swap the same way in the reply checks (a
pending deny counts, a pending permit does not), and there a deny from
reserved space only (private, CGNAT, loopback, link local, multicast,
reserved) does not count.

Two details differ from the table above: a firewall that is not in force
makes PFW-002 to PFW-005 and PFW-007 `skip` with a pointer to PFW-001
instead of repeating its failure, and every PFW result names the address it
is about (`address:<ip>`; PFW-008 rows `rule:<ip>/<order>`). The Hetzner
floating IP list has no address filter (only the primary IP list has `ip=`),
so the client pages through it, at most 20 pages of 50, and matches the
address exactly.

## Sources

- Hetzner Cloud API reference: <https://docs.hetzner.cloud/> (OpenAPI
  description at <https://docs.hetzner.cloud/cloud.spec.json>)
- Hetzner Cloud Firewalls overview and FAQ: <https://docs.hetzner.com/cloud/firewalls/overview>,
  <https://docs.hetzner.com/cloud/firewalls/faq>
- Hetzner API tokens: <https://docs.hetzner.com/cloud/api/getting-started/generating-api-token>
- OVHcloud API schema: <https://eu.api.ovh.com/1.0/ip.json> (console at
  <https://api.ovh.com/console/>)
- OVHcloud, Enabling and configuring the Edge Network Firewall:
  <https://docs.ovhcloud.com/en/guides/bare-metal-cloud/dedicated-servers/firewall-network>
