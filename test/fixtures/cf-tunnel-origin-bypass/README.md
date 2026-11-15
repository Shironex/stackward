# cf-tunnel-origin-bypass

A Docker host that serves its sites through one containerised cloudflared
connector, but still publishes the proxy on 0.0.0.0:80 and 0.0.0.0:443.
CrowdSec runs with the default private range whitelist and only the
firewall bouncer.

What it shows:

- The profile is inferred as `mixed` (a tunnel plus public web ports).
- CF-001 records the tunnel, CF-002 warns (one connector), CF-003 fails
  (the published proxy bypasses the tunnel; UFW does not filter Docker
  published ports), CF-004 warns (the token is a command line argument),
  CF-005 asks for `stackward probe`.
- CS-003 fails (behind a tunnel a firewall bouncer bans nothing useful),
  CS-004 fails (every request carries a whitelisted local source and no
  parser reads Cf-Connecting-Ip), CS-005 warns (no proxy log acquired),
  CS-007 is skipped (tunnel present, see CS-003).
- TS checks are skipped (Tailscale not installed; TS-004 passes since no
  rule names tailscale0), CS-010 passes (SSH is allowed from one source
  only).
