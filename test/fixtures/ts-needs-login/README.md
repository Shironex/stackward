# ts-needs-login

A host whose Tailscale node dropped to NeedsLogin after its key expired
two days before the audit. UFW still allows SSH only on `tailscale0` plus a
rate limited public rule, so the tailnet path everyone relies on is dead.

What it shows:

- The profile is inferred as `unknown`: the tailscaled socket and the
  tailscale0 rules hint at a tailnet, but the Tailscale facts say it is not
  Running, and nothing else gives a profile.
- TS-001 fails (NeedsLogin), TS-002 fails (the key expired), TS-004 fails
  (two UFW rules name `tailscale0` while the node is not Running).
- NET-003 warns rather than fails: SSH is public and no private path
  exists right now, so closing it would lock the owner out.
- CS-010 passes (the fail2ban sshd jail covers port 22); CS-011 warns
  (Tailscale is installed and the jail does not ignore 100.64.0.0/10).
- TS-003 and TS-005 are unknown: the facts hold no serve or lock state, as
  when `tailscale serve status` and `tailscale lock status` fail.
