# cs-public-ssh-fail2ban

A public web host without a tunnel: nginx on 80/443, SSH moved to 2222 and
open to anywhere, a Running Tailscale node with a key that still expires
and a Funnel left on 443, CrowdSec with only the firewall bouncer, and
fail2ban jails that still watch port 22.

What it shows:

- The profile is inferred as `public-web`.
- TS-002 fails (key expiry set), TS-003 fails (Funnel publishes 443),
  TS-001 and TS-004 pass.
- CF checks are skipped or informational (no tunnel).
- CS-002 warns (the bouncer last pulled 20 minutes ago), CS-005 passes
  (the nginx log is acquired), CS-006 warns (the local API is on 0.0.0.0),
  CS-007 warns (the firewall bouncer does not hook DOCKER-USER), CS-010
  warns (the sshd jail bans on 22 while sshd listens on 2222), CS-011 warns
  (no jail ignores 100.64.0.0/10).
- NET-003 fails: SSH is public although the tailnet offers a private path.
