# cs-tunnel-l7-ok

The healthy version of a tunnel host: two containerised cloudflared
replicas, the proxy published on loopback only, SSH allowed on
`tailscale0` only with a Running node, CrowdSec with the Traefik bouncer,
the proxy log acquired, a real IP parser that matches ranges, the local
API on the Docker bridge, and a fail2ban sshd jail that ignores the
tailnet.

What it shows:

- The profile is inferred as `tunnel`.
- TS-001, TS-002, TS-003 and TS-004 pass; TS-005 reports Tailnet Lock off.
- CF-002, CF-003 and CF-004 pass; CF-005 still asks for `stackward probe`.
- CS-001 to CS-006, CS-010 and CS-011 pass; CS-007 is skipped (behind a
  tunnel); CS-008 stays unknown (the interval lives in the bouncer config,
  which holds the API key and is not read).
- NET-003 passes: SSH is only reachable over the tailnet.
