package checks

import (
	"fmt"
	"strings"

	"github.com/Shironex/stackward/internal/facts"
	"github.com/Shironex/stackward/internal/profile"
)

// CF checks read the cloudflared collector (facts/cloudflared.go) and count
// running cloudflared containers from the Docker facts, so a containerised
// connector is seen even when the process scan cannot see other users'
// processes. CF-003 also reads the listeners and firewall.

func init() {
	Register(Check{ID: "CF-001", Run: checkTunnelPresence})
	Register(Check{ID: "CF-002", Run: checkTunnelReplicas})
	Register(Check{ID: "CF-003", Run: checkOriginBypass})
	Register(Check{ID: "CF-004", Run: checkTunnelTokenArgs})
	Register(Check{ID: "CF-005", Run: checkTunnelProbe})
}

// tunnelView joins the connectors from the process scan with running
// cloudflared containers from the Docker facts. A container's process is
// usually in the scan too, so the larger of the two container counts is
// used, never their sum.
type tunnelView struct {
	connectors  int
	inContainer int
	docker      int // running cloudflared containers in the Docker facts
	present     bool
	known       bool
}

func tunnelFacts(f *facts.Facts) tunnelView {
	c := f.Cloudflared
	v := tunnelView{connectors: len(c.Connectors), docker: profile.TunnelContainers(f)}
	for _, k := range c.Connectors {
		if k.Container {
			v.inContainer++
		}
	}
	if v.docker > v.inContainer {
		v.connectors += v.docker - v.inContainer
		v.inContainer = v.docker
	}
	v.present, v.known = c.TunnelPresent()
	if v.docker > 0 {
		v.present, v.known = true, true
	}
	return v
}

func tunnelEvidence(c *facts.Cloudflared, v tunnelView) map[string]any {
	return map[string]any{"connectors": v.connectors, "in_container": v.inContainer, "docker_containers": v.docker, "unit": unitWord(c.Unit)}
}

func checkTunnelPresence(in Input) []Result {
	c := in.Facts.Cloudflared
	if c == nil {
		return []Result{NotInspected(in.Facts, "cloudflared")}
	}
	v := tunnelFacts(in.Facts)
	ev := tunnelEvidence(c, v)
	ev["tunnel"] = presentWord(v.present, v.known)
	switch {
	case !v.known:
		return One(Unknown, "no cloudflared connector seen, but other users' processes are hidden from this user (run with sudo)", ev)
	case !v.present:
		return One(Info, "no Cloudflare Tunnel connector runs on this host", ev)
	case v.connectors == 0:
		return One(Info, "a Cloudflare Tunnel is present (cloudflared.service is active)", ev)
	}
	return One(Info, fmt.Sprintf("a Cloudflare Tunnel is present: %d connector(s), %d in a container", v.connectors, v.inContainer), ev)
}

func presentWord(present, known bool) string {
	switch {
	case !known:
		return "unknown"
	case present:
		return "present"
	}
	return "absent"
}

func checkTunnelReplicas(in Input) []Result {
	c := in.Facts.Cloudflared
	if c == nil {
		return []Result{NotInspected(in.Facts, "cloudflared")}
	}
	v := tunnelFacts(in.Facts)
	ev := tunnelEvidence(c, v)
	ev["profile"] = string(in.Profile)
	n, present, known := v.connectors, v.present, v.known
	switch {
	case n >= 2:
		return One(Pass, fmt.Sprintf("%d cloudflared connectors run", n), ev)
	case n == 1:
		return One(Warn, "only one cloudflared connector runs: a restart or crash takes every tunnel hostname down", ev)
	case present:
		return One(Unknown, "cloudflared.service is active but its processes are hidden from this user (run with sudo)", ev)
	case c.Unit.Loaded() && c.Unit.UnitFileState == "enabled" && !c.Unit.Active():
		return One(Fail, fmt.Sprintf("cloudflared.service is enabled but %s: no connector runs", valueOrUnknown(c.Unit.ActiveState)), ev)
	case !known:
		return One(Unknown, "no connector seen, but other users' processes are hidden from this user (run with sudo)", ev)
	case in.Profile == profile.Tunnel:
		return One(Fail, "the profile is tunnel but no cloudflared connector runs: the sites behind it are down", ev)
	}
	return One(Skip, "no Cloudflare Tunnel on this host", ev)
}

// webExposure judges whether TCP 80 or 443 accepts connections from any
// source. It returns the worst answer, the exposed ports, and why.
func webExposure(f *facts.Facts) (tri, []string, string) {
	worst := triNo
	var exposed, why []string
	for _, g := range groupListeners(f.Listeners.Sockets) {
		if g.proto != "tcp" || !webPorts[g.port] {
			continue
		}
		label := portLabel(g.proto, g.port)
		var o tri
		var reason string
		docker := false
		isExposed := false
		for _, s := range g.socks {
			if s.Class().Exposed() {
				isExposed = true
				if s.HasProcess("docker-proxy") {
					docker = true
				}
			}
		}
		switch {
		case !isExposed:
			o, reason = triNo, "loopback or private bind only"
		case docker && f.Firewall != nil && f.Firewall.DockerUser == "filtered":
			o, reason = triUnknown, "a published container port; DOCKER-USER has rules that are not analysed"
		case docker:
			o, reason = triYes, "a published container port on a wildcard or public address (UFW input rules do not apply)"
		default:
			o, reason = openFromAnywhere(f.Firewall, g.socks, g.proto, g.port)
		}
		why = append(why, label+": "+reason)
		if o == triYes {
			exposed = append(exposed, label)
		}
		if o == triYes || (o == triUnknown && worst == triNo) {
			worst = o
		}
	}
	if len(why) == 0 {
		return triNo, nil, "nothing listens on 80 or 443"
	}
	return worst, exposed, strings.Join(why, "; ")
}

// webPorts are the ports an origin proxy answers on.
var webPorts = map[int]bool{80: true, 443: true}

func checkOriginBypass(in Input) []Result {
	f := in.Facts
	c := f.Cloudflared
	if c == nil {
		return []Result{NotInspected(f, "cloudflared")}
	}
	v := tunnelFacts(f)
	present, known := v.present, v.known
	switch {
	case !known:
		return One(Unknown, "whether a tunnel runs is unknown (run with sudo)", map[string]any{"tunnel": "unknown"})
	case !present:
		return One(Skip, "no Cloudflare Tunnel on this host", map[string]any{"tunnel": "absent"})
	}
	if f.Listeners == nil {
		return []Result{NotInspected(f, "listeners")}
	}
	open, exposed, why := webExposure(f)
	ev := map[string]any{"tunnel": "present", "open_from_anywhere": open.String(), "exposed": orEmptyStrings(exposed)}
	switch open {
	case triYes:
		return One(Fail, fmt.Sprintf("the tunnel is the ingress, but the origin is reachable from anywhere on %s: it bypasses Cloudflare (%s)", strings.Join(exposed, ", "), why), ev)
	case triUnknown:
		return One(Unknown, "could not tell whether 80/443 are reachable past the tunnel: "+why, ev)
	}
	return One(Pass, "80/443 are not reachable from anywhere: "+why, ev)
}

func orEmptyStrings(v []string) []string {
	if v == nil {
		return []string{}
	}
	return v
}

func checkTunnelTokenArgs(in Input) []Result {
	c := in.Facts.Cloudflared
	if c == nil {
		return []Result{NotInspected(in.Facts, "cloudflared")}
	}
	if !c.Installed {
		return One(Skip, "cloudflared is not installed", map[string]any{"token_in_args": false})
	}
	inArgs, known := c.TokenInArgs()
	ev := map[string]any{"token_in_args": inArgs, "connectors": len(c.Connectors), "unit": unitWord(c.Unit)}
	switch {
	case inArgs:
		return One(Warn, "the tunnel token is passed on the command line: ps, the unit file and docker inspect show it", ev)
	case !known:
		return One(Unknown, "a connector's command line could not be read (run with sudo)", ev)
	case len(c.Connectors) == 0 && !c.Unit.Loaded():
		if !tunnelFacts(in.Facts).known {
			return One(Unknown, "no connector seen, but other users' processes are hidden from this user (run with sudo)", ev)
		}
		return One(Skip, "no running connector or cloudflared unit to inspect", ev)
	}
	return One(Pass, "no connector takes the token as a command line argument", ev)
}

func checkTunnelProbe(in Input) []Result {
	c := in.Facts.Cloudflared
	if c == nil {
		return []Result{NotInspected(in.Facts, "cloudflared")}
	}
	v := tunnelFacts(in.Facts)
	present, known := v.present, v.known
	switch {
	case !known:
		return One(Unknown, "whether a tunnel runs is unknown (run with sudo)", map[string]any{"tunnel": "unknown"})
	case !present:
		return One(Skip, "no Cloudflare Tunnel on this host", map[string]any{"tunnel": "absent"})
	}
	return One(Unknown, "only an outside view proves the origin does not answer; run `stackward probe` against the origin address from another machine", map[string]any{"tunnel": "present"})
}
