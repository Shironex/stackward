package checks

import (
	"sort"

	"github.com/Shironex/stackward/internal/facts"
	"github.com/Shironex/stackward/internal/profile"
)

// This file exports the NET, DKR and PAAS judgements the firewall plan
// steps (internal/plan ufw-policy and ufw-docker) build on, so a step
// opens and closes exactly what the checks say, without a second copy of
// their rules.

// WebPort reports whether port is one of the web ports (80, 443) whose
// public exposure the ingress profile decides.
func WebPort(port int) bool { return webPorts[port] }

// HostPort is a socket of a host service (not a published container
// port) that listens on a wildcard or public address, as NET-004 sees it.
type HostPort struct {
	Proto     string
	Port      int
	Processes []string
}

// ExposedHostPorts lists the host services a default deny firewall would
// close to the internet: wildcard or public listeners that no container
// publishes, without the DHCP client sockets and the outbound client
// sockets of cloudflared and tailscaled that NET-004 reports as info. It
// returns nil when the listeners were not inspected.
func ExposedHostPorts(f *facts.Facts) []HostPort {
	l := f.Listeners
	if l == nil {
		return nil
	}
	out := []HostPort{}
	for _, g := range groupListeners(l.Sockets) {
		var exposed []facts.Listener
		for _, s := range g.socks {
			if s.Class().Exposed() && !s.PublishedByContainer(f.Docker) {
				exposed = append(exposed, s)
			}
		}
		if len(exposed) == 0 || (g.proto == "udp" && dhcpClientPorts[g.port]) {
			continue
		}
		if udpClientSocket(l, portGroup{proto: g.proto, port: g.port, socks: exposed}) != "" {
			continue
		}
		seen := map[string]bool{}
		var procs []string
		for _, s := range exposed {
			for _, p := range s.Processes {
				if !seen[p] {
					seen[p] = true
					procs = append(procs, p)
				}
			}
		}
		sort.Strings(procs)
		out = append(out, HostPort{Proto: g.proto, Port: g.port, Processes: procs})
	}
	return out
}

// PublishedPort is one published container binding on a wildcard or
// public host address, as DKR-001 judges it.
type PublishedPort struct {
	Container string
	// Label is "0.0.0.0:443->443/tcp".
	Label         string
	Proto         string
	HostPort      int
	ContainerPort int
	// Open is "yes" when it is reachable from any source now, "no" when
	// the forward filter drops it, "unknown" otherwise.
	Open string
	// Filter names what decided (DKR-001's filter): none, docker-user,
	// ufw-docker, ufw-route, input, nftables or unknown.
	Filter string
	// Public is true when the profile expects it public, whatever filters
	// it now: a web port on a public-web or paas-panel host.
	Public bool
	// Panel is true when it is a PaaS panel port PAAS-003 judges.
	Panel bool
}

// PublishedPorts lists every published binding on a wildcard or public
// host address of every container, with DKR-001's verdict. ok is false
// when the Docker API was not read (the bindings are unknown); Docker
// not installed gives none and ok.
func PublishedPorts(f *facts.Facts, prof profile.Name) (out []PublishedPort, ok bool) {
	d := f.Docker
	if d == nil {
		return nil, false
	}
	if !d.Installed {
		return []PublishedPort{}, true
	}
	if d.API != "ok" || d.ContainersTruncated {
		return nil, false
	}
	panel := PanelPorts(f)
	out = []PublishedPort{}
	for _, c := range d.Containers {
		for _, p := range c.Ports {
			if !paasAddrClass(p.HostIP).Exposed() {
				continue
			}
			v := judgePublished(Input{Facts: f, Profile: prof}, d, p)
			proto := p.Proto
			if proto == "" {
				proto = "tcp"
			}
			_, isPanel := panel[p.HostPort]
			out = append(out, PublishedPort{
				Container: c.Name, Label: v.label, Proto: proto, HostPort: p.HostPort, ContainerPort: p.ContainerPort,
				Open: v.open.String(), Filter: v.filter,
				Public: publicLevel(prof, p.HostPort, "") == Pass, Panel: isPanel && proto == "tcp",
			})
		}
	}
	return out, true
}

// PanelPorts returns the PaaS panel ports PAAS-003 judges on this host,
// with the platform that owns each; empty when no panel runs here or the
// PaaS facts are missing.
func PanelPorts(f *facts.Facts) map[int]string {
	out := map[int]string{}
	if f.PaaS == nil {
		return out
	}
	containers, _ := paasContainers(f)
	for _, pl := range paasPlatforms(f.PaaS, containers) {
		if pl.Role == facts.RoleManaged {
			continue
		}
		for _, p := range paasPanelPorts[pl.Name] {
			out[p] = pl.Name
		}
	}
	return out
}
