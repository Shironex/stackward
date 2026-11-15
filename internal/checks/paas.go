package checks

import (
	"fmt"
	"sort"
	"strings"

	"github.com/Shironex/stackward/internal/facts"
)

// PAAS checks combine what the paas collector found on disk (facts/paas.go)
// with container, listener and firewall facts owned by other collectors.
//
// They read those facts through three small views (paasContainer,
// paasListener, paasFilter) filled by the read* hooks below. Without the
// Docker API (no socket access) the container view is unavailable and the
// checks that need containers fall back to listeners (PAAS-002) or return
// unknown (PAAS-004, PAAS-005), never pass. Tests swap the hooks to drive
// the checks over fake views.

// paasContainer is the part of a container the PAAS checks need.
type paasContainer struct {
	Name     string
	Image    string
	Labels   map[string]string
	Ports    []paasPort
	Project  string   // grouping project (Coolify project, compose, stack)
	Networks []string // attached networks
}

// paasPort is one published port of a container.
type paasPort struct {
	HostIP        string
	HostPort      int
	ContainerPort int
	Proto         string
}

// paasListener is one listening socket on the host.
type paasListener struct {
	Proto   string // "tcp" or "udp"
	Addr    string // bind address, "0.0.0.0", "::", "127.0.0.1", ...
	Port    int
	Process string
}

// paasFilter says whether the firewall filters traffic to a port.
type paasFilter string

const (
	paasFilterUnknown paasFilter = "unknown"
	paasFilterNone    paasFilter = "none"     // reachable from anywhere
	paasFilterApplied paasFilter = "filtered" // some source restriction applies
)

// Hooks reading facts owned by other collectors. A hook returns ok false
// when it cannot read its domain.
var (
	readPaaSContainers = paasContainersFrom
	readPaaSListeners  = paasListenersFrom
	// viaDocker is true for ports Docker publishes (filtered only in the
	// DOCKER-USER chain), false for host processes (filtered by INPUT).
	readPaaSFilter = paasFilterFor
)

// paasContainersFrom maps the Docker facts. Not installed is a known empty
// list; an API stackward could not read is not available.
func paasContainersFrom(d *facts.Docker) ([]paasContainer, bool) {
	if !d.Installed {
		return []paasContainer{}, true
	}
	if d.API != "ok" {
		return nil, false
	}
	out := make([]paasContainer, 0, len(d.Containers))
	for _, c := range d.Containers {
		pc := paasContainer{Name: c.Name, Image: c.Image, Labels: c.Labels, Project: c.Project, Networks: c.Networks}
		for _, p := range c.Ports {
			pc.Ports = append(pc.Ports, paasPort{HostIP: p.HostIP, HostPort: p.HostPort, ContainerPort: p.ContainerPort, Proto: p.Proto})
		}
		out = append(out, pc)
	}
	return out, true
}

// paasListenersFrom maps the listener facts.
func paasListenersFrom(l *facts.Listeners) ([]paasListener, bool) {
	out := make([]paasListener, 0, len(l.Sockets))
	for _, s := range l.Sockets {
		out = append(out, paasListener{Proto: s.Proto, Addr: s.Address, Port: s.Port, Process: strings.Join(s.Processes, ",")})
	}
	return out, true
}

// paasFilterFor reads whether the firewall filters proto/port.
//
// Docker published ports skip UFW's input rules; only the DOCKER-USER chain
// (or ufw-docker, which hooks into it) filters them. Host sockets are
// filtered by UFW when it is active with a deny default: no allow rule for
// the port means blocked (filtered), an allow from anywhere means
// reachable, an allow from a source or interface means filtered. Anything
// the facts do not show (no root, nftables only, firewalld) is unknown.
func paasFilterFor(fw *facts.Firewall, proto string, port int, viaDocker bool) paasFilter {
	if fw == nil {
		return paasFilterUnknown
	}
	if viaDocker {
		switch {
		case fw.UFWDocker != nil && fw.UFWDocker.Loaded == "yes", fw.DockerUser == "filtered":
			return paasFilterApplied
		case fw.DockerBackend == "iptables" && (fw.DockerUser == "default" || fw.DockerUser == "absent"):
			return paasFilterNone
		}
		return paasFilterUnknown
	}
	u := fw.UFW
	if u == nil || !u.Live() || u.Status != "active" || !u.RulesKnown {
		return paasFilterUnknown
	}
	if u.DefaultIncoming != "deny" && u.DefaultIncoming != "reject" {
		return paasFilterUnknown
	}
	for _, r := range u.Rules {
		if r.Direction == "in" && r.Allows() && r.FromAnywhere() && r.MatchesPort(proto, port) {
			return paasFilterNone
		}
	}
	return paasFilterApplied
}

// paasDockerFilter reads whether a standard ufw-docker chain lets a
// published port through from anywhere: a route rule allowing the
// container port is none, the chain's deny rules are filtered.
func paasDockerFilter(f *facts.Facts, proto string, port int) paasFilter {
	var socks []facts.Listener
	for _, s := range f.Listeners.Sockets {
		if s.Proto == proto && s.Port == port {
			socks = append(socks, s)
		}
	}
	switch o, _, _ := publishedReach(f, socks, proto, port); o {
	case triYes:
		return paasFilterNone
	case triNo:
		return paasFilterApplied
	}
	return paasFilterUnknown
}

// paasForwardBackend reports whether the shared forward filter has a special
// answer for this host that paasFilterFor cannot give: Docker's nftables
// backend, or Docker running with iptables off.
func paasForwardBackend(f *facts.Facts) bool {
	d := f.Docker
	return f.Firewall.DockerBackend == "nftables" || (d.Daemon != nil && d.Daemon.IPTables != nil && !*d.Daemon.IPTables)
}

// Collector names of the domains read through the hooks, for NotInspected.
const (
	paasDockerCollector    = "docker"
	paasListenersCollector = "listeners"
)

func init() {
	Register(Check{ID: "PAAS-001", Run: checkPaaSDetected})
	Register(Check{ID: "PAAS-002", Run: checkPaaSProxyExposure})
	Register(Check{ID: "PAAS-003", Run: checkPaaSPanelPorts})
	Register(Check{ID: "PAAS-004", Run: checkPaaSPublicDatabase})
	Register(Check{ID: "PAAS-005", Run: checkPaaSDefaultNetwork})
	Register(Check{ID: "PAAS-008", Run: checkPaaSSwarmPorts})
}

// paasContainers returns the container view, or the unknown result that
// explains why there is none.
func paasContainers(f *facts.Facts) ([]paasContainer, *Result) {
	if f.Docker == nil {
		r := NotInspected(f, paasDockerCollector)
		return nil, &r
	}
	cs, ok := readPaaSContainers(f.Docker)
	if !ok {
		reason := f.Docker.APIReason
		if reason == "" {
			reason = "the Docker API was not read"
		}
		return nil, &Result{Level: Unknown, Message: "containers not inspected: " + reason,
			Evidence: map[string]any{"collector": paasDockerCollector, "api": f.Docker.API}}
	}
	return cs, nil
}

// paasListeners returns the listener view, or the unknown result that
// explains why there is none.
func paasListeners(f *facts.Facts) ([]paasListener, *Result) {
	if f.Listeners == nil {
		r := NotInspected(f, paasListenersCollector)
		return nil, &r
	}
	ls, ok := readPaaSListeners(f.Listeners)
	if !ok {
		return nil, &Result{Level: Unknown, Message: "listener facts are present but this build cannot read them for PaaS checks",
			Evidence: map[string]any{"collector": paasListenersCollector}}
	}
	return ls, nil
}

// paasPlatform is a platform as the checks see it: disk detection refined
// by containers when they are available.
type paasPlatform struct {
	Name     string
	Role     string
	DataRoot string
	Version  string
	Sources  []string // "disk", "containers"
}

// paasPlatforms merges disk detection with container detection. containers
// may be nil (not available).
func paasPlatforms(p *facts.PaaS, containers []paasContainer) []paasPlatform {
	byName := map[string]*paasPlatform{}
	var order []string
	add := func(name string) *paasPlatform {
		if pl, ok := byName[name]; ok {
			return pl
		}
		pl := &paasPlatform{Name: name, Role: facts.RoleUnknown, DataRoot: paasDataRoot(name)}
		byName[name] = pl
		order = append(order, name)
		return pl
	}
	if p != nil {
		for _, d := range p.Platforms {
			pl := add(d.Name)
			pl.Role, pl.DataRoot = d.Role, d.DataRoot
			pl.Sources = append(pl.Sources, "disk")
		}
	}
	for name, seen := range paasPlatformsFromContainers(containers) {
		pl := add(name)
		if !paasContains(pl.Sources, "containers") {
			pl.Sources = append(pl.Sources, "containers")
		}
		if seen.panel {
			pl.Role = facts.RolePanel
		} else if pl.Role == facts.RoleUnknown && seen.managed {
			pl.Role = facts.RoleManaged
		}
		if seen.version != "" && seen.version != "latest" {
			pl.Version = seen.version
		}
	}
	sort.Strings(order)
	out := make([]paasPlatform, 0, len(order))
	for _, n := range order {
		out = append(out, *byName[n])
	}
	return out
}

func paasDataRoot(name string) string {
	if name == facts.PlatformDokploy {
		return facts.DokployRoot
	}
	return facts.CoolifyRoot
}

type paasSighting struct {
	panel, managed bool
	version        string
}

// paasPlatformsFromContainers recognises platform containers by image, name and
// labels, as the platforms' public install files define them: the Coolify
// panel image ghcr.io/coollabsio/coolify (container "coolify"), the
// coolify.managed label on every resource Coolify deploys, and the Dokploy
// swarm service "dokploy" running the dokploy/dokploy image.
func paasPlatformsFromContainers(cs []paasContainer) map[string]paasSighting {
	out := map[string]paasSighting{}
	for _, c := range cs {
		repo, tag := paasSplitImage(c.Image)
		switch {
		case repo == "coollabsio/coolify" || strings.HasSuffix(repo, "/coollabsio/coolify"):
			s := out[facts.PlatformCoolify]
			s.panel, s.version = true, tag
			out[facts.PlatformCoolify] = s
		case c.Labels["coolify.managed"] == "true":
			s := out[facts.PlatformCoolify]
			s.managed = true
			out[facts.PlatformCoolify] = s
		case repo == "dokploy/dokploy" || strings.HasSuffix(repo, "/dokploy/dokploy") ||
			c.Labels["com.docker.swarm.service.name"] == "dokploy":
			s := out[facts.PlatformDokploy]
			s.panel = true
			if repo == "dokploy/dokploy" || strings.HasSuffix(repo, "/dokploy/dokploy") {
				s.version = tag
			}
			out[facts.PlatformDokploy] = s
		case c.Name == "dokploy-traefik":
			s := out[facts.PlatformDokploy]
			s.managed = true
			out[facts.PlatformDokploy] = s
		}
	}
	return out
}

// paasSplitImage splits "ghcr.io/org/name:tag@sha256:..." into its repository
// without a registry host ("org/name") and its tag ("" when absent).
func paasSplitImage(image string) (repo, tag string) {
	image, _, _ = strings.Cut(image, "@")
	if i := strings.LastIndex(image, ":"); i > strings.LastIndex(image, "/") {
		image, tag = image[:i], image[i+1:]
	}
	if first, rest, ok := strings.Cut(image, "/"); ok && (strings.ContainsAny(first, ".:") || first == "localhost") {
		image = rest
	}
	return image, tag
}

func paasContains(list []string, s string) bool {
	for _, l := range list {
		if l == s {
			return true
		}
	}
	return false
}

func checkPaaSDetected(in Input) []Result {
	f := in.Facts
	if f.PaaS == nil {
		return []Result{NotInspected(f, "paas")}
	}
	containers, _ := paasContainers(f)
	platforms := paasPlatforms(f.PaaS, containers)
	disk := map[string]facts.Platform{}
	for _, d := range f.PaaS.Platforms {
		disk[d.Name] = d
	}
	if len(platforms) == 0 {
		return One(Skip, "no Coolify or Dokploy installation found", map[string]any{
			"platforms": []string{}, "containers_read": containers != nil,
		})
	}
	var out []Result
	for _, pl := range platforms {
		d := disk[pl.Name]
		ev := map[string]any{
			"platform": pl.Name, "role": pl.Role, "version": pl.Version,
			"sources": pl.Sources, "evidence": paasNonNil(d.Evidence), "denied": paasNonNil(d.Denied),
			"containers_read": containers != nil,
		}
		msg := fmt.Sprintf("%s detected, role %s", pl.Name, pl.Role)
		if pl.Version != "" {
			msg += ", version " + pl.Version
		}
		if pl.Role == facts.RoleUnknown && len(d.Denied) > 0 && !f.IsRoot() {
			msg += " (run with sudo to see the role)"
		}
		out = append(out, Result{Subject: "file:" + pl.DataRoot, Level: Info, Message: msg, Evidence: ev})
	}
	return out
}

func paasNonNil(s []string) []string {
	if s == nil {
		return []string{}
	}
	return s
}

// paasAddrClass classifies a bind address with the listener collector's
// rules, accepting brackets and a zone suffix. Unparseable addresses count
// as public so they are never silently treated as safe.
func paasAddrClass(addr string) facts.BindClass {
	a := strings.TrimSuffix(strings.TrimPrefix(addr, "["), "]")
	if i := strings.IndexByte(a, '%'); i >= 0 {
		a = a[:i]
	}
	c := facts.ClassifyAddress(a)
	if c == facts.BindInvalid {
		return facts.BindPublic
	}
	return c
}

// paasExposed reports whether a bind address is reachable from the internet
// when nothing filters it.
func paasExposed(addr string) bool { return paasAddrClass(addr).Exposed() }

func paasPortLabel(p paasPort) string {
	proto := p.Proto
	if proto == "" {
		proto = "tcp"
	}
	host := p.HostIP
	if host == "" {
		host = "0.0.0.0"
	}
	if strings.Contains(host, ":") {
		host = "[" + host + "]"
	}
	return fmt.Sprintf("%s:%d->%d/%s", host, p.HostPort, p.ContainerPort, proto)
}
