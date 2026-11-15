package checks

import (
	"fmt"
	"net/netip"
	"sort"
	"strconv"
	"strings"

	"github.com/Shironex/stackward/internal/facts"
	"github.com/Shironex/stackward/internal/profile"
)

// PAAS checks combine what the paas collector found on disk (facts/paas.go)
// with container, listener and firewall facts owned by other collectors.
//
// Those collectors land separately, so this file reads them through three
// small views (paasContainer, paasListener, paasFilter) filled by the
// read* hooks below. A hook that cannot map its facts yet reports them as
// unavailable and the checks that need them return unknown, never pass.
// Tests swap the hooks to drive the checks over fake views.

// paasContainer is the part of a container the PAAS checks need.
type paasContainer struct {
	Name   string
	Image  string
	Labels map[string]string
	Ports  []paasPort
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

// Hooks reading facts owned by other collectors. Each returns ok false
// while it cannot read its domain; the Docker, listener and firewall
// collectors map their facts here when they land.
var (
	readPaaSContainers = func(*facts.Docker) ([]paasContainer, bool) { return nil, false }
	readPaaSListeners  = func(*facts.Listeners) ([]paasListener, bool) { return nil, false }
	// viaDocker is true for ports Docker publishes (filtered only in the
	// DOCKER-USER chain), false for host processes (filtered by INPUT).
	readPaaSFilter = func(_ *facts.Firewall, _ string, _ int, _ bool) paasFilter { return paasFilterUnknown }
)

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
		return nil, &Result{Level: Unknown, Message: "container facts are present but this build cannot read them for PaaS checks",
			Evidence: map[string]any{"collector": paasDockerCollector}}
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
		if seen.version != "" {
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

// Address classes for bind addresses.
const (
	paasAddrWildcard = "wildcard"
	paasAddrLoopback = "loopback"
	paasAddrTailnet  = "tailnet"
	paasAddrPrivate  = "private"
	paasAddrPublic   = "public"
)

// Tailscale address ranges: 100.64.0.0/10 (shared address space) and the
// Tailscale ULA prefix.
var (
	paasTailnetV4 = netip.MustParsePrefix("100.64.0.0/10")
	paasTailnetV6 = netip.MustParsePrefix("fd7a:115c:a1e0::/48")
)

// paasAddrClass classifies a bind address. Unparseable addresses count as
// public so they are never silently treated as safe.
func paasAddrClass(addr string) string {
	a := strings.TrimSuffix(strings.TrimPrefix(addr, "["), "]")
	if i := strings.IndexByte(a, '%'); i >= 0 {
		a = a[:i]
	}
	switch a {
	case "", "*", "0.0.0.0", "::":
		return paasAddrWildcard
	}
	ip, err := netip.ParseAddr(a)
	if err != nil {
		return paasAddrPublic
	}
	ip = ip.Unmap()
	switch {
	case ip.IsUnspecified():
		return paasAddrWildcard
	case ip.IsLoopback():
		return paasAddrLoopback
	case paasTailnetV4.Contains(ip) || paasTailnetV6.Contains(ip):
		return paasAddrTailnet
	case ip.IsPrivate() || ip.IsLinkLocalUnicast():
		return paasAddrPrivate
	}
	return paasAddrPublic
}

// paasExposed reports whether a bind address is reachable from the internet
// when nothing filters it.
func paasExposed(addr string) bool {
	c := paasAddrClass(addr)
	return c == paasAddrWildcard || c == paasAddrPublic
}

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

// isPaaSProxy recognises the platform reverse proxy: Coolify names it
// coolify-proxy (label coolify.proxy=true), Dokploy dokploy-traefik.
func isPaaSProxy(c paasContainer) bool {
	return c.Name == "coolify-proxy" || c.Name == "dokploy-traefik" || c.Labels["coolify.proxy"] == "true"
}

func checkPaaSProxyExposure(in Input) []Result {
	f := in.Facts
	if f.PaaS == nil {
		return []Result{NotInspected(f, "paas")}
	}
	containers, why := paasContainers(f)
	if len(paasPlatforms(f.PaaS, containers)) == 0 {
		return One(Skip, "no Coolify or Dokploy installation found", nil)
	}
	if why != nil {
		return []Result{*why}
	}
	var out []Result
	for _, c := range containers {
		if !isPaaSProxy(c) {
			continue
		}
		out = append(out, paasJudgeProxy(c, in.Profile))
	}
	if len(out) == 0 {
		return One(Skip, "no platform proxy container found", nil)
	}
	return out
}

func paasJudgeProxy(c paasContainer, prof profile.Name) Result {
	var published, exposedWeb, exposedOther []string
	for _, p := range c.Ports {
		published = append(published, paasPortLabel(p))
		if !paasExposed(p.HostIP) {
			continue
		}
		if p.HostPort == 80 || p.HostPort == 443 {
			exposedWeb = append(exposedWeb, paasPortLabel(p))
		} else {
			exposedOther = append(exposedOther, paasPortLabel(p))
		}
	}
	exposed := append(append([]string{}, exposedWeb...), exposedOther...)
	r := Result{Subject: "container:" + c.Name, Evidence: map[string]any{
		"published": paasNonNil(published), "exposed": paasNonNil(exposed), "profile": string(prof),
	}}
	switch {
	case len(exposed) == 0:
		r.Level, r.Message = Pass, "proxy is published on loopback or private addresses only"
	case prof == profile.Tunnel || prof == profile.TailnetOnly:
		r.Level = Fail
		r.Message = fmt.Sprintf("proxy is published on all interfaces (%s) while ingress is meant to be %s only; the origin can be reached around it",
			strings.Join(exposed, ", "), prof)
	case len(exposedOther) > 0:
		r.Level = Warn
		r.Message = fmt.Sprintf("proxy publishes ports beyond 80 and 443 on all interfaces: %s", strings.Join(exposedOther, ", "))
	case prof == profile.PublicWeb:
		r.Level, r.Message = Pass, "proxy publishes only 80 and 443, as the public-web profile expects"
	default:
		r.Level = Unknown
		r.Message = fmt.Sprintf("proxy is published on all interfaces (%s); whether that is intended depends on the ingress profile (pass --profile)",
			strings.Join(exposedWeb, ", "))
	}
	return r
}

// Panel ports. Coolify: 8000 dashboard, 6001 realtime, 6002 terminal
// (https://coolify.io/docs/core/infrastructure/servers/firewall). Dokploy:
// 3000 (https://docs.dokploy.com/docs/core/manual-installation).
var paasPanelPorts = map[string][]int{
	facts.PlatformCoolify: {8000, 6001, 6002},
	facts.PlatformDokploy: {3000},
}

func checkPaaSPanelPorts(in Input) []Result {
	f := in.Facts
	if f.PaaS == nil {
		return []Result{NotInspected(f, "paas")}
	}
	containers, _ := paasContainers(f)
	platforms := paasPlatforms(f.PaaS, containers)
	var ports []int
	owner := map[int]string{}
	for _, pl := range platforms {
		if pl.Role == facts.RoleManaged {
			continue // managed servers run no panel
		}
		for _, p := range paasPanelPorts[pl.Name] {
			ports = append(ports, p)
			owner[p] = pl.Name
		}
	}
	if len(ports) == 0 {
		if len(platforms) == 0 {
			return One(Skip, "no Coolify or Dokploy installation found", nil)
		}
		return One(Skip, "no platform panel runs on this host", nil)
	}
	listeners, why := paasListeners(f)
	if why != nil {
		return []Result{*why}
	}
	sort.Ints(ports)
	var out []Result
	for _, port := range ports {
		out = append(out, paasJudgeHostPort(f, listeners, "tcp", port, true,
			fmt.Sprintf("%s panel port", owner[port]), Fail))
	}
	return out
}

// paasJudgeHostPort judges one port from the listener view. Not listening, or
// listening only on loopback, tailnet or private addresses, passes. A
// wildcard or public listener fails when the firewall does not filter it
// (failLevel), warns when it filters it or when that cannot be seen.
func paasJudgeHostPort(f *facts.Facts, ls []paasListener, proto string, port int, viaDocker bool, what string, failLevel Level) Result {
	subject := fmt.Sprintf("port:%s/%d", proto, port)
	var binds, exposed []string
	for _, l := range ls {
		if strings.TrimSuffix(l.Proto, "6") != proto || l.Port != port {
			continue
		}
		binds = append(binds, l.Addr)
		if paasExposed(l.Addr) {
			exposed = append(exposed, l.Addr)
		}
	}
	filter := readPaaSFilter(f.Firewall, proto, port, viaDocker)
	ev := map[string]any{"binds": paasNonNil(binds), "exposed": paasNonNil(exposed), "filter": string(filter)}
	r := Result{Subject: subject, Evidence: ev}
	switch {
	case len(binds) == 0:
		r.Level, r.Message = Pass, fmt.Sprintf("%s %d is not listening", what, port)
	case len(exposed) == 0:
		r.Level, r.Message = Pass, fmt.Sprintf("%s %d listens on loopback, tailnet or private addresses only", what, port)
	case filter == paasFilterNone:
		r.Level, r.Message = failLevel, fmt.Sprintf("%s %d listens on all interfaces and the firewall does not filter it", what, port)
	case filter == paasFilterApplied:
		r.Level, r.Message = Warn, fmt.Sprintf("%s %d listens on all interfaces behind a firewall filter; confirm from outside with probe", what, port)
	default:
		r.Level = Warn
		r.Message = fmt.Sprintf("%s %d listens on all interfaces and stackward could not tell whether the firewall filters it", what, port)
		if viaDocker {
			r.Message += " (Docker published ports bypass UFW)"
		}
	}
	return r
}

// paasDBImages are database images the platforms deploy (repository base
// names, matched with or without an org prefix).
var paasDBImages = []string{
	"postgres", "postgis", "mysql", "mariadb", "mongo", "redis", "valkey", "keydb",
	"dragonfly", "clickhouse-server", "clickhouse",
}

func paasIsDBImage(image string) bool {
	repo, _ := paasSplitImage(image)
	base := repo[strings.LastIndex(repo, "/")+1:]
	for _, db := range paasDBImages {
		if base == db || strings.HasPrefix(base, db+"-") {
			return true
		}
	}
	return false
}

// paasOwner reports which platform created a container, from its
// labels: coolify.* labels for Coolify, a swarm service label for Dokploy
// (it deploys databases as swarm services).
func paasOwner(c paasContainer, platforms []paasPlatform) string {
	for k := range c.Labels {
		if strings.HasPrefix(k, "coolify.") {
			return facts.PlatformCoolify
		}
	}
	if _, ok := c.Labels["com.docker.swarm.service.name"]; ok {
		for _, pl := range platforms {
			if pl.Name == facts.PlatformDokploy {
				return facts.PlatformDokploy
			}
		}
	}
	return ""
}

func checkPaaSPublicDatabase(in Input) []Result {
	f := in.Facts
	if f.PaaS == nil {
		return []Result{NotInspected(f, "paas")}
	}
	containers, why := paasContainers(f)
	platforms := paasPlatforms(f.PaaS, containers)
	if len(platforms) == 0 {
		return One(Skip, "no Coolify or Dokploy installation found", nil)
	}
	if why != nil {
		return []Result{*why}
	}
	var out []Result
	checked := 0
	for _, c := range containers {
		if !paasIsDBImage(c.Image) {
			continue
		}
		owner := paasOwner(c, platforms)
		if owner == "" {
			continue
		}
		checked++
		var exposed []string
		for _, p := range c.Ports {
			if paasExposed(p.HostIP) {
				exposed = append(exposed, paasPortLabel(p))
			}
		}
		if len(exposed) == 0 {
			continue
		}
		out = append(out, Result{
			Subject: "container:" + c.Name, Level: Fail,
			Message:  fmt.Sprintf("%s database published on all interfaces: %s", owner, strings.Join(exposed, ", ")),
			Evidence: map[string]any{"platform": owner, "image": c.Image, "exposed": exposed},
		})
	}
	if len(out) == 0 {
		return One(Pass, fmt.Sprintf("no platform database publishes a port publicly (%d checked)", checked),
			map[string]any{"checked": checked})
	}
	return out
}

// Docker Swarm ports: 2377/tcp management, 7946/tcp and udp node
// communication, 4789/udp overlay traffic
// (https://docs.docker.com/engine/swarm/swarm-tutorial/#open-protocols-and-ports-between-the-hosts).
var paasSwarmPorts = []struct {
	proto string
	port  int
}{{"tcp", 2377}, {"tcp", 7946}, {"udp", 4789}, {"udp", 7946}}

func checkPaaSSwarmPorts(in Input) []Result {
	f := in.Facts
	if f.PaaS == nil {
		return []Result{NotInspected(f, "paas")}
	}
	containers, _ := paasContainers(f)
	dokploy := false
	for _, pl := range paasPlatforms(f.PaaS, containers) {
		dokploy = dokploy || pl.Name == facts.PlatformDokploy
	}
	if !dokploy {
		return One(Skip, "Dokploy not found; Swarm ports are only judged on Dokploy hosts", nil)
	}
	listeners, why := paasListeners(f)
	if why != nil {
		return []Result{*why}
	}
	var out []Result
	for _, sp := range paasSwarmPorts {
		r := paasJudgeHostPort(f, listeners, sp.proto, sp.port, false, "swarm port", Fail)
		if r.Level == Warn && r.Evidence["filter"] == string(paasFilterApplied) {
			// Swarm ports are host sockets; an INPUT filter does apply.
			r.Level, r.Message = Pass, "swarm port "+strconv.Itoa(sp.port)+" listens on all interfaces behind a firewall filter"
		}
		out = append(out, r)
	}
	return out
}
