package checks

import (
	"fmt"
	"sort"
	"strings"

	"github.com/Shironex/stackward/internal/facts"
	"github.com/Shironex/stackward/internal/profile"
)

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
		// Without containers, judge the web ports from the listeners: on a
		// platform host 80 and 443 belong to the platform proxy.
		proxy, lwhy := paasProxyFromListeners(f)
		if lwhy != nil {
			return []Result{*why}
		}
		return []Result{paasJudgeProxy(f, proxy, "host", in.Profile, paasTunnelRuns(f))}
	}
	var out []Result
	for _, c := range containers {
		if !isPaaSProxy(c) {
			continue
		}
		out = append(out, paasJudgeProxy(f, c, "container:"+c.Name, in.Profile, paasTunnelRuns(f)))
	}
	if len(out) == 0 {
		return One(Skip, "no platform proxy container found", nil)
	}
	return out
}

// paasProxyFromListeners builds a proxy view from the TCP 80 and 443
// listeners.
func paasProxyFromListeners(f *facts.Facts) (paasContainer, *Result) {
	ls, why := paasListeners(f)
	if why != nil {
		return paasContainer{}, why
	}
	c := paasContainer{Name: "proxy"}
	for _, l := range ls {
		if strings.TrimSuffix(l.Proto, "6") == "tcp" && (l.Port == 80 || l.Port == 443) {
			c.Ports = append(c.Ports, paasPort{HostIP: l.Addr, HostPort: l.Port, ContainerPort: l.Port, Proto: "tcp"})
		}
	}
	return c, nil
}

// paasTunnelRuns reports whether a Cloudflare Tunnel connector is known to
// run on the host.
func paasTunnelRuns(f *facts.Facts) bool {
	present, known := profile.TunnelState(f)
	return present && known
}

// paasJudgeProxy judges the proxy's published ports. A binding on all
// interfaces only counts as exposed when the forward filter lets a
// connection through from any source (the judgement DKR-001 uses); one the
// filter drops is a warning to bind to loopback, and one whose filtering
// cannot be read is unknown.
func paasJudgeProxy(f *facts.Facts, c paasContainer, subject string, prof profile.Name, tunnel bool) Result {
	d := f.Docker
	if d == nil {
		d = &facts.Docker{}
	}
	var published, exposedWeb, exposedOther, filtered, undecided, why []string
	for _, p := range c.Ports {
		published = append(published, paasPortLabel(p))
		if !paasExposed(p.HostIP) {
			continue
		}
		label := paasPortLabel(p)
		proto := p.Proto
		if proto == "" {
			proto = "tcp"
		}
		open, _, reason := forwardFilter(f, d, proto, p.HostIP, p.HostPort, p.ContainerPort)
		switch open {
		case triNo:
			filtered = append(filtered, label)
			continue
		case triUnknown:
			undecided = append(undecided, label)
			why = append(why, label+": "+reason)
			continue
		}
		if p.HostPort == 80 || p.HostPort == 443 {
			exposedWeb = append(exposedWeb, label)
		} else {
			exposedOther = append(exposedOther, label)
		}
	}
	exposed := append(append([]string{}, exposedWeb...), exposedOther...)
	r := Result{Subject: subject, Evidence: map[string]any{
		"published": paasNonNil(published), "exposed": paasNonNil(exposed), "profile": string(prof),
	}}
	if len(filtered) > 0 {
		r.Evidence["filtered"] = filtered
	}
	if len(undecided) > 0 {
		r.Evidence["unknown"] = undecided
	}
	switch {
	case len(published) == 0:
		r.Level, r.Message = Pass, "nothing listens on 80 or 443"
	case len(exposed) == 0 && len(undecided) > 0:
		r.Level = Unknown
		r.Message = fmt.Sprintf("proxy is published on all interfaces (%s) and stackward could not tell what filters it: %s",
			strings.Join(undecided, ", "), strings.Join(why, "; "))
	case len(exposed) == 0 && len(filtered) > 0:
		r.Level = Warn
		r.Message = fmt.Sprintf("proxy is published on all interfaces (%s) but filtered by the forward filter (ufw-docker or DOCKER-USER) today; bind to 127.0.0.1 so a firewall change cannot expose it",
			strings.Join(filtered, ", "))
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
	case prof == profile.PaaSPanel && tunnel:
		r.Level = Info
		r.Message = fmt.Sprintf("proxy publishes only 80 and 443 (%s), as a panel host does; a tunnel runs as well, so if the tunnel is meant to be the only way in, publish the proxy on 127.0.0.1 and pass --profile tunnel",
			strings.Join(exposedWeb, ", "))
	case prof == profile.PaaSPanel:
		r.Level, r.Message = Pass, "proxy publishes only 80 and 443, as the paas-panel profile expects"
	case prof == profile.Mixed:
		r.Level = Warn
		r.Message = fmt.Sprintf("a tunnel runs and the proxy is also published on all interfaces (%s); if the tunnel is meant to be the only way in, publish the proxy on 127.0.0.1",
			strings.Join(exposedWeb, ", "))
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
	// A visible process name settles whether Docker published the port:
	// docker-proxy, or dockerd (no userland proxy, or the nftables
	// backend) while a container publishes that address and port.
	for _, l := range ls {
		if strings.TrimSuffix(l.Proto, "6") == proto && l.Port == port && l.Process != "" {
			sock := facts.Listener{Proto: proto, Address: l.Addr, Port: l.Port, Processes: strings.Split(l.Process, ",")}
			viaDocker = sock.PublishedByContainer(f.Docker)
			break
		}
	}
	filter := readPaaSFilter(f.Firewall, proto, port, viaDocker)
	if viaDocker && f.Firewall != nil && f.Listeners != nil && f.Docker != nil &&
		(ufwDockerChainOf(f) != nil || paasForwardBackend(f)) {
		filter = paasDockerFilter(f, proto, port)
	}
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
