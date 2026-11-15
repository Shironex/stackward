package checks

import (
	"fmt"
	"sort"
	"strconv"
	"strings"

	"github.com/Shironex/stackward/internal/facts"
)

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
		var exposed, why []string
		level, undecided := Warn, false
		for _, p := range c.Ports {
			if !paasExposed(p.HostIP) {
				continue
			}
			label := paasPortLabel(p)
			exposed = append(exposed, label)
			proto := p.Proto
			if proto == "" {
				proto = "tcp"
			}
			open, _, reason := forwardFilter(f, f.Docker, proto, p.HostIP, p.HostPort, p.ContainerPort)
			why = append(why, label+": "+reason)
			switch open {
			case triYes:
				level = Fail
			case triUnknown:
				undecided = true
			}
		}
		if len(exposed) == 0 {
			continue
		}
		if undecided && level != Fail {
			level = Unknown
		}
		msg := fmt.Sprintf("%s database published on all interfaces: %s", owner, strings.Join(why, "; "))
		if level == Unknown {
			msg = fmt.Sprintf("%s database published on all interfaces and stackward could not tell what filters it: %s", owner, strings.Join(why, "; "))
		}
		if level == Warn {
			msg = fmt.Sprintf("%s database published on all interfaces behind a forward filter; turn off public access or confirm from outside with probe: %s", owner, strings.Join(why, "; "))
		}
		out = append(out, Result{
			Subject: "container:" + c.Name, Level: level, Message: msg,
			Evidence: map[string]any{"platform": owner, "image": c.Image, "exposed": exposed},
		})
	}
	if len(out) == 0 {
		return One(Pass, fmt.Sprintf("no platform database publishes a port publicly (%d checked)", checked),
			map[string]any{"checked": checked})
	}
	return out
}

// paasDefaultNetworks are the networks each platform attaches every app to
// unless the project gets its own destination: Coolify's "coolify"
// destination network and Dokploy's "dokploy-network".
var paasDefaultNetworks = map[string]string{
	facts.PlatformCoolify: "coolify",
	facts.PlatformDokploy: "dokploy-network",
}

// isPaaSInternal is the platform's own container (panel, its database
// and cache, realtime, sentinel), which shares the default network by
// design.
func isPaaSInternal(c paasContainer) bool {
	repo, _ := paasSplitImage(c.Image)
	return strings.HasPrefix(c.Name, "coolify") && c.Labels["coolify.managed"] != "true" ||
		strings.HasPrefix(c.Name, "dokploy") || strings.HasPrefix(repo, "coollabsio/") || repo == "dokploy/dokploy"
}

// PAAS-005: apps of different projects should not share the platform's
// default network (DKR-030 judges every network; this names the platform
// setting behind it).
func checkPaaSDefaultNetwork(in Input) []Result {
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
	level := Pass
	var parts []string
	ev := map[string]any{"networks": []string{}, "projects": []string{}}
	var nets, allProjects []string
	for _, pl := range platforms {
		network := paasDefaultNetworks[pl.Name]
		seen := map[string]bool{}
		var projects []string
		for _, c := range containers {
			if !paasContains(c.Networks, network) || isPaaSProxy(c) || isPaaSInternal(c) || paasOwner(c, platforms) != pl.Name {
				continue
			}
			key := c.Project
			if key == "" {
				key = c.Name
			}
			if !seen[key] {
				seen[key] = true
				projects = append(projects, key)
			}
		}
		sort.Strings(projects)
		nets = append(nets, network)
		allProjects = append(allProjects, projects...)
		if len(projects) > 1 {
			level = Warn
			parts = append(parts, fmt.Sprintf("%d %s projects share the %s network (%s)", len(projects), pl.Name, network, strings.Join(capList(projects), ", ")))
		} else {
			parts = append(parts, fmt.Sprintf("%s network %s holds apps of %d project(s)", pl.Name, network, len(projects)))
		}
	}
	ev["networks"], ev["projects"] = nets, capList(allProjects)
	if level == Warn {
		return One(Warn, strings.Join(parts, "; ")+": any app can reach the others' services by name", ev)
	}
	return One(Pass, strings.Join(parts, "; "), ev)
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
