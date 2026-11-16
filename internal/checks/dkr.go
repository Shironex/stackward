package checks

import (
	"fmt"
	"path"
	"sort"
	"strings"

	"github.com/Shironex/stackward/internal/facts"
)

// DKR checks read what the docker collector gathers (facts/docker.go).
// Without access to the Docker socket every DKR check is unknown, never a
// pass. DKR-002 and DKR-003 may still fail on evidence from files (a TCP
// host in the daemon config, a listening port from the listener facts, a
// world writable socket), because hiding those behind "unknown" would hide
// the worst findings.

const dockerCollector = "docker"

func init() {
	Register(Check{ID: "DKR-002", Run: checkDaemonTCP})
	Register(Check{ID: "DKR-003", Run: checkSocketMode})
	Register(Check{ID: "DKR-010", Run: checkSocketMounted})
	Register(Check{ID: "DKR-011", Run: checkSocketProxyFlags})
	Register(Check{ID: "DKR-012", Run: checkHostBinds})
	Register(Check{ID: "DKR-020", Run: checkContainerRoot})
	Register(Check{ID: "DKR-021", Run: checkPrivileged})
	Register(Check{ID: "DKR-022", Run: checkCapAdd})
	Register(Check{ID: "DKR-023", Run: checkHostNamespaces})
	Register(Check{ID: "DKR-024", Run: checkSecurityOpt})
	Register(Check{ID: "DKR-030", Run: checkSharedNetworks})
	Register(Check{ID: "DKR-031", Run: checkLogRotation})
	Register(Check{ID: "DKR-032", Run: checkInfraTags})
	Register(Check{ID: "DKR-033", Run: checkIPTables})
	Register(Check{ID: "DKR-034", Run: checkEngineSupport})
}

// dockerFacts returns the Docker facts, or the results to return instead:
// unknown when not inspected, skip when Docker is not installed. When
// needAPI is set, a socket stackward could not read is unknown too.
func dockerFacts(in Input, needAPI bool) (*facts.Docker, []Result) {
	d := in.Facts.Docker
	if d == nil {
		return nil, []Result{NotInspected(in.Facts, dockerCollector)}
	}
	if !d.Installed {
		return nil, One(Skip, "Docker is not installed", map[string]any{"installed": false})
	}
	if needAPI && d.API != "ok" {
		return nil, apiUnknown(d)
	}
	return d, nil
}

func apiUnknown(d *facts.Docker) []Result {
	reason := d.APIReason
	if reason == "" {
		reason = "the Docker API was not read"
	}
	return One(Unknown, "not inspected: "+reason, map[string]any{"api": d.API, "socket": d.SocketPath})
}

// levelRank orders levels for "worst wins" merges.
var levelRank = map[Level]int{Fail: 5, Warn: 4, Unknown: 3, Info: 2, Pass: 1, Skip: 0}

func worse(a, b Level) Level {
	if levelRank[b] > levelRank[a] {
		return b
	}
	return a
}

// containerSubject is container:<project>/<service> for grouped
// containers and container:<name> for plain ones.
func containerSubject(c facts.DockerContainer) string {
	if c.Project != "" {
		return "container:" + c.Project + "/" + c.Service
	}
	return "container:" + c.Name
}

// eachContainer runs fn over every container and returns one result per
// subject: replicas of one compose service share a subject, and the worst
// result among them wins.
func eachContainer(in Input, fn func(d *facts.Docker, c facts.DockerContainer) Result) []Result {
	return eachContainerWhere(in, nil, fn)
}

// eachContainerWhere is eachContainer over the containers keep accepts
// (all of them when keep is nil).
func eachContainerWhere(in Input, keep func(facts.DockerContainer) bool, fn func(d *facts.Docker, c facts.DockerContainer) Result) []Result {
	d, early := dockerFacts(in, true)
	if early != nil {
		return early
	}
	if len(d.Containers) == 0 && !d.ContainersTruncated {
		return One(Pass, "no containers on this host", map[string]any{"containers": 0})
	}
	bySubject := map[string]Result{}
	count := map[string]int{}
	var order []string
	for _, c := range d.Containers {
		if keep != nil && !keep(c) {
			continue
		}
		r := fn(d, c)
		if r.Subject == "" {
			r.Subject = containerSubject(c)
		}
		prev, seen := bySubject[r.Subject]
		count[r.Subject]++
		if !seen {
			order = append(order, r.Subject)
			bySubject[r.Subject] = r
			continue
		}
		if levelRank[r.Level] > levelRank[prev.Level] {
			bySubject[r.Subject] = r
		}
	}
	out := make([]Result, 0, len(order)+1)
	for _, s := range order {
		r := bySubject[s]
		if n := count[s]; n > 1 {
			r.Message = fmt.Sprintf("%s (worst of %d replicas)", r.Message, n)
		}
		out = append(out, r)
	}
	if d.ContainersTruncated {
		out = append(out, Result{Level: Unknown, Message: "more containers exist than stackward inspects; the rest were not checked",
			Evidence: map[string]any{"inspected": len(d.Containers)}})
	}
	return out
}

func stateWord(c facts.DockerContainer) string {
	if c.Running {
		return ""
	}
	return " (stopped)"
}

// imageRef splits an image reference into repository, tag and digest.
// The repository is lower case and keeps its registry and path.
func imageRef(ref string) (repo, tag, digest string) {
	ref = strings.ToLower(strings.TrimSpace(ref))
	ref, digest, _ = strings.Cut(ref, "@")
	if i := strings.LastIndex(ref, ":"); i > strings.LastIndex(ref, "/") {
		ref, tag = ref[:i], ref[i+1:]
	}
	return ref, tag, digest
}

func imageBase(ref string) string {
	repo, _, _ := imageRef(ref)
	return path.Base(repo)
}

// Container roles, decided from the image and the name.
const (
	roleSocketProxy = "socket-proxy"
	roleProxy       = "proxy"
	rolePaaS        = "paas"
	roleTunnel      = "tunnel"
	roleCrowdSec    = "crowdsec"
	roleDatabase    = "database"
)

var (
	proxyImages = map[string]bool{"traefik": true, "caddy": true, "nginx-proxy": true, "caddy-docker-proxy": true, "nginx-proxy-manager": true}
	proxyNames  = map[string]bool{"coolify-proxy": true, "dokploy-traefik": true}
	paasNames   = map[string]bool{"coolify": true, "coolify-sentinel": true, "coolify-realtime": true, "dokploy": true}
	// databaseImages are image name prefixes of database servers.
	databaseImages = []string{"postgres", "postgis", "timescaledb", "mysql", "mariadb", "mongo", "redis", "valkey", "keydb", "clickhouse"}
)

func roleOf(c facts.DockerContainer) string {
	repo, _, _ := imageRef(c.Image)
	base := path.Base(repo)
	name := strings.ToLower(c.Name)
	switch {
	case strings.Contains(repo, "socket-proxy"):
		return roleSocketProxy
	case proxyImages[base] || proxyNames[name] || c.Labels["coolify.proxy"] == "true":
		return roleProxy
	case strings.Contains(repo, "coollabsio/coolify") || strings.Contains(repo, "coollabsio/sentinel") || base == "dokploy" || paasNames[name]:
		return rolePaaS
	case base == "cloudflared":
		return roleTunnel
	case base == "crowdsec":
		return roleCrowdSec
	case isDatabaseImage(c.Image):
		return roleDatabase
	}
	return ""
}

func isDatabaseImage(img string) bool {
	base := imageBase(img)
	for _, p := range databaseImages {
		if strings.HasPrefix(base, p) {
			return true
		}
	}
	return strings.Contains(base, "clickhouse")
}

// isRootUser reads a user[:group] value as Docker does: only the user part
// decides; empty, "root" and any all zero uid are root.
func isRootUser(u string) bool {
	user, _, _ := strings.Cut(u, ":")
	user = strings.TrimSpace(user)
	return user == "" || user == "root" || strings.Trim(user, "0") == ""
}

func isWildcardIP(ip string) bool {
	ip = strings.TrimSpace(ip)
	return ip == "" || ip == "0.0.0.0" || ip == "::"
}

// isPublic is true when a container publishes a port on every interface
// or a reverse proxy routes to it.
func isPublic(c facts.DockerContainer) bool {
	if c.ProxyRouted {
		return true
	}
	for _, p := range c.Ports {
		if isWildcardIP(p.HostIP) {
			return true
		}
	}
	return false
}

func mountText(m facts.DockerMount) string {
	s := m.Source + ":" + m.Target
	if m.ReadOnly {
		s += ":ro"
	}
	return s
}

// notSharedNetworks are networks that do not join projects: none, the
// host's own, and the default bridge (no name resolution between
// containers; stackward judges user networks only).
var notSharedNetworks = map[string]bool{"none": true, "host": true, "bridge": true}

// projectKey groups containers into projects. A platform's own containers
// (the Coolify panel stack, its proxy and sentinel; Dokploy's services)
// form one platform project, whatever compose project each carries.
func projectKey(c facts.DockerContainer) string {
	if p := platformOf(c); p != "" {
		return "platform:" + p
	}
	if c.Project != "" {
		return "project:" + c.Project
	}
	return "container:" + c.Name
}

func peerName(c facts.DockerContainer) string {
	return strings.TrimPrefix(containerSubject(c), "container:")
}

// maxPeers caps the peer lists in DKR-030 evidence.
const maxPeers = 20

// DKR-030: containers of different projects should not share a network,
// and never with a database.
func checkSharedNetworks(in Input) []Result {
	d, early := dockerFacts(in, true)
	if early != nil {
		return early
	}
	members := networkMembers(d)
	return eachContainer(in, func(_ *facts.Docker, c facts.DockerContainer) Result {
		ev := map[string]any{"project": c.Project, "networks": []string{}, "peers": []string{}, "database_peers": []string{}}
		switch {
		case roleOf(c) == roleProxy:
			return Result{Level: Skip, Message: c.Name + " is a reverse proxy; it joins project networks by design", Evidence: ev}
		case c.NetworkMode == "host":
			return Result{Level: Skip, Message: c.Name + " uses the host network (see DKR-023)", Evidence: ev}
		case strings.HasPrefix(c.NetworkMode, "container:"):
			return Result{Level: Skip, Message: c.Name + " shares the network of another container", Evidence: ev}
		}
		selfDB := roleOf(c) == roleDatabase
		shared, peers, dbPeers := foreignPeers(c, members)
		ev["networks"] = nonNil(shared)
		ev["peers"] = capList(peers)
		ev["database_peers"] = capList(dbPeers)
		switch {
		case len(peers) == 0:
			return Result{Level: Pass, Message: c.Name + " shares no network with another project", Evidence: ev}
		case len(dbPeers) > 0:
			return Result{Level: Fail, Message: fmt.Sprintf("%s shares %s with database %s of another project", c.Name, strings.Join(shared, ", "), strings.Join(capList(dbPeers), ", ")), Evidence: ev}
		case selfDB:
			return Result{Level: Fail, Message: fmt.Sprintf("database %s shares %s with %s of another project", c.Name, strings.Join(shared, ", "), strings.Join(capList(peers), ", ")), Evidence: ev}
		}
		return Result{Level: Warn, Message: fmt.Sprintf("%s shares %s with %s of another project", c.Name, strings.Join(shared, ", "), strings.Join(capList(peers), ", ")), Evidence: ev}
	})
}

// networkMembers lists the containers on each shared network, leaving out
// the reverse proxy, which joins every project network by design.
func networkMembers(d *facts.Docker) map[string][]facts.DockerContainer {
	members := map[string][]facts.DockerContainer{}
	for _, c := range d.Containers {
		if roleOf(c) == roleProxy {
			continue
		}
		for _, n := range c.Networks {
			if !notSharedNetworks[n] {
				members[n] = append(members[n], c)
			}
		}
	}
	return members
}

// foreignPeers returns the networks c shares with another project, the
// names of those peers, and which of them are databases; both name lists
// are sorted.
func foreignPeers(c facts.DockerContainer, members map[string][]facts.DockerContainer) (shared, peers, dbPeers []string) {
	self := projectKey(c)
	seen := map[string]bool{}
	for _, n := range c.Networks {
		if notSharedNetworks[n] {
			continue
		}
		found := false
		for _, o := range members[n] {
			if projectKey(o) == self {
				continue
			}
			found = true
			p := peerName(o)
			if seen[p] {
				continue
			}
			seen[p] = true
			peers = append(peers, p)
			if roleOf(o) == roleDatabase {
				dbPeers = append(dbPeers, p)
			}
		}
		if found {
			shared = append(shared, n)
		}
	}
	sort.Strings(peers)
	sort.Strings(dbPeers)
	return shared, peers, dbPeers
}

func capList(s []string) []string {
	if len(s) > maxPeers {
		return append(append([]string{}, s[:maxPeers]...), fmt.Sprintf("and %d more", len(s)-maxPeers))
	}
	return nonNil(s)
}
