package checks

import (
	"fmt"
	"path"
	"sort"
	"strconv"
	"strings"
	"time"

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

// DKR-002: the daemon must not listen on TCP without TLS client checks.
//
// A listener on 2375 or 2376 is not always the daemon's API: docker-proxy
// holds the port when a container publishes it, typically a Docker socket
// proxy on 127.0.0.1, and dockerd itself holds it when Docker runs without
// the userland proxy or on its nftables firewall backend. Whenever the
// Docker facts show a container publishing that address and port, the
// listener is that container's port, judged by what the container hands
// out, whatever the owner's name.
func checkDaemonTCP(in Input) []Result {
	d, early := dockerFacts(in, false)
	if early != nil {
		return early
	}
	dd := d.Daemon
	if dd == nil {
		dd = &facts.DockerDaemon{}
	}
	hosts := []string{}
	for _, h := range dd.Hosts {
		if strings.HasPrefix(strings.ToLower(h.Addr), "tcp://") {
			hosts = append(hosts, h.Addr)
		}
	}
	ports, tcpKnown := dockerPortListenersOwned(in.Facts, d)
	listeners := []string{}
	var daemonPorts, maybePublished []string
	var published []dockerAPIPort
	// dockerd holding a port that no tcp host in a fully read daemon
	// config asks for is most likely a published container port; without
	// the Docker API stackward cannot tell which.
	configSaysNoTCP := d.Daemon != nil && dd.ConfigError == "" && len(hosts) == 0 && d.API != "ok"
	for _, p := range ports {
		listeners = append(listeners, p.label())
		switch {
		case p.container:
			published = append(published, p)
		case p.dockerd && configSaysNoTCP:
			maybePublished = append(maybePublished, p.label())
		default:
			daemonPorts = append(daemonPorts, p.label())
		}
	}
	ev := map[string]any{"tcp_hosts": hosts, "listeners": listeners, "tlsverify": dd.TLSVerify, "published_by": []string{}}
	if !dd.TLSVerify && (len(hosts) > 0 || len(daemonPorts) > 0) {
		what := strings.Join(append(append([]string{}, hosts...), daemonPorts...), ", ")
		who := "anyone who reaches it is root"
		if len(hosts) == 0 && allLoopback(daemonPorts) {
			who = "it listens on loopback only, but every local user and every container that can reach the host's loopback is root"
		}
		return One(Fail, "Docker API on TCP without tlsverify ("+what+"): "+who, ev)
	}
	if len(published) > 0 {
		return []Result{judgePublishedAPIPorts(d, published, ev)}
	}
	if len(maybePublished) > 0 {
		return One(Unknown, fmt.Sprintf(
			"dockerd holds %s, but neither daemon.json nor the docker.service unit asks it to listen on TCP: most likely a container port published by dockerd (no userland proxy, or the nftables backend); which container it is needs the Docker API (%s)",
			strings.Join(maybePublished, ", "), valueOrUnknown(d.APIReason)), ev)
	}
	if d.API != "ok" {
		return apiUnknown(d)
	}
	if d.Daemon == nil || dd.ConfigError != "" || !tcpKnown {
		return One(Unknown, "could not read the daemon config and the listening sockets to rule out a TCP listener", ev)
	}
	if len(hosts) > 0 || len(daemonPorts) > 0 {
		return One(Pass, "Docker API on TCP requires TLS client certificates (tlsverify)", ev)
	}
	return One(Pass, "Docker API listens only on the Unix socket", ev)
}

func allLoopback(labels []string) bool {
	for _, l := range labels {
		if !strings.HasSuffix(l, "/loopback") {
			return false
		}
	}
	return len(labels) > 0
}

// dockerAPIPort is one listener on a Docker API port.
type dockerAPIPort struct {
	port int
	bind string // "loopback", "any" or "specific"
	// container is true when docker-proxy holds it or a container
	// publishes the port: a published container port, not the daemon's
	// API.
	container bool
	// dockerd is true when dockerd is the only owner named.
	dockerd bool
}

func (p dockerAPIPort) label() string { return fmt.Sprintf("%d/%s", p.port, p.bind) }

// judgePublishedAPIPorts judges container ports published on 2375 or 2376
// by the container behind them: a socket proxy hands out what its
// permission flags allow; any other container that mounts the socket is a
// raw proxy of the daemon.
func judgePublishedAPIPorts(d *facts.Docker, ports []dockerAPIPort, ev map[string]any) Result {
	if d.API != "ok" {
		return Result{Level: Unknown, Evidence: ev, Message: fmt.Sprintf(
			"a container publishes the Docker API port (%s) through docker-proxy; which container it is needs the Docker API (%s)",
			portLabels(ports), valueOrUnknown(d.APIReason))}
	}
	level := Info
	var msgs, by []string
	for _, p := range ports {
		owners := containersPublishing(d, p.port)
		if len(owners) == 0 {
			level = worse(level, Unknown)
			msgs = append(msgs, fmt.Sprintf("%s is held by docker-proxy, but no inspected container publishes it", p.label()))
			continue
		}
		for _, c := range owners {
			by = append(by, fmt.Sprintf("%s (%s)", c.Name, c.Image))
			l, m := judgeAPIPublisher(c, p)
			level = worse(level, l)
			msgs = append(msgs, m)
		}
	}
	ev["published_by"] = by
	return Result{Level: level, Message: strings.Join(msgs, "; "), Evidence: ev}
}

func judgeAPIPublisher(c facts.DockerContainer, p dockerAPIPort) (Level, string) {
	where := "on loopback"
	if p.bind != "loopback" {
		where = "beyond loopback (" + p.bind + ")"
	}
	head := fmt.Sprintf("%d is published %s by container %s (%s), not by dockerd", p.port, where, c.Name, c.Image)
	if roleOf(c) == roleSocketProxy {
		enabled, writes := socketProxyGrants(c)
		grants := "it allows " + strings.Join(enabled, ", ")
		if len(enabled) == 0 {
			grants = "its permission flags were not read"
		}
		switch {
		case p.bind != "loopback":
			return Fail, head + ": a socket proxy reachable from other hosts hands the Docker API to anyone who reaches it; " + grants
		case len(writes) > 0:
			return Warn, head + ": a socket proxy that allows " + strings.Join(writes, " and ") + " lets any local process change containers; " + grants
		}
		return Info, head + ": a socket proxy on loopback; " + grants + " (see DKR-011)"
	}
	if facts.MountsDockerSocket(c.Mounts) {
		if p.bind != "loopback" {
			return Fail, head + ", and it mounts the Docker socket: anyone who reaches it is likely root"
		}
		return Warn, head + ", and it mounts the Docker socket: every local process that reaches it is likely root"
	}
	return Info, head + "; it does not mount the Docker socket"
}

// socketProxyGrants lists a socket proxy's enabled permission flags and
// the write flags among them.
func socketProxyGrants(c facts.DockerContainer) (enabled, writes []string) {
	for k, v := range c.Flags {
		if truthy(v) {
			enabled = append(enabled, k)
		}
	}
	sort.Strings(enabled)
	for _, k := range socketProxyWriteFlags {
		if truthy(c.Flags[k]) {
			writes = append(writes, k)
		}
	}
	return enabled, writes
}

func containersPublishing(d *facts.Docker, port int) []facts.DockerContainer {
	var out []facts.DockerContainer
	for _, c := range d.Containers {
		for _, p := range c.Ports {
			if p.HostPort == port && (p.Proto == "" || p.Proto == "tcp") {
				out = append(out, c)
				break
			}
		}
	}
	return out
}

func portLabels(ps []dockerAPIPort) string {
	var out []string
	for _, p := range ps {
		out = append(out, p.label())
	}
	return strings.Join(out, ", ")
}

// dockerPortListenersOwned is dockerPortListeners with the owner of each
// port: docker-proxy, or a container the Docker API lists publishing the
// address and port (whether dockerd or no named process holds it), marks a
// published container port.
func dockerPortListenersOwned(f *facts.Facts, d *facts.Docker) (out []dockerAPIPort, known bool) {
	if l := f.Listeners; l != nil {
		idx := map[string]int{}
		for _, s := range l.Sockets {
			if s.Proto != "tcp" || !dockerAPIPorts[s.Port] {
				continue
			}
			p := dockerAPIPort{port: s.Port, bind: bindWord(s.Class())}
			p.container = s.PublishedByContainer(d)
			p.dockerd = len(s.Processes) > 0 && !p.container && onlyProcess(s, "dockerd")
			if i, ok := idx[p.label()]; ok {
				out[i].container = out[i].container && p.container
				out[i].dockerd = out[i].dockerd && p.dockerd
				continue
			}
			idx[p.label()] = len(out)
			out = append(out, p)
		}
		sort.Slice(out, func(i, j int) bool { return out[i].label() < out[j].label() })
		return out, true
	}
	for _, t := range d.TCP {
		out = append(out, dockerAPIPort{port: t.Port, bind: t.Bind})
	}
	return out, d.TCPRead
}

// onlyProcess reports whether every process named for the socket is name.
func onlyProcess(s facts.Listener, name string) bool {
	for _, p := range s.Processes {
		if p != name {
			return false
		}
	}
	return true
}

func bindWord(c facts.BindClass) string {
	switch c {
	case facts.BindLoopback:
		return "loopback"
	case facts.BindWildcard:
		return "any"
	}
	return "specific"
}

// dockerAPIPorts are the ports the Docker daemon uses for its TCP API.
var dockerAPIPorts = map[int]bool{2375: true, 2376: true}

// DKR-003: the socket must not be world writable.
func checkSocketMode(in Input) []Result {
	d, early := dockerFacts(in, false)
	if early != nil {
		return early
	}
	s := d.Socket
	if s == nil {
		return One(Unknown, "no Docker socket found at "+d.SocketPath, map[string]any{"path": d.SocketPath})
	}
	ev := map[string]any{"path": d.SocketPath, "perm": s.Perm, "uid": s.UID, "gid": s.GID, "group": s.Group}
	if s.WorldWritable {
		return One(Fail, fmt.Sprintf("%s is world writable (%s): every local user is root", d.SocketPath, s.Perm), ev)
	}
	if d.API != "ok" {
		return apiUnknown(d)
	}
	return One(Pass, fmt.Sprintf("%s is not world writable (%s)", d.SocketPath, s.Perm), ev)
}

// DKR-010: no container gets the Docker socket or a folder holding it.
func checkSocketMounted(in Input) []Result {
	return eachContainer(in, posture(in, func(_ *facts.Docker, c facts.DockerContainer) Result {
		var socket, what []string
		readOnly := false
		for _, m := range c.Mounts {
			if m.Type == "bind" && facts.IsDockerSocketPath(m.Source) {
				socket = append(socket, mountText(m))
				what = append(what, socketMountText(m))
				readOnly = readOnly || m.ReadOnly
			}
		}
		roNote := ""
		if readOnly {
			roNote = "; a read only mount does not stop connecting to a socket"
		}
		role := roleOf(c)
		ev := map[string]any{"container": c.Name, "image": c.Image, "role": role, "socket_mounts": socket, "running": c.Running}
		if len(socket) == 0 {
			return Result{Level: Pass, Message: c.Name + " does not mount the Docker socket", Evidence: ev}
		}
		switch role {
		case roleProxy, rolePaaS, roleSocketProxy:
			return Result{Level: Warn, Message: fmt.Sprintf("%s mounts %s; expected for a %s, but it is root on the host if compromised%s%s",
				c.Name, strings.Join(what, ", "), role, roNote, stateWord(c)), Evidence: ev}
		}
		return Result{Level: Fail, Message: fmt.Sprintf("%s mounts %s: the container controls the host%s%s",
			c.Name, strings.Join(what, ", "), roNote, stateWord(c)), Evidence: ev}
	}))
}

// risky socket proxy flags: POST enables every write, EXEC runs commands.
var socketProxyWriteFlags = []string{"POST", "EXEC"}

func truthy(v string) bool { return v == "1" || v == "true" || v == "yes" }

// DKR-011: a socket proxy must not allow writes.
func checkSocketProxyFlags(in Input) []Result {
	d, early := dockerFacts(in, true)
	if early != nil {
		return early
	}
	var proxies []facts.DockerContainer
	for _, c := range d.Containers {
		if roleOf(c) == roleSocketProxy {
			proxies = append(proxies, c)
		}
	}
	if len(proxies) == 0 {
		return One(Skip, "no Docker socket proxy container found", map[string]any{"socket_proxies": 0})
	}
	isProxy := func(c facts.DockerContainer) bool { return roleOf(c) == roleSocketProxy }
	return eachContainerWhere(in, isProxy, func(_ *facts.Docker, c facts.DockerContainer) Result {
		enabled, writes := socketProxyGrants(c)
		ev := map[string]any{"container": c.Name, "image": c.Image, "enabled": nonNil(enabled), "flags_read": len(c.Flags) > 0}
		if len(writes) > 0 {
			return Result{Level: Warn, Message: fmt.Sprintf("socket proxy %s allows %s", c.Name, strings.Join(writes, " and ")), Evidence: ev}
		}
		if len(c.Flags) == 0 && strings.Contains(c.Image, "wollomatic") {
			return Result{Level: Unknown, Message: "socket proxy " + c.Name + " is configured on its command line, which stackward does not read", Evidence: ev}
		}
		return Result{Level: Pass, Message: "socket proxy " + c.Name + " allows neither POST nor EXEC", Evidence: ev}
	})
}

// sensitiveHostPaths are host paths whose bind mount hands a container the
// host's identity, credentials or kernel interfaces.
var sensitiveHostPaths = map[string]bool{"/": true, "/etc": true, "/root": true, "/home": true, "/proc": true, "/sys": true}

// DKR-012: no bind mount of /, /etc, /root, /home, /proc or /sys.
func checkHostBinds(in Input) []Result {
	return eachContainer(in, posture(in, func(_ *facts.Docker, c facts.DockerContainer) Result {
		var rw, ro []string
		for _, m := range c.Mounts {
			if m.Type != "bind" || m.Source == "" || !sensitiveHostPaths[path.Clean(m.Source)] {
				continue
			}
			if m.ReadOnly {
				ro = append(ro, mountText(m))
			} else {
				rw = append(rw, mountText(m))
			}
		}
		ev := map[string]any{"container": c.Name, "writable": nonNil(rw), "read_only": nonNil(ro)}
		switch {
		case len(rw) > 0:
			return Result{Level: Fail, Message: fmt.Sprintf("%s mounts host %s writable%s", c.Name, strings.Join(rw, ", "), stateWord(c)), Evidence: ev}
		case len(ro) > 0:
			return Result{Level: Warn, Message: fmt.Sprintf("%s mounts host %s read only%s", c.Name, strings.Join(ro, ", "), stateWord(c)), Evidence: ev}
		}
		return Result{Level: Pass, Message: c.Name + " mounts no sensitive host path", Evidence: ev}
	}))
}

// DKR-020: containers should not run as root.
func checkContainerRoot(in Input) []Result {
	return eachContainer(in, posture(in, func(_ *facts.Docker, c facts.DockerContainer) Result {
		root := isRootUser(c.User)
		pub := isPublic(c)
		drops := ""
		if root && c.User == "" {
			drops = dropsTo(c.Image)
		}
		ev := map[string]any{"container": c.Name, "user": c.User, "root": root, "privileged": c.Privileged, "public": pub, "entrypoint_drops_to": drops}
		if !root {
			return Result{Level: Pass, Message: fmt.Sprintf("%s runs as %q", c.Name, c.User), Evidence: ev}
		}
		who := "root"
		if c.User != "" {
			who = fmt.Sprintf("root (%q)", c.User)
		}
		switch {
		case c.Privileged:
			return Result{Level: Fail, Message: fmt.Sprintf("%s runs as %s and privileged%s", c.Name, who, stateWord(c)), Evidence: ev}
		case pub:
			return Result{Level: Fail, Message: fmt.Sprintf("%s runs as %s and is reachable from outside%s", c.Name, who, stateWord(c)), Evidence: ev}
		case drops != "":
			return Result{Level: Info, Message: fmt.Sprintf("%s starts as root, and the %s image entrypoint drops to the %s user; set user: to make it explicit%s",
				c.Name, imageBase(c.Image), drops, stateWord(c)), Evidence: ev}
		}
		return Result{Level: Warn, Message: fmt.Sprintf("%s runs as %s%s", c.Name, who, stateWord(c)), Evidence: ev}
	}))
}

// DKR-021: no privileged containers.
func checkPrivileged(in Input) []Result {
	return eachContainer(in, posture(in, func(_ *facts.Docker, c facts.DockerContainer) Result {
		ev := map[string]any{"container": c.Name, "privileged": c.Privileged}
		if c.Privileged {
			return Result{Level: Fail, Message: c.Name + " is privileged: it has every capability and every device" + stateWord(c), Evidence: ev}
		}
		return Result{Level: Pass, Message: c.Name + " is not privileged", Evidence: ev}
	}))
}

var (
	dangerousCaps = map[string]bool{"SYS_ADMIN": true, "SYS_PTRACE": true, "SYS_MODULE": true, "ALL": true}
	riskyCaps     = map[string]bool{"NET_ADMIN": true, "NET_RAW": true}
)

// DKR-022: no dangerous added capabilities.
func checkCapAdd(in Input) []Result {
	return eachContainer(in, posture(in, func(_ *facts.Docker, c facts.DockerContainer) Result {
		dangerous, risky := []string{}, []string{}
		for _, raw := range c.CapAdd {
			capName := strings.TrimPrefix(strings.ToUpper(strings.TrimSpace(raw)), "CAP_")
			switch {
			case dangerousCaps[capName]:
				dangerous = append(dangerous, capName)
			case riskyCaps[capName]:
				risky = append(risky, capName)
			}
		}
		ev := map[string]any{"container": c.Name, "cap_add": nonNil(c.CapAdd), "dangerous": dangerous, "risky": risky}
		switch {
		case len(dangerous) > 0:
			return Result{Level: Fail, Message: fmt.Sprintf("%s adds %s%s", c.Name, strings.Join(dangerous, ", "), stateWord(c)), Evidence: ev}
		case len(risky) > 0:
			return Result{Level: Warn, Message: fmt.Sprintf("%s adds %s%s", c.Name, strings.Join(risky, ", "), stateWord(c)), Evidence: ev}
		}
		return Result{Level: Pass, Message: c.Name + " adds no dangerous capability", Evidence: ev}
	}))
}

// DKR-023: no host network, PID or IPC namespace.
func checkHostNamespaces(in Input) []Result {
	return eachContainer(in, posture(in, func(_ *facts.Docker, c facts.DockerContainer) Result {
		root := isRootUser(c.User)
		ev := map[string]any{"container": c.Name, "network_mode": c.NetworkMode, "pid_mode": c.PidMode, "ipc_mode": c.IpcMode, "root": root}
		level := Pass
		var why []string
		if c.PidMode == "host" {
			level = worse(level, Fail)
			why = append(why, "host PID namespace")
		}
		if c.NetworkMode == "host" {
			if root {
				level = worse(level, Fail)
				why = append(why, "host network as root")
			} else {
				level = worse(level, Warn)
				why = append(why, "host network")
			}
		}
		if c.IpcMode == "host" {
			level = worse(level, Warn)
			why = append(why, "host IPC namespace")
		}
		if level == Pass {
			return Result{Level: Pass, Message: c.Name + " uses its own network, PID and IPC namespaces", Evidence: ev}
		}
		return Result{Level: level, Message: fmt.Sprintf("%s uses the %s%s", c.Name, strings.Join(why, ", "), stateWord(c)), Evidence: ev}
	}))
}

// DKR-024: no unconfined seccomp or AppArmor; no-new-privileges on public
// containers.
func checkSecurityOpt(in Input) []Result {
	return eachContainer(in, posture(in, func(d *facts.Docker, c facts.DockerContainer) Result {
		var unconfined []string
		nnp := d.Daemon != nil && d.Daemon.NoNewPrivileges
		for _, o := range c.SecurityOpt {
			norm := strings.ToLower(strings.ReplaceAll(strings.TrimSpace(o), ":", "="))
			switch norm {
			case "seccomp=unconfined", "apparmor=unconfined":
				unconfined = append(unconfined, o)
			case "no-new-privileges", "no-new-privileges=true":
				nnp = true
			case "no-new-privileges=false":
				nnp = false
			}
		}
		pub := isPublic(c)
		ev := map[string]any{"container": c.Name, "security_opt": nonNil(c.SecurityOpt), "unconfined": nonNil(unconfined), "no_new_privileges": nnp, "public": pub}
		var why []string
		if len(unconfined) > 0 {
			why = append(why, "runs "+strings.Join(unconfined, ", "))
		}
		if pub && !nnp {
			why = append(why, "is reachable from outside without no-new-privileges")
		}
		if len(why) > 0 {
			return Result{Level: Warn, Message: fmt.Sprintf("%s %s%s", c.Name, strings.Join(why, " and "), stateWord(c)), Evidence: ev}
		}
		return Result{Level: Pass, Message: c.Name + " keeps the default seccomp and AppArmor confinement", Evidence: ev}
	}))
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
	members := map[string][]facts.DockerContainer{}
	for _, c := range d.Containers {
		if roleOf(c) == roleProxy {
			continue // the proxy joins every project network by design
		}
		for _, n := range c.Networks {
			if !notSharedNetworks[n] {
				members[n] = append(members[n], c)
			}
		}
	}
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
		self := projectKey(c)
		selfDB := roleOf(c) == roleDatabase
		var shared, peers, dbPeers []string
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

func capList(s []string) []string {
	if len(s) > maxPeers {
		return append(append([]string{}, s[:maxPeers]...), fmt.Sprintf("and %d more", len(s)-maxPeers))
	}
	return nonNil(s)
}

// DKR-031: json-file logs need a max-size or they grow without limit.
func checkLogRotation(in Input) []Result {
	d, early := dockerFacts(in, true)
	if early != nil {
		return early
	}
	dd := d.Daemon
	if dd == nil {
		return One(Unknown, "the daemon config was not read", map[string]any{"config_found": false})
	}
	driver := dd.LogDriver
	if driver == "" && d.Info != nil {
		driver = d.Info.LoggingDriver
	}
	if driver == "" {
		driver = "json-file"
	}
	ev := map[string]any{"driver": driver, "max_size": dd.LogMaxSize, "max_file": dd.LogMaxFile, "config_found": dd.ConfigFound}
	if dd.ConfigError != "" {
		return One(Unknown, "could not read daemon.json: "+dd.ConfigError, ev)
	}
	if driver == "json-file" && dd.LogMaxSize == "" {
		return One(Warn, "json-file container logs have no max-size and grow until the disk is full", ev)
	}
	if driver == "json-file" {
		return One(Pass, "json-file container logs rotate at "+dd.LogMaxSize, ev)
	}
	return One(Pass, "container logs use the "+driver+" driver", ev)
}

// DKR-032: infrastructure containers should run a pinned image.
func checkInfraTags(in Input) []Result {
	d, early := dockerFacts(in, true)
	if early != nil {
		return early
	}
	isInfra := func(c facts.DockerContainer) bool {
		switch roleOf(c) {
		case roleProxy, roleTunnel, roleCrowdSec:
			return true
		}
		return false
	}
	found := false
	for _, c := range d.Containers {
		found = found || isInfra(c)
	}
	if !found {
		return One(Skip, "no proxy, tunnel or CrowdSec container found", map[string]any{"infra_containers": 0})
	}
	return eachContainerWhere(in, isInfra, func(_ *facts.Docker, c facts.DockerContainer) Result {
		_, tag, digest := imageRef(c.Image)
		ev := map[string]any{"container": c.Name, "image": c.Image, "role": roleOf(c), "tag": tag, "digest": digest != ""}
		switch {
		case digest != "":
			return Result{Level: Pass, Message: c.Name + " runs an image pinned by digest", Evidence: ev}
		case tag == "" || tag == "latest":
			return Result{Level: Warn, Message: fmt.Sprintf("%s runs %s, which floats (latest)", c.Name, c.Image), Evidence: ev}
		}
		return Result{Level: Pass, Message: fmt.Sprintf("%s runs a pinned tag (%s)", c.Name, tag), Evidence: ev}
	})
}

// DKR-033: Docker should manage the firewall rules for its networks.
func checkIPTables(in Input) []Result {
	d, early := dockerFacts(in, true)
	if early != nil {
		return early
	}
	dd := d.Daemon
	if dd == nil {
		return One(Unknown, "the daemon config was not read", map[string]any{"iptables": nil, "config_found": false})
	}
	ev := map[string]any{"iptables": dd.IPTables == nil || *dd.IPTables, "config_found": dd.ConfigFound}
	if dd.IPTables != nil && !*dd.IPTables {
		return One(Warn, "Docker does not manage the firewall (iptables: false): published ports may be wide open or silently broken", ev)
	}
	if dd.ConfigError != "" {
		return One(Unknown, "could not read daemon.json: "+dd.ConfigError, ev)
	}
	return One(Pass, "Docker manages the firewall rules for its networks", ev)
}

// engineSupport is when each Docker Engine release line leaves upstream
// support (endoflife.date "docker-engine", as of 2026-11-15). A line not
// listed and newer than every listed one is assumed supported; anything
// older than 20.10 is out of support.
var engineSupport = map[string]string{
	"29": "", // supported
	"28": "2026-05-13", "27": "2025-05-03", "26.1": "2025-02-17", "26.0": "2024-06-08",
	"25.0": "2026-12-04", "24.0": "2024-06-08", "23.0": "2025-05-19", "20.10": "2023-12-10",
}

const engineSupportAsOf = "2026-11-15"

// engineCycle maps a version to its release line: the major from 27 on,
// major.minor before.
func engineCycle(v string) (cycle string, major, minor int, ok bool) {
	v = strings.TrimPrefix(strings.TrimSpace(v), "v")
	parts := strings.SplitN(v, ".", 3)
	if len(parts) < 2 {
		return "", 0, 0, false
	}
	var err error
	if major, err = strconv.Atoi(parts[0]); err != nil {
		return "", 0, 0, false
	}
	if minor, err = strconv.Atoi(strings.TrimLeftFunc(parts[1], func(r rune) bool { return r < '0' || r > '9' })); err != nil {
		minor = 0
	}
	if major >= 27 {
		return strconv.Itoa(major), major, minor, true
	}
	return fmt.Sprintf("%d.%d", major, minor), major, minor, true
}

// DKR-034: the Docker Engine release line is still supported upstream.
func checkEngineSupport(in Input) []Result {
	d, early := dockerFacts(in, true)
	if early != nil {
		return early
	}
	if d.Version == nil || d.Version.Version == "" {
		return One(Unknown, "the Docker API did not report a version", map[string]any{"version": ""})
	}
	v := d.Version.Version
	cycle, major, _, ok := engineCycle(v)
	ev := map[string]any{"version": v, "cycle": cycle, "eol": "", "table_as_of": engineSupportAsOf}
	if !ok {
		return One(Unknown, "cannot read Docker Engine version "+v, ev)
	}
	eol, known := engineSupport[cycle]
	switch {
	case !known && major > 29:
		return One(Pass, "Docker Engine "+v+" is newer than stackward's support table", ev)
	case !known:
		return One(Warn, "Docker Engine "+v+" is out of upstream support", ev)
	case eol == "":
		return One(Pass, "Docker Engine "+cycle+" is supported upstream", ev)
	}
	ev["eol"] = eol
	end, err := time.Parse("2006-01-02", eol)
	if err != nil || in.Facts.CollectedAt.IsZero() {
		return One(Unknown, "cannot compare the support date", ev)
	}
	if !in.Facts.CollectedAt.Before(end) {
		return One(Warn, fmt.Sprintf("Docker Engine %s left upstream support on %s", cycle, eol), ev)
	}
	return One(Pass, fmt.Sprintf("Docker Engine %s is supported upstream until %s", cycle, eol), ev)
}
