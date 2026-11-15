package checks

import (
	"fmt"
	"sort"
	"strings"

	"github.com/Shironex/stackward/internal/facts"
)

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
