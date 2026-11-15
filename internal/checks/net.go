package checks

import (
	"fmt"
	"sort"
	"strings"

	"github.com/Shironex/stackward/internal/facts"
	"github.com/Shironex/stackward/internal/profile"
)

// NET checks read what the firewall and listeners collectors gather
// (facts/firewall.go, facts/listeners.go); NET-007 also reads published
// ports from the Docker facts. DKR-001 (published ports past the firewall)
// lives with the DKR group.

func init() {
	Register(Check{ID: "NET-001", Run: checkFirewallActive})
	Register(Check{ID: "NET-002", Run: checkUFWIPv6})
	Register(Check{ID: "NET-003", Run: checkSSHFromAnywhere})
	Register(Check{ID: "NET-004", Run: checkExposure})
	Register(Check{ID: "NET-005", Run: checkWebRulesOnPrivateProfile})
	Register(Check{ID: "NET-006", Run: checkDockerUser})
	Register(Check{ID: "NET-007", Run: checkUFWDockerLoaded})
	Register(Check{ID: "NET-008", Run: checkUFWDockerBackend})
	Register(Check{ID: "NET-009", Run: checkProviderFirewall})
}

// tailnetState is profile.Tailnet, swapped in tests (the Tailscale facts
// type of another slice cannot implement the reporter from a test file).
var tailnetState = profile.Tailnet

// Tri-state answers for questions the facts may not settle.
type tri int

const (
	triUnknown tri = iota
	triNo
	triYes
)

func (t tri) String() string {
	switch t {
	case triYes:
		return "yes"
	case triNo:
		return "no"
	}
	return "unknown"
}

// hostFirewall is the verdict on whether some host firewall denies incoming
// traffic by default, and which one.
type hostFirewall struct {
	denies    tri    // default incoming is deny or reject
	mechanism string // "ufw", "nftables", "iptables", "firewalld", ""
	reason    string // why, in words
}

func judgeFirewall(fw *facts.Firewall) hostFirewall {
	u := fw.UFW
	if u != nil && u.Installed && u.Live() && u.Status == "active" {
		switch u.DefaultIncoming {
		case "deny", "reject":
			return hostFirewall{triYes, "ufw", "UFW is active with default incoming " + u.DefaultIncoming}
		case "allow":
			return hostFirewall{triNo, "ufw", "UFW is active but default incoming is allow"}
		}
		return hostFirewall{triUnknown, "ufw", "UFW is active but its default incoming policy was not printed"}
	}
	if fw.Firewalld != nil && fw.Firewalld.State == "running" {
		return hostFirewall{triYes, "firewalld", "firewalld is running (zones reject unmatched incoming traffic)"}
	}
	if fw.NFT.InputDrops() {
		return hostFirewall{triYes, "nftables", "an nftables input chain drops by default"}
	}
	if t := fw.Iptables; t != nil && t.Listed {
		if p := t.Policies["INPUT"]; p == "DROP" || p == "REJECT" {
			return hostFirewall{triYes, "iptables", "iptables INPUT policy is " + p}
		}
	}

	// Nothing denies. Say so only if every installed mechanism was read.
	nftSeen := fw.NFT == nil || !fw.NFT.Installed || fw.NFT.Listed
	iptSeen := fw.Iptables == nil || !fw.Iptables.Installed || fw.Iptables.Listed
	ufwSeen := u == nil || !u.Installed || u.Live()
	if nftSeen && iptSeen && ufwSeen {
		if u != nil && u.Installed && u.Status == "inactive" {
			if u.Enabled == "yes" {
				return hostFirewall{triNo, "", "UFW is enabled in ufw.conf but its rules are not loaded, and no other firewall drops incoming traffic"}
			}
			return hostFirewall{triNo, "", "UFW is inactive and no other firewall drops incoming traffic"}
		}
		return hostFirewall{triNo, "", "no host firewall drops incoming traffic"}
	}
	return hostFirewall{triUnknown, "", "the live firewall rules need root to read"}
}

func firewallEvidence(fw *facts.Firewall, v hostFirewall) map[string]any {
	ev := map[string]any{"denies_incoming": v.denies.String(), "mechanism": v.mechanism}
	if u := fw.UFW; u != nil && u.Installed {
		ev["ufw_status"] = valueOrUnknown(u.Status)
		ev["ufw_default_incoming"] = valueOrUnknown(u.DefaultIncoming)
		ev["ufw_source"] = u.Source
	}
	if fw.NFT != nil && fw.NFT.Installed {
		ev["nft_listed"] = fw.NFT.Listed
	}
	if t := fw.Iptables; t != nil && t.Installed {
		ev["iptables_backend"] = valueOrUnknown(t.Backend)
		ev["iptables_input_policy"] = valueOrUnknown(t.Policies["INPUT"])
	}
	if fw.Firewalld != nil {
		ev["firewalld_state"] = valueOrUnknown(fw.Firewalld.State)
	}
	return ev
}

func checkFirewallActive(in Input) []Result {
	fw := in.Facts.Firewall
	if fw == nil {
		return []Result{NotInspected(in.Facts, "firewall")}
	}
	v := judgeFirewall(fw)
	ev := firewallEvidence(fw, v)
	switch v.denies {
	case triYes:
		return One(Pass, v.reason, ev)
	case triNo:
		return One(Fail, v.reason, ev)
	}
	msg := v.reason
	if u := fw.UFW; u != nil && u.Source == "files" && u.Status != "" {
		msg = fmt.Sprintf("UFW files say %s at boot with default incoming %s; %s",
			u.Status, valueOrUnknown(u.DefaultIncoming), "the live rules need root to read (run with sudo)")
	}
	return One(Unknown, msg, ev)
}

func checkUFWIPv6(in Input) []Result {
	fw, l := in.Facts.Firewall, in.Facts.Listeners
	if fw == nil {
		return []Result{NotInspected(in.Facts, "firewall")}
	}
	u := fw.UFW
	if u == nil || !u.Installed {
		return One(Skip, "UFW is not installed", map[string]any{"ufw": false})
	}
	ev := map[string]any{"ipv6": valueOrUnknown(u.IPv6)}
	if u.IPv6 == "yes" {
		return One(Pass, "UFW filters IPv6 (IPV6=yes)", ev)
	}
	if u.IPv6 == "" {
		return One(Unknown, "could not read IPV6 from /etc/default/ufw", ev)
	}
	if l == nil {
		return []Result{NotInspected(in.Facts, "listeners")}
	}
	has, known := l.HasGlobalIPv6()
	ev["global_ipv6"] = has
	switch {
	case !known:
		return One(Unknown, "UFW has IPV6=no, but the interface addresses could not be read", ev)
	case has:
		return One(Fail, "UFW has IPV6=no while the host has a global IPv6 address: IPv6 traffic is not filtered", ev)
	}
	return One(Pass, "UFW has IPV6=no, and the host has no global IPv6 address", ev)
}

// sshPorts returns the TCP ports sshd listens on. Under the sandbox the
// names come from the socket ownership snapshot taken before it. Without
// process names (not root, a snapshot that could not be taken, or
// ssh.socket activation, where systemd holds the socket) it falls back to
// port 22.
func sshPorts(l *facts.Listeners) []int {
	ports := map[int]bool{}
	for _, s := range l.Sockets {
		if s.Proto == "tcp" && s.HasProcess("sshd") {
			ports[s.Port] = true
		}
	}
	if len(ports) == 0 {
		ports[22] = true
	}
	return sortedPorts(ports)
}

func sortedPorts(m map[int]bool) []int {
	out := make([]int, 0, len(m))
	for p := range m {
		out = append(out, p)
	}
	sort.Ints(out)
	return out
}

// openFromAnywhere answers whether proto/port accepts connections from any
// source, given the listeners on it and the firewall. The string says why.
func openFromAnywhere(fw *facts.Firewall, socks []facts.Listener, proto string, port int) (tri, string) {
	exposed := false
	for _, s := range socks {
		if s.Proto == proto && s.Port == port && s.Class().Exposed() {
			exposed = true
		}
	}
	if !exposed {
		return triNo, "it does not listen on a wildcard or public address"
	}
	if fw == nil {
		return triUnknown, "firewall not inspected"
	}
	v := judgeFirewall(fw)
	switch v.denies {
	case triNo:
		return triYes, v.reason
	case triUnknown:
		return triUnknown, v.reason
	}
	if v.mechanism != "ufw" {
		return triUnknown, fmt.Sprintf("%s drops by default, but its port rules are not analysed", v.mechanism)
	}
	if !fw.UFW.RulesKnown {
		return triUnknown, "UFW rules could not be read"
	}
	for _, r := range fw.UFW.Rules {
		if r.Direction == "in" && r.Allows() && r.FromAnywhere() && r.MatchesPort(proto, port) {
			return triYes, fmt.Sprintf("UFW allows %s from anywhere (%s)", portLabel(proto, port), ruleText(r))
		}
	}
	return triNo, "UFW allows it only from specific sources or interfaces, or not at all"
}

func ruleText(r facts.UFWRule) string {
	parts := []string{r.Action, r.Direction}
	switch {
	case r.App != "":
		parts = append(parts, r.App)
	case r.Port != "":
		parts = append(parts, r.Port+"/"+r.Proto)
	default:
		parts = append(parts, "any port")
	}
	if r.Interface != "" {
		parts = append(parts, "on "+r.Interface)
	}
	from := r.From
	if from == "" {
		from = "anywhere"
	}
	parts = append(parts, "from "+from)
	if r.V6 {
		parts = append(parts, "(v6)")
	}
	return strings.Join(parts, " ")
}

func portLabel(proto string, port int) string { return fmt.Sprintf("%s/%d", proto, port) }

// sshReach is the answer to "can sshd be reached from any source": the
// worst verdict over the sshd ports, the ports that are open, and why for
// each port. NET-003, SSH-011 and CS-010 share it.
type sshReach struct {
	open      tri
	ports     []int
	openPorts []int
	reasons   []string
}

// sshReachability needs both listeners and firewall facts; callers check
// for nil first.
func sshReachability(f *facts.Facts) sshReach {
	r := sshReach{open: triNo, ports: sshPorts(f.Listeners)}
	for _, p := range r.ports {
		o, reason := openFromAnywhere(f.Firewall, f.Listeners.Sockets, "tcp", p)
		r.reasons = append(r.reasons, fmt.Sprintf("tcp/%d: %s", p, reason))
		switch {
		case o == triYes:
			r.open = triYes
			r.openPorts = append(r.openPorts, p)
		case o == triUnknown && r.open != triYes:
			r.open = triUnknown
		}
	}
	return r
}

// where lists the open ports as "tcp/22, tcp/2222".
func (r sshReach) where() string {
	labels := make([]string, 0, len(r.openPorts))
	for _, p := range r.openPorts {
		labels = append(labels, portLabel("tcp", p))
	}
	return strings.Join(labels, ", ")
}

func checkSSHFromAnywhere(in Input) []Result {
	f := in.Facts
	if f.Listeners == nil {
		return []Result{NotInspected(f, "listeners")}
	}
	if f.Firewall == nil {
		return []Result{NotInspected(f, "firewall")}
	}
	reach := sshReachability(f)
	running, known := tailnetState(f)
	ev := map[string]any{"ssh_ports": reach.ports, "open_from_anywhere": reach.open.String(), "tailnet": tailnetWord(running, known)}
	reason := strings.Join(reach.reasons, "; ")
	where := reach.where()
	switch {
	case reach.open == triNo:
		return One(Pass, "SSH is not reachable from anywhere: "+reason, ev)
	case reach.open == triUnknown:
		return One(Unknown, "could not tell whether SSH is open to anywhere: "+reason, ev)
	case !known:
		return One(Unknown, fmt.Sprintf("SSH is open to anywhere on %s; Tailscale facts are missing, so whether a private path exists is unknown", where), ev)
	case running:
		return One(Fail, fmt.Sprintf("SSH is open to anywhere on %s although Tailscale is running and offers a private path", where), ev)
	}
	return One(Warn, fmt.Sprintf("SSH is open to anywhere on %s and no private path (tailnet) exists", where), ev)
}

func tailnetWord(running, known bool) string {
	switch {
	case !known:
		return "unknown"
	case running:
		return "running"
	}
	return "not running"
}

// dhcpClientPorts are UDP client ports every DHCP host binds; flagging them
// would only be noise.
var dhcpClientPorts = map[int]bool{68: true, 546: true}

// tailscaleWireGuardPort is tailscaled's default UDP port (--port).
const tailscaleWireGuardPort = 41641

// udpClientSocket explains a wildcard UDP socket that belongs to a known
// outbound client rather than a service: cloudflared's QUIC connections to
// the Cloudflare edge, and tailscaled's WireGuard and discovery sockets.
// Only process names seen as root count, and only when every process on
// the port is such a client, so a real listener sharing the port still
// gets judged.
func udpClientSocket(l *facts.Listeners, g portGroup) string {
	if g.proto != "udp" || !l.ProcessesVisible {
		return ""
	}
	owner := ""
	for _, s := range g.socks {
		if len(s.Processes) == 0 {
			return ""
		}
		for _, p := range s.Processes {
			if p != "cloudflared" && p != "tailscaled" {
				return ""
			}
			if owner != "" && owner != p {
				return ""
			}
			owner = p
		}
	}
	switch {
	case owner == "cloudflared":
		return "an outbound QUIC socket of cloudflared: the tunnel dials out to Cloudflare and accepts no inbound connections here"
	case owner == "tailscaled" && g.port == tailscaleWireGuardPort:
		return "Tailscale's WireGuard port: peers connect to it directly, and it answers only packets from authenticated tailnet nodes"
	case owner == "tailscaled":
		return "a socket of tailscaled (WireGuard or path discovery): it answers only packets from authenticated tailnet nodes"
	}
	return ""
}

type portGroup struct {
	proto string
	port  int
	socks []facts.Listener
}

func groupListeners(socks []facts.Listener) []portGroup {
	idx := map[string]int{}
	var out []portGroup
	for _, s := range socks {
		k := portLabel(s.Proto, s.Port)
		i, ok := idx[k]
		if !ok {
			i = len(out)
			idx[k] = i
			out = append(out, portGroup{proto: s.Proto, port: s.Port})
		}
		out[i].socks = append(out[i].socks, s)
	}
	return out
}

func checkExposure(in Input) []Result {
	f := in.Facts
	l := f.Listeners
	if l == nil {
		return []Result{NotInspected(f, "listeners")}
	}
	if len(l.Sockets) == 0 {
		return One(Info, "no listening sockets found", map[string]any{"source": l.Source})
	}
	var out []Result
	for _, g := range groupListeners(l.Sockets) {
		out = append(out, exposureResult(f, l, g))
	}
	return out
}

func exposureResult(f *facts.Facts, l *facts.Listeners, g portGroup) Result {
	var binds, procs []string
	worst := facts.BindLoopback
	rank := map[facts.BindClass]int{facts.BindLoopback: 0, facts.BindTailnet: 1, facts.BindPrivate: 2, facts.BindInvalid: 3, facts.BindPublic: 4, facts.BindWildcard: 5}
	docker := false
	seenProc := map[string]bool{}
	for _, s := range g.socks {
		b := s.Address
		if s.Interface != "" {
			b += "%" + s.Interface
		}
		binds = append(binds, b)
		if c := s.Class(); rank[c] > rank[worst] {
			worst = c
		}
		for _, p := range s.Processes {
			if !seenProc[p] {
				seenProc[p] = true
				procs = append(procs, p)
			}
		}
		if s.PublishedByContainer(f.Docker) {
			docker = true
		}
	}
	sort.Strings(procs)
	label := portLabel(g.proto, g.port)
	r := Result{Subject: "port:" + label, Evidence: map[string]any{
		"binds": binds, "class": string(worst), "processes": procs, "processes_visible": l.ProcessesVisible,
	}}
	who := ""
	if len(procs) > 0 {
		who = " (" + strings.Join(procs, ", ") + ")"
	}
	if !worst.Exposed() {
		r.Level, r.Message = Info, fmt.Sprintf("%s%s listens on %s addresses only", label, who, worst)
		return r
	}
	if g.proto == "udp" && dhcpClientPorts[g.port] {
		r.Level, r.Message = Info, fmt.Sprintf("%s%s is a DHCP client socket", label, who)
		return r
	}
	if docker {
		r.Level = Warn
		r.Message = fmt.Sprintf("%s is a published container port on %s: UFW input rules do not apply to it (see DKR-001)", label, worst)
		if f.Firewall != nil && f.Firewall.DockerUser == "filtered" {
			r.Level = Info
			r.Message = fmt.Sprintf("%s is a published container port on %s; DOCKER-USER has filtering rules (see DKR-001)", label, worst)
		}
		return r
	}
	open, reason := openFromAnywhere(f.Firewall, g.socks, g.proto, g.port)
	r.Evidence["open_from_anywhere"] = open.String()
	if open != triNo {
		if why := udpClientSocket(l, g); why != "" {
			r.Level, r.Message = Info, fmt.Sprintf("%s%s is %s", label, who, why)
			return r
		}
	}
	switch open {
	case triNo:
		r.Level, r.Message = Pass, fmt.Sprintf("%s%s listens on %s, but %s", label, who, worst, reason)
	case triUnknown:
		r.Level, r.Message = Unknown, fmt.Sprintf("%s%s listens on %s; %s", label, who, worst, reason)
	default:
		if judgeFirewall(f.Firewall).denies == triYes {
			r.Level, r.Message = Info, fmt.Sprintf("%s%s is public by design: %s", label, who, reason)
		} else {
			r.Level, r.Message = Warn, fmt.Sprintf("%s%s listens on %s and nothing filters it: %s", label, who, worst, reason)
		}
	}
	return r
}

func checkWebRulesOnPrivateProfile(in Input) []Result {
	fw := in.Facts.Firewall
	if fw == nil {
		return []Result{NotInspected(in.Facts, "firewall")}
	}
	ev := map[string]any{"profile": string(in.Profile)}
	switch in.Profile {
	case profile.Unknown:
		return One(Unknown, "ingress profile unknown; pass --profile to judge 80/443 rules", ev)
	case profile.PublicWeb, profile.PaaSPanel, profile.Mixed:
		return One(Skip, fmt.Sprintf("80/443 may be public on the %s profile", in.Profile), ev)
	}
	u := fw.UFW
	if u == nil || !u.Installed || u.Status != "active" {
		return One(Skip, "UFW is not active; no allow rules to judge", ev)
	}
	if !u.RulesKnown {
		return One(Unknown, "UFW rules could not be read (run with sudo)", ev)
	}
	var found []string
	for _, r := range u.Rules {
		if r.Direction == "in" && r.Allows() && r.FromAnywhere() && r.Port != "" && (r.MatchesPort("tcp", 80) || r.MatchesPort("tcp", 443)) {
			found = append(found, ruleText(r))
		}
	}
	ev["rules"] = found
	if len(found) > 0 {
		return One(Warn, fmt.Sprintf("UFW allows 80/443 from anywhere on a %s host: a dead rule, or an open door past the tunnel", in.Profile), ev)
	}
	return One(Pass, "no UFW rule opens 80/443 to anywhere", ev)
}

func checkDockerUser(in Input) []Result {
	fw := in.Facts.Firewall
	if fw == nil {
		return []Result{NotInspected(in.Facts, "firewall")}
	}
	ev := map[string]any{"docker_user": valueOrUnknown(fw.DockerUser), "docker_backend": valueOrUnknown(fw.DockerBackend)}
	switch fw.DockerUser {
	case "":
		return One(Unknown, "DOCKER-USER chain not read (iptables -S needs root)", ev)
	case "absent":
		msg := "no DOCKER-USER chain"
		if fw.DockerBackend == "nftables" {
			msg += " (Docker uses its nftables backend, which has none)"
		}
		return One(Info, msg, ev)
	case "filtered":
		return One(Info, "DOCKER-USER has filtering rules", ev)
	}
	return One(Info, "DOCKER-USER exists with no filtering rules: published ports are not filtered by the host firewall", ev)
}

func checkUFWDockerLoaded(in Input) []Result {
	f := in.Facts
	fw := f.Firewall
	if fw == nil {
		return []Result{NotInspected(f, "firewall")}
	}
	d := fw.UFWDocker
	if d == nil {
		return One(Skip, "UFW is not installed", nil)
	}
	ev := map[string]any{"in_files": valueOrUnknown(d.InFiles), "loaded": valueOrUnknown(d.Loaded)}
	switch {
	case d.InFiles == "absent" && d.Loaded != "yes":
		return One(Skip, "ufw-docker is not installed", ev)
	case d.InFiles == "" && d.Loaded == "":
		return One(Unknown, "could not read /etc/ufw/after.rules or the live rules (run with sudo)", ev)
	case d.InFiles == "present" && d.Loaded == "no":
		return One(Fail, "the ufw-docker block is in after.rules but not loaded: published ports are unfiltered until ufw reload", ev)
	case d.Loaded == "":
		return One(Unknown, "ufw-docker is in after.rules; whether it is loaded needs root", ev)
	}
	// Loaded. Tailnet traffic to published ports needs route rules.
	routes := 0
	if fw.UFW != nil {
		for _, r := range fw.UFW.Rules {
			if r.Direction == "fwd" && r.Allows() && r.Interface == "tailscale0" {
				routes++
			}
		}
	}
	ev["tailscale0_route_rules"] = routes
	running, known := tailnetState(f)
	published := publishedPorts(f)
	ev["published_ports_seen"] = published
	ev["tailnet"] = tailnetWord(running, known)
	switch {
	case routes > 0:
		return One(Pass, fmt.Sprintf("ufw-docker is loaded with %d route rule(s) on tailscale0", routes), ev)
	case known && !running:
		return One(Pass, "ufw-docker is loaded; no tailnet, so no tailscale0 route rules are needed", ev)
	case len(published) > 0:
		return One(Warn, "ufw-docker is loaded and ports are published, but no route rule allows them on tailscale0: tailnet access to them is dropped", ev)
	}
	if d := f.Docker; d != nil && (!d.Installed || d.API == "ok") {
		return One(Pass, "ufw-docker is loaded and no container publishes a port beyond loopback, so no tailscale0 route rules are needed", ev)
	}
	return One(Unknown, "ufw-docker is loaded with no tailscale0 route rules; whether ports are published needs the Docker facts", ev)
}

// publishedPorts lists published ports from the listeners a container
// holds (docker-proxy, or dockerd while the Docker API names the
// container) and, when the Docker API was read, from the containers
// themselves (hosts without the userland proxy may have no listener for
// them).
func publishedPorts(f *facts.Facts) []string {
	out := publishedListeners(f)
	if out == nil {
		out = []string{}
	}
	d := f.Docker
	if d == nil || d.API != "ok" {
		return out
	}
	seen := map[string]bool{}
	for _, p := range out {
		seen[p] = true
	}
	for _, c := range d.Containers {
		for _, p := range c.Ports {
			if facts.ClassifyAddress(p.HostIP) == facts.BindLoopback {
				continue // not reachable over the tailnet either way
			}
			proto := p.Proto
			if proto == "" {
				proto = "tcp"
			}
			if k := portLabel(proto, p.HostPort); !seen[k] {
				seen[k] = true
				out = append(out, k)
			}
		}
	}
	sort.Strings(out)
	return out
}

// publishedListeners lists ports whose listener a container holds. Hosts
// that run Docker without the userland proxy may publish ports without
// one, so an empty list proves nothing.
func publishedListeners(f *facts.Facts) []string {
	l := f.Listeners
	if l == nil {
		return nil
	}
	seen := map[string]bool{}
	out := []string{}
	for _, s := range l.Sockets {
		if s.PublishedByContainer(f.Docker) {
			k := portLabel(s.Proto, s.Port)
			if !seen[k] {
				seen[k] = true
				out = append(out, k)
			}
		}
	}
	return out
}

func checkUFWDockerBackend(in Input) []Result {
	fw := in.Facts.Firewall
	if fw == nil {
		return []Result{NotInspected(in.Facts, "firewall")}
	}
	d := fw.UFWDocker
	ev := map[string]any{"docker_backend": valueOrUnknown(fw.DockerBackend)}
	if d == nil || (d.InFiles == "absent" && d.Loaded != "yes") {
		return One(Skip, "ufw-docker is not installed", ev)
	}
	if d.InFiles == "" && d.Loaded == "" {
		return One(Unknown, "could not tell whether ufw-docker is installed (run with sudo)", ev)
	}
	switch fw.DockerBackend {
	case "nftables":
		return One(Warn, "ufw-docker is installed but Docker uses its nftables backend: there is no DOCKER-USER chain, so ufw-docker filters nothing", ev)
	case "iptables":
		return One(Pass, "ufw-docker is installed and Docker uses the iptables backend it needs", ev)
	case "none":
		return One(Pass, "ufw-docker is installed; no Docker firewall rules exist yet", ev)
	}
	return One(Unknown, "Docker's firewall backend could not be read (run with sudo)", ev)
}

func checkProviderFirewall(Input) []Result {
	return One(Unknown,
		"the provider firewall cannot be seen from inside the host; run `stackward probe` from another machine to see what is reachable",
		map[string]any{"visible_from_host": false})
}

// valueOrUnknown spells an empty fact as "unknown" in messages and evidence.
func valueOrUnknown(s string) string {
	if s == "" {
		return "unknown"
	}
	return s
}
