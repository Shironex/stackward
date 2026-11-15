package checks

import (
	"fmt"
	"strconv"
	"strings"

	"github.com/Shironex/stackward/internal/facts"
	"github.com/Shironex/stackward/internal/profile"
)

// DKR-001 joins three collectors: the Docker facts say what each container
// publishes, the firewall facts say what filters forwarded traffic (the
// DOCKER-USER chain, ufw-docker and its route rules, Docker's nftables
// backend), and the listener facts say which interfaces are public. Docker
// publishes ports through DNAT in PREROUTING and accepts them in FORWARD,
// so UFW's input rules never see them; only DOCKER-USER (or the nftables
// forward hook) can filter them.
//
// It lives in its own file because the DOCKER-USER rule reading is the
// largest piece of the DKR group.

func init() {
	Register(Check{ID: "DKR-001", Run: checkPublishedPorts})
}

// portVerdict is what DKR-001 concluded about one published binding.
type portVerdict struct {
	label  string // 0.0.0.0:5432->5432/tcp
	level  Level
	open   tri    // reachable from any source
	filter string // what decided: none, docker-user, ufw-docker, ufw-route, input, nftables, unknown
	reason string
}

func checkPublishedPorts(in Input) []Result {
	return eachContainer(in, func(d *facts.Docker, c facts.DockerContainer) Result {
		ev := map[string]any{"container": c.Name, "published": []string{}, "open": []string{}, "filtered": []string{},
			"unknown": []string{}, "profile": string(in.Profile), "docker_user": "unknown"}
		if fw := in.Facts.Firewall; fw != nil {
			ev["docker_user"] = valueOrUnknown(fw.DockerUser)
		}
		if len(c.Ports) == 0 {
			return Result{Level: Pass, Message: c.Name + " publishes no port", Evidence: ev}
		}
		var published, open, filtered, unknown, why []string
		level := Pass
		for _, p := range c.Ports {
			v := judgePublished(in, d, p)
			published = append(published, v.label)
			level = worse(level, v.level)
			switch {
			case v.filter == "":
				// loopback, tailnet or private bind: nothing to filter
			case v.open == triYes:
				open = append(open, v.label)
			case v.open == triNo:
				filtered = append(filtered, v.label)
			default:
				unknown = append(unknown, v.label)
			}
			if v.reason != "" && v.level != Pass {
				why = append(why, v.label+": "+v.reason)
			}
		}
		ev["published"], ev["open"], ev["filtered"], ev["unknown"] = published, nonNil(open), nonNil(filtered), nonNil(unknown)
		var msg string
		switch {
		case level == Fail:
			msg = fmt.Sprintf("%s is reachable from anywhere past the host firewall: %s", c.Name, strings.Join(why, "; "))
		case level == Warn:
			msg = fmt.Sprintf("%s publishes on all interfaces: %s", c.Name, strings.Join(why, "; "))
		case level == Unknown:
			msg = fmt.Sprintf("%s publishes on all interfaces and stackward could not tell what filters it: %s", c.Name, strings.Join(why, "; "))
		case len(open) > 0:
			msg = fmt.Sprintf("%s publishes %s from anywhere, as the %s profile expects", c.Name, strings.Join(open, ", "), in.Profile)
		case len(filtered) > 0:
			msg = fmt.Sprintf("%s publishes %s on all interfaces, and the forward filter drops it from unknown sources", c.Name, strings.Join(filtered, ", "))
		default:
			msg = fmt.Sprintf("%s publishes on loopback, tailnet or private addresses only", c.Name)
		}
		return Result{Level: level, Message: msg + stateWord(c), Evidence: ev}
	})
}

// judgePublished decides one binding. Only wildcard and public host
// addresses need a firewall verdict; the rest pass.
func judgePublished(in Input, d *facts.Docker, p facts.DockerPort) portVerdict {
	proto := p.Proto
	if proto == "" {
		proto = "tcp"
	}
	v := portVerdict{label: publishedLabel(p, proto)}
	if !paasAddrClass(p.HostIP).Exposed() {
		v.level = Pass
		return v
	}
	v.open, v.filter, v.reason = forwardFilter(in.Facts, d, proto, p.HostIP, p.HostPort, p.ContainerPort)
	switch v.open {
	case triNo:
		v.level = Pass
	case triUnknown:
		v.level = Unknown
	default:
		v.level = publicLevel(in.Profile, p.HostPort, v.filter)
	}
	return v
}

func publishedLabel(p facts.DockerPort, proto string) string {
	host := p.HostIP
	if host == "" {
		host = "0.0.0.0"
	}
	if strings.Contains(host, ":") {
		host = "[" + host + "]"
	}
	return fmt.Sprintf("%s:%d->%d/%s", host, p.HostPort, p.ContainerPort, proto)
}

// publicLevel judges a binding that is reachable from anywhere against the
// ingress profile: the web ports are public by design on public-web and
// paas-panel hosts; on tunnel and tailnet-only hosts nothing should be.
func publicLevel(prof profile.Name, hostPort int, filter string) Level {
	web := webPorts[hostPort]
	switch {
	case prof == profile.Tunnel || prof == profile.TailnetOnly:
		return Fail
	case web && (prof == profile.PublicWeb || prof == profile.PaaSPanel):
		return Pass
	case web:
		return Warn // mixed or unknown profile: maybe intended, say so
	case filter == "ufw-route":
		return Warn // a route rule opens it on purpose
	}
	return Fail
}

// forwardFilter answers whether forwarded traffic to a published port is
// accepted from any source, which mechanism decided, and why.
func forwardFilter(f *facts.Facts, d *facts.Docker, proto, hostIP string, hostPort, containerPort int) (tri, string, string) {
	fw := f.Firewall
	if fw == nil {
		return triUnknown, "unknown", "firewall facts were not collected"
	}
	if d.Daemon != nil && d.Daemon.IPTables != nil && !*d.Daemon.IPTables {
		// Without Docker's iptables rules the port is a plain host socket
		// held by docker-proxy, and the INPUT rules apply to it.
		addr := hostIP
		if addr == "" {
			addr = "0.0.0.0"
		}
		o, why := openFromAnywhere(fw, []facts.Listener{{Proto: proto, Address: addr, Port: hostPort}}, proto, hostPort)
		return o, "input", "Docker runs with iptables off, so the host input rules decide: " + why
	}
	if fw.DockerBackend == "nftables" {
		return nftForward(fw.NFT)
	}
	if c, why := fw.UFWDockerChain(); c != nil {
		return ufwDockerReach(f, c, proto, containerPort)
	} else if why != "" {
		return triUnknown, "ufw-docker", "ufw-docker is loaded, but DOCKER-USER " + why
	}
	if u := fw.UFWDocker; u != nil && u.Loaded == "yes" {
		// Facts without the DOCKER-USER rules: trust the jump.
		return ufwRoute(f, proto, containerPort)
	}
	switch fw.DockerUser {
	case "":
		return triUnknown, "unknown", "the DOCKER-USER chain needs root to read (run with sudo)"
	case "absent", "default":
		why := "DOCKER-USER has no filtering rules"
		if fw.DockerUser == "absent" {
			why = "there is no DOCKER-USER chain"
		}
		if v := judgeFirewall(fw); v.denies == triYes && v.mechanism == "ufw" {
			why += ", and UFW's input rules do not apply to published ports"
		}
		return triYes, "none", why
	}
	o, why := dockerUserVerdict(f, fw.Iptables.DockerUserRules, proto, containerPort, hostPort)
	return o, "docker-user", why
}

// nftForward judges Docker's nftables backend, which has no DOCKER-USER
// chain: another base chain on the forward hook that drops can filter,
// but its rules are not analysed.
func nftForward(n *facts.NFTables) (tri, string, string) {
	if n == nil || !n.Listed {
		return triUnknown, "nftables", "Docker uses its nftables backend and the ruleset needs root to read"
	}
	for _, c := range n.Chains {
		if c.Hook != "forward" || strings.HasPrefix(c.Table, "docker") {
			continue
		}
		if strings.EqualFold(c.Policy, "drop") || c.EndsInDrop {
			return triUnknown, "nftables", fmt.Sprintf("Docker uses its nftables backend and %s %s drops forwarded traffic, but its rules are not analysed", c.Family, c.Table)
		}
	}
	return triYes, "none", "Docker uses its nftables backend and no other forward chain drops traffic"
}

// ufwRoute judges a port behind ufw-docker: forwarded traffic is dropped
// unless a UFW route rule allows the container port. ufw-docker matches
// the container port, not the host port.
func ufwRoute(f *facts.Facts, proto string, containerPort int) (tri, string, string) {
	u := f.Firewall.UFW
	if u == nil || !u.RulesKnown {
		return triUnknown, "ufw-docker", "ufw-docker is loaded but the UFW route rules need root to read"
	}
	unsure := ""
	for _, r := range u.Rules {
		if r.Direction != "fwd" || !r.Allows() || r.From != "" || !r.MatchesPort(proto, containerPort) {
			continue
		}
		if r.Interface == "" {
			return triYes, "ufw-route", "a UFW route rule allows it from anywhere (" + ruleText(r) + ")"
		}
		switch ifacePublic(f, r.Interface) {
		case triYes:
			return triYes, "ufw-route", "a UFW route rule allows it from anywhere on " + r.Interface + " (" + ruleText(r) + ")"
		case triUnknown:
			unsure = r.Interface
		}
	}
	if unsure != "" {
		return triUnknown, "ufw-docker", "a UFW route rule allows it on " + unsure + ", and whether that interface is public is unknown"
	}
	return triNo, "ufw-docker", "ufw-docker drops it unless a route rule allows the source"
}

// ufwDockerReach judges a published port behind the DOCKER-USER chain of
// a standard ufw-docker install: a UFW route rule for the container port
// accepts new connections from anywhere; otherwise the chain's deny rules
// drop them, unless they leave that protocol and port out.
func ufwDockerReach(f *facts.Facts, c *facts.UFWDockerChain, proto string, containerPort int) (tri, string, string) {
	o, filter, why := ufwRoute(f, proto, containerPort)
	if o != triNo {
		return o, filter, why
	}
	if denied, dwhy := c.Denies(proto, containerPort); !denied {
		return triYes, "ufw-docker", dwhy
	}
	return triNo, "ufw-docker", "ufw-docker drops it: no UFW route rule allows " + portLabel(proto, containerPort) + " from anywhere"
}

// ufwDockerChainOf returns the DOCKER-USER chain when it is a standard
// ufw-docker install's, or nil.
func ufwDockerChainOf(f *facts.Facts) *facts.UFWDockerChain {
	c, _ := f.Firewall.UFWDockerChain()
	return c
}

// publishedReach judges whether a published port on proto/port, held by
// the given sockets, accepts connections from any source, the way DKR-001
// judges each binding (forwardFilter). The container port behind it comes
// from the Docker API; without it the answer is unknown.
func publishedReach(f *facts.Facts, socks []facts.Listener, proto string, port int) (tri, string, string) {
	var conts []facts.DockerContainer
	seen := map[string]bool{}
	for _, s := range socks {
		if !s.Class().Exposed() {
			continue
		}
		for _, ct := range f.Docker.Publishing(proto, s.Address, port) {
			if !seen[ct.Name] {
				seen[ct.Name] = true
				conts = append(conts, ct)
			}
		}
	}
	if len(conts) == 0 {
		return triUnknown, "unknown", "a published container port; which container port is behind it needs the Docker API"
	}
	rank := map[tri]int{triNo: 0, triUnknown: 1, triYes: 2}
	best, filter, why, found := triNo, "unknown", "", false
	for _, ct := range conts {
		for _, p := range ct.Ports {
			pp := p.Proto
			if pp == "" {
				pp = "tcp"
			}
			if p.HostPort != port || pp != proto || !paasAddrClass(p.HostIP).Exposed() {
				continue
			}
			o, fl, w := forwardFilter(f, f.Docker, proto, p.HostIP, port, p.ContainerPort)
			if !found || rank[o] > rank[best] {
				best, filter, why = o, fl, w
			}
			found = true
		}
	}
	if !found {
		return triUnknown, "unknown", "a published container port, but no container the Docker API lists publishes it on all interfaces"
	}
	return best, filter, why
}

// ifacePublic says whether an interface has a public address, from the
// interface addresses in the listener facts.
func ifacePublic(f *facts.Facts, name string) tri {
	if facts.InternalInterface(name) {
		return triNo
	}
	l := f.Listeners
	if l == nil || l.Addresses == nil || strings.ContainsAny(name, "+*") {
		return triUnknown
	}
	seen := false
	for _, a := range l.Addresses {
		if a.Interface != name {
			continue
		}
		seen = true
		if facts.ClassifyAddress(a.Address) == facts.BindPublic {
			return triYes
		}
	}
	if seen {
		return triNo
	}
	return triUnknown
}

// iptRule is the part of one `iptables -S` rule that DKR-001 understands.
type iptRule struct {
	text    string
	target  string
	iface   string
	ifNeg   bool
	srcSet  bool // a source match that limits who is accepted
	proto   string
	dport   string // after DNAT: the container port
	origDst string // --ctorigdstport: the host port
	states  string
	unsure  []string // options that are not understood
}

// parseIptRule reads one "-A DOCKER-USER ..." line.
func parseIptRule(line string) iptRule {
	r := iptRule{text: line}
	toks := strings.Fields(line)
	if len(toks) >= 2 && toks[0] == "-A" {
		toks = toks[2:]
	}
	neg := false
	next := func(i *int) string {
		*i++
		if *i >= len(toks) {
			return ""
		}
		v := toks[*i]
		if strings.HasPrefix(v, `"`) && (len(v) == 1 || !strings.HasSuffix(v, `"`)) {
			for *i+1 < len(toks) {
				*i++
				if strings.HasSuffix(toks[*i], `"`) {
					break
				}
			}
		}
		return v
	}
	for i := 0; i < len(toks); i++ {
		t := toks[i]
		if t == "!" {
			neg = true
			continue
		}
		switch t {
		case "-i", "--in-interface":
			r.iface, r.ifNeg = next(&i), neg
		case "-s", "--source":
			v := next(&i)
			if !neg && v != "0.0.0.0/0" && v != "::/0" {
				r.srcSet = true
			}
		case "-p", "--protocol":
			v := next(&i)
			if neg {
				r.unsure = append(r.unsure, "! -p")
			} else if v != "all" {
				r.proto = v
			}
		case "--dport", "--destination-port", "--dports":
			r.dport = next(&i)
			if neg {
				r.unsure = append(r.unsure, "! "+t)
			}
		case "--ctorigdstport":
			r.origDst = next(&i)
			if neg {
				r.unsure = append(r.unsure, "! "+t)
			}
		case "--ctstate", "--state":
			r.states = next(&i)
			if neg {
				r.unsure = append(r.unsure, "! "+t)
			}
		case "-m", "--match":
			if m := next(&i); m != "conntrack" && m != "state" && m != "tcp" && m != "udp" && m != "multiport" && m != "comment" {
				r.unsure = append(r.unsure, "-m "+m)
			}
		case "--comment", "--reject-with", "--log-prefix", "--log-level":
			next(&i)
		case "-j", "--jump", "-g", "--goto":
			r.target = next(&i)
		default:
			r.unsure = append(r.unsure, t)
			if i+1 < len(toks) && !strings.HasPrefix(toks[i+1], "-") && toks[i+1] != "!" {
				i++
			}
		}
		neg = false
	}
	return r
}

// portIn reports whether port is in an iptables port spec: "22", "80,443",
// "8000:8100".
func portIn(spec string, port int) bool {
	for _, part := range strings.Split(spec, ",") {
		lo, hi, isRange := strings.Cut(part, ":")
		a, err := strconv.Atoi(lo)
		if err != nil {
			continue
		}
		b := a
		if isRange {
			if b, err = strconv.Atoi(hi); err != nil {
				continue
			}
		}
		if port >= a && port <= b {
			return true
		}
	}
	return false
}

// dockerUserVerdict walks DOCKER-USER in order for a new connection from an
// arbitrary internet source to one published port: the first terminal rule
// that matches decides. A rule limited to some sources, internal
// interfaces, other ports or established traffic does not match. A rule
// stackward does not understand that might match makes the answer unknown.
func dockerUserVerdict(f *facts.Facts, rules []string, proto string, containerPort, hostPort int) (tri, string) {
	for _, line := range rules {
		r := parseIptRule(line)
		switch r.target {
		case "", "LOG", "NFLOG":
			continue
		}
		if r.srcSet {
			continue
		}
		if r.proto != "" && r.proto != proto {
			continue
		}
		if r.dport != "" && !portIn(r.dport, containerPort) {
			continue
		}
		if r.origDst != "" && !portIn(r.origDst, hostPort) {
			continue
		}
		if r.states != "" && !strings.Contains(","+strings.ToUpper(r.states)+",", ",NEW,") {
			continue
		}
		if r.iface != "" {
			pub := ifacePublic(f, r.iface)
			if r.ifNeg {
				pub = map[tri]tri{triYes: triNo, triNo: triYes, triUnknown: triUnknown}[pub]
			}
			switch pub {
			case triNo:
				continue
			case triUnknown:
				return triUnknown, "DOCKER-USER rule " + strconv.Quote(line) + " names an interface stackward cannot classify"
			}
		}
		if len(r.unsure) > 0 {
			return triUnknown, "DOCKER-USER rule " + strconv.Quote(line) + " uses " + strings.Join(r.unsure, ", ") + ", which stackward does not analyse"
		}
		switch r.target {
		case "DROP", "REJECT":
			return triNo, "DOCKER-USER drops it (" + line + ")"
		case "RETURN", "ACCEPT":
			return triYes, "DOCKER-USER lets it through from any source (" + line + ")"
		}
		return triUnknown, "DOCKER-USER jumps to " + r.target + ", which stackward does not analyse"
	}
	return triYes, "no DOCKER-USER rule drops it"
}
