package facts

import (
	"encoding/json"
	"fmt"
	"net/netip"
	"strconv"
	"strings"
)

// This file recognises the DOCKER-USER chain a standard ufw-docker install
// loads (the "BEGIN UFW AND DOCKER" block of /etc/ufw/after.rules, see
// https://github.com/chaifeng/ufw-docker):
//
//	-A DOCKER-USER -j ufw-user-forward
//	-A DOCKER-USER -m conntrack --ctstate RELATED,ESTABLISHED -j RETURN
//	-A DOCKER-USER -m conntrack --ctstate INVALID -j DROP
//	-A DOCKER-USER -i docker0 -o docker0 -j ACCEPT
//	-A DOCKER-USER -s 10.0.0.0/8 -j RETURN            (and 172.16/12, 192.168/16)
//	-A DOCKER-USER -d 10.0.0.0/8 -m conntrack --ctstate NEW -j ufw-docker-logging-deny
//	                                                   (and 172.16/12, 192.168/16)
//	-A DOCKER-USER -j RETURN
//
// Its meaning for a new connection from the internet to a published
// container port: the route rules in ufw-user-forward (`ufw route allow`)
// accept it, otherwise the deny rules drop it because every container
// address is private. The same chain listed by nft on iptables-nft hosts
// reads "jump ufw-user-forward", "ip saddr 10.0.0.0/8 counter return" and
// so on. Small variations are fine (extra private ranges, the RETURN rules
// for private sources in another place, the legacy rules without
// conntrack); anything else is not recognised and stays unknown.

// UFWDockerChain is a DOCKER-USER chain recognised as ufw-docker's.
type UFWDockerChain struct {
	// Source is "iptables" (iptables -S) or "nft" (nft -j list ruleset).
	Source string
	rules  []udRule
}

// udRule is one DOCKER-USER rule, reduced to what ufw-docker uses.
type udRule struct {
	text         string
	target       string // RETURN, ACCEPT, DROP, REJECT or a chain name
	src, dst     netip.Prefix
	iif, oif     string
	states       []string // upper case conntrack states
	proto        string
	sport, dport string // "53", "1024:65535"
	tcpSyn       bool   // --tcp-flags ... SYN: new TCP connections
	unknown      []string
}

// ufwDockerDenyTargets are the targets ufw-docker's deny rules jump to.
var ufwDockerDenyTargets = map[string]bool{
	"DROP": true, "REJECT": true, "ufw-docker-logging-deny": true, "ufw-user-logging-deny": true,
}

// ufwDockerPools are the private ranges container addresses come from:
// Docker's default address pools (172.17.0.0/16 and up, 192.168.0.0/16)
// and the 10.0.0.0/8 range custom pools commonly use.
var ufwDockerPools = []netip.Prefix{
	netip.MustParsePrefix("10.0.0.0/8"),
	netip.MustParsePrefix("172.16.0.0/12"),
	netip.MustParsePrefix("192.168.0.0/16"),
}

// UFWDockerChain returns the DOCKER-USER chain when it is the one
// ufw-docker loads. It returns nil and a reason when the chain jumps to
// ufw-user-forward but holds rules this reading does not understand, and
// nil and "" when there are no DOCKER-USER rules to read (not root, older
// facts) or no jump to ufw-user-forward at all (not ufw-docker).
func (fw *Firewall) UFWDockerChain() (*UFWDockerChain, string) {
	if fw == nil {
		return nil, ""
	}
	var lines []string
	var parse func(string) udRule
	source := ""
	switch {
	case fw.Iptables != nil && fw.Iptables.Listed:
		lines, parse, source = fw.Iptables.DockerUserRules, parseUDIptables, "iptables"
	case fw.NFT != nil && fw.NFT.Listed:
		lines, parse, source = fw.NFT.DockerUserRules, parseUDNFT, "nft"
	default:
		return nil, ""
	}
	c := &UFWDockerChain{Source: source}
	for _, l := range lines {
		c.rules = append(c.rules, parse(l))
	}
	jump := false
	for _, r := range c.rules {
		if r.isRouteJump() {
			jump = true
		}
	}
	if !jump {
		return nil, ""
	}
	if why := c.check(); why != "" {
		return nil, why
	}
	return c, ""
}

func (r udRule) isRouteJump() bool {
	return r.target == ufwForwardTarget && r.plain() && len(r.states) == 0
}

// plain reports whether the rule has no matches besides its states.
func (r udRule) plain() bool {
	return !r.src.IsValid() && !r.dst.IsValid() && r.iif == "" && r.oif == "" && r.proto == "" &&
		r.sport == "" && r.dport == "" && !r.tcpSyn && len(r.unknown) == 0
}

func (r udRule) hasState(s string) bool {
	for _, x := range r.states {
		if x == s {
			return true
		}
	}
	return false
}

// skipsPublicNew reports whether the rule never matches a new connection
// from a public source arriving on a public interface.
func (r udRule) skipsPublicNew() bool {
	if len(r.states) > 0 && !r.hasState("NEW") {
		return true
	}
	if r.iif != "" && InternalInterface(r.iif) {
		return true
	}
	return r.src.IsValid() && privateRange(r.src)
}

// check returns why the chain is not ufw-docker's, or "".
func (c *UFWDockerChain) check() string {
	seenJump, denies := false, false
	for _, r := range c.rules {
		if len(r.unknown) > 0 {
			return fmt.Sprintf("has a rule stackward does not analyse (%s: %s)", r.text, strings.Join(r.unknown, ", "))
		}
		switch {
		case r.isRouteJump():
			seenJump = true
			continue
		case len(r.states) > 0 && !r.hasState("NEW") && r.plain() && oneOf(r.target, "RETURN", "ACCEPT", "DROP", "REJECT"):
			// conntrack bookkeeping: RELATED,ESTABLISHED and INVALID
		case r.iif != "" && r.oif != "" && InternalInterface(r.iif) && InternalInterface(r.oif) &&
			!r.src.IsValid() && !r.dst.IsValid() && r.proto == "" && len(r.states) == 0 && oneOf(r.target, "ACCEPT", "RETURN"):
			// traffic between containers on one bridge
		case r.src.IsValid() && privateRange(r.src) && !r.dst.IsValid() && r.iif == "" && r.oif == "" &&
			r.proto == "" && r.sport == "" && r.dport == "" && oneOf(r.target, "RETURN", "ACCEPT"):
			// traffic from private sources (containers, the LAN)
		case ufwDockerDenyTargets[r.target] && r.dst.IsValid() && privateRange(r.dst) && !r.src.IsValid() &&
			r.iif == "" && r.oif == "" && r.sport == "" && (len(r.states) == 0 || r.hasState("NEW")):
			denies = true
		case r.target == "RETURN" && r.plain() && len(r.states) == 0:
			// the final RETURN
		case r.target == "RETURN" && r.proto == "udp" && r.sport != "" && !r.src.IsValid() && !r.dst.IsValid() &&
			r.iif == "" && r.oif == "" && len(r.states) == 0:
			// the legacy DNS reply rule (--sport 53 --dport 1024:65535)
		default:
			return "has a rule stackward does not analyse (" + r.text + ")"
		}
		if !seenJump && !r.skipsPublicNew() {
			return "decides traffic before it jumps to ufw-user-forward (" + r.text + ")"
		}
	}
	if !denies {
		return "jumps to ufw-user-forward but has no rule that drops new connections to containers"
	}
	return ""
}

// Denies walks the chain for a new connection from a public source to a
// container's proto/port, past the jump to ufw-user-forward (the caller
// judges the route rules there). It reports whether the chain drops the
// connection for containers on every private range, and why.
func (c *UFWDockerChain) Denies(proto string, port int) (bool, string) {
	for _, pool := range ufwDockerPools {
		open, why := c.walk(proto, port, pool)
		if open {
			return false, why
		}
	}
	return true, "ufw-docker drops new connections to containers unless a UFW route rule allows the port"
}

func (c *UFWDockerChain) walk(proto string, port int, pool netip.Prefix) (bool, string) {
	for _, r := range c.rules {
		if r.isRouteJump() || r.skipsPublicNew() {
			continue
		}
		if r.iif != "" || r.oif != "" {
			continue // a bridge to bridge rule never sees outside traffic
		}
		if (r.proto != "" && r.proto != proto) || (r.tcpSyn && proto != "tcp") {
			continue
		}
		if r.dport != "" && !portInSpec(r.dport, port) {
			continue
		}
		if r.dst.IsValid() && !covers(r.dst, pool) {
			continue
		}
		if ufwDockerDenyTargets[r.target] {
			return false, ""
		}
		if r.sport != "" {
			return true, fmt.Sprintf("ufw-docker lets %s/%d through from any source that sends from port %s (%s)", proto, port, r.sport, r.text)
		}
		return true, fmt.Sprintf("ufw-docker's rules do not drop new %s connections to containers on %s", proto, pool)
	}
	return true, fmt.Sprintf("ufw-docker's rules do not drop new %s connections to containers on %s", proto, pool)
}

// portInSpec reports whether port is in "80", "1024:65535" or "1024-65535".
func portInSpec(spec string, port int) bool {
	for _, part := range strings.Split(spec, ",") {
		lo, hi, found := strings.Cut(strings.ReplaceAll(part, "-", ":"), ":")
		a, err := strconv.Atoi(lo)
		if err != nil {
			continue
		}
		b := a
		if found {
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

// privateRange reports whether p lies inside 10/8, 172.16/12 or 192.168/16.
func privateRange(p netip.Prefix) bool {
	for _, pool := range ufwDockerPools {
		if covers(pool, p) {
			return true
		}
	}
	return false
}

// covers reports whether outer contains all of inner.
func covers(outer, inner netip.Prefix) bool {
	return outer.Bits() <= inner.Bits() && outer.Contains(inner.Addr())
}

func oneOf(s string, set ...string) bool {
	for _, x := range set {
		if s == x {
			return true
		}
	}
	return false
}

// internalIfacePrefixes are interfaces that never carry internet traffic
// straight in.
var internalIfacePrefixes = []string{"lo", "docker", "br-", "veth", "tailscale", "wg", "virbr", "cni", "flannel", "cali"}

// InternalInterface reports whether an interface never carries internet
// traffic straight in: loopback, container bridges and veths, VPN links.
func InternalInterface(name string) bool {
	for _, p := range internalIfacePrefixes {
		if strings.HasPrefix(name, p) {
			return true
		}
	}
	return false
}

// parseUDIptables reads one "-A DOCKER-USER ..." line of iptables -S.
func parseUDIptables(line string) udRule {
	r := udRule{text: line}
	t := strings.Fields(line)
	if len(t) >= 2 && t[0] == "-A" {
		t = t[2:]
	}
	arg := func(i *int) string {
		*i++
		if *i < len(t) {
			return t[*i]
		}
		return ""
	}
	for i := 0; i < len(t); i++ {
		switch t[i] {
		case "-j", "--jump", "-g", "--goto":
			r.target = arg(&i)
		case "-s", "--source":
			r.src = parsePrefix(arg(&i), &r)
		case "-d", "--destination":
			r.dst = parsePrefix(arg(&i), &r)
		case "-i", "--in-interface":
			r.iif = arg(&i)
		case "-o", "--out-interface":
			r.oif = arg(&i)
		case "-p", "--protocol":
			r.proto = arg(&i)
		case "-m", "--match":
			switch m := arg(&i); m {
			case "conntrack", "state", "tcp", "udp", "comment":
			default:
				r.unknown = append(r.unknown, "-m "+m)
			}
		case "--comment":
			skipQuoted(t, &i)
		case "--ctstate", "--state":
			r.states = strings.Split(strings.ToUpper(arg(&i)), ",")
		case "--sport", "--source-port":
			r.sport = arg(&i)
		case "--dport", "--destination-port":
			r.dport = arg(&i)
		case "--tcp-flags":
			mask, comp := arg(&i), arg(&i)
			if strings.Contains(mask, "SYN") && comp == "SYN" {
				r.tcpSyn = true
			} else {
				r.unknown = append(r.unknown, "--tcp-flags "+mask+" "+comp)
			}
		default:
			r.unknown = append(r.unknown, t[i])
		}
	}
	return r
}

// skipQuoted moves past a quoted argument that may span tokens.
func skipQuoted(t []string, i *int) {
	*i++
	if *i >= len(t) || !strings.HasPrefix(t[*i], `"`) {
		return
	}
	if len(t[*i]) > 1 && strings.HasSuffix(t[*i], `"`) {
		return
	}
	for *i+1 < len(t) {
		*i++
		if strings.HasSuffix(t[*i], `"`) {
			return
		}
	}
}

func parsePrefix(s string, r *udRule) netip.Prefix {
	if !strings.Contains(s, "/") {
		s += "/32"
	}
	p, err := netip.ParsePrefix(s)
	if err != nil {
		r.unknown = append(r.unknown, "address "+s)
		return netip.Prefix{}
	}
	return p.Masked()
}

// parseUDNFT reads one DOCKER-USER rule in nft syntax, as renderNFTRule
// writes it or `nft list chain ip filter DOCKER-USER` prints it.
func parseUDNFT(line string) udRule {
	r := udRule{text: line}
	t := strings.Fields(line)
	arg := func(i *int) string {
		*i++
		if *i < len(t) {
			return strings.Trim(t[*i], `"`)
		}
		return ""
	}
	// value reads a match value, noting a negation.
	value := func(i *int) string {
		v := arg(i)
		if v == "!=" {
			r.unknown = append(r.unknown, "!=")
			v = arg(i)
		}
		return v
	}
	for i := 0; i < len(t); i++ {
		switch t[i] {
		case "ip":
			switch f := arg(&i); f {
			case "saddr":
				r.src = parsePrefix(value(&i), &r)
			case "daddr":
				r.dst = parsePrefix(value(&i), &r)
			default:
				r.unknown = append(r.unknown, "ip "+f)
			}
		case "iifname", "iif":
			r.iif = value(&i)
		case "oifname", "oif":
			r.oif = value(&i)
		case "ct":
			if f := arg(&i); f != "state" {
				r.unknown = append(r.unknown, "ct "+f)
				continue
			}
			r.states = strings.Split(strings.ToUpper(strings.Trim(value(&i), "{}")), ",")
		case "meta":
			if f := arg(&i); f != "l4proto" {
				r.unknown = append(r.unknown, "meta "+f)
				continue
			}
			r.proto = value(&i)
		case "tcp", "udp":
			r.proto = t[i]
			switch f := arg(&i); f {
			case "sport":
				r.sport = value(&i)
			case "dport":
				r.dport = value(&i)
			default:
				r.unknown = append(r.unknown, t[i-1]+" "+f)
			}
		case "counter":
			// "counter packets 0 bytes 0"
			for i+2 < len(t) && (t[i+1] == "packets" || t[i+1] == "bytes") {
				i += 2
			}
		case "accept", "drop", "reject", "return":
			r.target = strings.ToUpper(t[i])
		case "jump", "goto":
			r.target = arg(&i)
		default:
			r.unknown = append(r.unknown, t[i])
		}
	}
	return r
}

// renderNFTRule writes a rule of `nft -j list ruleset` in nft's own
// syntax, for the expressions ufw-docker's rules use. Anything else turns
// into "?<name>", which parseUDNFT does not understand.
func renderNFTRule(expr []map[string]json.RawMessage) string {
	var out []string
	for _, e := range expr {
		for k, v := range e {
			switch k {
			case "match":
				out = append(out, renderNFTMatch(v))
			case "counter":
				// counters say nothing about the verdict
			case "accept", "drop", "return", "reject":
				out = append(out, k)
			case "jump", "goto":
				var j struct{ Target string }
				if json.Unmarshal(v, &j) != nil || j.Target == "" {
					out = append(out, "?"+k)
					continue
				}
				out = append(out, k+" "+j.Target)
			default:
				out = append(out, "?"+k)
			}
		}
	}
	return strings.Join(out, " ")
}

func renderNFTMatch(raw json.RawMessage) string {
	var m struct {
		Op    string
		Left  map[string]json.RawMessage
		Right json.RawMessage
	}
	if json.Unmarshal(raw, &m) != nil {
		return "?match"
	}
	left := ""
	switch {
	case m.Left["payload"] != nil:
		var p struct{ Protocol, Field string }
		if json.Unmarshal(m.Left["payload"], &p) != nil {
			return "?match"
		}
		left = p.Protocol + " " + p.Field
	case m.Left["meta"] != nil:
		var p struct{ Key string }
		if json.Unmarshal(m.Left["meta"], &p) != nil {
			return "?match"
		}
		left = p.Key
		if p.Key == "l4proto" || p.Key == "protocol" {
			left = "meta " + p.Key
		}
	case m.Left["ct"] != nil:
		var p struct{ Key string }
		if json.Unmarshal(m.Left["ct"], &p) != nil {
			return "?match"
		}
		left = "ct " + p.Key
	default:
		return "?match"
	}
	right := renderNFTValue(m.Right)
	if right == "" {
		return "?match"
	}
	switch m.Op {
	case "", "==", "in":
		return left + " " + right
	case "!=":
		return left + " != " + right
	}
	return "?match"
}

func renderNFTValue(raw json.RawMessage) string {
	var s string
	if json.Unmarshal(raw, &s) == nil {
		return s
	}
	var n json.Number
	if json.Unmarshal(raw, &n) == nil {
		return n.String()
	}
	var list []json.RawMessage
	if json.Unmarshal(raw, &list) == nil {
		var parts []string
		for _, x := range list {
			v := renderNFTValue(x)
			if v == "" {
				return ""
			}
			parts = append(parts, v)
		}
		return strings.Join(parts, ",")
	}
	var obj map[string]json.RawMessage
	if json.Unmarshal(raw, &obj) != nil {
		return ""
	}
	switch {
	case obj["prefix"] != nil:
		var p struct {
			Addr string
			Len  int
		}
		if json.Unmarshal(obj["prefix"], &p) != nil {
			return ""
		}
		return fmt.Sprintf("%s/%d", p.Addr, p.Len)
	case obj["set"] != nil:
		return renderNFTValue(obj["set"])
	case obj["range"] != nil:
		var r []json.RawMessage
		if json.Unmarshal(obj["range"], &r) != nil || len(r) != 2 {
			return ""
		}
		return renderNFTValue(r[0]) + "-" + renderNFTValue(r[1])
	}
	return ""
}
