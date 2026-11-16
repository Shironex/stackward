package checks

import (
	"fmt"
	"net/netip"
	"sort"
	"strings"

	"github.com/Shironex/stackward/internal/facts"
)

// The PFW group judges the provider firewall that the opt in provider client
// read (facts.ProviderFirewall). This file holds the shared parts: the gate
// every PFW check passes through and the evaluation of a packet against a
// rule list. The checks themselves are in pfw_checks.go.

// worldPrefixBits is the widest source prefix that is not "the world": a
// rule whose source is this wide or wider (a /8, a /0) counts as open to
// anywhere. One constant so every PFW check agrees.
const worldPrefixBits = 8

// ephemeralPort stands for the port a reply comes back to: inside the Linux
// ephemeral range (32768 to 60999).
const ephemeralPort = 40000

// wideRange is the number of ports from which a UDP range counts as wide.
const wideRange = 1000

// anySrcPort is the source port of a packet whose sender did not pick one to
// match a source port rule. It lies outside every port range, 0 included.
const anySrcPort = -1

// packet is one kind of inbound packet from a sender anywhere on the
// internet, as the PFW checks ask about it.
type packet struct {
	proto string // "tcp" or "udp"
	dst   int
	src   int // anySrcPort: matches no source port rule
	// established is true for a TCP packet with ACK set (a reply).
	established bool
	// blockIsFinding is set by the checks whose finding is a packet being
	// dropped (the reply checks); it swaps the source predicates.
	blockIsFinding bool
}

// Sources are read with two predicates that err in opposite directions, so
// a doubtful source leans toward a finding in every check. Where a packet
// getting in is the finding (PFW-002 to PFW-005), a permit counts with
// looseWorld and a deny with exactWorld. Where a packet being dropped is the
// finding (the reply checks in PFW-007), the two swap: a deny counts with
// looseWorld and a permit with exactWorld, and a deny whose sources all lie
// in reserved space (onlyReserved) does not count, since no internet reply
// comes from there. Pending rules follow the same split (inForceFor).

// looseWorld reports whether sources may cover a sender anywhere: no
// source, a source of /8 or wider, or a source that does not parse.
func looseWorld(sources []string) bool {
	if len(sources) == 0 {
		return true
	}
	for _, s := range sources {
		p, err := parseSource(s)
		if err != nil || p.Bits() <= worldPrefixBits {
			return true
		}
	}
	return false
}

// exactWorld reports whether sources surely cover every IPv4 sender (the
// packets the checks simulate are IPv4): no source, or 0.0.0.0/0 or
// ::ffff:0.0.0.0/96. A narrower, IPv6 only or unparsable source never
// counts.
func exactWorld(sources []string) bool {
	if len(sources) == 0 {
		return true
	}
	for _, s := range sources {
		if p, err := parseSource(s); err == nil && p.Addr().Is4() && p.Bits() == 0 {
			return true
		}
	}
	return false
}

// parseSource parses a CIDR source and unmaps an IPv4-mapped IPv6 prefix
// (::ffff:0.0.0.0/96 is all of IPv4).
func parseSource(s string) (netip.Prefix, error) {
	p, err := netip.ParsePrefix(s)
	if err != nil {
		return p, err
	}
	if a := p.Addr(); a.Is4In6() && p.Bits() >= 96 {
		return netip.PrefixFrom(a.Unmap(), p.Bits()-96), nil
	}
	return p, nil
}

// fromWorld picks the predicate for r's action and what p's check counts
// as a finding.
func fromWorld(r facts.ProviderRule, p packet) bool {
	if p.blockIsFinding && r.Action == "deny" && onlyReserved(r.Sources) {
		return false
	}
	if (r.Action == "permit") != p.blockIsFinding {
		return looseWorld(r.Sources)
	}
	return exactWorld(r.Sources)
}

func portsMatch(ranges []facts.PortRange, port int) bool {
	if len(ranges) == 0 {
		return true
	}
	if port == anySrcPort {
		return false
	}
	for _, r := range ranges {
		if port >= r.From && port <= r.To {
			return true
		}
	}
	return false
}

// inForce reports whether r is an inbound rule the checks count where a
// packet getting in is the finding: a pending permit counts (it may already
// let traffic in, or will shortly) and a pending deny does not (it may not
// block anything yet).
func inForce(r facts.ProviderRule) bool {
	return r.Direction == "in" && (!r.Pending || r.Action == "permit")
}

// inForceFor is inForce for p's check. Where a dropped packet is the
// finding (the reply checks) it swaps: a pending deny counts and a pending
// permit does not.
func inForceFor(r facts.ProviderRule, p packet) bool {
	return r.Direction == "in" && (!r.Pending || (r.Action == "permit") != p.blockIsFinding)
}

// reservedV4 is address space no internet reply comes from: this network,
// private, shared (CGNAT), loopback, link local, multicast and reserved.
var reservedV4 = []netip.Prefix{
	netip.MustParsePrefix("0.0.0.0/8"),
	netip.MustParsePrefix("10.0.0.0/8"),
	netip.MustParsePrefix("100.64.0.0/10"),
	netip.MustParsePrefix("127.0.0.0/8"),
	netip.MustParsePrefix("169.254.0.0/16"),
	netip.MustParsePrefix("172.16.0.0/12"),
	netip.MustParsePrefix("192.168.0.0/16"),
	netip.MustParsePrefix("224.0.0.0/4"),
	netip.MustParsePrefix("240.0.0.0/4"),
}

// onlyReserved reports whether every source lies inside reserved space, so
// a deny from it never drops a reply from the internet. An empty or
// unparsable source is not reserved.
func onlyReserved(sources []string) bool {
	if len(sources) == 0 {
		return false
	}
	for _, s := range sources {
		p, err := parseSource(s)
		if err != nil || !p.Addr().Is4() || !insideReserved(p) {
			return false
		}
	}
	return true
}

func insideReserved(p netip.Prefix) bool {
	for _, r := range reservedV4 {
		if r.Bits() <= p.Bits() && r.Contains(p.Addr()) {
			return true
		}
	}
	return false
}

// matches reports whether r matches p from a sender anywhere.
func matches(r facts.ProviderRule, p packet) bool {
	if !inForceFor(r, p) || r.Fragments || !fromWorld(r, p) {
		return false
	}
	if r.Protocol != "ipv4" && r.Protocol != p.proto {
		return false
	}
	switch r.TCPOption {
	case "established":
		if p.proto != "tcp" || !p.established {
			return false
		}
	case "syn":
		if p.proto != "tcp" || p.established {
			return false
		}
	}
	if r.Protocol == "ipv4" {
		return len(r.DstPorts) == 0 && len(r.SrcPorts) == 0
	}
	return portsMatch(r.DstPorts, p.dst) && portsMatch(r.SrcPorts, p.src)
}

// sortedRules returns the rules in evaluation order.
func sortedRules(t facts.ProviderTarget) []facts.ProviderRule {
	rs := append([]facts.ProviderRule(nil), t.Rules...)
	sort.SliceStable(rs, func(i, j int) bool { return rs[i].Order < rs[j].Order })
	return rs
}

// verdict says whether the enabled firewall of t lets p in, and the rule
// that decided, nil when the default did. Ordered lists take the first
// match; unordered ones (Hetzner, permit only) let p in when any rule
// permits it.
func verdict(t facts.ProviderTarget, p packet) (bool, *facts.ProviderRule) {
	rs := sortedRules(t)
	if t.Ordered {
		for i := range rs {
			if matches(rs[i], p) {
				return rs[i].Action == "permit", &rs[i]
			}
		}
		return t.DefaultInbound != "deny", nil
	}
	var deny *facts.ProviderRule
	for i := range rs {
		if !matches(rs[i], p) {
			continue
		}
		if rs[i].Action == "permit" {
			return true, &rs[i]
		}
		deny = &rs[i]
	}
	if deny != nil {
		return false, deny
	}
	return t.DefaultInbound != "deny", nil
}

// chosenSrcPorts are the source ports a sender anywhere may pick to match a
// source port rule. A stateless filter cannot tell a reply from a packet a
// sender crafted with that source port. Which rule a packet meets only
// changes at the edges of the source port ranges, so trying anySrcPort and,
// for every counted rule's range, its first and last port and the ports
// just outside it covers every case (a permit for 1000-2000 behind a deny
// for 1000 is reached from 1001).
func chosenSrcPorts(t facts.ProviderTarget, proto string) []int {
	out := []int{anySrcPort}
	seen := map[int]bool{anySrcPort: true}
	add := func(p int) {
		if p >= 0 && p <= 65535 && !seen[p] {
			seen[p] = true
			out = append(out, p)
		}
	}
	for _, r := range sortedRules(t) {
		if !inForce(r) || len(r.SrcPorts) == 0 || (r.Protocol != proto && r.Protocol != "ipv4") {
			continue
		}
		for _, pr := range r.SrcPorts {
			add(pr.From)
			add(pr.To)
			add(pr.From - 1)
			add(pr.To + 1)
		}
	}
	return out
}

// reachable says whether a sender anywhere, free to pick its source port,
// gets p (a new connection or datagram) in, the rule that let it in and the
// source port it used (anySrcPort when any port works).
func reachable(t facts.ProviderTarget, p packet) (bool, *facts.ProviderRule, int) {
	for _, src := range chosenSrcPorts(t, p.proto) {
		q := p
		q.src = src
		if ok, r := verdict(t, q); ok {
			return true, r, src
		}
	}
	return false, nil, anySrcPort
}

// viaLabel names the rule and, when it took a crafted source port, the
// port.
func viaLabel(t facts.ProviderTarget, r *facts.ProviderRule, src int) string {
	if src == anySrcPort {
		return ruleLabel(t, r)
	}
	return fmt.Sprintf("%s, from source port %d", ruleLabel(t, r), src)
}

// unusedPort returns a port no rule names, so a packet to it only meets
// rules that cover every port.
func unusedPort(t facts.ProviderTarget) int {
	for _, p := range []int{33434, 40001, 51234, 61999, 9} {
		used := false
		for _, r := range t.Rules {
			if len(r.DstPorts) > 0 && portsMatch(r.DstPorts, p) {
				used = true
				break
			}
		}
		if !used {
			return p
		}
	}
	return 65000
}

// ruleLabel names a rule the way its provider does.
func ruleLabel(t facts.ProviderTarget, r *facts.ProviderRule) string {
	if r == nil {
		return "the default"
	}
	if t.Ordered {
		return fmt.Sprintf("seq %d", r.Order)
	}
	return fmt.Sprintf("rule %d", r.Order)
}

func portList(rs []facts.PortRange) string {
	parts := make([]string, 0, len(rs))
	for _, r := range rs {
		parts = append(parts, r.String())
	}
	return strings.Join(parts, ",")
}

// describeRule is one line for PFW-008 and evidence.
func describeRule(t facts.ProviderTarget, r facts.ProviderRule) string {
	var b strings.Builder
	fmt.Fprintf(&b, "%s: %s %s %s", ruleLabel(t, &r), r.Direction, r.Action, r.Protocol)
	if r.TCPOption != "" {
		b.WriteString(" " + r.TCPOption)
	}
	if r.Fragments {
		b.WriteString(" fragments")
	}
	if r.Direction == "out" {
		dst := "anywhere"
		if len(r.Destinations) > 0 {
			dst = strings.Join(r.Destinations, ", ")
		}
		b.WriteString(" to " + dst)
	} else {
		src := "anywhere"
		if len(r.Sources) > 0 {
			src = strings.Join(r.Sources, ", ")
		}
		b.WriteString(" from " + src)
	}
	if len(r.SrcPorts) > 0 {
		b.WriteString(" source port " + portList(r.SrcPorts))
	}
	if len(r.DstPorts) > 0 {
		b.WriteString(" to port " + portList(r.DstPorts))
	}
	switch {
	case r.Pending && r.Action == "permit":
		b.WriteString(" (pending; counts as open, not as letting replies in)")
	case r.Pending:
		b.WriteString(" (pending; counts as dropping replies, not as blocking)")
	}
	return b.String()
}

// pfwSubject names the address a result is about.
func pfwSubject(t facts.ProviderTarget) string { return "address:" + t.Address }

// pfwNeeds says what a PFW check needs from a target before it can judge.
type pfwNeeds struct {
	enabled bool // a firewall in force
	rules   bool // every rule read
}

// pfwEach runs judge once per matched address, after the gate: no module
// result, a provider status other than ok, a target status other than ok,
// and (as needs asks) a firewall that is not in force or a partial rule
// read all answer for the check instead.
func pfwEach(in Input, needs pfwNeeds, judge func(*facts.ProviderFirewall, facts.ProviderTarget) Result) []Result {
	pf := in.Facts.ProviderFirewall
	if r, stop := pfwGate(pf); stop {
		return []Result{r}
	}
	out := make([]Result, 0, len(pf.Targets))
	for _, t := range pf.Targets {
		ev := map[string]any{"provider": pf.Provider, "address": t.Address, "status": string(t.Status)}
		r := Result{Subject: pfwSubject(t), Evidence: ev}
		switch {
		case t.Status != facts.ProviderOK:
			r.Level, r.Message = Unknown, targetUnknown(t)
		case needs.enabled && !t.Enabled:
			r.Level, r.Message = Skip, "no provider firewall is in force for this address (see PFW-001)"
		case needs.rules && !t.RulesComplete:
			r.Level, r.Message = Unknown, "some firewall rules could not be read; a judgement from part of them would mislead"
		default:
			r = judge(pf, t)
			r.Subject = pfwSubject(t)
		}
		out = append(out, r)
	}
	return out
}

// pfwGate answers for a module that did not run or did not reach any
// address.
func pfwGate(pf *facts.ProviderFirewall) (Result, bool) {
	if pf == nil {
		return Result{Level: Skip, Message: "provider firewall not checked; run the audit with --provider and a read only token to read it over the provider's API (docs/provider-firewall.md)",
			Evidence: map[string]any{"provider": "none", "status": "not_requested"}}, true
	}
	ev := map[string]any{"provider": pf.Provider, "status": string(pf.Status)}
	if pf.Status != facts.ProviderOK {
		return Result{Level: Unknown, Message: fmt.Sprintf("the %s firewall was not read (%s): %s", pf.Provider, pf.Status, valueOrUnknown(pf.Reason)),
			Evidence: ev}, true
	}
	if len(pf.Targets) == 0 {
		return Result{Level: Unknown, Message: fmt.Sprintf("the %s API was asked about no address", pf.Provider), Evidence: ev}, true
	}
	return Result{}, false
}

func targetUnknown(t facts.ProviderTarget) string {
	if t.Status == facts.ProviderNoMatch {
		return "no resource of this account has this address (it may belong to another account or project); not a verdict on its firewall"
	}
	return fmt.Sprintf("the provider firewall for this address was not read (%s): %s", t.Status, valueOrUnknown(t.Reason))
}

// pfwResult builds a judged result with the shared evidence keys.
func pfwResult(pf *facts.ProviderFirewall, t facts.ProviderTarget, level Level, msg string, extra map[string]any) Result {
	ev := map[string]any{"provider": pf.Provider, "address": t.Address, "status": string(t.Status)}
	for k, v := range extra {
		ev[k] = v
	}
	return Result{Level: level, Message: msg, Evidence: ev}
}

// inboundRules counts the inbound rules of t, in force or not.
func inboundRules(t facts.ProviderTarget) int {
	n := 0
	for _, r := range t.Rules {
		if r.Direction == "in" {
			n++
		}
	}
	return n
}
