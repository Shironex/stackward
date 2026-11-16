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
// match a source port rule.
const anySrcPort = 0

// packet is one kind of inbound packet from a sender anywhere on the
// internet, as the PFW checks ask about it.
type packet struct {
	proto string // "tcp" or "udp"
	dst   int
	src   int // anySrcPort: matches no source port rule
	// established is true for a TCP packet with ACK set (a reply).
	established bool
}

// worldSource reports whether sources reach anywhere: no source means any.
func worldSource(sources []string) bool {
	if len(sources) == 0 {
		return true
	}
	for _, s := range sources {
		if s == "any" {
			return true
		}
		p, err := netip.ParsePrefix(s)
		if err != nil {
			continue
		}
		if p.Bits() <= worldPrefixBits {
			return true
		}
	}
	return false
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

// inForce reports whether r is an inbound rule that filters now.
func inForce(r facts.ProviderRule) bool { return r.Direction == "in" && !r.Pending }

// matches reports whether r matches p from a sender anywhere.
func matches(r facts.ProviderRule, p packet) bool {
	if !inForce(r) || r.Fragments || !worldSource(r.Sources) {
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
	if r.Pending {
		b.WriteString(" (pending, not in force)")
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
		return Result{Level: Unknown, Message: "provider firewall not requested; run the audit with --provider to read it over the provider's API",
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
