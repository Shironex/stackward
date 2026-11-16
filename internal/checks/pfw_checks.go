package checks

import (
	"fmt"
	"strings"

	"github.com/Shironex/stackward/internal/facts"
	"github.com/Shironex/stackward/internal/profile"
)

func init() {
	// Without --provider only PFW-001 reports, with one skip row that says
	// how to enable the module; the others leave no row.
	Register(Check{ID: "PFW-001", Run: checkPFWAttached})
	Register(Check{ID: "PFW-002", Run: checkPFWDefaultDeny, Absent: pfwNotRequested})
	Register(Check{ID: "PFW-003", Run: checkPFWOpenUDP, Absent: pfwNotRequested})
	Register(Check{ID: "PFW-004", Run: checkPFWStaleRules, Absent: pfwNotRequested})
	Register(Check{ID: "PFW-005", Run: checkPFWSSH, Absent: pfwNotRequested})
	Register(Check{ID: "PFW-006", Run: checkPFWIPv6, Absent: pfwNotRequested})
	Register(Check{ID: "PFW-007", Run: checkPFWReturnTraffic, Absent: pfwNotRequested})
	Register(Check{ID: "PFW-008", Run: checkPFWRules, Absent: pfwNotRequested})
}

// pfwNotRequested is true when the provider module did not run.
func pfwNotRequested(in Input) bool { return in.Facts == nil || in.Facts.ProviderFirewall == nil }

// tunnelState is profile.TunnelState, swapped in tests.
var tunnelState = profile.TunnelState

func checkPFWAttached(in Input) []Result {
	return pfwEach(in, pfwNeeds{}, func(pf *facts.ProviderFirewall, t facts.ProviderTarget) Result {
		ev := map[string]any{"attached": t.Attached, "enabled": t.Enabled, "state": t.State, "firewalls": t.Firewalls,
			"inbound_rules": inboundRules(t), "pending": t.Pending}
		pending := ""
		if t.Pending {
			pending = "; a change is pending and not in force yet"
		}
		switch {
		case !t.Attached:
			return pfwResult(pf, t, Fail, "no provider firewall is attached to this address"+pending, ev)
		case !t.Enabled && t.Pending:
			return pfwResult(pf, t, Fail, fmt.Sprintf("a provider firewall is attached but not in force (state %s)%s", valueOrUnknown(t.State), pending), ev)
		case !t.Enabled && inboundRules(t) > 0:
			return pfwResult(pf, t, Warn, fmt.Sprintf("the provider firewall has %d inbound rules but is disabled, so it filters only while the provider switches it on during a detected attack", inboundRules(t)), ev)
		case !t.Enabled:
			return pfwResult(pf, t, Fail, "the provider firewall exists but is disabled and has no rules", ev)
		}
		return pfwResult(pf, t, Pass, fmt.Sprintf("%d provider firewall(s) in force with %d inbound rules%s", t.Firewalls, inboundRules(t), pending), ev)
	})
}

// catchAllDeny returns the first in force rule that denies every IPv4
// packet from anywhere.
func catchAllDeny(t facts.ProviderTarget) *facts.ProviderRule {
	rs := sortedRules(t)
	for i, r := range rs {
		if inForce(r) && r.Action == "deny" && r.Protocol == "ipv4" && denyFromWorld(r.Sources) &&
			len(r.DstPorts) == 0 && len(r.SrcPorts) == 0 && r.TCPOption == "" && !r.Fragments {
			return &rs[i]
		}
	}
	return nil
}

func checkPFWDefaultDeny(in Input) []Result {
	return pfwEach(in, pfwNeeds{enabled: true, rules: true}, func(pf *facts.ProviderFirewall, t facts.ProviderTarget) Result {
		ev := map[string]any{"default_inbound": t.DefaultInbound, "ordered": t.Ordered, "catch_all_deny": "", "tcp_open_by": ""}
		// A permit that matches only a source port lets a sender who picks
		// that port reach every TCP port, whatever the final deny says.
		if ok, r, src := reachable(t, packet{proto: "tcp", dst: unusedPort(t), src: anySrcPort}); ok {
			ev["tcp_open_by"] = viaLabel(t, r, src)
			if src != anySrcPort {
				return pfwResult(pf, t, Fail, fmt.Sprintf("every TCP port is reachable from anywhere by a sender that picks source port %d (%s); a stateless firewall cannot tell that from a reply", src, ruleLabel(t, r)), ev)
			}
			if t.DefaultInbound == "deny" || catchAllDeny(t) != nil {
				return pfwResult(pf, t, Fail, fmt.Sprintf("every TCP port is reachable from anywhere (%s)", ruleLabel(t, r)), ev)
			}
		}
		if d := catchAllDeny(t); d != nil {
			ev["catch_all_deny"] = ruleLabel(t, d)
			return pfwResult(pf, t, Pass, fmt.Sprintf("inbound is default deny: %s denies every packet no earlier rule permits", ruleLabel(t, d)), ev)
		}
		if t.DefaultInbound == "deny" {
			return pfwResult(pf, t, Pass, "inbound is default deny: traffic no rule permits is dropped", ev)
		}
		return pfwResult(pf, t, Fail, "the provider firewall has no catch-all deny rule, so inbound traffic no rule matches is allowed", ev)
	})
}

func checkPFWOpenUDP(in Input) []Result {
	return pfwEach(in, pfwNeeds{enabled: true, rules: true}, func(pf *facts.ProviderFirewall, t facts.ProviderTarget) Result {
		ev := map[string]any{"all_udp_by": "", "wide_ranges": []string{}, "source_port_only": []string{}}
		if ok, r := verdict(t, packet{proto: "udp", dst: unusedPort(t), src: anySrcPort}); ok {
			ev["all_udp_by"] = ruleLabel(t, r)
			return pfwResult(pf, t, Fail, fmt.Sprintf("UDP to every port is allowed from anywhere (%s)", ruleLabel(t, r)), ev)
		}
		var wide, srcOnly []string
		for _, r := range sortedRules(t) {
			if !inForce(r) || r.Action != "permit" || (r.Protocol != "udp") || !permitFromWorld(r.Sources) {
				continue
			}
			if len(r.DstPorts) == 0 && len(r.SrcPorts) > 0 {
				if liveForSomeSrcPort(t, r) {
					srcOnly = append(srcOnly, fmt.Sprintf("%s (source port %s)", ruleLabel(t, &r), portList(r.SrcPorts)))
				}
				continue
			}
			if rangeSize(r.DstPorts) >= wideRange {
				wide = append(wide, fmt.Sprintf("%s (ports %s)", ruleLabel(t, &r), portList(r.DstPorts)))
			}
		}
		ev["wide_ranges"], ev["source_port_only"] = nonNil(wide), nonNil(srcOnly)
		var parts []string
		if len(wide) > 0 {
			parts = append(parts, "wide UDP port ranges are open to anywhere: "+strings.Join(wide, ", "))
		}
		if len(srcOnly) > 0 {
			parts = append(parts, "rules that match only a source port let any sender reach every UDP port by choosing that source port: "+strings.Join(srcOnly, ", "))
		}
		if len(parts) > 0 {
			return pfwResult(pf, t, Warn, strings.Join(parts, "; "), ev)
		}
		return pfwResult(pf, t, Pass, "no inbound rule allows all UDP from anywhere", ev)
	})
}

// liveForSomeSrcPort reports whether a UDP packet to an unused port, from
// some source port a sender may pick inside r's ranges, is let in by r.
func liveForSomeSrcPort(t facts.ProviderTarget, r facts.ProviderRule) bool {
	for _, src := range chosenSrcPorts(t, "udp") {
		if !portsMatch(r.SrcPorts, src) {
			continue
		}
		if ok, by := verdict(t, packet{proto: "udp", dst: unusedPort(t), src: src}); ok && by != nil && by.Order == r.Order {
			return true
		}
	}
	return false
}

func rangeSize(rs []facts.PortRange) int {
	if len(rs) == 0 {
		return 65535
	}
	n := 0
	for _, r := range rs {
		n += r.To - r.From + 1
	}
	return n
}

// maxEnumerated is the largest rule range whose ports are checked one by
// one for a service; a larger range needs one service anywhere in it.
const maxEnumerated = 64

func checkPFWStaleRules(in Input) []Result {
	f := in.Facts
	return pfwEach(in, pfwNeeds{enabled: true, rules: true}, func(pf *facts.ProviderFirewall, t facts.ProviderTarget) Result {
		ev := map[string]any{"without_service": []string{}, "listeners_read": f.Listeners != nil}
		if f.Listeners == nil {
			return pfwResult(pf, t, Info, "the listening sockets could not be read, so whether a service sits behind each permitted port is unknown", ev)
		}
		var stale []string
		for _, r := range sortedRules(t) {
			if !inForce(r) || r.Action != "permit" || (r.Protocol != "tcp" && r.Protocol != "udp") ||
				len(r.DstPorts) == 0 || r.TCPOption == "established" {
				continue
			}
			for _, pr := range r.DstPorts {
				stale = append(stale, rangeWithoutService(f, r.Protocol, pr)...)
			}
		}
		stale = dedupe(stale)
		ev["without_service"] = nonNil(stale)
		if len(stale) > 0 {
			return pfwResult(pf, t, Warn, "the provider firewall permits ports with no service listening on the host (a stale rule, or a service that is down): "+strings.Join(stale, ", "), ev)
		}
		return pfwResult(pf, t, Pass, "every port the provider firewall permits has a service listening on the host", ev)
	})
}

// rangeWithoutService lists the ports of pr with no reachable service, or
// the whole range when it is large and nothing listens in it.
func rangeWithoutService(f *facts.Facts, proto string, pr facts.PortRange) []string {
	if pr.To-pr.From+1 > maxEnumerated {
		for p := pr.From; p <= pr.To; p++ {
			if served(f, proto, p) {
				return nil
			}
		}
		return []string{proto + "/" + pr.String()}
	}
	var out []string
	for p := pr.From; p <= pr.To; p++ {
		if !served(f, proto, p) {
			out = append(out, portLabel(proto, p))
		}
	}
	return out
}

// served reports whether something outside loopback listens on proto/port,
// or a container publishes it.
func served(f *facts.Facts, proto string, port int) bool {
	for _, s := range f.Listeners.Sockets {
		if s.Proto == proto && s.Port == port && s.Class() != facts.BindLoopback {
			return true
		}
	}
	return len(f.Docker.Publishing(proto, "0.0.0.0", port)) > 0
}

func dedupe(s []string) []string {
	seen := map[string]bool{}
	var out []string
	for _, v := range s {
		if !seen[v] {
			seen[v] = true
			out = append(out, v)
		}
	}
	return out
}

func checkPFWSSH(in Input) []Result {
	f := in.Facts
	return pfwEach(in, pfwNeeds{enabled: true, rules: true}, func(pf *facts.ProviderFirewall, t facts.ProviderTarget) Result {
		ports := []int{22}
		if f.Listeners != nil {
			ports = sshPorts(f.Listeners)
		}
		var open []string
		for _, p := range ports {
			if ok, r, src := reachable(t, packet{proto: "tcp", dst: p, src: anySrcPort}); ok {
				open = append(open, fmt.Sprintf("tcp/%d (%s)", p, viaLabel(t, r, src)))
			}
		}
		running, known := tailnetState(f)
		ev := map[string]any{"ssh_ports": ports, "open_to_anywhere": nonNil(open), "tailnet": tailnetWord(running, known)}
		where := strings.Join(open, ", ")
		switch {
		case len(open) == 0:
			return pfwResult(pf, t, Pass, "the provider firewall does not let SSH in from anywhere", ev)
		case running:
			return pfwResult(pf, t, Fail, "the provider firewall lets SSH in from anywhere on "+where+" although Tailscale offers a private path", ev)
		case !known:
			return pfwResult(pf, t, Warn, "the provider firewall lets SSH in from anywhere on "+where+"; whether a private path (tailnet) exists is unknown", ev)
		}
		return pfwResult(pf, t, Warn, "the provider firewall lets SSH in from anywhere on "+where+" and no private path (tailnet) exists", ev)
	})
}

func checkPFWIPv6(in Input) []Result {
	f := in.Facts
	return pfwEach(in, pfwNeeds{}, func(pf *facts.ProviderFirewall, t facts.ProviderTarget) Result {
		ev := map[string]any{"ipv6_filtered": pf.IPv6Filtered, "host_global_ipv6": "unknown", "host_firewall": "unknown"}
		has, known := f.Listeners.HasGlobalIPv6()
		if !known {
			return pfwResult(pf, t, Unknown, "the host's interface addresses were not read, so whether it has a global IPv6 address is unknown", ev)
		}
		ev["host_global_ipv6"] = has
		switch {
		case !has:
			return pfwResult(pf, t, Pass, "the host has no global IPv6 address", ev)
		case pf.IPv6Filtered && t.Enabled:
			return pfwResult(pf, t, Pass, "the provider firewall filters IPv6 as well as IPv4", ev)
		case pf.IPv6Filtered:
			return pfwResult(pf, t, Skip, "no provider firewall is in force for this address (see PFW-001)", ev)
		case f.Firewall == nil:
			return pfwResult(pf, t, Unknown, "the provider firewall cannot filter IPv6 and the host firewall was not read", ev)
		}
		v := judgeFirewall(f.Firewall)
		ev["host_firewall"] = v.denies.String()
		switch v.denies {
		case triYes:
			return pfwResult(pf, t, Info, fmt.Sprintf("the provider firewall cannot filter IPv6, so the host firewall (%s) is the only layer for IPv6", v.mechanism), ev)
		case triNo:
			return pfwResult(pf, t, Fail, "the host has a global IPv6 address that the provider firewall cannot filter, and no host firewall denies incoming traffic: every IPv6 service is open", ev)
		}
		return pfwResult(pf, t, Unknown, "the provider firewall cannot filter IPv6 and whether the host firewall does is unknown: "+v.reason, ev)
	})
}

func checkPFWReturnTraffic(in Input) []Result {
	f := in.Facts
	return pfwEach(in, pfwNeeds{}, func(pf *facts.ProviderFirewall, t facts.ProviderTarget) Result {
		ev := map[string]any{"stateful": pf.Stateful, "tcp_replies": "", "missing": []string{}}
		if pf.Stateful {
			return pfwResult(pf, t, Skip, "the provider firewall is stateful: replies to connections the host opened need no rule", ev)
		}
		if !t.Enabled {
			return pfwResult(pf, t, Skip, "no provider firewall is in force for this address (see PFW-001)", ev)
		}
		if !t.RulesComplete {
			return pfwResult(pf, t, Unknown, "some firewall rules could not be read; a judgement from part of them would mislead", ev)
		}
		ok, by := verdict(t, packet{proto: "tcp", dst: ephemeralPort, src: 443, established: true})
		ev["tcp_replies"] = ruleLabel(t, by)
		if !ok {
			return pfwResult(pf, t, Fail, fmt.Sprintf("replies to TCP connections the host opens are dropped: %s denies them before any \"tcp established\" permit, which can cut the host off", ruleLabel(t, by)), ev)
		}
		missing := missingReplies(f, t)
		ev["missing"] = nonNil(missing)
		if len(missing) > 0 {
			return pfwResult(pf, t, Warn, "the stateless firewall may drop replies the host needs: "+strings.Join(missing, "; "), ev)
		}
		return pfwResult(pf, t, Pass, "the stateless firewall lets the replies the host needs back in", ev)
	})
}

// missingReplies lists UDP replies the host likely needs and the rules do
// not let in. Warn only: the provider's own resolvers and time servers may
// sit inside its network, where the firewall does not filter.
func missingReplies(f *facts.Facts, t facts.ProviderTarget) []string {
	var out []string
	reply := func(src int) bool {
		ok, _ := verdict(t, packet{proto: "udp", dst: ephemeralPort, src: src})
		return ok
	}
	if !reply(53) {
		out = append(out, "DNS replies (UDP source port 53) are not permitted, which breaks name resolution through a resolver outside the provider's network")
	}
	if f.Clock != nil && f.Clock.NTPEnabled && !reply(123) {
		out = append(out, "time sync is on but NTP replies (UDP source port 123) are not permitted")
	}
	if present, _ := tunnelState(f); present && !reply(7844) {
		out = append(out, "a Cloudflare Tunnel runs but QUIC replies (UDP source port 7844) are not permitted, so it falls back to HTTP/2 or fails")
	}
	return out
}

func checkPFWRules(in Input) []Result {
	pf := in.Facts.ProviderFirewall
	if r, stop := pfwGate(pf); stop {
		return []Result{r}
	}
	var out []Result
	for _, t := range pf.Targets {
		ev := map[string]any{"provider": pf.Provider, "address": t.Address, "status": string(t.Status)}
		if t.Status != facts.ProviderOK {
			out = append(out, Result{Subject: pfwSubject(t), Level: Unknown, Message: targetUnknown(t), Evidence: ev})
			continue
		}
		if len(t.Rules) == 0 {
			out = append(out, Result{Subject: pfwSubject(t), Level: Info, Message: "the provider firewall has no rules", Evidence: ev})
			continue
		}
		for _, r := range sortedRules(t) {
			rev := map[string]any{"provider": pf.Provider, "address": t.Address, "status": string(t.Status),
				"order": r.Order, "direction": r.Direction, "action": r.Action, "protocol": r.Protocol, "pending": r.Pending}
			out = append(out, Result{Subject: fmt.Sprintf("rule:%s/%03d", t.Address, r.Order), Level: Info,
				Message: describeRule(t, r), Evidence: rev})
		}
	}
	return out
}
