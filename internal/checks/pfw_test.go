package checks

import (
	"strings"
	"testing"

	"github.com/Shironex/stackward/internal/facts"
	"github.com/Shironex/stackward/internal/profile"
)

const pfwAddr = "192.0.2.10"

func pr(from, to int) []facts.PortRange { return []facts.PortRange{{From: from, To: to}} }

func port(p int) []facts.PortRange { return pr(p, p) }

// ovhRealRules is the stateless rule set of a working OVH host: replies,
// SSH from one panel address, cloudflared QUIC replies, Tailscale, DNS,
// ICMP, NTP, DHCP and a final deny.
func ovhRealRules() []facts.ProviderRule {
	return []facts.ProviderRule{
		{Order: 0, Direction: "in", Action: "permit", Protocol: "tcp", TCPOption: "established"},
		{Order: 1, Direction: "in", Action: "permit", Protocol: "tcp", Sources: []string{"203.0.113.7/32"}, DstPorts: port(22)},
		{Order: 2, Direction: "in", Action: "permit", Protocol: "udp", SrcPorts: port(7844)},
		{Order: 3, Direction: "in", Action: "permit", Protocol: "udp", DstPorts: port(41641)},
		{Order: 4, Direction: "in", Action: "permit", Protocol: "udp", SrcPorts: port(53)},
		{Order: 5, Direction: "in", Action: "permit", Protocol: "icmp"},
		{Order: 6, Direction: "in", Action: "permit", Protocol: "udp", SrcPorts: port(123)},
		{Order: 7, Direction: "in", Action: "permit", Protocol: "udp", SrcPorts: port(67)},
		{Order: 19, Direction: "in", Action: "deny", Protocol: "ipv4"},
	}
}

func ovhPF(rules []facts.ProviderRule) *facts.ProviderFirewall {
	return &facts.ProviderFirewall{Provider: "ovh", Status: facts.ProviderOK, Targets: []facts.ProviderTarget{{
		Address: pfwAddr, Status: facts.ProviderOK, Attached: true, Enabled: true, State: "ok", Firewalls: 1,
		DefaultInbound: "allow", Ordered: true, RulesComplete: true, Rules: rules,
	}}}
}

func hetznerPF(rules []facts.ProviderRule) *facts.ProviderFirewall {
	return &facts.ProviderFirewall{Provider: "hetzner", Status: facts.ProviderOK, Stateful: true, IPv6Filtered: true,
		Targets: []facts.ProviderTarget{{
			Address: pfwAddr, Status: facts.ProviderOK, Attached: true, Enabled: true, State: "applied", Firewalls: 1,
			DefaultInbound: "deny", RulesComplete: true, Rules: rules,
		}}}
}

func hetznerWeb() []facts.ProviderRule {
	return []facts.ProviderRule{
		{Order: 0, Direction: "in", Action: "permit", Protocol: "tcp", Sources: []string{"203.0.113.7/32"}, DstPorts: port(22)},
		{Order: 1, Direction: "in", Action: "permit", Protocol: "tcp", Sources: []string{"0.0.0.0/0", "::/0"}, DstPorts: port(443)},
		{Order: 2, Direction: "in", Action: "permit", Protocol: "icmp", Sources: []string{"0.0.0.0/0", "::/0"}},
	}
}

func pfwListeners(v6 bool) *facts.Listeners {
	l := &facts.Listeners{Source: "ss", ProcessesVisible: true, Sockets: []facts.Listener{
		{Proto: "tcp", Address: "0.0.0.0", Port: 22, Processes: []string{"sshd"}},
		{Proto: "tcp", Address: "0.0.0.0", Port: 443, Processes: []string{"caddy"}},
		{Proto: "udp", Address: "0.0.0.0", Port: 41641, Processes: []string{"tailscaled"}},
		{Proto: "tcp", Address: "127.0.0.1", Port: 8080, Processes: []string{"app"}},
	}, Addresses: []facts.InterfaceAddr{{Interface: "eth0", Address: pfwAddr, Prefix: 24, Scope: "global"}}}
	if v6 {
		l.Addresses = append(l.Addresses, facts.InterfaceAddr{Interface: "eth0", Address: "2001:db8::10", Prefix: 64, Scope: "global"})
	}
	return l
}

func pfwFacts(pf *facts.ProviderFirewall) *facts.Facts {
	return &facts.Facts{ProviderFirewall: pf, Listeners: pfwListeners(false), Clock: &facts.Clock{NTPEnabled: true}}
}

func stubTunnel(t *testing.T, present bool) {
	t.Helper()
	tunnelState = func(*facts.Facts) (bool, bool) { return present, true }
	t.Cleanup(func() { tunnelState = profile.TunnelState })
}

func stubTailnet(t *testing.T, running, known bool) {
	t.Helper()
	tailnetState = func(*facts.Facts) (bool, bool) { return running, known }
	t.Cleanup(func() { tailnetState = profile.Tailnet })
}

func runOne(t *testing.T, fn func(Input) []Result, f *facts.Facts) Result {
	t.Helper()
	rs := fn(Input{Facts: f})
	if len(rs) != 1 {
		t.Fatalf("want one result, got %d: %+v", len(rs), rs)
	}
	return rs[0]
}

func wantLevel(t *testing.T, r Result, level Level, contains string) {
	t.Helper()
	if r.Level != level {
		t.Errorf("level = %s, want %s (%s)", r.Level, level, r.Message)
	}
	if contains != "" && !strings.Contains(r.Message, contains) {
		t.Errorf("message %q does not contain %q", r.Message, contains)
	}
}

var pfwChecks = map[string]func(Input) []Result{
	"PFW-001": checkPFWAttached, "PFW-002": checkPFWDefaultDeny, "PFW-003": checkPFWOpenUDP,
	"PFW-004": checkPFWStaleRules, "PFW-005": checkPFWSSH, "PFW-006": checkPFWIPv6,
	"PFW-007": checkPFWReturnTraffic, "PFW-008": checkPFWRules,
}

func TestPFWGateNeverPasses(t *testing.T) {
	cases := map[string]*facts.ProviderFirewall{
		"no credentials": {Provider: "hetzner", Status: facts.ProviderNoCredentials, Reason: "STACKWARD_HETZNER_TOKEN is not set"},
		"denied":         {Provider: "hetzner", Status: facts.ProviderDenied, Reason: "401"},
		"no targets":     {Provider: "ovh", Status: facts.ProviderOK},
		"no match": {Provider: "hetzner", Status: facts.ProviderOK, Targets: []facts.ProviderTarget{
			{Address: pfwAddr, Status: facts.ProviderNoMatch}}},
		"target error": {Provider: "ovh", Status: facts.ProviderOK, Targets: []facts.ProviderTarget{
			{Address: pfwAddr, Status: facts.ProviderError, Reason: "rate limited"}}},
	}
	for name, pf := range cases {
		for id, fn := range pfwChecks {
			for _, r := range fn(Input{Facts: pfwFacts(pf)}) {
				if r.Level != Unknown {
					t.Errorf("%s %s: level %s, want unknown (%s)", name, id, r.Level, r.Message)
				}
			}
		}
	}
	r := runOne(t, checkPFWAttached, pfwFacts(cases["no match"]))
	wantLevel(t, r, Unknown, "no resource of this account")
}

func TestPFWNotRequestedIsOneSkipRow(t *testing.T) {
	var pfw []Result
	for _, r := range Evaluate(Input{Facts: pfwFacts(nil)}) {
		if strings.HasPrefix(r.ID, "PFW-") {
			pfw = append(pfw, r)
		}
	}
	if len(pfw) != 1 || pfw[0].ID != "PFW-001" || pfw[0].Level != Skip || !strings.Contains(pfw[0].Message, "--provider") {
		t.Errorf("PFW rows without --provider: %+v", pfw)
	}
	// With a provider result every PFW check reports again.
	n := 0
	for _, r := range Evaluate(Input{Facts: pfwFacts(&facts.ProviderFirewall{Provider: "hetzner", Status: facts.ProviderNoCredentials})}) {
		if strings.HasPrefix(r.ID, "PFW-") {
			n++
		}
	}
	if n != 8 {
		t.Errorf("PFW rows with a provider result: %d, want 8", n)
	}
}

// TestPFWSourcePortOnlyTCPPermit is the rule set from the gate review: a
// permit for TCP from source port 443 before the final deny lets anyone
// reach every TCP port, SSH included, by sending from port 443.
func TestPFWSourcePortOnlyTCPPermit(t *testing.T) {
	stubTailnet(t, true, true)
	rules := []facts.ProviderRule{
		{Order: 0, Direction: "in", Action: "permit", Protocol: "tcp", TCPOption: "established"},
		{Order: 1, Direction: "in", Action: "permit", Protocol: "tcp", Sources: []string{"203.0.113.7/32"}, DstPorts: port(22)},
		{Order: 2, Direction: "in", Action: "permit", Protocol: "tcp", SrcPorts: port(443)},
		{Order: 19, Direction: "in", Action: "deny", Protocol: "ipv4"},
	}
	f := pfwFacts(ovhPF(rules))
	wantLevel(t, runOne(t, checkPFWDefaultDeny, f), Fail, "source port 443 (seq 2)")
	wantLevel(t, runOne(t, checkPFWSSH, f), Fail, "tcp/22 (seq 2, from source port 443)")

	// A source port rule that also names the destination port is fine.
	rules[2].DstPorts = pr(32768, 60999)
	f = pfwFacts(ovhPF(rules))
	wantLevel(t, runOne(t, checkPFWDefaultDeny, f), Pass, "seq 19")
	wantLevel(t, runOne(t, checkPFWSSH, f), Pass, "")
}

func TestPFWPendingRules(t *testing.T) {
	stubTailnet(t, false, true)
	// A pending permit counts: it may already let traffic in.
	rules := []facts.ProviderRule{
		{Order: 0, Direction: "in", Action: "permit", Protocol: "tcp", DstPorts: port(22), Pending: true},
		{Order: 19, Direction: "in", Action: "deny", Protocol: "ipv4"},
	}
	wantLevel(t, runOne(t, checkPFWSSH, pfwFacts(ovhPF(rules))), Warn, "tcp/22 (seq 0)")
	// A pending deny does not: it may block nothing yet.
	rules = []facts.ProviderRule{
		{Order: 0, Direction: "in", Action: "deny", Protocol: "tcp", DstPorts: port(22), Pending: true},
		{Order: 19, Direction: "in", Action: "deny", Protocol: "ipv4", Pending: true},
	}
	f := pfwFacts(ovhPF(rules))
	wantLevel(t, runOne(t, checkPFWSSH, f), Warn, "the default")
	wantLevel(t, runOne(t, checkPFWDefaultDeny, f), Fail, "no catch-all deny")
}

func TestPFWUnparsableSourceFailsClosed(t *testing.T) {
	stubTailnet(t, false, true)
	for _, src := range []string{"0.0.0.0", "garbage", "203.0.113.7"} {
		rules := []facts.ProviderRule{
			{Order: 0, Direction: "in", Action: "permit", Protocol: "tcp", Sources: []string{src}, DstPorts: port(22)},
		}
		wantLevel(t, runOne(t, checkPFWSSH, pfwFacts(hetznerPF(rules))), Warn, "tcp/22")
	}
}

func TestPFWOVHWorkingRuleSet(t *testing.T) {
	stubTunnel(t, true)
	stubTailnet(t, true, true)
	f := pfwFacts(ovhPF(ovhRealRules()))
	wantLevel(t, runOne(t, checkPFWAttached, f), Pass, "in force")
	wantLevel(t, runOne(t, checkPFWDefaultDeny, f), Pass, "seq 19")
	// The source port only rules are the provider's own advice, and still
	// let any sender reach every UDP port.
	r := runOne(t, checkPFWOpenUDP, f)
	wantLevel(t, r, Warn, "seq 4 (source port 53)")
	wantLevel(t, runOne(t, checkPFWStaleRules, f), Pass, "")
	wantLevel(t, runOne(t, checkPFWSSH, f), Pass, "")
	wantLevel(t, runOne(t, checkPFWIPv6, f), Pass, "no global IPv6")
	wantLevel(t, runOne(t, checkPFWReturnTraffic, f), Pass, "")
	if rs := checkPFWRules(Input{Facts: f}); len(rs) != 9 || rs[8].Subject != "rule:192.0.2.10/019" {
		t.Errorf("PFW-008 rows: %+v", rs)
	}
}

func TestPFWOVHOrderMatters(t *testing.T) {
	stubTunnel(t, false)
	// A deny for everything before the established permit drops replies,
	// and makes the SSH permit after it dead.
	rules := []facts.ProviderRule{
		{Order: 0, Direction: "in", Action: "deny", Protocol: "ipv4"},
		{Order: 1, Direction: "in", Action: "permit", Protocol: "tcp", TCPOption: "established"},
		{Order: 2, Direction: "in", Action: "permit", Protocol: "tcp", DstPorts: port(22)},
	}
	f := pfwFacts(ovhPF(rules))
	wantLevel(t, runOne(t, checkPFWReturnTraffic, f), Fail, "seq 0 denies them")
	wantLevel(t, runOne(t, checkPFWSSH, f), Pass, "")

	// A permit before a deny of the same traffic makes the deny dead.
	rules = []facts.ProviderRule{
		{Order: 0, Direction: "in", Action: "permit", Protocol: "tcp", DstPorts: port(22)},
		{Order: 1, Direction: "in", Action: "deny", Protocol: "tcp", DstPorts: port(22)},
		{Order: 19, Direction: "in", Action: "deny", Protocol: "ipv4"},
	}
	stubTailnet(t, false, true)
	wantLevel(t, runOne(t, checkPFWSSH, pfwFacts(ovhPF(rules))), Warn, "tcp/22 (seq 0)")
	stubTailnet(t, true, true)
	wantLevel(t, runOne(t, checkPFWSSH, pfwFacts(ovhPF(rules))), Fail, "Tailscale")
}

func TestPFWOVHNoCatchAllDeny(t *testing.T) {
	rules := ovhRealRules()[:8]
	f := pfwFacts(ovhPF(rules))
	wantLevel(t, runOne(t, checkPFWDefaultDeny, f), Fail, "no catch-all deny")
	wantLevel(t, runOne(t, checkPFWOpenUDP, f), Fail, "the default")
	// SSH from anywhere is allowed by the default.
	stubTailnet(t, false, false)
	wantLevel(t, runOne(t, checkPFWSSH, f), Warn, "tcp/22 (the default)")
	// Replies pass the default allow.
	stubTunnel(t, false)
	wantLevel(t, runOne(t, checkPFWReturnTraffic, f), Pass, "")
}

func TestPFWOVHMissingReplies(t *testing.T) {
	stubTunnel(t, true)
	rules := []facts.ProviderRule{
		{Order: 0, Direction: "in", Action: "permit", Protocol: "tcp", TCPOption: "established"},
		{Order: 19, Direction: "in", Action: "deny", Protocol: "ipv4"},
	}
	r := runOne(t, checkPFWReturnTraffic, pfwFacts(ovhPF(rules)))
	wantLevel(t, r, Warn, "DNS replies")
	for _, want := range []string{"NTP replies", "QUIC replies"} {
		if !strings.Contains(r.Message, want) {
			t.Errorf("message %q lacks %q", r.Message, want)
		}
	}
	// A pending permit counts as in force.
	rules = append(rules, facts.ProviderRule{Order: 1, Direction: "in", Action: "permit", Protocol: "udp", SrcPorts: port(53), Pending: true})
	if r := runOne(t, checkPFWReturnTraffic, pfwFacts(ovhPF(rules))); strings.Contains(r.Message, "DNS replies") {
		t.Errorf("pending DNS permit not counted: %s", r.Message)
	}
}

func TestPFWAttachedStates(t *testing.T) {
	disabled := ovhPF(ovhRealRules())
	disabled.Targets[0].Enabled = false
	wantLevel(t, runOne(t, checkPFWAttached, pfwFacts(disabled)), Warn, "detected attack")
	for id, fn := range pfwChecks {
		if id == "PFW-001" || id == "PFW-008" || id == "PFW-006" {
			continue
		}
		wantLevel(t, runOne(t, fn, pfwFacts(disabled)), Skip, "")
	}

	empty := ovhPF(nil)
	empty.Targets[0].Enabled = false
	wantLevel(t, runOne(t, checkPFWAttached, pfwFacts(empty)), Fail, "disabled and has no rules")

	none := hetznerPF(nil)
	none.Targets[0].Attached, none.Targets[0].Enabled, none.Targets[0].Firewalls = false, false, 0
	wantLevel(t, runOne(t, checkPFWAttached, pfwFacts(none)), Fail, "no provider firewall")

	pending := hetznerPF(hetznerWeb())
	pending.Targets[0].Enabled, pending.Targets[0].Pending, pending.Targets[0].State = false, true, "pending"
	wantLevel(t, runOne(t, checkPFWAttached, pfwFacts(pending)), Fail, "not in force")

	partial := ovhPF(ovhRealRules())
	partial.Targets[0].RulesComplete = false
	wantLevel(t, runOne(t, checkPFWDefaultDeny, pfwFacts(partial)), Unknown, "could not be read")
	wantLevel(t, runOne(t, checkPFWReturnTraffic, pfwFacts(partial)), Unknown, "could not be read")
}

func TestPFWHetzner(t *testing.T) {
	stubTailnet(t, true, true)
	f := pfwFacts(hetznerPF(hetznerWeb()))
	wantLevel(t, runOne(t, checkPFWAttached, f), Pass, "")
	wantLevel(t, runOne(t, checkPFWDefaultDeny, f), Pass, "default deny")
	wantLevel(t, runOne(t, checkPFWOpenUDP, f), Pass, "")
	wantLevel(t, runOne(t, checkPFWSSH, f), Pass, "")
	wantLevel(t, runOne(t, checkPFWReturnTraffic, f), Skip, "stateful")
	f.Listeners = pfwListeners(true)
	wantLevel(t, runOne(t, checkPFWIPv6, f), Pass, "filters IPv6")

	open := append(hetznerWeb(),
		facts.ProviderRule{Order: 3, Direction: "in", Action: "permit", Protocol: "tcp", Sources: []string{"0.0.0.0/0", "::/0"}, DstPorts: port(22)},
		facts.ProviderRule{Order: 4, Direction: "in", Action: "permit", Protocol: "udp", Sources: []string{"0.0.0.0/0"}, DstPorts: pr(1, 65535)},
		facts.ProviderRule{Order: 5, Direction: "in", Action: "permit", Protocol: "tcp", Sources: []string{"10.0.0.0/8"}, DstPorts: port(5432)},
	)
	f = pfwFacts(hetznerPF(open))
	wantLevel(t, runOne(t, checkPFWSSH, f), Fail, "tcp/22 (rule 3)")
	wantLevel(t, runOne(t, checkPFWOpenUDP, f), Fail, "rule 4")
	r := runOne(t, checkPFWStaleRules, f)
	wantLevel(t, r, Warn, "tcp/5432")
	if strings.Contains(r.Message, "tcp/22") || strings.Contains(r.Message, "tcp/443") {
		t.Errorf("served ports reported stale: %s", r.Message)
	}

	// A /8 source counts as anywhere for SSH; a /16 does not.
	wide := []facts.ProviderRule{{Order: 0, Direction: "in", Action: "permit", Protocol: "tcp", Sources: []string{"198.0.0.0/8"}, DstPorts: port(22)}}
	wantLevel(t, runOne(t, checkPFWSSH, pfwFacts(hetznerPF(wide))), Fail, "")
	wide[0].Sources = []string{"198.51.0.0/16"}
	wantLevel(t, runOne(t, checkPFWSSH, pfwFacts(hetznerPF(wide))), Pass, "")

	// Permits of a pending firewall next to an applied one count.
	pend := hetznerPF([]facts.ProviderRule{{Order: 0, Direction: "in", Action: "permit", Protocol: "tcp", DstPorts: port(22), Pending: true}})
	wantLevel(t, runOne(t, checkPFWSSH, pfwFacts(pend)), Fail, "tcp/22")
}

func TestPFWWideAndStale(t *testing.T) {
	rules := []facts.ProviderRule{
		{Order: 0, Direction: "in", Action: "permit", Protocol: "udp", DstPorts: pr(10000, 20000)},
		{Order: 1, Direction: "in", Action: "permit", Protocol: "tcp", DstPorts: pr(30000, 30100)},
		{Order: 19, Direction: "in", Action: "deny", Protocol: "ipv4"},
	}
	f := pfwFacts(ovhPF(rules))
	wantLevel(t, runOne(t, checkPFWOpenUDP, f), Warn, "wide UDP port ranges")
	r := runOne(t, checkPFWStaleRules, f)
	wantLevel(t, r, Warn, "tcp/30000-30100")
	// A container that publishes a port counts as a service.
	f.Docker = &facts.Docker{API: "ok", Containers: []facts.DockerContainer{{Ports: []facts.DockerPort{{HostPort: 30050, Proto: "tcp"}}}}}
	if r := runOne(t, checkPFWStaleRules, f); strings.Contains(r.Message, "tcp/30000") {
		t.Errorf("published port reported stale: %s", r.Message)
	}
	f.Listeners = nil
	wantLevel(t, runOne(t, checkPFWStaleRules, f), Info, "could not be read")
}

func TestPFWIPv6OnOVH(t *testing.T) {
	f := pfwFacts(ovhPF(ovhRealRules()))
	f.Listeners = pfwListeners(true)
	wantLevel(t, runOne(t, checkPFWIPv6, f), Unknown, "host firewall was not read")
	f.Firewall = &facts.Firewall{UFW: &facts.UFW{Installed: true, Status: "active", DefaultIncoming: "deny", Source: "iptables"}}
	r := runOne(t, checkPFWIPv6, f)
	if r.Level != Info && r.Level != Unknown {
		t.Errorf("level %s with UFW denying: %s", r.Level, r.Message)
	}
	f.Firewall = &facts.Firewall{}
	wantLevel(t, runOne(t, checkPFWIPv6, f), Fail, "every IPv6 service is open")
	f.Listeners.Addresses = nil
	wantLevel(t, runOne(t, checkPFWIPv6, f), Unknown, "")
}

func TestPFWSeveralAddresses(t *testing.T) {
	pf := hetznerPF(hetznerWeb())
	pf.Targets = append(pf.Targets, facts.ProviderTarget{Address: "198.51.100.20", Status: facts.ProviderNoMatch})
	rs := checkPFWAttached(Input{Facts: pfwFacts(pf)})
	if len(rs) != 2 || rs[0].Level != Pass || rs[1].Level != Unknown || rs[1].Subject != "address:198.51.100.20" {
		t.Errorf("results: %+v", rs)
	}
}

func TestPFWDescribePending(t *testing.T) {
	tg := ovhPF(nil).Targets[0]
	if s := describeRule(tg, facts.ProviderRule{Order: 3, Direction: "in", Action: "permit", Protocol: "udp", Pending: true}); !strings.Contains(s, "counted as in force") {
		t.Error(s)
	}
	if s := describeRule(tg, facts.ProviderRule{Order: 3, Direction: "in", Action: "deny", Protocol: "udp", Pending: true}); !strings.Contains(s, "not counted") {
		t.Error(s)
	}
}

func TestNET009ReadsProviderResult(t *testing.T) {
	r := runOne(t, checkProviderFirewall, pfwFacts(nil))
	wantLevel(t, r, Unknown, "cannot be seen from inside")
	r = runOne(t, checkProviderFirewall, pfwFacts(hetznerPF(hetznerWeb())))
	wantLevel(t, r, Info, "read 1 hetzner firewall(s) with 3 rules")
}
