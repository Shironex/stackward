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

// TestPFWUnparsableSourceFailsClosed: an unparsable permit source counts as
// anywhere (deny sources are the strict case above).
func TestPFWUnparsableSourceFailsClosed(t *testing.T) {
	stubTailnet(t, false, true)
	for _, src := range []string{"0.0.0.0", "garbage", "203.0.113.7"} {
		rules := []facts.ProviderRule{
			{Order: 0, Direction: "in", Action: "permit", Protocol: "tcp", Sources: []string{src}, DstPorts: port(22)},
		}
		wantLevel(t, runOne(t, checkPFWSSH, pfwFacts(hetznerPF(rules))), Warn, "tcp/22")
	}
}

// TestPFWDenySourcesAreStrict covers the second gate review's probes: a
// deny only counts against a sender anywhere when its source is empty or a
// true /0; a wide, narrow or unparsable source never makes it block the
// internet.
func TestPFWDenySourcesAreStrict(t *testing.T) {
	stubTailnet(t, false, true)
	ssh22 := facts.ProviderRule{Order: 1, Direction: "in", Action: "permit", Protocol: "tcp", DstPorts: port(22)}
	cases := []struct {
		name    string
		rules   []facts.ProviderRule
		want002 Level
		want005 Level
	}{
		{"deny from garbage as the only catch-all", []facts.ProviderRule{
			{Order: 19, Direction: "in", Action: "deny", Protocol: "ipv4", Sources: []string{"garbage"}},
		}, Fail, Warn},
		{"deny from 10.0.0.0/8 with the default allow", []facts.ProviderRule{
			{Order: 19, Direction: "in", Action: "deny", Protocol: "ipv4", Sources: []string{"10.0.0.0/8"}},
		}, Fail, Warn},
		{"deny from 0.0.0.0/1", []facts.ProviderRule{
			{Order: 19, Direction: "in", Action: "deny", Protocol: "ipv4", Sources: []string{"0.0.0.0/1"}},
		}, Fail, Warn},
		{"deny tcp 22 from 10.0.0.0/8, no catch-all", []facts.ProviderRule{
			{Order: 0, Direction: "in", Action: "deny", Protocol: "tcp", Sources: []string{"10.0.0.0/8"}, DstPorts: port(22)},
		}, Fail, Warn},
		{"deny tcp 22 from bogus, then permit ipv4", []facts.ProviderRule{
			{Order: 0, Direction: "in", Action: "deny", Protocol: "tcp", Sources: []string{"bogus"}, DstPorts: port(22)},
			{Order: 1, Direction: "in", Action: "permit", Protocol: "ipv4"},
		}, Fail, Warn},
		// True /0 denies still count, IPv4-mapped included.
		{"deny from 0.0.0.0/0", []facts.ProviderRule{
			{Order: 19, Direction: "in", Action: "deny", Protocol: "ipv4", Sources: []string{"0.0.0.0/0"}},
		}, Pass, Pass},
		{"deny from ::ffff:0.0.0.0/96", []facts.ProviderRule{
			{Order: 19, Direction: "in", Action: "deny", Protocol: "ipv4", Sources: []string{"::ffff:0.0.0.0/96"}},
		}, Pass, Pass},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			f := pfwFacts(ovhPF(c.rules))
			wantLevel(t, runOne(t, checkPFWDefaultDeny, f), c.want002, "")
			wantLevel(t, runOne(t, checkPFWSSH, f), c.want005, "")
		})
	}
	// The SSH permit behind a strict catch-all is still judged.
	f := pfwFacts(ovhPF([]facts.ProviderRule{ssh22, {Order: 19, Direction: "in", Action: "deny", Protocol: "ipv4"}}))
	wantLevel(t, runOne(t, checkPFWSSH, f), Warn, "tcp/22 (seq 1)")
}

func TestPFWMappedPermitCoversIPv4(t *testing.T) {
	stubTailnet(t, false, true)
	rules := []facts.ProviderRule{{Order: 0, Direction: "in", Action: "permit", Protocol: "tcp", Sources: []string{"::ffff:0.0.0.0/96"}, DstPorts: port(22)}}
	wantLevel(t, runOne(t, checkPFWSSH, pfwFacts(hetznerPF(rules))), Warn, "tcp/22")
	rules[0].Sources = []string{"::ffff:203.0.113.7/128"}
	wantLevel(t, runOne(t, checkPFWSSH, pfwFacts(hetznerPF(rules))), Pass, "")
}

// TestPFWSourcePortRangeEdges: a deny for source port 1000 in front of a
// permit for 1000-2000 still lets source port 1001 reach everything.
func TestPFWSourcePortRangeEdges(t *testing.T) {
	stubTailnet(t, false, true)
	rules := []facts.ProviderRule{
		{Order: 0, Direction: "in", Action: "deny", Protocol: "tcp", SrcPorts: port(1000)},
		{Order: 1, Direction: "in", Action: "permit", Protocol: "tcp", SrcPorts: pr(1000, 2000)},
		{Order: 19, Direction: "in", Action: "deny", Protocol: "ipv4"},
	}
	f := pfwFacts(ovhPF(rules))
	wantLevel(t, runOne(t, checkPFWDefaultDeny, f), Fail, "source port 1001 (seq 1)")
	wantLevel(t, runOne(t, checkPFWSSH, f), Warn, "from source port 1001")

	// The same shape for UDP is PFW-003's source port warning.
	udp := []facts.ProviderRule{
		{Order: 0, Direction: "in", Action: "deny", Protocol: "udp", SrcPorts: port(1000)},
		{Order: 1, Direction: "in", Action: "permit", Protocol: "udp", SrcPorts: pr(1000, 2000)},
		{Order: 19, Direction: "in", Action: "deny", Protocol: "ipv4"},
	}
	wantLevel(t, runOne(t, checkPFWOpenUDP, pfwFacts(ovhPF(udp))), Warn, "seq 1 (source port 1000-2000)")
	// Fully shadowed, it is not reported.
	udp[0].SrcPorts = pr(1000, 2000)
	wantLevel(t, runOne(t, checkPFWOpenUDP, pfwFacts(ovhPF(udp))), Pass, "")

	// A range starting at 0 is a real range, not "no source port".
	zero := []facts.ProviderRule{
		{Order: 0, Direction: "in", Action: "permit", Protocol: "tcp", SrcPorts: pr(0, 0)},
		{Order: 19, Direction: "in", Action: "deny", Protocol: "ipv4"},
	}
	wantLevel(t, runOne(t, checkPFWDefaultDeny, pfwFacts(ovhPF(zero))), Fail, "source port 0")
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
	// An applied DNS permit lets DNS replies in (a pending one does not,
	// see TestPFWRepliesPendingRules).
	rules = append(rules, facts.ProviderRule{Order: 1, Direction: "in", Action: "permit", Protocol: "udp", SrcPorts: port(53)})
	if r := runOne(t, checkPFWReturnTraffic, pfwFacts(ovhPF(rules))); strings.Contains(r.Message, "DNS replies") {
		t.Errorf("DNS permit not counted: %s", r.Message)
	}
}

// TestPFWRepliesLeanTowardAFinding: in the reply checks a dropped packet is
// the finding, so a deny counts from a wide or unparsable source and a
// permit only from an empty or true /0 source (the third gate review).
func TestPFWRepliesLeanTowardAFinding(t *testing.T) {
	stubTunnel(t, false)
	est := facts.ProviderRule{Order: 1, Direction: "in", Action: "permit", Protocol: "tcp", TCPOption: "established"}
	dns := facts.ProviderRule{Order: 2, Direction: "in", Action: "permit", Protocol: "udp", SrcPorts: port(53)}
	final := facts.ProviderRule{Order: 19, Direction: "in", Action: "deny", Protocol: "ipv4"}
	run := func(rules ...facts.ProviderRule) Result {
		f := pfwFacts(ovhPF(rules))
		f.Clock = nil
		return runOne(t, checkPFWReturnTraffic, f)
	}
	wantLevel(t, run(est, dns, final), Pass, "")

	// P12: a deny from half the internet before the established permit.
	for _, src := range []string{"0.0.0.0/1", "garbage"} {
		deny := facts.ProviderRule{Order: 0, Direction: "in", Action: "deny", Protocol: "ipv4", Sources: []string{src}}
		wantLevel(t, run(deny, est, dns, final), Fail, "seq 0 denies them")
	}
	// P13: a DNS reply deny from half the internet before the DNS permit.
	deny53 := facts.ProviderRule{Order: 0, Direction: "in", Action: "deny", Protocol: "udp", Sources: []string{"0.0.0.0/1"}, SrcPorts: port(53)}
	wantLevel(t, run(est, deny53, dns, final), Warn, "DNS replies")

	// A narrow permit does not let replies in from anywhere.
	narrow := est
	narrow.Sources = []string{"10.0.0.0/8"}
	wantLevel(t, run(narrow, dns, final), Fail, "seq 19 denies them")
	narrowDNS := dns
	narrowDNS.Sources = []string{"10.0.0.0/8"}
	wantLevel(t, run(est, narrowDNS, final), Warn, "DNS replies")
	// An IPv6 /0 permit does not cover IPv4 senders either.
	v6 := est
	v6.Sources = []string{"::/0"}
	wantLevel(t, run(v6, dns, final), Fail, "seq 19 denies them")
	// A true /0, mapped included, does.
	mapped := est
	mapped.Sources = []string{"::ffff:0.0.0.0/96"}
	wantLevel(t, run(mapped, dns, final), Pass, "")
}

// TestPFWRepliesPendingRules: in the reply checks a pending deny counts and
// a pending permit does not (the fourth gate review, probes Q1 to Q4, Q13).
func TestPFWRepliesPendingRules(t *testing.T) {
	stubTunnel(t, false)
	est := facts.ProviderRule{Order: 1, Direction: "in", Action: "permit", Protocol: "tcp", TCPOption: "established"}
	dns := facts.ProviderRule{Order: 2, Direction: "in", Action: "permit", Protocol: "udp", SrcPorts: port(53)}
	final := facts.ProviderRule{Order: 19, Direction: "in", Action: "deny", Protocol: "ipv4"}
	run := func(rules ...facts.ProviderRule) Result {
		f := pfwFacts(ovhPF(rules))
		f.Clock = nil
		return runOne(t, checkPFWReturnTraffic, f)
	}
	pending := func(r facts.ProviderRule) facts.ProviderRule { r.Pending = true; return r }

	// Q1: the established permit is being removed.
	wantLevel(t, run(pending(est), dns, final), Fail, "seq 19 denies them")
	// Q2: a pending deny before the established permit.
	wantLevel(t, run(pending(facts.ProviderRule{Order: 0, Direction: "in", Action: "deny", Protocol: "ipv4"}), est, dns, final), Fail, "seq 0 denies them")
	// Q3: a pending DNS reply deny before the DNS permit.
	wantLevel(t, run(est, pending(facts.ProviderRule{Order: 0, Direction: "in", Action: "deny", Protocol: "udp", SrcPorts: port(53)}), dns, final), Warn, "DNS replies")
	// Q4: the DNS permit itself is pending.
	wantLevel(t, run(est, pending(dns), final), Warn, "DNS replies")
	// Q13: a first final deny still pending, no UDP reply permits.
	wantLevel(t, run(est, pending(final)), Warn, "DNS replies")

	// The checks where a packet getting in is the finding keep the other
	// reading: a pending permit counts, a pending deny does not.
	ssh := facts.ProviderRule{Order: 0, Direction: "in", Action: "permit", Protocol: "tcp", DstPorts: port(22), Pending: true}
	stubTailnet(t, false, true)
	wantLevel(t, runOne(t, checkPFWSSH, pfwFacts(ovhPF([]facts.ProviderRule{ssh, final}))), Warn, "tcp/22")
	wantLevel(t, runOne(t, checkPFWDefaultDeny, pfwFacts(ovhPF([]facts.ProviderRule{pending(final)}))), Fail, "")
}

// TestPFWRepliesReservedDeny: a deny from reserved space only drops no
// internet reply, so it does not count in the reply checks (P14, Q9).
func TestPFWRepliesReservedDeny(t *testing.T) {
	stubTunnel(t, false)
	est := facts.ProviderRule{Order: 1, Direction: "in", Action: "permit", Protocol: "tcp", TCPOption: "established"}
	dns := facts.ProviderRule{Order: 2, Direction: "in", Action: "permit", Protocol: "udp", SrcPorts: port(53)}
	final := facts.ProviderRule{Order: 19, Direction: "in", Action: "deny", Protocol: "ipv4"}
	run := func(rules ...facts.ProviderRule) Result {
		f := pfwFacts(ovhPF(rules))
		f.Clock = nil
		return runOne(t, checkPFWReturnTraffic, f)
	}
	// P14: deny 10.0.0.0/8 before the established permit.
	deny := facts.ProviderRule{Order: 0, Direction: "in", Action: "deny", Protocol: "ipv4", Sources: []string{"10.0.0.0/8"}}
	wantLevel(t, run(deny, est, dns, final), Pass, "")
	// Q9: a DNS reply deny from several reserved ranges before the DNS permit.
	deny53 := facts.ProviderRule{Order: 0, Direction: "in", Action: "deny", Protocol: "udp", SrcPorts: port(53),
		Sources: []string{"192.168.0.0/16", "172.16.0.0/12", "100.64.0.0/10", "::ffff:127.0.0.0/104"}}
	wantLevel(t, run(est, deny53, dns, final), Pass, "")
	// A source wider than a reserved range makes the deny count again.
	wide := deny53
	wide.Sources = append(append([]string(nil), deny53.Sources...), "0.0.0.0/7")
	wantLevel(t, run(est, wide, dns, final), Warn, "DNS replies")
	deny.Sources = []string{"garbage"}
	wantLevel(t, run(deny, est, dns, final), Fail, "seq 0 denies them")
	// Where a packet getting in is the finding a reserved deny changes nothing.
	stubTailnet(t, false, true)
	deny.Sources = []string{"10.0.0.0/8"}
	wantLevel(t, runOne(t, checkPFWDefaultDeny, pfwFacts(ovhPF([]facts.ProviderRule{deny}))), Fail, "")
}

// TestPFWIPv6DenyDoesNotBlockIPv4: a deny from ::/0 is no catch-all for the
// IPv4 packets the checks simulate.
func TestPFWIPv6DenyDoesNotBlockIPv4(t *testing.T) {
	stubTailnet(t, false, true)
	rules := []facts.ProviderRule{{Order: 19, Direction: "in", Action: "deny", Protocol: "ipv4", Sources: []string{"::/0"}}}
	f := pfwFacts(ovhPF(rules))
	wantLevel(t, runOne(t, checkPFWDefaultDeny, f), Fail, "")
	wantLevel(t, runOne(t, checkPFWSSH, f), Warn, "")
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
	if s := describeRule(tg, facts.ProviderRule{Order: 3, Direction: "in", Action: "permit", Protocol: "udp", Pending: true}); !strings.Contains(s, "counts as open, not as letting replies in") {
		t.Error(s)
	}
	if s := describeRule(tg, facts.ProviderRule{Order: 3, Direction: "in", Action: "deny", Protocol: "udp", Pending: true}); !strings.Contains(s, "counts as dropping replies, not as blocking") {
		t.Error(s)
	}
}

func TestNET009ReadsProviderResult(t *testing.T) {
	r := runOne(t, checkProviderFirewall, pfwFacts(nil))
	wantLevel(t, r, Unknown, "cannot be seen from inside")
	r = runOne(t, checkProviderFirewall, pfwFacts(hetznerPF(hetznerWeb())))
	wantLevel(t, r, Info, "read 1 hetzner firewall(s) with 3 rules")
}
