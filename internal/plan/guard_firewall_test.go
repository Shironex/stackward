package plan

import (
	"net/netip"
	"slices"
	"strings"
	"testing"

	"github.com/Shironex/stackward/internal/facts"
)

// guardFirewallFacts is a live host with UFW in the given state, sshd on
// port, and rules.
func guardFirewallFacts(status string, port string, rules ...facts.UFWRule) *facts.Facts {
	return &facts.Facts{
		SSH:       &facts.SSH{Installed: true, Effective: map[string][]string{"port": {port}}},
		Listeners: &facts.Listeners{},
		Firewall: &facts.Firewall{UFW: &facts.UFW{Installed: true, Source: "live", Status: status, IPv6: "yes",
			DefaultIncoming: "deny", RulesKnown: true, Rules: rules}},
	}
}

var turnOn = FirewallChange{What: "turns UFW on with default deny incoming", TurnsOn: true}

func prove(fc FirewallChange, f *facts.Facts, src string) (Proof, error) {
	var a netip.Addr
	if src != "" {
		a = netip.MustParseAddr(src)
	}
	return proveFirewall("ufw-policy", Proof{Narrows: []string{fc.What}}, fc, GuardInput{Facts: f, Source: a})
}

func TestFirewallGuardRefuses(t *testing.T) {
	allow22 := facts.UFWRule{Action: "allow", Direction: "in", Port: "22", Proto: "tcp"}
	cases := map[string]struct {
		fc   FirewallChange
		f    *facts.Facts
		src  string
		want string
	}{
		"no facts": {turnOn, nil, "192.0.2.10", "not audited"},
		"rules unread": {turnOn, func() *facts.Facts {
			f := guardFirewallFacts("inactive", "22")
			f.Firewall.UFW.RulesKnown = false
			return f
		}(), "", "could not be read"},
		"files only": {turnOn, func() *facts.Facts {
			f := guardFirewallFacts("inactive", "22")
			f.Firewall.UFW.Source = "files"
			return f
		}(), "", "root"},
		"no sshd port":     {turnOn, func() *facts.Facts { f := guardFirewallFacts("inactive", "22", allow22); f.SSH = nil; return f }(), "", "does not assume 22"},
		"no rule at all":   {turnOn, guardFirewallFacts("inactive", "22"), "192.0.2.10", "no UFW rule would let SSH on tcp/22 in"},
		"other port":       {turnOn, guardFirewallFacts("inactive", "2222", allow22), "192.0.2.10", "tcp/2222"},
		"already on":       {turnOn, guardFirewallFacts("active", "22", allow22), "192.0.2.10", "plan again"},
		"off for reload":   {FirewallChange{What: "reloads"}, guardFirewallFacts("inactive", "22", allow22), "", "expects UFW to be active"},
		"source not in":    {turnOn, guardFirewallFacts("inactive", "22", facts.UFWRule{Action: "allow", Direction: "in", Port: "22", Proto: "tcp", From: "198.51.100.0/24"}), "192.0.2.10", "no UFW rule"},
		"unknown source":   {turnOn, guardFirewallFacts("inactive", "22", facts.UFWRule{Action: "allow", Direction: "in", Port: "22", Proto: "tcp", From: "198.51.100.0/24"}), "", "address is unknown"},
		"tailnet only":     {turnOn, guardFirewallFacts("inactive", "22", facts.UFWRule{Action: "allow", Direction: "in", Port: "22", Proto: "tcp", Interface: "tailscale0"}), "192.0.2.10", "no UFW rule"},
		"deny comes first": {turnOn, guardFirewallFacts("inactive", "22", facts.UFWRule{Action: "deny", Direction: "in", Port: "22", Proto: "tcp", From: "192.0.2.0/24"}, allow22), "192.0.2.10", "comes first"},
		"deny maybe first": {turnOn, guardFirewallFacts("inactive", "22", facts.UFWRule{Action: "reject", Direction: "in", Port: "22", Proto: "tcp", Interface: "eth1"}, allow22), "192.0.2.10", "comes first"},
		"ipv6 off": {turnOn, func() *facts.Facts {
			f := guardFirewallFacts("inactive", "22", allow22)
			f.Firewall.UFW.IPv6 = "no"
			return f
		}(), "2001:db8::7", "IPV6=no"},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			p, err := prove(tc.fc, tc.f, tc.src)
			if err == nil || !strings.Contains(err.Error(), tc.want) || !strings.Contains(err.Error(), "lockout guard: ufw-policy") {
				t.Errorf("err %v, want %q", err, tc.want)
			}
			if !p.Needed {
				t.Error("a firewall change always needs the proof")
			}
		})
	}
}

func TestFirewallGuardProves(t *testing.T) {
	// The step's own rule lets SSH in from anywhere: any session passes,
	// and the confirm may come from anywhere.
	fc := turnOn
	fc.Adds = []facts.UFWRule{ufwAdd{proto: "tcp", port: 2222}.fact(), ufwAdd{proto: "tcp", port: 2222, v6: true}.fact()}
	for _, src := range []string{"", "192.0.2.10", "2001:db8::7", "100.100.1.2"} {
		p, err := prove(fc, guardFirewallFacts("inactive", "2222"), src)
		if err != nil || len(p.Ways) != 1 || p.ConfirmFrom != nil {
			t.Errorf("%q: %+v %v", src, p, err)
		}
	}
	// Rules that only let the tailnet in: a tailnet session passes, and the
	// confirm must come over the tailnet.
	f := guardFirewallFacts("inactive", "22", facts.UFWRule{Action: "allow", Direction: "in", Proto: "any", Interface: "tailscale0"})
	p, err := prove(turnOn, f, "100.100.1.2")
	if err != nil || !slices.Equal(p.ConfirmFrom, []string{TailnetV4.String(), TailnetV6.String()}) {
		t.Errorf("tailnet: %+v %v", p, err)
	}
	// A source rule: the session in it passes, the confirm must come
	// from that network.
	f = guardFirewallFacts("active", "22", facts.UFWRule{Action: "limit", Direction: "in", Port: "22", Proto: "tcp", From: "198.51.100.0/24"})
	p, err = prove(FirewallChange{What: "reloads"}, f, "198.51.100.7")
	if err != nil || !slices.Equal(p.ConfirmFrom, []string{"198.51.100.0/24"}) || !strings.Contains(p.Ways[0], "198.51.100.7") {
		t.Errorf("source: %+v %v", p, err)
	}
}
