package test

import (
	"fmt"
	"path/filepath"
	"strings"
	"testing"
)

// agreementFixtures give one published web port per firewall flavour, with a
// tunnel as the ingress. DKR-001, NET-004 and CF-003 must reach the same
// verdict for the port, or one report disagrees with itself.
//
// Without Docker API facts DKR-001 is not inspected (it has no binding to
// judge), so the scenarios without them expect no DKR-001 verdict: NET-004
// and CF-003 still say yes when nothing filters forwarded traffic, because
// the container port does not matter then, and stay unknown when rules exist.
var agreementFixtures = map[string]struct{ want, dkr string }{
	"fwd-ufw-docker-route-open":   {"yes", "yes"},
	"ufw-docker-deny-all":         {"no", "no"},
	"fwd-docker-user-drop":        {"no", "no"},
	"cf-tunnel-origin-bypass":     {"yes", "yes"}, // DOCKER-USER without rules
	"fwd-nftables-backend":        {"yes", "yes"},
	"fwd-iptables-off":            {"no", "no"},
	"fwd-docker-user-unread":      {"unknown", "unknown"},
	"fwd-no-api-unfiltered":       {"yes", ""},
	"fwd-no-api-docker-user-drop": {"unknown", ""},
}

func TestPublishedPortVerdictsAgree(t *testing.T) {
	for name, tc := range agreementFixtures {
		want := tc.want
		t.Run(name, func(t *testing.T) {
			rep := evaluate(t, filepath.Join("fixtures", name, "facts.json"))
			var dkr, net, cf string
			for _, r := range rep.Results {
				switch {
				case r.ID == "DKR-001":
					if v := dkrVerdict(r.Evidence, "443"); v != "" {
						dkr = v
					}
				case r.ID == "NET-004" && r.Subject == "port:tcp/443":
					net = fmt.Sprint(r.Evidence["open_from_anywhere"])
				case r.ID == "CF-003":
					cf = fmt.Sprint(r.Evidence["open_from_anywhere"])
				}
			}
			if dkr != tc.dkr {
				t.Errorf("DKR-001 says %q for tcp/443, want %q", dkr, tc.dkr)
			}
			for check, got := range map[string]string{"NET-004": net, "CF-003": cf} {
				if got != want {
					t.Errorf("%s says %q for tcp/443, want %q (DKR-001 %q, NET-004 %q, CF-003 %q)", check, got, want, dkr, net, cf)
				}
			}
		})
	}
}

// dkrVerdict reads DKR-001's per binding lists for a host port.
func dkrVerdict(ev map[string]any, port string) string {
	for key, verdict := range map[string]string{"open": "yes", "filtered": "no", "unknown": "unknown"} {
		list, _ := ev[key].([]any)
		for _, b := range list {
			if strings.Contains(fmt.Sprint(b), ":"+port+"->") {
				return verdict
			}
		}
	}
	return ""
}
