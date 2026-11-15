// Package profile names the intended ingress of a host. The profile changes
// what checks expect (80/443 open is fine on public-web, a bypass on
// tunnel); it never hides a finding.
package profile

import (
	"fmt"

	"github.com/Shironex/stackward/internal/facts"
)

// Name is one ingress profile.
type Name string

// Known profiles. Unknown means "not inferred": checks that depend on the
// profile must then return unknown or judge without it, never pass.
const (
	Unknown     Name = "unknown"
	Tunnel      Name = "tunnel"       // nothing public; ingress through a tunnel
	PublicWeb   Name = "public-web"   // 80/443 public by design
	TailnetOnly Name = "tailnet-only" // reachable over the tailnet only
	PaaSPanel   Name = "paas-panel"   // hosts a PaaS control panel
)

// All lists the profiles a user may pass to --profile, in display order.
var All = []Name{Tunnel, PublicWeb, TailnetOnly, PaaSPanel}

// Parse validates a --profile value. "auto" and "" mean infer.
func Parse(s string) (Name, bool, error) {
	if s == "" || s == "auto" {
		return Unknown, false, nil
	}
	for _, n := range All {
		if string(n) == s {
			return n, true, nil
		}
	}
	return Unknown, false, fmt.Errorf("unknown profile %q (want auto, tunnel, public-web, tailnet-only or paas-panel)", s)
}

// Infer guesses the profile from facts. The firewall and exposure slice
// implements it; until then every host is Unknown.
func Infer(*facts.Facts) Name { return Unknown }
