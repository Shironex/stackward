package plan

import (
	"net/netip"
	"strings"
	"testing"

	"github.com/Shironex/stackward/internal/profile"
)

// The guard runs through ProveAccess and the plan time veto for the
// registered steps.
func TestFirewallStepsGoThroughTheLockoutGuard(t *testing.T) {
	in := fwInput(t, policyFixture, profile.Unknown, restrictSSH)
	s := complete(mustLookup(t, UFWPolicyID), *planUFWPolicy(in).Step)
	if !NeedsProof(s) {
		t.Fatal("ufw-policy must need the guard's proof")
	}
	veto := LockoutVeto(GuardInput{Facts: in.Facts, Source: netip.MustParseAddr("192.0.2.10")})
	if reason := veto(s); !strings.Contains(reason, "192.0.2.10") {
		t.Errorf("a session outside the allowed sources: %q", reason)
	}
	ok := LockoutVeto(GuardInput{Facts: in.Facts, Source: netip.MustParseAddr("198.51.100.20")})
	if reason := ok(s); reason != "" {
		t.Errorf("a session inside them: %q", reason)
	}
	d := fwInput(t, dockerFixture, profile.PaaSPanel, nil)
	ds := complete(mustLookup(t, UFWDockerID), *planUFWDocker(d).Step)
	if p, err := ProveAccess(ds, GuardInput{Facts: d.Facts}); err != nil || !p.Needed {
		t.Errorf("ufw-docker: %+v %v", p, err)
	}
}
