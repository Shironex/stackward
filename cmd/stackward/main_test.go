//go:build !stackward_scenario

package main

import (
	"testing"

	"github.com/Shironex/stackward/internal/plan"
	"github.com/Shironex/stackward/internal/plan/txntest"
)

// realAccessCritical lists the access-critical steps a released binary may
// carry: the account and sshd steps, the firewall steps and the fail2ban
// jail.
var realAccessCritical = map[string]bool{
	plan.AdminUserID: true, plan.PaaSUserID: true, plan.LockDefaultUserID: true, plan.SSHDHardeningID: true,
	"fail2ban-sshd": true, plan.UFWPolicyID: true,
}

// The binary as released (no build tag) must not contain the test-only
// access-critical steps, nor any access-critical step that is not a real
// one.
func TestReleasedBinaryHasNoTestSteps(t *testing.T) {
	for _, id := range txntest.IDs {
		if _, ok := plan.Lookup(id); ok {
			t.Errorf("test step %s is registered in the released binary", id)
		}
	}
	for _, g := range plan.Generators() {
		if g.Risk == plan.AccessCritical && !realAccessCritical[g.ID] {
			t.Errorf("access-critical step %s is not a known real step", g.ID)
		}
	}
}
