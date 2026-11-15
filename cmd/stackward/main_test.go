//go:build !stackward_scenario

package main

import (
	"testing"

	"github.com/Shironex/stackward/internal/plan"
	"github.com/Shironex/stackward/internal/plan/txntest"
)

// realAccessCritical lists the access-critical steps a released binary may
// carry. None exists yet; #28 adds the first.
var realAccessCritical = map[string]bool{}

// The binary as released (no build tag) must not contain the test-only
// access-critical steps, nor any access-critical step that is not a real
// one.
func TestReleasedBinaryHasNoTestSteps(t *testing.T) {
	for _, id := range []string{txntest.GoodID, txntest.BadID} {
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
