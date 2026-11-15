package cli

import (
	"slices"
	"strings"
	"testing"

	"github.com/Shironex/stackward/internal/plan"
	"github.com/Shironex/stackward/internal/report"
)

// The account flags of stackward plan, over the account fixtures.

func TestPlanAdminUserFromTheFlags(t *testing.T) {
	code, out, errs := run("plan", "--no-sandbox", "--facts", fixture("plan-accounts-create"), "--admin-user", "ops", "--admin-keys-from", "ubuntu", "--json")
	if code != report.ExitOK {
		t.Fatalf("exit %d: %s", code, errs)
	}
	p := decodePlan(t, []byte(out))
	if !slices.ContainsFunc(p.Steps, func(s plan.Step) bool { return s.ID == plan.AdminUserID }) {
		t.Fatalf("no admin-user step: %+v", p.Skipped)
	}
	// Without the flags it says how to ask for one.
	code, out, _ = run("plan", "--no-sandbox", "--facts", fixture("plan-accounts-create"))
	if code != report.ExitOK || !strings.Contains(out, "--admin-user NAME --admin-keys-from USER") {
		t.Errorf("exit %d:\n%s", code, out)
	}
}

func TestPlanRefusesBadAccountFlags(t *testing.T) {
	for _, args := range [][]string{
		{"--admin-user", "root"},
		{"--admin-user", "../etc"},
		{"--paas-user", "Bad Name"},
		{"--admin-keys-from", "ubuntu"},
	} {
		code, _, errs := run(append([]string{"plan", "--no-sandbox", "--facts", fixture("plan-accounts-create")}, args...)...)
		if code != report.ExitError || errs == "" {
			t.Errorf("%v: exit %d %q", args, code, errs)
		}
	}
}

// A plan from a saved facts file has no applying session, so the lockout
// guard refuses the lock: it must come from a session of the admin
// account.
func TestPlanRefusesTheLockWithoutTheAdminSession(t *testing.T) {
	code, out, errs := run("plan", "--no-sandbox", "--facts", fixture("plan-accounts-lock"), "--json")
	if code != report.ExitOK {
		t.Fatalf("exit %d: %s", code, errs)
	}
	p := decodePlan(t, []byte(out))
	i := slices.IndexFunc(p.Skipped, func(s plan.Skipped) bool { return s.ID == plan.LockDefaultUserID })
	if i < 0 || p.Skipped[i].Kind != plan.SkipRefused || !strings.Contains(p.Skipped[i].Reason, "the account applying it is unknown") {
		t.Fatalf("lock-default-user: %+v", p.Skipped)
	}
	if !slices.ContainsFunc(p.Steps, func(s plan.Step) bool { return s.ID == plan.SSHDHardeningID }) {
		t.Errorf("sshd-hardening is proven by ops and should be planned: %+v", p.Skipped)
	}
}
