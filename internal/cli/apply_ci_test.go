package cli

import (
	"strings"
	"testing"

	"github.com/Shironex/stackward/internal/apply"
	"github.com/Shironex/stackward/internal/report"
)

// Apply refuses in a CI job that did not say it owns a throwaway VM,
// before it needs root or reads the plan, and changes nothing.
func TestApplyRefusesInCI(t *testing.T) {
	a := newApplyTest(t)
	a.env.ci = func() apply.CIEnv { return apply.CIEnv{Var: "GITHUB_ACTIONS", Where: "pid 300 (bash)"} }
	a.env.euid = func() int { return 1000 }
	code, out, errs := a.apply("--all-safe", "--yes", a.plan)
	if code != report.ExitError || !strings.Contains(errs, "CI job") || !strings.Contains(errs, apply.CIApplyEnv+"="+apply.CIApplyValue) ||
		!strings.Contains(errs, "nothing was changed") || strings.Contains(errs, "needs root") {
		t.Errorf("exit %d: %s%s", code, out, errs)
	}
	if len(a.runner.Calls()) != 0 {
		t.Errorf("commands ran: %v", a.runner.Calls())
	}
	assertUntouched(t, a)

	// The matrix job's flag lets it through to the usual checks.
	a.env.ci = func() apply.CIEnv { return apply.CIEnv{Var: "GITHUB_ACTIONS", Where: "pid 300 (bash)", Allowed: true} }
	a.env.euid = func() int { return 0 }
	if code, out, errs = a.apply("--all-safe", "--yes", a.plan); code != report.ExitOK {
		t.Errorf("allowed: exit %d: %s%s", code, out, errs)
	}
}
