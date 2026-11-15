package apply_test

import (
	"strings"
	"testing"

	"github.com/Shironex/stackward/internal/apply"
	"github.com/Shironex/stackward/internal/apply/applytest"
	"github.com/Shironex/stackward/internal/plan"
	"github.com/Shironex/stackward/internal/report"
)

// An access-critical generator exists only in this test binary: no real
// step is access-critical yet.
func init() {
	plan.Register(plan.Generator{
		ID: "test-access-step", Title: "test", Fixes: []string{"SSH-001"}, Risk: plan.AccessCritical,
		Plan:      func(plan.Input) plan.Outcome { return plan.Outcome{} },
		Authorize: func(plan.Step) error { return nil },
		Check:     func(plan.Reader, plan.Step) (bool, string, error) { return false, "", nil },
	})
}

func withAccessStep(p *plan.Plan) *plan.Plan {
	cp := *p
	cp.Steps = append(append([]plan.Step{}, p.Steps...), plan.Step{ID: "test-access-step", Risk: plan.AccessCritical, Fixes: []string{"SSH-001"}})
	return &cp
}

func TestSelect(t *testing.T) {
	p := withAccessStep(applytest.FixturePlan(t, "plan-host-settings-fix"))

	if _, err := apply.Select(p, nil, false); err == nil || !strings.Contains(err.Error(), "--all-safe") {
		t.Errorf("no selection: %v", err)
	}
	if _, err := apply.Select(p, []string{"make-coffee"}, false); err == nil || !strings.Contains(err.Error(), "not in this plan") {
		t.Errorf("unknown id: %v", err)
	}
	if _, err := apply.Select(p, []string{"test-access-step"}, false); err == nil || !strings.Contains(err.Error(), "#26") {
		t.Errorf("access-critical named: %v", err)
	}

	sel, err := apply.Select(p, nil, true)
	if err != nil {
		t.Fatal(err)
	}
	if got := strings.Join(ids(sel.Steps), ","); got != "journald-cap,sysctl-hardening" {
		t.Errorf("--all-safe: %s", got)
	}
	reasons := map[string]string{}
	for _, n := range sel.NotRun {
		reasons[n.ID] = n.Reason
	}
	if !strings.Contains(reasons["docker-log-rotation"], "--step docker-log-rotation") || !strings.Contains(reasons["docker-log-rotation"], "restarts docker") {
		t.Errorf("docker reason %q", reasons["docker-log-rotation"])
	}
	if !strings.Contains(reasons["test-access-step"], "#26") {
		t.Errorf("access reason %q", reasons["test-access-step"])
	}

	sel, err = apply.Select(p, []string{"docker-log-rotation"}, false)
	if err != nil {
		t.Fatal(err)
	}
	if got := strings.Join(ids(sel.Steps), ","); got != "docker-log-rotation" {
		t.Errorf("--step docker: %s", got)
	}
	// A plan that relabels the Docker step as safe does not sneak it into
	// --all-safe: selection reads the registry.
	relabeled := applytest.FixturePlan(t, "plan-host-settings-fix")
	for i := range relabeled.Steps {
		relabeled.Steps[i].Risk, relabeled.Steps[i].OptIn = plan.Safe, false
	}
	sel, _ = apply.Select(relabeled, nil, true)
	if got := strings.Join(ids(sel.Steps), ","); got != "journald-cap,sysctl-hardening" {
		t.Errorf("relabeled --all-safe: %s", got)
	}
}

func TestCheckPlan(t *testing.T) {
	good := applytest.FixturePlan(t, "plan-host-settings-fix")
	if err := apply.CheckPlan(good, applytest.Hostname); err != nil {
		t.Fatalf("good plan: %v", err)
	}
	shown := applytest.FixturePlan(t, "plan-host-settings-fix")
	shown.Host = report.Host{Hostname: applytest.Hostname}
	if err := apply.CheckPlan(shown, applytest.Hostname); err != nil {
		t.Errorf("plan with --show-hostname: %v", err)
	}
	for name, tc := range map[string]struct {
		edit     func(p *plan.Plan)
		hostname string
		want     string
	}{
		"other host":   {func(*plan.Plan) {}, "other.example.com", "plan again on this host"},
		"no hostname":  {func(*plan.Plan) {}, "", "host's name"},
		"other schema": {func(p *plan.Plan) { p.Schema = "stackward.plan.v2" }, applytest.Hostname, "schema"},
		"other tool":   {func(p *plan.Plan) { p.Tool.Name = "kakoi" }, applytest.Hostname, "not stackward"},
		"bad hash": {func(p *plan.Plan) {
			p.Steps[0].Edits[0].NewSHA256 = strings.Repeat("0", 64)
		}, applytest.Hostname, "not valid"},
	} {
		t.Run(name, func(t *testing.T) {
			p := applytest.FixturePlan(t, "plan-host-settings-fix")
			tc.edit(p)
			if err := apply.CheckPlan(p, tc.hostname); err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Errorf("err %v, want %q", err, tc.want)
			}
		})
	}
}
