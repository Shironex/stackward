package cli

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/Shironex/stackward/internal/plan"
	"github.com/Shironex/stackward/internal/report"
	"github.com/Shironex/stackward/internal/schemacheck"
)

// Every plan call here passes --no-sandbox, like the audit tests; the
// sandboxed run is TestPlanUnderLandlock, in a child process.

func planSchema(t *testing.T) []byte {
	t.Helper()
	b, err := os.ReadFile(filepath.Join("..", "..", "schema", "plan.v1.json"))
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func decodePlan(t *testing.T, b []byte) plan.Plan {
	t.Helper()
	var p plan.Plan
	if err := json.Unmarshal(b, &p); err != nil {
		t.Fatalf("%v\n%s", err, b)
	}
	return p
}

func TestPlanJSONFromFacts(t *testing.T) {
	code, out, errs := run("plan", "--no-sandbox", "--facts", fixture("plan-host-settings-fix"), "--json")
	if code != report.ExitOK {
		t.Fatalf("exit %d: %s", code, errs)
	}
	for _, e := range schemacheck.Validate(planSchema(t), []byte(out)) {
		t.Error(e)
	}
	p := decodePlan(t, []byte(out))
	if p.Source.Kind != plan.FromFacts || !p.Source.Facts || p.Sandbox.State != "disabled" {
		t.Errorf("source %+v sandbox %+v", p.Source, p.Sandbox)
	}
	if p.Summary.Steps != 3 || p.Summary.Networking != 1 || p.Summary.OptIn != 1 {
		t.Errorf("summary %+v", p.Summary)
	}
	if err := p.Validate(); err != nil {
		t.Error(err)
	}
}

func TestPlanOutAndSummary(t *testing.T) {
	path := filepath.Join(t.TempDir(), "plan.json")
	code, out, errs := run("plan", "--no-sandbox", "--facts", fixture("plan-host-settings-fix"), "--out", path)
	if code != report.ExitOK {
		t.Fatalf("exit %d: %s", code, errs)
	}
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range schemacheck.Validate(planSchema(t), b) {
		t.Error(e)
	}
	if fi, _ := os.Stat(path); fi.Mode().Perm() != 0o600 {
		t.Errorf("plan file mode %v, want 0600", fi.Mode().Perm())
	}
	for _, want := range []string{"nothing on this host was changed", "1. journald-cap  [safe]  fixes LOG-001", "3. docker-log-rotation  [networking]", "restarts:  systemd-journald, docker"} {
		if !strings.Contains(out, want) {
			t.Errorf("summary misses %q:\n%s", want, out)
		}
	}
}

func TestPlanEmitScript(t *testing.T) {
	code, out, errs := run("plan", "--no-sandbox", "--facts", fixture("plan-host-settings-fix"), "--emit-script")
	if code != report.ExitOK {
		t.Fatalf("exit %d: %s", code, errs)
	}
	golden, err := os.ReadFile(filepath.Join("..", "..", "test", "fixtures", "plan-host-settings-fix", "plan.sh"))
	if err != nil {
		t.Fatal(err)
	}
	// Only the header names the version and the source; the steps match
	// the golden script byte for byte.
	body := func(s string) string {
		_, rest, ok := strings.Cut(s, "set -eu\n")
		if !ok {
			t.Fatalf("no set -eu in:\n%s", s)
		}
		return rest
	}
	if body(out) != body(string(golden)) {
		t.Errorf("script differs from the golden plan.sh:\n%s", out)
	}
}

func TestPlanFromReport(t *testing.T) {
	dir := t.TempDir()
	repPath := filepath.Join(dir, "report.json")
	if code, _, errs := run("audit", "--no-sandbox", "--facts", fixture("plan-host-settings-fix"), "--json", "--out", repPath, "--fail-on", "never"); code != report.ExitOK {
		t.Fatalf("audit: %s", errs)
	}
	// A report alone has no file contents: nothing can be planned.
	code, out, errs := run("plan", "--no-sandbox", "--report", repPath, "--json")
	if code != report.ExitOK {
		t.Fatalf("exit %d: %s", code, errs)
	}
	p := decodePlan(t, []byte(out))
	if p.Source.Kind != plan.FromReport || p.Source.Facts || len(p.Steps) != 0 || len(p.Skipped) != len(plan.Generators()) {
		t.Fatalf("report alone: %+v", p)
	}
	for _, s := range p.Skipped {
		if s.Kind != plan.SkipUnknown {
			t.Errorf("%s: %s, want unknown", s.ID, s.Kind)
		}
	}
	// With the facts of the same audit, the steps come back.
	code, out, errs = run("plan", "--no-sandbox", "--report", repPath, "--facts", fixture("plan-host-settings-fix"), "--json")
	if code != report.ExitOK {
		t.Fatalf("exit %d: %s", code, errs)
	}
	if p := decodePlan(t, []byte(out)); p.Source.Kind != plan.FromReportFacts || len(p.Steps) != 3 {
		t.Errorf("report and facts: %+v", p.Summary)
	}
	// Facts of another audit are refused.
	code, _, errs = run("plan", "--no-sandbox", "--report", repPath, "--facts", fixture("plan-host-settings-ok"))
	if code != report.ExitError || !strings.Contains(errs, "different audits") {
		t.Errorf("mismatched facts: exit %d, %s", code, errs)
	}
}

func TestPlanFlagErrors(t *testing.T) {
	for _, args := range [][]string{
		{"--json", "--emit-script"},
		{"--report", "r.json", "--profile", "tunnel"},
		{"--profile", "moat"},
		{"--facts", "does-not-exist.json"},
		{"stray"},
	} {
		code, _, errs := run(append([]string{"plan", "--no-sandbox"}, args...)...)
		if code != report.ExitError || errs == "" {
			t.Errorf("%v: exit %d, stderr %q", args, code, errs)
		}
	}
	if code, _, _ := run("plan", "-h"); code != report.ExitOK {
		t.Errorf("-h exit %d", code)
	}
}
