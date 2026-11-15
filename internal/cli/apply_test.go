package cli

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/Shironex/stackward/internal/apply"
	"github.com/Shironex/stackward/internal/apply/applytest"
	"github.com/Shironex/stackward/internal/plan"
	"github.com/Shironex/stackward/internal/report"
)

// Every apply and undo test runs through testEnv: a t.TempDir() root, a
// fake runner and an injected euid, so a test never writes outside its
// temporary directory or starts a program, even when go test runs as root.

type applyTest struct {
	root   string
	runner *applytest.Runner
	env    applyEnv
	plan   string
}

func newApplyTest(t *testing.T) *applyTest {
	t.Helper()
	root := t.TempDir()
	p := applytest.FixturePlan(t, "plan-host-settings-fix")
	applytest.Seed(t, root, p)
	b, err := json.Marshal(p)
	if err != nil {
		t.Fatal(err)
	}
	planFile := filepath.Join(t.TempDir(), "plan.json")
	if err := os.WriteFile(planFile, b, 0o600); err != nil {
		t.Fatal(err)
	}
	h, r := applytest.NewHost(root)
	return &applyTest{
		root: root, runner: r, plan: planFile,
		env: applyEnv{
			host: h, goos: "linux",
			euid:     func() int { return 0 },
			hostname: func() (string, error) { return applytest.Hostname, nil },
			stdin:    strings.NewReader(""),
			isTTY:    func() bool { return false },
			now:      func() time.Time { return time.Date(2026, 3, 1, 12, 0, 0, 0, time.UTC) },
			runID:    "20260301T120000Z-c11c11",
		},
	}
}

func (a *applyTest) apply(args ...string) (int, string, string) {
	var out, errs bytes.Buffer
	code := runApplyEnv(args, &out, &errs, a.env)
	return code, out.String(), errs.String()
}

func (a *applyTest) undo(args ...string) (int, string, string) {
	var out, errs bytes.Buffer
	code := runUndoEnv(args, &out, &errs, a.env)
	return code, out.String(), errs.String()
}

func TestApplyRefusesWithoutRoot(t *testing.T) {
	a := newApplyTest(t)
	a.env.euid = func() int { return 1000 }
	code, _, errs := a.apply("--all-safe", "--yes", a.plan)
	if code != report.ExitError || !strings.Contains(errs, "needs root") || !strings.Contains(errs, "1000") || !strings.Contains(errs, "nothing was changed") {
		t.Errorf("exit %d: %s", code, errs)
	}
	code, _, errs = a.undo("--run", "20260301T120000Z-c11c11", "--yes")
	if code != report.ExitError || !strings.Contains(errs, "needs root") {
		t.Errorf("undo: exit %d: %s", code, errs)
	}
	a.env.euid = func() int { return 0 }
	a.env.goos = "darwin"
	if code, _, errs = a.apply("--all-safe", "--yes", a.plan); code != report.ExitError || !strings.Contains(errs, "Linux") {
		t.Errorf("darwin: exit %d: %s", code, errs)
	}
	assertUntouched(t, a)
}

func TestApplyRefusals(t *testing.T) {
	for name, tc := range map[string]struct {
		args func(a *applyTest) []string
		prep func(a *applyTest)
		want string
	}{
		"no selection":   {func(a *applyTest) []string { return []string{"--yes", a.plan} }, nil, "--all-safe"},
		"unknown step":   {func(a *applyTest) []string { return []string{"--step", "nope", "--yes", a.plan} }, nil, "not in this plan"},
		"no plan":        {func(*applyTest) []string { return []string{"--all-safe"} }, nil, "exactly one plan file"},
		"no terminal":    {func(a *applyTest) []string { return []string{"--all-safe", a.plan} }, nil, "pass --yes"},
		"other host":     {func(a *applyTest) []string { return []string{"--all-safe", "--yes", a.plan} }, func(a *applyTest) { a.env.hostname = func() (string, error) { return "other.example.com", nil } }, "plan again on this host"},
		"changed file":   {func(a *applyTest) []string { return []string{"--step", "docker-log-rotation", "--yes", a.plan} }, func(a *applyTest) { applytest.Write(t, a.root, "/etc/docker/daemon.json", "{}\n", 0o644) }, "changed since the audit"},
		"unknown field":  {func(a *applyTest) []string { return []string{"--all-safe", "--yes", a.plan} }, func(a *applyTest) { rewritePlan(t, a, func(m map[string]any) { m["ordering"] = "x" }) }, "unknown field"},
		"tampered cmd":   {func(a *applyTest) []string { return []string{"--all-safe", "--yes", a.plan} }, func(a *applyTest) { tamperCommand(t, a) }, "not one the step runs"},
		"step and plan2": {func(a *applyTest) []string { return []string{a.plan, a.plan, "--all-safe", "--yes"} }, nil, "exactly one plan file"},
	} {
		t.Run(name, func(t *testing.T) {
			a := newApplyTest(t)
			if tc.prep != nil {
				tc.prep(a)
			}
			code, _, errs := a.apply(tc.args(a)...)
			if code != report.ExitError || !strings.Contains(errs, tc.want) {
				t.Errorf("exit %d, want %q in: %s", code, tc.want, errs)
			}
			if len(a.runner.Calls()) != 0 {
				t.Errorf("commands ran: %v", a.runner.Calls())
			}
			if _, err := os.Stat(filepath.Join(a.root, "var")); err == nil {
				t.Error("a refusal created the backup directory")
			}
		})
	}
}

func TestApplyRunTwiceThenUndo(t *testing.T) {
	a := newApplyTest(t)
	// Flags after the plan file work too.
	code, out, errs := a.apply(a.plan, "--all-safe", "--yes")
	if code != report.ExitOK {
		t.Fatalf("exit %d: %s\n%s", code, out, errs)
	}
	for _, want := range []string{
		"sandbox:   none", "Will apply:", "journald-cap", "sysctl-hardening",
		"docker-log-rotation  networking (restarts docker): runs only with --step docker-log-rotation",
		"restarts:  systemd-journald", "run:       20260301T120000Z-c11c11 (ok)",
		"sudo stackward undo --run 20260301T120000Z-c11c11",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("output lacks %q:\n%s", want, out)
		}
	}
	if _, ok := applytest.Read(t, a.root, apply.JournalPath("20260301T120000Z-c11c11")); !ok {
		t.Fatal("no journal")
	}

	a.runner.Reset()
	a.env.runID = "20260301T120000Z-c22c22"
	code, out, _ = a.apply("--all-safe", "--yes", a.plan)
	if code != report.ExitOK || !strings.Contains(out, "nothing to do") || !strings.Contains(out, "Already applied") {
		t.Errorf("second run: exit %d:\n%s", code, out)
	}
	if len(a.runner.Calls()) != 0 {
		t.Errorf("second run ran %v", a.runner.Calls())
	}
	if _, ok := applytest.Read(t, a.root, apply.JournalPath("20260301T120000Z-c22c22")); ok {
		t.Error("a run with nothing to do wrote a journal")
	}

	code, out, errs = a.undo("--run", "20260301T120000Z-c11c11", "--yes")
	if code != report.ExitOK || !strings.Contains(out, "undone") {
		t.Fatalf("undo: exit %d:\n%s\n%s", code, out, errs)
	}
	for _, p := range []string{"/etc/systemd/journald.conf.d/90-stackward-journal-cap.conf", "/etc/sysctl.d/90-stackward-hardening.conf"} {
		if _, ok := applytest.Read(t, a.root, p); ok {
			t.Errorf("%s is still there after undo", p)
		}
	}
	code, out, _ = a.undo("--run", "20260301T120000Z-c11c11", "--yes")
	if code != report.ExitOK || !strings.Contains(out, "nothing to undo") {
		t.Errorf("second undo: exit %d:\n%s", code, out)
	}
	if code, _, errs = a.undo("--run", "../../etc/passwd", "--yes"); code != report.ExitError || !strings.Contains(errs, "not a run id") {
		t.Errorf("bad run id: exit %d: %s", code, errs)
	}
}

func TestApplyAsksOnATerminal(t *testing.T) {
	a := newApplyTest(t)
	a.env.isTTY = func() bool { return true }
	a.env.stdin = strings.NewReader("n\n")
	code, out, _ := a.apply("--step", "journald-cap", a.plan)
	if code != report.ExitError || !strings.Contains(out, "Apply 1 step(s) on this host? [y/N]") || !strings.Contains(out, "not confirmed") {
		t.Errorf("answer n: exit %d:\n%s", code, out)
	}
	assertUntouched(t, a)

	a.env.stdin = strings.NewReader("y\n")
	if code, out, _ = a.apply("--step", "journald-cap", a.plan); code != report.ExitOK {
		t.Errorf("answer y: exit %d:\n%s", code, out)
	}
	if _, ok := applytest.Read(t, a.root, "/etc/systemd/journald.conf.d/90-stackward-journal-cap.conf"); !ok {
		t.Error("confirmed, yet nothing was written")
	}
}

func TestApplyFailurePrintsUndo(t *testing.T) {
	a := newApplyTest(t)
	a.runner.Exit["sysctl"] = 255
	code, out, errs := a.apply("--all-safe", "--yes", a.plan)
	if code != exitStepFailed {
		t.Fatalf("exit %d", code)
	}
	if !strings.Contains(errs, "sysctl -p /etc/sysctl.d/90-stackward-hardening.conf exited 255") || !strings.Contains(errs, "later steps did not run") {
		t.Errorf("stderr: %s", errs)
	}
	for _, want := range []string{"(failed)", "To undo this run:", "rm -f /etc/sysctl.d/90-stackward-hardening.conf", "rm -f /etc/systemd/journald.conf.d/90-stackward-journal-cap.conf"} {
		if !strings.Contains(out, want) {
			t.Errorf("output lacks %q:\n%s", want, out)
		}
	}
}

func TestApplyAndUndoAreRouted(t *testing.T) {
	// Run routes to the host env; -h never touches anything.
	if code, _, errs := run("apply", "-h"); code != report.ExitOK || !strings.Contains(errs, "Usage: stackward apply") {
		t.Errorf("apply -h: %d %s", code, errs)
	}
	if code, _, errs := run("undo", "-h"); code != report.ExitOK || !strings.Contains(errs, "Usage: stackward undo") {
		t.Errorf("undo -h: %d %s", code, errs)
	}
}

func assertUntouched(t *testing.T, a *applyTest) {
	t.Helper()
	if len(a.runner.Calls()) != 0 {
		t.Errorf("commands ran: %v", a.runner.Calls())
	}
	for _, p := range []string{"var", "etc/systemd", "etc/sysctl.d"} {
		if _, err := os.Stat(filepath.Join(a.root, p)); err == nil {
			t.Errorf("%s was created", p)
		}
	}
}

func rewritePlan(t *testing.T, a *applyTest, edit func(map[string]any)) {
	t.Helper()
	b, err := os.ReadFile(a.plan)
	if err != nil {
		t.Fatal(err)
	}
	var m map[string]any
	if err := json.Unmarshal(b, &m); err != nil {
		t.Fatal(err)
	}
	edit(m)
	if b, err = json.Marshal(m); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(a.plan, b, 0o600); err != nil {
		t.Fatal(err)
	}
}

func tamperCommand(t *testing.T, a *applyTest) {
	t.Helper()
	b, _ := os.ReadFile(a.plan)
	var p plan.Plan
	if err := json.Unmarshal(b, &p); err != nil {
		t.Fatal(err)
	}
	p.Steps[0].Commands[0].Args = []string{"bash", "-c", "id"}
	b, _ = json.Marshal(p)
	if err := os.WriteFile(a.plan, b, 0o600); err != nil {
		t.Fatal(err)
	}
}
