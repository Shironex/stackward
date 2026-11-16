package cli

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	tea "charm.land/bubbletea/v2"
	"github.com/charmbracelet/x/ansi"
	"github.com/charmbracelet/x/exp/golden"
	"github.com/charmbracelet/x/exp/teatest/v2"

	"github.com/Shironex/stackward/internal/apply"
	"github.com/Shironex/stackward/internal/apply/applytest"
	"github.com/Shironex/stackward/internal/facts"
	"github.com/Shironex/stackward/internal/plan/txntest"
	"github.com/Shironex/stackward/internal/report"
	"github.com/Shironex/stackward/internal/tui"
)

// The step list over real plans: the CLI judges the steps with apply's
// code, the list (internal/tui) is driven with teatest, and a confirmed
// choice runs through applySelected against a t.TempDir() root. No test
// opens a terminal or applies the sandbox. This file sorts after
// plan_test.go: it registers the test-only access steps.

func stepsBackendFor(t *testing.T, a *applyTest) (*stepsBackend, tui.StepList) {
	t.Helper()
	p, _, err := loadPlan(a.plan)
	if err != nil {
		t.Fatal(err)
	}
	var errs bytes.Buffer
	b, list, err := newStepsBackend(context.Background(), a.env, a.plan, p, apply.DefaultConfirmWithin, &errs)
	if err != nil {
		t.Fatalf("%v (%s)", err, errs.String())
	}
	return b, list
}

func stepKey(k string) tea.KeyPressMsg {
	switch k {
	case "enter":
		return tea.KeyPressMsg{Code: tea.KeyEnter}
	case "down":
		return tea.KeyPressMsg{Code: tea.KeyDown}
	case "end":
		return tea.KeyPressMsg{Code: tea.KeyEnd}
	case "ctrl+c":
		return tea.KeyPressMsg{Code: 'c', Mod: tea.ModCtrl}
	}
	r := []rune(k)[0]
	return tea.KeyPressMsg{Code: r, Text: k}
}

// driveList runs the list at 80x24, presses keys and returns the final
// model; a trailing ctrl+c quits whatever is on screen.
func driveList(t *testing.T, b *stepsBackend, list tui.StepList, keys ...string) tui.StepsModel {
	t.Helper()
	tm := teatest.NewTestModel(t, tui.NewSteps(list, b.options(true)), teatest.WithInitialTermSize(80, 24))
	for _, k := range keys {
		tm.Send(stepKey(k))
	}
	tm.Send(stepKey("ctrl+c"))
	m, ok := tm.FinalModel(t, teatest.WithFinalTimeout(5*time.Second)).(tui.StepsModel)
	if !ok {
		t.Fatal("final model is not a tui.StepsModel")
	}
	return m
}

func TestStepListFlagErrors(t *testing.T) {
	planFile := filepath.Join("..", "..", "test", "fixtures", "plan-host-settings-fix", "plan.json")
	for _, tc := range []struct {
		args []string
		want string
	}{
		{[]string{"--plan", planFile, "--report", savedReport("ubuntu-2404-clean")}, "--report does not go with --plan"},
		{[]string{"--plan", planFile, "--no-sandbox"}, "--no-sandbox does not go with --plan"},
		{[]string{"--plan", planFile, "--profile", "tunnel"}, "--profile does not go with --plan"},
		{[]string{"--confirm-within", "10m"}, "--confirm-within goes with --plan"},
		{[]string{"--plain", "--report", savedReport("ubuntu-2404-clean")}, "--plain goes with --plan"},
		{[]string{"--plan", "does-not-exist.json"}, "does-not-exist.json"},
		{[]string{"--plan", planFile, "stray"}, "unexpected argument"},
	} {
		code, out, errs := run(append([]string{"tui"}, tc.args...)...)
		if code != report.ExitError || !strings.Contains(errs, tc.want) {
			t.Errorf("tui %v: exit %d stderr %q, want %q", tc.args, code, errs, tc.want)
		}
		if out != "" {
			t.Errorf("tui %v wrote to stdout: %q", tc.args, out)
		}
	}
}

// Without a terminal (and with --plain) the step list prints the plan as
// stackward plan does and applies nothing; it needs no root for that.
func TestStepListWithoutATerminalPrintsThePlan(t *testing.T) {
	dir := filepath.Join("..", "..", "test", "fixtures", "plan-host-settings-fix")
	want, err := os.ReadFile(filepath.Join(dir, "plan.txt"))
	if err != nil {
		t.Fatal(err)
	}
	for _, args := range [][]string{{"--plan", filepath.Join(dir, "plan.json")}, {"--plain", "--plan", filepath.Join(dir, "plan.json")}} {
		a := newApplyTest(t)
		a.env.euid = func() int { return 1000 }
		var out, errs bytes.Buffer
		code := runTUIEnv(args, &out, &errs, a.env)
		if code != report.ExitOK || out.String() != string(want) {
			t.Errorf("%v: exit %d, stdout is not plan.txt:\n%s", args, code, out.String())
		}
		if !strings.Contains(errs.String(), "nothing was applied") || !strings.Contains(errs.String(), "stackward apply --step ID") {
			t.Errorf("%v: stderr %q", args, errs.String())
		}
		assertUntouched(t, a)
	}
}

func TestStepListJudgesStepsWithApplysCode(t *testing.T) {
	a := newApplyTest(t)
	// journald-cap is already in place on this host; daemon.json changed
	// since the audit.
	p, _, err := loadPlan(a.plan)
	if err != nil {
		t.Fatal(err)
	}
	for _, s := range p.Steps {
		if s.ID == "journald-cap" {
			applytest.Write(t, a.root, s.Edits[0].Path, s.Edits[0].New, 0o644)
		}
	}
	applytest.Write(t, a.root, "/etc/docker/daemon.json", "{}\n", 0o644)
	_, list := stepsBackendFor(t, a)
	byID := map[string]tui.StepItem{}
	for _, s := range list.Steps {
		byID[s.ID] = s
	}
	if s := byID["journald-cap"]; s.Class != tui.ClassSafe || s.OptIn || !s.Applied || s.AppliedWhy == "" || s.Blocked != "" || len(s.Diff) == 0 || len(s.Undo) < 2 {
		t.Errorf("journald-cap: %+v", s)
	}
	if s := byID["sysctl-hardening"]; s.Class != tui.ClassSafe || s.Applied || s.Blocked != "" || len(s.Fixes) == 0 {
		t.Errorf("sysctl-hardening: %+v", s)
	}
	if s := byID["docker-log-rotation"]; s.Class != tui.ClassNetworking || !s.OptIn || !strings.Contains(s.Blocked, "changed since the audit") {
		t.Errorf("docker-log-rotation: %+v", s)
	}
	if list.Host == "" || list.PlanFile != a.plan || list.NotPlanned != len(p.Skipped) {
		t.Errorf("header: %+v", list)
	}
	if len(a.runner.Calls()) != 0 {
		t.Errorf("judging ran commands: %v", a.runner.Calls())
	}
}

// A choice confirmed on the review runs applySelected, the code of
// stackward apply: the same files are written and the same journal kept.
func TestStepListAppliesTheConfirmedChoice(t *testing.T) {
	a := newApplyTest(t)
	b, list := stepsBackendFor(t, a)
	m := driveList(t, b, list, "enter", "y")
	c := m.Choice()
	if !c.Apply || !reflect.DeepEqual(c.Steps, []string{"journald-cap", "sysctl-hardening"}) {
		t.Fatalf("choice %+v", c)
	}
	var out, errs bytes.Buffer
	if code := b.applyChoice(c, &out, &errs); code != report.ExitOK {
		t.Fatalf("exit %d: %s\n%s", code, out.String(), errs.String())
	}
	for _, want := range []string{
		"applying journald-cap, sysctl-hardening, confirmed on the review screen",
		"stackward apply: this changes the host", "Will apply:", "run:       20260301T120000Z-c11c11 (ok)",
		"sudo stackward undo --run 20260301T120000Z-c11c11",
	} {
		if !strings.Contains(out.String(), want) {
			t.Errorf("missing %q:\n%s", want, out.String())
		}
	}
	if _, ok := applytest.Read(t, a.root, "/etc/systemd/journald.conf.d/90-stackward-journal-cap.conf"); !ok {
		t.Error("journald-cap was not applied")
	}
	if _, err := apply.LoadJournal(a.env.host, "20260301T120000Z-c11c11"); err != nil {
		t.Errorf("no journal: %v", err)
	}
	if _, ok := applytest.Read(t, a.root, "/etc/docker/daemon.json.orig"); ok {
		t.Error("an unselected step ran")
	}
}

func TestStepListQuitAppliesNothing(t *testing.T) {
	a := newApplyTest(t)
	b, list := stepsBackendFor(t, a)
	for _, keys := range [][]string{{"q"}, {"enter", "esc", "q"}, {"enter", "n", "q"}} {
		m := driveList(t, b, list, keys...)
		var out, errs bytes.Buffer
		if code := b.applyChoice(m.Choice(), &out, &errs); code != report.ExitOK || !strings.Contains(out.String(), "nothing was applied") {
			t.Errorf("%v: exit %d %q", keys, code, out.String())
		}
	}
	if len(a.runner.Calls()) != 0 {
		t.Errorf("commands ran: %v", a.runner.Calls())
	}
	assertUntouched(t, a)
}

// The review is apply's own: Select refuses an access-critical step beside
// others, and the review of an access-critical step shows the guard proof,
// the transaction and how to confirm and roll back, by the run id apply
// will use.
func TestStepListReviewIsApplys(t *testing.T) {
	x := newTxnTest(t)
	b, list := stepsBackendFor(t, x.applyTest)
	if err := b.options(true).Allowed([]string{"journald-cap", txntest.GoodID}); err == nil || !strings.Contains(err.Error(), "run of their own") {
		t.Errorf("an access-critical step beside a safe one: %v", err)
	}
	r := b.review([]string{txntest.KeysOnlyID})
	if r.Refused != "" || !r.AccessCritical || r.ToRun != 1 {
		t.Fatalf("review %+v", r)
	}
	for _, want := range []string{
		"ACCESS-CRITICAL", "provider console", "Will apply:", "lockout guard:", "second way in:",
		"stackward-rollback-" + txnRunID + ".timer", "NEW SSH session",
		"sudo stackward confirm " + txnRunID, "sudo stackward undo --transaction " + txnRunID,
	} {
		if !strings.Contains(r.Text, want) {
			t.Errorf("review lacks %q:\n%s", want, r.Text)
		}
	}
	byID := map[string]tui.StepItem{}
	for _, s := range list.Steps {
		byID[s.ID] = s
	}
	if s := byID[txntest.KeysOnlyID]; s.Class != tui.ClassAccessCritical || s.Guard == nil || !s.Guard.Needed || len(s.Guard.Ways) == 0 {
		t.Errorf("%s: %+v", txntest.KeysOnlyID, s)
	}
	// A step that narrows no way in needs no proof, and says so.
	if s := byID[txntest.GoodID]; s.Guard == nil || s.Guard.Needed {
		t.Errorf("%s: %+v", txntest.GoodID, s)
	}
	if len(x.runner.Calls()) != 0 {
		t.Errorf("the review ran commands: %v", x.runner.Calls())
	}
}

// A guard refusal is never hidden: the step cannot be selected, the list
// says why, and a review of it refuses with the guard's words.
func TestStepListShowsAGuardRefusal(t *testing.T) {
	x := newTxnTest(t)
	x.env.liveFacts = func(context.Context) *facts.Facts {
		f := applytest.GuardFacts(&facts.Facts{})
		f.SSH.Users = nil
		return f
	}
	b, list := stepsBackendFor(t, x.applyTest)
	var keysOnly tui.StepItem
	for _, s := range list.Steps {
		if s.ID == txntest.KeysOnlyID {
			keysOnly = s
		}
	}
	if !strings.Contains(keysOnly.Blocked, "lockout guard") || keysOnly.Guard != nil {
		t.Fatalf("%s: %+v", txntest.KeysOnlyID, keysOnly)
	}
	if r := b.review([]string{txntest.KeysOnlyID}); !strings.Contains(r.Refused, "no second way in") {
		t.Errorf("review %+v", r)
	}
}

// An open transaction blocks every access-critical step, in the list and
// in the review, with the reason apply gives.
func TestStepListShowsAnOpenTransaction(t *testing.T) {
	x := newTxnTest(t)
	if code, out, errs := x.apply("--step", txntest.GoodID, "--yes", x.plan); code != report.ExitOK {
		t.Fatalf("exit %d: %s\n%s", code, out, errs)
	}
	x.env.runID = "20260301T120100Z-d22d22"
	b, list := stepsBackendFor(t, x.applyTest)
	for _, s := range list.Steps {
		if s.Class == tui.ClassAccessCritical && !strings.Contains(s.Blocked, "is open until") {
			t.Errorf("%s not blocked by the open transaction: %q", s.ID, s.Blocked)
		}
	}
	if r := b.review([]string{txntest.KeysOnlyID}); !strings.Contains(r.Refused, "only one transaction can be open") {
		t.Errorf("review %+v", r)
	}
}

// Golden frames of the list over a real plan: the access-critical steps,
// the guard proof and the review of a transaction, at 80x24.
func TestStepListFrames(t *testing.T) {
	x := newTxnTest(t)
	b, list := stepsBackendFor(t, x.applyTest)
	// A fixed plan name: the temporary path differs between machines and
	// would move the wrapped lines.
	b.planFile, list.PlanFile = "plan.json", "plan.json"
	good := 0
	for i, s := range list.Steps {
		if s.ID == txntest.KeysOnlyID {
			good = i
		}
	}
	// The cursor starts on the first step; the access-critical steps sort
	// after the safe and networking ones, one class header between.
	down := make([]string, 0, good)
	for range good {
		down = append(down, "j")
	}
	for name, keys := range map[string][]string{
		"list":   nil,
		"guard":  append(append([]string{}, down...), "tab", "end"),
		"dialog": append(append([]string{}, down...), " "),
		"review": append(append([]string{}, down...), " ", "y", "enter", "end"),
	} {
		t.Run(name, func(t *testing.T) {
			m := driveList(t, b, list, keys...)
			golden.RequireEqual(t, ansi.Strip(m.View().Content)+"\n")
		})
	}
}
