package apply_test

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/Shironex/stackward/internal/apply"
	"github.com/Shironex/stackward/internal/apply/applytest"
	"github.com/Shironex/stackward/internal/plan"
	"github.com/Shironex/stackward/internal/schemacheck"
)

var restartJournald = []string{"systemctl", "restart", "systemd-journald"}

// failedRestart applies journald-cap with a restart that fails, and
// returns the host with the file in place and the restart pending.
func failedRestart(t *testing.T) (string, apply.Host, *applytest.Runner, plan.Step) {
	t.Helper()
	root := t.TempDir()
	p := applytest.FixturePlan(t, "plan-host-settings-fix")
	applytest.Seed(t, root, p)
	h, r := applytest.NewHost(root)
	s := applytest.Step(t, p, "journald-cap")
	r.Exit["systemctl"] = 1
	j, err := run(t, h, []plan.Step{s}, "20260301T120000Z-aaaaaa")
	if err == nil || j.Status != apply.RunFailed {
		t.Fatalf("the restart should fail the run: %v", err)
	}
	if got, ok := applytest.Read(t, root, journaldPath); !ok || got != s.Edits[0].New {
		t.Fatalf("the file was not written: %q", got)
	}
	saved, err := apply.LoadJournal(h, j.RunID)
	if err != nil || !saved.Steps[0].RestartPending {
		t.Fatalf("the journal does not mark the restart pending: %v %+v", err, saved)
	}
	// The mark is part of the journal schema.
	b, err := os.ReadFile(filepath.Join(root, apply.JournalPath(j.RunID)))
	if err != nil {
		t.Fatal(err)
	}
	schema, err := os.ReadFile(applytest.RepoPath("schema/journal.v1.json"))
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range schemacheck.Validate(schema, b) {
		t.Errorf("journal does not match the schema: %v", e)
	}
	if !strings.Contains(string(b), `"restart_pending": true`) {
		t.Errorf("no restart_pending in %s", b)
	}
	return root, h, r, s
}

func TestFailedRestartIsFinishedByTheNextRun(t *testing.T) {
	_, h, r, s := failedRestart(t)
	r.Exit["systemctl"] = 0
	r.Reset()

	// The file is in place, so a plain second apply would see the step as
	// already applied and skip the restart: this is the bug.
	prepared, err := apply.Prepare(h, []plan.Step{s})
	if err != nil || apply.ToRun(prepared) != 0 {
		t.Fatalf("expected the step to look applied: %v %+v", err, prepared)
	}

	pending, warns, err := apply.FindPending(h)
	if err != nil || len(warns) != 0 || len(pending) != 1 || pending[0].StepID != "journald-cap" || pending[0].RunID != "20260301T120000Z-aaaaaa" {
		t.Fatalf("pending %+v %v %v", pending, warns, err)
	}
	if !slices.Equal(pending[0].Commands[0], restartJournald) {
		t.Errorf("commands %v", pending[0].Commands)
	}
	var said []string
	err = apply.FinishPending(context.Background(), pending, apply.PendingOptions{
		Host: h, Now: func() time.Time { return fixedNow },
		Progress: func(format string, a ...any) { said = append(said, fmt.Sprintf(format, a...)) },
	})
	if err != nil {
		t.Fatal(err)
	}
	if want := [][]string{restartJournald}; !slices.EqualFunc(r.Calls(), want, slices.Equal) {
		t.Errorf("commands %v, want %v", r.Calls(), want)
	}
	if len(said) == 0 || !strings.Contains(said[0], "finishing the pending restart") {
		t.Errorf("progress %v", said)
	}
	saved, err := apply.LoadJournal(h, "20260301T120000Z-aaaaaa")
	if err != nil || saved.Steps[0].RestartPending {
		t.Fatalf("the journal still marks it pending: %v", err)
	}
	if last := saved.Steps[0].Commands[len(saved.Steps[0].Commands)-1]; !slices.Equal(last.Args, restartJournald) || last.ExitCode != 0 {
		t.Errorf("the finished restart is not in the journal: %+v", last)
	}
	if again, _, _ := apply.FindPending(h); len(again) != 0 {
		t.Errorf("still pending: %+v", again)
	}
}

func TestPendingRestartThatFailsAgainStaysPending(t *testing.T) {
	_, h, _, _ := failedRestart(t)
	pending, _, err := apply.FindPending(h)
	if err != nil || len(pending) != 1 {
		t.Fatalf("%v %+v", err, pending)
	}
	err = apply.FinishPending(context.Background(), pending, apply.PendingOptions{Host: h})
	if err == nil || !strings.Contains(err.Error(), "finishing the pending restart of step journald-cap") {
		t.Fatalf("err %v", err)
	}
	if again, _, _ := apply.FindPending(h); len(again) != 1 {
		t.Errorf("the restart is no longer pending: %+v", again)
	}
}

func TestPendingRestartIsDroppedWhenTheFileChanged(t *testing.T) {
	root, h, r, _ := failedRestart(t)
	applytest.Write(t, root, journaldPath, "[Journal]\nSystemMaxUse=1M\n", 0o644)
	r.Exit["systemctl"] = 0
	r.Reset()
	pending, _, _ := apply.FindPending(h)
	var said []string
	err := apply.FinishPending(context.Background(), pending, apply.PendingOptions{
		Host: h, Progress: func(format string, a ...any) { said = append(said, fmt.Sprintf(format, a...)) },
	})
	if err != nil || len(r.Calls()) != 0 || len(said) != 1 || !strings.Contains(said[0], "dropped") {
		t.Fatalf("err %v calls %v said %v", err, r.Calls(), said)
	}
	if again, _, _ := apply.FindPending(h); len(again) != 0 {
		t.Errorf("still pending: %+v", again)
	}
}

func TestUndoClearsAPendingRestart(t *testing.T) {
	_, h, r, _ := failedRestart(t)
	r.Exit["systemctl"] = 0
	j, err := apply.LoadJournal(h, "20260301T120000Z-aaaaaa")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := apply.Undo(context.Background(), j, apply.UndoOptions{Host: h}); err != nil {
		t.Fatal(err)
	}
	if again, _, _ := apply.FindPending(h); len(again) != 0 {
		t.Errorf("still pending after undo: %+v", again)
	}
}

func TestFindPendingWarnsAboutAnUnreadableJournal(t *testing.T) {
	root := t.TempDir()
	applytest.Write(t, root, apply.JournalPath("20260301T120000Z-dddddd"), "{not json", 0o600)
	h, _ := applytest.NewHost(root)
	pending, warns, err := apply.FindPending(h)
	if err != nil || len(pending) != 0 || len(warns) != 1 {
		t.Fatalf("%+v %v %v", pending, warns, err)
	}
	// No backup directory at all is not an error either.
	h2, _ := applytest.NewHost(t.TempDir())
	if pending, warns, err := apply.FindPending(h2); err != nil || pending != nil || warns != nil {
		t.Fatalf("%+v %v %v", pending, warns, err)
	}
}
