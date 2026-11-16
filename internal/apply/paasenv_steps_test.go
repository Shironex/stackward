package apply_test

import (
	"context"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/Shironex/stackward/internal/apply"
	"github.com/Shironex/stackward/internal/apply/applytest"
	"github.com/Shironex/stackward/internal/plan"
)

// The paas-env-perms step against a t.TempDir() root with the fake
// runner: applied, applied again, undone byte for byte, and refused when
// tampered with or when the platform is gone. Whether the timer really
// closes files is the paas-env scenario's job (a real systemd).

var paasEnvUnits = []string{
	"/etc/systemd/system/stackward-paas-env-perms.service",
	"/etc/systemd/system/stackward-paas-env-perms.timer",
	"/etc/systemd/system/timers.target.d/90-stackward-paas-env-perms.conf",
}

// seedCoolify lays out the Coolify folders the plan covers, with an app
// .env whose content the test checks is never touched.
func seedCoolify(t *testing.T, root string) {
	t.Helper()
	applytest.Write(t, root, "/data/coolify/applications/a1b2c3/.env", "DB_PASSWORD=not-a-real-one\n", 0o644)
	applytest.Write(t, root, "/data/coolify/services/g7h8i9/.env", "X=1\n", 0o644)
	applytest.Write(t, root, "/data/coolify/source/.env", "APP_KEY=not-a-real-one\n", 0o644)
}

func TestPaaSEnvStepApplyTwiceThenUndoRemovesTheUnits(t *testing.T) {
	root := t.TempDir()
	seedCoolify(t, root)
	p := applytest.FixturePlan(t, "plan-paas-env-perms")
	h, r := applytest.NewHost(root)

	if got := ids(mustSelect(t, p, nil, true)); len(got) != 0 {
		t.Fatalf("--all-safe selected %v; the step is opt in", got)
	}
	steps := mustSelect(t, p, []string{"paas-env-perms"}, false)
	j, err := run(t, h, steps, "20260301T120000Z-f1f1f1")
	if err != nil || j.Status != apply.RunOK {
		t.Fatalf("run: %v %+v", err, j)
	}
	for i, u := range paasEnvUnits {
		got, ok := applytest.Read(t, root, u)
		if !ok || got != steps[0].Edits[i].New {
			t.Errorf("%s: %q", u, got)
		}
		if m := mode(t, root, u); m != 0o644 {
			t.Errorf("%s: mode %v", u, m)
		}
	}
	want := [][]string{
		{"systemctl", "daemon-reload"},
		{"systemctl", "start", "stackward-paas-env-perms.service"},
		{"systemctl", "start", "stackward-paas-env-perms.timer"},
	}
	if got := r.Calls(); !slices.EqualFunc(got, want, slices.Equal) {
		t.Errorf("commands %v, want %v (no enable, no chmod of its own)", got, want)
	}
	// Apply itself never opens a platform file: the content is the same.
	if got, _ := applytest.Read(t, root, "/data/coolify/applications/a1b2c3/.env"); got != "DB_PASSWORD=not-a-real-one\n" {
		t.Errorf("an app .env changed: %q", got)
	}

	// Applied twice: the units are in place and the files the test user
	// owns are not the timer's (it changes only root's and uid 9999's).
	r.Reset()
	prepared, err := apply.Prepare(h, steps)
	if err != nil {
		t.Fatal(err)
	}
	if n := apply.ToRun(prepared); n != 0 || len(r.Calls()) != 0 {
		t.Errorf("second run would apply %d steps, ran %v", n, r.Calls())
	}

	// Undo removes all three units and stops the timer, nothing else.
	r.Reset()
	loaded, err := apply.LoadJournal(h, j.RunID)
	if err != nil {
		t.Fatal(err)
	}
	if changed, err := apply.Undo(context.Background(), loaded, undoOpts(h)); err != nil || !changed {
		t.Fatalf("undo: %v %v", changed, err)
	}
	for _, u := range paasEnvUnits {
		if _, ok := applytest.Read(t, root, u); ok {
			t.Errorf("%s is still there after undo", u)
		}
	}
	wantUndo := [][]string{{"systemctl", "stop", "stackward-paas-env-perms.timer"}, {"systemctl", "daemon-reload"}}
	if got := r.Calls(); !slices.EqualFunc(got, wantUndo, slices.Equal) {
		t.Errorf("undo commands %v, want %v", got, wantUndo)
	}
}

func TestPaaSEnvStepRefusals(t *testing.T) {
	p := applytest.FixturePlan(t, "plan-paas-env-perms")
	for name, tc := range map[string]struct {
		seed   bool
		tamper func(s *plan.Step)
		want   string
	}{
		"the platform is gone": {seed: false, tamper: func(*plan.Step) {}, want: "not installed"},
		"another folder": {seed: true, tamper: func(s *plan.Step) {
			s.Touches[0] = "file-mode:/data/coolify/ssh/keys"
		}, want: "never touched"},
		"a file edit under the data root": {seed: true, tamper: func(s *plan.Step) {
			s.Edits[0].Path = "/data/coolify/source/.env"
		}, want: "never touched"},
		"an enable instead of the drop-in": {seed: true, tamper: func(s *plan.Step) {
			s.Commands[2].Args = []string{"systemctl", "enable", "--now", "stackward-paas-env-perms.timer"}
		}, want: "not one the step runs"},
	} {
		t.Run(name, func(t *testing.T) {
			root := t.TempDir()
			if tc.seed {
				seedCoolify(t, root)
			}
			s := applytest.Step(t, p, "paas-env-perms")
			s.Touches = slices.Clone(s.Touches)
			s.Edits = slices.Clone(s.Edits)
			s.Commands = slices.Clone(s.Commands)
			tc.tamper(&s)
			h, r := applytest.NewHost(root)
			_, err := apply.Prepare(h, []plan.Step{s})
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("got %v, want an error with %q", err, tc.want)
			}
			if len(r.Calls()) != 0 {
				t.Errorf("ran %v", r.Calls())
			}
			if _, err := os.Stat(filepath.Join(root, "etc")); err == nil {
				t.Error("something was written under /etc")
			}
		})
	}
}
