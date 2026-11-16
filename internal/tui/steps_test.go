package tui

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"reflect"
	"strings"
	"testing"
	"time"

	tea "charm.land/bubbletea/v2"
	"github.com/charmbracelet/colorprofile"
	"github.com/charmbracelet/x/ansi"
	"github.com/charmbracelet/x/exp/golden"
	"github.com/charmbracelet/x/exp/teatest/v2"
)

// The step list is tested on a hand made list, so the frames do not move
// when a step's wording changes; internal/cli drives it over real plans.
// Run "go test ./internal/tui/ -update" to rewrite the golden files after an
// intended change, then read every one of them.

func sampleList() StepList {
	return StepList{
		PlanFile: "plan.json", Host: "4f1c2a9e0b7d", ToolVersion: "0.2.0-dev",
		GeneratedAt: "2026-03-01T12:00:00Z", NotPlanned: 9,
		Steps: []StepItem{
			{
				ID: "journald-cap", Title: "Cap the systemd journal at 500M", Class: ClassSafe,
				Fixes:    []string{"LOG-001"},
				Changes:  []string{"create /etc/systemd/journald.conf.d/90-stackward-journal-cap.conf (0644)", "run systemctl restart systemd-journald", "restarts systemd-journald"},
				Diff:     []string{"--- /dev/null", "+++ b/etc/systemd/journald.conf.d/90-stackward-journal-cap.conf", "@@ -0,0 +1,2 @@", "+[Journal]", "+SystemMaxUse=500M"},
				Restarts: []string{"systemd-journald"},
				Undo:     []string{"Remove the drop-in and restart journald.", "rm -f /etc/systemd/journald.conf.d/90-stackward-journal-cap.conf", "systemctl restart systemd-journald"},
			},
			{
				ID: "sysctl-hardening", Title: "Set the kernel hardening sysctls", Class: ClassSafe,
				Fixes: []string{"KRN-002", "KRN-003", "KRN-004"}, Applied: true, AppliedWhy: "the drop-in holds the planned content and every value matches",
				Changes: []string{"create /etc/sysctl.d/90-stackward-hardening.conf (0644)", "run sysctl -p /etc/sysctl.d/90-stackward-hardening.conf"},
				Undo:    []string{"Remove the drop-in and set the old values back.", "rm -f /etc/sysctl.d/90-stackward-hardening.conf"},
			},
			{
				ID: "unattended-upgrades-install", Title: "Install unattended-upgrades and turn it on", Class: ClassSafe, OptIn: true,
				Fixes:   []string{"UPD-001"},
				Changes: []string{"run apt-get install -y unattended-upgrades"},
				Undo:    []string{"Purge the package.", "apt-get purge -y unattended-upgrades"},
			},
			{
				ID: "docker-log-rotation", Title: "Rotate Docker container logs", Class: ClassNetworking, OptIn: true,
				Fixes:    []string{"DKR-031"},
				Changes:  []string{"replace /etc/docker/daemon.json", "checked first with: dockerd --validate --config-file <new file>", "run systemctl restart docker", "restarts docker"},
				Diff:     []string{"--- a/etc/docker/daemon.json", "+++ b/etc/docker/daemon.json", "@@ -1,3 +1,7 @@", " {", "-  \"live-restore\": true", "+  \"live-restore\": true,", "+  \"log-driver\": \"json-file\""},
				Restarts: []string{"docker"},
				Undo:     []string{"Put the old daemon.json back and restart Docker.", "systemctl restart docker"},
				Notes:    []string{"Containers stop and start while Docker restarts."},
			},
			{
				ID: "sshd-hardening", Title: "Harden the SSH server settings", Class: ClassAccessCritical,
				Fixes:   []string{"SSH-001", "SSH-003", "SSH-005"},
				Changes: []string{"create /etc/ssh/sshd_config.d/10-stackward-hardening.conf (0600)", "checked first with: sshd -t -f <new file>", "run systemctl reload ssh"},
				Undo:    []string{"Remove the drop-in and reload sshd.", "rm -f /etc/ssh/sshd_config.d/10-stackward-hardening.conf", "systemctl reload ssh"},
				Guard: &GuardProof{
					Needed: true, Narrows: []string{"password logins", "root login"},
					Ways:        []string{"key login for admin (authorized_keys holds 1 key) over public SSH on port 22"},
					ConfirmFrom: []string{"198.51.100.0/24"},
				},
			},
			{
				ID: "ufw-policy", Title: "Turn on a default deny firewall", Class: ClassAccessCritical,
				Fixes:   []string{"NET-001"},
				Changes: []string{"replace /etc/ufw/user.rules"},
				Undo:    []string{"ufw disable"},
				Blocked: "lockout guard: no second way in survives: SSH is only reachable through the port this step closes",
			},
		},
	}
}

// fakeAllowed refuses an access-critical step beside any other step, the
// shape of apply.Select's rule.
func fakeAllowed(l StepList) func([]string) error {
	return func(ids []string) error {
		ac, other := 0, 0
		for _, id := range ids {
			for _, s := range l.Steps {
				if s.ID == id && s.Class == ClassAccessCritical {
					ac++
				} else if s.ID == id {
					other++
				}
			}
		}
		if ac > 0 && other > 0 {
			return errors.New("access-critical steps run inside the rollback transaction, in a run of their own")
		}
		return nil
	}
}

// fakeReview returns a review shaped like the CLI's.
func fakeReview(ids []string) Review {
	r := Review{ToRun: len(ids)}
	var b strings.Builder
	b.WriteString("stackward apply: this changes the host\nplan:      plan.json\n\nWill apply:\n")
	for i, id := range ids {
		if id == "sshd-hardening" {
			r.AccessCritical = true
		}
		if id == "sysctl-hardening" {
			r.ToRun--
			continue
		}
		fmt.Fprintf(&b, "%d. %s\n", i+1, id)
	}
	if r.AccessCritical {
		b.WriteString("\ntransaction: the steps run inside a rollback transaction\n   a systemd timer (stackward-rollback-20260301T120000Z-c11c11.timer) rolls them back after 5m0s unless confirmed;\n   confirm with stackward confirm from a NEW SSH session (this one is refused)\n")
	}
	r.Text = b.String()
	return r
}

func stepsOpts(l StepList) StepsOptions {
	return StepsOptions{ConfirmWithin: "5m0s", Allowed: fakeAllowed(l), Review: fakeReview}
}

// driveSteps runs the step list at w x h, presses keys and returns the
// final model. A trailing ctrl+c quits from every screen.
func driveSteps(t *testing.T, l StepList, o StepsOptions, w, h int, keys ...string) StepsModel {
	t.Helper()
	tm := teatest.NewTestModel(t, NewSteps(l, o), teatest.WithInitialTermSize(w, h))
	for _, k := range keys {
		tm.Send(key(k))
	}
	tm.Send(key("ctrl+c"))
	fm, ok := tm.FinalModel(t, teatest.WithFinalTimeout(5*time.Second)).(StepsModel)
	if !ok {
		t.Fatal("final model is not a tui.StepsModel")
	}
	return fm
}

func stepsScreen(m StepsModel) string { return ansi.Strip(m.render()) + "\n" }

func TestStepScreens(t *testing.T) {
	l := sampleList()
	empty := StepList{PlanFile: "plan.json", Host: "4f1c2a9e0b7d", ToolVersion: "0.2.0-dev", NotPlanned: 12}
	refuse := stepsOpts(l)
	refuse.Review = func([]string) Review {
		return Review{Refused: "transaction 20260301T110000Z-aaaaaa is open until 2026-03-01T11:05:00Z and only one transaction can be open"}
	}
	cases := []struct {
		name string
		list StepList
		opts StepsOptions
		w, h int
		keys []string
	}{
		{"main", l, stepsOpts(l), 80, 24, nil},
		{"applied_step", l, stepsOpts(l), 80, 24, []string{"j"}},
		{"networking_detail", l, stepsOpts(l), 80, 24, []string{"j", "j", "j", "tab", "pgdown"}},
		{"networking_dialog", l, stepsOpts(l), 80, 24, []string{"j", "j", "j", " "}},
		{"access_critical_dialog", l, stepsOpts(l), 80, 24, []string{"j", "j", "j", "j", " "}},
		{"access_critical_guard", l, stepsOpts(l), 80, 24, []string{"j", "j", "j", "j", "tab", "end"}},
		{"guard_refused", l, stepsOpts(l), 80, 24, []string{"end"}},
		{"guard_refused_toggle", l, stepsOpts(l), 80, 24, []string{"end", " "}},
		{"review_safe", l, stepsOpts(l), 80, 24, []string{"enter"}},
		{"review_access_critical", l, stepsOpts(l), 80, 24, []string{"j", "j", "j", "j", " ", "y", "enter"}},
		{"review_refused", l, refuse, 80, 24, []string{"enter"}},
		{"nothing_selected", l, stepsOpts(l), 80, 24, []string{" ", "enter"}},
		{"help", l, stepsOpts(l), 80, 24, []string{"?"}},
		{"no_steps", empty, stepsOpts(empty), 80, 24, nil},
		{"wide", l, stepsOpts(l), 120, 32, []string{"j", "j", "j"}},
		{"too_small", l, stepsOpts(l), 50, 12, nil},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			m := driveSteps(t, tc.list, tc.opts, tc.w, tc.h, tc.keys...)
			out := stepsScreen(m)
			lines := strings.Split(strings.TrimSuffix(out, "\n"), "\n")
			if len(lines) != tc.h {
				t.Errorf("screen has %d lines, want %d", len(lines), tc.h)
			}
			for i, ln := range lines {
				if n := ansi.StringWidth(ln); n > tc.w {
					t.Errorf("line %d is %d cells wide, more than %d: %q", i+1, n, tc.w, ln)
				}
			}
			golden.RequireEqual(t, out)
		})
	}
}

func TestStepDefaults(t *testing.T) {
	m := NewSteps(sampleList(), stepsOpts(sampleList()))
	// Safe, not opt in, not applied, not blocked: only journald-cap.
	if got, want := m.Selected(), []string{"journald-cap"}; !reflect.DeepEqual(got, want) {
		t.Errorf("selected at start %v, want %v", got, want)
	}
}

func TestStepChoices(t *testing.T) {
	l := sampleList()
	cases := []struct {
		name  string
		keys  []string
		apply bool
		steps []string
	}{
		{"quit applies nothing", []string{"q"}, false, []string{"journald-cap"}},
		{"review then back applies nothing", []string{"enter", "esc", "q"}, false, []string{"journald-cap"}},
		{"review and yes", []string{"enter", "y"}, true, []string{"journald-cap"}},
		{"y outside the review does nothing", []string{"y", "q"}, false, []string{"journald-cap"}},
		{"opt in safe step joins at once", []string{"j", "j", " ", "enter", "y"}, true, []string{"journald-cap", "unattended-upgrades-install"}},
		{"networking step needs its own yes", []string{"j", "j", "j", " ", "y", "enter", "y"}, true, []string{"journald-cap", "docker-log-rotation"}},
		{"networking step refused in the dialog", []string{"j", "j", "j", " ", "n", "enter", "y"}, true, []string{"journald-cap"}},
		{"access-critical replaces the others", []string{"j", "j", "j", "j", " ", "y", "enter", "y"}, true, []string{"sshd-hardening"}},
		{"access-critical dialog declined", []string{"j", "j", "j", "j", " ", "esc", "q"}, false, []string{"journald-cap"}},
		{"blocked step cannot be selected", []string{"end", " ", "q"}, false, []string{"journald-cap"}},
		{"deselect everything then review", []string{" ", "enter", "q"}, false, nil},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			m := driveSteps(t, l, stepsOpts(l), 80, 24, tc.keys...)
			c := m.Choice()
			if c.Apply != tc.apply {
				t.Errorf("apply %v, want %v", c.Apply, tc.apply)
			}
			if !reflect.DeepEqual(m.Selected(), tc.steps) {
				t.Errorf("selected %v, want %v", m.Selected(), tc.steps)
			}
			if c.Apply && !reflect.DeepEqual(c.Steps, tc.steps) {
				t.Errorf("choice steps %v, want %v", c.Steps, tc.steps)
			}
		})
	}
}

func TestStepReviewThatRefusesCannotApply(t *testing.T) {
	l := sampleList()
	for name, review := range map[string]Review{
		"refused":       {Text: "x", ToRun: 1, Refused: "the lockout guard cannot prove a second way in"},
		"nothing to do": {Text: "Already applied (nothing to do):\n   sysctl-hardening\n", ToRun: 0},
	} {
		t.Run(name, func(t *testing.T) {
			o := stepsOpts(l)
			o.Review = func([]string) Review { return review }
			m := driveSteps(t, l, o, 80, 24, "enter", "y", "y")
			if m.Choice().Apply {
				t.Error("y applied a selection the review did not allow")
			}
			if review.Refused != "" && !strings.Contains(stepsScreen(m), "Apply would refuse this selection") {
				t.Errorf("the refusal is not on screen:\n%s", stepsScreen(m))
			}
		})
	}
}

// The review gets exactly the selected ids, in plan order.
func TestStepReviewGetsTheSelection(t *testing.T) {
	l := sampleList()
	var got []string
	o := stepsOpts(l)
	o.Review = func(ids []string) Review { got = ids; return fakeReview(ids) }
	driveSteps(t, l, o, 80, 24, "j", "j", " ", "enter")
	if want := []string{"journald-cap", "unattended-upgrades-install"}; !reflect.DeepEqual(got, want) {
		t.Errorf("review got %v, want %v", got, want)
	}
}

// NO_COLOR: the program is downsampled to ASCII, so no color sequence
// reaches the terminal; reverse video still marks the cursor.
func TestStepsNoColor(t *testing.T) {
	l := sampleList()
	var out bytes.Buffer
	in := strings.NewReader("q")
	c, err := RunSteps(l, StepsOptions{NoColor: true, Allowed: fakeAllowed(l), Review: fakeReview}, in, &out)
	if err != nil {
		t.Fatal(err)
	}
	if c.Apply {
		t.Error("q applied")
	}
	if s := out.String(); strings.Contains(s, "\x1b[38;") || strings.Contains(s, "\x1b[48;") {
		t.Errorf("colors in NO_COLOR output: %q", s[:min(len(s), 200)])
	}
	tm := teatest.NewTestModel(t, NewSteps(l, StepsOptions{}), teatest.WithInitialTermSize(80, 24),
		teatest.WithProgramOptions(tea.WithColorProfile(colorprofile.Ascii)))
	tm.Send(key("ctrl+c"))
	b, err := io.ReadAll(tm.FinalOutput(t, teatest.WithFinalTimeout(5*time.Second)))
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(b), "\x1b[38;") {
		t.Error("colors with the ASCII profile")
	}
}
