package plan

import (
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/Shironex/stackward/internal/checks"
	"github.com/Shironex/stackward/internal/facts"
)

func rebootInput(u *facts.Updates, r *facts.Reboot, levels map[string]checks.Level) Input {
	return Input{
		Facts:   &facts.Facts{CollectedAt: time.Date(2026, 3, 1, 12, 0, 0, 0, time.UTC), Updates: u, Reboot: r},
		Results: results(levels),
	}
}

func TestRebootDecisionPlanCases(t *testing.T) {
	quiet := map[string]checks.Level{"SYS-002": checks.Pass, "SYS-003": checks.Pass, "UPD-004": checks.Info, "UPD-001": checks.Pass}
	// Nothing pending and updates already on: nothing to decide.
	if out := planReboot(rebootInput(offUpdates(), &facts.Reboot{}, quiet)); out.Step != nil || out.Kind != SkipPassing {
		t.Fatalf("pass: %+v", out)
	}
	// Unknown: no step and a reason.
	unknown := map[string]checks.Level{"SYS-002": checks.Unknown, "SYS-003": checks.Unknown, "UPD-004": checks.Unknown}
	if out := planReboot(rebootInput(offUpdates(), nil, unknown)); out.Step != nil || out.Kind != SkipUnknown || out.Reason == "" {
		t.Errorf("unknown: %+v", out)
	}
	pending := map[string]checks.Level{"SYS-002": checks.Fail, "SYS-003": checks.Warn, "UPD-004": checks.Warn}
	if out := planReboot(Input{Results: results(pending)}); out.Step != nil || out.Kind != SkipUnknown {
		t.Errorf("report alone: %+v", out)
	}
	// Automatic reboot already on: the owner's choice stays.
	on := offUpdates()
	on.AutomaticReboot, on.AutomaticRebootTime = true, "02:00"
	if out := planReboot(rebootInput(on, &facts.Reboot{Required: true}, pending)); out.Step != nil || out.Kind != SkipManual || !strings.Contains(out.Reason, "02:00") {
		t.Errorf("already on: %+v", out)
	}

	// A reboot pending: the exact drop-in, a window, no command at all.
	since := time.Date(2026, 2, 9, 6, 30, 0, 0, time.UTC)
	out := planReboot(rebootInput(offUpdates(), &facts.Reboot{Required: true, Since: since, Packages: []string{"linux-image-generic"}}, pending))
	if out.Step == nil {
		t.Fatalf("pending: %+v", out)
	}
	s := out.Step
	wantDiff := "--- /dev/null\n+++ b/etc/apt/apt.conf.d/91stackward-automatic-reboot\n@@ -0,0 +1,5 @@\n" +
		"+// Written by stackward: plan step unattended-upgrades-reboot.\n" +
		"+// Lets unattended-upgrades reboot the host at 04:00 (host time)\n" +
		"+// when an update needs a reboot. Remove this file to undo.\n" +
		"+Unattended-Upgrade::Automatic-Reboot \"true\";\n" +
		"+Unattended-Upgrade::Automatic-Reboot-Time \"04:00\";\n"
	if e := s.Edits[0]; e.Path != rebootDropin || e.Action != Create || e.Diff != wantDiff || !slices.Equal(e.Validate, aptValidate) {
		t.Errorf("edit %+v\ndiff:\n%s", e, e.Diff)
	}
	if len(s.Commands) != 0 || len(s.Restarts) != 0 {
		t.Errorf("the reboot decision runs %v and restarts %v; it must only write a setting", s.Commands, s.Restarts)
	}
	if !slices.Equal(s.Fixes, []string{"SYS-002", "SYS-003", "UPD-004"}) {
		t.Errorf("fixes %v", s.Fixes)
	}
	notes := strings.Join(s.Notes, "\n")
	for _, want := range []string{"never reboots", "04:00", "for 20 days", "linux-image-generic"} {
		if !strings.Contains(notes, want) {
			t.Errorf("notes lack %q:\n%s", want, notes)
		}
	}
	g := mustLookup(t, "unattended-upgrades-reboot")
	if !g.OptIn || g.Risk != Networking {
		t.Errorf("reboot step: opt in %v, risk %s", g.OptIn, g.Risk)
	}
	if err := Authorize(complete(g, *s)); err != nil {
		t.Errorf("its own step refused: %v", err)
	}

	// Turning updates on now with nothing pending still offers the choice.
	turnOn := map[string]checks.Level{"SYS-002": checks.Pass, "SYS-003": checks.Pass, "UPD-004": checks.Info, "UPD-001": checks.Fail}
	out = planReboot(rebootInput(offUpdates(), &facts.Reboot{}, turnOn))
	if out.Step == nil || !slices.Equal(out.Step.Fixes, []string{"UPD-004"}) {
		t.Fatalf("turning on: %+v", out)
	}
	if strings.Contains(strings.Join(out.Step.Notes, "\n"), "pending now") {
		t.Errorf("a note claims a pending reboot: %v", out.Step.Notes)
	}
}

func TestRebootDecisionAuthorizeRefusesTampering(t *testing.T) {
	pending := map[string]checks.Level{"SYS-002": checks.Fail, "SYS-003": checks.Pass, "UPD-004": checks.Warn}
	out := planReboot(rebootInput(offUpdates(), &facts.Reboot{Required: true}, pending))
	base := complete(mustLookup(t, "unattended-upgrades-reboot"), *out.Step)
	for name, tamper := range map[string]func(s *Step){
		"reboot now": func(s *Step) { s.Commands = []Command{cmd("", "systemctl", "reboot")} },
		"window": func(s *Step) {
			s.Edits[0].New = strings.ReplaceAll(s.Edits[0].New, "04:00", "now")
			s.Edits[0].NewSHA256 = sha(s.Edits[0].New)
		},
		"undo":     func(s *Step) { s.Undo.Commands = append(s.Undo.Commands, cmd("", "shutdown", "-r", "now")) },
		"validate": func(s *Step) { s.Edits[0].Validate = []string{"sh", "-c"} },
		"not opt in": func(s *Step) {
			s.OptIn = false
		},
	} {
		s := cloneStep(base)
		tamper(&s)
		if err := Authorize(s); err == nil {
			t.Errorf("%s: tampered step accepted", name)
		}
	}
}
