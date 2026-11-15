package plan

import (
	"io/fs"
	"slices"
	"strings"
	"testing"

	"github.com/Shironex/stackward/internal/checks"
	"github.com/Shironex/stackward/internal/facts"
)

func boolp(b bool) *bool { return &b }

func updatesInput(u *facts.Updates, levels map[string]checks.Level) Input {
	return Input{Facts: &facts.Facts{Updates: u}, Results: results(levels)}
}

func offUpdates() *facts.Updates {
	return &facts.Updates{Apt: true, UnattendedInstalled: true, PeriodicUnattended: "0", ConfigSource: "apt-config",
		TimerEnabled: boolp(true), TimerActive: boolp(true)}
}

func argsOf(cs []Command) [][]string {
	out := make([][]string, len(cs))
	for i, c := range cs {
		out[i] = c.Args
	}
	return out
}

func TestUnattendedUpgradesPlanCases(t *testing.T) {
	fail := map[string]checks.Level{"UPD-001": checks.Fail}
	// Pass: no step from either generator.
	for _, plan := range []func(Input) Outcome{planUnattended, planUnattendedInstall} {
		if out := plan(updatesInput(offUpdates(), map[string]checks.Level{"UPD-001": checks.Pass})); out.Step != nil || out.Kind != SkipPassing {
			t.Errorf("pass: %+v", out)
		}
		// Unknown: no step and a reason.
		for name, in := range map[string]Input{
			"report alone":  {Results: results(fail)},
			"no updates":    {Facts: &facts.Facts{}, Results: results(fail)},
			"check unknown": updatesInput(offUpdates(), map[string]checks.Level{"UPD-001": checks.Unknown}),
		} {
			if out := plan(in); out.Step != nil || out.Kind != SkipUnknown || out.Reason == "" {
				t.Errorf("%s: %+v", name, out)
			}
		}
	}
	// Installed and off: the drop-in, nothing installed.
	out := planUnattended(updatesInput(offUpdates(), fail))
	if out.Step == nil {
		t.Fatalf("fail: %+v", out)
	}
	e := out.Step.Edits[0]
	wantDiff := "--- /dev/null\n+++ b/etc/apt/apt.conf.d/90stackward-unattended-upgrades\n@@ -0,0 +1,5 @@\n" +
		"+// Written by stackward: plan step unattended-upgrades, fixes UPD-001.\n" +
		"+// Turns on the daily package list update and unattended-upgrades.\n" +
		"+// Remove this file to undo.\n" +
		"+APT::Periodic::Update-Package-Lists \"1\";\n" +
		"+APT::Periodic::Unattended-Upgrade \"1\";\n"
	if e.Path != uuDropin || e.Action != Create || e.Mode != "0644" || e.Diff != wantDiff || !slices.Equal(e.Validate, aptValidate) {
		t.Errorf("edit %+v\ndiff:\n%s", e, e.Diff)
	}
	if len(out.Step.Commands) != 0 || !slices.EqualFunc(argsOf(out.Step.Undo.Commands), [][]string{uuRemove}, slices.Equal) {
		t.Errorf("commands %v undo %v", out.Step.Commands, out.Step.Undo.Commands)
	}
	if !strings.Contains(strings.Join(out.Step.Notes, "\n"), "Reboot decision: automatic reboot stays off") {
		t.Errorf("no reboot decision note: %v", out.Step.Notes)
	}
	// The install step does not plan for an installed package.
	if out := planUnattendedInstall(updatesInput(offUpdates(), fail)); out.Step != nil {
		t.Errorf("install planned for an installed package: %+v", out)
	}
	// Not an apt host.
	if out := planUnattended(updatesInput(&facts.Updates{}, fail)); out.Step != nil || out.Kind != SkipPassing {
		t.Errorf("not apt: %+v", out)
	}
}

func TestUnattendedUpgradesTimerShapes(t *testing.T) {
	fail := map[string]checks.Level{"UPD-001": checks.Fail}
	for name, tc := range map[string]struct {
		enabled, active *bool
		cmds, undo      [][]string
	}{
		"enabled":            {boolp(true), boolp(true), nil, [][]string{uuRemove}},
		"unknown":            {nil, nil, nil, [][]string{uuRemove}},
		"disabled, stopped":  {boolp(false), boolp(false), [][]string{timerEnable, timerStart}, [][]string{uuRemove, timerStop, timerDisable}},
		"disabled, running":  {boolp(false), boolp(true), [][]string{timerEnable}, [][]string{uuRemove, timerDisable}},
		"disabled, unknown?": {boolp(false), nil, [][]string{timerEnable, timerStart}, [][]string{uuRemove, timerStop, timerDisable}},
	} {
		u := offUpdates()
		u.TimerEnabled, u.TimerActive = tc.enabled, tc.active
		out := planUnattended(updatesInput(u, fail))
		if out.Step == nil {
			t.Fatalf("%s: %+v", name, out)
		}
		if got := argsOf(out.Step.Commands); !slices.EqualFunc(got, tc.cmds, slices.Equal) {
			t.Errorf("%s: commands %v, want %v", name, got, tc.cmds)
		}
		if got := argsOf(out.Step.Undo.Commands); !slices.EqualFunc(got, tc.undo, slices.Equal) {
			t.Errorf("%s: undo %v, want %v", name, got, tc.undo)
		}
		s := complete(mustLookup(t, "unattended-upgrades"), *out.Step)
		if err := Authorize(s); err != nil {
			t.Errorf("%s: its own step refused: %v", name, err)
		}
	}
}

func TestUnattendedUpgradesInstallIsNamedAndOptIn(t *testing.T) {
	u := &facts.Updates{Apt: true, ConfigSource: "apt-config", TimerEnabled: boolp(true)}
	out := planUnattendedInstall(updatesInput(u, map[string]checks.Level{"UPD-001": checks.Fail}))
	if out.Step == nil {
		t.Fatalf("not installed: %+v", out)
	}
	if got := argsOf(out.Step.Commands); !slices.EqualFunc(got, [][]string{uuInstall}, slices.Equal) {
		t.Errorf("commands %v", got)
	}
	if got := argsOf(out.Step.Undo.Commands); !slices.EqualFunc(got, [][]string{uuRemove, uuPurge}, slices.Equal) {
		t.Errorf("undo %v", got)
	}
	g := mustLookup(t, "unattended-upgrades-install")
	if !g.OptIn || g.CommandsOnChange {
		t.Errorf("install step: opt in %v, commands on change %v", g.OptIn, g.CommandsOnChange)
	}
	if err := Authorize(complete(g, *out.Step)); err != nil {
		t.Errorf("its own step refused: %v", err)
	}
	// The config step does not plan for a missing package.
	if out := planUnattended(updatesInput(u, map[string]checks.Level{"UPD-001": checks.Fail})); out.Step != nil {
		t.Errorf("config step planned without the package: %+v", out)
	}
}

func TestUnattendedUpgradesAuthorizeRefusesTampering(t *testing.T) {
	u := offUpdates()
	u.TimerEnabled, u.TimerActive = boolp(false), boolp(false)
	out := planUnattended(updatesInput(u, map[string]checks.Level{"UPD-001": checks.Fail}))
	base := complete(mustLookup(t, "unattended-upgrades"), *out.Step)
	for name, tamper := range map[string]func(s *Step){
		"content": func(s *Step) {
			s.Edits[0].New += "APT::Periodic::AutocleanInterval \"0\";\n"
			s.Edits[0].NewSHA256 = sha(s.Edits[0].New)
		},
		"validate":     func(s *Step) { s.Edits[0].Validate = nil },
		"install":      func(s *Step) { s.Commands = append([]Command{cmd("", uuInstall...)}, s.Commands...) },
		"undo shape":   func(s *Step) { s.Undo.Commands = s.Undo.Commands[:2] },
		"other timer":  func(s *Step) { s.Commands[0].Args = []string{"systemctl", "enable", "ssh.socket"} },
		"path":         func(s *Step) { s.Edits[0].Path = "/etc/apt/apt.conf.d/20auto-upgrades" },
		"restarts":     func(s *Step) { s.Restarts = []string{"ssh"} },
		"opt in flips": func(s *Step) { s.OptIn = true },
	} {
		s := cloneStep(base)
		tamper(&s)
		if err := Authorize(s); err == nil {
			t.Errorf("%s: tampered step accepted", name)
		}
	}
}

func TestDpkgInstalled(t *testing.T) {
	status := "Package: fail2ban\nStatus: deinstall ok config-files\nVersion: 1\n\n" +
		"Package: unattended-upgrades\nStatus: install ok installed\nVersion: 2\n"
	r := mapReader{dpkgStatus: status}
	if ok, err := dpkgInstalled(r, "unattended-upgrades"); !ok || err != nil {
		t.Errorf("installed: %v %v", ok, err)
	}
	if ok, err := dpkgInstalled(r, "fail2ban"); ok || err != nil {
		t.Errorf("config files only counts as installed: %v %v", ok, err)
	}
	if ok, err := dpkgInstalled(mapReader{}, "fail2ban"); ok || err != nil {
		t.Errorf("no status file: %v %v", ok, err)
	}
}

// mapReader is a Reader over in-memory files.
type mapReader map[string]string

func (m mapReader) ReadFile(p string) ([]byte, error) {
	if v, ok := m[p]; ok {
		return []byte(v), nil
	}
	return nil, fs.ErrNotExist
}
