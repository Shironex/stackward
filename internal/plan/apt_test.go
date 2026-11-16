package plan

import (
	"bytes"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/Shironex/stackward/internal/checks"
	"github.com/Shironex/stackward/internal/facts"
)

// The package installs of fail2ban-sshd and unattended-upgrades-install:
// they run before the edits, after an apt-get update when the audit saw
// the package lists empty (a fresh cloud image) or stale.

var auditedAt = time.Date(2026, 11, 16, 12, 0, 0, 0, time.UTC)

// withLists puts the apt facts with the given lists on f.
func withLists(f *facts.Facts, l *facts.AptLists) {
	f.CollectedAt = auditedAt
	if f.Updates == nil {
		f.Updates = &facts.Updates{Apt: true}
	}
	f.Updates.Lists = l
}

var (
	emptyLists = &facts.AptLists{Read: true}
	staleLists = &facts.AptLists{Read: true, Indexes: 4, Newest: auditedAt.Add(-10 * 24 * time.Hour)}
	freshLists = &facts.AptLists{Read: true, Indexes: 4, Newest: auditedAt.Add(-2 * time.Hour)}
)

func f2bInstallStep(t *testing.T, l *facts.AptLists) Step {
	t.Helper()
	f := jailFacts(&facts.Fail2ban{}, false, 22)
	if l != nil {
		withLists(f, l)
	}
	out := planFail2banSSHD(Input{Facts: f, Results: results(cs010Fail)})
	if out.Step == nil {
		t.Fatalf("no step: %+v", out)
	}
	return complete(mustLookup(t, "fail2ban-sshd"), *out.Step)
}

func uuInstallStep(t *testing.T, l *facts.AptLists) Step {
	t.Helper()
	u := &facts.Updates{Apt: true, ConfigSource: "apt-config", TimerEnabled: boolp(true)}
	in := updatesInput(u, map[string]checks.Level{"UPD-001": checks.Fail})
	if l != nil {
		withLists(in.Facts, l)
	}
	out := planUnattendedInstall(in)
	if out.Step == nil {
		t.Fatalf("no step: %+v", out)
	}
	return complete(mustLookup(t, "unattended-upgrades-install"), *out.Step)
}

func TestInstallStepsRefreshEmptyOrStaleLists(t *testing.T) {
	for name, tc := range map[string]struct {
		lists   *facts.AptLists
		refresh bool
		note    string
	}{
		"empty lists (a fresh cloud image)": {emptyLists, true, "the apt package lists are empty"},
		"stale lists":                       {staleLists, true, "last updated 10 days ago"},
		"fresh lists":                       {freshLists, false, ""},
		"lists not judged":                  {nil, false, "could not judge the apt package lists"},
	} {
		for _, s := range []Step{f2bInstallStep(t, tc.lists), uuInstallStep(t, tc.lists)} {
			pkg := map[string]string{"fail2ban-sshd": "fail2ban", "unattended-upgrades-install": "unattended-upgrades"}[s.ID]
			want := [][]string{aptInstall(pkg)}
			if tc.refresh {
				want = [][]string{aptUpdate, aptInstall(pkg)}
			}
			if got := argsOf(s.Before); !slices.EqualFunc(got, want, slices.Equal) {
				t.Errorf("%s, %s: before %v, want %v", name, s.ID, got, want)
			}
			notes := strings.Join(s.Notes, "\n")
			if tc.note != "" && !strings.Contains(notes, tc.note) {
				t.Errorf("%s, %s: no note saying %q:\n%s", name, s.ID, tc.note, notes)
			}
			if tc.note == "" && strings.Contains(notes, "apt-get update") {
				t.Errorf("%s, %s: fresh lists need no update:\n%s", name, s.ID, notes)
			}
			if tc.refresh && !strings.Contains(s.Before[0].Why, "package lists") {
				t.Errorf("%s, %s: the update says why: %q", name, s.ID, s.Before[0].Why)
			}
			if err := Authorize(s); err != nil {
				t.Errorf("%s, %s: its own step refused: %v", name, s.ID, err)
			}
		}
	}
}

// The plan names the update and the install before the files it writes,
// in the text and the script.
func TestInstallBeforeIsRendered(t *testing.T) {
	s := f2bInstallStep(t, emptyLists)
	s.Fixes = []string{"CS-010"}
	p := &Plan{Schema: SchemaID, Steps: []Step{s}}
	var txt, sh bytes.Buffer
	if err := WriteText(&txt, p); err != nil {
		t.Fatal(err)
	}
	if err := WriteScript(&sh, p); err != nil {
		t.Fatal(err)
	}
	// The text shows the edit as "create   PATH", the script writes it
	// with mkdir -p and a here document.
	for name, tc := range map[string]struct{ out, write string }{
		"text":   {txt.String(), "create   " + f2bDropin},
		"script": {sh.String(), "mkdir -p /etc/fail2ban/jail.d"},
	} {
		out := tc.out
		upd := strings.Index(out, "apt-get -o DPkg::Lock::Timeout=120 update")
		inst := strings.Index(out, "apt-get -o DPkg::Lock::Timeout=120 install -y fail2ban")
		jail := strings.Index(out, tc.write)
		if upd < 0 || inst < upd || jail < inst {
			t.Errorf("%s: update at %d, install at %d, the jail at %d; want them in that order:\n%s", name, upd, inst, jail, out)
		}
	}
	if !strings.Contains(txt.String(), "   first    ") {
		t.Errorf("text does not mark the commands that run first:\n%s", txt.String())
	}
}

func TestInstallBeforeAuthorize(t *testing.T) {
	for _, base := range []Step{f2bInstallStep(t, emptyLists), uuInstallStep(t, emptyLists)} {
		pkg := map[string]string{"fail2ban-sshd": "fail2ban", "unattended-upgrades-install": "unattended-upgrades"}[base.ID]
		for name, tamper := range map[string]func(s *Step){
			"update only":          func(s *Step) { s.Before = s.Before[:1] },
			"update after install": func(s *Step) { s.Before[0], s.Before[1] = s.Before[1], s.Before[0] },
			"another package":      func(s *Step) { s.Before[1].Args = aptInstall("netcat-openbsd") },
			"an upgrade":           func(s *Step) { s.Before[0].Args = aptGet("upgrade", "-y") },
			"an extra command":     func(s *Step) { s.Before = append(s.Before, cmd("", "sh", "-c", "id")) },
			"install twice":        func(s *Step) { s.Commands = append([]Command{s.Before[1]}, s.Commands...) },
		} {
			s := cloneStep(base)
			tamper(&s)
			if err := Authorize(s); err == nil {
				t.Errorf("%s, %s: tampered step accepted", base.ID, name)
			}
		}
		// A plan from 0.2.0-rc.1 ran the install as the first command
		// after the edits; its runs must stay undoable.
		legacy := cloneStep(base)
		legacy.Commands = append([]Command{cmd("", aptInstall(pkg)...)}, legacy.Commands...)
		legacy.Before = nil
		if err := Authorize(legacy); err != nil {
			t.Errorf("%s: the rc.1 shape refused: %v", base.ID, err)
		}
		if !installs(legacy, pkg) || !installs(base, pkg) {
			t.Errorf("%s: installs does not see the install", base.ID)
		}
	}
}

// Only a step whose generator runs commands before its edits may have
// them, and the never touched list sees them like every command.
func TestBeforeIsRefusedElsewhere(t *testing.T) {
	u := offUpdates()
	out := planUnattended(updatesInput(u, map[string]checks.Level{"UPD-001": checks.Fail}))
	s := complete(mustLookup(t, "unattended-upgrades"), *out.Step)
	s.Before = []Command{cmd("", aptInstall("unattended-upgrades")...)}
	if err := Authorize(s); err == nil || !strings.Contains(err.Error(), "before its edits") {
		t.Errorf("Before on a step without it: %v", err)
	}
	s = f2bInstallStep(t, emptyLists)
	s.Before = append(s.Before, cmd("", "update-grub"))
	if err := checkNeverTouched(s); err == nil {
		t.Error("the never touched list does not see a Before command")
	}
}
