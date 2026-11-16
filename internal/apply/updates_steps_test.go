package apply_test

import (
	"context"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/Shironex/stackward/internal/apply"
	"github.com/Shironex/stackward/internal/apply/applytest"
	"github.com/Shironex/stackward/internal/facts"
	"github.com/Shironex/stackward/internal/plan"
)

// The update and intrusion steps (unattended-upgrades,
// unattended-upgrades-install, unattended-upgrades-reboot, fail2ban-sshd)
// against a t.TempDir() root with the fake runner: applied, applied
// again, undone, and refused when tampered with.

const (
	uuPath     = "/etc/apt/apt.conf.d/90stackward-unattended-upgrades"
	rebootPath = "/etc/apt/apt.conf.d/91stackward-automatic-reboot"
	jailPath   = "/etc/fail2ban/jail.d/90-stackward-sshd.local"
	dpkgPath   = "/var/lib/dpkg/status"
)

// withoutValidate drops the validate calls (apt-config dump -c STAGED),
// whose staged path is random.
func withoutValidate(calls [][]string) [][]string {
	var out [][]string
	for _, c := range calls {
		if len(c) > 0 && c[0] == "apt-config" {
			continue
		}
		out = append(out, c)
	}
	return out
}

func TestUpdateStepsApplyTwiceThenUndoRestoresExactly(t *testing.T) {
	root := t.TempDir()
	p := applytest.FixturePlan(t, "plan-updates-fail2ban-jail")
	h, r := applytest.NewHost(root)

	// The reboot step is opt in and never part of --all-safe.
	if got := ids(mustSelect(t, p, nil, true)); !slices.Equal(got, []string{"unattended-upgrades"}) {
		t.Fatalf("--all-safe selected %v", got)
	}
	steps := mustSelect(t, p, []string{"unattended-upgrades", "unattended-upgrades-reboot"}, false)
	j, err := run(t, h, steps, "20260301T120000Z-d1d1d1")
	if err != nil || j.Status != apply.RunOK {
		t.Fatalf("run: %v %+v", err, j)
	}
	for _, s := range steps {
		if got, ok := applytest.Read(t, root, s.Edits[0].Path); !ok || got != s.Edits[0].New {
			t.Errorf("%s: %q", s.Edits[0].Path, got)
		}
	}
	calls := r.Calls()
	validated := 0
	for _, c := range calls {
		if len(c) == 4 && c[0] == "apt-config" && c[1] == "dump" && c[2] == "-c" {
			validated++
		}
	}
	if validated != 2 {
		t.Errorf("apt-config validated %d staged files, want 2: %v", validated, calls)
	}
	want := [][]string{{"systemctl", "enable", "apt-daily-upgrade.timer"}, {"systemctl", "start", "apt-daily-upgrade.timer"}}
	if got := withoutValidate(calls); !slices.EqualFunc(got, want, slices.Equal) {
		t.Errorf("commands %v, want %v (and never a reboot)", got, want)
	}

	// Applied twice: the second run changes and runs nothing.
	r.Reset()
	prepared, err := apply.Prepare(h, steps)
	if err != nil {
		t.Fatal(err)
	}
	if n := apply.ToRun(prepared); n != 0 || len(r.Calls()) != 0 {
		t.Errorf("second run would apply %d steps, ran %v", n, r.Calls())
	}

	// Undo removes both drop-ins and reverses the timer, nothing else.
	r.Reset()
	loaded, err := apply.LoadJournal(h, j.RunID)
	if err != nil {
		t.Fatal(err)
	}
	if changed, err := apply.Undo(context.Background(), loaded, undoOpts(h)); err != nil || !changed {
		t.Fatalf("undo: %v %v", changed, err)
	}
	for _, p := range []string{uuPath, rebootPath} {
		if _, ok := applytest.Read(t, root, p); ok {
			t.Errorf("%s is still there after undo", p)
		}
	}
	wantUndo := [][]string{{"systemctl", "stop", "apt-daily-upgrade.timer"}, {"systemctl", "disable", "apt-daily-upgrade.timer"}}
	if got := r.Calls(); !slices.EqualFunc(got, wantUndo, slices.Equal) {
		t.Errorf("undo commands %v, want %v", got, wantUndo)
	}
}

func TestInstallStepsRetryUntilThePackageIsInstalled(t *testing.T) {
	root := t.TempDir()
	p := applytest.FixturePlan(t, "plan-updates-fail2ban-install")
	h, r := applytest.NewHost(root)
	steps := mustSelect(t, p, []string{"unattended-upgrades-install"}, false)
	if _, err := run(t, h, steps, "20260301T120000Z-e1e1e1"); err != nil {
		t.Fatal(err)
	}
	// The plan saw empty package lists: apt-get update, then the install,
	// both before the drop-in.
	before := applytest.Step(t, p, "unattended-upgrades-install").Before
	if len(before) != 2 {
		t.Fatalf("before %+v", before)
	}
	if got := withoutValidate(r.Calls()); !slices.EqualFunc(got, [][]string{before[0].Args, before[1].Args}, slices.Equal) {
		t.Errorf("commands %v", got)
	}
	// The fake apt installed nothing: dpkg does not list the package, so
	// the step is not applied and its install runs again.
	r.Reset()
	prepared, err := apply.Prepare(h, steps)
	if err != nil {
		t.Fatal(err)
	}
	if apply.ToRun(prepared) != 1 {
		t.Fatalf("a missing package counts as applied: %+v", prepared)
	}
	applytest.Write(t, root, dpkgPath, "Package: unattended-upgrades\nStatus: install ok installed\n", 0o644)
	prepared, err = apply.Prepare(h, steps)
	if err != nil {
		t.Fatal(err)
	}
	if n := apply.ToRun(prepared); n != 0 || len(r.Calls()) != 0 {
		t.Errorf("installed: %d to run, calls %v", n, r.Calls())
	}
}

func TestFail2banJailInTheTransaction(t *testing.T) {
	root := t.TempDir()
	h, r, _ := applytest.NewTxnHost(t, root)
	p := applytest.FixturePlan(t, "plan-updates-fail2ban-jail")
	ctx := context.Background()
	steps := mustSelect(t, p, []string{"fail2ban-sshd"}, false)
	if !(apply.Selection{Steps: steps}).AccessCritical() {
		t.Fatal("the jail must run as a transaction")
	}
	prepared, err := apply.Prepare(h, steps)
	if err != nil {
		t.Fatal(err)
	}
	base, err := apply.Preflight(ctx, h)
	if err != nil {
		t.Fatal(err)
	}
	o := options(h, txnID)
	o.Now = func() time.Time { return fixedNow }
	j, st, err := apply.RunTransaction(ctx, prepared, apply.TxnOptions{
		Options: o, ConfirmWithin: time.Minute, Session: applying, Exe: applytest.Exe, Baseline: base,
	})
	if err != nil || st.Status != apply.TxnOpen {
		t.Fatalf("transaction: %v %+v", err, st)
	}
	s := steps[0]
	if got, ok := applytest.Read(t, root, jailPath); !ok || got != s.Edits[0].New {
		t.Errorf("jail %q", got)
	}
	if callIndex(r, "fail2ban-client -t") < 0 || callIndex(r, "fail2ban-client -t") > callIndex(r, "systemctl reload fail2ban") {
		t.Errorf("the configuration test must run before the reload: %v", r.Calls())
	}
	// Applied twice: nothing to do.
	prepared, err = apply.Prepare(h, steps)
	if err != nil {
		t.Fatal(err)
	}
	if n := apply.ToRun(prepared); n != 0 {
		t.Errorf("second run would apply %d steps", n)
	}
	// The rollback removes the jail and reloads fail2ban, lifting its bans.
	r.Reset()
	if err := apply.RollBack(ctx, h, j, st, apply.CauseTimer, apply.UndoOptions{Host: h, Now: o.Now}); err != nil {
		t.Fatal(err)
	}
	if _, ok := applytest.Read(t, root, jailPath); ok {
		t.Error("the rollback left the jail")
	}
	if callIndex(r, "systemctl reload fail2ban") < 0 {
		t.Errorf("the rollback did not reload fail2ban: %v", r.Calls())
	}
}

func TestUpdateStepsTamperedAreRefused(t *testing.T) {
	p := applytest.FixturePlan(t, "plan-updates-fail2ban-jail")
	pi := applytest.FixturePlan(t, "plan-updates-fail2ban-install")
	rehash := func(e *plan.FileEdit) { e.NewSHA256 = plan.SHA256([]byte(e.New)) }
	for name, tc := range map[string]struct {
		p      *plan.Plan
		id     string
		tamper func(s *plan.Step)
		want   string
	}{
		"uu content": {p, "unattended-upgrades", func(s *plan.Step) {
			s.Edits[0].New = strings.ReplaceAll(s.Edits[0].New, "\"1\"", "\"0\"")
			rehash(&s.Edits[0])
		}, "not what the step writes"},
		"uu silent install": {p, "unattended-upgrades", func(s *plan.Step) {
			s.Commands = append([]plan.Command{{Args: []string{"apt-get", "install", "-y", "unattended-upgrades"}}}, s.Commands...)
		}, "not ones the step runs"},
		"uu upgrade everything": {pi, "unattended-upgrades-install", func(s *plan.Step) {
			s.Before[1].Args = []string{"apt-get", "upgrade", "-y"}
		}, "not the install the step runs"},
		"reboot now": {p, "unattended-upgrades-reboot", func(s *plan.Step) {
			s.Commands = []plan.Command{{Args: []string{"systemctl", "reboot"}}}
		}, "commands"},
		"reboot window": {p, "unattended-upgrades-reboot", func(s *plan.Step) {
			s.Edits[0].New = strings.ReplaceAll(s.Edits[0].New, "04:00", "now")
			rehash(&s.Edits[0])
		}, "not what the step writes"},
		"jail ignore list": {p, "fail2ban-sshd", func(s *plan.Step) {
			s.Edits[0].New = strings.Replace(s.Edits[0].New, "127.0.0.1/8 ::1 ", "", 1)
			rehash(&s.Edits[0])
		}, "loopback"},
		"jail bantime": {p, "fail2ban-sshd", func(s *plan.Step) {
			s.Edits[0].New += "bantime = -1\n"
			rehash(&s.Edits[0])
		}, "not what the step writes"},
		"jail path": {p, "fail2ban-sshd", func(s *plan.Step) { s.Edits[0].Path = "/etc/fail2ban/jail.local" }, "only ever edits"},
		"jail undo": {p, "fail2ban-sshd", func(s *plan.Step) { s.Undo.Commands[1].Args = []string{"systemctl", "stop", "ssh"} }, "not one the step runs"},
	} {
		t.Run(name, func(t *testing.T) {
			s := clone(applytest.Step(t, tc.p, tc.id))
			tc.tamper(&s)
			h, r := applytest.NewHost(t.TempDir())
			_, err := apply.Prepare(h, []plan.Step{s})
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("err %v, want %q", err, tc.want)
			}
			if len(r.Calls()) != 0 {
				t.Errorf("commands ran: %v", r.Calls())
			}
		})
	}
}

// Before the transaction, apply proves the jail would not ban the session
// that applies it: a plan made without a source (a facts file) is refused
// from an SSH session whose address the jail does not ignore, and passes
// from the console.
func TestFail2banGuardChecksTheApplyingSession(t *testing.T) {
	p := applytest.FixturePlan(t, "plan-updates-fail2ban-jail")
	steps := mustSelect(t, p, []string{"fail2ban-sshd"}, false)
	if !apply.NeedsProof(steps) {
		t.Fatal("the jail must go through the lockout guard")
	}
	live := &facts.Facts{}
	if _, err := apply.GuardAccess(steps, live, applying); err == nil || !strings.Contains(err.Error(), "192.0.2.10") {
		t.Errorf("an unignored applying session: %v", err)
	}
	if _, err := apply.GuardAccess(steps, live, console); err != nil {
		t.Errorf("the console: %v", err)
	}
	tailnet := applying
	tailnet.SSHConnection = "100.100.7.8 50022 100.101.102.105 2222"
	if _, err := apply.GuardAccess(steps, live, tailnet); err != nil {
		t.Errorf("a tailnet session: %v", err)
	}
}
