package cli

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/Shironex/stackward/internal/apply"
	"github.com/Shironex/stackward/internal/plan/txntest"
	"github.com/Shironex/stackward/internal/report"
)

// bootCommand reads the ExecStart of the installed boot unit, the command
// systemd runs at boot.
func (x *txnTest) bootCommand(t *testing.T, id string) []string {
	t.Helper()
	b, err := os.ReadFile(filepath.Join(x.root, apply.BootUnitPath(id)))
	if err != nil {
		t.Fatalf("the boot unit is not installed: %v", err)
	}
	for _, line := range strings.Split(string(b), "\n") {
		if cmd, ok := strings.CutPrefix(line, "ExecStart="); ok {
			return strings.Fields(cmd)
		}
	}
	t.Fatal("the boot unit has no ExecStart")
	return nil
}

// The host reboots before the confirm: the transient timer is gone and the
// boot unit runs its command with no session. It rolls back, removes
// itself, and access steps stay blocked until acknowledged.
func TestTransactionBootRollbackThenAck(t *testing.T) {
	x := newTxnTest(t)
	if code, out, errs := x.apply("--step", txntest.GoodID, "--confirm-within", "5m", "--yes", x.plan); code != report.ExitOK {
		t.Fatalf("exit %d: %s\n%s", code, out, errs)
	}
	cmd := x.bootCommand(t, txnRunID)
	if len(cmd) < 2 || cmd[0] != apply.TxnBinary(txnRunID) || cmd[len(cmd)-1] != "--by-boot" {
		t.Fatalf("the boot unit runs %q", cmd)
	}
	x.sys.Fire("stackward-rollback-" + txnRunID) // the reboot drops the timer
	x.tick = x.tick.Add(time.Minute)             // before the deadline
	x.env.session = func() apply.Session { return apply.Session{} }
	code, out, errs := x.undo(cmd[2:]...)
	if code != report.ExitOK || !strings.Contains(out, "booted") || !strings.Contains(out, "--ack-rollback "+txnRunID) {
		t.Fatalf("boot rollback: exit %d: %s\n%s", code, out, errs)
	}
	if x.exists(txntest.GoodPath) || x.exists(apply.BootUnitPath(txnRunID)) {
		t.Error("the change or the boot unit is still there")
	}
	if st := x.state(t); st.Status != apply.TxnRolledBack || st.Cause != apply.CauseBoot || st.AckedAt != "" {
		t.Errorf("state %+v", st)
	}
	x.env.runID = "20260301T120100Z-e33e33"
	if code, _, errs = x.apply("--step", txntest.GoodID, "--yes", x.plan); code != report.ExitError || !strings.Contains(errs, "--ack-rollback "+txnRunID) {
		t.Errorf("blocked: exit %d: %s", code, errs)
	}
	if code, out, _ = x.confirm(secondSession, "--ack-rollback", txnRunID); code != report.ExitOK || !strings.Contains(out, "(boot)") {
		t.Errorf("ack: exit %d: %s", code, out)
	}
}

// A boot unit left behind runs at the next boot, finds the transaction no
// longer open and removes itself. Until then apply refuses access steps
// and prints the fix.
func TestStaleBootUnitBlocksAccessSteps(t *testing.T) {
	x := newTxnTest(t)
	if code, out, errs := x.apply("--step", txntest.GoodID, "--yes", x.plan); code != report.ExitOK {
		t.Fatalf("exit %d: %s\n%s", code, out, errs)
	}
	cmd := x.bootCommand(t, txnRunID)
	unit, _ := os.ReadFile(filepath.Join(x.root, apply.BootUnitPath(txnRunID)))
	x.tick = x.tick.Add(time.Minute)
	if code, out, errs := x.confirm(secondSession, txnRunID); code != report.ExitOK {
		t.Fatalf("confirm: exit %d: %s\n%s", code, out, errs)
	}
	// Put the unit back, as if its removal had failed.
	if err := os.WriteFile(filepath.Join(x.root, apply.BootUnitPath(txnRunID)), unit, 0o644); err != nil {
		t.Fatal(err)
	}
	x.env.runID = "20260301T120100Z-e33e33"
	// The good step is in place now, so ask for the bad one.
	code, _, errs := x.apply("--step", txntest.BadID, "--yes", x.plan)
	if code != report.ExitError || !strings.Contains(errs, "left over") || !strings.Contains(errs, "sudo rm -f ") || !strings.Contains(errs, apply.BootUnitPath(txnRunID)) {
		t.Errorf("stale unit: exit %d: %s", code, errs)
	}
	if code, out, errs := x.undo(cmd[2:]...); code != report.ExitOK || !strings.Contains(out, "confirmed; nothing to roll back") {
		t.Errorf("late boot: exit %d: %s\n%s", code, out, errs)
	}
	if x.exists(apply.BootUnitPath(txnRunID)) || !x.exists(txntest.GoodPath) {
		t.Error("the boot unit must remove itself and keep the confirmed change")
	}
	x.env.runID = "20260301T120200Z-f44f44"
	if code, out, errs := x.apply("--step", txntest.BadID, "--yes", x.plan); code != exitStepFailed || strings.Contains(errs, "left over") {
		t.Errorf("after the cleanup the transaction runs (and rolls the bad step back): exit %d: %s\n%s", code, out, errs)
	}
}

func TestUndoByFlags(t *testing.T) {
	x := newTxnTest(t)
	for args, want := range map[string]string{
		"--transaction " + txnRunID + " --by-timer --by-boot": "not both",
		"--run " + txnRunID + " --by-boot":                    "go with --transaction",
	} {
		if code, _, errs := x.undo(strings.Fields(args)...); code != report.ExitError || !strings.Contains(errs, want) {
			t.Errorf("%s: exit %d: %s", args, code, errs)
		}
	}
}

// The rollback timer and the boot unit do not check the hostname: at early
// boot it may be unset, and a renamed host must still roll back. They note
// what they saw. A person's undo still refuses.
func TestAutomaticRollbackSkipsTheHostnameCheck(t *testing.T) {
	for _, by := range []string{"--by-boot", "--by-timer"} {
		for _, name := range []string{"", "renamed.example.com"} {
			t.Run(by+" "+name, func(t *testing.T) {
				x := newTxnTest(t)
				if code, out, errs := x.apply("--step", txntest.GoodID, "--yes", x.plan); code != report.ExitOK {
					t.Fatalf("exit %d: %s\n%s", code, out, errs)
				}
				x.env.hostname = func() (string, error) { return name, nil }
				x.env.session = func() apply.Session { return apply.Session{} }
				code, out, errs := x.undo("--transaction", txnRunID, "--yes", by)
				if code != report.ExitOK || !strings.Contains(out, "note:") {
					t.Fatalf("exit %d: %s\n%s", code, out, errs)
				}
				st := x.state(t)
				want := "unset"
				if name != "" {
					want = report.HashHostname(name)
				}
				if st.Status != apply.TxnRolledBack || x.exists(txntest.GoodPath) || st.RollbackHost != want || !strings.Contains(st.HostNote, want) {
					t.Errorf("state %+v", st)
				}
				if _, out, _ := x.confirm(secondSession); !strings.Contains(out, "note:") {
					t.Errorf("the status view lacks the note:\n%s", out)
				}
			})
		}
	}
	// The same hostname: recorded, no note.
	x := newTxnTest(t)
	if code, out, errs := x.apply("--step", txntest.GoodID, "--yes", x.plan); code != report.ExitOK {
		t.Fatalf("exit %d: %s\n%s", code, out, errs)
	}
	if code, out, errs := x.undo("--transaction", txnRunID, "--yes", "--by-boot"); code != report.ExitOK || strings.Contains(out, "note:") {
		t.Fatalf("exit %d: %s\n%s", code, out, errs)
	}
	if st := x.state(t); st.RollbackHost == "" || st.RollbackHost == "unset" || st.HostNote != "" {
		t.Errorf("state %+v", st)
	}
}

func TestManualUndoKeepsTheHostnameCheck(t *testing.T) {
	for _, name := range []string{"", "renamed.example.com"} {
		x := newTxnTest(t)
		if code, out, errs := x.apply("--step", txntest.GoodID, "--yes", x.plan); code != report.ExitOK {
			t.Fatalf("exit %d: %s\n%s", code, out, errs)
		}
		x.env.hostname = func() (string, error) { return name, nil }
		code, _, errs := x.undo("--transaction", txnRunID, "--yes")
		if code != report.ExitError || !strings.Contains(errs, "set the old hostname back") || !strings.Contains(errs, "nothing was changed") {
			t.Errorf("%q: exit %d: %s", name, code, errs)
		}
		if st := x.state(t); st.Status != apply.TxnOpen || !x.exists(txntest.GoodPath) {
			t.Errorf("a refused undo changed something: %+v", st)
		}
	}
	// undo --run too.
	x := newTxnTest(t)
	if code, out, errs := x.apply("--step", "journald-cap", "--yes", x.plan); code != report.ExitOK {
		t.Fatalf("exit %d: %s\n%s", code, out, errs)
	}
	x.env.hostname = func() (string, error) { return "renamed.example.com", nil }
	if code, _, errs := x.undo("--run", txnRunID, "--yes"); code != report.ExitError || !strings.Contains(errs, "set the old hostname back") {
		t.Errorf("undo --run: exit %d: %s", code, errs)
	}
}
