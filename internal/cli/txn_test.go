package cli

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/Shironex/stackward/internal/apply"
	"github.com/Shironex/stackward/internal/apply/applytest"
	"github.com/Shironex/stackward/internal/plan/txntest"
	"github.com/Shironex/stackward/internal/report"
)

// The transaction through the command line, against a t.TempDir() root:
// applytest.System fakes systemd, sshd and ss, so no timer is armed, and
// the timer "fires" by the test running the command it was given.

const txnRunID = "20260301T120000Z-c11c11"

var (
	applyingSession = apply.Session{SSHConnection: "192.0.2.10 50022 198.51.100.5 22", AuditSession: "7", SSHD: "700:5000"}
	secondSession   = apply.Session{SSHConnection: "192.0.2.10 50544 198.51.100.5 22", AuditSession: "9", SSHD: "900:7000"}
)

type txnTest struct {
	*applyTest
	sys  *applytest.System
	tick time.Time
}

func newTxnTest(t *testing.T) *txnTest {
	t.Helper()
	a := newApplyTest(t)
	h, r, sys := applytest.NewTxnHost(t, a.root)
	a.env.host, a.runner = h, r
	a.plan = applytest.WritePlan(t, applytest.TxnPlan(t))
	x := &txnTest{applyTest: a, sys: sys, tick: time.Date(2026, 3, 1, 12, 0, 0, 0, time.UTC)}
	a.env.now = func() time.Time { return x.tick }
	a.env.session = func() apply.Session { return applyingSession }
	return x
}

func (x *txnTest) confirm(sess apply.Session, args ...string) (int, string, string) {
	x.env.session = func() apply.Session { return sess }
	var out, errs bytes.Buffer
	code := runConfirmEnv(args, &out, &errs, x.env)
	return code, out.String(), errs.String()
}

func (x *txnTest) exists(p string) bool {
	_, err := os.Stat(filepath.Join(x.root, p))
	return err == nil
}

func (x *txnTest) state(t *testing.T) *apply.Txn {
	t.Helper()
	st, err := apply.LoadTxn(x.env.host)
	if err != nil || st == nil {
		t.Fatalf("state: %v %v", st, err)
	}
	return st
}

func TestTransactionApplyThenConfirmFromANewSession(t *testing.T) {
	x := newTxnTest(t)
	code, out, errs := x.apply("--step", txntest.GoodID, "--confirm-within", "1m", "--yes", x.plan)
	if code != report.ExitOK {
		t.Fatalf("exit %d: %s\n%s", code, out, errs)
	}
	// The console reminder comes before anything about the steps.
	if r, p := strings.Index(out, "provider console"), strings.Index(out, "Will apply"); r < 0 || p < 0 || r > p {
		t.Errorf("reminder at %d, preview at %d:\n%s", r, p, out)
	}
	for _, want := range []string{
		"ACCESS-CRITICAL", "stackward-rollback-" + txnRunID + ".timer", "NEW SSH session",
		"sudo stackward confirm " + txnRunID, "sudo stackward confirm --console " + txnRunID,
		"sudo stackward undo --transaction " + txnRunID, "2026-03-01T12:01:00Z", "SSH from 192.0.2.10 port 50022",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("output lacks %q:\n%s", want, out)
		}
	}
	if strings.Contains(out, "undo --run") {
		t.Errorf("an open transaction must not point at undo --run:\n%s", out)
	}
	if !x.exists(txntest.GoodPath) || !x.sys.Active("stackward-rollback-"+txnRunID+".timer") {
		t.Fatal("the change or the timer is missing")
	}

	// A second transaction is refused while one is open, and changes
	// nothing.
	x.runner.Reset()
	x.env.runID = "20260301T120010Z-d22d22"
	code, _, errs = x.apply("--step", txntest.BadID, "--yes", x.plan)
	if code != report.ExitError || !strings.Contains(errs, "only one transaction") {
		t.Errorf("second transaction: exit %d: %s", code, errs)
	}
	if x.exists(txntest.BadPath) || len(x.runner.Calls()) != 0 {
		t.Errorf("the refused transaction ran %v", x.runner.Calls())
	}
	// undo --run is refused for an open transaction.
	if code, _, errs = x.undo("--run", txnRunID, "--yes"); code != report.ExitError || !strings.Contains(errs, "--transaction "+txnRunID) {
		t.Errorf("undo --run: exit %d: %s", code, errs)
	}

	// Same session: refused. No SSH at all: refused, pointing at --console.
	if code, _, errs = x.confirm(applyingSession, txnRunID); code != report.ExitError || !strings.Contains(errs, "same") {
		t.Errorf("same session: exit %d: %s", code, errs)
	}
	if code, _, errs = x.confirm(apply.Session{}, txnRunID); code != report.ExitError || !strings.Contains(errs, "--console") {
		t.Errorf("no session: exit %d: %s", code, errs)
	}
	if code, _, errs = x.confirm(secondSession, "20260301T120010Z-d22d22"); code != report.ExitError || !strings.Contains(errs, "not the current transaction") {
		t.Errorf("wrong id: exit %d: %s", code, errs)
	}
	if st := x.state(t); st.Status != apply.TxnOpen {
		t.Fatalf("a refused confirm changed the state: %+v", st)
	}
	x.tick = x.tick.Add(40 * time.Second)
	code, out, errs = x.confirm(secondSession, txnRunID)
	if code != report.ExitOK || !strings.Contains(out, "confirmed") || !strings.Contains(out, "new SSH session") {
		t.Fatalf("confirm: exit %d: %s\n%s", code, out, errs)
	}
	if x.sys.Active("stackward-rollback-"+txnRunID+".timer") || !x.exists(txntest.GoodPath) {
		t.Error("after confirm the timer must be gone and the change must stay")
	}
	// The status view.
	if code, out, _ = x.confirm(secondSession); code != report.ExitOK || !strings.Contains(out, "status:      confirmed") {
		t.Errorf("status: %s", out)
	}
	// The timer would find nothing to do now.
	code, out, _ = x.undo("--transaction", txnRunID, "--yes", "--by-timer")
	if code != report.ExitOK || !strings.Contains(out, "confirmed; nothing to roll back") || !x.exists(txntest.GoodPath) {
		t.Errorf("late timer: exit %d: %s", code, out)
	}
}

// The timer fires with no SSH session at all (the session is gone): the
// rollback restores the host and blocks access steps until acknowledged.
// Safe steps still run.
func TestTransactionTimerRollbackThenAck(t *testing.T) {
	x := newTxnTest(t)
	if code, out, errs := x.apply("--step", txntest.GoodID, "--confirm-within", "30s", "--yes", x.plan); code != report.ExitOK {
		t.Fatalf("exit %d: %s\n%s", code, out, errs)
	}
	cmd := x.sys.Fire("stackward-rollback-" + txnRunID)
	if len(cmd) < 2 || cmd[0] != apply.TxnBinary(txnRunID) || cmd[1] != "undo" {
		t.Fatalf("the timer runs %q", cmd)
	}
	x.tick = x.tick.Add(30 * time.Second)
	x.env.session = func() apply.Session { return apply.Session{} } // a systemd service: no session
	code, out, errs := x.undo(cmd[2:]...)
	if code != report.ExitOK || !strings.Contains(out, "--ack-rollback "+txnRunID) {
		t.Fatalf("timer rollback: exit %d: %s\n%s", code, out, errs)
	}
	if x.exists(txntest.GoodPath) {
		t.Error("the rollback left the drop-in")
	}
	st := x.state(t)
	if st.Status != apply.TxnRolledBack || st.Cause != apply.CauseTimer || st.AckedAt != "" {
		t.Errorf("state %+v", st)
	}
	// Firing twice does nothing.
	if code, out, _ = x.undo(cmd[2:]...); code != report.ExitOK || !strings.Contains(out, "nothing to roll back") {
		t.Errorf("second fire: exit %d: %s", code, out)
	}

	// Access steps are blocked until acknowledged; safe steps are not.
	x.env.runID = "20260301T120100Z-e33e33"
	if code, _, errs = x.apply("--step", txntest.GoodID, "--yes", x.plan); code != report.ExitError || !strings.Contains(errs, "--ack-rollback "+txnRunID) {
		t.Errorf("blocked: exit %d: %s", code, errs)
	}
	if code, out, errs = x.apply("--all-safe", "--yes", x.plan); code != report.ExitOK {
		t.Errorf("safe steps after a rollback: exit %d: %s\n%s", code, out, errs)
	}
	// A confirm cannot acknowledge; --ack-rollback with another id neither.
	if code, _, _ = x.confirm(secondSession, txnRunID); code != report.ExitError {
		t.Error("confirm of a rolled back transaction")
	}
	if code, _, _ = x.confirm(secondSession, "--ack-rollback", "20260301T120100Z-e33e33"); code != report.ExitError {
		t.Error("ack of another id")
	}
	code, out, errs = x.confirm(applyingSession, "--ack-rollback", txnRunID)
	if code != report.ExitOK || !strings.Contains(out, "Acknowledged") || !strings.Contains(out, "(timer)") {
		t.Fatalf("ack: exit %d: %s\n%s", code, out, errs)
	}
	x.env.runID = "20260301T120200Z-f44f44"
	x.env.session = func() apply.Session { return applyingSession }
	if code, out, errs = x.apply("--step", txntest.GoodID, "--yes", x.plan); code != report.ExitOK {
		t.Errorf("after ack: exit %d: %s\n%s", code, out, errs)
	}
}

func TestTransactionValidationFailureRollsBackAtOnce(t *testing.T) {
	x := newTxnTest(t)
	code, out, errs := x.apply("--step", txntest.BadID, "--yes", x.plan)
	if code != exitStepFailed || !strings.Contains(errs, "validation failed") || !strings.Contains(errs, "rolled back at once") {
		t.Fatalf("exit %d: %s\n%s", code, out, errs)
	}
	if x.exists(txntest.BadPath) || x.sys.Active("stackward-rollback-"+txnRunID+".timer") {
		t.Error("the bad file or the timer is still there")
	}
	if st := x.state(t); st.Status != apply.TxnRolledBack || st.Cause != apply.CauseValidation || st.Blocks(x.tick) != "" {
		t.Errorf("state %+v", st)
	}
}

func TestTransactionManualUndo(t *testing.T) {
	x := newTxnTest(t)
	if code, out, errs := x.apply("--step", txntest.GoodID, "--yes", x.plan); code != report.ExitOK {
		t.Fatalf("exit %d: %s\n%s", code, out, errs)
	}
	code, out, errs := x.undo("--transaction", txnRunID, "--yes")
	if code != report.ExitOK || !strings.Contains(out, "rolled back") {
		t.Fatalf("exit %d: %s\n%s", code, out, errs)
	}
	st := x.state(t)
	if x.exists(txntest.GoodPath) || x.sys.Active(st.TimerUnit+".timer") || st.Cause != apply.CauseManual || st.Blocks(x.tick) != "" {
		t.Errorf("after a manual rollback: %+v", st)
	}
}

func TestTransactionRefusals(t *testing.T) {
	for name, tc := range map[string]struct {
		args []string
		want string
	}{
		"with --all-safe":    {[]string{"--step", txntest.GoodID, "--all-safe", "--yes"}, "run of their own"},
		"with a safe step":   {[]string{"--step", txntest.GoodID, "--step", "journald-cap", "--yes"}, "journald-cap"},
		"deadline too short": {[]string{"--step", txntest.GoodID, "--confirm-within", "10s", "--yes"}, "outside 30s to 30m0s"},
		"deadline too long":  {[]string{"--step", txntest.GoodID, "--confirm-within", "2h", "--yes"}, "outside"},
		"no terminal":        {[]string{"--step", txntest.GoodID}, "pass --yes"},
	} {
		t.Run(name, func(t *testing.T) {
			x := newTxnTest(t)
			code, _, errs := x.apply(append(tc.args, x.plan)...)
			if code != report.ExitError || !strings.Contains(errs, tc.want) {
				t.Errorf("exit %d, want %q: %s", code, tc.want, errs)
			}
			if x.exists(txntest.GoodPath) || x.exists(apply.TxnStatePath) {
				t.Error("a refusal changed something")
			}
		})
	}
	// sshd not listening: refused before anything changes.
	x := newTxnTest(t)
	x.sys.Listening = nil
	if code, _, errs := x.apply("--step", txntest.GoodID, "--yes", x.plan); code != report.ExitError || !strings.Contains(errs, "nothing listens") {
		t.Errorf("not listening: exit %d: %s", code, errs)
	}
	if x.exists(txntest.GoodPath) || x.exists(apply.TxnStatePath) {
		t.Error("a refused preflight changed something")
	}
}

func TestConfirmArguments(t *testing.T) {
	x := newTxnTest(t)
	for _, args := range [][]string{{"a", "b"}, {"--ack-rollback", txnRunID, txnRunID}, {"--ack-rollback", txnRunID, "--console"}, {"../etc"}} {
		if code, _, _ := x.confirm(secondSession, args...); code != report.ExitError {
			t.Errorf("%v accepted", args)
		}
	}
	if code, out, _ := x.confirm(secondSession); code != report.ExitOK || !strings.Contains(out, "no transaction") {
		t.Errorf("status without a transaction: %s", out)
	}
	x.env.euid = func() int { return 1000 }
	if code, _, errs := x.confirm(secondSession, txnRunID); code != report.ExitError || !strings.Contains(errs, "needs root") {
		t.Errorf("non root: %s", errs)
	}
}

// The rollback timer waits for the lock an apply or confirm holds.
func TestTimerRollbackWaitsForTheLock(t *testing.T) {
	x := newTxnTest(t)
	if code, out, errs := x.apply("--step", txntest.GoodID, "--yes", x.plan); code != report.ExitOK {
		t.Fatalf("exit %d: %s\n%s", code, out, errs)
	}
	release, err := apply.AcquireRunLock(x.env.host, "a confirm")
	if err != nil {
		t.Skipf("locking: %v", err)
	}
	waits := 0
	x.env.sleep = func(time.Duration) {
		if waits++; waits == 2 {
			_ = release()
		}
	}
	x.tick = x.tick.Add(5 * time.Minute)
	if code, out, errs := x.undo("--transaction", txnRunID, "--yes", "--by-timer"); code != report.ExitOK || waits != 2 {
		t.Fatalf("exit %d after %d waits: %s\n%s", code, waits, out, errs)
	}
	if x.exists(txntest.GoodPath) {
		t.Error("not rolled back")
	}
}

func TestConfirmIsRouted(t *testing.T) {
	var out, errs bytes.Buffer
	if code := Run([]string{"confirm", "-h"}, &out, &errs); code != report.ExitOK || !strings.Contains(errs.String(), "--console") {
		t.Errorf("confirm -h: %d %s", code, errs.String())
	}
	out.Reset()
	if Run([]string{"help"}, &out, &errs); !strings.Contains(out.String(), "stackward confirm ID") {
		t.Errorf("usage lacks confirm:\n%s", out.String())
	}
}
