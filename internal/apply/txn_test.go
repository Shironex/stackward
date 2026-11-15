package apply_test

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/Shironex/stackward/internal/apply"
	"github.com/Shironex/stackward/internal/apply/applytest"
	"github.com/Shironex/stackward/internal/plan"
	"github.com/Shironex/stackward/internal/plan/txntest"
	"github.com/Shironex/stackward/internal/schemacheck"
)

// The transaction runs here against a t.TempDir() root: systemd, sshd and
// ss are faked by applytest.System, so no timer is armed and no program
// starts.

const txnID = "20260301T120000Z-7a7a7a"

type txnRig struct {
	root string
	h    apply.Host
	r    *applytest.Runner
	sys  *applytest.System
	p    *plan.Plan
	now  time.Time
}

func newTxnRig(t *testing.T) *txnRig {
	t.Helper()
	root := t.TempDir()
	h, r, sys := applytest.NewTxnHost(t, root)
	return &txnRig{root: root, h: h, r: r, sys: sys, p: applytest.TxnPlan(t), now: fixedNow}
}

func (g *txnRig) clock() time.Time { return g.now }

// start runs a transaction of step id the way apply does.
func (g *txnRig) start(t *testing.T, id string) (*apply.Journal, *apply.Txn, error) {
	t.Helper()
	ctx := context.Background()
	steps := mustSelect(t, g.p, []string{id}, false)
	prepared, err := apply.Prepare(g.h, steps)
	if err != nil {
		t.Fatal(err)
	}
	base, err := apply.Preflight(ctx, g.h)
	if err != nil {
		t.Fatal(err)
	}
	o := options(g.h, txnID)
	o.Now = g.clock
	return apply.RunTransaction(ctx, prepared, apply.TxnOptions{
		Options: o, ConfirmWithin: time.Minute, Session: applying, Exe: applytest.Exe, Baseline: base,
	})
}

func (g *txnRig) state(t *testing.T) *apply.Txn {
	t.Helper()
	st, err := apply.LoadTxn(g.h)
	if err != nil {
		t.Fatal(err)
	}
	return st
}

func (g *txnRig) exists(p string) bool {
	_, err := os.Stat(filepath.Join(g.root, p))
	return err == nil
}

func TestConfirmWithinBounds(t *testing.T) {
	for d, ok := range map[time.Duration]bool{
		29 * time.Second: false, 30 * time.Second: true, 5 * time.Minute: true,
		30 * time.Minute: true, 31 * time.Minute: false, 0: false, -time.Minute: false,
	} {
		if err := apply.CheckConfirmWithin(d); (err == nil) != ok {
			t.Errorf("%s: %v", d, err)
		}
	}
}

// open -> confirmed, with a second transaction refused while open and the
// applying session refused as the confirmer.
func TestTransactionOpenThenConfirmed(t *testing.T) {
	g := newTxnRig(t)
	j, st, err := g.start(t, txntest.GoodID)
	if err != nil {
		t.Fatal(err)
	}
	if st.Status != apply.TxnOpen || st.Deadline != "2026-03-01T12:01:00Z" || st.TimerUnit != "stackward-rollback-"+txnID {
		t.Errorf("state %+v", st)
	}
	if !g.sys.Active(st.TimerUnit+".timer") || !g.exists(txntest.GoodPath) || !g.exists(apply.TxnBinary(txnID)) {
		t.Fatal("timer, file or binary copy missing after the transaction opened")
	}
	if got := strings.Join(st.Rollback, " "); got != apply.TxnBinary(txnID)+" undo --transaction "+txnID+" --yes --by-timer" {
		t.Errorf("rollback command %q", got)
	}
	if j.Transaction == nil || j.Transaction.Status != apply.TxnOpen || len(j.Transaction.Checks) != 3 {
		t.Fatalf("journal transaction %+v", j.Transaction)
	}
	if mode(t, g.root, apply.TxnBinary(txnID)) != 0o700 || mode(t, g.root, apply.TxnStatePath) != 0o600 || mode(t, g.root, apply.TxnDir(txnID)) != 0o700 {
		t.Error("modes of the binary copy, the state or its directory")
	}
	// The timer command line names the transaction and the copy.
	armed := callWith(g.r, "systemd-run --quiet --collect --unit=")
	for _, want := range []string{"--unit=stackward-rollback-" + txnID, "--on-active=60s", "--timer-property=RemainAfterElapse=no", apply.TxnBinary(txnID)} {
		if !strings.Contains(armed, want) {
			t.Errorf("systemd-run lacks %q: %s", want, armed)
		}
	}
	// The timer is armed before any file is written.
	if i, k := callIndex(g.r, "systemd-run --quiet --collect --unit="), callIndex(g.r, "systemctl try-reload-or-restart"); i < 0 || k < 0 || i > k {
		t.Errorf("systemd-run at %d, the reload at %d", i, k)
	}

	// Only one transaction at a time.
	loaded := g.state(t)
	if why := loaded.Blocks(g.now); !strings.Contains(why, "only one transaction") {
		t.Errorf("blocks: %q", why)
	}
	// The applying session cannot confirm; the console session neither
	// (without --console).
	for _, s := range []apply.Session{applying, console} {
		if _, err := apply.ConfirmTxn(context.Background(), g.h, loaded, false, s, g.now); err == nil {
			t.Errorf("confirm from %+v accepted", s)
		}
	}
	if loaded.Status != apply.TxnOpen || !g.sys.Active(st.TimerUnit+".timer") {
		t.Fatal("a refused confirm changed the state or the timer")
	}
	why, err := apply.ConfirmTxn(context.Background(), g.h, loaded, false, newSession, g.now.Add(30*time.Second))
	if err != nil || !strings.Contains(why, "new SSH session") {
		t.Fatalf("confirm: %v %s", err, why)
	}
	if err := apply.UpdateJournalTxn(g.h, loaded); err != nil {
		t.Fatal(err)
	}
	if g.sys.Active(st.TimerUnit+".timer") || g.sys.Active(st.TimerUnit+".service") {
		t.Error("the timer is still active after confirm")
	}
	after := g.state(t)
	if after.Status != apply.TxnConfirmed || after.ConfirmedVia != apply.ViaSSH || after.ConfirmSession == nil || after.Blocks(g.now) != "" {
		t.Errorf("after confirm: %+v", after)
	}
	if !g.exists(txntest.GoodPath) || g.exists(apply.TxnBinary(txnID)) {
		t.Error("confirm must keep the change and remove the binary copy")
	}
	jj, err := apply.LoadJournal(g.h, txnID)
	if err != nil || jj.Transaction.Status != apply.TxnConfirmed || jj.Transaction.ConfirmedVia != apply.ViaSSH {
		t.Errorf("journal after confirm: %v %+v", err, jj.Transaction)
	}
	validateAgainst(t, "schema/transaction.v1.json", filepath.Join(g.root, apply.TxnStatePath))
	validateAgainst(t, "schema/journal.v1.json", filepath.Join(g.root, apply.JournalPath(txnID)))
}

// open -> rolled-back (timer) -> acked. The rollback needs no session: it
// is the journal and the state, run by the timer.
func TestTimerRollbackBlocksUntilAcknowledged(t *testing.T) {
	g := newTxnRig(t)
	if _, _, err := g.start(t, txntest.GoodID); err != nil {
		t.Fatal(err)
	}
	g.now = g.now.Add(time.Minute)
	st := g.state(t)
	if _, err := apply.ConfirmTxn(context.Background(), g.h, st, true, console, g.now); err == nil || !strings.Contains(err.Error(), "deadline") {
		t.Errorf("confirm after the deadline: %v", err)
	}
	j, err := apply.LoadJournal(g.h, txnID)
	if err != nil {
		t.Fatal(err)
	}
	g.r.Reset()
	if err := apply.RollBack(context.Background(), g.h, j, st, apply.CauseTimer, apply.UndoOptions{Host: g.h, Now: g.clock}); err != nil {
		t.Fatal(err)
	}
	if g.exists(txntest.GoodPath) {
		t.Error("the rollback left the drop-in")
	}
	if got := callWith(g.r, "systemctl try-reload-or-restart"); got == "" {
		t.Error("the rollback did not reload ssh")
	}
	st = g.state(t)
	if st.Status != apply.TxnRolledBack || st.Cause != apply.CauseTimer || st.AckedAt != "" {
		t.Errorf("after the timer: %+v", st)
	}
	if why := st.Blocks(g.now); !strings.Contains(why, "--ack-rollback "+txnID) {
		t.Errorf("blocks: %q", why)
	}
	if err := apply.AckRollback(g.h, st, g.now); err != nil {
		t.Fatal(err)
	}
	st = g.state(t)
	if st.AckedAt == "" || st.Blocks(g.now) != "" || g.exists(apply.TxnBinary(txnID)) {
		t.Errorf("after ack: %+v", st)
	}
	j, _ = apply.LoadJournal(g.h, txnID)
	if j.Status != apply.RunUndone || j.Transaction.Status != apply.TxnRolledBack || j.Transaction.Cause != apply.CauseTimer {
		t.Errorf("journal %s %+v", j.Status, j.Transaction)
	}
	validateAgainst(t, "schema/transaction.v1.json", filepath.Join(g.root, apply.TxnStatePath))
	// A second rollback (the timer firing after a confirm or twice) finds
	// nothing: AckRollback on a confirmed transaction refuses.
	if err := apply.AckRollback(g.h, &apply.Txn{ID: txnID, Status: apply.TxnConfirmed}, g.now); err == nil {
		t.Error("ack of a confirmed transaction")
	}
}

func TestValidationFailureRollsBackAtOnce(t *testing.T) {
	g := newTxnRig(t)
	_, st, err := g.start(t, txntest.BadID)
	if err == nil || !strings.Contains(err.Error(), "validation failed") || !strings.Contains(err.Error(), "sshd -t") {
		t.Fatalf("err %v", err)
	}
	if st.Status != apply.TxnRolledBack || st.Cause != apply.CauseValidation || st.AckedAt == "" || st.Blocks(g.now) != "" {
		t.Errorf("state %+v", st)
	}
	if g.exists(txntest.BadPath) || g.sys.Active(st.TimerUnit+".timer") || g.exists(apply.TxnBinary(txnID)) {
		t.Error("the bad drop-in, the timer or the binary copy is still there")
	}
}

// The step's own setting must be in effect: a drop-in read before ours
// that sets the same key makes the validation fail.
func TestValidationChecksTheEffectiveSSHDValues(t *testing.T) {
	g := newTxnRig(t)
	applytest.Write(t, g.root, "/etc/ssh/sshd_config.d/00-other.conf", "LoginGraceTime 30\n", 0o644)
	_, st, err := g.start(t, txntest.GoodID)
	if err == nil || !strings.Contains(err.Error(), `logingracetime "30"`) {
		t.Fatalf("err %v", err)
	}
	if st.Status != apply.TxnRolledBack || g.exists(txntest.GoodPath) {
		t.Errorf("state %+v", st)
	}
}

func TestValidationChecksTheListeners(t *testing.T) {
	g := newTxnRig(t)
	ctx := context.Background()
	steps := mustSelect(t, g.p, []string{txntest.GoodID}, false)
	prepared, _ := apply.Prepare(g.h, steps)
	base, err := apply.Preflight(ctx, g.h)
	if err != nil {
		t.Fatal(err)
	}
	g.sys.Listening = nil // sshd stops listening during the change
	o := options(g.h, txnID)
	_, st, err := apply.RunTransaction(ctx, prepared, apply.TxnOptions{Options: o, ConfirmWithin: time.Minute, Session: applying, Exe: applytest.Exe, Baseline: base})
	if err == nil || !strings.Contains(err.Error(), "nothing listens on port 22") || st.Status != apply.TxnRolledBack {
		t.Errorf("err %v, state %+v", err, st)
	}
}

func TestPreflightRefusesBeforeAnyChange(t *testing.T) {
	g := newTxnRig(t)
	g.sys.Listening = []string{"80"}
	if _, err := apply.Preflight(context.Background(), g.h); err == nil || !strings.Contains(err.Error(), "nothing listens on sshd's port 22") {
		t.Errorf("not listening: %v", err)
	}
	g.sys.Listening = []string{"22"}
	applytest.Write(t, g.root, "/etc/ssh/sshd_config.d/00-broken.conf", "LoginGraceTime soon\n", 0o644)
	if _, err := apply.Preflight(context.Background(), g.h); err == nil || !strings.Contains(err.Error(), "before any change") {
		t.Errorf("broken sshd: %v", err)
	}
	if g.exists("/var") {
		t.Error("preflight wrote something")
	}
}

func TestApplyFailureRollsBackAtOnce(t *testing.T) {
	g := newTxnRig(t)
	g.r.Exit["systemctl"] = 1 // the reload fails, and so does every systemctl
	_, st, err := g.start(t, txntest.GoodID)
	if err == nil || st == nil {
		t.Fatalf("err %v state %+v", err, st)
	}
	// systemctl fails, so the arming check fails first: nothing changed.
	if st.Status != apply.TxnAborted || g.exists(txntest.GoodPath) {
		t.Errorf("state %+v", st)
	}
	// Only the reload fails: the step fails after its file was written.
	g = newTxnRig(t)
	sys := g.sys
	g.r.Respond = func(args []string) (apply.CmdResult, bool) {
		if len(args) > 1 && args[1] == "try-reload-or-restart" {
			return apply.CmdResult{ExitCode: 1, Output: []byte("reload refused by the test")}, true
		}
		return sys.Respond(args)
	}
	_, st, err = g.start(t, txntest.GoodID)
	if err == nil || st.Status != apply.TxnRollbackFailed {
		// The undo runs the same reload, which fails again.
		t.Errorf("err %v state %+v", err, st)
	}
	if g.exists(txntest.GoodPath) {
		t.Error("the file stayed after the rollback")
	}
	if why := st.Blocks(g.now); !strings.Contains(why, "--ack-rollback") {
		t.Errorf("a failed rollback must block: %q", why)
	}
}

func TestArmFailureChangesNothing(t *testing.T) {
	g := newTxnRig(t)
	g.sys.FailArm = true
	j, st, err := g.start(t, txntest.GoodID)
	if err == nil || j != nil || st.Status != apply.TxnAborted || st.Blocks(g.now) != "" {
		t.Fatalf("err %v journal %v state %+v", err, j, st)
	}
	if g.exists(txntest.GoodPath) || g.exists(apply.RunDir(txnID)) || g.exists(apply.TxnBinary(txnID)) {
		t.Error("an aborted transaction changed something")
	}
}

// A copy of the binary that systemd cannot start (a noexec mount) is
// found before anything changes.
func TestBinaryThatCannotRunAsAServiceChangesNothing(t *testing.T) {
	g := newTxnRig(t)
	g.sys.FailProve = true
	j, st, err := g.start(t, txntest.GoodID)
	if err == nil || !strings.Contains(err.Error(), "does not start as a systemd service") || j != nil || st != nil {
		t.Fatalf("err %v journal %v state %+v", err, j, st)
	}
	if g.exists(txntest.GoodPath) || g.exists(apply.TxnStatePath) || g.exists(apply.TxnBinary(txnID)) {
		t.Error("something changed")
	}
}

func TestTransactionNeedsTheBinaryAndABoundedDeadline(t *testing.T) {
	g := newTxnRig(t)
	steps := mustSelect(t, g.p, []string{txntest.GoodID}, false)
	prepared, _ := apply.Prepare(g.h, steps)
	o := options(g.h, txnID)
	if _, _, err := apply.RunTransaction(context.Background(), prepared, apply.TxnOptions{Options: o, ConfirmWithin: time.Second, Exe: applytest.Exe}); err == nil {
		t.Error("a one second deadline was accepted")
	}
	if _, _, err := apply.RunTransaction(context.Background(), prepared, apply.TxnOptions{Options: o, ConfirmWithin: time.Minute, Exe: "/nowhere/stackward"}); err == nil {
		t.Error("a missing binary was accepted")
	}
	if g.exists(txntest.GoodPath) || g.exists(apply.TxnStatePath) {
		t.Error("a refused transaction changed something")
	}
}

func TestLoadTxnRefusesAForeignState(t *testing.T) {
	g := newTxnRig(t)
	if st, err := apply.LoadTxn(g.h); st != nil || err != nil {
		t.Errorf("no state: %v %v", st, err)
	}
	for _, body := range []string{`{"schema":"other"}`, `{"schema":"stackward.transaction.v1","id":"../x"}`, `{"schema":"stackward.transaction.v1","id":"` + txnID + `","extra":1}`} {
		applytest.Write(t, g.root, apply.TxnStatePath, body, 0o600)
		if _, err := apply.LoadTxn(g.h); err == nil {
			t.Errorf("accepted %s", body)
		}
	}
}

func TestRunLockWaitRetries(t *testing.T) {
	g := newTxnRig(t)
	release, err := apply.AcquireRunLock(g.h, "an apply")
	if err != nil {
		t.Skipf("locking: %v", err)
	}
	slept := 0
	got, err := apply.AcquireRunLockWait(g.h, "rollback", time.Minute, time.Second, func(time.Duration) {
		slept++
		if slept == 3 {
			_ = release()
		}
	})
	if err != nil || slept != 3 {
		t.Fatalf("err %v after %d sleeps", err, slept)
	}
	_ = got()
	// Held for longer than the wait: refused with the holder.
	release, _ = apply.AcquireRunLock(g.h, "a stuck apply")
	defer func() { _ = release() }()
	slept = 0
	if _, err := apply.AcquireRunLockWait(g.h, "rollback", 5*time.Second, time.Second, func(time.Duration) { slept++ }); !apply.IsHeld(err) || slept != 5 {
		t.Errorf("err %v after %d sleeps", err, slept)
	}
}

func callWith(r *applytest.Runner, prefix string) string {
	for _, c := range r.Calls() {
		if s := strings.Join(c, " "); strings.HasPrefix(s, prefix) && s != "systemd-run --version" {
			return s
		}
	}
	return ""
}

func callIndex(r *applytest.Runner, prefix string) int {
	for i, c := range r.Calls() {
		if s := strings.Join(c, " "); strings.HasPrefix(s, prefix) && s != "systemd-run --version" {
			return i
		}
	}
	return -1
}

func validateAgainst(t *testing.T, schemaPath, file string) {
	t.Helper()
	schema, err := os.ReadFile(applytest.RepoPath(schemaPath))
	if err != nil {
		t.Fatal(err)
	}
	b, err := os.ReadFile(file)
	if err != nil {
		t.Fatal(err)
	}
	if !json.Valid(b) {
		t.Fatalf("%s is not JSON", file)
	}
	for _, e := range schemacheck.Validate(schema, b) {
		t.Errorf("%s does not match %s: %v", filepath.Base(file), schemaPath, e)
	}
}
