package apply_test

import (
	"context"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/Shironex/stackward/internal/apply"
	"github.com/Shironex/stackward/internal/apply/applytest"
	"github.com/Shironex/stackward/internal/schemacheck"
)

// What the v0.2.0-rc.1 VPS test found: on a fresh image (empty package
// lists) the fail2ban install failed, the rollback's purge failed too
// (exit 100) and the transaction ended rollback-failed. Here the install
// runs before the jail is written, a purge of a package dpkg never heard
// of counts as undone, and a rolled back step leaves no pending restart.

// failInstall makes apt-get install of pkg exit 100 ("Unable to locate
// package"), and the purge too, as apt does for a package it does not
// know. Everything else answers as before.
func failInstall(r *applytest.Runner, pkg string) {
	next := r.Respond
	r.Respond = func(args []string) (apply.CmdResult, bool) {
		if slices.Contains(args, "apt-get") && slices.Contains(args, pkg) {
			return apply.CmdResult{ExitCode: 100, Output: []byte("E: Unable to locate package " + pkg + "\n")}, true
		}
		if next != nil {
			return next(args)
		}
		return apply.CmdResult{}, false
	}
}

func TestFailedInstallRollsBackCleanly(t *testing.T) {
	root := t.TempDir()
	h, r, _ := applytest.NewTxnHost(t, root)
	failInstall(r, "fail2ban")
	j, st, err := f2bTxn(t, h)
	if err == nil || !strings.Contains(err.Error(), "Unable to locate package") {
		t.Fatalf("the install should fail the transaction: %v", err)
	}
	if st.Status != apply.TxnRolledBack {
		t.Fatalf("transaction %s (%s), want rolled-back", st.Status, st.Error)
	}
	// The update ran first, then the install; nothing after it, and no
	// purge: dpkg never heard of fail2ban.
	var apt [][]string
	for _, c := range r.Calls() {
		if slices.Contains(c, "apt-get") {
			apt = append(apt, c)
		}
	}
	if len(apt) != 2 || !slices.Contains(apt[0], "update") || !slices.Contains(apt[1], "install") {
		t.Errorf("apt calls %v, want the update then the install", apt)
	}
	if callIndex(r, "fail2ban-client") >= 0 || callIndex(r, "systemctl restart fail2ban") >= 0 {
		t.Errorf("commands after the failed install ran: %v", r.Calls())
	}
	// Nothing was written: no jail, no folder.
	for _, p := range []string{jailPath, "/etc/fail2ban/jail.d", "/etc/fail2ban"} {
		if exists(root, p) {
			t.Errorf("%s exists after the rollback", p)
		}
	}
	// The journal says what ran and why the purge did not.
	saved, err := apply.LoadJournal(h, j.RunID)
	if err != nil {
		t.Fatal(err)
	}
	js := saved.Steps[0]
	if js.RestartPending {
		t.Error("a rolled back step is still restart pending")
	}
	var kinds []string
	for _, c := range js.Commands {
		kinds = append(kinds, c.Kind)
	}
	if !slices.Equal(kinds, []string{apply.KindBefore, apply.KindBefore, apply.KindUndo}) {
		t.Errorf("journal command kinds %v", kinds)
	}
	if purge := js.Commands[len(js.Commands)-1]; !strings.Contains(purge.Skipped, "dpkg has no record of fail2ban") {
		t.Errorf("the purge is not recorded as skipped: %+v", purge)
	}
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
	if pending, _, _ := apply.FindPending(h); len(pending) != 0 {
		t.Errorf("the next apply would find pending restarts: %+v", pending)
	}
}

// A transaction whose rollback failed leaves its restart to nobody: the
// next apply must not finish it.
func TestRollbackFailedLeavesNoPendingRestart(t *testing.T) {
	root := t.TempDir()
	h, r, _ := applytest.NewTxnHost(t, root)
	p := applytest.FixturePlan(t, "plan-updates-fail2ban-jail")
	steps := mustSelect(t, p, []string{"fail2ban-sshd"}, false)
	r.Exit["systemctl"] = 0
	next := r.Respond
	r.Respond = func(args []string) (apply.CmdResult, bool) {
		if len(args) == 3 && args[0] == "systemctl" && args[1] == "reload" && args[2] == "fail2ban" {
			return apply.CmdResult{ExitCode: 1, Output: []byte("fail2ban.service is not active\n")}, true
		}
		return next(args)
	}
	ctx := context.Background()
	prepared, err := apply.Prepare(h, steps)
	if err != nil {
		t.Fatal(err)
	}
	base, err := apply.Preflight(ctx, h)
	if err != nil {
		t.Fatal(err)
	}
	j, st, err := apply.RunTransaction(ctx, prepared, apply.TxnOptions{
		Options: options(h, "20260301T120000Z-f3f3f3"), ConfirmWithin: time.Minute, Session: applying, Exe: applytest.Exe, Baseline: base,
	})
	if err == nil || st.Status != apply.TxnRollbackFailed {
		t.Fatalf("transaction %v %+v, want rollback-failed (the reload fails both ways)", err, st)
	}
	saved, err := apply.LoadJournal(h, j.RunID)
	if err != nil {
		t.Fatal(err)
	}
	if saved.Steps[0].RestartPending {
		t.Error("the restored step is still restart pending")
	}
	if pending, _, _ := apply.FindPending(h); len(pending) != 0 {
		t.Errorf("pending after a failed rollback: %+v", pending)
	}
}
