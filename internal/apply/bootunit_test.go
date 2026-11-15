package apply_test

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/Shironex/stackward/internal/apply"
	"github.com/Shironex/stackward/internal/apply/applytest"
	"github.com/Shironex/stackward/internal/plan/txntest"
)

// The boot unit: written from one template (golden below, and checked by
// systemd-analyze verify in the transaction scenario), installed with the
// timer, removed on confirm and on every rollback.

const bootLink = "/etc/systemd/system/sysinit.target.wants/stackward-boot-rollback-" + txnID + ".service"

func TestBootUnitTextGolden(t *testing.T) {
	got, err := apply.BootUnitText(txnID)
	if err != nil {
		t.Fatal(err)
	}
	golden := filepath.Join("testdata", "boot-unit.golden.service")
	if *update {
		if err := os.WriteFile(golden, []byte(got), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	want, err := os.ReadFile(golden)
	if err != nil {
		t.Fatalf("%v (run with -update)", err)
	}
	if got != string(want) {
		t.Errorf("the boot unit differs from %s (run with -update and review):\n%s", golden, got)
	}
	for _, line := range []string{
		"DefaultDependencies=no",
		"Before=ssh.service sshd.service ssh.socket sshd.socket shutdown.target",
		"ConditionPathExists=" + apply.TxnStatePath,
		"ConditionPathExists=" + apply.TxnBinary(txnID),
		"ExecStart=" + apply.TxnBinary(txnID) + " undo --transaction " + txnID + " --yes --by-boot",
		"WantedBy=sysinit.target",
	} {
		if !strings.Contains(got, "\n"+line+"\n") {
			t.Errorf("the boot unit lacks the line %q", line)
		}
	}
	if _, err := apply.BootUnitText("../etc"); err == nil {
		t.Error("a unit for a bad id")
	}
}

func TestBootUnitInstalledThenRemovedOnConfirm(t *testing.T) {
	g := newTxnRig(t)
	_, st, err := g.start(t, txntest.GoodID)
	if err != nil {
		t.Fatal(err)
	}
	if st.BootUnit != apply.BootUnit(txnID) || !g.exists(apply.BootUnitPath(txnID)) || !g.bootLinked() {
		t.Fatalf("boot unit not installed: %+v", st)
	}
	if mode(t, g.root, apply.BootUnitPath(txnID)) != 0o644 {
		t.Error("the unit file mode")
	}
	// Installed before any file is written.
	if i, k := callIndex(g.r, "systemctl enable"), callIndex(g.r, "systemctl try-reload-or-restart"); i < 0 || k < 0 || i > k {
		t.Errorf("enable at %d, the reload at %d", i, k)
	}
	// Its own open transaction is not stale.
	if why, err := apply.StaleBootUnits(g.h, g.state(t)); why != "" || err != nil {
		t.Errorf("stale: %q %v", why, err)
	}
	reloads := g.sys.Reloads
	if _, err := apply.ConfirmTxn(context.Background(), g.h, g.state(t), true, console, g.now); err != nil {
		t.Fatal(err)
	}
	if g.exists(apply.BootUnitPath(txnID)) || g.bootLinked() || g.sys.Reloads != reloads+1 {
		t.Errorf("confirm left the boot unit (reloads %d)", g.sys.Reloads-reloads)
	}
}

func TestBootUnitRemovedOnEveryRollback(t *testing.T) {
	// Validation failure.
	g := newTxnRig(t)
	if _, _, err := g.start(t, txntest.BadID); err == nil {
		t.Fatal("the bad step validated")
	}
	if g.exists(apply.BootUnitPath(txnID)) || g.bootLinked() {
		t.Error("the validation rollback left the boot unit")
	}
	// The timer, and at boot: both need an acknowledgement.
	for _, cause := range []string{apply.CauseTimer, apply.CauseBoot, apply.CauseManual} {
		g := newTxnRig(t)
		if _, _, err := g.start(t, txntest.GoodID); err != nil {
			t.Fatal(err)
		}
		j, err := apply.LoadJournal(g.h, txnID)
		if err != nil {
			t.Fatal(err)
		}
		st := g.state(t)
		if cause == apply.CauseBoot {
			// What the CLI records when the hostname differs at boot.
			st.RollbackHost, st.HostNote = "unset", "rolled back while the hostname was unset"
		}
		if err := apply.RollBack(context.Background(), g.h, j, st, cause, apply.UndoOptions{Host: g.h, Now: g.clock}); err != nil {
			t.Fatal(err)
		}
		if g.exists(apply.BootUnitPath(txnID)) || g.bootLinked() || g.exists(txntest.GoodPath) {
			t.Errorf("%s: the boot unit or the change is still there", cause)
		}
		st = g.state(t)
		needsAck := cause != apply.CauseManual
		if st.Cause != cause || (st.AckedAt == "") != needsAck {
			t.Errorf("%s: state %+v", cause, st)
		}
		validateAgainst(t, "schema/transaction.v1.json", filepath.Join(g.root, apply.TxnStatePath))
	}
}

func TestBootUnitEnableFailureChangesNothing(t *testing.T) {
	g := newTxnRig(t)
	g.sys.FailEnable = true
	j, st, err := g.start(t, txntest.GoodID)
	if err == nil || !strings.Contains(err.Error(), "enabling the boot unit") || j != nil || st.Status != apply.TxnAborted {
		t.Fatalf("err %v journal %v state %+v", err, j, st)
	}
	if g.exists(txntest.GoodPath) || g.exists(apply.BootUnitPath(txnID)) || g.sys.Active(st.TimerUnit+".timer") || g.exists(apply.TxnBinary(txnID)) {
		t.Error("an aborted transaction left something behind")
	}
}

func TestStaleBootUnits(t *testing.T) {
	g := newTxnRig(t)
	if why, err := apply.StaleBootUnits(g.h, nil); why != "" || err != nil {
		t.Errorf("no units: %q %v", why, err)
	}
	// A unit with no transaction, and a dangling link of another.
	other := "20260301T110000Z-0b0b0b"
	applytest.Write(t, g.root, apply.BootUnitPath(txnID), "[Unit]\n", 0o644)
	if err := os.MkdirAll(filepath.Join(g.root, filepath.Dir(bootLink)), 0o750); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(apply.BootUnitPath(other), filepath.Join(g.root, strings.ReplaceAll(bootLink, txnID, other))); err != nil {
		t.Fatal(err)
	}
	for _, st := range []*apply.Txn{nil, {ID: txnID, Status: apply.TxnConfirmed}, {ID: other, Status: apply.TxnOpen}} {
		why, err := apply.StaleBootUnits(g.h, st)
		if err != nil || !strings.Contains(why, "sudo rm -f") || !strings.Contains(why, "daemon-reload") {
			t.Errorf("%+v: %q %v", st, why, err)
		}
		if st == nil && (!strings.Contains(why, txnID) || !strings.Contains(why, other)) {
			t.Errorf("both units must be named: %q", why)
		}
	}
	// RemoveBootUnit cleans up both, and is quiet when nothing is there.
	for _, id := range []string{txnID, other} {
		if err := apply.RemoveBootUnit(context.Background(), g.h, id); err != nil {
			t.Fatal(err)
		}
	}
	if why, _ := apply.StaleBootUnits(g.h, nil); why != "" {
		t.Errorf("after removal: %q", why)
	}
	reloads := g.sys.Reloads
	if err := apply.RemoveBootUnit(context.Background(), g.h, txnID); err != nil || g.sys.Reloads != reloads {
		t.Errorf("removing nothing: %v, %d reloads", err, g.sys.Reloads-reloads)
	}
}

func (g *txnRig) bootLinked() bool {
	fi, err := os.Lstat(filepath.Join(g.root, bootLink))
	return err == nil && fi.Mode()&os.ModeSymlink != 0
}
