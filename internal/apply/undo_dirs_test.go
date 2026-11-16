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
)

// Undo removes the folders apply created for a new file, while they are
// empty, so a rolled back step leaves no empty /etc/fail2ban/jail.d behind
// (seen in the v0.2.0-rc.1 VPS test).

const f2bInstallRun = "20260301T120000Z-f2f2f2"

// f2bTxn runs the fail2ban-sshd step of the install fixture (empty lists:
// apt-get update, then the install) as a transaction.
func f2bTxn(t *testing.T, h apply.Host) (*apply.Journal, *apply.Txn, error) {
	t.Helper()
	ctx := context.Background()
	p := applytest.FixturePlan(t, "plan-updates-fail2ban-install")
	steps := mustSelect(t, p, []string{"fail2ban-sshd"}, false)
	prepared, err := apply.Prepare(h, steps)
	if err != nil {
		t.Fatal(err)
	}
	base, err := apply.Preflight(ctx, h)
	if err != nil {
		t.Fatal(err)
	}
	o := options(h, f2bInstallRun)
	return apply.RunTransaction(ctx, prepared, apply.TxnOptions{
		Options: o, ConfirmWithin: time.Minute, Session: applying, Exe: applytest.Exe, Baseline: base,
	})
}

func exists(root, p string) bool {
	_, err := os.Lstat(filepath.Join(root, p))
	return err == nil
}

// The install worked but the configuration test failed: the rollback
// removes the jail, the folders the step created for it, and purges the
// package dpkg now lists.
func TestRollbackRemovesTheFoldersItCreatedAndPurgesWhatItInstalled(t *testing.T) {
	root := t.TempDir()
	h, r, _ := applytest.NewTxnHost(t, root)
	next := r.Respond
	r.Respond = func(args []string) (apply.CmdResult, bool) {
		switch {
		case slices.Contains(args, "install") && slices.Contains(args, "fail2ban"):
			// What dpkg records once apt unpacked the package.
			applytest.Write(t, root, dpkgPath, "Package: fail2ban\nStatus: install ok installed\n", 0o644)
		case len(args) == 2 && args[0] == "fail2ban-client" && args[1] == "-t":
			return apply.CmdResult{ExitCode: 255, Output: []byte("ERROR  test failed\n")}, true
		}
		return next(args)
	}
	_, st, err := f2bTxn(t, h)
	if err == nil || st.Status != apply.TxnRolledBack {
		t.Fatalf("transaction %v %+v, want rolled-back", err, st)
	}
	for _, p := range []string{jailPath, "/etc/fail2ban/jail.d", "/etc/fail2ban"} {
		if exists(root, p) {
			t.Errorf("%s exists after the rollback", p)
		}
	}
	if callIndex(r, "env DEBIAN_FRONTEND=noninteractive apt-get -o DPkg::Lock::Timeout=120 purge -y fail2ban") < 0 {
		t.Errorf("the rollback did not purge the installed package: %v", r.Calls())
	}
}

// A folder the step created is kept when something else wrote into it
// since; an existing folder is never removed.
func TestUndoKeepsFoldersThatAreNotEmptyOrWereThere(t *testing.T) {
	root := t.TempDir()
	h, _ := applytest.NewHost(root)
	p := applytest.FixturePlan(t, "plan-host-settings-fix")
	applytest.Seed(t, root, p)
	steps := mustSelect(t, p, []string{"journald-cap"}, false)
	j, err := run(t, h, steps, "20260301T120000Z-d0d0d0")
	if err != nil {
		t.Fatal(err)
	}
	created := j.Steps[0].Files[0].CreatedDirs
	if !slices.Contains(created, "/etc/systemd/journald.conf.d") {
		t.Fatalf("created dirs %v", created)
	}
	applytest.Write(t, root, "/etc/systemd/journald.conf.d/50-owner.conf", "[Journal]\n", 0o644)
	if _, err := apply.Undo(context.Background(), j, undoOpts(h)); err != nil {
		t.Fatal(err)
	}
	if exists(root, journaldPath) || !exists(root, "/etc/systemd/journald.conf.d/50-owner.conf") {
		t.Error("undo must remove its file and keep the owner's")
	}

	// Without the owner's file the folders go, innermost first, up to the
	// first one that was there before.
	root = t.TempDir()
	h, _ = applytest.NewHost(root)
	applytest.Seed(t, root, p)
	applytest.Write(t, root, "/etc/hostname", "x\n", 0o644)
	j, err = run(t, h, steps, "20260301T120000Z-d1d1d1")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := apply.Undo(context.Background(), j, undoOpts(h)); err != nil {
		t.Fatal(err)
	}
	for _, d := range j.Steps[0].Files[0].CreatedDirs {
		if exists(root, d) {
			t.Errorf("%s, created by the step, is still there", d)
		}
	}
	if !exists(root, "/etc") {
		t.Error("undo removed /etc, which was there before")
	}
}

// A hand edited journal cannot point undo at a folder that is not a
// parent of the file it created.
func TestUndoRefusesCreatedDirsOutsideTheFile(t *testing.T) {
	root := t.TempDir()
	h, _ := applytest.NewHost(root)
	p := applytest.FixturePlan(t, "plan-host-settings-fix")
	applytest.Seed(t, root, p)
	j, err := run(t, h, mustSelect(t, p, []string{"journald-cap"}, false), "20260301T120000Z-d2d2d2")
	if err != nil {
		t.Fatal(err)
	}
	j.Steps[0].Files[0].CreatedDirs = []string{"/srv"}
	if _, err := apply.Undo(context.Background(), j, undoOpts(h)); err == nil || !strings.Contains(err.Error(), "not a parent") {
		t.Errorf("undo accepted a foreign folder: %v", err)
	}
}
