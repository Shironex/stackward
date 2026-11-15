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
	"github.com/Shironex/stackward/internal/facts"
	"github.com/Shironex/stackward/internal/plan"
)

// The account and sshd steps against a t.TempDir() root. accountSystem
// plays useradd, userdel, usermod, install and mv on the files under the
// root, so a test can see what the step leaves and what undo restores;
// systemd, sshd and ss come from applytest.System as in the transaction
// tests. No program starts.

const (
	passwdBefore = "root:x:0:0:root:/root:/bin/bash\nubuntu:x:1000:1000:Ubuntu:/home/ubuntu:/bin/bash\n"
	groupBefore  = "root:x:0:\nsudo:x:27:ubuntu\nubuntu:x:1000:\n"
	// keyMaterial stands for a public key; it must never reach a plan,
	// a journal or the output.
	keyMaterial = "ssh-ed25519 AAAA-stands-for-key-material owner@example.com\n"
	sudoersOps  = "/etc/sudoers.d/90-stackward-ops"
	sshdDropin  = "/etc/ssh/sshd_config.d/00-stackward-hardening.conf"
)

type accountRig struct {
	root string
	h    apply.Host
	r    *applytest.Runner
	sys  *applytest.System
}

func newAccountRig(t *testing.T) *accountRig {
	t.Helper()
	root := t.TempDir()
	h, r, sys := applytest.NewTxnHost(t, root)
	g := &accountRig{root: root, h: h, r: r, sys: sys}
	r.Respond = func(args []string) (apply.CmdResult, bool) {
		if res, ok := g.account(t, args); ok {
			return res, true
		}
		return sys.Respond(args)
	}
	applytest.Write(t, root, "/etc/passwd", passwdBefore, 0o644)
	applytest.Write(t, root, "/etc/group", groupBefore, 0o644)
	applytest.Write(t, root, "/home/ubuntu/.ssh/authorized_keys", keyMaterial, 0o600)
	return g
}

func (g *accountRig) path(p string) string { return filepath.Join(g.root, filepath.FromSlash(p)) }

func (g *accountRig) read(t *testing.T, p string) string {
	t.Helper()
	s, _ := applytest.Read(t, g.root, p)
	return s
}

// account plays the account commands on the files under the root.
func (g *accountRig) account(t *testing.T, a []string) (apply.CmdResult, bool) {
	t.Helper()
	ok := apply.CmdResult{}
	switch {
	case a[0] == "useradd":
		name := a[len(a)-1]
		g.appendTo(t, "/etc/passwd", name+":x:1001:1001::/home/"+name+":/bin/bash\n")
		g.appendTo(t, "/etc/group", name+":x:1001:\n")
		g.mkdir(t, "/home/"+name)
	case a[0] == "userdel":
		name := a[len(a)-1]
		g.dropLines(t, "/etc/passwd", name+":")
		g.dropLines(t, "/etc/group", name+":")
		if err := os.RemoveAll(g.path("/home/" + name)); err != nil {
			t.Fatal(err)
		}
	case a[0] == "install" && a[1] == "-d":
		g.mkdir(t, a[len(a)-1])
	case a[0] == "install":
		applytest.Write(t, g.root, a[len(a)-1], g.read(t, a[len(a)-2]), 0o600)
	case a[0] == "usermod" && a[1] == "--shell":
		b := g.read(t, "/etc/passwd")
		var out []string
		for _, line := range strings.SplitAfter(b, "\n") {
			if strings.HasPrefix(line, a[3]+":") {
				f := strings.Split(strings.TrimSuffix(line, "\n"), ":")
				f[6] = a[2]
				line = strings.Join(f, ":") + "\n"
			}
			out = append(out, line)
		}
		applytest.Write(t, g.root, "/etc/passwd", strings.Join(out, ""), 0o644)
	case a[0] == "usermod":
	case a[0] == "mv":
		if err := os.Rename(g.path(a[2]), g.path(a[3])); err != nil {
			return apply.CmdResult{ExitCode: 1, Output: []byte(err.Error())}, true
		}
	case a[0] == "visudo", len(a) == 4 && a[0] == "sshd" && a[1] == "-t" && a[2] == "-f":
	default:
		return ok, false
	}
	return ok, true
}

func (g *accountRig) appendTo(t *testing.T, p, line string) {
	t.Helper()
	applytest.Write(t, g.root, p, g.read(t, p)+line, 0o644)
}

func (g *accountRig) dropLines(t *testing.T, p, prefix string) {
	t.Helper()
	var keep []string
	for _, line := range strings.SplitAfter(g.read(t, p), "\n") {
		if !strings.HasPrefix(line, prefix) {
			keep = append(keep, line)
		}
	}
	applytest.Write(t, g.root, p, strings.Join(keep, ""), 0o644)
}

func (g *accountRig) mkdir(t *testing.T, p string) {
	t.Helper()
	if err := os.MkdirAll(g.path(p), 0o750); err != nil {
		t.Fatal(err)
	}
}

// transaction runs step id of fixture plan name as apply does.
func (g *accountRig) transaction(t *testing.T, name, id string) (*apply.Journal, *apply.Txn, error) {
	t.Helper()
	ctx := context.Background()
	p := applytest.FixturePlan(t, name)
	steps := mustSelect(t, p, []string{id}, false)
	prepared, err := apply.Prepare(g.h, steps)
	if err != nil {
		t.Fatalf("prepare: %v", err)
	}
	base, err := apply.Preflight(ctx, g.h)
	if err != nil {
		t.Fatal(err)
	}
	return apply.RunTransaction(ctx, prepared, apply.TxnOptions{
		Options: options(g.h, txnID), ConfirmWithin: time.Minute, Session: applying, Exe: applytest.Exe, Baseline: base,
	})
}

func (g *accountRig) rollBack(t *testing.T, j *apply.Journal, txn *apply.Txn) {
	t.Helper()
	if err := apply.RollBack(context.Background(), g.h, j, txn, apply.CauseManual, apply.UndoOptions{Host: g.h, Now: func() time.Time { return fixedNow }}); err != nil {
		t.Fatalf("roll back: %v", err)
	}
}

// noKeyMaterial fails when the key reached the journal or the plan.
func (g *accountRig) noKeyMaterial(t *testing.T, j *apply.Journal) {
	t.Helper()
	b, err := os.ReadFile(g.path(apply.JournalPath(j.RunID)))
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(b), "stands-for-key-material") {
		t.Error("the journal holds key material")
	}
}

func prepared(t *testing.T, h apply.Host, name, id string) apply.Prepared {
	t.Helper()
	p := applytest.FixturePlan(t, name)
	out, err := apply.Prepare(h, mustSelect(t, p, []string{id}, false))
	if err != nil {
		t.Fatalf("prepare: %v", err)
	}
	return out[0]
}

func TestAdminUserTransactionAppliedTwiceAndRolledBack(t *testing.T) {
	g := newAccountRig(t)
	j, txn, err := g.transaction(t, "plan-accounts-create", plan.AdminUserID)
	if err != nil {
		t.Fatalf("transaction: %v", err)
	}
	if txn.Status != apply.TxnOpen {
		t.Fatalf("status %s", txn.Status)
	}
	if fi, err := os.Stat(g.path(sudoersOps)); err != nil || fi.Mode().Perm() != 0o440 {
		t.Errorf("sudoers drop-in: %v %v", fi, err)
	}
	if !strings.Contains(g.read(t, "/etc/passwd"), "\nops:") || g.read(t, "/home/ops/.ssh/authorized_keys") != keyMaterial {
		t.Errorf("the account or its keys are missing:\n%s", g.read(t, "/etc/passwd"))
	}
	if callWith(g.r, "visudo -c -f "+g.path("/etc/sudoers.d")) == "" {
		t.Errorf("the staged drop-in was not checked with visudo: %v", g.r.Calls())
	}
	g.noKeyMaterial(t, j)
	// Applied twice: the second run finds it in place.
	if p := prepared(t, g.h, "plan-accounts-create", plan.AdminUserID); !p.Applied {
		t.Error("a second apply would run the step again")
	}
	// The rollback deletes exactly what the step created.
	g.rollBack(t, j, txn)
	if _, err := os.Stat(g.path(sudoersOps)); !os.IsNotExist(err) {
		t.Errorf("the sudoers drop-in is still there: %v", err)
	}
	if g.read(t, "/etc/passwd") != passwdBefore || g.read(t, "/etc/group") != groupBefore {
		t.Errorf("the account files are not as before:\n%s%s", g.read(t, "/etc/passwd"), g.read(t, "/etc/group"))
	}
	if _, err := os.Stat(g.path("/home/ops")); !os.IsNotExist(err) {
		t.Errorf("the home is still there: %v", err)
	}
	if callWith(g.r, "userdel --remove ops") == "" {
		t.Error("the undo did not delete the account")
	}
}

func TestAdminUserRefusesAnAccountItDidNotCreate(t *testing.T) {
	g := newAccountRig(t)
	g.mkdir(t, "/home/ops")
	p := applytest.FixturePlan(t, "plan-accounts-create")
	if _, err := apply.Prepare(g.h, mustSelect(t, p, []string{plan.AdminUserID}, false)); err == nil || !strings.Contains(err.Error(), "/home/ops exists") {
		t.Errorf("an existing home must be refused, its undo would delete it: %v", err)
	}
	g = newAccountRig(t)
	g.appendTo(t, "/etc/passwd", "ops:x:1001:1001::/srv/ops:/bin/sh\n")
	if _, err := apply.Prepare(g.h, mustSelect(t, p, []string{plan.AdminUserID}, false)); err == nil || !strings.Contains(err.Error(), "exists now") {
		t.Errorf("an existing account must be refused: %v", err)
	}
}

func TestLockDefaultUserAppliedTwiceAndUndone(t *testing.T) {
	g := newAccountRig(t)
	ctx := context.Background()
	p := prepared(t, g.h, "plan-accounts-lock", plan.LockDefaultUserID)
	if p.Applied {
		t.Fatal("applied before it ran")
	}
	j, err := apply.Execute(ctx, []apply.Prepared{p}, options(g.h, txnID))
	if err != nil {
		t.Fatalf("execute: %v", err)
	}
	if !strings.Contains(g.read(t, "/etc/passwd"), "ubuntu:x:1000:1000:Ubuntu:/home/ubuntu:/usr/sbin/nologin\n") {
		t.Errorf("shell not changed:\n%s", g.read(t, "/etc/passwd"))
	}
	if _, err := os.Stat(g.path("/home/ubuntu/.ssh/authorized_keys")); !os.IsNotExist(err) {
		t.Error("the keys are still in place")
	}
	g.noKeyMaterial(t, j)
	if p := prepared(t, g.h, "plan-accounts-lock", plan.LockDefaultUserID); !p.Applied {
		t.Error("a second apply would run the step again")
	}
	if _, err := apply.Undo(ctx, j, apply.UndoOptions{Host: g.h}); err != nil {
		t.Fatalf("undo: %v", err)
	}
	if g.read(t, "/etc/passwd") != passwdBefore || g.read(t, "/home/ubuntu/.ssh/authorized_keys") != keyMaterial {
		t.Errorf("undo did not restore exactly:\n%s", g.read(t, "/etc/passwd"))
	}
	if _, err := os.Stat(g.path("/home/ubuntu/.ssh/authorized_keys.stackward-locked")); !os.IsNotExist(err) {
		t.Error("the locked name is left behind")
	}
}

func TestSSHDHardeningTransactionAppliedTwiceAndRolledBack(t *testing.T) {
	g := newAccountRig(t)
	j, txn, err := g.transaction(t, "plan-accounts-create", plan.SSHDHardeningID)
	if err != nil {
		t.Fatalf("transaction: %v", err)
	}
	if txn.Status != apply.TxnOpen {
		t.Fatalf("status %s", txn.Status)
	}
	if callWith(g.r, "sshd -t -f "+g.path("/etc/ssh/sshd_config.d")) == "" {
		t.Errorf("the staged drop-in was not checked with sshd -t -f: %v", g.r.Calls())
	}
	if callWith(g.r, "systemctl try-reload-or-restart ssh.service") == "" {
		t.Error("ssh.service was not reloaded")
	}
	if p := prepared(t, g.h, "plan-accounts-create", plan.SSHDHardeningID); !p.Applied {
		t.Error("a second apply would run the step again")
	}
	g.rollBack(t, j, txn)
	if _, err := os.Stat(g.path(sshdDropin)); !os.IsNotExist(err) {
		t.Errorf("the drop-in is still there: %v", err)
	}
}

// A drop-in whose settings sshd -T does not show (an earlier file wins)
// rolls back at once.
func TestSSHDHardeningRollsBackWhenAnEarlierFileWins(t *testing.T) {
	g := newAccountRig(t)
	applytest.Write(t, g.root, "/etc/ssh/sshd_config.d/00-aaa.conf", "PasswordAuthentication yes\n", 0o644)
	_, txn, err := g.transaction(t, "plan-accounts-create", plan.SSHDHardeningID)
	if err == nil || !strings.Contains(err.Error(), "passwordauthentication") {
		t.Fatalf("want a validation failure naming passwordauthentication: %v", err)
	}
	if txn.Status != apply.TxnRolledBack || txn.Cause != apply.CauseValidation {
		t.Errorf("state %s/%s", txn.Status, txn.Cause)
	}
	if _, err := os.Stat(g.path(sshdDropin)); !os.IsNotExist(err) {
		t.Error("the drop-in was kept")
	}
}

func TestAccountStepsTamperedAreRefused(t *testing.T) {
	create := applytest.FixturePlan(t, "plan-accounts-create")
	lock := applytest.FixturePlan(t, "plan-accounts-lock")
	for name, tc := range map[string]struct {
		s      plan.Step
		tamper func(s *plan.Step)
	}{
		"admin keys from root": {applytest.Step(t, create, plan.AdminUserID), func(s *plan.Step) { s.Commands[2].Args[7] = "/root/.ssh/authorized_keys" }},
		"admin rule for everyone": {applytest.Step(t, create, plan.AdminUserID), func(s *plan.Step) {
			s.Edits[0].New = "ALL ALL=(ALL:ALL) NOPASSWD: ALL\n"
			s.Edits[0].NewSHA256 = plan.SHA256([]byte(s.Edits[0].New))
		}},
		"lock the admin":          {applytest.Step(t, lock, plan.LockDefaultUserID), func(s *plan.Step) { s.Commands[0].Args[3] = "ops" }},
		"lock with a new shell":   {applytest.Step(t, lock, plan.LockDefaultUserID), func(s *plan.Step) { s.Undo.Commands[1].Args[2] = "/tmp/sh" }},
		"sshd without validation": {applytest.Step(t, create, plan.SSHDHardeningID), func(s *plan.Step) { s.Edits[0].Validate = nil }},
	} {
		s := clone(tc.s)
		tc.tamper(&s)
		g := newAccountRig(t)
		if _, err := apply.Prepare(g.h, []plan.Step{s}); err == nil {
			t.Errorf("%s: prepare accepted it", name)
		}
	}
}

// liveLockFacts are the facts of the lock fixture, as the guard would read
// them from the live host.
func liveLockFacts(t *testing.T) *facts.Facts {
	t.Helper()
	fh, err := os.Open(applytest.RepoPath("test/fixtures/plan-accounts-lock/facts.json"))
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = fh.Close() }()
	f, err := facts.Load(fh)
	if err != nil {
		t.Fatal(err)
	}
	return f
}

// The guard on the live host: the lock runs only from a session of the
// admin account that stays, never from the account it locks.
func TestGuardRefusesTheLockFromTheWrongSession(t *testing.T) {
	lock := applytest.Step(t, applytest.FixturePlan(t, "plan-accounts-lock"), plan.LockDefaultUserID)
	live := liveLockFacts(t)
	for name, tc := range map[string]struct {
		loginUID string
		want     string
	}{
		"as ops":     {loginUID: "1001"},
		"as ubuntu":  {loginUID: "1000", want: "it would disable ubuntu, the account applying it"},
		"as root":    {loginUID: "0", want: "root, the account applying it, is not a proven second way in"},
		"login lost": {loginUID: "", want: "the account applying it is unknown"},
	} {
		sess := applying
		sess.LoginUID = tc.loginUID
		_, err := apply.GuardAccess([]plan.Step{lock}, live, sess)
		switch {
		case tc.want == "" && err != nil:
			t.Errorf("%s: refused: %v", name, err)
		case tc.want != "" && (err == nil || !strings.Contains(err.Error(), tc.want)):
			t.Errorf("%s: %v, want %q", name, err, tc.want)
		}
	}
	// ubuntu holds the only key: nobody else logs in, so the lock is refused
	// whoever applies.
	live.SSH.Users = slices.DeleteFunc(live.SSH.Users, func(u facts.SSHUser) bool { return u.Name == "ops" })
	sess := applying
	sess.LoginUID = "1001"
	if _, err := apply.GuardAccess([]plan.Step{lock}, live, sess); err == nil || !strings.Contains(err.Error(), "ops: no usable authorized key") {
		t.Errorf("the only key holder: %v", err)
	}
}
