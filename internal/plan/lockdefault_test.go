package plan

import (
	"slices"
	"strings"
	"testing"

	"github.com/Shironex/stackward/internal/checks"
	"github.com/Shironex/stackward/internal/facts"
)

// lockInput is the cloud host after admin-user: ops is proven, and
// USR-003 warns that ubuntu is still usable.
func lockInput() Input {
	f := cloudFacts()
	addOps(f)
	return Input{Facts: f, Results: warnUSR003("user:ubuntu")}
}

func lockStepOf(t *testing.T, in Input) Step {
	t.Helper()
	out := planLockDefault(in)
	if out.Step == nil {
		t.Fatalf("no step: %+v", out)
	}
	s := complete(mustLookup(t, LockDefaultUserID), *out.Step)
	return s
}

func mustLookup(t *testing.T, id string) Generator {
	t.Helper()
	g, ok := Lookup(id)
	if !ok {
		t.Fatalf("no generator %s", id)
	}
	return g
}

func TestLockDefaultPlan(t *testing.T) {
	s := lockStepOf(t, lockInput())
	want := [][]string{
		{"usermod", "--shell", "/usr/sbin/nologin", "ubuntu"},
		{"mv", "-T", "/home/ubuntu/.ssh/authorized_keys", "/home/ubuntu/.ssh/authorized_keys.stackward-locked"},
	}
	if err := wantCommands("commands", s.Commands, want...); err != nil {
		t.Error(err)
	}
	undo := [][]string{
		{"mv", "-T", "/home/ubuntu/.ssh/authorized_keys.stackward-locked", "/home/ubuntu/.ssh/authorized_keys"},
		{"usermod", "--shell", "/bin/bash", "ubuntu"},
	}
	if err := wantCommands("undo", s.Undo.Commands, undo...); err != nil {
		t.Error(err)
	}
	if len(s.Edits) != 0 {
		t.Errorf("edits %+v", s.Edits)
	}
	if err := Authorize(s); err != nil {
		t.Errorf("Authorize refuses its own step: %v", err)
	}
	if !slices.ContainsFunc(s.Notes, func(n string) bool { return strings.Contains(n, "NOPASSWD") }) {
		t.Errorf("the NOPASSWD line that stays is not named: %v", s.Notes)
	}
	a := accessLockDefault(s)
	if !a.ApplierStays || !slices.Equal(a.Disables, []string{"ubuntu"}) || !slices.Equal(a.RemovesKeys, []string{"ubuntu"}) {
		t.Errorf("access %+v", a)
	}

	// A usable password is locked too, and unlocked by the undo.
	in := lockInput()
	in.Facts.Users.Accounts[1].PasswordStatus = "P"
	s = lockStepOf(t, in)
	if !slices.ContainsFunc(s.Commands, func(c Command) bool { return slices.Equal(c.Args, []string{"usermod", "--lock", "ubuntu"}) }) ||
		!slices.ContainsFunc(s.Undo.Commands, func(c Command) bool { return slices.Equal(c.Args, []string{"usermod", "--unlock", "ubuntu"}) }) {
		t.Errorf("password lock missing: %+v %+v", s.Commands, s.Undo.Commands)
	}
	if err := Authorize(s); err != nil {
		t.Errorf("Authorize refuses its own step: %v", err)
	}
}

func TestLockDefaultSkips(t *testing.T) {
	for name, tc := range map[string]struct {
		in   func() Input
		kind string
		want string
	}{
		// USR-003 passes when ubuntu is the only admin: locking it would
		// remove the way in.
		"ubuntu is the only admin": {in: func() Input {
			return Input{Facts: cloudFacts(), Results: []checks.Result{{ID: "USR-003", Subject: "user:ubuntu", Level: checks.Pass}}}
		}, kind: SkipPassing},
		"USR-003 unknown": {in: func() Input {
			return Input{Facts: cloudFacts(), Results: []checks.Result{{ID: "USR-003", Subject: "user:ubuntu", Level: checks.Unknown}}}
		}, kind: SkipUnknown},
		"no password status": {in: func() Input {
			in := lockInput()
			in.Facts.Users.PasswordStatusChecked = false
			return in
		}, kind: SkipUnknown, want: "passwd -S -a"},
		"an empty password": {in: func() Input {
			in := lockInput()
			in.Facts.Users.Accounts[1].PasswordStatus = "NP"
			return in
		}, kind: SkipManual, want: "USR-002"},
		"another home": {in: func() Input {
			in := lockInput()
			in.Facts.Users.Accounts[1].Home = "/srv/ubuntu"
			return in
		}, kind: SkipManual, want: "/srv/ubuntu"},
		"a keys file elsewhere": {in: func() Input {
			in := lockInput()
			in.Facts.SSH.Users[0].KeyFiles[0].Path = "/etc/ssh/keys/ubuntu"
			return in
		}, kind: SkipManual, want: "does not move"},
		"keys file not listed": {in: func() Input {
			in := lockInput()
			in.Facts.SSH.Users = in.Facts.SSH.Users[1:]
			return in
		}, kind: SkipManual, want: "do not list it"},
		"only NOPASSWD left": {in: func() Input {
			in := lockInput()
			in.Facts.Users.Accounts[1].LoginShell, in.Facts.Users.Accounts[1].Shell = false, "/usr/sbin/nologin"
			in.Facts.Users.Accounts[1].AuthorizedKeys = nil
			in.Facts.SSH.Users = in.Facts.SSH.Users[1:]
			return in
		}, kind: SkipManual, want: "never removes"},
	} {
		out := planLockDefault(tc.in())
		if out.Step != nil || out.Kind != tc.kind || !strings.Contains(out.Reason, tc.want) {
			t.Errorf("%s: %s %q, want %s containing %q", name, out.Kind, out.Reason, tc.kind, tc.want)
		}
	}
}

func TestLockDefaultAuthorizeRefusesTampering(t *testing.T) {
	in := lockInput()
	in.Facts.Users.Accounts[1].PasswordStatus = "P"
	base := lockStepOf(t, in)
	for name, tamper := range map[string]func(s *Step){
		"lock root":            func(s *Step) { s.Commands[0].Args[3] = "root" },
		"lock the admin":       func(s *Step) { s.Commands[1].Args[2] = "ops" },
		"move root's keys":     func(s *Step) { s.Commands[2].Args[2] = "/root/.ssh/authorized_keys" },
		"move another file":    func(s *Step) { s.Commands[2].Args[2] = "/home/ubuntu/.bashrc" },
		"move to another name": func(s *Step) { s.Commands[2].Args[3] = "/home/ubuntu/.ssh/gone" },
		"undo sets a shell":    func(s *Step) { s.Undo.Commands[2].Args[2] = "/tmp/x" },
		"undo shell climbs":    func(s *Step) { s.Undo.Commands[2].Args[2] = "/bin/../tmp/sh" },
		"no undo of the lock":  func(s *Step) { s.Undo.Commands = slices.Delete(s.Undo.Commands, 1, 2) },
		"reordered": func(s *Step) {
			s.Commands[0], s.Commands[2] = s.Commands[2], s.Commands[0]
		},
		"deletes the account": func(s *Step) { s.Commands = append(s.Commands, Command{Args: []string{"userdel", "ubuntu"}}) },
		"a file edit": func(s *Step) {
			s.Edits = []FileEdit{newEdit("/etc/sudoers.d/90-cloud-init-users", Create, "0440", "", "x\n")}
		},
	} {
		s := cloneStep(base)
		tamper(&s)
		if err := Authorize(s); err == nil {
			t.Errorf("%s: Authorize accepted it", name)
		}
	}
}

func TestLockDefaultPinAndCheck(t *testing.T) {
	s := lockStepOf(t, lockInput())
	host := fakeReader{"/etc/passwd": passwdBefore, "/home/ubuntu/.ssh/authorized_keys": fakeKey}
	if err := Pin(host, s); err != nil {
		t.Fatalf("pin: %v", err)
	}
	if applied, _, err := Check(host, s); applied || err != nil {
		t.Fatalf("check before: %v %v", applied, err)
	}
	for name, r := range map[string]fakeReader{
		"shell changed since": {"/etc/passwd": strings.Replace(passwdBefore, "ubuntu:/bin/bash", "ubuntu:/bin/zsh", 1), "/home/ubuntu/.ssh/authorized_keys": fakeKey},
		"half locked":         {"/etc/passwd": passwdBefore, "/home/ubuntu/.ssh/authorized_keys.stackward-locked": fakeKey},
		"locked name taken":   {"/etc/passwd": passwdBefore, "/home/ubuntu/.ssh/authorized_keys": fakeKey, "/home/ubuntu/.ssh/authorized_keys.stackward-locked": ""},
		"account gone":        {"/etc/passwd": "root:x:0:0:root:/root:/bin/bash\n", "/home/ubuntu/.ssh/authorized_keys": fakeKey},
	} {
		if err := Pin(r, s); err == nil {
			t.Errorf("%s: pin accepted it", name)
		}
	}
	done := fakeReader{
		"/etc/passwd": strings.Replace(passwdBefore, "ubuntu:/bin/bash", "ubuntu:/usr/sbin/nologin", 1),
		"/home/ubuntu/.ssh/authorized_keys.stackward-locked": fakeKey,
	}
	if applied, _, err := Check(done, s); !applied || err != nil {
		t.Errorf("check after: %v %v", applied, err)
	}
}

// The lockout guard on the lock step: the applying account must be the
// proven admin account, never the account it locks, never unknown.
func TestLockDefaultGuard(t *testing.T) {
	s := lockStepOf(t, lockInput())
	live := lockInput().Facts
	for name, tc := range map[string]struct {
		applier string
		facts   func(f *facts.Facts)
		want    string
	}{
		"applied by ops":            {applier: "ops"},
		"applied by ubuntu":         {applier: "ubuntu", want: "it would disable ubuntu, the account applying it"},
		"applier unknown":           {applier: "", want: "the account applying it is unknown"},
		"applied by root":           {applier: "root", want: "root, the account applying it, is not a proven second way in"},
		"ops has no key":            {applier: "ops", facts: func(f *facts.Facts) { f.SSH.Users = f.SSH.Users[:1] }, want: "ops: no usable authorized key"},
		"ops has no sudo":           {applier: "ops", facts: func(f *facts.Facts) { f.Users.Sudoers = f.Users.Sudoers[:2] }, want: "ops: no sudo rule"},
		"ubuntu holds the only key": {applier: "ops", facts: func(f *facts.Facts) { f.SSH.Users = f.SSH.Users[:1] }, want: "no usable authorized key"},
	} {
		f := cloneGuardFacts(live)
		if tc.facts != nil {
			tc.facts(f)
		}
		_, err := ProveAccess(s, GuardInput{Facts: f, Applier: tc.applier, Source: homeAddr})
		switch {
		case tc.want == "" && err != nil:
			t.Errorf("%s: refused: %v", name, err)
		case tc.want != "" && (err == nil || !strings.Contains(err.Error(), tc.want)):
			t.Errorf("%s: %v, want %q", name, err, tc.want)
		}
	}
	// The plan time veto refuses it the same way.
	p := Build(lockInput(), testReport(), Options{Version: "test", Vetoes: []Veto{LockoutVeto(GuardInput{Facts: live})}})
	if !slices.ContainsFunc(p.Skipped, func(sk Skipped) bool { return sk.ID == LockDefaultUserID && sk.Kind == SkipRefused }) {
		t.Errorf("plan without a known applier must refuse the lock: %+v", p.Skipped)
	}
}

// cloneGuardFacts copies the parts of f the guard tests change.
func cloneGuardFacts(f *facts.Facts) *facts.Facts {
	c := *f
	ssh := *f.SSH
	ssh.Users = slices.Clone(f.SSH.Users)
	c.SSH = &ssh
	u := *f.Users
	u.Accounts = slices.Clone(f.Users.Accounts)
	u.Sudoers = slices.Clone(f.Users.Sudoers)
	c.Users = &u
	return &c
}
