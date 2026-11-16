package plan

import (
	"errors"
	"io/fs"
	"slices"
	"strings"
	"testing"

	"github.com/Shironex/stackward/internal/checks"
	"github.com/Shironex/stackward/internal/facts"
	"github.com/Shironex/stackward/internal/facts/sshd"
)

// The account steps over fake facts: a cloud host where ubuntu (the image's
// default account, NOPASSWD sudo, an ed25519 key) is the only admin.

func cloudFacts() *facts.Facts {
	yes := true
	return &facts.Facts{
		SSH: &facts.SSH{
			Installed: true, Source: "sshd -T", Complete: true,
			Effective: map[string][]string{
				"pubkeyauthentication": {"yes"}, "authenticationmethods": {"any"}, "passwordauthentication": {"yes"},
				"kbdinteractiveauthentication": {"no"}, "permitrootlogin": {"prohibit-password"}, "permitemptypasswords": {"no"},
				"maxauthtries": {"6"}, "authorizedkeysfile": {".ssh/authorized_keys .ssh/authorized_keys2"}, "usepam": {"yes"},
				"port": {"22"}, "listenaddress": {"0.0.0.0:22", "[::]:22"},
			},
			Config: &sshd.Config{
				Files: []sshd.File{
					{Path: "/etc/ssh/sshd_config", Readable: true},
					{Path: "/etc/ssh/sshd_config.d/50-cloud-init.conf", Readable: true},
				},
				Directives: []sshd.Directive{
					{Keyword: "passwordauthentication", Value: "yes", File: "/etc/ssh/sshd_config.d/50-cloud-init.conf", Line: 1},
					{Keyword: "usepam", Value: "yes", File: "/etc/ssh/sshd_config", Line: 15},
				},
				Includes: []sshd.Include{{Pattern: "/etc/ssh/sshd_config.d/*.conf", File: "/etc/ssh/sshd_config", Line: 12}},
			},
			Users: []facts.SSHUser{{Name: "ubuntu", UID: 1000, Home: "/home/ubuntu", KeyFiles: ed25519Key("/home/ubuntu")}},
		},
		Users: &facts.Users{
			Accounts: []facts.Account{
				{Name: "root", UID: 0, Home: "/root", Shell: "/bin/bash", LoginShell: true, PasswordStatus: "L"},
				{Name: "ubuntu", UID: 1000, GID: 1000, Home: "/home/ubuntu", Shell: "/bin/bash", LoginShell: true, PasswordStatus: "L", AuthorizedKeys: &yes},
			},
			Groups: []facts.Group{{Name: "ubuntu", GID: 1000}, {Name: "sudo", GID: 27, Members: []string{"ubuntu"}}},
			Sudoers: []facts.Sudoers{
				{Path: "/etc/sudoers", Readable: true, Principals: []string{"root", "%sudo"}},
				{Path: "/etc/sudoers.d/90-cloud-init-users", Readable: true, Principals: []string{"ubuntu"}, NoPasswd: []facts.SudoRule{{Who: "ubuntu", Line: 2}}},
			},
			PasswordStatusChecked: true,
		},
		PaaS: &facts.PaaS{Platforms: []facts.Platform{}},
	}
}

// addOps adds ops, an admin account with sudo and a key, as admin-user
// leaves it.
func addOps(f *facts.Facts) {
	f.Users.Accounts = append(f.Users.Accounts, facts.Account{Name: "ops", UID: 1001, GID: 1001, Home: "/home/ops", Shell: "/bin/bash", LoginShell: true, PasswordStatus: "L"})
	f.Users.Groups = append(f.Users.Groups, facts.Group{Name: "ops", GID: 1001})
	f.Users.Sudoers = append(f.Users.Sudoers, facts.Sudoers{Path: "/etc/sudoers.d/90-stackward-ops", Readable: true, Principals: []string{"ops"}, NoPasswd: []facts.SudoRule{{Who: "ops", Line: 4}}})
	f.SSH.Users = append(f.SSH.Users, facts.SSHUser{Name: "ops", UID: 1001, Home: "/home/ops", KeyFiles: ed25519Key("/home/ops")})
}

func adminChoices() AccountChoices { return AccountChoices{Admin: "ops", AdminKeysFrom: "ubuntu"} }

func TestAdminUserPlan(t *testing.T) {
	out := planAdminUser(Input{Facts: cloudFacts(), Accounts: adminChoices()})
	if out.Step == nil {
		t.Fatalf("no step: %+v", out)
	}
	s := out.Step
	wantContent := "# Written by stackward: plan step admin-user, the admin account.\n" +
		"# NOPASSWD because the account has no password; stackward never sets one.\n" +
		"# Remove this file to take the rights away.\n" +
		"ops ALL=(ALL:ALL) NOPASSWD: ALL\n"
	e := s.Edits[0]
	if e.Path != "/etc/sudoers.d/90-stackward-ops" || e.Action != Create || e.Mode != "0440" || e.New != wantContent {
		t.Errorf("edit %+v", e)
	}
	if !slices.Equal(e.Validate, []string{"visudo", "-c", "-f"}) {
		t.Errorf("validate %v", e.Validate)
	}
	want := [][]string{
		{"useradd", "--create-home", "--home-dir", "/home/ops", "--user-group", "--shell", "/bin/bash", "ops"},
		{"install", "-d", "-m", "0700", "-o", "ops", "-g", "ops", "/home/ops/.ssh"},
		{"install", "-m", "0600", "-o", "ops", "-g", "ops", "/home/ubuntu/.ssh/authorized_keys", "/home/ops/.ssh/authorized_keys"},
	}
	if err := wantCommands("commands", s.Commands, want...); err != nil {
		t.Error(err)
	}
	if err := wantCommands("undo", s.Undo.Commands, []string{"rm", "-f", "/etc/sudoers.d/90-stackward-ops"}, []string{"userdel", "--remove", "ops"}); err != nil {
		t.Error(err)
	}
	// No password and no key ever appears in the step.
	for _, c := range s.Commands {
		for _, a := range c.Args {
			if strings.Contains(a, "ssh-ed25519") || strings.HasPrefix(a, "--password") || a == "-p" {
				t.Errorf("command %v carries a key or a password", c.Args)
			}
		}
	}
	full := Build(Input{Facts: cloudFacts(), Accounts: adminChoices()}, testReport(), Options{Version: "test"})
	for _, st := range full.Steps {
		if err := Authorize(st); err != nil {
			t.Errorf("Authorize refuses its own %s: %v", st.ID, err)
		}
	}
}

func TestAdminUserSkips(t *testing.T) {
	for name, tc := range map[string]struct {
		in   func() Input
		kind string
		want string
	}{
		"no flag, no other admin": {in: func() Input { return Input{Facts: cloudFacts()} }, kind: SkipManual, want: "--admin-user NAME --admin-keys-from USER"},
		"no flag, ops exists": {in: func() Input {
			f := cloudFacts()
			addOps(f)
			return Input{Facts: f}
		}, kind: SkipPassing, want: "(ops)"},
		"report alone": {in: func() Input { return Input{Accounts: adminChoices()} }, kind: SkipUnknown},
		"account exists": {in: func() Input {
			f := cloudFacts()
			addOps(f)
			return Input{Facts: f, Accounts: adminChoices()}
		}, kind: SkipManual, want: "already exists"},
		"group exists": {in: func() Input {
			f := cloudFacts()
			f.Users.Groups = append(f.Users.Groups, facts.Group{Name: "ops", GID: 2000})
			return Input{Facts: f, Accounts: adminChoices()}
		}, kind: SkipManual, want: "group named ops"},
		"a default account name": {in: func() Input {
			return Input{Facts: cloudFacts(), Accounts: AccountChoices{Admin: "debian", AdminKeysFrom: "ubuntu"}}
		}, kind: SkipManual, want: "default account name"},
		"no key source": {in: func() Input {
			return Input{Facts: cloudFacts(), Accounts: AccountChoices{Admin: "ops"}}
		}, kind: SkipManual, want: "never invents a key"},
		"key source is root": {in: func() Input {
			return Input{Facts: cloudFacts(), Accounts: AccountChoices{Admin: "ops", AdminKeysFrom: "root"}}
		}, kind: SkipManual, want: "root"},
		"key source has no keys": {in: func() Input {
			f := cloudFacts()
			f.SSH.Users = nil
			return Input{Facts: f, Accounts: adminChoices()}
		}, kind: SkipManual, want: "no readable /home/ubuntu/.ssh/authorized_keys"},
		"key source has only a DSA key": {in: func() Input {
			f := cloudFacts()
			f.SSH.Users[0].KeyFiles[0].Keys = []sshd.PubKey{{Type: "ssh-dss", Bits: 1024}}
			return Input{Facts: f, Accounts: adminChoices()}
		}, kind: SkipManual, want: "no key current OpenSSH accepts"},
		"no sudo": {in: func() Input {
			f := cloudFacts()
			f.Users.Sudoers = nil
			return Input{Facts: f, Accounts: adminChoices()}
		}, kind: SkipManual, want: "sudo is not installed"},
	} {
		out := planAdminUser(tc.in())
		if out.Step != nil || out.Kind != tc.kind || !strings.Contains(out.Reason, tc.want) {
			t.Errorf("%s: %s %q, want %s containing %q", name, out.Kind, out.Reason, tc.kind, tc.want)
		}
	}
}

func TestPaaSUserPlan(t *testing.T) {
	f := cloudFacts()
	if out := planPaaSUser(Input{Facts: f, Accounts: AccountChoices{PaaS: "coolify"}}); out.Kind != SkipPassing {
		t.Errorf("no platform: %+v", out)
	}
	f.PaaS.Platforms = []facts.Platform{{Name: facts.PlatformCoolify, Role: facts.RolePanel, DataRoot: "/data/coolify"}}
	if out := planPaaSUser(Input{Facts: f}); out.Kind != SkipManual || !strings.Contains(out.Reason, "--paas-user NAME") {
		t.Errorf("no flag: %+v", out)
	}
	if out := planPaaSUser(Input{Facts: f, Accounts: AccountChoices{Admin: "ops", PaaS: "ops"}}); out.Kind != SkipManual {
		t.Errorf("same as admin: %+v", out)
	}
	out := planPaaSUser(Input{Facts: f, Accounts: AccountChoices{PaaS: "deploy"}})
	if out.Step == nil {
		t.Fatalf("no step: %+v", out)
	}
	if len(out.Step.Commands) != 2 || slices.ContainsFunc(out.Step.Commands, func(c Command) bool { return slices.Contains(c.Args, "/home/ubuntu/.ssh/authorized_keys") }) {
		t.Errorf("the PaaS account gets no copied keys: %+v", out.Step.Commands)
	}
	s := *out.Step
	s.ID, s.Risk, s.Fixes = PaaSUserID, AccessCritical, []string{"SSH-003"}
	if err := Authorize(s); err != nil {
		t.Errorf("Authorize refuses its own step: %v", err)
	}
}

// adminStep is the admin-user step Build plans on the cloud host.
func adminStep(t *testing.T) Step {
	t.Helper()
	p := Build(Input{Facts: cloudFacts(), Accounts: adminChoices()}, testReport(), Options{Version: "test"})
	for _, s := range p.Steps {
		if s.ID == AdminUserID {
			return s
		}
	}
	t.Fatalf("no admin-user step: %+v", p.Skipped)
	return Step{}
}

func cloneStep(s Step) Step {
	s.Edits = slices.Clone(s.Edits)
	for i := range s.Edits {
		s.Edits[i].Validate = slices.Clone(s.Edits[i].Validate)
	}
	s.Commands = slices.Clone(s.Commands)
	for i := range s.Commands {
		s.Commands[i].Args = slices.Clone(s.Commands[i].Args)
	}
	s.Undo.Commands = slices.Clone(s.Undo.Commands)
	for i := range s.Undo.Commands {
		s.Undo.Commands[i].Args = slices.Clone(s.Undo.Commands[i].Args)
	}
	s.Restarts = slices.Clone(s.Restarts)
	return s
}

// setNew replaces an edit's content and its hash, as a hand edit that
// keeps the plan's invariants would.
func setNew(e *FileEdit, content string) {
	e.New, e.NewSHA256 = content, sha(content)
}

func TestAdminUserAuthorizeRefusesTampering(t *testing.T) {
	base := adminStep(t)
	for name, tamper := range map[string]func(s *Step){
		"another drop-in path":  func(s *Step) { s.Edits[0].Path = "/etc/sudoers.d/zz" },
		"the main sudoers file": func(s *Step) { s.Edits[0].Path = "/etc/sudoers" },
		"a rule for root": func(s *Step) {
			s.Edits[0].Path = "/etc/sudoers.d/90-stackward-root"
		},
		"a default account": func(s *Step) { s.Edits[0].Path = "/etc/sudoers.d/90-stackward-ubuntu" },
		"other content":     func(s *Step) { setNew(&s.Edits[0], "ALL ALL=(ALL:ALL) NOPASSWD: ALL\n") },
		"mode 0644":         func(s *Step) { s.Edits[0].Mode = "0644" },
		"no validation":     func(s *Step) { s.Edits[0].Validate = nil },
		"keys from root":    func(s *Step) { s.Commands[2].Args[7] = "/root/.ssh/authorized_keys" },
		"keys from a file":  func(s *Step) { s.Commands[2].Args[7] = "/tmp/keys" },
		"keys to elsewhere": func(s *Step) { s.Commands[2].Args[8] = "/root/.ssh/authorized_keys" },
		"a password":        func(s *Step) { s.Commands[0].Args = append(s.Commands[0].Args[:7:7], "--password", "x", "ops") },
		"another shell":     func(s *Step) { s.Commands[0].Args[6] = "/bin/sh" },
		"an extra command": func(s *Step) {
			s.Commands = append(s.Commands, Command{Args: []string{"usermod", "-aG", "docker", "ops"}})
		},
		"undo deletes another account": func(s *Step) {
			s.Undo.Commands[1].Args[2] = "ubuntu"
		},
		"undo keeps the home": func(s *Step) { s.Undo.Commands[1].Args = []string{"userdel", "ops"} },
		"a restart":           func(s *Step) { s.Restarts = []string{"ssh"} },
	} {
		s := cloneStep(base)
		tamper(&s)
		if err := Authorize(s); err == nil {
			t.Errorf("%s: Authorize accepted it", name)
		}
	}
}

// fakeReader is a Reader over a map of paths; a path ending in "/" is a
// directory (reading it fails, but not as missing).
type fakeReader map[string]string

func (r fakeReader) ReadFile(p string) ([]byte, error) {
	if _, ok := r[p+"/"]; ok {
		return nil, errors.New("is a directory")
	}
	v, ok := r[p]
	if !ok {
		return nil, fs.ErrNotExist
	}
	return []byte(v), nil
}

const (
	passwdBefore = "root:x:0:0:root:/root:/bin/bash\nubuntu:x:1000:1000:Ubuntu:/home/ubuntu:/bin/bash\n"
	groupBefore  = "root:x:0:\nsudo:x:27:ubuntu\nubuntu:x:1000:\n"
	fakeKey      = "ssh-ed25519 AAAA-not-a-real-key test\n"
)

func TestAdminUserPinAndCheck(t *testing.T) {
	s := adminStep(t)
	host := fakeReader{"/etc/passwd": passwdBefore, "/etc/group": groupBefore, "/home/ubuntu/.ssh/authorized_keys": fakeKey}
	if err := pinAccount(host, s); err != nil {
		t.Fatalf("pin on a clean host: %v", err)
	}
	if applied, _, err := checkAccount(host, s); applied || err != nil {
		t.Fatalf("check on a clean host: %v %v", applied, err)
	}
	for name, change := range map[string]func(r fakeReader){
		"the account exists": func(r fakeReader) { r["/etc/passwd"] += "ops:x:1001:1001::/home/ops:/bin/bash\n" },
		"the group exists":   func(r fakeReader) { r["/etc/group"] += "ops:x:1001:\n" },
		"the home exists":    func(r fakeReader) { r["/home/ops/"] = "" },
		"no keys to copy":    func(r fakeReader) { delete(r, "/home/ubuntu/.ssh/authorized_keys") },
		"empty keys":         func(r fakeReader) { r["/home/ubuntu/.ssh/authorized_keys"] = "\n" },
	} {
		r := fakeReader{}
		for k, v := range host {
			r[k] = v
		}
		change(r)
		if err := pinAccount(r, s); err == nil {
			t.Errorf("%s: pin accepted it", name)
		}
	}
	// After the step: applied, so a second run does nothing.
	done := fakeReader{
		"/etc/passwd": passwdBefore + "ops:x:1001:1001::/home/ops:/bin/bash\n", "/etc/group": groupBefore + "ops:x:1001:\n",
		"/etc/sudoers.d/90-stackward-ops": s.Edits[0].New, "/home/ops/.ssh/authorized_keys": fakeKey,
	}
	if applied, why, err := checkAccount(done, s); !applied || err != nil {
		t.Errorf("check after the step: %v %q %v", applied, why, err)
	}
	delete(done, "/home/ops/.ssh/authorized_keys")
	if applied, _, _ := checkAccount(done, s); applied {
		t.Error("an admin account without its keys is not applied")
	}
}

func TestValidAccountName(t *testing.T) {
	for _, ok := range []string{"ops", "a", "deploy-1", "web_admin"} {
		if err := ValidAccountName(ok); err != nil {
			t.Errorf("%s: %v", ok, err)
		}
	}
	for _, bad := range []string{"", "root", "Ops", "1ops", "ops.x", "../x", "a b", strings.Repeat("a", 32), "-ops"} {
		if err := ValidAccountName(bad); err == nil {
			t.Errorf("%q accepted", bad)
		}
	}
}

func TestAccountStepsOrderBeforeTheLock(t *testing.T) {
	var order []string
	for _, g := range Generators() {
		if g.Risk == AccessCritical {
			order = append(order, g.ID)
		}
	}
	want := []string{AdminUserID, PaaSUserID, SSHDHardeningID, LockDefaultUserID, UFWPolicyID, "fail2ban-sshd"}
	if !slices.Equal(order, want) {
		t.Errorf("access-critical order %v, want %v", order, want)
	}
}

// The admin step narrows no way in: the guard has nothing to prove.
func TestAdminUserNeedsNoProof(t *testing.T) {
	if NeedsProof(adminStep(t)) {
		t.Error("creating an account narrows no way in")
	}
}

func warnUSR003(subjects ...string) []checks.Result {
	var out []checks.Result
	for _, s := range subjects {
		out = append(out, checks.Result{ID: "USR-003", Subject: s, Level: checks.Warn})
	}
	return out
}
