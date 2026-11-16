package plan

import (
	"slices"
	"strings"
	"testing"

	"github.com/Shironex/stackward/internal/facts"
)

// admin-user on a root only image (Hetzner, DigitalOcean, Vultr): root is
// the only account and holds the owner's key, so the admin account gets
// root's keys. Root itself is only read.

// rootOnlyFacts is cloudFacts without the image's default account: root
// holds the only key.
func rootOnlyFacts() *facts.Facts {
	f := cloudFacts()
	f.Users.Accounts = f.Users.Accounts[:1]
	f.Users.Groups = []facts.Group{{Name: "root", GID: 0}, {Name: "sudo", GID: 27}}
	f.Users.Sudoers = f.Users.Sudoers[:1]
	f.SSH.Users = []facts.SSHUser{{Name: "root", UID: 0, Home: "/root", KeyFiles: ed25519Key("/root")}}
	return f
}

func rootChoices() AccountChoices { return AccountChoices{Admin: "ops", AdminKeysFrom: "root"} }

func TestAdminUserFromRootKeys(t *testing.T) {
	out := planAdminUser(Input{Facts: rootOnlyFacts(), Accounts: rootChoices()})
	if out.Step == nil {
		t.Fatalf("no step: %+v", out)
	}
	s := out.Step
	want := [][]string{
		{"useradd", "--create-home", "--home-dir", "/home/ops", "--user-group", "--shell", "/bin/bash", "ops"},
		{"install", "-d", "-m", "0700", "-o", "ops", "-g", "ops", "/home/ops/.ssh"},
		{"install", "-m", "0600", "-o", "ops", "-g", "ops", "/root/.ssh/authorized_keys", "/home/ops/.ssh/authorized_keys"},
	}
	if err := wantCommands("commands", s.Commands, want...); err != nil {
		t.Error(err)
	}
	notes := strings.Join(s.Notes, "\n")
	for _, w := range []string{"The keys come from root (/root/.ssh/authorized_keys)", "PermitRootLogin no", "sshd-hardening"} {
		if !strings.Contains(notes, w) {
			t.Errorf("the notes do not say %q:\n%s", w, notes)
		}
	}
	if strings.Contains(notes, "lock-default-user") {
		t.Errorf("a root only image has no default account to lock:\n%s", notes)
	}
	// Root is never created, locked or changed: nothing touches it.
	for _, tg := range s.Touches {
		if strings.HasSuffix(tg, ":root") || strings.HasPrefix(tg, "file:/root") {
			t.Errorf("the step touches %s", tg)
		}
	}

	// Build keeps it: the never touched list lets admin-user read root's
	// keys, and Authorize accepts its own step.
	p := Build(Input{Facts: rootOnlyFacts(), Accounts: rootChoices()}, testReport(), Options{Version: "test"})
	i := slices.IndexFunc(p.Steps, func(s Step) bool { return s.ID == AdminUserID })
	if i < 0 {
		t.Fatalf("Build dropped admin-user: %+v", p.Skipped)
	}
	if err := Authorize(p.Steps[i]); err != nil {
		t.Errorf("Authorize refuses its own step: %v", err)
	}
	if err := checkNeverTouched(p.Steps[i]); err != nil {
		t.Errorf("never touched: %v", err)
	}
	if got := specOf(p.Steps[i]).keysFrom; got != "root" {
		t.Errorf("the key source reads back as %q", got)
	}

	// Pin reads root's keys on the host.
	host := fakeReader{"/etc/passwd": "root:x:0:0:root:/root:/bin/bash\n", "/etc/group": "root:x:0:\n", "/root/.ssh/authorized_keys": fakeKey}
	if err := pinAccount(host, p.Steps[i]); err != nil {
		t.Errorf("pin on a root only host: %v", err)
	}
	delete(host, "/root/.ssh/authorized_keys")
	if err := pinAccount(host, p.Steps[i]); err == nil || !strings.Contains(err.Error(), "/root/.ssh/authorized_keys") {
		t.Errorf("pin without root's keys: %v", err)
	}
}

// Only root itself gives its keys: another uid 0 account, a root that is
// not uid 0 or one with another home, and root as the account to create,
// are all refused.
func TestAdminUserRootSourceRefusals(t *testing.T) {
	for name, tc := range map[string]struct {
		f    func() *facts.Facts
		ch   AccountChoices
		want string
	}{
		"another uid 0 account": {func() *facts.Facts {
			f := rootOnlyFacts()
			f.Users.Accounts = append(f.Users.Accounts, facts.Account{Name: "toor", UID: 0, Home: "/home/toor", Shell: "/bin/bash", LoginShell: true})
			f.SSH.Users = append(f.SSH.Users, facts.SSHUser{Name: "toor", UID: 0, Home: "/home/toor", KeyFiles: ed25519Key("/home/toor")})
			return f
		}, AccountChoices{Admin: "ops", AdminKeysFrom: "toor"}, "uid 0 but is not root"},
		"root is not uid 0": {func() *facts.Facts {
			f := rootOnlyFacts()
			f.Users.Accounts[0].UID = 1500
			return f
		}, rootChoices(), "does not have uid 0"},
		"root lives elsewhere": {func() *facts.Facts {
			f := rootOnlyFacts()
			f.Users.Accounts[0].Home = "/var/root"
			return f
		}, rootChoices(), "the home of root is /var/root"},
		"root has no keys": {func() *facts.Facts {
			f := rootOnlyFacts()
			f.SSH.Users = nil
			return f
		}, rootChoices(), "no readable /root/.ssh/authorized_keys"},
		"creating root": {rootOnlyFacts, AccountChoices{Admin: "root", AdminKeysFrom: "root"}, "root is not an account to create"},
	} {
		out := planAdminUser(Input{Facts: tc.f(), Accounts: tc.ch})
		if out.Step != nil || out.Kind != SkipManual || !strings.Contains(out.Reason, tc.want) {
			t.Errorf("%s: %s %q, want manual containing %q", name, out.Kind, out.Reason, tc.want)
		}
	}
}

// The exception lets admin-user read root's keys and nothing else: no
// other step reaches them, and admin-user still cannot reach root's other
// files.
func TestRootKeysExceptionIsNarrow(t *testing.T) {
	read := Step{ID: AdminUserID, Commands: []Command{{Args: []string{"install", "/root/.ssh/authorized_keys", "/home/ops/.ssh/authorized_keys"}}}}
	if err := checkNeverTouched(read); err != nil {
		t.Errorf("admin-user reading root's keys: %v", err)
	}
	for name, s := range map[string]Step{
		"another step":    {ID: PaaSUserID, Commands: []Command{{Args: []string{"install", "/root/.ssh/authorized_keys", "/home/x/.ssh/authorized_keys"}}}},
		"root's ssh dir":  {ID: AdminUserID, Commands: []Command{{Args: []string{"install", "-d", "/root/.ssh"}}}},
		"root's key file": {ID: AdminUserID, Touches: []string{"authorized-keys:root"}},
	} {
		if err := checkNeverTouched(s); err == nil {
			t.Errorf("%s: not refused", name)
		}
	}
}
