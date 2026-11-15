package plan

import (
	"net/netip"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/Shironex/stackward/internal/facts"
	"github.com/Shironex/stackward/internal/facts/sshd"
)

// The lockout guard over fake facts: every way-in narrowing, with and
// without a second way in. Addresses are documentation ranges and the
// tailnet's 100.64.0.0/10.

func ed25519Key(home string) []facts.SSHKeyFile {
	return []facts.SSHKeyFile{{Path: home + "/.ssh/authorized_keys", Keys: []sshd.PubKey{{Type: "ssh-ed25519", Bits: 256}}}}
}

// guardFacts is a host where alice (sudo through %sudo, an ed25519 key)
// can log in, Tailscale runs with key expiry off, and UFW lets 22 in from
// anywhere and on tailscale0.
func guardFacts() *facts.Facts {
	return &facts.Facts{
		SSH: &facts.SSH{
			Installed: true, Source: "sshd -T", Complete: true,
			Effective: map[string][]string{
				"pubkeyauthentication": {"yes"}, "authenticationmethods": {"any"}, "passwordauthentication": {"yes"},
				"authorizedkeysfile": {".ssh/authorized_keys .ssh/authorized_keys2"}, "usepam": {"yes"},
				"port": {"22"}, "listenaddress": {"0.0.0.0:22", "[::]:22"},
			},
			Config: &sshd.Config{},
			Users:  []facts.SSHUser{{Name: "alice", UID: 1000, Home: "/home/alice", KeyFiles: ed25519Key("/home/alice")}},
		},
		Users: &facts.Users{
			Accounts: []facts.Account{
				{Name: "root", UID: 0, Home: "/root", Shell: "/bin/bash", LoginShell: true},
				{Name: "alice", UID: 1000, GID: 1000, Home: "/home/alice", Shell: "/bin/bash", LoginShell: true},
			},
			Groups:  []facts.Group{{Name: "alice", GID: 1000}, {Name: "sudo", GID: 27, Members: []string{"alice"}}},
			Sudoers: []facts.Sudoers{{Path: "/etc/sudoers", Readable: true, Principals: []string{"root", "%sudo"}}},
		},
		Tailscale: &facts.Tailscale{Installed: true, StatusRead: true, BackendState: "Running"},
		Firewall: &facts.Firewall{UFW: &facts.UFW{
			Installed: true, Status: "active", DefaultIncoming: "deny", RulesKnown: true,
			Rules: []facts.UFWRule{
				{Action: "allow", Direction: "in", Port: "22", Proto: "tcp"},
				{Action: "allow", Direction: "in", Port: "22", Proto: "tcp", Interface: "tailscale0"},
			},
		}},
	}
}

func sshdChange(kv ...string) change {
	m := map[string]string{}
	for i := 0; i+1 < len(kv); i += 2 {
		m[kv[i]] = kv[i+1]
	}
	return change{sshd: m, declared: true}
}

func closePublic(a Access) change {
	a.ClosesPublicSSH = true
	return change{access: a, declared: true}
}

func addBob(f *facts.Facts) {
	f.Users.Accounts = append(f.Users.Accounts, facts.Account{Name: "bob", UID: 1001, GID: 1001, Home: "/home/bob", Shell: "/bin/bash", LoginShell: true})
	f.Users.Groups[1].Members = append(f.Users.Groups[1].Members, "bob")
	f.SSH.Users = append(f.SSH.Users, facts.SSHUser{Name: "bob", UID: 1001, Home: "/home/bob", KeyFiles: ed25519Key("/home/bob")})
}

func match(f *facts.Facts, criteria string, kv ...string) {
	f.SSH.Config.Matches = append(f.SSH.Config.Matches, sshd.Match{Criteria: criteria, File: "/etc/ssh/sshd_config", Line: 100 + len(f.SSH.Config.Matches)})
	for i := 0; i+1 < len(kv); i += 2 {
		f.SSH.Config.Directives = append(f.SSH.Config.Directives, sshd.Directive{Keyword: kv[i], Value: kv[i+1], Match: len(f.SSH.Config.Matches)})
	}
}

var (
	homeAddr  = netip.MustParseAddr("192.0.2.10")
	otherAddr = netip.MustParseAddr("198.51.100.7")
)

func TestLockoutGuard(t *testing.T) {
	expiry := time.Date(2026, 6, 1, 0, 0, 0, 0, time.UTC)
	for name, tc := range map[string]struct {
		c       change
		src     netip.Addr
		applier string
		facts   func(f *facts.Facts)
		// want is "" for a proof, or text the refusal must hold.
		want        string
		confirmFrom []string
	}{
		// Password authentication off.
		"password off, a sudo user with a key": {c: sshdChange("passwordauthentication", "no")},
		"password off, the only sudo user has no key": {
			c: sshdChange("passwordauthentication", "no"), facts: func(f *facts.Facts) { f.SSH.Users = nil },
			want: "alice: no usable authorized key (it would log in with a password only)",
		},
		"password off, only a DSA key": {
			c: sshdChange("passwordauthentication", "no"),
			facts: func(f *facts.Facts) {
				f.SSH.Users[0].KeyFiles[0].Keys = []sshd.PubKey{{Type: "ssh-dss", Bits: 1024}}
			},
			want: "no usable authorized key",
		},
		"password off, the key holder has no sudo": {
			c: sshdChange("passwordauthentication", "no"), facts: func(f *facts.Facts) { f.Users.Groups[1].Members = nil },
			want: "alice: no sudo rule",
		},
		"password off, sudoers unreadable": {
			c: sshdChange("passwordauthentication", "no"), facts: func(f *facts.Facts) { f.Users.Sudoers[0].Readable = false },
			want: "sudoers could not be read",
		},
		"password off, sudo granted by name": {
			c: sshdChange("passwordauthentication", "no"),
			facts: func(f *facts.Facts) {
				f.Users.Groups[1].Members = nil
				f.Users.Sudoers = append(f.Users.Sudoers, facts.Sudoers{Path: "/etc/sudoers.d/90-alice", Readable: true, Principals: []string{"alice"}})
			},
		},
		// Root login off while root is the only way in.
		"root login off, only root can log in": {
			c: sshdChange("permitrootlogin", "no"), facts: func(f *facts.Facts) { f.Users.Accounts = f.Users.Accounts[:1] },
			want: "no account but root can log in",
		},
		"root login off, alice can": {c: sshdChange("permitrootlogin", "no")},
		// AllowUsers and AllowGroups.
		"AllowUsers without the admin": {c: sshdChange("allowusers", "bob"), want: "AllowUsers bob does not let alice in"},
		"AllowUsers with the admin":    {c: sshdChange("allowusers", "deploy,alice")},
		"AllowUsers with a wildcard":   {c: sshdChange("allowusers", "al*")},
		"AllowUsers user@network, session inside": {
			c: sshdChange("allowusers", "alice@192.0.2.0/24"), src: homeAddr,
		},
		"AllowUsers user@network, session outside": {
			c: sshdChange("allowusers", "alice@192.0.2.0/24"), src: otherAddr, want: "does not let alice in from 198.51.100.7",
		},
		"AllowUsers user@network, source unknown": {
			c: sshdChange("allowusers", "alice@192.0.2.0/24"), want: "does not let alice in from an unknown address",
		},
		"AllowGroups without the admin's groups": {c: sshdChange("allowgroups", "admins"), want: "AllowGroups admins does not let alice in"},
		"AllowGroups with the sudo group":        {c: sshdChange("allowgroups", "sudo")},
		"DenyUsers the admin, a second admin":    {c: sshdChange("denyusers", "alice"), facts: addBob},
		"DenyUsers the only admin":               {c: sshdChange("denyusers", "alice"), want: "DenyUsers alice refuses alice"},
		// Methods and key settings.
		"AuthenticationMethods needs a password too": {
			c: sshdChange("authenticationmethods", "publickey,password"), want: "needs more than a key",
		},
		"AuthenticationMethods key only":    {c: sshdChange("authenticationmethods", "publickey")},
		"public keys off":                   {c: sshdChange("pubkeyauthentication", "no"), want: "public key authentication would be off"},
		"keys moved where alice has none":   {c: sshdChange("authorizedkeysfile", "/etc/ssh/keys/%u"), want: "no usable key in the authorized keys files"},
		"keys moved where alice has a file": {c: sshdChange("authorizedkeysfile", ".ssh/authorized_keys")},
		// Match blocks for the admin and a typical source.
		"Match User turns keys off for the admin": {
			c:     sshdChange("passwordauthentication", "no"),
			facts: func(f *facts.Facts) { match(f, "User alice", "pubkeyauthentication", "no") },
			want:  "public key authentication would be off for alice",
		},
		"Match User for someone else": {
			c:     sshdChange("passwordauthentication", "no"),
			facts: func(f *facts.Facts) { match(f, "User deploy", "pubkeyauthentication", "no") },
		},
		"Match Address may deny, source unknown": {
			c:     sshdChange("passwordauthentication", "no"),
			facts: func(f *facts.Facts) { match(f, "Address 203.0.113.0/24", "denyusers", "*") },
			want:  "DenyUsers * refuses alice (with the Match block at /etc/ssh/sshd_config:100 (Address 203.0.113.0/24) applied, which the guard cannot rule out for alice from an unknown address)",
		},
		"Match Address may deny, session elsewhere": {
			c: sshdChange("passwordauthentication", "no"), src: homeAddr,
			facts: func(f *facts.Facts) { match(f, "Address 203.0.113.0/24", "denyusers", "*") },
		},
		"Match Group negated": {
			c:     sshdChange("passwordauthentication", "no"),
			facts: func(f *facts.Facts) { match(f, "Group *,!sudo,!alice", "pubkeyauthentication", "no") },
		},
		"Match block with an unreadable include": {
			c: sshdChange("passwordauthentication", "no"),
			facts: func(f *facts.Facts) {
				match(f, "User alice")
				f.SSH.Config.Matches[0].Incomplete = true
			},
			want: "includes a file that could not be read",
		},
		// A new port.
		"port change the firewall does not allow": {c: sshdChange("port", "2222"), want: "no UFW rule lets tcp/2222 in"},
		"port change the firewall allows": {
			c: sshdChange("port", "2222"),
			facts: func(f *facts.Facts) {
				f.Firewall.UFW.Rules = append(f.Firewall.UFW.Rules, facts.UFWRule{Action: "allow", Direction: "in", Port: "2222", Proto: "tcp"})
			},
		},
		"port change, firewall not audited": {
			c: sshdChange("port", "2222"), facts: func(f *facts.Facts) { f.Firewall = nil }, want: "firewall was not audited",
		},
		// Disabling accounts and removing keys.
		"disable the only admin":                {c: change{access: Access{Disables: []string{"alice"}}, declared: true}, want: "alice: the step disables it"},
		"disable one of two admins":             {c: change{access: Access{Disables: []string{"alice"}}, declared: true}, facts: addBob},
		"disable the account that applies":      {c: change{access: Access{Disables: []string{"alice"}}, declared: true}, facts: addBob, applier: "alice", want: "the account applying it"},
		"remove the last admin key":             {c: change{access: Access{RemovesKeys: []string{"alice"}}, declared: true}, want: "alice: the step removes its keys"},
		"remove one admin's keys, another left": {c: change{access: Access{RemovesKeys: []string{"alice"}}, declared: true}, facts: addBob},
		// Closing public SSH.
		"close public SSH, tailnet proven": {
			c: closePublic(Access{}), confirmFrom: []string{"100.64.0.0/10", "fd7a:115c:a1e0::/48"},
		},
		"close public SSH, tailscale logged out": {
			c: closePublic(Access{}), facts: func(f *facts.Facts) { f.Tailscale.BackendState = "NeedsLogin" },
			want: "the Tailscale backend is NeedsLogin, not Running",
		},
		"close public SSH, key expiry on": {
			c: closePublic(Access{}), facts: func(f *facts.Facts) { f.Tailscale.KeyExpiry = &expiry },
			want: "key expires at 2026-06-01T00:00:00Z",
		},
		"close public SSH, no tailscale": {
			c: closePublic(Access{}), facts: func(f *facts.Facts) { f.Tailscale = &facts.Tailscale{} }, want: "no Tailscale is installed",
		},
		"close public SSH, sshd not on the tailnet": {
			c: closePublic(Access{}), facts: func(f *facts.Facts) { f.SSH.Effective["listenaddress"] = []string{"203.0.113.5:22"} },
			want: "not on the tailnet",
		},
		"close public SSH, sshd on the tailnet address only": {
			c: closePublic(Access{}), facts: func(f *facts.Facts) { f.SSH.Effective["listenaddress"] = []string{"100.101.102.103:22"} },
			confirmFrom: []string{"100.64.0.0/10", "fd7a:115c:a1e0::/48"},
		},
		"close public SSH, firewall lacks the tailnet rule": {
			c: closePublic(Access{}), facts: func(f *facts.Facts) { f.Firewall.UFW.Rules = f.Firewall.UFW.Rules[:1] },
			want: "no firewall rule lets the tailnet reach sshd on tcp/22",
		},
		"close public SSH, the step adds the tailnet rule": {
			c: closePublic(Access{TailnetSSH: true}), facts: func(f *facts.Facts) { f.Firewall.UFW.Rules = f.Firewall.UFW.Rules[:1] },
			confirmFrom: []string{"100.64.0.0/10", "fd7a:115c:a1e0::/48"},
		},
		"close public SSH, tailnet rule by source network": {
			c: closePublic(Access{}),
			facts: func(f *facts.Facts) {
				f.Firewall.UFW.Rules[1] = facts.UFWRule{Action: "allow", Direction: "in", Port: "22", Proto: "tcp", From: "100.64.0.0/10"}
			},
			confirmFrom: []string{"100.64.0.0/10", "fd7a:115c:a1e0::/48"},
		},
		"close public SSH, Match Address keeps the tailnet out": {
			c:     closePublic(Access{}),
			facts: func(f *facts.Facts) { match(f, "Address 100.64.0.0/10", "denyusers", "alice") },
			want:  "DenyUsers alice refuses alice",
		},
		"close public SSH, allowed source and the session from it": {
			c: closePublic(Access{AllowFrom: []string{"192.0.2.0/24"}}), src: homeAddr,
			facts:       func(f *facts.Facts) { f.Tailscale.BackendState = "Stopped" },
			confirmFrom: []string{"192.0.2.0/24"},
		},
		"close public SSH, allowed source, session elsewhere": {
			c: closePublic(Access{AllowFrom: []string{"192.0.2.0/24"}}), src: otherAddr,
			facts: func(f *facts.Facts) { f.Tailscale.BackendState = "Stopped" },
			want:  "this session comes from 198.51.100.7, outside the allowed sources 192.0.2.0/24",
		},
		"close public SSH, allowed source, session unknown": {
			c:     closePublic(Access{AllowFrom: []string{"192.0.2.0/24"}}),
			facts: func(f *facts.Facts) { f.Tailscale.BackendState = "Stopped" },
			want:  "this session's source is unknown",
		},
		"close public SSH, both ways": {
			c: closePublic(Access{AllowFrom: []string{"192.0.2.0/24"}}), src: homeAddr,
			confirmFrom: []string{"100.64.0.0/10", "fd7a:115c:a1e0::/48", "192.0.2.0/24"},
		},
		"close public SSH, no second way at all": {
			c:     closePublic(Access{}),
			facts: func(f *facts.Facts) { f.Tailscale.BackendState = "Stopped" },
			want:  "public SSH must not close without a proven second way in",
		},
		// What the guard cannot read counts against the proof.
		"no facts": {c: sshdChange("passwordauthentication", "no"), facts: func(f *facts.Facts) { *f = facts.Facts{} }, want: "sshd was not audited"},
		"effective setting unknown": {
			c: sshdChange("passwordauthentication", "no"),
			facts: func(f *facts.Facts) {
				f.SSH.Complete = false
				delete(f.SSH.Effective, "authenticationmethods")
			},
			want: "sshd's effective authenticationmethods is not known",
		},
		"a change that says nothing about access": {c: change{}},
		"a change that says nothing, no sudo user": {
			c: change{}, facts: func(f *facts.Facts) { f.Users.Groups[1].Members = nil }, want: "does not say what it does to access",
		},
	} {
		t.Run(name, func(t *testing.T) {
			f := guardFacts()
			if tc.facts != nil {
				tc.facts(f)
			}
			p, err := proveChange("txn-test", tc.c, GuardInput{Facts: f, Source: tc.src, Applier: tc.applier})
			if tc.want != "" {
				if err == nil || !strings.Contains(err.Error(), tc.want) {
					t.Fatalf("err %v, want %q", err, tc.want)
				}
				if !strings.HasPrefix(err.Error(), "lockout guard: txn-test ") {
					t.Errorf("the refusal does not name the guard and the step: %v", err)
				}
				return
			}
			if err != nil {
				t.Fatalf("refused: %v", err)
			}
			if !p.Needed || len(p.Ways) == 0 {
				t.Fatalf("proof %+v", p)
			}
			if !slices.Equal(p.ConfirmFrom, tc.confirmFrom) {
				t.Errorf("confirm from %v, want %v", p.ConfirmFrom, tc.confirmFrom)
			}
		})
	}
}

// A change that narrows nothing needs no proof, even without facts.
func TestLockoutGuardSkipsChangesThatNarrowNothing(t *testing.T) {
	p, err := proveChange("txn-test", sshdChange("logingracetime", "60"), GuardInput{})
	if err != nil || p.Needed {
		t.Fatalf("proof %+v, err %v", p, err)
	}
	p, err = ProveAccess(Step{ID: "journald-cap"}, GuardInput{})
	if err != nil || p.Needed {
		t.Fatalf("a safe step: proof %+v, err %v", p, err)
	}
}

func TestLockoutGuardNamesTheWayIn(t *testing.T) {
	p, err := proveChange("txn-test", closePublic(Access{}), GuardInput{Facts: guardFacts()})
	if err != nil {
		t.Fatal(err)
	}
	if want := "alice (sudo, authorized key) logs in with a key from the tailnet over the tailnet"; len(p.Ways) != 1 || p.Ways[0] != want {
		t.Errorf("ways %q, want %q", p.Ways, want)
	}
	if !slices.Equal(p.Narrows, []string{"closes public SSH"}) {
		t.Errorf("narrows %q", p.Narrows)
	}
}

func TestMatchList(t *testing.T) {
	user := func(name string) func(string) tri {
		return func(p string) tri { return boolTri(wildMatch(p, name)) }
	}
	for _, tc := range []struct {
		list, name string
		want       tri
	}{
		{"alice", "alice", triYes},
		{"bob,alice", "alice", triYes},
		{"*,!alice", "alice", triNo},
		{"*,!alice", "bob", triYes},
		{"a?ice", "alice", triYes},
		{"bob", "alice", triNo},
	} {
		if got := matchList(tc.list, user(tc.name)); got != tc.want {
			t.Errorf("matchList(%q, %q) = %v, want %v", tc.list, tc.name, got, tc.want)
		}
	}
	tailnet := netSource(TailnetV4, "the tailnet")
	for _, tc := range []struct {
		pattern string
		src     source
		want    tri
	}{
		{"*", source{}, triYes},
		{"192.0.2.0/24", source{}, triMaybe},
		{"192.0.2.0/24", addrSource(homeAddr), triYes},
		{"192.0.2.10", addrSource(homeAddr), triYes},
		{"192.0.2.*", addrSource(homeAddr), triYes},
		{"203.0.113.0/24", addrSource(homeAddr), triNo},
		{"100.64.0.0/10", tailnet, triYes},
		{"100.100.0.0/16", tailnet, triMaybe},
		{"203.0.113.0/24", tailnet, triNo},
	} {
		if got := matchAddr(tc.pattern, tc.src); got != tc.want {
			t.Errorf("matchAddr(%q, %s) = %v, want %v", tc.pattern, tc.src.label, got, tc.want)
		}
	}
}
