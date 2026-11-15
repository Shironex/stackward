package plan

import (
	"slices"
	"strings"
	"testing"

	"github.com/Shironex/stackward/internal/checks"
	"github.com/Shironex/stackward/internal/facts"
	"github.com/Shironex/stackward/internal/facts/sshd"
)

// sshdResults: password login on (SSH-001 fail), root by key (SSH-003
// warn), MaxAuthTries 6 (SSH-005 warn); the rest pass.
func sshdResults() []checks.Result {
	return results(map[string]checks.Level{
		"SSH-001": checks.Fail, "SSH-002": checks.Pass, "SSH-003": checks.Warn, "SSH-004": checks.Pass, "SSH-005": checks.Warn,
	})
}

func sshdStepOf(t *testing.T, in Input) Step {
	t.Helper()
	out := planSSHDHardening(in)
	if out.Step == nil {
		t.Fatalf("no step: %+v", out)
	}
	return complete(mustLookup(t, SSHDHardeningID), *out.Step)
}

func TestSSHDHardeningPlan(t *testing.T) {
	s := sshdStepOf(t, Input{Facts: cloudFacts(), Results: sshdResults()})
	want := "# Written by stackward: plan step sshd-hardening, fixes SSH-001, SSH-003, SSH-005.\n" +
		"# Named to sort first: sshd keeps the first value it reads. Remove this\n" +
		"# file and reload ssh.service to undo.\n" +
		"PasswordAuthentication no\n" +
		"PermitRootLogin no\n" +
		"MaxAuthTries 3\n"
	e := s.Edits[0]
	if e.Path != "/etc/ssh/sshd_config.d/00-stackward-hardening.conf" || e.Action != Create || e.Mode != "0644" || e.New != want {
		t.Errorf("edit %+v\n%s", e, e.New)
	}
	if !slices.Equal(e.Validate, []string{"sshd", "-t", "-f"}) {
		t.Errorf("validate %v", e.Validate)
	}
	if !slices.Equal(s.Fixes, []string{"SSH-001", "SSH-003", "SSH-005"}) || !slices.Equal(s.Restarts, []string{"ssh"}) {
		t.Errorf("fixes %v restarts %v", s.Fixes, s.Restarts)
	}
	wantSSHD := map[string]string{"passwordauthentication": "no", "permitrootlogin": "no", "maxauthtries": "3"}
	if got := SSHDExpect(s); len(got) != len(wantSSHD) || got["passwordauthentication"] != "no" || got["permitrootlogin"] != "no" || got["maxauthtries"] != "3" {
		t.Errorf("SSHD %v, want %v", got, wantSSHD)
	}
	if err := Authorize(s); err != nil {
		t.Errorf("Authorize refuses its own step: %v", err)
	}
	if !NeedsProof(s) {
		t.Error("turning password login off needs the guard's proof")
	}
}

func TestSSHDHardeningLeavesOutWhatItCannotWin(t *testing.T) {
	for name, tc := range map[string]struct {
		change func(f *facts.Facts)
		// lines must be in the drop-in, gone must not.
		lines, gone []string
		note        string
		fixes       []string
	}{
		"an earlier drop-in sets password login": {
			change: func(f *facts.Facts) {
				c := f.SSH.Config
				c.Files = slices.Insert(c.Files, 1, sshd.File{Path: "/etc/ssh/sshd_config.d/00-aaa.conf", Readable: true})
				c.Directives = append(c.Directives, sshd.Directive{Keyword: "passwordauthentication", Value: "yes", File: "/etc/ssh/sshd_config.d/00-aaa.conf", Line: 3})
			},
			lines: []string{"PermitRootLogin no"}, gone: []string{"PasswordAuthentication"}, note: "00-aaa.conf:3 sets yes and is read before",
			fixes: []string{"SSH-003", "SSH-005"},
		},
		"the main file sets it before the Include": {
			change: func(f *facts.Facts) {
				f.SSH.Config.Directives = append(f.SSH.Config.Directives, sshd.Directive{Keyword: "maxauthtries", Value: "6", File: "/etc/ssh/sshd_config", Line: 2})
			},
			gone: []string{"MaxAuthTries"}, note: "sshd_config:2 sets 6",
			fixes: []string{"SSH-001", "SSH-003"},
		},
		"the main file sets it after the Include": {
			change: func(f *facts.Facts) {
				f.SSH.Config.Directives = append(f.SSH.Config.Directives, sshd.Directive{Keyword: "maxauthtries", Value: "6", File: "/etc/ssh/sshd_config", Line: 40})
			},
			lines: []string{"MaxAuthTries 3"}, fixes: []string{"SSH-001", "SSH-003", "SSH-005"},
		},
		"a Match block sets it": {
			change: func(f *facts.Facts) {
				c := f.SSH.Config
				c.Matches = append(c.Matches, sshd.Match{Criteria: "User deploy", File: "/etc/ssh/sshd_config", Line: 50})
				c.Directives = append(c.Directives, sshd.Directive{Keyword: "passwordauthentication", Value: "yes", File: "/etc/ssh/sshd_config", Line: 51, Match: 1})
			},
			lines: []string{"PasswordAuthentication no"}, note: "Match block at /etc/ssh/sshd_config:50",
			fixes: []string{"SSH-003", "SSH-005"},
		},
		"a platform logs in as root": {
			change: func(f *facts.Facts) {
				f.PaaS.Platforms = []facts.Platform{{Name: facts.PlatformCoolify, Role: facts.RolePanel, DataRoot: "/data/coolify"}}
			},
			gone: []string{"PermitRootLogin"}, note: "coolify logs in as root", fixes: []string{"SSH-001", "SSH-005"},
		},
		"platform facts missing": {
			change: func(f *facts.Facts) { f.PaaS = nil },
			gone:   []string{"PermitRootLogin"}, note: "platform facts are missing", fixes: []string{"SSH-001", "SSH-005"},
		},
		"AuthenticationMethods needs a password": {
			change: func(f *facts.Facts) { f.SSH.Effective["authenticationmethods"] = []string{"publickey,password"} },
			gone:   []string{"PasswordAuthentication"}, note: "AuthenticationMethods is", fixes: []string{"SSH-003", "SSH-005"},
		},
	} {
		f := cloudFacts()
		tc.change(f)
		s := sshdStepOf(t, Input{Facts: f, Results: sshdResults()})
		content := s.Edits[0].New
		for _, l := range tc.lines {
			if !strings.Contains(content, l+"\n") {
				t.Errorf("%s: missing %q:\n%s", name, l, content)
			}
		}
		for _, g := range tc.gone {
			if strings.Contains(content, "\n"+g+" ") {
				t.Errorf("%s: holds %s:\n%s", name, g, content)
			}
		}
		if tc.note != "" && !slices.ContainsFunc(s.Notes, func(n string) bool { return strings.Contains(n, tc.note) }) {
			t.Errorf("%s: no note %q in %v", name, tc.note, s.Notes)
		}
		if !slices.Equal(s.Fixes, tc.fixes) {
			t.Errorf("%s: fixes %v, want %v", name, s.Fixes, tc.fixes)
		}
		if err := Authorize(s); err != nil {
			t.Errorf("%s: Authorize refuses its own step: %v", name, err)
		}
	}
}

func TestSSHDHardeningSkips(t *testing.T) {
	fail := sshdResults()
	for name, tc := range map[string]struct {
		in   Input
		kind string
		want string
	}{
		"checks pass": {in: Input{Facts: cloudFacts(), Results: results(map[string]checks.Level{
			"SSH-001": checks.Pass, "SSH-002": checks.Pass, "SSH-003": checks.Pass, "SSH-004": checks.Pass, "SSH-005": checks.Pass,
		})}, kind: SkipPassing},
		"report alone": {in: Input{Results: fail}, kind: SkipUnknown},
		"unreadable drop-in": {in: func() Input {
			f := cloudFacts()
			f.SSH.Config.Files = append(f.SSH.Config.Files, sshd.File{Path: "/etc/ssh/sshd_config.d/10-x.conf", Error: "permission denied"})
			return Input{Facts: f, Results: fail}
		}(), kind: SkipUnknown, want: "run the audit with sudo"},
		"no Include": {in: func() Input {
			f := cloudFacts()
			f.SSH.Config.Includes = nil
			return Input{Facts: f, Results: fail}
		}(), kind: SkipManual, want: "does not include"},
		"Include inside a Match block": {in: func() Input {
			f := cloudFacts()
			f.SSH.Config.Includes[0].Match = 1
			return Input{Facts: f, Results: fail}
		}(), kind: SkipManual, want: "does not include"},
		"the drop-in exists": {in: func() Input {
			f := cloudFacts()
			f.SSH.Config.Files = append(f.SSH.Config.Files, sshd.File{Path: sshdDropin, Readable: true})
			return Input{Facts: f, Results: fail}
		}(), kind: SkipManual, want: "already exists"},
		"nothing a drop-in can win": {in: func() Input {
			f := cloudFacts()
			f.PaaS = nil
			f.SSH.Config.Directives = append(f.SSH.Config.Directives,
				sshd.Directive{Keyword: "maxauthtries", Value: "6", File: "/etc/ssh/sshd_config", Line: 1},
				sshd.Directive{Keyword: "passwordauthentication", Value: "yes", File: "/etc/ssh/sshd_config", Line: 2})
			return Input{Facts: f, Results: fail}
		}(), kind: SkipManual, want: "read before"},
	} {
		out := planSSHDHardening(tc.in)
		if out.Step != nil || out.Kind != tc.kind || !strings.Contains(out.Reason, tc.want) {
			t.Errorf("%s: %s %q, want %s containing %q", name, out.Kind, out.Reason, tc.kind, tc.want)
		}
	}
}

func TestSSHDHardeningAuthorizeRefusesTampering(t *testing.T) {
	base := sshdStepOf(t, Input{Facts: cloudFacts(), Results: sshdResults()})
	header := "# Written by stackward: plan step sshd-hardening, fixes SSH-001, SSH-003, SSH-005.\n" +
		"# Named to sort first: sshd keeps the first value it reads. Remove this\n" +
		"# file and reload ssh.service to undo.\n"
	for name, tamper := range map[string]func(s *Step){
		"another path":  func(s *Step) { s.Edits[0].Path = "/etc/ssh/sshd_config.d/99-x.conf" },
		"the main file": func(s *Step) { s.Edits[0].Path = "/etc/ssh/sshd_config"; s.Edits[0].Action = Replace },
		"an extra line": func(s *Step) { setNew(&s.Edits[0], s.Edits[0].New+"AllowUsers nobody\n") },
		"root login yes": func(s *Step) {
			setNew(&s.Edits[0], header+"PasswordAuthentication no\nPermitRootLogin yes\nMaxAuthTries 3\n")
		},
		"lines reordered": func(s *Step) {
			setNew(&s.Edits[0], header+"MaxAuthTries 3\nPasswordAuthentication no\nPermitRootLogin no\n")
		},
		"a repeated line": func(s *Step) {
			setNew(&s.Edits[0], header+"PasswordAuthentication no\nPasswordAuthentication no\nPermitRootLogin no\nMaxAuthTries 3\n")
		},
		"a claim it does not": func(s *Step) { s.Fixes = append(s.Fixes, "SSH-002") },
		"no validation":       func(s *Step) { s.Edits[0].Validate = nil },
		"another validation":  func(s *Step) { s.Edits[0].Validate = []string{"true"} },
		"another reload":      func(s *Step) { s.Commands[0].Args = []string{"systemctl", "restart", "ssh.socket"} },
		"undo keeps the file": func(s *Step) { s.Undo.Commands = s.Undo.Commands[1:] },
		"no restart named":    func(s *Step) { s.Restarts = nil },
		"a Match block": func(s *Step) {
			setNew(&s.Edits[0], header+"PasswordAuthentication no\nPermitRootLogin no\nMaxAuthTries 3\nMatch all\n")
		},
	} {
		s := cloneStep(base)
		tamper(&s)
		if err := Authorize(s); err == nil {
			t.Errorf("%s: Authorize accepted it", name)
		}
	}
}

// The lockout guard on the drop-in: it needs a non-root sudo account that
// logs in with a key afterwards.
func TestSSHDHardeningGuard(t *testing.T) {
	s := sshdStepOf(t, Input{Facts: cloudFacts(), Results: sshdResults()})
	if _, err := ProveAccess(s, GuardInput{Facts: cloudFacts(), Source: homeAddr}); err != nil {
		t.Errorf("ubuntu (sudo, key) is a second way in: %v", err)
	}
	for name, change := range map[string]func(f *facts.Facts){
		"no key":          func(f *facts.Facts) { f.SSH.Users = nil },
		"no sudo":         func(f *facts.Facts) { f.Users.Sudoers = f.Users.Sudoers[:1]; f.Users.Groups[1].Members = nil },
		"only root":       func(f *facts.Facts) { f.Users.Accounts = f.Users.Accounts[:1] },
		"pubkey off":      func(f *facts.Facts) { f.SSH.Effective["pubkeyauthentication"] = []string{"no"} },
		"not audited":     func(f *facts.Facts) { f.Users = nil },
		"sshd -T unknown": func(f *facts.Facts) { delete(f.SSH.Effective, "usepam") },
	} {
		f := cloneGuardFacts(cloudFacts())
		f.SSH.Effective = map[string][]string{}
		for k, v := range cloudFacts().SSH.Effective {
			f.SSH.Effective[k] = v
		}
		f.Users.Groups = slices.Clone(cloudFacts().Users.Groups)
		f.Users.Groups[1].Members = slices.Clone(f.Users.Groups[1].Members)
		change(f)
		if _, err := ProveAccess(s, GuardInput{Facts: f, Source: homeAddr}); err == nil || !strings.Contains(err.Error(), "lockout guard: sshd-hardening") {
			t.Errorf("%s: %v", name, err)
		}
	}
}
