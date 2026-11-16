package plan

import (
	"net/netip"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/Shironex/stackward/internal/checks"
	"github.com/Shironex/stackward/internal/facts"
	"github.com/Shironex/stackward/internal/profile"
)

// fwInput loads a firewall plan fixture, lets edit change its facts, and
// evaluates the checks on the result, as plan does.
func fwInput(t *testing.T, name string, prof profile.Name, edit func(f *facts.Facts)) Input {
	t.Helper()
	fh, err := os.Open(filepath.Join("..", "..", "test", "fixtures", name, "facts.json"))
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = fh.Close() }()
	f, err := facts.Load(fh)
	if err != nil {
		t.Fatal(err)
	}
	if edit != nil {
		edit(f)
	}
	return Input{Facts: f, Results: checks.Evaluate(checks.Input{Facts: f, Profile: prof}), Profile: prof}
}

const policyFixture = "plan-firewall-ufw-policy"

// setUserRules replaces the IPv4 rules of a fixture, in the facts and in
// the user.rules text, so the two agree.
func setUserRules(f *facts.Facts, rules []facts.UFWRule, blocks ...string) {
	u := f.Firewall.UFW
	u.Rules = rules
	old := fromTemplate(u.Files[facts.UFWUserRulesPath], false)
	at, err := rulesEnd(old)
	if err != nil {
		panic(err)
	}
	u.Files[facts.UFWUserRulesPath] = old[:at] + strings.Join(blocks, "") + old[at:]
}

func TestUFWPolicyPlansTheRulesBeforeTheDefaultDeny(t *testing.T) {
	in := fwInput(t, policyFixture, profile.Unknown, nil)
	// The fixture holds the templates ufw 0.36 ships, byte for byte.
	if !isUFWTemplate(in.Facts.Firewall.UFW.Files[facts.UFWUserRulesPath], false) || !isUFWTemplate(in.Facts.Firewall.UFW.Files[facts.UFWUser6RulesPath], true) {
		t.Fatal("the fixture's rules files are not ufw's templates")
	}
	out := planUFWPolicy(in)
	if out.Step == nil {
		t.Fatalf("no step: %+v", out)
	}
	s := out.Step
	var paths []string
	for _, e := range s.Edits {
		paths = append(paths, e.Path)
	}
	// The rules first, ufw.conf last; /etc/default/ufw already says DROP.
	if !slices.Equal(paths, []string{facts.UFWUserRulesPath, facts.UFWUser6RulesPath, facts.UFWConfPath}) {
		t.Errorf("edits %v", paths)
	}
	for _, want := range []string{"allow tcp 22 0.0.0.0/0", "allow tcp 2222 0.0.0.0/0", "in_tailscale0"} {
		if !strings.Contains(s.Edits[0].New, want) {
			t.Errorf("user.rules lacks %q", want)
		}
	}
	if !slices.Equal(s.Edits[0].Validate, ufwTest4) || !slices.Equal(s.Edits[1].Validate, ufwTest6) {
		t.Errorf("validate %v %v", s.Edits[0].Validate, s.Edits[1].Validate)
	}
	if len(s.Commands) != 1 || !slices.Equal(s.Commands[0].Args, ufwEnable) || !slices.Equal(s.Undo.Commands[0].Args, ufwDisable) {
		t.Errorf("commands %+v undo %+v", s.Commands, s.Undo.Commands)
	}
	if !strings.Contains(strings.Join(s.Notes, "\n"), "tcp/5432 (postgres)") {
		t.Errorf("the closed services are not listed: %v", s.Notes)
	}
	if err := authorizeUFWPolicy(complete(mustLookup(t, UFWPolicyID), *s)); err != nil {
		t.Errorf("its own step is refused: %v", err)
	}
	a := accessUFWPolicy(*s)
	if a.Firewall == nil || !a.Firewall.TurnsOn || len(a.Firewall.Adds) != 6 {
		t.Errorf("access %+v", a.Firewall)
	}
}

func TestUFWPolicySkips(t *testing.T) {
	cases := map[string]struct {
		prof profile.Name
		edit func(f *facts.Facts)
		kind string
		want string
	}{
		"report alone":      {edit: nil, kind: SkipUnknown},
		"passes":            {edit: func(f *facts.Facts) { f.Firewall.UFW.Status, f.Firewall.UFW.Enabled = "active", "yes" }, kind: SkipPassing},
		"not root":          {edit: func(f *facts.Facts) { f.Firewall.UFW.Source = "files" }, kind: SkipUnknown},
		"no ufw":            {edit: func(f *facts.Facts) { f.Firewall.UFW = &facts.UFW{} }, kind: SkipManual, want: "not installed"},
		"enabled not run":   {edit: func(f *facts.Facts) { f.Firewall.UFW.Enabled = "yes" }, kind: SkipManual, want: "ENABLED=yes"},
		"no sshd port":      {edit: func(f *facts.Facts) { f.SSH = nil; f.Listeners.Sockets = f.Listeners.Sockets[3:] }, kind: SkipUnknown, want: "does not assume 22"},
		"no user.rules":     {edit: func(f *facts.Facts) { delete(f.Firewall.UFW.Files, facts.UFWUserRulesPath) }, kind: SkipUnknown, want: "user.rules"},
		"odd user.rules":    {edit: func(f *facts.Facts) { f.Firewall.UFW.Files[facts.UFWUserRulesPath] = "*filter\nCOMMIT\n" }, kind: SkipManual, want: "RULES section"},
		"web needs profile": {edit: addWebListener, kind: SkipManual, want: "--profile"},
		"template, log level off": {edit: func(f *facts.Facts) {
			u := f.Firewall.UFW
			u.Files[facts.UFWConfPath] = strings.Replace(u.Files[facts.UFWConfPath], "LOGLEVEL=low", "LOGLEVEL=off", 1)
		}, kind: SkipManual, want: "log level"},
		"ssh denied": {edit: func(f *facts.Facts) {
			setUserRules(f, []facts.UFWRule{{Action: "deny", Direction: "in", Port: "22", Proto: "tcp"}},
				"### tuple ### deny tcp 22 0.0.0.0/0 any 0.0.0.0/0 in\n-A ufw-user-input -p tcp --dport 22 -j DROP\n\n")
		}, kind: SkipManual, want: "denies SSH"},
		"restricted ssh on a panel host": {edit: func(f *facts.Facts) {
			restrictSSH(f)
			f.PaaS = &facts.PaaS{Platforms: []facts.Platform{{Name: facts.PlatformCoolify, Role: facts.RolePanel, DataRoot: facts.CoolifyRoot}}}
		}, kind: SkipManual, want: "PaaS panel"},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			in := fwInput(t, policyFixture, tc.prof, tc.edit)
			if name == "report alone" {
				in.Facts = nil
			}
			out := planUFWPolicy(in)
			if out.Step != nil || out.Kind != tc.kind || !strings.Contains(out.Reason, tc.want) {
				t.Errorf("got %+v, want %s containing %q", out, tc.kind, tc.want)
			}
		})
	}
}

func addWebListener(f *facts.Facts) {
	f.Listeners.Sockets = append(f.Listeners.Sockets, facts.Listener{Proto: "tcp", Address: "0.0.0.0", Port: 443, Processes: []string{"caddy"}})
}

func restrictSSH(f *facts.Facts) {
	setUserRules(f, []facts.UFWRule{
		{Action: "allow", Direction: "in", Port: "22", Proto: "tcp", From: "198.51.100.0/24"},
		{Action: "allow", Direction: "in", Port: "2222", Proto: "tcp", From: "198.51.100.0/24"},
	},
		"### tuple ### allow tcp 22 0.0.0.0/0 any 198.51.100.0/24 in\n-A ufw-user-input -p tcp --dport 22 -s 198.51.100.0/24 -j ACCEPT\n\n",
		"### tuple ### allow tcp 2222 0.0.0.0/0 any 198.51.100.0/24 in\n-A ufw-user-input -p tcp --dport 2222 -s 198.51.100.0/24 -j ACCEPT\n\n")
}

func TestUFWPolicyFollowsTheProfileForWebPorts(t *testing.T) {
	pub := planUFWPolicy(fwInput(t, policyFixture, profile.PublicWeb, addWebListener))
	if pub.Step == nil || !strings.Contains(pub.Step.Edits[0].New, "allow tcp 443 0.0.0.0/0") {
		t.Fatalf("public-web keeps 443: %+v", pub)
	}
	tun := planUFWPolicy(fwInput(t, policyFixture, profile.Tunnel, addWebListener))
	if tun.Step == nil || strings.Contains(tun.Step.Edits[0].New, "443") || !strings.Contains(strings.Join(tun.Step.Notes, " "), "tcp/443 (caddy)") {
		t.Fatalf("a tunnel host closes 443: %+v", tun)
	}
}

func TestUFWPolicyKeepsRestrictedSSHAsItIs(t *testing.T) {
	out := planUFWPolicy(fwInput(t, policyFixture, profile.Unknown, restrictSSH))
	if out.Step == nil {
		t.Fatalf("no step: %+v", out)
	}
	if strings.Contains(out.Step.Edits[0].New, "allow tcp 22 0.0.0.0/0 any 0.0.0.0/0") {
		t.Error("public SSH was opened although the rules restrict it")
	}
	if !strings.Contains(strings.Join(out.Step.Notes, " "), "Public SSH closes") {
		t.Errorf("notes %v", out.Step.Notes)
	}
}

func TestUFWPolicyReloadsAnActiveUFWWithAnAllowDefault(t *testing.T) {
	out := planUFWPolicy(fwInput(t, policyFixture, profile.Unknown, func(f *facts.Facts) {
		u := f.Firewall.UFW
		u.Status, u.Enabled, u.DefaultIncoming = "active", "yes", "allow"
		u.Files[facts.UFWDefaultPath] = strings.Replace(u.Files[facts.UFWDefaultPath], `DEFAULT_INPUT_POLICY="DROP"`, `DEFAULT_INPUT_POLICY="ACCEPT"`, 1)
		u.Files[facts.UFWConfPath] = strings.Replace(u.Files[facts.UFWConfPath], "ENABLED=no", "ENABLED=yes", 1)
	}))
	if out.Step == nil {
		t.Fatalf("no step: %+v", out)
	}
	s := out.Step
	last := s.Edits[len(s.Edits)-1]
	if last.Path != facts.UFWDefaultPath || !strings.Contains(last.New, `DEFAULT_INPUT_POLICY="DROP"`) || strings.Count(last.Diff, "\n+") != 2 {
		t.Errorf("default edit %+v", last)
	}
	if !slices.Equal(s.Commands[0].Args, ufwReload) || !slices.Equal(s.Undo.Commands[0].Args, ufwReload) {
		t.Errorf("commands %+v", s)
	}
	if err := authorizeUFWPolicy(*s); err != nil {
		t.Errorf("refused: %v", err)
	}
	if a := accessUFWPolicy(*s); a.Firewall.TurnsOn {
		t.Error("a reload does not turn UFW on")
	}
}

func TestUFWPolicyAuthorizeRefusesTampering(t *testing.T) {
	base := *planUFWPolicy(fwInput(t, policyFixture, profile.Unknown, nil)).Step
	rehash := func(e *FileEdit) { e.NewSHA256 = sha(e.New) }
	for name, tc := range map[string]struct {
		tamper func(s *Step)
		want   string
	}{
		"deny rule": {func(s *Step) {
			s.Edits[0].New = strings.Replace(s.Edits[0].New, "### tuple ### allow tcp 22", "### tuple ### deny tcp 22", 1)
			rehash(&s.Edits[0])
		}, "does not allow"},
		"rule from a source": {func(s *Step) {
			s.Edits[0].New = strings.Replace(s.Edits[0].New, "-A ufw-user-input -p tcp --dport 22 -j ACCEPT", "-A ufw-user-input -p tcp --dport 22 -s 203.0.113.9 -j ACCEPT", 1)
			rehash(&s.Edits[0])
		}, "not one the step adds"},
		"route rule": {func(s *Step) {
			s.Edits[0].New = strings.Replace(s.Edits[0].New, "### tuple ### allow tcp 22 0.0.0.0/0 any 0.0.0.0/0 in\n-A ufw-user-input -p tcp --dport 22 -j ACCEPT",
				"### tuple ### route:allow tcp 22 0.0.0.0/0 any 0.0.0.0/0 in\n-A ufw-user-forward -p tcp --dport 22 -j ACCEPT", 1)
			rehash(&s.Edits[0])
		}, "not one the step adds"},
		"rule removed": {func(s *Step) {
			s.Edits[0].Old = strings.Replace(ufwEmptyRules(false), "### RULES ###\n\n", "### RULES ###\n\n### tuple ### allow tcp 80 0.0.0.0/0 any 0.0.0.0/0 in\n-A ufw-user-input -p tcp --dport 80 -j ACCEPT\n\n", 1)
			s.Edits[0].OldSHA256 = sha(s.Edits[0].Old)
		}, "not rules added"},
		"no validate": {func(s *Step) { s.Edits[0].Validate = nil }, "validate"},
		"forward policy": {func(s *Step) {
			s.Edits = append(s.Edits, newEdit(facts.UFWDefaultPath, Replace, "", "DEFAULT_FORWARD_POLICY=\"DROP\"\n", "DEFAULT_FORWARD_POLICY=\"ACCEPT\"\n"))
		}, "DEFAULT_INPUT_POLICY"},
		"conf value": {func(s *Step) {
			e := &s.Edits[2]
			e.New = strings.Replace(e.New, "LOGLEVEL=low", "LOGLEVEL=off", 1)
			rehash(e)
		}, "not what the step writes"},
		"other file":    {func(s *Step) { s.Edits[2].Path = "/etc/ufw/before.rules" }, "only edits"},
		"reload shape":  {func(s *Step) { s.Commands[0].Args, s.Undo.Commands[0].Args = ufwReload, ufwReload }, "not one the step runs"},
		"reset on undo": {func(s *Step) { s.Undo.Commands[0].Args = []string{"ufw", "--force", "reset"} }, "not one the step runs"},
		"create":        {func(s *Step) { s.Edits[2].Action = Create }, "only replaces"},
	} {
		t.Run(name, func(t *testing.T) {
			s := base
			s.Edits = slices.Clone(base.Edits)
			s.Commands = slices.Clone(base.Commands)
			s.Undo.Commands = slices.Clone(base.Undo.Commands)
			tc.tamper(&s)
			if err := authorizeUFWPolicy(s); err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Errorf("err %v, want %q", err, tc.want)
			}
		})
	}
}

func TestUFWAddsRoundTrip(t *testing.T) {
	for _, r := range []ufwAdd{
		{proto: "tcp", port: 22}, {proto: "tcp", port: 22, v6: true}, {proto: "any", iface: tailnetIface},
		{route: true, proto: "udp", port: 51820}, {route: true, proto: "any", iface: tailnetIface},
	} {
		got, err := parseAdd(r.tuple(), r.v6)
		if err != nil || got != r {
			t.Errorf("%+v: got %+v %v", r, got, err)
		}
		fr := r.fact()
		if fr.Action != "allow" || (r.port > 0 && !fr.MatchesPort(r.proto, r.port)) || fr.Interface != r.iface {
			t.Errorf("%+v parses back as %+v", r, fr)
		}
	}
	if (ufwAdd{proto: "udp", port: 53}).shapeOK(false) {
		t.Error("an input rule for udp is not a shape ufw-policy adds")
	}
}

// The guard for ufw-policy: from the plan's own facts it proves SSH from
// anywhere, so a session from anywhere (or the console) passes.
func TestUFWPolicyPassesTheGuardFromItsFacts(t *testing.T) {
	in := fwInput(t, policyFixture, profile.Unknown, nil)
	s := complete(mustLookup(t, UFWPolicyID), *planUFWPolicy(in).Step)
	for _, src := range []string{"", "192.0.2.10", "2001:db8:1::5", "100.100.1.2"} {
		var a netip.Addr
		if src != "" {
			a = netip.MustParseAddr(src)
		}
		p, err := ProveAccess(s, GuardInput{Facts: in.Facts, Source: a})
		if err != nil || !p.Needed || len(p.Ways) != 2 || len(p.ConfirmFrom) != 0 {
			t.Errorf("source %q: %+v %v", src, p, err)
		}
	}
}
