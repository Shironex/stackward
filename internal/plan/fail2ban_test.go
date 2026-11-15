package plan

import (
	"net/netip"
	"slices"
	"strings"
	"testing"

	"github.com/Shironex/stackward/internal/checks"
	"github.com/Shironex/stackward/internal/facts"
)

func runningFail2ban(ignore ...string) *facts.Fail2ban {
	return &facts.Fail2ban{
		Installed: true, StatusRead: true, ActiveJails: []string{"recidive"}, ConfigRead: true,
		Unit:  &facts.ServiceUnit{Name: "fail2ban.service", LoadState: "loaded", ActiveState: "active", SubState: "running"},
		Jails: []facts.Fail2banJail{{Name: "sshd", Port: "ssh", IgnoreIP: ignore}},
	}
}

func jailFacts(f2b *facts.Fail2ban, tailscale bool, sshPorts ...int) *facts.Facts {
	l := &facts.Listeners{}
	for _, p := range sshPorts {
		l.Sockets = append(l.Sockets, facts.Listener{Proto: "tcp", Address: "0.0.0.0", Port: p, Processes: []string{"sshd"}})
	}
	return &facts.Facts{Fail2ban: f2b, Listeners: l, Tailscale: &facts.Tailscale{Installed: tailscale}}
}

var cs010Fail = map[string]checks.Level{"CS-010": checks.Fail}

func TestFail2banSSHDPlanCases(t *testing.T) {
	// SSH not public, or already protected: CS-010 passes, no step.
	if out := planFail2banSSHD(Input{Facts: jailFacts(runningFail2ban(), false, 22), Results: results(map[string]checks.Level{"CS-010": checks.Pass})}); out.Step != nil || out.Kind != SkipPassing {
		t.Fatalf("not public: %+v", out)
	}
	// Unknown: no step and a reason.
	for name, in := range map[string]Input{
		"report alone":  {Results: results(cs010Fail)},
		"no fail2ban":   {Facts: &facts.Facts{Listeners: &facts.Listeners{}, Tailscale: &facts.Tailscale{}}, Results: results(cs010Fail)},
		"no tailscale":  {Facts: &facts.Facts{Fail2ban: runningFail2ban(), Listeners: &facts.Listeners{}}, Results: results(cs010Fail)},
		"check unknown": {Facts: jailFacts(runningFail2ban(), false, 22), Results: results(map[string]checks.Level{"CS-010": checks.Unknown})},
		"config unread": {Facts: jailFacts(&facts.Fail2ban{Installed: true, StatusRead: true}, false, 22), Results: results(cs010Fail)},
	} {
		if out := planFail2banSSHD(in); out.Step != nil || out.Kind != SkipUnknown || out.Reason == "" {
			t.Errorf("%s: %+v", name, out)
		}
	}
	// A jail on the wrong port, or a stopped fail2ban: a person decides.
	if out := planFail2banSSHD(Input{Facts: jailFacts(runningFail2ban(), false, 22), Results: results(map[string]checks.Level{"CS-010": checks.Warn})}); out.Kind != SkipManual {
		t.Errorf("wrong port: %+v", out)
	}
	stopped := runningFail2ban()
	stopped.StatusRead, stopped.Unit.ActiveState = false, "inactive"
	if out := planFail2banSSHD(Input{Facts: jailFacts(stopped, false, 22), Results: results(cs010Fail)}); out.Kind != SkipManual {
		t.Errorf("stopped: %+v", out)
	}
	if out := planFail2banSSHD(Input{Facts: jailFacts(runningFail2ban("127.0.0.1/8", "office.example.com"), false, 22), Results: results(cs010Fail)}); out.Kind != SkipManual {
		t.Errorf("a host name in ignoreip: %+v", out)
	}
}

func TestFail2banSSHDJailContent(t *testing.T) {
	src := netip.MustParseAddr("203.0.113.7")
	in := Input{Facts: jailFacts(runningFail2ban("127.0.0.1/8", "::1", "198.51.100.0/24"), true, 2222, 22), Results: results(map[string]checks.Level{"CS-010": checks.Fail, "SSH-011": checks.Warn}), Source: src}
	out := planFail2banSSHD(in)
	if out.Step == nil {
		t.Fatalf("fail: %+v", out)
	}
	s := out.Step
	want := f2bHeadText + "[sshd]\nenabled = true\nport = 22,2222\n" +
		"ignoreip = 127.0.0.1/8 ::1 198.51.100.0/24 100.64.0.0/10 fd7a:115c:a1e0::/48 203.0.113.7\n"
	if e := s.Edits[0]; e.Path != f2bDropin || e.Action != Create || e.New != want {
		t.Errorf("edit %s %s:\n%s", e.Path, e.Action, e.New)
	}
	if got := argsOf(s.Commands); !slices.EqualFunc(got, [][]string{f2bTest, f2bReload}, slices.Equal) {
		t.Errorf("commands %v", got)
	}
	if got := argsOf(s.Undo.Commands); !slices.EqualFunc(got, [][]string{f2bRemove, f2bReload}, slices.Equal) {
		t.Errorf("undo %v", got)
	}
	if !slices.Equal(s.Fixes, []string{"CS-010", "SSH-011"}) {
		t.Errorf("fixes %v", s.Fixes)
	}
	if !strings.Contains(strings.Join(s.Notes, "\n"), "never bans 203.0.113.7") {
		t.Errorf("notes: %v", s.Notes)
	}
	g := mustLookup(t, "fail2ban-sshd")
	if g.Risk != AccessCritical || !g.OptIn {
		t.Errorf("risk %s opt in %v", g.Risk, g.OptIn)
	}
	if err := Authorize(complete(g, *s)); err != nil {
		t.Errorf("its own step refused: %v", err)
	}

	// A source the tailnet already covers is not repeated; no Tailscale,
	// no tailnet entries.
	in.Source = netip.MustParseAddr("100.101.102.103")
	if out := planFail2banSSHD(in); strings.Contains(out.Step.Edits[0].New, "100.101.102.103") {
		t.Errorf("covered source repeated:\n%s", out.Step.Edits[0].New)
	}
	in.Facts.Tailscale.Installed, in.Source = false, netip.Addr{}
	out = planFail2banSSHD(in)
	if e := out.Step.Edits[0].New; strings.Contains(e, "100.64.0.0/10") || !strings.HasSuffix(e, "ignoreip = 127.0.0.1/8 ::1 198.51.100.0/24\n") {
		t.Errorf("no tailscale, no source:\n%s", e)
	}
	if !strings.Contains(strings.Join(out.Step.Notes, "\n"), "No SSH client address was known") {
		t.Errorf("no note on the missing source: %v", out.Step.Notes)
	}
}

func TestFail2banSSHDInstallShape(t *testing.T) {
	out := planFail2banSSHD(Input{Facts: jailFacts(&facts.Fail2ban{}, false), Results: results(cs010Fail)})
	if out.Step == nil {
		t.Fatalf("not installed: %+v", out)
	}
	if got := argsOf(out.Step.Commands); !slices.EqualFunc(got, [][]string{f2bInstall, f2bTest, f2bRestart}, slices.Equal) {
		t.Errorf("commands %v", got)
	}
	if got := argsOf(out.Step.Undo.Commands); !slices.EqualFunc(got, [][]string{f2bRemove, f2bPurge}, slices.Equal) {
		t.Errorf("undo %v", got)
	}
	if !strings.Contains(out.Step.Edits[0].New, "enabled = true\nbackend = systemd\nport = 22\n") {
		t.Errorf("default port, journal backend:\n%s", out.Step.Edits[0].New)
	}
	// The journal backend belongs to the install shape only.
	s := complete(mustLookup(t, "fail2ban-sshd"), *out.Step)
	s = cloneStep(s)
	s.Commands, s.Undo.Commands = s.Commands[1:], []Command{cmd("", f2bRemove...), cmd("", f2bReload...)}
	s.Commands[1] = cmd("", f2bReload...)
	if err := Authorize(s); err == nil {
		t.Error("a journal backend jail without the install was accepted")
	}
	if err := Authorize(complete(mustLookup(t, "fail2ban-sshd"), *out.Step)); err != nil {
		t.Errorf("its own step refused: %v", err)
	}
}

func TestFail2banSSHDAuthorizeRefusesTampering(t *testing.T) {
	in := Input{Facts: jailFacts(runningFail2ban(), true, 22), Results: results(cs010Fail), Source: netip.MustParseAddr("203.0.113.7")}
	base := complete(mustLookup(t, "fail2ban-sshd"), *planFail2banSSHD(in).Step)
	edit := func(f func(string) string) func(s *Step) {
		return func(s *Step) {
			s.Edits[0].New = f(s.Edits[0].New)
			s.Edits[0].NewSHA256 = sha(s.Edits[0].New)
		}
	}
	for name, tamper := range map[string]func(s *Step){
		"extra option": edit(func(c string) string { return c + "bantime = -1\n" }),
		"no loopback":  edit(func(c string) string { return strings.Replace(c, "127.0.0.1/8 ::1 ", "", 1) }),
		"host name":    edit(func(c string) string { return c[:len(c)-1] + " evil.example.com\n" }),
		"port zero":    edit(func(c string) string { return strings.Replace(c, "port = 22", "port = 0", 1) }),
		"port range":   edit(func(c string) string { return strings.Replace(c, "port = 22", "port = 0:65535", 1) }),
		"other jail":   edit(func(c string) string { return strings.Replace(c, "[sshd]", "[recidive]", 1) }),
		"duplicate":    edit(func(c string) string { return c[:len(c)-1] + " ::1\n" }),
		"command":      func(s *Step) { s.Commands[1].Args = []string{"systemctl", "stop", "ssh"} },
		"install":      func(s *Step) { s.Commands = append([]Command{cmd("", f2bInstall...)}, s.Commands...) },
		"undo":         func(s *Step) { s.Undo.Commands[1].Args = f2bPurge },
		"validate":     func(s *Step) { s.Edits[0].Validate = []string{"sh", "-c"} },
		"restarts":     func(s *Step) { s.Restarts = nil },
		"risk":         func(s *Step) { s.Risk = Safe },
	} {
		s := cloneStep(base)
		tamper(&s)
		if err := Authorize(s); err == nil {
			t.Errorf("%s: tampered step accepted", name)
		}
	}
}

func TestFail2banSSHDLockoutGuard(t *testing.T) {
	src := netip.MustParseAddr("203.0.113.7")
	in := Input{Facts: jailFacts(runningFail2ban(), true, 22), Results: results(cs010Fail), Source: src}
	s := complete(mustLookup(t, "fail2ban-sshd"), *planFail2banSSHD(in).Step)
	if !NeedsProof(s) {
		t.Fatal("a jail that bans needs the guard before the transaction")
	}
	for name, tc := range map[string]struct {
		source netip.Addr
		ok     bool
	}{
		"the planning session":   {src, true},
		"over the tailnet":       {netip.MustParseAddr("100.100.1.2"), true},
		"loopback":               {netip.MustParseAddr("127.0.0.1"), true},
		"mapped planning source": {netip.MustParseAddr("::ffff:203.0.113.7"), true},
		"the console (unknown)":  {netip.Addr{}, true},
		"another address":        {netip.MustParseAddr("198.51.100.9"), false},
	} {
		p, err := ProveAccess(s, GuardInput{Facts: in.Facts, Source: tc.source})
		if (err == nil) != tc.ok {
			t.Errorf("%s: err %v, want ok %v", name, err, tc.ok)
		}
		if err != nil && !strings.Contains(err.Error(), "plan again from this session") {
			t.Errorf("%s: %v", name, err)
		}
		if p.Needed {
			t.Errorf("%s: the jail narrows no way in, yet the proof is needed: %+v", name, p)
		}
	}
	// At plan time the veto passes for the session the plan is made from.
	if reason := LockoutVeto(GuardInput{Facts: in.Facts, Source: src})(s); reason != "" {
		t.Errorf("plan time veto: %s", reason)
	}
}
