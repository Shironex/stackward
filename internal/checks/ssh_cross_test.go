package checks

import (
	"testing"

	"github.com/Shironex/stackward/internal/facts"
	"github.com/Shironex/stackward/internal/facts/sshd"
)

// sshCross builds facts for the SSH checks that join other collectors:
// sshd on 0.0.0.0:22, UFW with the given rules, and the given SSH facts.
func sshCross(s *facts.SSH, rules ...facts.UFWRule) *facts.Facts {
	return &facts.Facts{
		SSH:       s,
		Listeners: &facts.Listeners{Sockets: []facts.Listener{netSock("tcp", "0.0.0.0", 22, "sshd")}},
		Firewall:  netUFW("deny", rules...),
		CrowdSec:  csAbsent,
		Fail2ban:  &facts.Fail2ban{},
	}
}

func sshJail(f *facts.Facts) *facts.Facts {
	f.Fail2ban = &facts.Fail2ban{Installed: true, StatusRead: true, ActiveJails: []string{"sshd"}, ConfigRead: true,
		Jails: []facts.Fail2banJail{{Name: "sshd", Enabled: true, Port: "ssh"}}}
	return f
}

func TestSSH011(t *testing.T) {
	noFirewall := sshCross(sshHardened())
	noFirewall.Firewall = nil
	notRoot := sshCross(sshHardened(), netSSHAnywhere)
	notRoot.Firewall.UFW.Source, notRoot.Firewall.UFW.RulesKnown = "files", false
	unknownGuard := sshCross(sshHardened(), netSSHAnywhere)
	unknownGuard.Fail2ban = nil
	kbd2FA := sshWith(sshHardened(), "kbdinteractiveauthentication", "yes")
	kbd2FA.PAM2FA = []string{"pam_google_authenticator"}

	netCases(t, "SSH-011", []netCase{
		{"no facts", &facts.Facts{}, "", Unknown},
		{"no openssh", &facts.Facts{SSH: &facts.SSH{}}, "", Skip},
		{"firewall missing", noFirewall, "", Unknown},
		{"tailnet only", sshCross(sshWith(sshHardened(), "passwordauthentication", "yes"), netSSHTailnet), "", Pass},
		{"public with passwords", sshCross(sshWith(sshHardened(), "passwordauthentication", "yes"), netSSHAnywhere), "", Fail},
		{"public with kbd-interactive", sshCross(sshWith(sshHardened(), "kbdinteractiveauthentication", "yes"), netSSHAnywhere), "", Fail},
		{"public, kbd with a second factor, no jail", sshCross(kbd2FA, netSSHAnywhere), "", Warn},
		{"public, keys only, no jail", sshCross(sshHardened(), netSSHAnywhere), "", Warn},
		{"public, keys only, jail", sshJail(sshCross(sshHardened(), netSSHAnywhere)), "", Pass},
		{"public, keys only, guard unknown", unknownGuard, "", Unknown},
		{"public, password unknown", sshCross(sshNonRoot(), netSSHAnywhere), "", Unknown},
		{"rules unreadable", notRoot, "", Unknown},
	})
}

func TestSSH011MatchAllCounts(t *testing.T) {
	s := sshHardened()
	s.Config.Directives = []sshd.Directive{{Keyword: "passwordauthentication", Value: "yes", Match: 1, File: "/etc/ssh/sshd_config", Line: 40}}
	s.Config.Matches = []sshd.Match{{Criteria: "all"}}
	if r := netOne(t, "SSH-011", sshCross(s, netSSHAnywhere), ""); r.Level != Fail {
		t.Errorf("Match all with passwords: got %s (%s)", r.Level, r.Message)
	}
}

func TestSSH016(t *testing.T) {
	on, off := true, false
	ts := func(ssh *bool) *facts.Tailscale {
		return &facts.Tailscale{Installed: true, StatusRead: true, BackendState: "Running", SSH: ssh}
	}
	with := func(t *facts.Tailscale, s *facts.SSH) *facts.Facts { return &facts.Facts{Tailscale: t, SSH: s} }
	quiet := sshHardened()
	quiet.Listening = nil
	netCases(t, "SSH-016", []netCase{
		{"no facts", &facts.Facts{}, "", Unknown},
		{"tailscale absent", with(&facts.Tailscale{}, sshHardened()), "", Skip},
		{"prefs unread", with(ts(nil), sshHardened()), "", Unknown},
		{"tailscale ssh off", with(ts(&off), sshHardened()), "", Pass},
		{"both on", with(ts(&on), sshHardened()), "", Warn},
		{"tailscale ssh only", with(ts(&on), &facts.SSH{}), "", Pass},
		{"openssh not listening", with(ts(&on), quiet), "", Pass},
		{"ssh facts missing", with(ts(&on), nil), "", Unknown},
	})
}
