package checks

import (
	"strings"
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

// When the brute force guard is unknown, CS-010 and SSH-011 say what could
// not be read. The sudo hint only appears when the audit was not root:
// telling root to use sudo sends the reader in circles.
func TestBruteForceGuardUnknownSaysWhat(t *testing.T) {
	present := func(root bool) *facts.Facts {
		f := sshCross(sshHardened(), netSSHAnywhere)
		f.Host = &facts.Host{Root: root}
		// fail2ban-client is there, the server did not answer, systemd
		// does not list the unit.
		f.Fail2ban = &facts.Fail2ban{Installed: true, Unit: &facts.ServiceUnit{LoadState: "not-found"}}
		return f
	}
	for _, id := range []string{"CS-010", "SSH-011"} {
		r := netOne(t, id, present(true), "")
		if r.Level != Unknown || strings.Contains(r.Message, "sudo") ||
			!strings.Contains(r.Message, "fail2ban-client status did not answer") || !strings.Contains(r.Message, "systemd does not list fail2ban.service") {
			t.Errorf("%s as root: %s %q", id, r.Level, r.Message)
		}
		r = netOne(t, id, present(false), "")
		if r.Level != Unknown || !strings.Contains(r.Message, "fail2ban-client status needs root") || !strings.HasSuffix(r.Message, "(run with sudo)") {
			t.Errorf("%s not root: %s %q", id, r.Level, r.Message)
		}
	}
	// A running fail2ban whose jail files could not be read says so.
	f := present(true)
	f.Fail2ban = &facts.Fail2ban{Installed: true, Unit: &facts.ServiceUnit{LoadState: "loaded", ActiveState: "active"}}
	if r := netOne(t, "CS-010", f, ""); r.Level != Unknown || !strings.Contains(r.Message, "jail configuration") || strings.Contains(r.Message, "sudo") {
		t.Errorf("config unread as root: %s %q", r.Level, r.Message)
	}
	// An unread CrowdSec hub is named too.
	f = present(true)
	f.Fail2ban = &facts.Fail2ban{}
	f.CrowdSec = &facts.CrowdSec{Installed: true}
	if r := netOne(t, "CS-010", f, ""); r.Level != Unknown || !strings.Contains(r.Message, "CrowdSec is installed but its collections") {
		t.Errorf("hub unread: %s %q", r.Level, r.Message)
	}
}
