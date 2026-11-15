package checks

import (
	"testing"
	"time"

	"github.com/Shironex/stackward/internal/facts"
	"github.com/Shironex/stackward/internal/profile"
)

var tsNow = time.Date(2026, 3, 1, 12, 0, 0, 0, time.UTC)

func tsRunning() *facts.Tailscale {
	return &facts.Tailscale{Installed: true, StatusRead: true, BackendState: "Running",
		Unit: &facts.ServiceUnit{Name: "tailscaled.service", LoadState: "loaded", ActiveState: "active"}}
}

func tsWith(mut func(*facts.Tailscale)) *facts.Facts {
	t := tsRunning()
	mut(t)
	return &facts.Facts{CollectedAt: tsNow, Tailscale: t}
}

func TestTS001(t *testing.T) {
	netCases(t, "TS-001", []netCase{
		{"no facts", &facts.Facts{}, "", Unknown},
		{"not installed", &facts.Facts{Tailscale: &facts.Tailscale{}}, "", Skip},
		{"running", tsWith(func(*facts.Tailscale) {}), "", Pass},
		{"needs login", tsWith(func(t *facts.Tailscale) { t.BackendState = "NeedsLogin" }), "", Fail},
		{"stopped", tsWith(func(t *facts.Tailscale) { t.BackendState = "Stopped" }), "", Fail},
		{"daemon down", tsWith(func(t *facts.Tailscale) {
			t.StatusRead, t.BackendState = false, ""
			t.Unit.ActiveState = "inactive"
		}), "", Fail},
		{"state unread", tsWith(func(t *facts.Tailscale) { t.StatusRead, t.BackendState = false, "" }), "", Unknown},
		{"starting", tsWith(func(t *facts.Tailscale) { t.BackendState = "Starting" }), "", Unknown},
	})
}

func TestTS002(t *testing.T) {
	soon := tsNow.Add(20 * 24 * time.Hour)
	past := tsNow.Add(-24 * time.Hour)
	netCases(t, "TS-002", []netCase{
		{"no facts", &facts.Facts{}, "", Unknown},
		{"not installed", &facts.Facts{Tailscale: &facts.Tailscale{}}, "", Skip},
		{"disabled", tsWith(func(*facts.Tailscale) {}), "", Pass},
		{"expiring", tsWith(func(t *facts.Tailscale) { t.KeyExpiry = &soon }), "", Fail},
		{"expired", tsWith(func(t *facts.Tailscale) { t.KeyExpiry = &past }), "", Fail},
		{"unread", tsWith(func(t *facts.Tailscale) { t.StatusRead = false }), "", Unknown},
	})
	r := netOne(t, "TS-002", tsWith(func(t *facts.Tailscale) { t.KeyExpiry = &soon }), "")
	if r.Evidence["days_left"] != 20 {
		t.Errorf("days_left = %v", r.Evidence["days_left"])
	}
}

func TestTS003(t *testing.T) {
	netCases(t, "TS-003", []netCase{
		{"no facts", &facts.Facts{}, "", Unknown},
		{"not installed", &facts.Facts{Tailscale: &facts.Tailscale{}}, "", Skip},
		{"unread", tsWith(func(*facts.Tailscale) {}), "", Unknown},
		{"nothing", tsWith(func(t *facts.Tailscale) { t.Serve = &facts.TailscaleServe{} }), "", Pass},
		{"serve", tsWith(func(t *facts.Tailscale) { t.Serve = &facts.TailscaleServe{ServePorts: []int{443}} }), "", Warn},
		{"funnel", tsWith(func(t *facts.Tailscale) {
			t.Serve = &facts.TailscaleServe{ServePorts: []int{443}, FunnelPorts: []int{443}}
		}), "", Fail},
	})
}

func TestTS004(t *testing.T) {
	withRules := func(ts *facts.Tailscale) *facts.Facts {
		return &facts.Facts{Firewall: netUFW("deny", netSSHTailnet), Tailscale: ts}
	}
	netCases(t, "TS-004", []netCase{
		{"no facts", &facts.Facts{}, "", Unknown},
		{"no ufw", &facts.Facts{Firewall: &facts.Firewall{UFW: &facts.UFW{}}}, "", Skip},
		{"no tailscale0 rules", &facts.Facts{Firewall: netUFW("deny", netSSHAnywhere)}, "", Pass},
		{"rules, tailscale facts missing", withRules(nil), "", Unknown},
		{"rules, tailscale absent", withRules(&facts.Tailscale{}), "", Fail},
		{"rules, logged out", withRules(&facts.Tailscale{Installed: true, StatusRead: true, BackendState: "NeedsLogin"}), "", Fail},
		{"rules, state unread", withRules(&facts.Tailscale{Installed: true}), "", Unknown},
		{"rules, running", withRules(tsRunning()), "", Pass},
		{"rules unread", &facts.Facts{Firewall: &facts.Firewall{UFW: &facts.UFW{Installed: true, Source: "files", Status: "active"}}}, "", Unknown},
	})
}

func TestTS005(t *testing.T) {
	on, off := true, false
	netCases(t, "TS-005", []netCase{
		{"no facts", &facts.Facts{}, "", Unknown},
		{"not installed", &facts.Facts{Tailscale: &facts.Tailscale{}}, "", Skip},
		{"unknown", tsWith(func(*facts.Tailscale) {}), "", Unknown},
		{"on", tsWith(func(t *facts.Tailscale) { t.LockEnabled = &on }), "", Info},
		{"off", tsWith(func(t *facts.Tailscale) { t.LockEnabled = &off }), "", Info},
	})
}

// TestNETWithTailscaleFacts proves NET-003 and NET-007 read the real
// Tailscale facts type (no seam): the same host changes verdict when the
// node is Running, logged out, or not installed.
func TestNETWithTailscaleFacts(t *testing.T) {
	publicSSH := &facts.Listeners{Sockets: []facts.Listener{netSock("tcp", "0.0.0.0", 22, "sshd")}}
	loggedOut := &facts.Tailscale{Installed: true, StatusRead: true, BackendState: "NeedsLogin"}
	sshHost := func(ts *facts.Tailscale) *facts.Facts {
		return &facts.Facts{Listeners: publicSSH, Firewall: netUFW("deny", netSSHAnywhere), Tailscale: ts}
	}
	netCases(t, "NET-003", []netCase{
		{"tailscale facts missing", sshHost(nil), "", Unknown},
		{"node running", sshHost(tsRunning()), "", Fail},
		{"node logged out", sshHost(loggedOut), "", Warn},
		{"tailscale not installed", sshHost(&facts.Tailscale{}), "", Warn},
		{"state unread", sshHost(&facts.Tailscale{Installed: true}), "", Unknown},
	})

	ufwDocker := func(ts *facts.Tailscale) *facts.Facts {
		fw := netUFW("deny")
		fw.UFWDocker = &facts.UFWDocker{InFiles: "present", Loaded: "yes"}
		return &facts.Facts{Firewall: fw, Listeners: &facts.Listeners{}, Tailscale: ts}
	}
	netCases(t, "NET-007", []netCase{
		{"tailscale facts missing", ufwDocker(nil), "", Unknown},
		{"node logged out, no route rules needed", ufwDocker(loggedOut), "", Pass},
		{"node running, nothing published seen", ufwDocker(tsRunning()), "", Unknown},
	})

	// Infer reads the same facts through profile.Tailnet.
	f := &facts.Facts{Listeners: &facts.Listeners{}, Tailscale: tsRunning()}
	if p := profile.Infer(f); p != profile.TailnetOnly {
		t.Errorf("Infer = %s, want tailnet-only", p)
	}
}
