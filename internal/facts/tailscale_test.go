package facts

import (
	"context"
	"testing"
	"time"
)

const tsUnitKey = "systemctl show tailscaled.service --property=" + unitProperties

func unitShow(load, active, file string) CmdResult {
	return CmdResult{Stdout: []byte("LoadState=" + load + "\nActiveState=" + active + "\nSubState=running\nUnitFileState=" + file + "\n")}
}

// tsStatusJSON is trimmed `tailscale status --json` output with documentation
// values: peers and addresses are present to prove they are ignored.
const tsStatusJSON = `{
  "Version": "1.80.0-t0000000-g0000000",
  "BackendState": "Running",
  "TailscaleIPs": ["100.101.102.103"],
  "Self": {"ID": "n1", "HostName": "edge1", "DNSName": "edge1.example.com.", "TailscaleIPs": ["100.101.102.103"], "Online": true, "KeyExpiry": "2026-09-01T00:00:00Z"},
  "Peer": {"nodekey:abc": {"HostName": "laptop", "TailscaleIPs": ["100.100.1.2"]}}
}`

func TestTailscaleCollectorRunning(t *testing.T) {
	sys := newFakeSystem(nil)
	sys.cmds[tsUnitKey] = unitShow("loaded", "active", "enabled")
	sys.cmds["tailscale status --json"] = CmdResult{Stdout: []byte(tsStatusJSON)}
	sys.cmds["tailscale serve status --json"] = CmdResult{Stdout: []byte(`{"TCP":{"443":{"HTTPS":true}},"Web":{"edge1.example.com:443":{"Handlers":{"/":{"Proxy":"http://127.0.0.1:3000"}}}},"AllowFunnel":{"edge1.example.com:443":true}}`)}
	sys.cmds["tailscale lock status --json"] = CmdResult{Stdout: []byte(`{"Enabled":false}`)}

	out := &Facts{}
	if err := (tailscaleCollector{}).Collect(context.Background(), sys, out); err != nil {
		t.Fatal(err)
	}
	ts := out.Tailscale
	if !ts.Installed || !ts.StatusRead || ts.BackendState != "Running" || ts.Version == "" {
		t.Fatalf("status not read: %+v", ts)
	}
	if ts.KeyExpiry == nil || !ts.KeyExpiry.Equal(time.Date(2026, 9, 1, 0, 0, 0, 0, time.UTC)) {
		t.Errorf("key expiry: %v", ts.KeyExpiry)
	}
	if ts.Serve == nil || len(ts.Serve.FunnelPorts) != 1 || ts.Serve.FunnelPorts[0] != 443 || len(ts.Serve.ServePorts) != 1 {
		t.Errorf("serve: %+v", ts.Serve)
	}
	if ts.LockEnabled == nil || *ts.LockEnabled {
		t.Errorf("lock: %v", ts.LockEnabled)
	}
	if r, k := ts.TailnetRunning(); !r || !k {
		t.Errorf("TailnetRunning = %v %v", r, k)
	}
}

func TestTailscaleCollectorStates(t *testing.T) {
	// Logged out: JSON with NeedsLogin and no key expiry.
	sys := newFakeSystem(nil)
	sys.cmds[tsUnitKey] = unitShow("loaded", "active", "enabled")
	sys.cmds["tailscale status --json"] = CmdResult{Stdout: []byte(`{"BackendState":"NeedsLogin","Self":{"Online":false}}`)}
	out := &Facts{}
	if err := (tailscaleCollector{}).Collect(context.Background(), sys, out); err != nil {
		t.Fatal(err)
	}
	if r, k := out.Tailscale.TailnetRunning(); r || !k || out.Tailscale.State() != "NeedsLogin" {
		t.Errorf("NeedsLogin: %+v", out.Tailscale)
	}

	// tailscaled stopped: status fails to connect, unit inactive.
	sys = newFakeSystem(nil)
	sys.cmds[tsUnitKey] = unitShow("loaded", "inactive", "disabled")
	sys.cmds["tailscale status --json"] = CmdResult{Stderr: []byte("failed to connect to local tailscaled; it doesn't appear to be running"), ExitCode: 1}
	out = &Facts{}
	if err := (tailscaleCollector{}).Collect(context.Background(), sys, out); err != nil {
		t.Fatalf("a stopped daemon is a state, not an error: %v", err)
	}
	if out.Tailscale.State() != "DaemonStopped" {
		t.Errorf("state = %q", out.Tailscale.State())
	}

	// Status fails while the unit claims active: unknown, with an error.
	sys = newFakeSystem(nil)
	sys.cmds[tsUnitKey] = unitShow("loaded", "active", "enabled")
	sys.cmds["tailscale status --json"] = CmdResult{Stderr: []byte("permission denied"), ExitCode: 1}
	out = &Facts{}
	if err := (tailscaleCollector{}).Collect(context.Background(), sys, out); err == nil {
		t.Error("want an error")
	}
	if _, k := out.Tailscale.TailnetRunning(); k {
		t.Error("unread state must be unknown")
	}

	// Not installed: no command and systemd knows no such unit.
	sys = newFakeSystem(nil)
	sys.cmds[tsUnitKey] = unitShow("not-found", "inactive", "")
	out = &Facts{}
	if err := (tailscaleCollector{}).Collect(context.Background(), sys, out); err != nil {
		t.Fatal(err)
	}
	if out.Tailscale == nil || out.Tailscale.Installed {
		t.Errorf("absent: %+v", out.Tailscale)
	}
	if r, k := out.Tailscale.TailnetRunning(); r || !k {
		t.Error("not installed must be a known no")
	}
}

func TestParseTailscaleServe(t *testing.T) {
	for _, empty := range []string{"", "{}", "No serve config\n"} {
		s, err := ParseTailscaleServe([]byte(empty))
		if err != nil || len(s.ServePorts)+len(s.FunnelPorts) != 0 {
			t.Errorf("%q: %+v %v", empty, s, err)
		}
	}
	fg := `{"Foreground":{"session1":{"TCP":{"8443":{"HTTPS":true}},"AllowFunnel":{"edge1.example.com:8443":true}}}}`
	s, err := ParseTailscaleServe([]byte(fg))
	if err != nil || len(s.FunnelPorts) != 1 || s.FunnelPorts[0] != 8443 {
		t.Errorf("foreground: %+v %v", s, err)
	}
	if _, err := ParseTailscaleServe([]byte("{broken")); err == nil {
		t.Error("broken JSON accepted")
	}
}

func TestParseTailscaleLock(t *testing.T) {
	if v := parseTailscaleLock([]byte("Tailnet Lock is NOT enabled.\n")); v == nil || *v {
		t.Errorf("text off: %v", v)
	}
	if v := parseTailscaleLock([]byte("Tailnet Lock is ENABLED.\n")); v == nil || !*v {
		t.Errorf("text on: %v", v)
	}
	if v := parseTailscaleLock([]byte("garbage")); v != nil {
		t.Errorf("garbage: %v", *v)
	}
}

func TestScanProcs(t *testing.T) {
	sys := newFakeSystem(map[string]string{
		"/proc/1/comm":      "systemd\n",
		"/proc/42/comm":     "cloudflared\n",
		"/proc/42/cgroup":   "0::/system.slice/docker-0123abcd.scope\n",
		"/proc/77/comm":     "cloudflared\n",
		"/proc/77/cgroup":   "0::/system.slice/cloudflared.service\n",
		"/proc/self/comm":   "stackward\n",
		"/proc/cpuinfo":     "x",
		"/proc/99/comm":     "crowdsec\n",
		"/proc/sys/x/y":     "z",
		"/proc/1000/status": "x", // no comm: exited
	})
	scan, err := scanProcs(sys, "cloudflared")
	if err != nil {
		t.Fatal(err)
	}
	n, inC := scan.count("cloudflared")
	if !scan.Visible || n != 2 || inC != 1 {
		t.Errorf("scan = %+v (n=%d, in container=%d)", scan, n, inC)
	}
}
