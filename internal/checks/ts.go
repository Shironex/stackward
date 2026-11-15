package checks

import (
	"fmt"
	"math"

	"github.com/Shironex/stackward/internal/facts"
)

// TS checks read the tailscale collector (facts/tailscale.go); TS-004 also
// reads the firewall rules.

func init() {
	Register(Check{ID: "TS-001", Run: checkTailscaleRunning})
	Register(Check{ID: "TS-002", Run: checkTailscaleKeyExpiry})
	Register(Check{ID: "TS-003", Run: checkTailscaleFunnel})
	Register(Check{ID: "TS-004", Run: checkTailscaleDeadRules})
	Register(Check{ID: "TS-005", Run: checkTailnetLock})
}

// unitWord describes a systemd unit for evidence.
func unitWord(u *facts.ServiceUnit) string {
	switch {
	case u == nil:
		return "unknown"
	case !u.Loaded():
		return valueOrUnknown(u.LoadState)
	}
	return valueOrUnknown(u.ActiveState)
}

func tailscaleNotInstalled() []Result {
	return One(Skip, "Tailscale is not installed", map[string]any{"installed": false})
}

func checkTailscaleRunning(in Input) []Result {
	t := in.Facts.Tailscale
	if t == nil {
		return []Result{NotInspected(in.Facts, "tailscale")}
	}
	if !t.Installed {
		return tailscaleNotInstalled()
	}
	state := t.State()
	ev := map[string]any{"state": valueOrUnknown(state), "unit": unitWord(t.Unit)}
	switch state {
	case "":
		return One(Unknown, "Tailscale is installed but its state could not be read (tailscale status --json failed)", ev)
	case "Running":
		return One(Pass, "Tailscale is logged in and Running", ev)
	case "Starting":
		return One(Unknown, "Tailscale is still starting; run the audit again", ev)
	case "DaemonStopped":
		return One(Fail, "tailscaled is not running: every tailscale0 firewall rule is dead", ev)
	}
	return One(Fail, fmt.Sprintf("Tailscale is installed but %s, not Running: every tailscale0 firewall rule is dead", state), ev)
}

func checkTailscaleKeyExpiry(in Input) []Result {
	t := in.Facts.Tailscale
	if t == nil {
		return []Result{NotInspected(in.Facts, "tailscale")}
	}
	if !t.Installed {
		return tailscaleNotInstalled()
	}
	if !t.StatusRead {
		return One(Unknown, "Tailscale status could not be read, so key expiry is unknown", map[string]any{"key_expiry": "unknown"})
	}
	if t.KeyExpiry == nil {
		return One(Pass, "node key expiry is disabled", map[string]any{"key_expiry": "disabled"})
	}
	ev := map[string]any{"key_expiry": t.KeyExpiry.Format("2006-01-02T15:04:05Z")}
	days := int(math.Floor(t.KeyExpiry.Sub(in.Facts.CollectedAt).Hours() / 24))
	ev["days_left"] = days
	if days < 0 {
		return One(Fail, fmt.Sprintf("the node key expired on %s: the node is logged out until re-authenticated", t.KeyExpiry.Format("2006-01-02")), ev)
	}
	return One(Fail, fmt.Sprintf("the node key expires on %s (in %d days); when it does the node logs out on its own", t.KeyExpiry.Format("2006-01-02"), days), ev)
}

func checkTailscaleFunnel(in Input) []Result {
	t := in.Facts.Tailscale
	if t == nil {
		return []Result{NotInspected(in.Facts, "tailscale")}
	}
	if !t.Installed {
		return tailscaleNotInstalled()
	}
	if t.Serve == nil {
		why := "tailscale serve status could not be read (it may need root or the operator role)"
		if !t.StatusRead {
			why = "Tailscale status could not be read"
		}
		return One(Unknown, why, map[string]any{"serve_ports": nil, "funnel_ports": nil})
	}
	ev := map[string]any{"serve_ports": orEmpty(t.Serve.ServePorts), "funnel_ports": orEmpty(t.Serve.FunnelPorts)}
	switch {
	case len(t.Serve.FunnelPorts) > 0:
		return One(Fail, fmt.Sprintf("Tailscale Funnel publishes port(s) %s to the internet, past the host firewall", joinInts(t.Serve.FunnelPorts)), ev)
	case len(t.Serve.ServePorts) > 0:
		return One(Warn, fmt.Sprintf("Tailscale Serve exposes port(s) %s to the tailnet; check that is intended", joinInts(t.Serve.ServePorts)), ev)
	}
	return One(Pass, "no Tailscale Serve or Funnel configuration", ev)
}

func checkTailscaleDeadRules(in Input) []Result {
	fw := in.Facts.Firewall
	if fw == nil {
		return []Result{NotInspected(in.Facts, "firewall")}
	}
	u := fw.UFW
	if u == nil || !u.Installed {
		return One(Skip, "UFW is not installed; other firewalls' interface rules are not analysed", map[string]any{"tailscale0_rules": 0})
	}
	if u.Status == "inactive" {
		return One(Skip, "UFW is not active", map[string]any{"tailscale0_rules": 0})
	}
	if !u.RulesKnown {
		return One(Unknown, "UFW rules could not be read (run with sudo)", map[string]any{"tailscale0_rules": "unknown"})
	}
	n := 0
	for _, r := range u.Rules {
		if r.Interface == "tailscale0" {
			n++
		}
	}
	ev := map[string]any{"tailscale0_rules": n}
	if n == 0 {
		return One(Pass, "no UFW rule names tailscale0", ev)
	}
	t := in.Facts.Tailscale
	if t == nil {
		return []Result{NotInspected(in.Facts, "tailscale")}
	}
	running, known := t.TailnetRunning()
	ev["tailscale"] = tailnetWord(running, known)
	switch {
	case !t.Installed:
		ev["tailscale"] = "not installed"
		return One(Fail, fmt.Sprintf("%d UFW rule(s) name tailscale0 but Tailscale is not installed: they are dead rules", n), ev)
	case !known:
		return One(Unknown, fmt.Sprintf("%d UFW rule(s) name tailscale0; whether Tailscale runs is unknown", n), ev)
	case !running:
		return One(Fail, fmt.Sprintf("%d UFW rule(s) name tailscale0 but Tailscale is not Running: they match nothing (see TS-001)", n), ev)
	}
	return One(Pass, fmt.Sprintf("%d UFW rule(s) name tailscale0 and Tailscale is Running", n), ev)
}

func checkTailnetLock(in Input) []Result {
	t := in.Facts.Tailscale
	if t == nil {
		return []Result{NotInspected(in.Facts, "tailscale")}
	}
	if !t.Installed {
		return tailscaleNotInstalled()
	}
	if t.LockEnabled == nil {
		return One(Unknown, "Tailnet Lock state could not be read", map[string]any{"lock": "unknown"})
	}
	if *t.LockEnabled {
		return One(Info, "Tailnet Lock is on", map[string]any{"lock": "on"})
	}
	return One(Info, "Tailnet Lock is off", map[string]any{"lock": "off"})
}

func orEmpty(v []int) []int {
	if v == nil {
		return []int{}
	}
	return v
}

func joinInts(v []int) string {
	s := ""
	for i, n := range v {
		if i > 0 {
			s += ", "
		}
		s += fmt.Sprint(n)
	}
	return s
}
