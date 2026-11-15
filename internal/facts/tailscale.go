package facts

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"sort"
	"strconv"
	"strings"
	"time"
)

// Tailscale is Tailscale backend state, key expiry, serve and funnel (TS
// group). Peers, host names and tailnet addresses are never recorded.
type Tailscale struct {
	// Installed is true when the tailscale command or the tailscaled unit
	// exists. False with a non nil Tailscale means "not installed", which
	// is a known answer (no tailnet), unlike a nil Tailscale.
	Installed bool `json:"installed"`
	// Unit is tailscaled.service, nil when systemd could not be asked.
	Unit *ServiceUnit `json:"unit,omitempty"`
	// StatusRead is true when `tailscale status --json` answered.
	StatusRead bool `json:"status_read"`
	// BackendState is "Running", "NeedsLogin", "NeedsMachineAuth",
	// "Stopped", "Starting" or "NoState"; "" when the status was not read.
	BackendState string `json:"backend_state,omitempty"`
	Version      string `json:"version,omitempty"`
	// KeyExpiry is when this node's key expires. Nil with StatusRead means
	// key expiry is disabled for the node.
	KeyExpiry *time.Time `json:"key_expiry,omitempty"`
	// Serve is the serve and funnel configuration; nil when it could not
	// be read.
	Serve *TailscaleServe `json:"serve,omitempty"`
	// LockEnabled is Tailnet Lock; nil when unknown.
	LockEnabled *bool `json:"lock_enabled,omitempty"`
	// SSH is the RunSSH preference (Tailscale SSH server on); nil when
	// the preferences could not be read.
	SSH *bool `json:"ssh,omitempty"`
}

// TailscaleServe is what `tailscale serve status --json` shows, reduced to
// ports (node names are not recorded).
type TailscaleServe struct {
	// ServePorts are ports with a serve handler (reachable from the
	// tailnet), sorted.
	ServePorts []int `json:"serve_ports,omitempty"`
	// FunnelPorts are ports that Funnel publishes to the internet, sorted.
	FunnelPorts []int `json:"funnel_ports,omitempty"`
}

// State is the backend state, or "DaemonStopped" when the status could
// not be read and tailscaled is known not to run, or "" when unknown.
func (t *Tailscale) State() string {
	if t == nil {
		return ""
	}
	if t.StatusRead && t.BackendState != "" {
		return t.BackendState
	}
	if t.Unit != nil && t.Unit.Loaded() && !t.Unit.Active() {
		return "DaemonStopped"
	}
	return ""
}

// TailnetRunning implements profile.TailnetReporter: running is true when
// the node is logged in and Running. Not installed is a known "no".
func (t *Tailscale) TailnetRunning() (running, known bool) {
	if t == nil {
		return false, false
	}
	if !t.Installed {
		return false, true
	}
	switch s := t.State(); s {
	case "":
		return false, false
	case "Running":
		return true, true
	}
	return false, true
}

type tailscaleCollector struct{}

func init() { Register(tailscaleCollector{}) }

func (tailscaleCollector) Name() string    { return "tailscale" }
func (tailscaleCollector) NeedsRoot() bool { return false }

// Collect runs (all read only):
//
//	systemctl show tailscaled.service --property=LoadState,ActiveState,SubState,UnitFileState
//	tailscale status --json
//	tailscale serve status --json
//	tailscale lock status --json
//	tailscale debug prefs          (prints the preferences; only RunSSH is kept)
func (tailscaleCollector) Collect(ctx context.Context, sys System, out *Facts) error {
	t := &Tailscale{}
	_, lookErr := sys.LookPath("tailscale")
	t.Unit = readServiceUnit(ctx, sys, "tailscaled.service")
	t.Installed = lookErr == nil || (t.Unit != nil && t.Unit.Loaded())
	out.Tailscale = t
	if lookErr != nil {
		return nil
	}

	var errs []error
	res, err := sys.Run(ctx, "tailscale", "status", "--json")
	switch {
	case err != nil:
		errs = append(errs, fmt.Errorf("tailscale status: %w", err))
	case !bytes.HasPrefix(bytes.TrimSpace(res.Stdout), []byte("{")):
		// tailscaled down: "failed to connect to local tailscaled".
		if t.Unit == nil || !t.Unit.Loaded() || t.Unit.Active() {
			errs = append(errs, fmt.Errorf("tailscale status exited %d: %s", res.ExitCode, firstLine(res.Stderr)))
		}
	default:
		st, perr := ParseTailscaleStatus(res.Stdout)
		if perr != nil {
			errs = append(errs, perr)
			break
		}
		t.StatusRead = true
		t.BackendState, t.Version, t.KeyExpiry = st.BackendState, st.Version, st.KeyExpiry
	}

	if t.StatusRead {
		if res, err := sys.Run(ctx, "tailscale", "serve", "status", "--json"); err == nil && res.ExitCode == 0 {
			if s, perr := ParseTailscaleServe(res.Stdout); perr == nil {
				t.Serve = s
			} else {
				errs = append(errs, perr)
			}
		}
		if res, err := sys.Run(ctx, "tailscale", "lock", "status", "--json"); err == nil && res.ExitCode == 0 {
			t.LockEnabled = parseTailscaleLock(res.Stdout)
		}
	}
	if res, err := sys.Run(ctx, "tailscale", "debug", "prefs"); err == nil && res.ExitCode == 0 {
		t.SSH = parseTailscaleRunSSH(res.Stdout)
	}
	return errors.Join(errs...)
}

// TailscaleStatus is the part of `tailscale status --json` stackward reads.
type TailscaleStatus struct {
	BackendState string
	Version      string
	KeyExpiry    *time.Time
}

// ParseTailscaleStatus reads BackendState, Version and Self.KeyExpiry from
// `tailscale status --json`. Peers and addresses are ignored.
func ParseTailscaleStatus(b []byte) (TailscaleStatus, error) {
	var doc struct {
		Version      string
		BackendState string
		Self         *struct {
			KeyExpiry *time.Time `json:",omitempty"`
		}
	}
	if err := json.Unmarshal(b, &doc); err != nil {
		return TailscaleStatus{}, fmt.Errorf("tailscale status --json: %w", err)
	}
	st := TailscaleStatus{BackendState: doc.BackendState, Version: doc.Version}
	if doc.Self != nil && doc.Self.KeyExpiry != nil && !doc.Self.KeyExpiry.IsZero() {
		e := doc.Self.KeyExpiry.UTC()
		st.KeyExpiry = &e
	}
	return st, nil
}

// tsServeConfig mirrors the parts of Tailscale's ServeConfig that say what
// is exposed. Foreground holds the configs of foreground `tailscale serve`
// sessions, one per session.
type tsServeConfig struct {
	TCP         map[string]json.RawMessage `json:"TCP"`
	Web         map[string]json.RawMessage `json:"Web"`
	AllowFunnel map[string]bool            `json:"AllowFunnel"`
	Foreground  map[string]tsServeConfig   `json:"Foreground"`
}

// ParseTailscaleServe reads `tailscale serve status --json`. Older clients
// print "No serve config" instead of JSON when nothing is configured.
func ParseTailscaleServe(b []byte) (*TailscaleServe, error) {
	trimmed := bytes.TrimSpace(b)
	s := &TailscaleServe{}
	if len(trimmed) == 0 || bytes.Contains(bytes.ToLower(trimmed), []byte("no serve config")) {
		return s, nil
	}
	var cfg tsServeConfig
	if err := json.Unmarshal(trimmed, &cfg); err != nil {
		return nil, fmt.Errorf("tailscale serve status --json: %w", err)
	}
	serve, funnel := map[int]bool{}, map[int]bool{}
	var walk func(c tsServeConfig)
	walk = func(c tsServeConfig) {
		for k := range c.TCP {
			if p, err := strconv.Atoi(k); err == nil {
				serve[p] = true
			}
		}
		for k := range c.Web {
			if p, ok := hostPortNumber(k); ok {
				serve[p] = true
			}
		}
		for k, on := range c.AllowFunnel {
			if p, ok := hostPortNumber(k); ok && on {
				funnel[p] = true
			}
		}
		for _, fg := range c.Foreground {
			walk(fg)
		}
	}
	walk(cfg)
	s.ServePorts, s.FunnelPorts = intKeys(serve), intKeys(funnel)
	return s, nil
}

func hostPortNumber(hp string) (int, bool) {
	_, port, err := net.SplitHostPort(hp)
	if err != nil {
		return 0, false
	}
	p, err := strconv.Atoi(port)
	return p, err == nil
}

func intKeys(m map[int]bool) []int {
	if len(m) == 0 {
		return nil
	}
	out := make([]int, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Ints(out)
	return out
}

// parseTailscaleLock reads Enabled from `tailscale lock status --json`, or
// the sentence of the text output when the client has no JSON mode.
func parseTailscaleLock(b []byte) *bool {
	var doc struct{ Enabled *bool }
	if json.Unmarshal(b, &doc) == nil && doc.Enabled != nil {
		return doc.Enabled
	}
	s := strings.ToLower(string(b))
	switch {
	case strings.Contains(s, "is not enabled"):
		v := false
		return &v
	case strings.Contains(s, "is enabled"):
		v := true
		return &v
	}
	return nil
}

// parseTailscaleRunSSH reads RunSSH from `tailscale debug prefs`. Every
// other preference (control URL, routes, host name) is dropped here.
func parseTailscaleRunSSH(b []byte) *bool {
	var doc struct{ RunSSH *bool }
	if json.Unmarshal(b, &doc) != nil {
		return nil
	}
	return doc.RunSSH
}

// ServiceUnit is the state of one systemd unit as `systemctl show` prints
// it. The access collectors (tailscale, cloudflared, crowdsec, fail2ban)
// share it.
type ServiceUnit struct {
	Name string `json:"name"`
	// LoadState is "loaded", "not-found", "masked" or "".
	LoadState string `json:"load_state,omitempty"`
	// ActiveState is "active", "inactive", "failed", "activating" or "".
	ActiveState string `json:"active_state,omitempty"`
	SubState    string `json:"sub_state,omitempty"`
	// UnitFileState is "enabled", "disabled", "static", "masked" or "".
	UnitFileState string `json:"unit_file_state,omitempty"`
}

// Loaded reports whether the unit exists.
func (u *ServiceUnit) Loaded() bool { return u != nil && u.LoadState == "loaded" }

// Active reports whether the unit is running (or starting).
func (u *ServiceUnit) Active() bool {
	return u != nil && (u.ActiveState == "active" || u.ActiveState == "activating" || u.ActiveState == "reloading")
}

// unitProperties are the properties readServiceUnit asks for.
const unitProperties = "LoadState,ActiveState,SubState,UnitFileState"

// readServiceUnit asks systemd for a unit's state. It returns nil when
// systemctl is missing or printed nothing usable.
func readServiceUnit(ctx context.Context, sys System, name string) *ServiceUnit {
	res, err := sys.Run(ctx, "systemctl", "show", name, "--property="+unitProperties)
	if err != nil {
		return nil
	}
	kv := ParseKeyValues(res.Stdout)
	if kv["LoadState"] == "" {
		return nil
	}
	return &ServiceUnit{Name: name, LoadState: kv["LoadState"], ActiveState: kv["ActiveState"], SubState: kv["SubState"], UnitFileState: kv["UnitFileState"]}
}

// procEntry is one process found by scanProcs: its pid, short name and
// whether its cgroup says it runs in a container.
type procEntry struct {
	PID       string
	Comm      string
	Container bool
}

// procScan is the result of scanProcs.
type procScan struct {
	// Visible is false when /proc hides other users' processes (hidepid)
	// from this user, so absence proves nothing.
	Visible bool
	Entries []procEntry
}

// count returns how many processes have the given name.
func (p procScan) count(comm string) (n, inContainer int) {
	for _, e := range p.Entries {
		if e.Comm == comm {
			n++
			if e.Container {
				inContainer++
			}
		}
	}
	return n, inContainer
}

// scanProcs lists processes whose short name (/proc/<pid>/comm) is in
// names. The host PID namespace sees container processes too, which is how
// a containerised cloudflared or CrowdSec is found without the Docker API.
// Only comm and cgroup are read here.
func scanProcs(sys System, names ...string) (procScan, error) {
	want := map[string]bool{}
	for _, n := range names {
		want[n] = true
	}
	entries, err := sys.ReadDir("/proc")
	if err != nil {
		return procScan{}, fmt.Errorf("list /proc: %w", err)
	}
	_, err1 := sys.ReadFile("/proc/1/comm")
	scan := procScan{Visible: err1 == nil}
	for _, e := range entries {
		pid := e.Name()
		if !isPIDName(pid) {
			continue
		}
		comm, err := sys.ReadFile("/proc/" + pid + "/comm")
		if err != nil {
			continue // the process exited, or is hidden
		}
		name := strings.TrimSpace(string(comm))
		if !want[name] {
			continue
		}
		pe := procEntry{PID: pid, Comm: name}
		if cg, err := sys.ReadFile("/proc/" + pid + "/cgroup"); err == nil {
			pe.Container = cgroupIsContainer(cg)
		}
		scan.Entries = append(scan.Entries, pe)
	}
	return scan, nil
}

func isPIDName(s string) bool {
	if s == "" {
		return false
	}
	for _, r := range s {
		if r < '0' || r > '9' {
			return false
		}
	}
	return true
}

// cgroupIsContainer reports whether a /proc/<pid>/cgroup file names a
// container runtime scope.
func cgroupIsContainer(b []byte) bool {
	s := string(b)
	for _, marker := range []string{"/docker/", "docker-", "/containerd/", "cri-containerd", "/kubepods", "libpod-", "/lxc/"} {
		if strings.Contains(s, marker) {
			return true
		}
	}
	return false
}
