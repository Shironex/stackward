package facts

import (
	"bufio"
	"bytes"
	"context"
	"errors"
	"io/fs"
	"path"
	"sort"
	"strconv"
	"strings"
)

// Sysctl is the kernel settings the KRN group reads, plus the hints needed
// to judge them (is Docker or Tailscale here).
type Sysctl struct {
	// Values holds every watched key that /proc/sys answered, keyed with
	// dots ("net.ipv4.ip_forward"). A watched key missing from Values has
	// no file on this kernel (for example yama without the module).
	Values map[string]string `json:"values"`
	// Configured is the last setting of each watched key in /etc/sysctl.conf
	// and the sysctl.d directories: what a reboot or `sysctl --system`
	// will apply, and which file said so.
	Configured map[string]SysctlSetting `json:"configured,omitempty"`
	// UFW is the watched keys set in /etc/ufw/sysctl.conf, which ufw applies
	// on every enable and reload, on top of sysctl.d.
	UFW map[string]string `json:"ufw,omitempty"`
	// DockerPresent and TailscalePresent say whether either is installed
	// (binary, socket or state directory found).
	DockerPresent    bool `json:"docker_present"`
	TailscalePresent bool `json:"tailscale_present"`
	// GlobalIPv6Dynamic is true when an interface holds a global IPv6
	// address that is not permanent, which is how router advertisements
	// (SLAAC) and DHCPv6 addresses look in /proc/net/if_inet6.
	GlobalIPv6Dynamic bool `json:"global_ipv6_dynamic"`
}

// SysctlSetting is one configured value and the file it came from.
type SysctlSetting struct {
	Value string `json:"value"`
	File  string `json:"file"`
}

// WatchedSysctls is every key the collector reads, in report order.
var WatchedSysctls = []string{
	"net.ipv4.ip_forward",
	"net.ipv4.conf.all.rp_filter",
	"net.ipv4.conf.default.rp_filter",
	"net.ipv4.conf.all.accept_redirects",
	"net.ipv4.conf.default.accept_redirects",
	"net.ipv4.conf.all.send_redirects",
	"net.ipv4.conf.all.accept_source_route",
	"net.ipv4.conf.default.accept_source_route",
	"net.ipv4.tcp_syncookies",
	"net.ipv4.icmp_echo_ignore_broadcasts",
	"net.ipv4.conf.all.log_martians",
	"net.ipv6.conf.all.accept_redirects",
	"net.ipv6.conf.default.accept_redirects",
	"net.ipv6.conf.all.accept_source_route",
	"net.ipv6.conf.all.accept_ra",
	"net.ipv6.conf.default.accept_ra",
	"kernel.kptr_restrict",
	"kernel.dmesg_restrict",
	"kernel.unprivileged_bpf_disabled",
	"kernel.yama.ptrace_scope",
	"fs.protected_hardlinks",
	"fs.protected_symlinks",
	"fs.protected_fifos",
	"fs.protected_regular",
}

// Paths the sysctl collector reads.
const (
	procSysDir     = "/proc/sys"
	sysctlConfPath = "/etc/sysctl.conf"
	ufwSysctlPath  = "/etc/ufw/sysctl.conf"
	ifInet6Path    = "/proc/net/if_inet6"
)

// sysctlDirs are the drop-in directories in increasing priority: a file in
// an earlier directory is masked by a same-named file in a later one.
var sysctlDirs = []string{"/usr/lib/sysctl.d", "/run/sysctl.d", "/etc/sysctl.d"}

var (
	dockerMarkers    = []string{"/var/run/docker.sock", "/run/docker.sock", "/usr/bin/docker", "/usr/bin/dockerd", "/etc/docker", "/var/lib/docker"}
	tailscaleMarkers = []string{"/usr/bin/tailscale", "/usr/sbin/tailscaled", "/var/lib/tailscale"}
)

type sysctlCollector struct{}

func init() { Register(sysctlCollector{}) }

func (sysctlCollector) Name() string    { return "sysctl" }
func (sysctlCollector) NeedsRoot() bool { return false }

func (sysctlCollector) Collect(_ context.Context, sys System, out *Facts) error {
	s := &Sysctl{Values: map[string]string{}}
	for _, key := range WatchedSysctls {
		b, err := sys.ReadFile(path.Join(procSysDir, strings.ReplaceAll(key, ".", "/")))
		if err != nil {
			continue // absent on this kernel, or unreadable: not in Values
		}
		s.Values[key] = strings.TrimSpace(string(b))
	}
	s.Configured = readConfiguredSysctls(sys)
	if b, err := sys.ReadFile(ufwSysctlPath); err == nil {
		s.UFW = map[string]string{}
		for k, v := range ParseSysctlConf(b) {
			s.UFW[k] = v
		}
	}
	s.DockerPresent = anyExists(sys, dockerMarkers)
	s.TailscalePresent = anyExists(sys, tailscaleMarkers)
	if b, err := sys.ReadFile(ifInet6Path); err == nil {
		s.GlobalIPv6Dynamic = HasDynamicGlobalIPv6(b)
	}
	out.Sysctl = s
	if len(s.Values) == 0 {
		return errors.New("no value readable under /proc/sys")
	}
	return nil
}

func anyExists(sys System, paths []string) bool {
	for _, p := range paths {
		if _, err := sys.Meta(p); err == nil {
			return true
		}
	}
	return false
}

var watched = func() map[string]bool {
	m := map[string]bool{}
	for _, k := range WatchedSysctls {
		m[k] = true
	}
	return m
}()

// ParseSysctlConf parses sysctl.conf syntax and returns the watched keys it
// sets, normalised to dots. Later lines win.
func ParseSysctlConf(b []byte) map[string]string {
	out := map[string]string{}
	sc := bufio.NewScanner(bytes.NewReader(b))
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" || line[0] == '#' || line[0] == ';' {
			continue
		}
		key, val, ok := strings.Cut(line, "=")
		if !ok {
			continue
		}
		key = strings.ReplaceAll(strings.TrimPrefix(strings.TrimSpace(key), "-"), "/", ".")
		if watched[key] {
			out[key] = strings.TrimSpace(val)
		}
	}
	return out
}

// readConfiguredSysctls applies the sysctl.d precedence: drop-ins by file
// name across directories (an /etc file masks a same-named /usr/lib file),
// then /etc/sysctl.conf last.
func readConfiguredSysctls(sys System) map[string]SysctlSetting {
	byName := map[string]string{}
	for _, dir := range sysctlDirs {
		entries, err := sys.ReadDir(dir)
		if err != nil && !errors.Is(err, fs.ErrNotExist) {
			continue
		}
		for _, e := range entries {
			if !e.IsDir() && strings.HasSuffix(e.Name(), ".conf") {
				byName[e.Name()] = path.Join(dir, e.Name())
			}
		}
	}
	names := make([]string, 0, len(byName))
	for n := range byName {
		names = append(names, n)
	}
	sort.Strings(names)
	files := make([]string, 0, len(names)+1)
	for _, n := range names {
		files = append(files, byName[n])
	}
	files = append(files, sysctlConfPath)

	out := map[string]SysctlSetting{}
	for _, f := range files {
		b, err := sys.ReadFile(f)
		if err != nil {
			continue
		}
		for k, v := range ParseSysctlConf(b) {
			out[k] = SysctlSetting{Value: v, File: f}
		}
	}
	return out
}

// HasDynamicGlobalIPv6 reads /proc/net/if_inet6 ("addr ifindex prefixlen
// scope flags name") and reports a global (scope 00) address without the
// permanent flag (0x80) on a non loopback interface.
func HasDynamicGlobalIPv6(b []byte) bool {
	sc := bufio.NewScanner(bytes.NewReader(b))
	for sc.Scan() {
		f := strings.Fields(sc.Text())
		if len(f) < 6 || f[5] == "lo" || f[3] != "00" {
			continue
		}
		flags, err := strconv.ParseUint(f[4], 16, 32)
		if err == nil && flags&0x80 == 0 {
			return true
		}
	}
	return false
}
