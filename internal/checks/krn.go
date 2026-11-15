package checks

import (
	"fmt"
	"strconv"
	"strings"

	"github.com/Shironex/stackward/internal/facts"
)

// KRN checks read what the sysctl collector gathers (facts/sysctl.go).

func init() {
	Register(Check{ID: "KRN-001", Run: checkIPForward})
	Register(Check{ID: "KRN-002", Run: checkRPFilter})
	Register(Check{ID: "KRN-003", Run: checkNetBaseline})
	Register(Check{ID: "KRN-004", Run: checkKernelBaseline})
	Register(Check{ID: "KRN-005", Run: checkAcceptRA})
}

const (
	keyIPForward   = "net.ipv4.ip_forward"
	keyRPFilterAll = "net.ipv4.conf.all.rp_filter"
	keyRPFilterDef = "net.ipv4.conf.default.rp_filter"
	keyRAAll       = "net.ipv6.conf.all.accept_ra"
	keyRADefault   = "net.ipv6.conf.default.accept_ra"
)

// baseline is one sysctl and the value it should have: exactly want, or at
// least want when atLeast (kernel hardening knobs where higher is stricter).
type baseline struct {
	key     string
	want    int
	atLeast bool
}

func (b baseline) ok(v int) bool {
	if b.atLeast {
		return v >= b.want
	}
	return v == b.want
}

func (b baseline) wantText() string {
	if b.atLeast {
		return fmt.Sprintf(">=%d", b.want)
	}
	return strconv.Itoa(b.want)
}

var netBaseline = []baseline{
	{"net.ipv4.conf.all.accept_redirects", 0, false},
	{"net.ipv4.conf.default.accept_redirects", 0, false},
	{"net.ipv6.conf.all.accept_redirects", 0, false},
	{"net.ipv6.conf.default.accept_redirects", 0, false},
	{"net.ipv4.conf.all.send_redirects", 0, false},
	{"net.ipv4.conf.all.accept_source_route", 0, false},
	{"net.ipv4.conf.default.accept_source_route", 0, false},
	{"net.ipv6.conf.all.accept_source_route", 0, false},
	{"net.ipv4.tcp_syncookies", 1, false},
	{"net.ipv4.icmp_echo_ignore_broadcasts", 1, false},
	{"net.ipv4.conf.all.log_martians", 1, false},
}

var kernelBaseline = []baseline{
	{"kernel.kptr_restrict", 1, true},
	{"kernel.dmesg_restrict", 1, true},
	{"kernel.unprivileged_bpf_disabled", 1, true},
	{"kernel.yama.ptrace_scope", 1, true},
	{"fs.protected_hardlinks", 1, true},
	{"fs.protected_symlinks", 1, true},
	{"fs.protected_fifos", 1, true},
	{"fs.protected_regular", 1, true},
}

func sysctlInt(s *facts.Sysctl, key string) (int, bool) {
	v, ok := s.Values[key]
	if !ok {
		return 0, false
	}
	n, err := strconv.Atoi(strings.TrimSpace(v))
	return n, err == nil
}

func checkIPForward(in Input) []Result {
	s := in.Facts.Sysctl
	if s == nil {
		return []Result{NotInspected(in.Facts, "sysctl")}
	}
	if !s.DockerPresent {
		return One(Skip, "Docker not found; IPv4 forwarding is not required by it", map[string]any{"docker": false})
	}
	v, ok := sysctlInt(s, keyIPForward)
	if !ok {
		return One(Unknown, "could not read net.ipv4.ip_forward", map[string]any{"docker": true})
	}
	set := s.Configured[keyIPForward]
	ev := map[string]any{"docker": true, "value": v, "configured_value": set.Value, "configured_file": set.File}
	if v == 0 {
		msg := "net.ipv4.ip_forward is 0 on a Docker host: container networking is broken"
		if set.File != "" {
			msg += " (set in " + set.File + ")"
		}
		return One(Fail, msg, ev)
	}
	return One(Pass, "net.ipv4.ip_forward is on, as Docker needs", ev)
}

func checkRPFilter(in Input) []Result {
	s := in.Facts.Sysctl
	if s == nil {
		return []Result{NotInspected(in.Facts, "sysctl")}
	}
	if !s.DockerPresent && !s.TailscalePresent {
		return One(Skip, "neither Docker nor Tailscale found; strict rp_filter is the normal default", map[string]any{"docker": false, "tailscale": false})
	}
	all, okAll := sysctlInt(s, keyRPFilterAll)
	def, okDef := sysctlInt(s, keyRPFilterDef)
	if !okAll && !okDef {
		return One(Unknown, "could not read rp_filter", map[string]any{"docker": s.DockerPresent, "tailscale": s.TailscalePresent})
	}
	ev := map[string]any{"docker": s.DockerPresent, "tailscale": s.TailscalePresent, "all": nilIf(okAll, all), "default": nilIf(okDef, def)}
	var strict []string
	if okAll && all == 1 {
		strict = append(strict, "all")
	}
	if okDef && def == 1 {
		strict = append(strict, "default")
	}
	if len(strict) > 0 {
		return One(Warn, fmt.Sprintf("strict rp_filter=1 (%s) can drop Docker and Tailscale traffic; use 2 (loose)", strings.Join(strict, ", ")), ev)
	}
	return One(Pass, "rp_filter is not strict", ev)
}

func nilIf(ok bool, v int) any {
	if !ok {
		return nil
	}
	return v
}

// offBaseline evaluates a table against the running values and returns the
// entries that are off, the ones that could not be read, and how many were
// judged.
func offBaseline(s *facts.Sysctl, table []baseline) (off, unavailable []string, judged int) {
	for _, b := range table {
		v, ok := sysctlInt(s, b.key)
		if !ok {
			unavailable = append(unavailable, b.key)
			continue
		}
		judged++
		if !b.ok(v) {
			off = append(off, fmt.Sprintf("%s=%d (want %s)", b.key, v, b.wantText()))
		}
	}
	return off, unavailable, judged
}

func checkNetBaseline(in Input) []Result {
	s := in.Facts.Sysctl
	if s == nil {
		return []Result{NotInspected(in.Facts, "sysctl")}
	}
	off, unavailable, judged := offBaseline(s, netBaseline)
	// ufw reapplies /etc/ufw/sysctl.conf on enable and reload, so a value
	// there undoes a hardening drop-in even when the running value is fine.
	var ufw []string
	for _, b := range netBaseline {
		if raw, ok := s.UFW[b.key]; ok {
			if n, err := strconv.Atoi(raw); err == nil && !b.ok(n) {
				ufw = append(ufw, fmt.Sprintf("%s=%d (want %s)", b.key, n, b.wantText()))
			}
		}
	}
	ev := map[string]any{"off_baseline": nonNil(off), "ufw_overrides": nonNil(ufw), "unavailable": nonNil(unavailable), "judged": judged}
	switch {
	case judged == 0:
		return One(Unknown, "no network sysctl could be read", ev)
	case len(off) > 0 || len(ufw) > 0:
		return One(Warn, fmt.Sprintf("%d network setting(s) off baseline, %d reset by /etc/ufw/sysctl.conf", len(off), len(ufw)), ev)
	}
	return One(Pass, "network sysctls match the baseline", ev)
}

func checkKernelBaseline(in Input) []Result {
	s := in.Facts.Sysctl
	if s == nil {
		return []Result{NotInspected(in.Facts, "sysctl")}
	}
	off, unavailable, judged := offBaseline(s, kernelBaseline)
	ev := map[string]any{"off_baseline": nonNil(off), "unavailable": nonNil(unavailable), "judged": judged}
	switch {
	case judged == 0:
		return One(Unknown, "no kernel hardening sysctl could be read", ev)
	case len(off) > 0:
		return One(Warn, fmt.Sprintf("%d kernel hardening setting(s) off baseline", len(off)), ev)
	}
	return One(Pass, "kernel hardening sysctls match the baseline", ev)
}

func nonNil(s []string) []string {
	if s == nil {
		return []string{}
	}
	return s
}

func checkAcceptRA(in Input) []Result {
	s := in.Facts.Sysctl
	if s == nil {
		return []Result{NotInspected(in.Facts, "sysctl")}
	}
	all, okAll := sysctlInt(s, keyRAAll)
	if !okAll {
		return One(Unknown, "could not read net.ipv6.conf.all.accept_ra (IPv6 may be disabled)", map[string]any{"value": nil})
	}
	cfg, set := s.Configured[keyRAAll]
	if !set {
		cfg, set = s.Configured[keyRADefault]
	}
	ev := map[string]any{"value": all, "configured_file": cfg.File, "global_ipv6_dynamic": s.GlobalIPv6Dynamic}
	if all == 0 && set && cfg.Value == "0" && s.GlobalIPv6Dynamic {
		return One(Warn, "accept_ra=0 set in "+cfg.File+" while this host holds a router advertised IPv6 address: IPv6 will break when it expires", ev)
	}
	return One(Pass, "accept_ra is not switched off in a way that breaks IPv6 here", ev)
}
