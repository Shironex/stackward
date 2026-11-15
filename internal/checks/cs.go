package checks

import (
	"fmt"
	"net"
	"net/netip"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/Shironex/stackward/internal/facts"
	"github.com/Shironex/stackward/internal/profile"
)

// CS checks read the crowdsec and fail2ban collectors (facts/crowdsec.go,
// facts/fail2ban.go), with the tunnel, firewall, listeners and Tailscale
// facts where a rule depends on them.

func init() {
	Register(Check{ID: "CS-001", Run: checkCrowdSecRunning})
	Register(Check{ID: "CS-002", Run: checkBouncers})
	Register(Check{ID: "CS-003", Run: checkBouncerBehindTunnel})
	Register(Check{ID: "CS-004", Run: checkRealIPWhitelist})
	Register(Check{ID: "CS-005", Run: checkProxyAcquisition})
	Register(Check{ID: "CS-006", Run: checkLAPIListen})
	Register(Check{ID: "CS-007", Run: checkFirewallBouncerDocker})
	Register(Check{ID: "CS-008", Run: checkBouncerInterval})
	Register(Check{ID: "CS-010", Run: checkSSHBruteForce})
	Register(Check{ID: "CS-011", Run: checkFail2banTailnet})
}

// Thresholds from the design brief.
const (
	bouncerStaleAfter    = 5 * time.Minute
	bouncerIntervalLimit = 60 * time.Second
)

func crowdsecAbsent() []Result {
	return One(Skip, "CrowdSec is not installed", map[string]any{"installed": false})
}

func checkCrowdSecRunning(in Input) []Result {
	c := in.Facts.CrowdSec
	if c == nil {
		return []Result{NotInspected(in.Facts, "crowdsec")}
	}
	if !c.Installed {
		return One(Skip, "CrowdSec is not installed (an option for blocking scanners and brute force, see crowdsec.net)", map[string]any{"installed": false})
	}
	running, known := c.EngineRunning()
	ev := map[string]any{"unit": unitWord(c.Unit), "engine_processes": c.EngineProcesses, "in_container": c.EngineInContainer, "version": valueOrUnknown(c.Version)}
	switch {
	case !known:
		return One(Unknown, "CrowdSec is installed; whether the engine runs could not be seen (run with sudo)", ev)
	case running:
		return One(Pass, "the CrowdSec engine is running", ev)
	}
	return One(Fail, "CrowdSec is installed but the engine is not running: nothing is detected or banned", ev)
}

// liveBouncers returns the bouncers that are not revoked, one per bouncer.
//
// A bouncer that runs in several containers (or behind several addresses)
// registers its base name once and then a name@IP row per address, all
// sharing the base row's API key; the base row itself may never pull again.
// They are one bouncer: the merged row keeps the base name and the newest
// pull of any of its rows. Deleting the base row would break every row that
// shares its key, so stackward never suggests it.
func liveBouncers(c *facts.CrowdSec) []facts.CrowdSecBouncer {
	var out []facts.CrowdSecBouncer
	idx := map[string]int{}
	for _, b := range c.Bouncers {
		if b.Revoked {
			continue
		}
		base := bouncerBase(b.Name)
		i, seen := idx[base]
		if !seen {
			idx[base] = len(out)
			b.Name = base
			out = append(out, b)
			continue
		}
		m := &out[i]
		if b.LastPull != nil && (m.LastPull == nil || b.LastPull.After(*m.LastPull)) {
			m.LastPull = b.LastPull
		}
		if m.Kind == "" || m.Kind == "other" {
			m.Kind = b.Kind
		}
		if m.Type == "" {
			m.Type = b.Type
		}
		if m.Version == "" {
			m.Version = b.Version
		}
	}
	return out
}

// bouncerBase strips the @IP suffix CrowdSec adds to the rows of a bouncer
// that connects from more than one address ("traefik@192.0.2.10").
func bouncerBase(name string) string {
	base, addr, ok := strings.Cut(name, "@")
	if !ok || base == "" {
		return name
	}
	if _, err := netip.ParseAddr(addr); err != nil {
		return name
	}
	return base
}

func bouncersUnread(c *facts.CrowdSec) string {
	if !c.Cscli {
		return "cscli is not on the host PATH (CrowdSec in a container?), so bouncers could not be listed"
	}
	return "cscli bouncers list needs root (run with sudo)"
}

func bouncerNames(bs []facts.CrowdSecBouncer) []string {
	out := []string{}
	for _, b := range bs {
		out = append(out, b.Name)
	}
	return out
}

func checkBouncers(in Input) []Result {
	c := in.Facts.CrowdSec
	if c == nil {
		return []Result{NotInspected(in.Facts, "crowdsec")}
	}
	if !c.Installed {
		return crowdsecAbsent()
	}
	if !c.BouncersRead {
		return One(Unknown, bouncersUnread(c), map[string]any{"bouncers": "unknown"})
	}
	live := liveBouncers(c)
	now := in.Facts.CollectedAt
	var stale []string
	for _, b := range live {
		if b.LastPull == nil || now.Sub(*b.LastPull) > bouncerStaleAfter {
			stale = append(stale, b.Name)
		}
	}
	ev := map[string]any{"bouncers": bouncerNames(live), "stale": orEmptyStrings(stale)}
	switch {
	case len(live) == 0:
		return One(Fail, "no bouncer is registered: CrowdSec detections ban nothing", ev)
	case len(stale) > 0:
		return One(Warn, fmt.Sprintf("bouncer(s) %s last pulled decisions more than 5 minutes ago (or never): they may have lost the local API", strings.Join(stale, ", ")), ev)
	}
	return One(Pass, fmt.Sprintf("%d bouncer(s) registered and pulling decisions", len(live)), ev)
}

// tunnelIngress says whether the host's ingress is a tunnel: from the
// cloudflared facts, or from --profile tunnel.
func tunnelIngress(in Input) (present, known bool) {
	if in.Profile == profile.Tunnel {
		return true, true
	}
	return profile.TunnelState(in.Facts)
}

func checkBouncerBehindTunnel(in Input) []Result {
	c := in.Facts.CrowdSec
	if c == nil {
		return []Result{NotInspected(in.Facts, "crowdsec")}
	}
	if !c.Installed {
		return crowdsecAbsent()
	}
	present, known := tunnelIngress(in)
	switch {
	case !known:
		return One(Unknown, "whether a tunnel is the ingress is unknown", map[string]any{"tunnel": "unknown"})
	case !present:
		return One(Skip, "no tunnel: a firewall bouncer sees real client addresses", map[string]any{"tunnel": "absent"})
	}
	if !c.BouncersRead {
		return One(Unknown, bouncersUnread(c), map[string]any{"tunnel": "present", "kinds": "unknown"})
	}
	kinds := map[string]int{}
	for _, b := range liveBouncers(c) {
		kinds[b.Kind]++
	}
	ev := map[string]any{"tunnel": "present", "kinds": kinds}
	switch {
	case kinds["proxy"] > 0 || kinds["cloudflare"] > 0:
		return One(Pass, "an L7 (proxy or Cloudflare) bouncer enforces bans behind the tunnel", ev)
	case kinds["firewall"] > 0:
		return One(Fail, "behind the tunnel only a firewall bouncer runs: it sees cloudflared's local address, never the real client, and bans nothing useful", ev)
	case kinds["other"] > 0:
		return One(Unknown, "behind the tunnel, the registered bouncers could not be classified as L7 or firewall", ev)
	}
	return One(Fail, "behind the tunnel no bouncer is registered at all (see CS-002)", ev)
}

// localSources are the source ranges a proxy behind a tunnel logs as the
// client: loopback and the private ranges Docker networks use.
var localSources = []netip.Prefix{
	netip.MustParsePrefix("127.0.0.0/8"),
	netip.MustParsePrefix("10.0.0.0/8"),
	netip.MustParsePrefix("172.16.0.0/12"),
	netip.MustParsePrefix("192.168.0.0/16"),
	netip.MustParsePrefix("::1/128"),
}

// parsePrefixOrAddr reads "10.0.0.0/8" or "127.0.0.1".
func parsePrefixOrAddr(s string) (netip.Prefix, bool) {
	s = strings.TrimSpace(s)
	if p, err := netip.ParsePrefix(s); err == nil {
		return p.Masked(), true
	}
	if a, err := netip.ParseAddr(s); err == nil {
		return netip.PrefixFrom(a, a.BitLen()), true
	}
	return netip.Prefix{}, false
}

func whitelistsLocal(pf facts.CrowdSecParserFile) bool {
	for _, s := range append(append([]string{}, pf.WhitelistCIDRs...), pf.WhitelistIPs...) {
		p, ok := parsePrefixOrAddr(s)
		if !ok {
			continue
		}
		for _, l := range localSources {
			if p.Overlaps(l) {
				return true
			}
		}
	}
	return false
}

func checkRealIPWhitelist(in Input) []Result {
	c := in.Facts.CrowdSec
	if c == nil {
		return []Result{NotInspected(in.Facts, "crowdsec")}
	}
	if !c.Installed {
		return crowdsecAbsent()
	}
	present, known := tunnelIngress(in)
	switch {
	case !known:
		return One(Unknown, "whether a tunnel is the ingress is unknown", map[string]any{"tunnel": "unknown"})
	case !present:
		return One(Skip, "no tunnel: the proxy logs real client addresses", map[string]any{"tunnel": "absent"})
	}
	if !c.ParserFilesRead {
		return One(Unknown, "the CrowdSec parser directories could not be read", map[string]any{"tunnel": "present"})
	}
	var whitelists, realIP, keyed []string
	allKeyed := true
	for _, pf := range c.ParserFiles {
		if whitelistsLocal(pf) {
			whitelists = append(whitelists, pf.Path)
		}
		if pf.RealIPHeader != "" {
			realIP = append(realIP, pf.Path)
			if len(pf.RealIPKeyedTo) > 0 {
				keyed = append(keyed, pf.RealIPKeyedTo...)
			} else {
				allKeyed = false
			}
		}
	}
	ev := map[string]any{"tunnel": "present", "local_whitelists": orEmptyStrings(whitelists), "real_ip_parsers": orEmptyStrings(realIP), "keyed_to": orEmptyStrings(keyed)}
	switch {
	case len(realIP) == 0 && len(whitelists) > 0:
		return One(Fail, "behind the tunnel the proxy logs a local address for every client, a whitelist covers local ranges, and no parser reads the real address: every request is whitelisted", ev)
	case len(realIP) == 0:
		return One(Warn, "behind the tunnel no parser reads the real client address: CrowdSec attributes every request to cloudflared's local address", ev)
	case allKeyed:
		return One(Warn, fmt.Sprintf("the real IP parser only trusts %s: when a new Docker network becomes the route its requests are whitelisted as private", strings.Join(keyed, ", ")), ev)
	}
	return One(Pass, "a parser takes the real client address from a header for local sources", ev)
}

// proxyLogTypes are acquisition label types of reverse proxy access logs.
var proxyLogTypes = map[string]bool{"traefik": true, "caddy": true, "nginx": true, "haproxy": true, "apache2": true, "apache": true, "envoy": true, "openresty": true, "nginx-proxy-manager": true}

func checkProxyAcquisition(in Input) []Result {
	f := in.Facts
	c := f.CrowdSec
	if c == nil {
		return []Result{NotInspected(f, "crowdsec")}
	}
	if !c.Installed {
		return crowdsecAbsent()
	}
	present, _ := tunnelIngress(in)
	web := present
	if !web {
		if f.Listeners == nil {
			return []Result{NotInspected(f, "listeners")}
		}
		for _, s := range f.Listeners.Sockets {
			if s.Proto == "tcp" && webPorts[s.Port] {
				web = true
			}
		}
	}
	if !web {
		return One(Skip, "no web proxy found (nothing on 80/443 and no tunnel)", map[string]any{"web_proxy": false})
	}
	if !c.AcquisitionRead {
		return One(Unknown, "the CrowdSec acquisition files could not be read", map[string]any{"web_proxy": true})
	}
	var types []string
	acquired := false
	seen := map[string]bool{}
	for _, s := range c.Acquisition {
		if s.Type != "" && !seen[s.Type] {
			seen[s.Type] = true
			types = append(types, s.Type)
		}
		if proxyLogTypes[s.Type] {
			acquired = true
		}
	}
	sort.Strings(types)
	ev := map[string]any{"web_proxy": true, "types": orEmptyStrings(types)}
	if acquired {
		return One(Pass, "a reverse proxy access log is acquired (its format is not checked)", ev)
	}
	return One(Warn, "a web proxy serves this host but no proxy access log is acquired: HTTP scenarios never fire", ev)
}

func checkLAPIListen(in Input) []Result {
	f := in.Facts
	c := f.CrowdSec
	if c == nil {
		return []Result{NotInspected(f, "crowdsec")}
	}
	if !c.Installed {
		return crowdsecAbsent()
	}
	if c.LAPIListen != "" {
		host, _, err := net.SplitHostPort(c.LAPIListen)
		if err != nil {
			host = c.LAPIListen
		}
		class := facts.ClassifyAddress(host)
		ev := map[string]any{"listen": c.LAPIListen, "class": string(class), "source": "config"}
		if class.Exposed() {
			return One(Warn, fmt.Sprintf("the local API listens on %s (%s)", c.LAPIListen, class), ev)
		}
		return One(Pass, fmt.Sprintf("the local API listens on %s (%s)", c.LAPIListen, class), ev)
	}
	if binds, exposed := crowdsecListenerBinds(f); len(binds) > 0 {
		ev := map[string]any{"listen": binds, "source": "listeners"}
		if exposed {
			return One(Warn, "a crowdsec listener is on a wildcard or public address: "+strings.Join(binds, ", "), ev)
		}
		return One(Pass, "crowdsec listens on loopback or private addresses only: "+strings.Join(binds, ", "), ev)
	}
	return One(Unknown, "the local API listen address could not be read", map[string]any{"listen": "unknown"})
}

// crowdsecListenerBinds lists the TCP sockets a crowdsec process holds and
// whether any of them is on a wildcard or public address.
func crowdsecListenerBinds(f *facts.Facts) (binds []string, exposed bool) {
	if f.Listeners == nil {
		return nil, false
	}
	for _, s := range f.Listeners.Sockets {
		if s.Proto == "tcp" && s.HasProcess("crowdsec") {
			binds = append(binds, net.JoinHostPort(s.Address, strconv.Itoa(s.Port)))
			if s.Class().Exposed() {
				exposed = true
			}
		}
	}
	return binds, exposed
}

// firewallBouncerSeen reports whether a firewall bouncer is registered or
// its rules are loaded.
func firewallBouncerSeen(c *facts.CrowdSec, fw *facts.Firewall) bool {
	for _, b := range liveBouncers(c) {
		if b.Kind == "firewall" {
			return true
		}
	}
	if t := fw.Iptables; t != nil {
		for _, ch := range t.Chains {
			if strings.Contains(strings.ToLower(ch), "crowdsec") {
				return true
			}
		}
	}
	if n := fw.NFT; n != nil {
		for _, tb := range n.Tables {
			if strings.Contains(strings.ToLower(tb.Name), "crowdsec") {
				return true
			}
		}
	}
	return false
}

func checkFirewallBouncerDocker(in Input) []Result {
	f := in.Facts
	c := f.CrowdSec
	if c == nil {
		return []Result{NotInspected(f, "crowdsec")}
	}
	if !c.Installed {
		return crowdsecAbsent()
	}
	fw := f.Firewall
	if fw == nil {
		return []Result{NotInspected(f, "firewall")}
	}
	if present, known := tunnelIngress(in); known && present {
		return One(Skip, "behind a tunnel a firewall bouncer is the wrong tool (see CS-003)", map[string]any{"tunnel": "present"})
	}
	ev := map[string]any{"docker_backend": valueOrUnknown(fw.DockerBackend)}
	switch fw.DockerBackend {
	case "":
		return One(Unknown, "Docker's firewall rules could not be read (run with sudo)", ev)
	case "none":
		return One(Skip, "no Docker firewall rules: nothing is published", ev)
	}
	if !firewallBouncerSeen(c, fw) {
		if !c.BouncersRead && (fw.Iptables == nil || !fw.Iptables.Listed) {
			return One(Unknown, "whether a firewall bouncer runs could not be seen (run with sudo)", ev)
		}
		return One(Skip, "no firewall bouncer", ev)
	}
	covered := false
	if fw.Iptables != nil {
		for _, r := range fw.Iptables.DockerUserRules {
			if strings.Contains(strings.ToLower(r), "crowdsec") {
				covered = true
			}
		}
	}
	if fw.NFT != nil {
		for _, ch := range fw.NFT.Chains {
			if strings.Contains(strings.ToLower(ch.Table), "crowdsec") && ch.Hook == "forward" {
				covered = true
			}
		}
	}
	ev["docker_user_hooked"] = covered
	switch {
	case covered:
		return One(Pass, "the firewall bouncer also filters forwarded traffic to containers", ev)
	case fw.Iptables == nil || !fw.Iptables.Listed:
		return One(Unknown, "the live iptables rules could not be read (run with sudo)", ev)
	}
	return One(Warn, "the firewall bouncer does not hook DOCKER-USER or forward: published containers are not protected", ev)
}

func checkBouncerInterval(in Input) []Result {
	c := in.Facts.CrowdSec
	if c == nil {
		return []Result{NotInspected(in.Facts, "crowdsec")}
	}
	if !c.Installed {
		return crowdsecAbsent()
	}
	if !c.BouncersRead {
		return One(Unknown, bouncersUnread(c), map[string]any{"proxy_bouncers": "unknown"})
	}
	var proxies, slow []string
	now := in.Facts.CollectedAt
	for _, b := range liveBouncers(c) {
		if b.Kind != "proxy" {
			continue
		}
		proxies = append(proxies, b.Name)
		if b.LastPull == nil {
			continue // never pulled: CS-002
		}
		if age := now.Sub(*b.LastPull); age > bouncerIntervalLimit && age <= bouncerStaleAfter {
			slow = append(slow, fmt.Sprintf("%s (%ds)", b.Name, int(age.Seconds())))
		}
	}
	ev := map[string]any{"proxy_bouncers": orEmptyStrings(proxies), "slow": orEmptyStrings(slow)}
	switch {
	case len(proxies) == 0:
		return One(Skip, "no proxy bouncer", ev)
	case len(slow) > 0:
		return One(Warn, "proxy bouncer(s) last pulled more than 60 s ago: "+strings.Join(slow, ", ")+"; a long update interval lets fast scanners finish before a ban lands (or the bouncer runs in live mode)", ev)
	}
	return One(Unknown, "proxy bouncers pulled within the last 60 s; the interval itself is in the bouncer config, which holds the API key and is not read", ev)
}

// resolveJailPorts turns a fail2ban port setting into port ranges. ok is
// false when a part cannot be resolved (a service name other than ssh).
func resolveJailPorts(spec string) (ranges [][2]int, ok bool) {
	if strings.TrimSpace(spec) == "" {
		return nil, false
	}
	for _, part := range strings.Split(spec, ",") {
		part = strings.TrimSpace(part)
		if part == "ssh" {
			ranges = append(ranges, [2]int{22, 22})
			continue
		}
		lo, hi, isRange := strings.Cut(part, ":")
		a, err := strconv.Atoi(lo)
		if err != nil {
			return nil, false
		}
		b := a
		if isRange {
			if b, err = strconv.Atoi(hi); err != nil {
				return nil, false
			}
		}
		ranges = append(ranges, [2]int{a, b})
	}
	return ranges, true
}

func portsCovered(ranges [][2]int, ports []int) bool {
	for _, p := range ports {
		in := false
		for _, r := range ranges {
			if p >= r[0] && p <= r[1] {
				in = true
			}
		}
		if !in {
			return false
		}
	}
	return true
}

func checkSSHBruteForce(in Input) []Result {
	f := in.Facts
	if f.Listeners == nil {
		return []Result{NotInspected(f, "listeners")}
	}
	if f.Firewall == nil {
		return []Result{NotInspected(f, "firewall")}
	}
	reach := sshReachability(f)
	ports := reach.ports
	ev := map[string]any{"ssh_ports": ports, "ssh_public": reach.open.String()}
	switch reach.open {
	case triNo:
		return One(Pass, "SSH is not reachable from anywhere, so brute force protection is optional", ev)
	case triUnknown:
		return One(Unknown, "could not tell whether SSH is public (see NET-003)", ev)
	}
	p := sshProtection(f, ports)
	ev["crowdsec_sshd"] = p.crowdsec
	if p.crowdsec {
		return One(Pass, "SSH is public and the CrowdSec sshd collection watches it", ev)
	}
	ev["fail2ban_sshd"] = p.jail.String()
	if p.jail == triYes {
		ev["jail_port"] = valueOrUnknown(p.jailPort)
		switch p.level {
		case triUnknown:
			return One(Unknown, fmt.Sprintf("SSH is public and the fail2ban sshd jail is active, but its port (%s) could not be resolved", valueOrUnknown(p.jailPort)), ev)
		case triNo:
			return One(Warn, fmt.Sprintf("the fail2ban sshd jail bans on port %s while sshd listens on %s: bans miss the real port", p.jailPort, joinInts(ports)), ev)
		}
		return One(Pass, "SSH is public and the fail2ban sshd jail covers its port", ev)
	}
	if p.level == triUnknown {
		return One(Unknown, "SSH is public; whether fail2ban or CrowdSec protects it could not be fully read (run with sudo)", ev)
	}
	return One(Fail, "SSH is public and neither a fail2ban sshd jail nor the CrowdSec sshd collection protects it", ev)
}

// sshGuard is whether fail2ban or CrowdSec bans SSH brute force on the
// sshd ports. level is the overall answer; crowdsec, jail and jailPort say
// how it was reached.
type sshGuard struct {
	level    tri
	crowdsec bool   // the CrowdSec engine runs with the sshd collection
	jail     tri    // the fail2ban sshd jail is active
	jailPort string // the jail's port setting, when it is active
}

func sshProtection(f *facts.Facts, ports []int) sshGuard {
	c, f2b := f.CrowdSec, f.Fail2ban
	g := sshGuard{}
	if c != nil && c.Installed && c.HasItem("sshd") {
		if running, _ := c.EngineRunning(); running {
			g.crowdsec, g.level = true, triYes
			return g
		}
	}
	csKnown := c != nil && (!c.Installed || c.HubRead)
	active, jailKnown := f2b.JailActive("sshd")
	g.jail = triOf(active, jailKnown)
	if active {
		j, _ := f2b.Jail("sshd")
		g.jailPort = j.Port
		ranges, ok := resolveJailPorts(j.Port)
		switch {
		case !ok:
			g.level = triUnknown
		case !portsCovered(ranges, ports):
			g.level = triNo
		default:
			g.level = triYes
		}
		return g
	}
	if !jailKnown || !csKnown {
		g.level = triUnknown
		return g
	}
	g.level = triNo
	return g
}

func triOf(v, known bool) tri {
	switch {
	case !known:
		return triUnknown
	case v:
		return triYes
	}
	return triNo
}

// tailnetRange is Tailscale's CGNAT range.
var tailnetRange = netip.MustParsePrefix("100.64.0.0/10")

func coversTailnet(entries []string) bool {
	for _, e := range entries {
		if p, ok := parsePrefixOrAddr(e); ok && p.Addr().Is4() && p.Bits() <= tailnetRange.Bits() && p.Contains(tailnetRange.Addr()) {
			return true
		}
	}
	return false
}

func checkFail2banTailnet(in Input) []Result {
	f := in.Facts
	f2b := f.Fail2ban
	if f2b == nil {
		return []Result{NotInspected(f, "fail2ban")}
	}
	if !f2b.Installed {
		return One(Skip, "fail2ban is not installed", map[string]any{"installed": false})
	}
	t := f.Tailscale
	if t == nil {
		return []Result{NotInspected(f, "tailscale")}
	}
	if !t.Installed {
		return One(Skip, "Tailscale is not installed", map[string]any{"tailscale": false})
	}
	if !f2b.ConfigRead {
		return One(Unknown, "the fail2ban jail configuration could not be read", map[string]any{"tailscale": true})
	}
	var enabled, missing []string
	for _, j := range f2b.Jails {
		if !j.Enabled {
			continue
		}
		enabled = append(enabled, j.Name)
		if !coversTailnet(j.IgnoreIP) {
			missing = append(missing, j.Name)
		}
	}
	ev := map[string]any{"tailscale": true, "jails": orEmptyStrings(enabled), "missing": orEmptyStrings(missing)}
	switch {
	case len(enabled) == 0:
		return One(Skip, "no fail2ban jail is enabled", ev)
	case len(missing) > 0:
		return One(Warn, fmt.Sprintf("jail(s) %s do not ignore 100.64.0.0/10: a tailnet peer can ban itself", strings.Join(missing, ", ")), ev)
	}
	return One(Pass, "every enabled jail ignores the tailnet range 100.64.0.0/10", ev)
}
