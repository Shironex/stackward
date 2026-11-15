package checks

import (
	"fmt"
	"net/netip"
	"strings"

	"github.com/Shironex/stackward/internal/facts"
	"github.com/Shironex/stackward/internal/facts/sshd"
)

// covered reports whether a configured endpoint ("0.0.0.0:22") is served by
// one of the listeners as ss prints them ("*:22", "[::]:22").
func covered(endpoint string, listeners []string) (bool, bool) {
	host, port, _ := sshd.SplitHostPort(endpoint)
	ip, err := netip.ParseAddr(host)
	if err != nil {
		return false, false // a host name: cannot compare without resolving
	}
	ip = ip.Unmap()
	for _, l := range listeners {
		lh, lp, _ := sshd.SplitHostPort(l)
		if lp != port {
			continue
		}
		if lh == "*" {
			return true, true
		}
		la, err := netip.ParseAddr(lh)
		if err != nil {
			continue
		}
		la = la.Unmap()
		if la == ip || (la.IsUnspecified() && la.Is4() == ip.Is4()) {
			return true, true
		}
	}
	return false, true
}

func checkListeners(in Input) []Result {
	s, res := sshFacts(in)
	if s == nil {
		return res
	}
	sock := s.Socket
	ev := map[string]any{"configured": []string{}, "listening": nonNil(s.Listening), "missing": []string{},
		"socket_unit": "", "socket_active": false, "socket_listen": []string{}}
	if sock != nil {
		ev["socket_unit"], ev["socket_active"], ev["socket_listen"] = sock.Unit, sock.Active(), nonNil(sock.Listen)
	}
	if !s.ListeningInspected {
		return One(Unknown, "could not list listening sockets: "+s.ListeningError, ev)
	}
	conf, ok := s.Setting("listenaddress")
	if !ok || len(conf) == 0 {
		r := unknownSetting(s, "ListenAddress and Port")
		r[0].Evidence = ev
		return r
	}
	ev["configured"] = conf
	if sock.Active() && listenAddressUnset(s) {
		return socketOwnsAddresses(s, sock, ev)
	}
	var missing, unresolved []string
	for _, e := range conf {
		hit, canCompare := covered(e, s.Listening)
		switch {
		case !canCompare:
			unresolved = append(unresolved, e)
		case !hit:
			missing = append(missing, e)
		}
	}
	ev["missing"] = nonNil(missing)
	if len(missing) > 0 {
		msg := fmt.Sprintf("configured %s not listening (listening: %s)", strings.Join(missing, ", "), listOrNone(s.Listening))
		if sock.Active() {
			msg += fmt.Sprintf("; %s is active and listens on %s, so Port and ListenAddress changes need a daemon-reload and a socket restart", sock.Unit, listOrNone(sock.Listen))
		}
		return One(Fail, msg, ev)
	}
	if len(unresolved) > 0 {
		return One(Unknown, "cannot compare host name listen addresses: "+strings.Join(unresolved, ", "), ev)
	}
	if sock.Active() {
		return socketListenResult(sock, conf, ev)
	}
	return One(Pass, "sshd listens on every configured address: "+strings.Join(conf, ", "), ev)
}

// socketListenResult judges socket activation, where ssh.socket holds the
// listening sockets and sshd's Port and ListenAddress only matter through
// the unit (Ubuntu's sshd-socket-generator writes them into a drop-in at
// daemon-reload). It passes when the socket listens exactly where the
// config says, and warns on a real mismatch: a configured address the
// socket does not cover, or a socket address the config does not name.
// listenAddressUnset reports whether every sshd config file was read and
// none sets ListenAddress in the global section. With socket activation
// that leaves the addresses to the socket unit.
func listenAddressUnset(s *facts.SSH) bool {
	if s.Config == nil || len(s.Config.Unreadable()) > 0 {
		return false
	}
	for _, d := range s.Config.Directives {
		if d.Match == 0 && d.Keyword == "listenaddress" {
			return false
		}
	}
	return true
}

// socketOwnsAddresses judges socket activation with no ListenAddress in the
// config: the socket unit is the source of truth for addresses, so only
// the ports are compared with Port.
func socketOwnsAddresses(s *facts.SSH, sock *facts.SSHSocket, ev map[string]any) []Result {
	if len(sock.Listen) == 0 {
		return One(Warn, fmt.Sprintf("socket activation in use: %s decides where sshd listens, but its listen addresses could not be read", sock.Unit), ev)
	}
	ports, ok := s.Setting("port")
	if !ok || len(ports) == 0 {
		ports = []string{"22"}
	}
	want, have := map[string]bool{}, map[string]bool{}
	for _, p := range ports {
		want[p] = true
	}
	var extra, missing []string
	for _, l := range sock.Listen {
		_, p, _ := sshd.SplitHostPort(l)
		have[p] = true
		if !want[p] {
			extra = append(extra, l)
		}
	}
	for _, p := range ports {
		if !have[p] {
			missing = append(missing, p)
		}
	}
	switch {
	case len(missing) > 0:
		return One(Fail, fmt.Sprintf("configured port %s not listening (listening: %s); %s is active and listens on %s, so Port changes need a daemon-reload and a socket restart",
			strings.Join(missing, ", "), listOrNone(s.Listening), sock.Unit, listOrNone(sock.Listen)), ev)
	case len(extra) > 0:
		return One(Warn, fmt.Sprintf("%s also listens on %s, which Port does not name; the socket, not sshd_config, decides where SSH is reachable",
			sock.Unit, strings.Join(extra, ", ")), ev)
	}
	return One(Pass, fmt.Sprintf("socket activation in use: %s listens on %s; ListenAddress is not set, so the socket decides the addresses, on the configured port", sock.Unit, strings.Join(sock.Listen, ", ")), ev)
}

func socketListenResult(sock *facts.SSHSocket, conf []string, ev map[string]any) []Result {
	if len(sock.Listen) == 0 {
		return One(Warn, fmt.Sprintf("socket activation in use: %s decides where sshd listens, but its listen addresses could not be read; Port and ListenAddress take effect only after daemon-reload and a socket restart", sock.Unit), ev)
	}
	var notOnSocket, notConfigured, unresolved []string
	for _, e := range conf {
		hit, canCompare := socketCovers(e, sock.Listen)
		switch {
		case !canCompare:
			unresolved = append(unresolved, e)
		case !hit:
			notOnSocket = append(notOnSocket, e)
		}
	}
	for _, l := range sock.Listen {
		if hit, canCompare := covered(l, conf); canCompare && !hit && !wildcardCoveredByConfig(l, conf) {
			notConfigured = append(notConfigured, l)
		}
	}
	switch {
	case len(notOnSocket) > 0:
		return One(Warn, fmt.Sprintf("%s listens on %s, but sshd is configured for %s, which the socket ignores; run daemon-reload and restart %s, or set ListenStream in the unit",
			sock.Unit, listOrNone(sock.Listen), strings.Join(notOnSocket, ", "), sock.Unit), ev)
	case len(notConfigured) > 0:
		return One(Warn, fmt.Sprintf("%s listens on %s, which Port and ListenAddress do not name; the socket, not sshd_config, decides where SSH is reachable (daemon-reload and a socket restart apply ListenAddress)",
			sock.Unit, strings.Join(notConfigured, ", ")), ev)
	case len(unresolved) > 0:
		return One(Unknown, "cannot compare host name listen addresses with the socket: "+strings.Join(unresolved, ", "), ev)
	}
	return One(Pass, fmt.Sprintf("socket activation in use: %s listens on %s, which matches Port and ListenAddress", sock.Unit, strings.Join(sock.Listen, ", ")), ev)
}

// socketCovers is covered for socket unit addresses: systemd binds "[::]"
// dual stack by default (BindIPv6Only=default), so it covers IPv4 too.
func socketCovers(endpoint string, listen []string) (bool, bool) {
	hit, ok := covered(endpoint, listen)
	if hit || !ok {
		return hit, ok
	}
	_, port, _ := sshd.SplitHostPort(endpoint)
	for _, l := range listen {
		lh, lp, _ := sshd.SplitHostPort(l)
		if lp == port && lh == "::" {
			return true, true
		}
	}
	return false, true
}

// wildcardCoveredByConfig reports whether a dual stack socket address
// ("[::]:22") is what the config's pair of wildcards (0.0.0.0:22 and
// [::]:22, the default with no ListenAddress) means.
func wildcardCoveredByConfig(l string, conf []string) bool {
	lh, lp, _ := sshd.SplitHostPort(l)
	if lh != "::" {
		return false
	}
	for _, e := range conf {
		h, p, _ := sshd.SplitHostPort(e)
		if p == lp && (h == "0.0.0.0" || h == "::") {
			return true
		}
	}
	return false
}

func listOrNone(v []string) string {
	if len(v) == 0 {
		return "nothing"
	}
	return strings.Join(v, ", ")
}

// passwordLogin says whether a password alone logs in for every
// connection: PasswordAuthentication, or keyboard-interactive without a
// PAM second factor, set globally or by a Match all block and offered
// alone by AuthenticationMethods. Conditional Match blocks do not count
// (SSH-001 and SSH-002 report them).
func passwordLogin(s *facts.SSH) (tri, string) {
	pw, pwOK := s.Value("passwordauthentication")
	kbd, kbdOK := s.Value("kbdinteractiveauthentication")
	pwAll, _ := matchOverrides(s, "passwordauthentication", isYes)
	kbdAll, _ := matchOverrides(s, "kbdinteractiveauthentication", isYes)
	if (pw == "yes" || len(pwAll) > 0) && methodUse(s, "password") == "sole" {
		return triYes, "PasswordAuthentication"
	}
	if (kbd == "yes" || len(kbdAll) > 0) && len(s.PAM2FA) == 0 && methodUse(s, "keyboard-interactive") == "sole" {
		return triYes, "KbdInteractiveAuthentication"
	}
	if !pwOK || !kbdOK {
		return triUnknown, ""
	}
	return triNo, ""
}

// SSH-011: sshd reachable from anywhere must not take passwords, and
// with keys only it should still have a brute force jail.
func checkSSHReachableAuth(in Input) []Result {
	f := in.Facts
	s, res := sshFacts(in)
	if s == nil {
		return res
	}
	if f.Listeners == nil {
		return []Result{NotInspected(f, "listeners")}
	}
	if f.Firewall == nil {
		return []Result{NotInspected(f, "firewall")}
	}
	reach := sshReachability(f)
	ev := map[string]any{"ssh_ports": reach.ports, "open_from_anywhere": reach.open.String(),
		"password_login": "unknown", "brute_force_guard": "unknown"}
	switch reach.open {
	case triNo:
		return One(Pass, "sshd is not reachable from anywhere: "+strings.Join(reach.reasons, "; "), ev)
	case triUnknown:
		return One(Unknown, "could not tell whether sshd is reachable from anywhere: "+strings.Join(reach.reasons, "; "), ev)
	}
	where := reach.where()
	pw, by := passwordLogin(s)
	ev["password_login"] = pw.String()
	switch pw {
	case triYes:
		return One(Fail, fmt.Sprintf("sshd is reachable from anywhere on %s and accepts a password alone (%s): every bot on the internet can guess", where, by), ev)
	case triUnknown:
		return One(Unknown, fmt.Sprintf("sshd is reachable from anywhere on %s; whether it accepts passwords is unknown: %s", where, why(s)), ev)
	}
	g := sshProtection(f, reach.ports)
	ev["brute_force_guard"] = g.level.String()
	switch g.level {
	case triYes:
		return One(Pass, fmt.Sprintf("sshd is reachable from anywhere on %s, takes keys only and brute force is banned", where), ev)
	case triUnknown:
		return One(Unknown, fmt.Sprintf("sshd is reachable from anywhere on %s and takes keys only; whether fail2ban or CrowdSec bans brute force could not be read (run with sudo)", where), ev)
	}
	return One(Warn, fmt.Sprintf("sshd is reachable from anywhere on %s with keys only and no fail2ban jail or CrowdSec sshd collection bans brute force", where), ev)
}

// SSH-016: Tailscale SSH and OpenSSH side by side are two login paths
// with different rules.
func checkTailscaleSSH(in Input) []Result {
	f := in.Facts
	t := f.Tailscale
	if t == nil {
		return []Result{NotInspected(f, "tailscale")}
	}
	if !t.Installed {
		return One(Skip, "Tailscale is not installed", map[string]any{"tailscale_ssh": "absent", "openssh": "unknown"})
	}
	ev := map[string]any{"tailscale_ssh": "unknown", "openssh": "unknown", "backend_state": valueOrUnknown(t.State())}
	if t.SSH == nil {
		return One(Unknown, "could not read whether Tailscale SSH is on (tailscale debug prefs did not answer)", ev)
	}
	if !*t.SSH {
		ev["tailscale_ssh"] = "off"
		return One(Pass, "Tailscale SSH is off; OpenSSH is the only SSH server", ev)
	}
	ev["tailscale_ssh"] = "on"
	s := f.SSH
	if s == nil {
		return []Result{NotInspected(f, "ssh")}
	}
	switch {
	case !s.Installed:
		ev["openssh"] = "absent"
		return One(Pass, "Tailscale SSH is the only SSH server (no OpenSSH server installed)", ev)
	case s.ListeningInspected && len(s.Listening) == 0:
		ev["openssh"] = "not listening"
		return One(Pass, "Tailscale SSH is on and OpenSSH does not listen", ev)
	}
	ev["openssh"] = "installed"
	return One(Warn, "Tailscale SSH is on alongside OpenSSH: two login paths with different authentication and logging to reason about", ev)
}
