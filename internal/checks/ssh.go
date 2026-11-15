package checks

import (
	"fmt"
	"net/netip"
	"sort"
	"strconv"
	"strings"

	"github.com/Shironex/stackward/internal/facts"
	"github.com/Shironex/stackward/internal/facts/sshd"
)

// SSH checks read what the ssh collector gathers (facts/ssh.go). The
// effective configuration comes from sshd -T as root, or from the parsed
// files otherwise; a value the files could not settle is unknown, never a
// pass. SSH-011 joins the SSH facts with the firewall, listener, fail2ban
// and CrowdSec facts; SSH-016 joins them with the Tailscale facts.

func init() {
	Register(Check{ID: "SSH-001", Run: checkPasswordAuth})
	Register(Check{ID: "SSH-002", Run: checkKbdInteractive})
	Register(Check{ID: "SSH-003", Run: checkRootLogin})
	Register(Check{ID: "SSH-004", Run: checkEmptyPasswords})
	Register(Check{ID: "SSH-005", Run: checkMaxAuthTries})
	Register(Check{ID: "SSH-006", Run: checkAllowList})
	Register(Check{ID: "SSH-007", Run: checkForwarding})
	Register(Check{ID: "SSH-008", Run: checkDropInOrder})
	Register(Check{ID: "SSH-009", Run: checkMatchCoverage})
	Register(Check{ID: "SSH-010", Run: checkListeners})
	Register(Check{ID: "SSH-011", Run: checkSSHReachableAuth})
	Register(Check{ID: "SSH-012", Run: checkHostKeys})
	Register(Check{ID: "SSH-013", Run: checkSSHFileModes})
	Register(Check{ID: "SSH-014", Run: checkAuthorizedKeyTypes})
	Register(Check{ID: "SSH-015", Run: checkWeakAlgorithms})
	Register(Check{ID: "SSH-016", Run: checkTailscaleSSH})
}

// maxAuthTriesLimit is the highest MaxAuthTries SSH-005 accepts.
const maxAuthTriesLimit = 4

// Minimum key sizes: host RSA keys (SSH-012) and user RSA keys (SSH-014).
const (
	minHostRSABits = 3072
	minUserRSABits = 2048
)

// sshFacts returns the ssh facts, or the result to return when there are
// none to judge (not inspected, or no OpenSSH server).
func sshFacts(in Input) (*facts.SSH, []Result) {
	s := in.Facts.SSH
	if s == nil {
		return nil, []Result{NotInspected(in.Facts, "ssh")}
	}
	if !s.Installed {
		return nil, One(Skip, "no OpenSSH server installed", nil)
	}
	return s, nil
}

// why says in words why the effective configuration is not fully known.
func why(s *facts.SSH) string {
	var parts []string
	if s.Config != nil {
		for _, f := range s.Config.Files {
			if !f.Readable && f.Match == 0 {
				parts = append(parts, fmt.Sprintf("could not read %s (%s)", f.Path, f.Error))
			}
		}
	}
	if s.SshdTError != "" {
		parts = append(parts, "sshd -T unavailable: "+s.SshdTError)
	}
	if len(parts) == 0 {
		parts = append(parts, "the configuration does not settle it")
	}
	msg := strings.Join(parts, "; ")
	if s.SshdTError == "not root" {
		msg += "; run with sudo for full coverage"
	}
	return msg
}

func unknownSetting(s *facts.SSH, keyword string) []Result {
	return One(Unknown, fmt.Sprintf("%s unknown: %s", keyword, why(s)),
		map[string]any{"keyword": keyword, "source": s.Source, "unreadable": unreadable(s)})
}

func unreadable(s *facts.SSH) []string {
	out := []string{}
	if s.Config != nil {
		out = append(out, s.Config.Unreadable()...)
	}
	return out
}

// override is a Match block that sets a keyword.
type override struct {
	Criteria string `json:"criteria"`
	Value    string `json:"value"`
	File     string `json:"file"`
	Line     int    `json:"line"`
}

// matchOverrides returns the Match blocks whose (first) value for keyword
// satisfies bad, split into blocks for every connection ("Match all") and
// conditional ones.
func matchOverrides(s *facts.SSH, keyword string, bad func(string) bool) (all, some []override) {
	all, some = []override{}, []override{}
	if s.Config == nil {
		return all, some
	}
	done := map[int]bool{}
	for _, d := range s.Config.Directives {
		if d.Match == 0 || d.Keyword != keyword || done[d.Match] {
			continue
		}
		done[d.Match] = true // first value wins inside a block too
		if !bad(strings.ToLower(d.Value)) {
			continue
		}
		m := s.Config.Matches[d.Match-1]
		o := override{Criteria: m.Criteria, Value: d.Value, File: d.File, Line: d.Line}
		if m.All() {
			all = append(all, o)
		} else {
			some = append(some, o)
		}
	}
	return all, some
}

func criteriaList(os []override) string {
	var c []string
	for _, o := range os {
		c = append(c, "Match "+o.Criteria)
	}
	return strings.Join(c, ", ")
}

func isYes(v string) bool { return v == "yes" }

// methodUse says how AuthenticationMethods lets a method be used: "sole"
// (alone is enough), "combined" (only with another method, a second
// factor) or "none".
func methodUse(s *facts.SSH, method string) string {
	v, ok := s.Setting("authenticationmethods")
	if !ok || len(v) == 0 {
		return "sole"
	}
	best := "none"
	for _, list := range strings.Fields(strings.ToLower(strings.Join(v, " "))) {
		if list == "any" {
			return "sole"
		}
		ms := strings.Split(list, ",")
		for _, m := range ms {
			name, _, _ := strings.Cut(m, ":") // keyboard-interactive:pam
			if name != method {
				continue
			}
			if len(ms) == 1 {
				return "sole"
			}
			best = "combined"
		}
	}
	return best
}

func authMethods(s *facts.SSH) string {
	if v, ok := s.Setting("authenticationmethods"); ok && len(v) > 0 {
		return strings.Join(v, " ")
	}
	return "unknown"
}

func checkPasswordAuth(in Input) []Result {
	s, res := sshFacts(in)
	if s == nil {
		return res
	}
	v, ok := s.Value("passwordauthentication")
	if !ok {
		return unknownSetting(s, "PasswordAuthentication")
	}
	all, some := matchOverrides(s, "passwordauthentication", isYes)
	ev := map[string]any{"passwordauthentication": v, "source": s.Source,
		"authenticationmethods": authMethods(s), "match_all": all, "match_some": some}
	if v == "yes" || len(all) > 0 {
		where := "globally"
		if v != "yes" {
			where = "for every connection by " + criteriaList(all)
		}
		switch methodUse(s, "password") {
		case "combined":
			return One(Warn, fmt.Sprintf("password authentication is enabled %s, but AuthenticationMethods only accepts it after another method", where), ev)
		case "none":
			return One(Warn, fmt.Sprintf("password authentication is enabled %s, but AuthenticationMethods does not offer it", where), ev)
		}
		return One(Fail, fmt.Sprintf("password authentication is enabled %s", where), ev)
	}
	if len(some) > 0 {
		return One(Warn, "password authentication is off globally but enabled by "+criteriaList(some), ev)
	}
	return One(Pass, "password authentication is off", ev)
}

func checkKbdInteractive(in Input) []Result {
	s, res := sshFacts(in)
	if s == nil {
		return res
	}
	v, ok := s.Value("kbdinteractiveauthentication")
	if !ok {
		return unknownSetting(s, "KbdInteractiveAuthentication")
	}
	all, some := matchOverrides(s, "kbdinteractiveauthentication", isYes)
	pam := []string{}
	if s.PAM2FA != nil {
		pam = s.PAM2FA
	}
	ev := map[string]any{"kbdinteractiveauthentication": v, "source": s.Source,
		"authenticationmethods": authMethods(s), "pam_2fa": pam, "match_all": all, "match_some": some}
	if v == "yes" || len(all) > 0 {
		switch {
		case len(s.PAM2FA) > 0:
			return One(Warn, fmt.Sprintf("keyboard-interactive authentication is enabled with a PAM second factor (%s); confirm it cannot fall back to a password alone", strings.Join(s.PAM2FA, ", ")), ev)
		case methodUse(s, "keyboard-interactive") == "combined":
			return One(Warn, "keyboard-interactive authentication is enabled, but AuthenticationMethods only accepts it after another method", ev)
		case methodUse(s, "keyboard-interactive") == "none":
			return One(Warn, "keyboard-interactive authentication is enabled, but AuthenticationMethods does not offer it", ev)
		}
		return One(Fail, "keyboard-interactive authentication is enabled (passwords through PAM)", ev)
	}
	if len(some) > 0 {
		return One(Warn, "keyboard-interactive authentication is off globally but enabled by "+criteriaList(some), ev)
	}
	return One(Pass, "keyboard-interactive authentication is off", ev)
}

func rootLoginRank(v string) int {
	switch v {
	case "no":
		return 3
	case "forced-commands-only":
		return 2
	case "prohibit-password", "without-password":
		return 1
	}
	return 0 // yes, or anything sshd would not accept
}

func checkRootLogin(in Input) []Result {
	s, res := sshFacts(in)
	if s == nil {
		return res
	}
	v, ok := s.Value("permitrootlogin")
	if !ok {
		return unknownSetting(s, "PermitRootLogin")
	}
	all, some := matchOverrides(s, "permitrootlogin", func(m string) bool { return rootLoginRank(m) < rootLoginRank(v) })
	ev := map[string]any{"permitrootlogin": v, "source": s.Source, "match_all": all, "match_some": some}
	eff := v
	if len(all) > 0 {
		eff = strings.ToLower(all[0].Value)
	}
	switch rootLoginRank(eff) {
	case 0:
		return One(Fail, fmt.Sprintf("root may log in with a password (PermitRootLogin %s)", eff), ev)
	case 1, 2:
		return One(Warn, fmt.Sprintf("root may log in with a key (PermitRootLogin %s)", eff), ev)
	}
	if len(some) > 0 {
		return One(Warn, "root login is off globally but allowed by "+criteriaList(some), ev)
	}
	return One(Pass, "root login is off", ev)
}

func checkEmptyPasswords(in Input) []Result {
	s, res := sshFacts(in)
	if s == nil {
		return res
	}
	v, ok := s.Value("permitemptypasswords")
	if !ok {
		return unknownSetting(s, "PermitEmptyPasswords")
	}
	all, some := matchOverrides(s, "permitemptypasswords", isYes)
	ev := map[string]any{"permitemptypasswords": v, "source": s.Source, "match_all": all, "match_some": some}
	switch {
	case v == "yes" || len(all) > 0:
		return One(Fail, "accounts with an empty password may log in", ev)
	case len(some) > 0:
		return One(Fail, "accounts with an empty password may log in when "+criteriaList(some)+" applies", ev)
	}
	return One(Pass, "empty passwords are refused", ev)
}

func checkMaxAuthTries(in Input) []Result {
	s, res := sshFacts(in)
	if s == nil {
		return res
	}
	v, ok := s.Value("maxauthtries")
	if !ok {
		return unknownSetting(s, "MaxAuthTries")
	}
	n, err := strconv.Atoi(v)
	if err != nil {
		return One(Unknown, fmt.Sprintf("MaxAuthTries %q is not a number", v), map[string]any{"maxauthtries": v, "source": s.Source, "match_some": []override{}})
	}
	_, some := matchOverrides(s, "maxauthtries", func(m string) bool {
		x, err := strconv.Atoi(m)
		return err == nil && x > maxAuthTriesLimit
	})
	ev := map[string]any{"maxauthtries": n, "source": s.Source, "match_some": some}
	if n > maxAuthTriesLimit {
		return One(Warn, fmt.Sprintf("MaxAuthTries is %d (above %d)", n, maxAuthTriesLimit), ev)
	}
	if len(some) > 0 {
		return One(Warn, fmt.Sprintf("MaxAuthTries is %d but raised by %s", n, criteriaList(some)), ev)
	}
	return One(Pass, fmt.Sprintf("MaxAuthTries is %d", n), ev)
}

func checkAllowList(in Input) []Result {
	s, res := sshFacts(in)
	if s == nil {
		return res
	}
	users, uok := s.Setting("allowusers")
	groups, gok := s.Setting("allowgroups")
	ev := map[string]any{"allowusers": nonNil(users), "allowgroups": nonNil(groups), "source": s.Source}
	switch {
	case len(users) > 0 || len(groups) > 0:
		return One(Pass, fmt.Sprintf("logins limited to %s and %s", count(len(users), "user"), count(len(groups), "group")), ev)
	case !uok || !gok:
		return unknownSetting(s, "AllowUsers and AllowGroups")
	}
	return One(Warn, "no AllowUsers or AllowGroups: every account with a key or password may log in", ev)
}

func checkForwarding(in Input) []Result {
	s, res := sshFacts(in)
	if s == nil {
		return res
	}
	x11, xok := s.Value("x11forwarding")
	agent, aok := s.Value("allowagentforwarding")
	_, xsome := matchOverrides(s, "x11forwarding", isYes)
	_, asome := matchOverrides(s, "allowagentforwarding", isYes)
	ev := map[string]any{"x11forwarding": orQ(x11, xok), "allowagentforwarding": orQ(agent, aok),
		"source": s.Source, "match_some": append(xsome, asome...)}
	var on []string
	if x11 == "yes" {
		on = append(on, "X11Forwarding")
	}
	if agent == "yes" {
		on = append(on, "AllowAgentForwarding")
	}
	switch {
	case len(on) > 0:
		return One(Warn, strings.Join(on, " and ")+" enabled", ev)
	case !xok || !aok:
		r := unknownSetting(s, "X11Forwarding or AllowAgentForwarding")
		r[0].Evidence = ev
		return r
	case len(xsome)+len(asome) > 0:
		return One(Warn, "forwarding is off globally but enabled by "+criteriaList(append(xsome, asome...)), ev)
	}
	return One(Pass, "X11 and agent forwarding are off", ev)
}

// count formats n with a singular or plural noun ("1 user", "2 users").
func count(n int, noun string) string {
	if n == 1 {
		return "1 " + noun
	}
	return fmt.Sprintf("%d %ss", n, noun)
}

func orQ(v string, ok bool) string {
	if !ok {
		return "unknown"
	}
	return v
}

// securityRank orders values of keywords whose insecure value can shadow a
// later secure one (higher is safer). ok is false for other keywords.
func securityRank(keyword, value string) (int, bool) {
	v := strings.ToLower(value)
	switch keyword {
	case "passwordauthentication", "kbdinteractiveauthentication", "permitemptypasswords",
		"x11forwarding", "allowagentforwarding":
		if v == "no" {
			return 1, true
		}
		return 0, true
	case "permitrootlogin":
		return rootLoginRank(v), true
	case "maxauthtries":
		n, err := strconv.Atoi(v)
		if err != nil {
			return 0, false
		}
		return -n, true
	}
	return 0, false
}

// shadowed is one insecure first value that hides a later safer one.
type shadowed struct {
	Keyword      string `json:"keyword"`
	Value        string `json:"value"`
	Line         int    `json:"line"`
	IgnoredFile  string `json:"ignored_file"`
	IgnoredLine  int    `json:"ignored_line"`
	IgnoredValue string `json:"ignored_value"`
}

func checkDropInOrder(in Input) []Result {
	s, res := sshFacts(in)
	if s == nil {
		return res
	}
	c := s.Config
	if c == nil || len(c.Files) == 0 || !c.Files[0].Readable {
		return One(Unknown, "configuration files could not be read: "+why(s), map[string]any{"unreadable": unreadable(s)})
	}
	winner := map[string]sshd.Directive{}
	reported := map[string]bool{}
	byFile := map[string][]shadowed{}
	for _, d := range c.Directives {
		if d.Match != 0 {
			continue
		}
		rank, ok := securityRank(d.Keyword, d.Value)
		if !ok {
			continue
		}
		w, seen := winner[d.Keyword]
		if !seen {
			winner[d.Keyword] = d
			continue
		}
		wrank, _ := securityRank(w.Keyword, w.Value)
		if rank > wrank && !reported[d.Keyword] {
			reported[d.Keyword] = true
			byFile[w.File] = append(byFile[w.File], shadowed{Keyword: d.Keyword, Value: w.Value, Line: w.Line,
				IgnoredFile: d.File, IgnoredLine: d.Line, IgnoredValue: d.Value})
		}
	}
	if len(byFile) > 0 {
		files := make([]string, 0, len(byFile))
		for f := range byFile {
			files = append(files, f)
		}
		sort.Strings(files)
		var out []Result
		for _, f := range files {
			var parts []string
			for _, sh := range byFile[f] {
				parts = append(parts, fmt.Sprintf("%s %s (line %d) wins over %s in %s line %d",
					sh.Keyword, sh.Value, sh.Line, sh.IgnoredValue, sh.IgnoredFile, sh.IgnoredLine))
			}
			out = append(out, Result{Subject: "file:" + f, Level: Warn,
				Message:  "first value wins: " + strings.Join(parts, "; "),
				Evidence: map[string]any{"settings": byFile[f]}})
		}
		return out
	}
	if u := unreadable(s); len(u) > 0 {
		return One(Unknown, "could not check the drop-in order: "+why(s), map[string]any{"unreadable": u})
	}
	return One(Pass, fmt.Sprintf("no insecure value shadows a later setting in %d files", len(c.Files)),
		map[string]any{"files": len(c.Files)})
}

func checkMatchCoverage(in Input) []Result {
	s, res := sshFacts(in)
	if s == nil {
		return res
	}
	matches := 0
	if s.Config != nil {
		matches = len(s.Config.Matches)
	}
	ev := map[string]any{"source": s.Source, "match_blocks": matches, "unreadable": unreadable(s)}
	switch {
	case s.Source == "sshd -T":
		return One(Skip, "effective configuration read with sshd -T", ev)
	case !s.Complete:
		return One(Unknown, "configuration only partly read: "+why(s), ev)
	case matches > 0:
		return One(Unknown, fmt.Sprintf("%s and no sshd -T: per connection settings are not confirmed (%s)", count(matches, "Match block"), why(s)), ev)
	}
	return One(Pass, "every configuration file read and no Match blocks", ev)
}

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
		return One(Warn, fmt.Sprintf("socket activation in use: %s listens on %s and decides where sshd listens; Port and ListenAddress take effect only after daemon-reload and a socket restart", sock.Unit, listOrNone(sock.Listen)), ev)
	}
	return One(Pass, "sshd listens on every configured address: "+strings.Join(conf, ", "), ev)
}

func listOrNone(v []string) string {
	if len(v) == 0 {
		return "nothing"
	}
	return strings.Join(v, ", ")
}

func checkHostKeys(in Input) []Result {
	s, res := sshFacts(in)
	if s == nil {
		return res
	}
	if len(s.HostKeys) == 0 {
		return One(Unknown, "no host key files found in /etc/ssh", nil)
	}
	var out []Result
	for _, k := range s.HostKeys {
		ev := map[string]any{"type": k.Type, "bits": k.Bits, "configured": k.Configured, "mode": "", "uid": -1}
		level, issues := Pass, []string{}
		raise := func(l Level, msg string) {
			issues = append(issues, msg)
			if l == Fail || (l == Warn && level != Fail) || (l == Unknown && level == Pass) {
				level = l
			}
		}
		if k.Meta == nil {
			raise(Unknown, "could not inspect the private key file: "+k.MetaError)
		} else {
			perm := k.Meta.Mode.Perm()
			ev["mode"], ev["uid"] = fmt.Sprintf("%04o", perm), k.Meta.UID
			switch {
			case perm&0o004 != 0:
				raise(Fail, "private key readable by every user")
			case perm&0o022 != 0:
				raise(Fail, "private key writable by group or others")
			case perm&0o040 != 0:
				raise(Warn, "private key readable by its group")
			}
			if k.Meta.UID > 0 {
				raise(Fail, fmt.Sprintf("private key owned by uid %d, not root", k.Meta.UID))
			}
		}
		typ := k.Type
		if typ == "" {
			typ = keyTypeFromName(k.Path)
		}
		switch {
		case typ == "ssh-dss":
			raise(Warn, "DSA host key (deprecated and disabled in current OpenSSH)")
		case typ == "ssh-rsa" && k.Bits == 0:
			raise(Unknown, "RSA key size unknown (no readable .pub file)")
		case typ == "ssh-rsa" && k.Bits < minHostRSABits:
			raise(Warn, fmt.Sprintf("RSA host key of %d bits (under %d)", k.Bits, minHostRSABits))
		}
		msg := fmt.Sprintf("%s host key is fine", orQ(typ, typ != ""))
		if len(issues) > 0 {
			msg = strings.Join(issues, "; ")
		}
		out = append(out, Result{Subject: "file:" + k.Path, Level: level, Message: msg, Evidence: ev})
	}
	return out
}

func keyTypeFromName(p string) string {
	switch {
	case strings.Contains(p, "_dsa_"):
		return "ssh-dss"
	case strings.Contains(p, "_rsa_"):
		return "ssh-rsa"
	case strings.Contains(p, "_ecdsa_"):
		return "ecdsa"
	case strings.Contains(p, "_ed25519_"):
		return "ssh-ed25519"
	}
	return ""
}

func writableByOthers(m *facts.FileMeta) bool { return m != nil && m.Mode.Perm()&0o022 != 0 }

func modeText(m *facts.FileMeta) string {
	if m == nil {
		return ""
	}
	return fmt.Sprintf("%04o", m.Mode.Perm())
}

func badOwner(m *facts.FileMeta, uid int) bool {
	return m != nil && m.UID >= 0 && m.UID != uid && m.UID != 0
}

func checkSSHFileModes(in Input) []Result {
	s, res := sshFacts(in)
	if s == nil {
		return res
	}
	if s.UsersError != "" {
		return One(Unknown, "could not read /etc/passwd: "+s.UsersError, nil)
	}
	var out []Result
	for _, u := range s.Users {
		ev := map[string]any{"home_mode": modeText(u.HomeMeta), "ssh_dir_mode": modeText(u.SSHDir), "key_files": map[string]string{}}
		subj := "user:" + u.Name
		if u.Error != "" {
			out = append(out, Result{Subject: subj, Level: Unknown, Message: "could not inspect " + u.Error + notRootHint(in.Facts), Evidence: ev})
			continue
		}
		var fails, warns, unknowns []string
		if writableByOthers(u.HomeMeta) {
			fails = append(fails, fmt.Sprintf("home %s is writable by group or others", u.Home))
		}
		if badOwner(u.HomeMeta, u.UID) {
			fails = append(fails, fmt.Sprintf("home %s is owned by uid %d", u.Home, u.HomeMeta.UID))
		}
		if u.SSHDir != nil {
			switch {
			case writableByOthers(u.SSHDir):
				fails = append(fails, "~/.ssh is writable by group or others")
			case u.SSHDir.Mode.Perm() != 0o700:
				warns = append(warns, fmt.Sprintf("~/.ssh is %s, not 0700", modeText(u.SSHDir)))
			}
			if badOwner(u.SSHDir, u.UID) {
				fails = append(fails, fmt.Sprintf("~/.ssh is owned by uid %d", u.SSHDir.UID))
			}
		}
		kfModes := map[string]string{}
		for _, kf := range u.KeyFiles {
			if kf.Meta == nil {
				unknowns = append(unknowns, fmt.Sprintf("%s: %s", kf.Path, kf.Error))
				continue
			}
			kfModes[kf.Path] = modeText(kf.Meta)
			if writableByOthers(kf.Meta) {
				fails = append(fails, kf.Path+" is writable by group or others")
			}
			if badOwner(kf.Meta, u.UID) {
				fails = append(fails, fmt.Sprintf("%s is owned by uid %d", kf.Path, kf.Meta.UID))
			}
		}
		ev["key_files"] = kfModes
		switch {
		case len(fails) > 0:
			out = append(out, Result{Subject: subj, Level: Fail, Message: strings.Join(append(fails, warns...), "; "), Evidence: ev})
		case len(warns) > 0:
			out = append(out, Result{Subject: subj, Level: Warn, Message: strings.Join(warns, "; "), Evidence: ev})
		case len(unknowns) > 0:
			out = append(out, Result{Subject: subj, Level: Unknown, Message: "could not inspect " + strings.Join(unknowns, "; "), Evidence: ev})
		default:
			out = append(out, Result{Subject: subj, Level: Pass, Message: "home, ~/.ssh and authorized keys are private", Evidence: ev})
		}
	}
	if len(out) == 0 {
		return One(Skip, "no account has a ~/.ssh directory or authorized keys file", nil)
	}
	return out
}

func notRootHint(f *facts.Facts) string {
	if !f.IsRoot() {
		return "; run with sudo for full coverage"
	}
	return ""
}

func checkAuthorizedKeyTypes(in Input) []Result {
	s, res := sshFacts(in)
	if s == nil {
		return res
	}
	if s.UsersError != "" {
		return One(Unknown, "could not read /etc/passwd: "+s.UsersError, nil)
	}
	rootLogin, rootKnown := s.Value("permitrootlogin")
	var out []Result
	for _, u := range s.Users {
		subj := "user:" + u.Name
		if u.Error != "" {
			out = append(out, Result{Subject: subj, Level: Unknown, Message: "could not inspect " + u.Error + notRootHint(in.Facts),
				Evidence: map[string]any{"keys": 0, "weak": []string{}}})
			continue
		}
		n, weak, unread := 0, []string{}, []string{}
		for _, kf := range u.KeyFiles {
			if kf.Error != "" {
				unread = append(unread, kf.Path+": "+kf.Error)
			}
			for _, k := range kf.Keys {
				n++
				switch {
				case k.Type == "ssh-dss":
					weak = append(weak, "ssh-dss")
				case k.Type == "ssh-rsa" && k.Bits < minUserRSABits:
					weak = append(weak, fmt.Sprintf("ssh-rsa %d bits", k.Bits))
				}
			}
		}
		ev := map[string]any{"keys": n, "weak": weak}
		var warns []string
		if len(weak) > 0 {
			warns = append(warns, fmt.Sprintf("%s: %s", count(len(weak), "weak key"), strings.Join(weak, ", ")))
		}
		if u.UID == 0 && n > 0 && rootKnown && rootLogin == "no" {
			warns = append(warns, fmt.Sprintf("root has %s while root login is off (stale)", count(n, "authorized key")))
		}
		switch {
		case len(warns) > 0:
			out = append(out, Result{Subject: subj, Level: Warn, Message: strings.Join(warns, "; "), Evidence: ev})
		case len(unread) > 0:
			out = append(out, Result{Subject: subj, Level: Unknown, Message: "could not read " + strings.Join(unread, "; ") + notRootHint(in.Facts), Evidence: ev})
		case n > 0:
			out = append(out, Result{Subject: subj, Level: Pass, Message: fmt.Sprintf("%s, none weak", count(n, "authorized key")), Evidence: ev})
		}
	}
	if len(out) == 0 {
		return One(Skip, "no account has authorized keys", nil)
	}
	return out
}

// weakAlgorithms is a short built in list of algorithms ssh-audit and the
// distribution hardening guides remove. Entries ending in "*" are prefixes.
var weakAlgorithms = map[string][]string{
	"kexalgorithms": {
		"diffie-hellman-group1-sha1", "diffie-hellman-group14-sha1", "diffie-hellman-group-exchange-sha1",
		"gss-gex-sha1-*", "gss-group1-sha1-*", "gss-group14-sha1-*",
	},
	"ciphers": {
		"3des-cbc", "aes128-cbc", "aes192-cbc", "aes256-cbc", "blowfish-cbc", "cast128-cbc",
		"arcfour", "arcfour128", "arcfour256", "rijndael-cbc@lysator.liu.se",
	},
	"macs": {
		"hmac-md5*", "hmac-sha1", "hmac-sha1-96", "hmac-sha1-etm@openssh.com", "hmac-sha1-96-etm@openssh.com",
		"umac-64@openssh.com", "umac-64-etm@openssh.com", "hmac-ripemd160*",
	},
}

func isWeak(kind, alg string) bool {
	for _, w := range weakAlgorithms[kind] {
		if p, ok := strings.CutSuffix(w, "*"); ok && strings.HasPrefix(alg, p) || alg == w {
			return true
		}
	}
	return false
}

func checkWeakAlgorithms(in Input) []Result {
	s, res := sshFacts(in)
	if s == nil {
		return res
	}
	weak := map[string][]string{}
	var unknown []string
	for _, kind := range []string{"kexalgorithms", "ciphers", "macs"} {
		weak[kind] = []string{}
		v, ok := s.Value(kind)
		if !ok {
			unknown = append(unknown, kind)
			continue
		}
		list := v
		partial := false
		switch {
		case strings.HasPrefix(v, "+"):
			// Appended to a built in default stackward does not know.
			list, partial = v[1:], true
		case strings.HasPrefix(v, "-") || strings.HasPrefix(v, "^"):
			unknown = append(unknown, kind)
			continue
		}
		for _, alg := range strings.Split(list, ",") {
			if isWeak(kind, alg) {
				weak[kind] = append(weak[kind], alg)
			}
		}
		if partial && len(weak[kind]) == 0 {
			unknown = append(unknown, kind)
		}
	}
	n := len(weak["kexalgorithms"]) + len(weak["ciphers"]) + len(weak["macs"])
	ev := map[string]any{"weak": weak, "unknown": nonNil(unknown), "source": s.Source}
	switch {
	case n > 0:
		var parts []string
		for _, kind := range []string{"kexalgorithms", "ciphers", "macs"} {
			if len(weak[kind]) > 0 {
				parts = append(parts, kind+": "+strings.Join(weak[kind], ","))
			}
		}
		return One(Warn, "weak algorithms enabled: "+strings.Join(parts, "; "), ev)
	case len(unknown) > 0:
		return One(Unknown, fmt.Sprintf("algorithm lists unknown (%s): %s", strings.Join(unknown, ", "), algWhy(s)), ev)
	}
	return One(Pass, "no weak key exchange, cipher or MAC algorithms enabled", ev)
}

func algWhy(s *facts.SSH) string {
	if s.Source == "files" && s.Complete {
		return "the built in defaults depend on the OpenSSH build and sshd -T was unavailable (" + s.SshdTError + ")"
	}
	return why(s)
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
