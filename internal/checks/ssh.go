package checks

import (
	"fmt"
	"strconv"
	"strings"

	"github.com/Shironex/stackward/internal/facts"
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
	// "not root" is said once by the report; every other reason adds detail.
	if s.SshdTError != "" && s.SshdTError != "not root" {
		parts = append(parts, "sshd -T unavailable: "+s.SshdTError)
	}
	if len(parts) == 0 && s.SshdTError == "not root" {
		parts = append(parts, "sshd -T needs root")
	}
	if len(parts) == 0 {
		parts = append(parts, "the configuration does not settle it")
	}
	msg := strings.Join(parts, "; ")
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
