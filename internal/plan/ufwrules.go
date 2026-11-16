package plan

import (
	"errors"
	"fmt"
	"strconv"
	"strings"

	"github.com/Shironex/stackward/internal/facts"
)

// The firewall steps (ufw-policy, ufw-docker) write UFW's own files
// instead of running `ufw allow`, so a plan shows the exact change, apply
// keeps a backup, and undo puts the previous files back byte for byte.
// This file renders and reads back the rules they add to
// /etc/ufw/user.rules and user6.rules, in the format ufw itself writes:
// a "### tuple ###" comment (ufw's own record of the rule) followed by
// the iptables line it loads, inserted before "### END RULES ###".
//
// The steps only ever add allow rules of four shapes: an input rule for a
// TCP port from anywhere, an input rule for everything on tailscale0, a
// route rule for a container port from anywhere, and a route rule for
// everything on tailscale0. Nothing else is accepted back.

const (
	ufwRulesBegin = "### RULES ###"
	ufwRulesEnd   = "### END RULES ###"
)

// ufwAdd is one allow rule a firewall step adds.
type ufwAdd struct {
	// route is true for a route rule (forwarded traffic, ufw route allow).
	route bool
	// proto is "tcp" or "udp" for a port rule, "any" for an interface rule.
	proto string
	// port is the destination port; 0 for an interface rule.
	port int
	// iface is tailnetIface for an interface rule, "" for a port rule.
	iface string
	v6    bool
}

// tuple is ufw's comment line for the rule.
func (r ufwAdd) tuple() string {
	anyNet := "0.0.0.0/0"
	if r.v6 {
		anyNet = "::/0"
	}
	action := "allow"
	if r.route {
		action = "route:allow"
	}
	port, dir := "any", "in"
	if r.port > 0 {
		port = strconv.Itoa(r.port)
	}
	if r.iface != "" {
		dir = "in_" + r.iface
	}
	return fmt.Sprintf("### tuple ### %s %s %s %s any %s %s", action, r.proto, port, anyNet, anyNet, dir)
}

// iptables is the line ufw loads for the rule.
func (r ufwAdd) iptables() string {
	chain := "ufw-user-input"
	if r.route {
		chain = "ufw-user-forward"
	}
	if r.v6 {
		chain = strings.Replace(chain, "ufw-", "ufw6-", 1)
	}
	line := "-A " + chain
	if r.iface != "" {
		line += " -i " + r.iface
	}
	if r.port > 0 {
		line += fmt.Sprintf(" -p %s --dport %d", r.proto, r.port)
	}
	return line + " -j ACCEPT"
}

// block is the rule as it sits in the file: tuple, iptables line, and the
// blank line ufw keeps between rules.
func (r ufwAdd) block() string { return r.tuple() + "\n" + r.iptables() + "\n\n" }

// fact is the rule as the firewall facts parse it back.
func (r ufwAdd) fact() facts.UFWRule {
	got := facts.ParseUFWUserRules([]byte(r.tuple()), r.v6)
	return got[0]
}

// words describes the rule for notes and the lockout guard's output.
func (r ufwAdd) words() string {
	what := "allow in"
	if r.route {
		what = "route allow"
	}
	if r.iface != "" {
		what += " on " + r.iface
	} else {
		what += fmt.Sprintf(" %d/%s from anywhere", r.port, r.proto)
	}
	if r.v6 {
		what += " (v6)"
	}
	return what
}

// shapeOK reports whether r is one of the four shapes, and whether a step
// that adds route rules (or input rules) may add it.
func (r ufwAdd) shapeOK(route bool) bool {
	if r.route != route {
		return false
	}
	switch r.iface {
	case tailnetIface:
		return r.proto == "any" && r.port == 0
	case "":
		portProto := r.proto == "tcp" || (route && r.proto == "udp")
		return portProto && r.port > 0 && r.port < 65536
	}
	return false
}

// rulesEnd returns the offset of the "### END RULES ###" line in a user
// rules file, after checking that the file has exactly one rules section.
func rulesEnd(content string) (int, error) {
	lines := strings.SplitAfter(content, "\n")
	begin, end, at, off := 0, 0, -1, 0
	for _, l := range lines {
		switch strings.TrimRight(l, "\n") {
		case ufwRulesBegin:
			begin++
		case ufwRulesEnd:
			end++
			at = off
		}
		off += len(l)
	}
	if begin != 1 || end != 1 || at < 0 || !strings.HasSuffix(content, "\n") {
		return 0, errors.New("it does not have the one RULES section ufw writes")
	}
	if !strings.HasSuffix(content[:at], "\n\n") {
		return 0, errors.New("its last rule is not followed by the blank line ufw writes")
	}
	return at, nil
}

// addRules inserts adds at the end of the rules section of a user rules
// file, where `ufw allow` appends. ufw's template becomes the file ufw
// writes in its place first (see fromTemplate).
func addRules(content string, adds []ufwAdd, v6 bool) (string, error) {
	content = fromTemplate(content, v6)
	at, err := rulesEnd(content)
	if err != nil {
		return "", err
	}
	var b strings.Builder
	b.WriteString(content[:at])
	for _, r := range adds {
		b.WriteString(r.block())
	}
	b.WriteString(content[at:])
	return b.String(), nil
}

// addedRules reads back the rules an edit of a user rules file added:
// the new content must be the old one with rule blocks of the allowed
// shapes inserted before "### END RULES ###", and nothing else.
func addedRules(e FileEdit, v6, route bool) ([]ufwAdd, error) {
	old := fromTemplate(e.Old, v6)
	at, err := rulesEnd(old)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", e.Path, err)
	}
	head, tail := old[:at], old[at:]
	if !strings.HasPrefix(e.New, head) || !strings.HasSuffix(e.New, tail) || len(e.New) <= len(head)+len(tail) {
		return nil, fmt.Errorf("%s: the change is not rules added at the end of the RULES section", e.Path)
	}
	middle := e.New[len(head) : len(e.New)-len(tail)]
	var out []ufwAdd
	for middle != "" {
		tuple, rest, ok1 := strings.Cut(middle, "\n")
		line, rest, ok2 := strings.Cut(rest, "\n")
		blank, rest, ok3 := strings.Cut(rest, "\n")
		if !ok1 || !ok2 || !ok3 || blank != "" {
			return nil, fmt.Errorf("%s: an added rule is not a tuple, an iptables line and a blank line", e.Path)
		}
		r, err := parseAdd(tuple, v6)
		if err != nil {
			return nil, fmt.Errorf("%s: %w", e.Path, err)
		}
		if !r.shapeOK(route) || r.iptables() != line {
			return nil, fmt.Errorf("%s: rule %q is not one the step adds", e.Path, tuple)
		}
		out = append(out, r)
		middle = rest
	}
	return out, nil
}

// parseAdd reads a tuple line the step would write.
func parseAdd(tuple string, v6 bool) (ufwAdd, error) {
	f := strings.Fields(strings.TrimPrefix(tuple, "### tuple ###"))
	anyNet := "0.0.0.0/0"
	if v6 {
		anyNet = "::/0"
	}
	if !strings.HasPrefix(tuple, "### tuple ### ") || len(f) != 7 || f[3] != anyNet || f[4] != "any" || f[5] != anyNet {
		return ufwAdd{}, fmt.Errorf("rule %q is not one the step adds", tuple)
	}
	r := ufwAdd{proto: f[1], v6: v6}
	switch f[0] {
	case "allow":
	case "route:allow":
		r.route = true
	default:
		return ufwAdd{}, fmt.Errorf("rule %q does not allow", tuple)
	}
	if f[2] != "any" {
		n, err := strconv.Atoi(f[2])
		if err != nil || strconv.Itoa(n) != f[2] {
			return ufwAdd{}, fmt.Errorf("rule %q has a port the step does not write", tuple)
		}
		r.port = n
	}
	switch dir := f[6]; {
	case dir == "in":
	case strings.HasPrefix(dir, "in_"):
		r.iface = strings.TrimPrefix(dir, "in_")
	default:
		return ufwAdd{}, fmt.Errorf("rule %q is not an inbound rule", tuple)
	}
	return r, nil
}

// setShellVar replaces the one KEY=... line of a shell variable file
// (/etc/default/ufw, /etc/ufw/ufw.conf) with KEY=value, the way
// `ufw default` and `ufw enable` rewrite it. A file without exactly one
// such line is refused.
func setShellVar(content, key, value string) (string, error) {
	lines := strings.SplitAfter(content, "\n")
	found := 0
	for i, l := range lines {
		if strings.HasPrefix(l, key+"=") {
			found++
			lines[i] = key + "=" + value + "\n"
		}
	}
	if found != 1 || !strings.HasSuffix(content, "\n") {
		return "", fmt.Errorf("it does not set %s on exactly one line", key)
	}
	return strings.Join(lines, ""), nil
}

// shellVar returns the unquoted value of the one KEY=... line, "" when
// there is none.
func shellVar(content, key string) string {
	for _, l := range strings.Split(content, "\n") {
		if v, ok := strings.CutPrefix(l, key+"="); ok {
			return strings.Trim(strings.TrimSpace(v), `"'`)
		}
	}
	return ""
}
