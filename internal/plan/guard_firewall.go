package plan

import (
	"errors"
	"fmt"
	"net/netip"
	"slices"
	"strconv"
	"strings"

	"github.com/Shironex/stackward/internal/facts"
)

// The lockout guard's rule for a firewall step (Access.Firewall). After
// the step UFW is active and denies incoming traffic by default, so the
// guard proves, from the live UFW rules plus the rules the step adds,
// that every port sshd listens on (from the sshd facts, never an assumed
// 22) still lets the applying session in: the first rule that matches a
// new connection from the session's address on that port allows it. A
// session on the tailnet arrives on tailscale0. A session whose address
// is unknown (the provider console) needs a rule that lets SSH in from
// anywhere. Anything the guard cannot read or decide refuses the step.

// FirewallChange is what a firewall step leaves in UFW.
type FirewallChange struct {
	// What says, in words, what the step does to the firewall.
	What string
	// TurnsOn is true when UFW is inactive before the step and the step
	// turns it on; otherwise UFW must already be active.
	TurnsOn bool
	// Adds are the rules the step appends to UFW's user rules.
	Adds []facts.UFWRule
}

// proveFirewall is the guard for a firewall change fc of step id.
func proveFirewall(id string, p Proof, fc FirewallChange, in GuardInput) (Proof, error) {
	p.Needed = true
	refuse := func(err error) (Proof, error) {
		return p, fmt.Errorf("lockout guard: %s %s, and %w", id, strings.Join(p.Narrows, ", "), err)
	}
	f := in.Facts
	if f == nil || f.Firewall == nil || f.Firewall.UFW == nil {
		return refuse(errors.New("the firewall was not audited, so whether SSH stays reachable is unknown"))
	}
	u := f.Firewall.UFW
	switch {
	case !u.Installed:
		return refuse(errors.New("UFW is not installed"))
	case !u.Live():
		return refuse(errors.New("the live UFW state could not be read (run as root)"))
	case !u.RulesKnown:
		return refuse(errors.New("the UFW rules could not be read"))
	case fc.TurnsOn && u.Status != "inactive":
		return refuse(fmt.Errorf("the step turns UFW on, but UFW is %s now; plan again", orNoState(u.Status)))
	case !fc.TurnsOn && u.Status != "active":
		return refuse(fmt.Errorf("the step expects UFW to be active, but it is %s now; plan again", orNoState(u.Status)))
	}
	ports := sshdPortsKnown(f)
	if len(ports) == 0 {
		return refuse(errors.New("the port sshd listens on is unknown (no sshd facts and no sshd listener), and the guard does not assume 22"))
	}
	rules := append(slices.Clone(u.Rules), fc.Adds...)
	anywhere := false
	var nets []string
	for _, port := range ports {
		way, from, err := sshAllowed(rules, u.IPv6, port, in.Source)
		if err != nil {
			return refuse(err)
		}
		p.Ways = append(p.Ways, way)
		if len(from) == 0 {
			anywhere = true
		}
		for _, n := range from {
			if !slices.Contains(nets, n) {
				nets = append(nets, n)
			}
		}
	}
	if !anywhere {
		p.ConfirmFrom = nets
	}
	return p, nil
}

// sshdPortsKnown returns the TCP ports sshd is configured for or listens
// on, from the sshd and listener facts; nil when neither says.
func sshdPortsKnown(f *facts.Facts) []int {
	seen := map[int]bool{}
	if f.Listeners != nil {
		for _, s := range f.Listeners.Sockets {
			if s.Proto == "tcp" && s.HasProcess("sshd") {
				seen[s.Port] = true
			}
		}
	}
	if f.SSH != nil {
		for _, p := range f.SSH.Effective["port"] {
			if n, err := strconv.Atoi(p); err == nil && n > 0 && n < 65536 {
				seen[n] = true
			}
		}
	}
	var out []int
	for p := range seen {
		out = append(out, p)
	}
	slices.Sort(out)
	return out
}

// fwMatch is whether a UFW rule matches a new connection from the session.
type fwMatch int

const (
	fwNo    fwMatch = iota
	fwMaybe         // the facts cannot tell (an unknown source, another interface)
	fwYes
)

// sshAllowed walks UFW's input rules in order for a new TCP connection
// to port from src, as UFW does. The first rule that surely matches and
// allows wins; a deny or reject that may match first refuses; no rule
// leaves the default deny. It returns the way in and, when the allowing
// rule only lets some networks in, those networks.
func sshAllowed(rules []facts.UFWRule, ipv6 string, port int, src netip.Addr) (string, []string, error) {
	src = src.Unmap()
	v6 := src.IsValid() && src.Is6()
	if v6 && ipv6 != "yes" {
		return "", nil, fmt.Errorf("this session comes over IPv6 (%s) and UFW has IPV6=%s, so the guard cannot tell what UFW does to it; apply from an IPv4 session", src, ipv6Word(ipv6))
	}
	who := "a session from anywhere (this session's address is unknown)"
	if src.IsValid() {
		who = "this session (" + src.String() + ")"
	}
	tailnet := src.IsValid() && (TailnetV4.Contains(src) || TailnetV6.Contains(src))
	for _, r := range rules {
		if r.Direction != "in" || r.V6 != v6 || !r.MatchesPort("tcp", port) {
			continue
		}
		m := sessionMatch(r, src, tailnet)
		switch {
		case r.Allows() && m == fwYes:
			return fmt.Sprintf("tcp/%d lets %s in through UFW rule %q", port, who, ufwRuleWords(r)), allowedNets(r), nil
		case !r.Allows() && m != fwNo:
			return "", nil, fmt.Errorf("UFW rule %q comes first and would drop SSH on tcp/%d for %s", ufwRuleWords(r), port, who)
		}
	}
	return "", nil, fmt.Errorf("no UFW rule would let SSH on tcp/%d in for %s, and the default denies it; allow it first", port, who)
}

// sessionMatch decides whether rule r matches a connection from src
// (tailnet when src is a tailnet address, which arrives on tailscale0).
func sessionMatch(r facts.UFWRule, src netip.Addr, tailnet bool) fwMatch {
	m := fwYes
	worse := func(x fwMatch) {
		if x < m {
			m = x
		}
	}
	if r.To != "" {
		worse(fwMaybe)
	}
	switch {
	case r.Interface == "":
	case !src.IsValid():
		worse(fwMaybe)
	case r.Interface == tailnetIface && !tailnet, r.Interface != tailnetIface && tailnet:
		worse(fwNo)
	case r.Interface != tailnetIface:
		worse(fwMaybe)
	}
	if r.From != "" {
		n, ok := parseNet(r.From)
		switch {
		case !ok || !src.IsValid():
			worse(fwMaybe)
		case !n.Contains(src):
			worse(fwNo)
		}
	}
	return m
}

// allowedNets returns the networks rule r lets in, nil for anywhere.
func allowedNets(r facts.UFWRule) []string {
	if r.From != "" {
		if n, ok := parseNet(r.From); ok {
			return []string{n.Masked().String()}
		}
	}
	if r.Interface == tailnetIface {
		return []string{TailnetV4.String(), TailnetV6.String()}
	}
	return nil
}

// ufwRuleWords prints a rule the way the guard names it.
func ufwRuleWords(r facts.UFWRule) string {
	parts := []string{r.Action, r.Direction}
	switch {
	case r.Port != "":
		parts = append(parts, r.Port+"/"+r.Proto)
	default:
		parts = append(parts, "any port")
	}
	if r.Interface != "" {
		parts = append(parts, "on "+r.Interface)
	}
	from := r.From
	if from == "" {
		from = "anywhere"
	}
	parts = append(parts, "from "+from)
	if r.V6 {
		parts = append(parts, "(v6)")
	}
	return strings.Join(parts, " ")
}

func ipv6Word(s string) string {
	if s == "" {
		return "unknown"
	}
	return s
}
