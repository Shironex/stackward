package apply

import (
	"net/netip"
	"strconv"
	"strings"

	"github.com/Shironex/stackward/internal/facts"
	"github.com/Shironex/stackward/internal/plan"
)

// NeedsProof reports whether any of steps closes or narrows a way in, so
// the lockout guard must prove a second way in from the live host before
// the transaction opens.
func NeedsProof(steps []plan.Step) bool {
	for _, s := range steps {
		if plan.NeedsProof(s) {
			return true
		}
	}
	return false
}

// GuardAccess runs the lockout guard on every step against live, facts
// read from this host right now (the plan's facts may be stale), and the
// session that applies: its client address is the source the guard
// evaluates, and its login user may not be disabled. It only reads. The
// first step whose second way in cannot be proven refuses the run.
func GuardAccess(steps []plan.Step, live *facts.Facts, sess Session) ([]plan.Proof, error) {
	in := GuardInput(live, sess)
	var out []plan.Proof
	for _, s := range steps {
		p, err := plan.ProveAccess(s, in)
		if err != nil {
			return nil, err
		}
		out = append(out, p)
	}
	return out, nil
}

// GuardInput is what the lockout guard proves from for the session sess
// over facts f: the session's client address and its login user.
func GuardInput(f *facts.Facts, sess Session) plan.GuardInput {
	return plan.GuardInput{Facts: f, Source: sess.ClientAddr(), Applier: loginName(f, sess.LoginUID)}
}

// ConfirmFrom joins the networks the proofs require the confirming
// session to come from, without repeats.
func ConfirmFrom(proofs []plan.Proof) []string {
	var out []string
	seen := map[string]bool{}
	for _, p := range proofs {
		for _, n := range p.ConfirmFrom {
			if !seen[n] {
				seen[n] = true
				out = append(out, n)
			}
		}
	}
	return out
}

// ClientAddr is the client address of SSH_CONNECTION; not valid when the
// session is not over SSH or the address cannot be read.
func (s Session) ClientAddr() netip.Addr {
	f := strings.Fields(s.SSHConnection)
	if len(f) == 0 {
		return netip.Addr{}
	}
	a, err := netip.ParseAddr(f[0])
	if err != nil {
		return netip.Addr{}
	}
	return a.Unmap()
}

// loginName maps a login uid to its account name in f, "" when unknown.
func loginName(f *facts.Facts, uid string) string {
	n, err := strconv.Atoi(uid)
	if err != nil || f == nil || f.Users == nil {
		return ""
	}
	for _, a := range f.Users.Accounts {
		if a.UID == n {
			return a.Name
		}
	}
	return ""
}

// fromAny reports whether addr is inside one of nets (CIDR strings).
func fromAny(addr netip.Addr, nets []string) bool {
	if !addr.IsValid() {
		return false
	}
	for _, s := range nets {
		if n, err := netip.ParsePrefix(s); err == nil && n.Contains(addr) {
			return true
		}
	}
	return false
}
