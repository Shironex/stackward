package plan

import (
	"slices"
	"sort"
	"strings"
)

// Access is what an access-critical step does to the ways into the host,
// beyond the effective sshd settings its SSHD hook returns. The lockout
// guard reads it; it is not part of the plan file, because it comes from
// the generator's code, never from a plan someone could edit.
type Access struct {
	// ClosesPublicSSH is true when, after the step, sshd can no longer be
	// reached from the internet: a firewall rule drops public SSH, or
	// sshd listens only on private addresses.
	ClosesPublicSSH bool
	// TailnetSSH is true when the step itself lets the tailnet reach
	// sshd (an allow rule on tailscale0 or from 100.64.0.0/10).
	TailnetSSH bool
	// AllowFrom lists the networks (CIDR) that may still reach sshd
	// after the step closes public SSH, besides the tailnet.
	AllowFrom []string
	// Disables lists the accounts the step locks or disables.
	Disables []string
	// RemovesKeys lists the accounts whose authorized keys the step
	// removes, all of them.
	RemovesKeys []string
	// ApplierStays is true when the account applying the step must itself
	// be the proven second way in: create an account, log in as it, and
	// only then lock the old one. An unknown applier is refused.
	ApplierStays bool
	// Bans is true when the step starts banning SSH clients (a fail2ban
	// jail). The lockout guard then requires the session that plans or
	// applies to come from one of IgnoredSources (CIDR or addresses),
	// so a failed login from the owner's own address cannot ban it.
	Bans           bool
	IgnoredSources []string
}

// narrowingSSHD are the sshd keywords that decide who can log in, how and
// where. A step that sets any of them can lock someone out, whatever the
// value, so it needs the lockout guard's proof.
var narrowingSSHD = map[string]string{
	"passwordauthentication":       "password authentication",
	"kbdinteractiveauthentication": "keyboard-interactive authentication",
	"permitrootlogin":              "root login",
	"permitemptypasswords":         "empty passwords",
	"pubkeyauthentication":         "public key authentication",
	"authenticationmethods":        "the authentication methods",
	"authorizedkeysfile":           "the authorized keys files",
	"authorizedkeyscommand":        "the authorized keys command",
	"usepam":                       "PAM",
	"maxauthtries":                 "the number of authentication tries",
	"port":                         "the SSH port",
	"listenaddress":                "the listen addresses",
	"allowusers":                   "AllowUsers",
	"allowgroups":                  "AllowGroups",
	"denyusers":                    "DenyUsers",
	"denygroups":                   "DenyGroups",
}

// change is what a step does to access, from its generator's hooks.
type change struct {
	sshd   map[string]string
	access Access
	// declared is false when the generator has neither hook: the guard
	// then assumes the step narrows every way in.
	declared bool
}

// changeOf reads the access change of step s from its generator. ok is
// false when s is not a known access-critical step: the guard has
// nothing to prove for it.
func changeOf(s Step) (change, bool) {
	g, found := Lookup(s.ID)
	if !found || g.Risk != AccessCritical {
		return change{}, false
	}
	var c change
	if g.SSHD != nil {
		c.sshd, c.declared = g.SSHD(s), true
	}
	if g.Access != nil {
		c.access, c.declared = g.Access(s), true
	}
	return c, true
}

// narrows lists, in words, the ways in the change closes or narrows; nil
// when it narrows none.
func (c change) narrows() []string {
	if !c.declared {
		return []string{"an access-critical change that does not say what it does to access"}
	}
	var out []string
	keys := make([]string, 0, len(c.sshd))
	for k := range c.sshd {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		if what, ok := narrowingSSHD[k]; ok {
			out = append(out, "sets "+what+" ("+k+" "+c.sshd[k]+")")
		}
	}
	a := c.access
	if a.ClosesPublicSSH {
		out = append(out, "closes public SSH")
	}
	if len(a.Disables) > 0 {
		out = append(out, "disables "+strings.Join(a.Disables, ", "))
	}
	if len(a.RemovesKeys) > 0 {
		out = append(out, "removes the authorized keys of "+strings.Join(a.RemovesKeys, ", "))
	}
	return out
}

// disables reports whether the change locks or disables account name.
func (c change) disables(name string) bool { return slices.Contains(c.access.Disables, name) }

// removesKeys reports whether the change removes every key of name.
func (c change) removesKeys(name string) bool { return slices.Contains(c.access.RemovesKeys, name) }

// NeedsProof reports whether step s is access-critical and closes or
// narrows a way in, or starts banning clients, so applying it needs the
// lockout guard's proof from the live host.
func NeedsProof(s Step) bool {
	c, ok := changeOf(s)
	return ok && (len(c.narrows()) > 0 || c.access.Bans)
}
