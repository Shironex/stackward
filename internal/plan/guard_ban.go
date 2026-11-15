package plan

import (
	"fmt"
	"net/netip"
	"strings"
)

// banSpares is the lockout guard's rule for a step that starts banning
// SSH clients (Access.Bans): the session that plans or applies must come
// from an address the step never bans, so a mistyped key or a failed
// test login from the owner's own address cannot lock the owner out.
// A session whose source is unknown (the provider console, or no SSH
// session) cannot be banned and passes.
func banSpares(id string, a Access, src netip.Addr) error {
	if !a.Bans || !src.IsValid() {
		return nil
	}
	src = src.Unmap()
	if sourceIn(src, a.IgnoredSources) {
		return nil
	}
	return fmt.Errorf("lockout guard: %s bans SSH clients, and this session comes from %s, which it does not ignore (it ignores %s); plan again from this session so its address is added", id, src, strings.Join(a.IgnoredSources, " "))
}

// sourceIn reports whether addr lies in one of entries (CIDR or plain
// addresses); entries that are neither never match.
func sourceIn(addr netip.Addr, entries []string) bool {
	for _, e := range entries {
		if n, ok := parseNet(e); ok && n.Contains(addr) {
			return true
		}
	}
	return false
}

// parseNet reads a CIDR or a plain address (as a single host network).
func parseNet(s string) (netip.Prefix, bool) {
	if n, err := netip.ParsePrefix(s); err == nil {
		return n, true
	}
	a, err := netip.ParseAddr(s)
	if err != nil {
		return netip.Prefix{}, false
	}
	a = a.Unmap()
	return netip.PrefixFrom(a, a.BitLen()), true
}
