package plan

import (
	"fmt"
	"net/netip"
	"path"
	"strconv"
	"strings"

	"github.com/Shironex/stackward/internal/facts"
	"github.com/Shironex/stackward/internal/facts/sshd"
)

// The sshd half of the lockout guard: the effective configuration a step
// leaves behind, evaluated for one account and one source the way sshd
// decides a login (sshd_config(5), auth.c allowed_user, match.c).

// tri is a yes, no or "cannot tell" answer.
type tri int

const (
	triNo tri = iota
	triYes
	triMaybe
)

// source is where a connection comes from, as far as the guard knows: one
// address, a network (the tailnet), or nothing.
type source struct {
	net   netip.Prefix
	known bool
	label string
}

func addrSource(a netip.Addr) source {
	if !a.IsValid() {
		return source{label: "an unknown address"}
	}
	a = a.Unmap()
	return source{net: netip.PrefixFrom(a, a.BitLen()), known: true, label: a.String()}
}

func netSource(p netip.Prefix, label string) source {
	return source{net: p.Masked(), known: true, label: label}
}

// guardKeys are the effective settings the guard reads; every one must be
// known, or the guard cannot prove anything.
var guardKeys = []string{
	"pubkeyauthentication", "authenticationmethods", "authorizedkeysfile", "usepam",
	"allowusers", "denyusers", "allowgroups", "denygroups", "port", "listenaddress",
}

// sshdView is the configuration after the step: the global settings with
// the step's values laid over, and the Match blocks as they are.
type sshdView struct {
	global map[string][]string
	blocks []matchBlock
}

type matchBlock struct {
	where      string
	criteria   string
	incomplete bool
	settings   map[string][]string
}

// projectSSHD lays the step's effective settings over the audited ones.
func projectSSHD(s *facts.SSH, set map[string]string) (*sshdView, error) {
	switch {
	case s == nil:
		return nil, fmt.Errorf("sshd was not audited")
	case !s.Installed:
		return nil, fmt.Errorf("sshd is not installed, so no SSH way in exists")
	case s.Config == nil:
		return nil, fmt.Errorf("the sshd configuration files were not read, so Match blocks cannot be checked")
	}
	v := &sshdView{global: map[string][]string{}}
	for _, k := range guardKeys {
		if val, ok := set[k]; ok {
			v.global[k] = splitSetting(k, val)
			continue
		}
		val, ok := s.Setting(k)
		if !ok {
			return nil, fmt.Errorf("sshd's effective %s is not known (run the audit as root, so sshd -T answers)", k)
		}
		v.global[k] = fieldsOf(val)
	}
	for i, m := range s.Config.Matches {
		b := matchBlock{where: fmt.Sprintf("%s:%d", m.File, m.Line), criteria: m.Criteria, incomplete: m.Incomplete, settings: map[string][]string{}}
		for _, d := range s.Config.Directives {
			if d.Match == i+1 {
				b.settings[d.Keyword] = append(b.settings[d.Keyword], strings.Fields(d.Value)...)
			}
		}
		v.blocks = append(v.blocks, b)
	}
	return v, nil
}

// splitSetting reads a value in the form a step's SSHD hook gives it (as
// the transaction compares it with sshd -T): accumulating keywords join
// their values with commas.
func splitSetting(k, val string) []string {
	if !sshd.Accumulates(k) {
		return strings.Fields(val)
	}
	var out []string
	for _, part := range strings.Split(val, ",") {
		out = append(out, strings.Fields(part)...)
	}
	return out
}

func fieldsOf(vals []string) []string {
	var out []string
	for _, v := range vals {
		out = append(out, strings.Fields(v)...)
	}
	return out
}

// ports returns the sshd ports after the step.
func (v *sshdView) ports() []int {
	var out []int
	for _, p := range v.global["port"] {
		if n, err := strconv.Atoi(p); err == nil {
			out = append(out, n)
		}
	}
	return out
}

// account is what the guard knows about one login candidate.
type account struct {
	facts.Account
	groups []string
	keys   []facts.SSHKeyFile
}

// loginFor decides whether a can log in with a key from src after the
// step. A Match block the guard cannot decide is tried both ways, and the
// login must work either way. It returns "" when it works, or the reason
// it does not.
func (v *sshdView) loginFor(a account, src source) string {
	var open []int
	applies := make([]tri, len(v.blocks))
	for i, b := range v.blocks {
		applies[i] = b.applies(a, src, v.ports())
		if applies[i] == triMaybe {
			open = append(open, i)
		}
	}
	const maxOpen = 6
	if len(open) > maxOpen {
		return fmt.Sprintf("%d Match blocks may or may not apply to %s from %s; too many to try every way", len(open), a.Name, src.label)
	}
	for mask := 0; mask < 1<<len(open); mask++ {
		on := make([]bool, len(v.blocks))
		for i, t := range applies {
			on[i] = t == triYes
		}
		for bit, i := range open {
			on[i] = mask&(1<<bit) != 0
		}
		set, why := v.settingsFor(on)
		if why == "" {
			why = canLogin(a, set, src)
		}
		if why != "" {
			return why + v.assumed(open, on, a, src)
		}
	}
	return ""
}

// assumed names the undecided Match blocks taken as applying in a failed
// try, so the refusal says which block to look at.
func (v *sshdView) assumed(open []int, on []bool, a account, src source) string {
	var parts []string
	for _, i := range open {
		if on[i] {
			parts = append(parts, fmt.Sprintf("the Match block at %s (%s)", v.blocks[i].where, v.blocks[i].criteria))
		}
	}
	if len(parts) == 0 {
		return ""
	}
	return fmt.Sprintf(" (with %s applied, which the guard cannot rule out for %s from %s)", strings.Join(parts, " and "), a.Name, src.label)
}

// settingsFor returns the settings of a connection that the blocks
// marked on apply to: the first block that sets a keyword wins over the
// global value.
func (v *sshdView) settingsFor(on []bool) (map[string][]string, string) {
	set := make(map[string][]string, len(v.global))
	for k, val := range v.global {
		set[k] = val
	}
	seen := map[string]bool{}
	for i, b := range v.blocks {
		if !on[i] {
			continue
		}
		if b.incomplete {
			return nil, fmt.Sprintf("the Match block at %s includes a file that could not be read, so what it sets is unknown", b.where)
		}
		for k, val := range b.settings {
			if !seen[k] {
				seen[k] = true
				set[k] = val
			}
		}
	}
	return set, ""
}

// canLogin checks one set of connection settings: AllowUsers, DenyUsers,
// AllowGroups and DenyGroups, public key authentication, the
// authentication methods, a locked account, and a usable key in one of
// the authorized keys files.
func canLogin(a account, set map[string][]string, src source) string {
	if why := userLists(a, set, src); why != "" {
		return why
	}
	if first(set["pubkeyauthentication"]) != "yes" {
		return fmt.Sprintf("public key authentication would be off for %s", a.Name)
	}
	if !keyOnly(set["authenticationmethods"]) {
		return fmt.Sprintf("AuthenticationMethods %q needs more than a key for %s", strings.Join(set["authenticationmethods"], " "), a.Name)
	}
	if first(set["usepam"]) == "no" && a.PasswordStatus == "L" {
		return fmt.Sprintf("%s is locked and UsePAM is off, so sshd refuses the account even with a key", a.Name)
	}
	files := keyFiles(set["authorizedkeysfile"], a)
	for _, kf := range a.keys {
		if files[path.Clean(kf.Path)] && usableKeys(kf) > 0 {
			return ""
		}
	}
	return fmt.Sprintf("%s has no usable key in the authorized keys files sshd would read (%s)", a.Name, strings.Join(set["authorizedkeysfile"], " "))
}

func userLists(a account, set map[string][]string, src source) string {
	if m := matchUsers(set["denyusers"], a.Name, src); m != triNo {
		return fmt.Sprintf("DenyUsers %s %s", strings.Join(set["denyusers"], " "), refuses(m, a.Name, src))
	}
	if allow := set["allowusers"]; len(allow) > 0 && matchUsers(allow, a.Name, src) != triYes {
		return fmt.Sprintf("AllowUsers %s does not let %s in from %s", strings.Join(allow, " "), a.Name, src.label)
	}
	if m := matchGroups(set["denygroups"], a.groups); m != triNo {
		return fmt.Sprintf("DenyGroups %s %s", strings.Join(set["denygroups"], " "), refuses(m, a.Name, src))
	}
	if allow := set["allowgroups"]; len(allow) > 0 && matchGroups(allow, a.groups) != triYes {
		return fmt.Sprintf("AllowGroups %s does not let %s in (groups %s)", strings.Join(allow, " "), a.Name, strings.Join(a.groups, ", "))
	}
	return ""
}

func refuses(m tri, user string, src source) string {
	if m == triMaybe {
		return "may refuse " + user + " from " + src.label
	}
	return "refuses " + user
}

// keyOnly reports whether some AuthenticationMethods list is satisfied by
// public keys alone.
func keyOnly(methods []string) bool {
	if len(methods) == 0 || (len(methods) == 1 && methods[0] == "any") {
		return true
	}
	for _, list := range methods {
		ok := true
		for _, m := range strings.Split(list, ",") {
			if m != "publickey" {
				ok = false
			}
		}
		if ok {
			return true
		}
	}
	return false
}

// keyFiles expands AuthorizedKeysFile for one account (%h, %u, %U, %%;
// relative paths start at the home directory).
func keyFiles(spec []string, a account) map[string]bool {
	out := map[string]bool{}
	r := strings.NewReplacer("%%", "%", "%h", a.Home, "%u", a.Name, "%U", strconv.Itoa(a.UID))
	for _, f := range spec {
		if strings.EqualFold(f, "none") {
			continue
		}
		p := r.Replace(f)
		if !path.IsAbs(p) {
			p = path.Join(a.Home, p)
		}
		out[path.Clean(p)] = true
	}
	return out
}

// usableKeys counts the keys current OpenSSH still accepts: no DSA, no
// RSA under 1024 bits.
func usableKeys(kf facts.SSHKeyFile) int {
	n := 0
	for _, k := range kf.Keys {
		if k.Type == "ssh-dss" || (k.Type == "ssh-rsa" && k.Bits > 0 && k.Bits < 1024) {
			continue
		}
		n++
	}
	return n
}

func first(v []string) string {
	if len(v) == 0 {
		return ""
	}
	return strings.ToLower(v[0])
}

// applies decides whether the block applies to a from src. Criteria the
// guard cannot evaluate (Host, LocalAddress, RDomain, anything unknown)
// are "cannot tell".
func (b matchBlock) applies(a account, src source, ports []int) tri {
	f := strings.Fields(b.criteria)
	if len(f) == 1 && strings.EqualFold(f[0], "all") {
		return triYes
	}
	res := triYes
	for i := 0; i < len(f); i += 2 {
		if i+1 >= len(f) {
			return triMaybe
		}
		var t tri
		switch strings.ToLower(f[i]) {
		case "user":
			t = matchList(f[i+1], func(p string) tri { return boolTri(wildMatch(p, a.Name)) })
		case "group":
			t = matchGroups([]string{f[i+1]}, a.groups)
		case "address":
			t = matchList(f[i+1], func(p string) tri { return matchAddr(p, src) })
		case "localport":
			t = matchPorts(f[i+1], ports)
		default:
			t = triMaybe
		}
		res = and(res, t)
	}
	return res
}

func and(a, b tri) tri {
	switch {
	case a == triNo || b == triNo:
		return triNo
	case a == triMaybe || b == triMaybe:
		return triMaybe
	}
	return triYes
}

func boolTri(b bool) tri {
	if b {
		return triYes
	}
	return triNo
}

// matchList is sshd's match_pattern_list: comma separated patterns, a
// leading "!" negates, and a matching negated pattern fails the list.
func matchList(list string, one func(string) tri) tri {
	res, negMaybe := triNo, false
	for _, p := range strings.Split(list, ",") {
		neg := strings.HasPrefix(p, "!")
		t := one(strings.TrimPrefix(p, "!"))
		switch {
		case neg && t == triYes:
			return triNo
		case neg && t == triMaybe:
			negMaybe = true
		case !neg && t == triYes:
			res = triYes
		case !neg && t == triMaybe && res == triNo:
			res = triMaybe
		}
	}
	if res == triYes && negMaybe {
		return triMaybe
	}
	return res
}

// matchUsers matches AllowUsers or DenyUsers entries (USER or USER@HOST)
// against an account and a source.
func matchUsers(entries []string, user string, src source) tri {
	res := triNo
	for _, e := range entries {
		u, host, hasHost := strings.Cut(e, "@")
		if !wildMatch(u, user) {
			continue
		}
		t := triYes
		if hasHost {
			t = matchList(host, func(p string) tri { return matchAddr(p, src) })
		}
		if t == triYes {
			return triYes
		}
		if t == triMaybe {
			res = triMaybe
		}
	}
	return res
}

// matchGroups matches group pattern lists against the account's groups.
func matchGroups(entries []string, groups []string) tri {
	res := triNo
	for _, e := range entries {
		for _, g := range groups {
			if t := matchList(e, func(p string) tri { return boolTri(wildMatch(p, g)) }); t == triYes {
				return triYes
			} else if t == triMaybe {
				res = triMaybe
			}
		}
	}
	return res
}

// matchAddr matches one address pattern (an address, a CIDR network or a
// wildcard pattern) against a source.
func matchAddr(p string, src source) tri {
	if p == "*" {
		return triYes
	}
	if !src.known {
		return triMaybe
	}
	if n, err := netip.ParsePrefix(p); err == nil {
		n = n.Masked()
		switch {
		case n.Bits() <= src.net.Bits() && n.Contains(src.net.Addr()):
			return triYes
		case !n.Overlaps(src.net):
			return triNo
		}
		return triMaybe
	}
	if a, err := netip.ParseAddr(p); err == nil {
		return matchAddr(netip.PrefixFrom(a, a.BitLen()).String(), src)
	}
	if src.net.IsSingleIP() && strings.ContainsAny(p, "*?") {
		return boolTri(wildMatch(p, src.net.Addr().String()))
	}
	return triMaybe
}

// matchPorts decides a LocalPort criterion over every sshd port.
func matchPorts(list string, ports []int) tri {
	var yes, no int
	for _, port := range ports {
		switch matchList(list, func(p string) tri { return boolTri(p == strconv.Itoa(port)) }) {
		case triYes:
			yes++
		default:
			no++
		}
	}
	switch {
	case no == 0 && yes > 0:
		return triYes
	case yes == 0:
		return triNo
	}
	return triMaybe
}
