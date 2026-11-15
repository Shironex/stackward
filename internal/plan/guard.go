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

// The lockout guard. Before an access-critical step may close or narrow a
// way in (password authentication off, root login off, a new port,
// AllowUsers or AllowGroups, a firewall rule that drops public SSH, a
// disabled account, removed keys), it proves from facts that a second way
// in survives the step:
//
//   - public SSH stays open: a non-root account with sudo and a usable
//     authorized key logs in with that key under the sshd configuration
//     the step leaves behind (AllowUsers and AllowGroups, DenyUsers and
//     DenyGroups, PubkeyAuthentication, AuthenticationMethods,
//     AuthorizedKeysFile and every Match block for that account and the
//     source), on a port the firewall lets in;
//   - public SSH closes: the same account logs in over the tailnet
//     (Tailscale running with key expiry off, sshd listening on the
//     tailnet, the firewall letting the tailnet reach it), or from a
//     network the step still allows, which the session must come from.
//
// Plan proves it from the audit's facts (LockoutVeto); apply proves it
// again from facts read from the live host right before the transaction,
// because the plan's facts may be stale. The transaction's confirm from a
// new session stays the final proof: when public SSH closes, that session
// must arrive over the way that stays (Proof.ConfirmFrom). When the proof
// fails, the step is refused with the missing piece. The guard fails
// closed: what it cannot read or decide counts against the proof.

// Tailnet networks: Tailscale's CGNAT range and its IPv6 ULA range.
var (
	TailnetV4 = netip.MustParsePrefix("100.64.0.0/10")
	TailnetV6 = netip.MustParsePrefix("fd7a:115c:a1e0::/48")
)

// tailnetIface is the interface Tailscale creates on Linux.
const tailnetIface = "tailscale0"

// GuardInput is what the lockout guard proves from.
type GuardInput struct {
	Facts *facts.Facts
	// Source is the client address of the session that plans or applies;
	// not valid when unknown (no SSH session, or a saved facts file).
	Source netip.Addr
	// Applier is the account that applies, "" when unknown.
	Applier string
}

// Proof is the guard's answer for one step.
type Proof struct {
	// Needed is false when the step narrows no way in.
	Needed bool
	// Narrows says, in words, what the step closes or narrows.
	Narrows []string
	// Ways says which second way in survives, one line each.
	Ways []string
	// ConfirmFrom, when set, lists the networks the confirming session
	// must come from: the step closes public SSH, so a confirm from
	// anywhere else proves nothing about the way that stays.
	ConfirmFrom []string
}

// LockoutVeto returns the plan time policy: it refuses an access-critical
// step whose second way in the guard cannot prove from in.
func LockoutVeto(in GuardInput) Veto {
	return func(s Step) string {
		if _, err := ProveAccess(s, in); err != nil {
			return err.Error()
		}
		return ""
	}
}

// ProveAccess proves that a second way in survives step s, or returns an
// error naming the missing piece.
func ProveAccess(s Step, in GuardInput) (Proof, error) {
	c, ok := changeOf(s)
	if !ok {
		return Proof{}, nil
	}
	return proveChange(s.ID, c, in)
}

// proveChange is ProveAccess for change c of step id.
func proveChange(id string, c change, in GuardInput) (Proof, error) {
	p := Proof{Narrows: c.narrows()}
	if len(p.Narrows) == 0 {
		return p, nil
	}
	p.Needed = true
	refuse := func(err error) (Proof, error) {
		return p, fmt.Errorf("lockout guard: %s %s, and %w", id, strings.Join(p.Narrows, ", "), err)
	}
	f := in.Facts
	if f == nil {
		return refuse(errors.New("there are no facts to prove a second way in from (a plan from a saved report alone cannot)"))
	}
	if in.Applier != "" && c.disables(in.Applier) {
		return refuse(fmt.Errorf("it would disable %s, the account applying it", in.Applier))
	}
	v, err := projectSSHD(f.SSH, c.sshd)
	if err != nil {
		return refuse(err)
	}
	admins, err := candidates(f, c)
	if err != nil {
		return refuse(err)
	}
	if c.access.ApplierStays {
		if admins, err = applierOnly(admins, in.Applier); err != nil {
			return refuse(err)
		}
	}
	if !c.access.ClosesPublicSSH {
		if err := portsOpen(f, c, v); err != nil {
			return refuse(err)
		}
		way, err := firstLogin(admins, v, addrSource(in.Source), "over SSH on port "+joinInts(v.ports()))
		if err != nil {
			return refuse(err)
		}
		p.Ways = append(p.Ways, way)
		return p, nil
	}
	var missing []string
	if way, err := tailnetWay(f, c, v, admins); err == nil {
		p.Ways = append(p.Ways, way)
		p.ConfirmFrom = append(p.ConfirmFrom, TailnetV4.String(), TailnetV6.String())
	} else {
		missing = append(missing, "no tailnet path: "+err.Error())
	}
	if way, nets, err := allowedSourceWay(c, v, admins, in.Source); err == nil {
		p.Ways = append(p.Ways, way)
		p.ConfirmFrom = append(p.ConfirmFrom, nets...)
	} else {
		missing = append(missing, "no allowed source: "+err.Error())
	}
	if len(p.Ways) == 0 {
		return refuse(fmt.Errorf("public SSH must not close without a proven second way in: %s", strings.Join(missing, "; ")))
	}
	return p, nil
}

// candidates returns the accounts that could be the second way in: not
// root, a login shell, sudo, a usable authorized key, and neither
// disabled nor stripped of its keys by the step. With none, the error
// names what each account lacks.
func candidates(f *facts.Facts, c change) ([]account, error) {
	if f.Users == nil {
		return nil, errors.New("the accounts were not audited")
	}
	if f.SSH.UsersError != "" {
		return nil, fmt.Errorf("the authorized keys could not be read: %s", f.SSH.UsersError)
	}
	var out []account
	var lacks []string
	for _, acc := range f.Users.Accounts {
		if acc.UID == 0 || !acc.LoginShell {
			continue
		}
		a := account{Account: acc, groups: f.Users.GroupsOf(acc), keys: keysOf(f.SSH, acc.Name)}
		switch why := lacking(f.Users, a, c); why {
		case "":
			out = append(out, a)
		default:
			lacks = append(lacks, acc.Name+": "+why)
		}
	}
	if len(out) > 0 {
		return out, nil
	}
	if len(lacks) == 0 {
		return nil, errors.New("no second way in exists: no account but root can log in; create a non-root sudo user with an authorized key first")
	}
	return nil, fmt.Errorf("no second way in exists: it needs a non-root sudo user with an authorized key (%s)", strings.Join(lacks, "; "))
}

// applierOnly keeps only the account applying the step: a step with
// ApplierStays needs that account, proven, to be the way that stays.
func applierOnly(admins []account, applier string) ([]account, error) {
	if applier == "" {
		return nil, errors.New("the account applying it is unknown (no login uid); log in over SSH with a key as the account that stays and apply from that session")
	}
	for _, a := range admins {
		if a.Name == applier {
			return []account{a}, nil
		}
	}
	names := make([]string, len(admins))
	for i, a := range admins {
		names[i] = a.Name
	}
	return nil, fmt.Errorf("%s, the account applying it, is not a proven second way in; log in over SSH with a key as %s and apply from that session", applier, orList(names))
}

// orList joins names with "or".
func orList(names []string) string {
	switch len(names) {
	case 0:
		return "a non-root sudo user"
	case 1:
		return names[0]
	}
	return strings.Join(names[:len(names)-1], ", ") + " or " + names[len(names)-1]
}

// lacking says what keeps a from being a second way in, or "".
func lacking(u *facts.Users, a account, c change) string {
	switch {
	case c.disables(a.Name):
		return "the step disables it"
	case c.removesKeys(a.Name):
		return "the step removes its keys"
	}
	sudo := hasSudo(u, a)
	keys := 0
	for _, kf := range a.keys {
		keys += usableKeys(kf)
	}
	switch {
	case sudo == triNo && keys == 0:
		return "no sudo rule and no authorized key"
	case sudo == triMaybe:
		return "sudoers could not be read, so its sudo rights are unknown (run the audit as root)"
	case sudo == triNo:
		return "no sudo rule"
	case keys == 0:
		return "no usable authorized key (it would log in with a password only)"
	}
	return ""
}

// hasSudo answers from the sudoers principals: the account itself, ALL,
// or %GROUP for one of its groups. Unreadable sudoers is "cannot tell".
func hasSudo(u *facts.Users, a account) tri {
	readable := false
	for _, s := range u.Sudoers {
		if !s.Readable {
			continue
		}
		readable = true
		for _, p := range s.Principals {
			if p == a.Name || p == "ALL" {
				return triYes
			}
			if g, ok := strings.CutPrefix(p, "%"); ok && slices.Contains(a.groups, g) {
				return triYes
			}
		}
	}
	if !readable {
		return triMaybe
	}
	return triNo
}

func keysOf(s *facts.SSH, name string) []facts.SSHKeyFile {
	for _, u := range s.Users {
		if u.Name == name {
			return u.KeyFiles
		}
	}
	return nil
}

// firstLogin returns the first account that logs in from src, as a way
// in, or the reasons none does.
func firstLogin(admins []account, v *sshdView, src source, how string) (string, error) {
	var why []string
	for _, a := range admins {
		w := v.loginFor(a, src)
		if w == "" {
			return fmt.Sprintf("%s (sudo, authorized key) logs in with a key from %s %s", a.Name, src.label, how), nil
		}
		why = append(why, w)
	}
	return "", fmt.Errorf("no sudo user could log in with a key after the step: %s", strings.Join(why, "; "))
}

// portsOpen checks, for a step that sets the SSH port, that the firewall
// lets every new port in from anywhere.
func portsOpen(f *facts.Facts, c change, v *sshdView) error {
	if _, sets := c.sshd["port"]; !sets {
		return nil
	}
	if f.Firewall == nil {
		return errors.New("the firewall was not audited, so whether the new SSH port is let in is unknown")
	}
	u := f.Firewall.UFW
	if u == nil || !u.Installed || u.Status != "active" {
		if nftDrops(f.Firewall.NFT) {
			return errors.New("a firewall other than UFW drops incoming traffic, and the guard cannot tell whether it lets the new SSH port in")
		}
		return nil
	}
	if !u.RulesKnown {
		return errors.New("the UFW rules could not be read although UFW is active")
	}
	for _, port := range v.ports() {
		if !ufwAllows(u, port, func(r facts.UFWRule) bool { return r.FromAnywhere() }) {
			return fmt.Errorf("no UFW rule lets tcp/%d in from anywhere while UFW is active; allow the new port first", port)
		}
	}
	return nil
}

func nftDrops(n *facts.NFTables) bool {
	if n == nil {
		return false
	}
	for _, ch := range n.Chains {
		if ch.Hook == "input" && (ch.Policy == "drop" || ch.EndsInDrop) {
			return true
		}
	}
	return false
}

func ufwAllows(u *facts.UFW, port int, from func(facts.UFWRule) bool) bool {
	for _, r := range u.Rules {
		if r.Direction == "in" && r.Allows() && r.MatchesPort("tcp", port) && from(r) {
			return true
		}
	}
	return false
}

// tailnetWay proves the tailnet path: Tailscale running with key expiry
// off, sshd listening on the tailnet, the firewall letting the tailnet
// reach sshd, and an account that logs in from the tailnet.
func tailnetWay(f *facts.Facts, c change, v *sshdView, admins []account) (string, error) {
	t := f.Tailscale
	switch {
	case t == nil:
		return "", errors.New("the Tailscale facts are missing (not audited)")
	case !t.Installed:
		return "", errors.New("no Tailscale is installed")
	case !t.StatusRead:
		return "", errors.New("the Tailscale status could not be read (run the audit as root)")
	case t.BackendState != "Running":
		return "", fmt.Errorf("the Tailscale backend is %s, not Running", orNoState(t.BackendState))
	case t.KeyExpiry != nil:
		return "", fmt.Errorf("this node's key expires at %s; disable key expiry for it first, or the tailnet path ends then", t.KeyExpiry.UTC().Format("2006-01-02T15:04:05Z"))
	}
	if err := listensOnTailnet(v); err != nil {
		return "", err
	}
	if !c.access.TailnetSSH {
		if err := firewallLetsTailnet(f, v); err != nil {
			return "", err
		}
	}
	return firstLogin(admins, v, netSource(TailnetV4, "the tailnet"), "over the tailnet")
}

func orNoState(s string) string {
	if s == "" {
		return "in no state"
	}
	return s
}

// listensOnTailnet checks that some listen address of sshd after the step
// is a wildcard or a tailnet address.
func listensOnTailnet(v *sshdView) error {
	addrs := v.global["listenaddress"]
	for _, la := range addrs {
		host := la
		if h, _, ok := splitHostPort(la); ok {
			host = h
		}
		switch facts.ClassifyAddress(host) {
		case facts.BindWildcard, facts.BindTailnet:
			return nil
		}
	}
	return fmt.Errorf("sshd would listen only on %s, not on the tailnet", strings.Join(addrs, ", "))
}

// splitHostPort splits "0.0.0.0:22" and "[::]:22".
func splitHostPort(s string) (host, port string, ok bool) {
	i := strings.LastIndex(s, ":")
	if i < 0 {
		return "", "", false
	}
	host, port = s[:i], s[i+1:]
	if strings.HasPrefix(host, "[") && strings.HasSuffix(host, "]") {
		host = host[1 : len(host)-1]
	}
	return host, port, true
}

// firewallLetsTailnet checks the audited firewall for a rule that lets
// the tailnet reach every sshd port: an allow rule on tailscale0 or from
// a tailnet network. No active firewall lets everything in.
func firewallLetsTailnet(f *facts.Facts, v *sshdView) error {
	if f.Firewall == nil {
		return errors.New("the firewall was not audited")
	}
	u := f.Firewall.UFW
	if u == nil || !u.Installed || u.Status != "active" {
		if nftDrops(f.Firewall.NFT) {
			return errors.New("a firewall other than UFW drops incoming traffic, and the guard cannot tell whether it lets the tailnet reach sshd")
		}
		return nil
	}
	if !u.RulesKnown {
		return errors.New("the UFW rules could not be read although UFW is active")
	}
	for _, port := range v.ports() {
		if !ufwAllows(u, port, fromTailnet) {
			return fmt.Errorf("no firewall rule lets the tailnet reach sshd on tcp/%d (and the step adds none): allow it on %s first", port, tailnetIface)
		}
	}
	return nil
}

func fromTailnet(r facts.UFWRule) bool {
	if r.Interface == tailnetIface {
		return r.From == ""
	}
	if r.Interface != "" || r.From == "" {
		return false
	}
	n, err := netip.ParsePrefix(r.From)
	if err != nil {
		a, aerr := netip.ParseAddr(r.From)
		if aerr != nil {
			return false
		}
		n = netip.PrefixFrom(a, a.BitLen())
	}
	return TailnetV4.Overlaps(n) || TailnetV6.Overlaps(n)
}

// allowedSourceWay proves the allowed source path: the step still lets
// some networks reach sshd, the session that plans or applies comes from
// one of them, and an account logs in from there.
func allowedSourceWay(c change, v *sshdView, admins []account, from netip.Addr) (string, []string, error) {
	if len(c.access.AllowFrom) == 0 {
		return "", nil, errors.New("the step allows no other source")
	}
	if !from.IsValid() {
		return "", nil, fmt.Errorf("the step still allows %s, but this session's source is unknown, so it cannot be shown to come from there (run it from an SSH session)", strings.Join(c.access.AllowFrom, ", "))
	}
	from = from.Unmap()
	var nets []string
	inside := false
	for _, s := range c.access.AllowFrom {
		n, err := netip.ParsePrefix(s)
		if err != nil {
			return "", nil, fmt.Errorf("the allowed source %q is not a network", s)
		}
		nets = append(nets, n.Masked().String())
		inside = inside || n.Contains(from)
	}
	if !inside {
		return "", nil, fmt.Errorf("this session comes from %s, outside the allowed sources %s, so it would be cut off", from, strings.Join(nets, ", "))
	}
	way, err := firstLogin(admins, v, addrSource(from), "(an allowed source)")
	return way, nets, err
}

func joinInts(ns []int) string {
	s := make([]string, len(ns))
	for i, n := range ns {
		s[i] = strconv.Itoa(n)
	}
	return strings.Join(s, ", ")
}
