package facts

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"regexp"
	"sort"
	"strconv"
	"strings"
)

// Firewall is the host firewall state: UFW, nftables, iptables, firewalld,
// the DOCKER-USER chain and ufw-docker (NET group). Docker's own facts
// (containers, daemon.json) belong to the docker collector; this domain only
// records what the firewall rules show about Docker.
type Firewall struct {
	UFW       *UFW       `json:"ufw,omitempty"`
	NFT       *NFTables  `json:"nft,omitempty"`
	Iptables  *Iptables  `json:"iptables,omitempty"`
	Firewalld *Firewalld `json:"firewalld,omitempty"`
	UFWDocker *UFWDocker `json:"ufw_docker,omitempty"`
	// DockerUser is the DOCKER-USER chain: "absent", "default" (only a
	// RETURN or empty), "filtered" (any other rule), or "" when it could not
	// be read (needs root).
	DockerUser string `json:"docker_user,omitempty"`
	// DockerBackend is the firewall backend Docker programs, as seen in the
	// rules: "iptables" (DOCKER chains), "nftables" (docker-bridges
	// tables), "none" (no Docker rules at all), or "" when unknown.
	DockerBackend string `json:"docker_backend,omitempty"`
}

// UFW is the Uncomplicated Firewall.
type UFW struct {
	Installed bool `json:"installed"`
	// Source is "status" (ufw status verbose, root) or "files" (only the
	// configuration files could be read; they say what loads at boot, not
	// what is loaded now).
	Source string `json:"source,omitempty"`
	// Status is "active", "inactive" or "" when unknown.
	Status string `json:"status,omitempty"`
	// DefaultIncoming and DefaultRouted are "deny", "reject", "allow" or
	// "" when unknown.
	DefaultIncoming string `json:"default_incoming,omitempty"`
	DefaultRouted   string `json:"default_routed,omitempty"`
	// IPv6 is the IPV6 setting of /etc/default/ufw: "yes", "no" or "".
	IPv6 string `json:"ipv6,omitempty"`
	// RulesKnown is false when the rules could not be read; Rules is then
	// empty and proves nothing.
	RulesKnown bool      `json:"rules_known"`
	Rules      []UFWRule `json:"rules,omitempty"`
}

// UFWRule is one UFW rule.
type UFWRule struct {
	// Action is "allow", "deny", "reject" or "limit".
	Action string `json:"action"`
	// Direction is "in", "out" or "fwd" (a route rule).
	Direction string `json:"direction"`
	// Port is the destination port spec: "22", "80,443", "6000:6007", or
	// "" for any port.
	Port string `json:"port,omitempty"`
	// Proto is "tcp", "udp" or "any".
	Proto string `json:"proto"`
	// To is the destination address, "" for anywhere.
	To string `json:"to,omitempty"`
	// From is the source address or network, "" for anywhere.
	From string `json:"from,omitempty"`
	// Interface is the inbound interface ("on tailscale0"), if any.
	Interface string `json:"interface,omitempty"`
	V6        bool   `json:"v6,omitempty"`
	// App is the application profile name, when the rule uses one.
	App string `json:"app,omitempty"`
}

// FromAnywhere reports whether the rule accepts any source on any
// interface.
func (r UFWRule) FromAnywhere() bool { return r.From == "" && r.Interface == "" }

// Allows reports whether the rule lets traffic in (allow or limit).
func (r UFWRule) Allows() bool { return r.Action == "allow" || r.Action == "limit" }

// MatchesPort reports whether the rule covers proto/port. An unresolved
// application profile (Port "" and App set) does not match anything.
func (r UFWRule) MatchesPort(proto string, port int) bool {
	if r.Proto != "any" && r.Proto != "" && r.Proto != proto {
		return false
	}
	if r.Port == "" {
		return r.App == ""
	}
	for _, part := range strings.Split(r.Port, ",") {
		lo, hi, found := strings.Cut(part, ":")
		a, err := strconv.Atoi(lo)
		if err != nil {
			continue
		}
		b := a
		if found {
			if b, err = strconv.Atoi(hi); err != nil {
				continue
			}
		}
		if port >= a && port <= b {
			return true
		}
	}
	return false
}

// NFTables is the nftables ruleset summary (nft -j list ruleset, root).
type NFTables struct {
	Installed bool `json:"installed"`
	// Listed is true when the ruleset was read.
	Listed bool       `json:"listed"`
	Tables []NFTTable `json:"tables,omitempty"`
	// Chains are the base chains (those with a hook).
	Chains []NFTChain `json:"chains,omitempty"`
}

// NFTTable is one nftables table.
type NFTTable struct {
	Family string `json:"family"`
	Name   string `json:"name"`
}

// NFTChain is one nftables base chain.
type NFTChain struct {
	Family string `json:"family"`
	Table  string `json:"table"`
	Name   string `json:"name"`
	Hook   string `json:"hook"`
	Policy string `json:"policy,omitempty"`
	Rules  int    `json:"rules"`
	// EndsInDrop is true when the last rule is an unconditional drop or
	// reject, which works like a drop policy.
	EndsInDrop bool `json:"ends_in_drop,omitempty"`
}

// Iptables is the iptables view (filter table).
type Iptables struct {
	Installed bool `json:"installed"`
	// Backend is "nf_tables", "legacy" or "" (from iptables -V).
	Backend string `json:"backend,omitempty"`
	// Listed is true when iptables -S ran (root).
	Listed bool `json:"listed"`
	// Policies maps the built in chains to their policy ("ACCEPT", "DROP").
	Policies map[string]string `json:"policies,omitempty"`
	// Chains is every chain name in the filter table, sorted.
	Chains []string `json:"chains,omitempty"`
	// InputRules counts rules appended to INPUT.
	InputRules int `json:"input_rules"`
	// DockerUserRules are the DOCKER-USER rules as printed by -S.
	DockerUserRules []string `json:"docker_user_rules,omitempty"`
}

// HasChain reports whether the filter table has the named chain.
func (t *Iptables) HasChain(name string) bool {
	if t == nil {
		return false
	}
	i := sort.SearchStrings(t.Chains, name)
	return i < len(t.Chains) && t.Chains[i] == name
}

// Firewalld is firewalld's state.
type Firewalld struct {
	Installed bool `json:"installed"`
	// State is "running", "not running" or "" when unknown.
	State string `json:"state,omitempty"`
}

// UFWDocker is the ufw-docker integration.
type UFWDocker struct {
	// InFiles is "present" or "absent" for the "BEGIN UFW AND DOCKER"
	// block in /etc/ufw/after.rules, "" when the file could not be read.
	InFiles string `json:"in_files,omitempty"`
	// Loaded is "yes" when DOCKER-USER jumps to ufw-user-forward, "no"
	// when it does not, "" when iptables could not be listed.
	Loaded string `json:"loaded,omitempty"`
}

// Paths the firewall collector reads.
const (
	ufwConfPath      = "/etc/ufw/ufw.conf"
	ufwDefaultPath   = "/etc/default/ufw"
	ufwUserRules     = "/etc/ufw/user.rules"
	ufwUser6Rules    = "/etc/ufw/user6.rules"
	ufwAfterRules    = "/etc/ufw/after.rules"
	ufwDockerMarker  = "# BEGIN UFW AND DOCKER"
	dockerUserChain  = "DOCKER-USER"
	dockerNFTTable   = "docker-bridges"
	ufwForwardTarget = "ufw-user-forward"
)

type firewallCollector struct{}

func init() { Register(firewallCollector{}) }

func (firewallCollector) Name() string    { return "firewall" }
func (firewallCollector) NeedsRoot() bool { return false }

// Collect runs (all read only):
//
//	ufw status verbose     (root)
//	nft -j list ruleset    (root)
//	iptables -V
//	iptables -S            (root, filter table)
//	firewall-cmd --state
//
// and reads /etc/ufw/ufw.conf, /etc/default/ufw, /etc/ufw/user.rules,
// /etc/ufw/user6.rules and /etc/ufw/after.rules where readable.
func (firewallCollector) Collect(ctx context.Context, sys System, out *Facts) error {
	root := sys.Identity().Root
	fw := &Firewall{}
	var errs []error
	add := func(err error) {
		if err != nil {
			errs = append(errs, err)
		}
	}

	ufw, err := collectUFW(ctx, sys, root)
	add(err)
	fw.UFW = ufw

	nft, err := collectNFT(ctx, sys, root)
	add(err)
	fw.NFT = nft

	ipt, err := collectIptables(ctx, sys, root)
	add(err)
	fw.Iptables = ipt

	fw.Firewalld = collectFirewalld(ctx, sys)

	fw.DockerUser = dockerUserState(ipt)
	fw.DockerBackend = dockerBackend(nft, ipt)
	fw.UFWDocker = collectUFWDocker(sys, ufw, ipt)

	out.Firewall = fw
	return errors.Join(errs...)
}

func collectUFW(ctx context.Context, sys System, root bool) (*UFW, error) {
	u := &UFW{}
	_, lookErr := sys.LookPath("ufw")
	conf, confErr := sys.ReadFile(ufwConfPath)
	u.Installed = lookErr == nil || confErr == nil
	if !u.Installed {
		return u, nil
	}
	if def, err := sys.ReadFile(ufwDefaultPath); err == nil {
		kv := parseShellVars(def)
		u.IPv6 = strings.ToLower(kv["IPV6"])
		u.DefaultIncoming = policyWord(kv["DEFAULT_INPUT_POLICY"])
		u.DefaultRouted = policyWord(kv["DEFAULT_FORWARD_POLICY"])
	}

	var statusErr error
	if root && lookErr == nil {
		res, err := sys.Run(ctx, "ufw", "status", "verbose")
		switch {
		case err != nil:
			statusErr = err
		case res.ExitCode != 0:
			statusErr = fmt.Errorf("ufw status exited %d: %s", res.ExitCode, firstLine(res.Stderr))
		default:
			st := ParseUFWStatus(res.Stdout)
			u.Source, u.Status = "status", st.Status
			if st.DefaultIncoming != "" {
				u.DefaultIncoming = st.DefaultIncoming
			}
			if st.DefaultRouted != "" {
				u.DefaultRouted = st.DefaultRouted
			}
			// An inactive UFW prints no rules; that says nothing about
			// what is configured, so leave RulesKnown false.
			u.Rules, u.RulesKnown = st.Rules, st.Status == "active"
			return u, nil
		}
	}

	// Files fallback: what loads at boot, not proof of what is loaded.
	u.Source = "files"
	if confErr == nil {
		switch strings.ToLower(parseShellVars(conf)["ENABLED"]) {
		case "yes":
			u.Status = "active"
		case "no":
			u.Status = "inactive"
		}
	}
	var rules []UFWRule
	readAny := false
	for _, p := range []string{ufwUserRules, ufwUser6Rules} {
		b, err := sys.ReadFile(p)
		if err != nil {
			continue
		}
		readAny = true
		rules = append(rules, ParseUFWUserRules(b, p == ufwUser6Rules)...)
	}
	u.Rules, u.RulesKnown = rules, readAny
	return u, statusErr
}

func policyWord(s string) string {
	switch strings.ToUpper(strings.TrimSpace(s)) {
	case "DROP", "DENY":
		return "deny"
	case "REJECT":
		return "reject"
	case "ACCEPT", "ALLOW":
		return "allow"
	}
	return ""
}

// parseShellVars reads KEY=value lines, stripping quotes and comments.
func parseShellVars(b []byte) map[string]string {
	out := map[string]string{}
	sc := bufio.NewScanner(bytes.NewReader(b))
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		k, v, ok := strings.Cut(line, "=")
		if !ok {
			continue
		}
		v = strings.TrimSpace(v)
		if i := strings.Index(v, " #"); i >= 0 {
			v = strings.TrimSpace(v[:i])
		}
		out[strings.TrimSpace(k)] = strings.Trim(v, `"'`)
	}
	return out
}

// UFWStatus is what `ufw status verbose` prints.
type UFWStatus struct {
	Status          string
	DefaultIncoming string
	DefaultRouted   string
	Rules           []UFWRule
}

var (
	ufwDefaultRE = regexp.MustCompile(`(\w+) \((incoming|outgoing|routed)\)`)
	// ufw pads the To column to 26 characters plus one space, so a long
	// destination is followed by a single space: find the action instead
	// of splitting on runs of spaces.
	ufwActionRE = regexp.MustCompile(`\s(ALLOW|DENY|REJECT|LIMIT)(?: (IN|OUT|FWD))?\s+`)
)

// ufwApps resolves the application profiles shipped with common packages.
// Unknown names stay unresolved and match no port.
var ufwApps = map[string]struct{ port, proto string }{
	"OpenSSH":       {"22", "tcp"},
	"Nginx Full":    {"80,443", "tcp"},
	"Nginx HTTP":    {"80", "tcp"},
	"Nginx HTTPS":   {"443", "tcp"},
	"Apache":        {"80", "tcp"},
	"Apache Full":   {"80,443", "tcp"},
	"Apache Secure": {"443", "tcp"},
	"WWW":           {"80", "tcp"},
	"WWW Full":      {"80,443", "tcp"},
	"WWW Secure":    {"443", "tcp"},
}

// ParseUFWStatus parses `ufw status verbose` (C locale).
func ParseUFWStatus(b []byte) UFWStatus {
	var st UFWStatus
	inRules := false
	sc := bufio.NewScanner(bytes.NewReader(b))
	for sc.Scan() {
		line := strings.TrimRight(sc.Text(), " \t")
		switch {
		case strings.HasPrefix(line, "Status:"):
			st.Status = strings.TrimSpace(strings.TrimPrefix(line, "Status:"))
		case strings.HasPrefix(line, "Default:"):
			for _, m := range ufwDefaultRE.FindAllStringSubmatch(line, -1) {
				switch m[2] {
				case "incoming":
					st.DefaultIncoming = policyWord(m[1])
				case "routed":
					st.DefaultRouted = policyWord(m[1])
				}
			}
		case strings.HasPrefix(line, "--"):
			inRules = true
		case inRules && strings.TrimSpace(line) != "":
			if r, ok := parseUFWStatusRule(line); ok {
				st.Rules = append(st.Rules, r)
			}
		}
	}
	return st
}

func parseUFWStatusRule(line string) (UFWRule, bool) {
	if i := strings.Index(line, " # "); i >= 0 {
		line = line[:i] // comment
	}
	loc := ufwActionRE.FindStringSubmatchIndex(line)
	if loc == nil {
		return UFWRule{}, false
	}
	m := ufwActionRE.FindStringSubmatch(line)
	to, from := strings.TrimSpace(line[:loc[0]]), strings.TrimSpace(line[loc[1]:])
	if to == "" || from == "" {
		return UFWRule{}, false
	}
	r := UFWRule{Action: strings.ToLower(m[1]), Direction: "in", Proto: "any"}
	if m[2] != "" {
		r.Direction = strings.ToLower(m[2])
	}
	if strings.Contains(to, "(v6)") || strings.Contains(from, "(v6)") {
		r.V6 = true
	}
	to = strings.TrimSpace(strings.ReplaceAll(to, "(v6)", ""))
	from = strings.TrimSpace(strings.ReplaceAll(from, "(v6)", ""))

	// Interfaces: "22/tcp on tailscale0" for in rules; route rules print
	// the inbound interface on the From side ("Anywhere on tailscale0").
	if t, iface, ok := strings.Cut(to, " on "); ok {
		to, r.Interface = strings.TrimSpace(t), strings.TrimSpace(iface)
	}
	if f, iface, ok := strings.Cut(from, " on "); ok {
		from = strings.TrimSpace(f)
		if r.Interface == "" {
			r.Interface = strings.TrimSpace(iface)
		}
	}
	if from != "Anywhere" {
		r.From = from
	}

	// "To" is a port spec, an address, "address port/proto", "Anywhere",
	// or an application profile name.
	fields := strings.Fields(to)
	switch {
	case to == "Anywhere":
	case len(fields) == 2 && looksLikePortSpec(fields[1]):
		r.To = fields[0]
		r.Port, r.Proto = splitPortProto(fields[1])
	case looksLikePortSpec(to):
		r.Port, r.Proto = splitPortProto(to)
	case looksLikeAddress(to):
		r.To = to
	default:
		r.App = to
		if a, ok := ufwApps[to]; ok {
			r.Port, r.Proto = a.port, a.proto
		}
	}
	return r, true
}

var portSpecRE = regexp.MustCompile(`^[0-9]+([:,][0-9]+)*(/(tcp|udp))?$`)

func looksLikePortSpec(s string) bool { return portSpecRE.MatchString(s) }

func looksLikeAddress(s string) bool {
	return strings.ContainsAny(s, ".:") && !strings.ContainsRune(s, ' ')
}

func splitPortProto(s string) (port, proto string) {
	port, proto, found := strings.Cut(s, "/")
	if !found {
		proto = "any"
	}
	return port, proto
}

// ParseUFWUserRules parses the "### tuple ###" lines of /etc/ufw/user.rules
// or user6.rules:
//
//	### tuple ### allow tcp 22 0.0.0.0/0 any 0.0.0.0/0 in
//	### tuple ### allow tcp 22 0.0.0.0/0 any 0.0.0.0/0 OpenSSH - in_tailscale0
//	### tuple ### route:allow tcp 80 0.0.0.0/0 any 0.0.0.0/0 in_tailscale0
func ParseUFWUserRules(b []byte, v6 bool) []UFWRule {
	var out []UFWRule
	sc := bufio.NewScanner(bytes.NewReader(b))
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		rest, ok := strings.CutPrefix(line, "### tuple ###")
		if !ok {
			continue
		}
		var f []string
		for _, w := range strings.Fields(rest) {
			if !strings.HasPrefix(w, "comment=") {
				f = append(f, w)
			}
		}
		if len(f) != 7 && len(f) != 9 {
			continue
		}
		action := strings.TrimSuffix(strings.TrimSuffix(f[0], "_log-all"), "_log")
		r := UFWRule{Proto: f[1], V6: v6, Direction: "in"}
		if a, ok := strings.CutPrefix(action, "route:"); ok {
			action, r.Direction = a, "fwd"
		}
		r.Action = action
		if f[2] != "any" {
			r.Port = f[2]
		}
		if !isAnyNet(f[3]) {
			r.To = f[3]
		}
		if !isAnyNet(f[5]) {
			r.From = f[5]
		}
		dir := f[len(f)-1]
		if len(f) == 9 && f[6] != "-" {
			r.App = strings.ReplaceAll(f[6], "%20", " ")
		}
		// "in", "out", "in_eth0", route rules "in_eth0!out_eth1".
		first, _, _ := strings.Cut(dir, "!")
		d, iface, _ := strings.Cut(first, "_")
		if r.Direction != "fwd" {
			r.Direction = d
		}
		if d == "in" {
			r.Interface = iface
		}
		out = append(out, r)
	}
	return out
}

func isAnyNet(s string) bool { return s == "0.0.0.0/0" || s == "::/0" || s == "any" }

func collectNFT(ctx context.Context, sys System, root bool) (*NFTables, error) {
	n := &NFTables{}
	if _, err := sys.LookPath("nft"); err != nil {
		return n, nil
	}
	n.Installed = true
	if !root {
		return n, nil
	}
	res, err := sys.Run(ctx, "nft", "-j", "list", "ruleset")
	if err != nil {
		return n, err
	}
	if res.ExitCode != 0 {
		return n, fmt.Errorf("nft list ruleset exited %d: %s", res.ExitCode, firstLine(res.Stderr))
	}
	parsed, err := ParseNFTJSON(res.Stdout)
	if err != nil {
		return n, err
	}
	parsed.Installed = true
	return parsed, nil
}

// ParseNFTJSON summarises `nft -j list ruleset`.
func ParseNFTJSON(b []byte) (*NFTables, error) {
	n := &NFTables{Listed: true}
	if len(bytes.TrimSpace(b)) == 0 {
		return n, nil // empty ruleset prints nothing on older nft
	}
	var doc struct {
		Nftables []map[string]json.RawMessage `json:"nftables"`
	}
	if err := json.Unmarshal(b, &doc); err != nil {
		return nil, fmt.Errorf("nft -j: %w", err)
	}
	type key struct{ family, table, chain string }
	idx := map[key]int{}
	for _, obj := range doc.Nftables {
		switch {
		case obj["table"] != nil:
			var t NFTTable
			if json.Unmarshal(obj["table"], &t) == nil {
				n.Tables = append(n.Tables, t)
			}
		case obj["chain"] != nil:
			var c struct {
				Family, Table, Name, Hook, Policy string
			}
			if json.Unmarshal(obj["chain"], &c) == nil && c.Hook != "" {
				idx[key{c.Family, c.Table, c.Name}] = len(n.Chains)
				n.Chains = append(n.Chains, NFTChain{Family: c.Family, Table: c.Table, Name: c.Name, Hook: c.Hook, Policy: c.Policy})
			}
		case obj["rule"] != nil:
			var r struct {
				Family, Table, Chain string
				Expr                 []map[string]json.RawMessage
			}
			if json.Unmarshal(obj["rule"], &r) != nil {
				continue
			}
			i, ok := idx[key{r.Family, r.Table, r.Chain}]
			if !ok {
				continue
			}
			n.Chains[i].Rules++
			n.Chains[i].EndsInDrop = unconditionalDrop(r.Expr)
		}
	}
	return n, nil
}

// unconditionalDrop reports whether a rule is only a drop or reject
// verdict, optionally with a counter or log statement.
func unconditionalDrop(expr []map[string]json.RawMessage) bool {
	verdict := false
	for _, e := range expr {
		for k := range e {
			switch k {
			case "drop", "reject":
				verdict = true
			case "counter", "log", "limit":
			default:
				return false
			}
		}
	}
	return verdict
}

// InputDrops reports whether some base input chain drops what it does not
// accept (drop policy or a final unconditional drop).
func (n *NFTables) InputDrops() bool {
	if n == nil {
		return false
	}
	for _, c := range n.Chains {
		if c.Hook == "input" && (c.Policy == "drop" || c.EndsInDrop) {
			return true
		}
	}
	return false
}

// HasTable reports whether a table with the given name exists in any
// family.
func (n *NFTables) HasTable(name string) bool {
	if n == nil {
		return false
	}
	for _, t := range n.Tables {
		if t.Name == name {
			return true
		}
	}
	return false
}

var iptablesVersionRE = regexp.MustCompile(`\((nf_tables|legacy)\)`)

func collectIptables(ctx context.Context, sys System, root bool) (*Iptables, error) {
	t := &Iptables{}
	if _, err := sys.LookPath("iptables"); err != nil {
		return t, nil
	}
	t.Installed = true
	if res, err := sys.Run(ctx, "iptables", "-V"); err == nil {
		if m := iptablesVersionRE.FindSubmatch(res.Stdout); m != nil {
			t.Backend = string(m[1])
		}
	}
	if !root {
		return t, nil
	}
	res, err := sys.Run(ctx, "iptables", "-S")
	if err != nil {
		return t, err
	}
	if res.ExitCode != 0 {
		return t, fmt.Errorf("iptables -S exited %d: %s", res.ExitCode, firstLine(res.Stderr))
	}
	parsed := ParseIptablesS(res.Stdout)
	parsed.Installed, parsed.Backend = true, t.Backend
	return parsed, nil
}

// ParseIptablesS parses `iptables -S` for the filter table.
func ParseIptablesS(b []byte) *Iptables {
	t := &Iptables{Listed: true, Policies: map[string]string{}}
	chains := map[string]bool{}
	sc := bufio.NewScanner(bytes.NewReader(b))
	sc.Buffer(make([]byte, 64<<10), 1<<20)
	for sc.Scan() {
		f := strings.Fields(sc.Text())
		if len(f) < 2 {
			continue
		}
		switch f[0] {
		case "-P":
			chains[f[1]] = true
			if len(f) >= 3 {
				t.Policies[f[1]] = f[2]
			}
		case "-N":
			chains[f[1]] = true
		case "-A":
			chains[f[1]] = true
			switch f[1] {
			case "INPUT":
				t.InputRules++
			case dockerUserChain:
				t.DockerUserRules = append(t.DockerUserRules, strings.Join(f, " "))
			}
		}
	}
	for c := range chains {
		t.Chains = append(t.Chains, c)
	}
	sort.Strings(t.Chains)
	return t
}

func dockerUserState(t *Iptables) string {
	if t == nil || !t.Listed {
		return ""
	}
	if !t.HasChain(dockerUserChain) {
		return "absent"
	}
	for _, r := range t.DockerUserRules {
		if r != "-A DOCKER-USER -j RETURN" {
			return "filtered"
		}
	}
	return "default"
}

func dockerBackend(n *NFTables, t *Iptables) string {
	nftKnown := n != nil && n.Listed
	iptKnown := t != nil && t.Listed
	switch {
	case nftKnown && n.HasTable(dockerNFTTable):
		return "nftables"
	case iptKnown && (t.HasChain("DOCKER") || t.HasChain(dockerUserChain)):
		return "iptables"
	case iptKnown && (nftKnown || t.Backend == "legacy"):
		// Both views (or the only one a legacy host has) show no Docker
		// rules at all.
		return "none"
	}
	return ""
}

func collectUFWDocker(sys System, u *UFW, t *Iptables) *UFWDocker {
	if u == nil || !u.Installed {
		return nil
	}
	d := &UFWDocker{}
	if b, err := sys.ReadFile(ufwAfterRules); err == nil {
		d.InFiles = "absent"
		if bytes.Contains(b, []byte(ufwDockerMarker)) {
			d.InFiles = "present"
		}
	}
	if t != nil && t.Listed {
		d.Loaded = "no"
		for _, r := range t.DockerUserRules {
			if strings.HasSuffix(r, "-j "+ufwForwardTarget) {
				d.Loaded = "yes"
			}
		}
	}
	return d
}

func collectFirewalld(ctx context.Context, sys System) *Firewalld {
	if _, err := sys.LookPath("firewall-cmd"); err != nil {
		return nil
	}
	f := &Firewalld{Installed: true}
	res, err := sys.Run(ctx, "firewall-cmd", "--state")
	if err != nil {
		return f
	}
	switch s := strings.TrimSpace(string(res.Stdout) + string(res.Stderr)); {
	case strings.HasPrefix(s, "running"):
		f.State = "running"
	case strings.HasPrefix(s, "not running"):
		f.State = "not running"
	}
	return f
}
