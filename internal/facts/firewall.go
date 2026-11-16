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
	// Source is "live" (root: the rules files, with the listed ruleset
	// proving whether UFW is loaded now), "files" (only the configuration
	// files could be read; they say what loads at boot, not what is loaded
	// now) or "status" (facts files from builds that ran `ufw status
	// verbose`; it means the same as "live").
	Source string `json:"source,omitempty"`
	// Status is "active", "inactive" or "" when unknown. With Source
	// "live" it is the loaded state, whatever ufw.conf says.
	Status string `json:"status,omitempty"`
	// Enabled is ENABLED from /etc/ufw/ufw.conf ("yes", "no" or ""): what
	// UFW does at boot.
	Enabled string `json:"enabled,omitempty"`
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
	// Files is the text of the UFW files a firewall plan step edits
	// (UFWFilePaths), keyed by path, for those that were readable and at
	// most MaxUFWFileBytes long. They hold settings and rules, no
	// secrets; a plan needs them to write an exact edit and to restore
	// it.
	Files map[string]string `json:"files,omitempty"`
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

// Live reports whether Status is the loaded state of the host (root read
// the live ruleset) rather than what the files say about boot.
func (u *UFW) Live() bool { return u != nil && (u.Source == "live" || u.Source == "status") }

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
	// UFWChains is true when the ruleset holds UFW's ufw-user-input chain
	// (iptables-nft hosts), which exists only while UFW is loaded.
	UFWChains bool `json:"ufw_chains,omitempty"`
	// DockerUser is true when the ip family holds a DOCKER-USER chain
	// (iptables-nft hosts), and DockerUserRules are its rules in nft's
	// own syntax ("ip saddr 10.0.0.0/8 counter return"), rendered from the
	// JSON listing. They matter when iptables itself could not be listed.
	DockerUser      bool     `json:"docker_user,omitempty"`
	DockerUserRules []string `json:"docker_user_rules,omitempty"`
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
	// ufwUserInputChain exists only while UFW is loaded (ufw enable
	// creates it, ufw disable removes it).
	ufwUserInputChain = "ufw-user-input"
)

type firewallCollector struct{}

func init() { Register(firewallCollector{}) }

func (firewallCollector) Name() string    { return "firewall" }
func (firewallCollector) NeedsRoot() bool { return false }

// Collect runs (all read only, none of them writes a file; see the command
// table in docs/safety.md):
//
//	nft -j list ruleset    (root)
//	iptables -V
//	iptables -S            (root, filter table)
//	firewall-cmd --state
//
// and reads /etc/ufw/ufw.conf, /etc/default/ufw, /etc/ufw/user.rules,
// /etc/ufw/user6.rules and /etc/ufw/after.rules where readable.
//
// It never runs `ufw status`: ufw opens /run/ufw.lock for writing even to
// print the status, so it fails under the no writes sandbox. The status
// command itself prints the rules of user.rules and checks that the ufw
// chains are loaded; the collector does the same from the files and the
// listed ruleset.
func (firewallCollector) Collect(ctx context.Context, sys System, out *Facts) error {
	root := sys.Identity().Root
	fw := &Firewall{}
	var errs []error
	add := func(err error) {
		if err != nil {
			errs = append(errs, err)
		}
	}

	nft, err := collectNFT(ctx, sys, root)
	add(err)
	fw.NFT = nft

	ipt, err := collectIptables(ctx, sys, root)
	add(err)
	fw.Iptables = ipt

	ufw := collectUFW(sys, ipt, nft)
	fw.UFW = ufw

	fw.Firewalld = collectFirewalld(ctx, sys)

	fw.DockerUser = dockerUserState(ipt, nft)
	fw.DockerBackend = dockerBackend(nft, ipt)
	fw.UFWDocker = collectUFWDocker(sys, ufw, ipt, nft)

	out.Firewall = fw
	return errors.Join(errs...)
}

func collectUFW(sys System, ipt *Iptables, nft *NFTables) *UFW {
	u := &UFW{}
	_, lookErr := sys.LookPath("ufw")
	conf, confErr := sys.ReadFile(ufwConfPath)
	u.Installed = lookErr == nil || confErr == nil
	if !u.Installed {
		return u
	}
	if def, err := sys.ReadFile(ufwDefaultPath); err == nil {
		kv := parseShellVars(def)
		u.IPv6 = strings.ToLower(kv["IPV6"])
		u.DefaultIncoming = policyWord(kv["DEFAULT_INPUT_POLICY"])
		u.DefaultRouted = policyWord(kv["DEFAULT_FORWARD_POLICY"])
	}
	if confErr == nil {
		switch e := strings.ToLower(parseShellVars(conf)["ENABLED"]); e {
		case "yes", "no":
			u.Enabled = e
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
	u.Files = readUFWFiles(sys)

	loaded, known := ufwLoaded(ipt, nft)
	if known {
		// The live ruleset says whether UFW filters now; the files say
		// which rules it loaded (ufw writes user.rules and loads it in
		// one step, and `ufw status` prints the same file).
		u.Source = "live"
		u.Status = "inactive"
		if loaded {
			u.Status = "active"
			if u.DefaultIncoming == "" && ipt != nil && ipt.Listed {
				u.DefaultIncoming = policyWord(ipt.Policies["INPUT"])
			}
		}
		return u
	}

	// Files only: what loads at boot, not proof of what is loaded.
	u.Source = "files"
	switch u.Enabled {
	case "yes":
		u.Status = "active"
	case "no":
		u.Status = "inactive"
	}
	return u
}

// ufwLoaded reports whether UFW's chains are in the live ruleset, from
// iptables -S or, when that was not listed, from the nftables view
// (iptables-nft puts UFW's chains in the ip filter table). known is false
// when neither was listed (not root, or both commands failed).
func ufwLoaded(ipt *Iptables, nft *NFTables) (loaded, known bool) {
	if ipt != nil && ipt.Listed {
		return ipt.HasChain(ufwUserInputChain), true
	}
	if nft != nil && nft.Listed {
		return nft.UFWChains, true
	}
	return false, false
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
			if json.Unmarshal(obj["chain"], &c) != nil {
				continue
			}
			if c.Name == ufwUserInputChain {
				n.UFWChains = true
			}
			if c.Name == dockerUserChain && c.Family == "ip" {
				n.DockerUser = true
			}
			if c.Hook != "" {
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
			if r.Chain == dockerUserChain && r.Family == "ip" {
				n.DockerUserRules = append(n.DockerUserRules, renderNFTRule(r.Expr))
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

// dockerUserState reads the DOCKER-USER chain from iptables -S, or from
// the nft listing when iptables could not be listed.
func dockerUserState(t *Iptables, n *NFTables) string {
	if t == nil || !t.Listed {
		if n == nil || !n.Listed {
			return ""
		}
		if !n.DockerUser {
			return "absent"
		}
		for _, r := range n.DockerUserRules {
			if r != "return" {
				return "filtered"
			}
		}
		return "default"
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

func collectUFWDocker(sys System, u *UFW, t *Iptables, n *NFTables) *UFWDocker {
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
	switch {
	case t != nil && t.Listed:
		d.Loaded = "no"
		for _, r := range t.DockerUserRules {
			if strings.HasSuffix(r, "-j "+ufwForwardTarget) {
				d.Loaded = "yes"
			}
		}
	case n != nil && n.Listed:
		d.Loaded = "no"
		for _, r := range n.DockerUserRules {
			if strings.HasSuffix(r, "jump "+ufwForwardTarget) {
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
