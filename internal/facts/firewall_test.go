package facts

import (
	"context"
	"reflect"
	"testing"
)

func TestUFWRuleMatchesPort(t *testing.T) {
	cases := []struct {
		r     UFWRule
		proto string
		port  int
		want  bool
	}{
		{UFWRule{Port: "22", Proto: "tcp"}, "tcp", 22, true},
		{UFWRule{Port: "22", Proto: "tcp"}, "udp", 22, false},
		{UFWRule{Port: "80,443", Proto: "tcp"}, "tcp", 443, true},
		{UFWRule{Port: "3000:3005", Proto: "tcp"}, "tcp", 3003, true},
		{UFWRule{Port: "3000:3005", Proto: "tcp"}, "tcp", 3006, false},
		{UFWRule{Proto: "any"}, "udp", 53, true},
		{UFWRule{Proto: "any", App: "Custom App"}, "tcp", 22, false},
	}
	for _, c := range cases {
		if got := c.r.MatchesPort(c.proto, c.port); got != c.want {
			t.Errorf("%+v.MatchesPort(%s, %d) = %v", c.r, c.proto, c.port, got)
		}
	}
}

// userRulesCapture is /etc/ufw/user.rules (trimmed to the tuples and the
// iptables lines around one of them).
const userRulesCapture = `*filter
:ufw-user-input - [0:0]
:ufw-user-output - [0:0]
:ufw-user-forward - [0:0]
### RULES ###

### tuple ### allow tcp 22 0.0.0.0/0 any 0.0.0.0/0 in_tailscale0
-A ufw-user-input -i tailscale0 -p tcp --dport 22 -j ACCEPT

### tuple ### allow tcp 22 0.0.0.0/0 any 198.51.100.7 in comment=61646d696e
-A ufw-user-input -p tcp --dport 22 -s 198.51.100.7 -j ACCEPT

### tuple ### allow tcp 80,443 0.0.0.0/0 any 0.0.0.0/0 in
### tuple ### limit tcp 22 0.0.0.0/0 any 192.0.2.0/24 OpenSSH - in
### tuple ### deny_log tcp 9000 203.0.113.10 any 0.0.0.0/0 in
### tuple ### route:allow tcp 8080 0.0.0.0/0 any 0.0.0.0/0 in_tailscale0
### tuple ### route:allow tcp 3000:3005 0.0.0.0/0 any 0.0.0.0/0 in_tailscale0!out_docker0

### END RULES ###
COMMIT
`

func TestParseUFWUserRules(t *testing.T) {
	got := ParseUFWUserRules([]byte(userRulesCapture), false)
	want := []UFWRule{
		{Action: "allow", Direction: "in", Port: "22", Proto: "tcp", Interface: "tailscale0"},
		{Action: "allow", Direction: "in", Port: "22", Proto: "tcp", From: "198.51.100.7"},
		{Action: "allow", Direction: "in", Port: "80,443", Proto: "tcp"},
		{Action: "limit", Direction: "in", Port: "22", Proto: "tcp", From: "192.0.2.0/24", App: "OpenSSH"},
		{Action: "deny", Direction: "in", Port: "9000", Proto: "tcp", To: "203.0.113.10"},
		{Action: "allow", Direction: "fwd", Port: "8080", Proto: "tcp", Interface: "tailscale0"},
		{Action: "allow", Direction: "fwd", Port: "3000:3005", Proto: "tcp", Interface: "tailscale0"},
	}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("got\n%+v\nwant\n%+v", got, want)
	}
}

// nftCapture is `nft -j list ruleset` (shortened) from an iptables-nft host
// with UFW, plus a native inet table that ends its input chain in a drop.
const nftCapture = `{"nftables": [{"metainfo": {"version": "1.0.9", "release_name": "Old Doc Yak #3", "json_schema_version": 1}},
{"table": {"family": "ip", "name": "filter", "handle": 1}},
{"chain": {"family": "ip", "table": "filter", "name": "INPUT", "handle": 1, "type": "filter", "hook": "input", "prio": 0, "policy": "drop"}},
{"chain": {"family": "ip", "table": "filter", "name": "ufw-user-input", "handle": 9}},
{"rule": {"family": "ip", "table": "filter", "chain": "INPUT", "handle": 30, "expr": [{"counter": {"packets": 10, "bytes": 600}}, {"jump": {"target": "ufw-before-input"}}]}},
{"table": {"family": "inet", "name": "host", "handle": 2}},
{"chain": {"family": "inet", "table": "host", "name": "input", "handle": 1, "type": "filter", "hook": "input", "prio": 10, "policy": "accept"}},
{"rule": {"family": "inet", "table": "host", "chain": "input", "handle": 4, "expr": [{"match": {"op": "==", "left": {"meta": {"key": "iifname"}}, "right": "lo"}}, {"accept": null}]}},
{"rule": {"family": "inet", "table": "host", "chain": "input", "handle": 5, "expr": [{"counter": {"packets": 0, "bytes": 0}}, {"drop": null}]}},
{"table": {"family": "ip", "name": "docker-bridges", "handle": 3}}
]}`

func TestParseNFTJSON(t *testing.T) {
	n, err := ParseNFTJSON([]byte(nftCapture))
	if err != nil {
		t.Fatal(err)
	}
	if !n.Listed || len(n.Tables) != 3 || len(n.Chains) != 2 {
		t.Fatalf("%+v", n)
	}
	want := NFTChain{Family: "inet", Table: "host", Name: "input", Hook: "input", Policy: "accept", Rules: 2, EndsInDrop: true}
	if n.Chains[1] != want {
		t.Errorf("chain = %+v, want %+v", n.Chains[1], want)
	}
	if !n.InputDrops() || !n.HasTable("docker-bridges") {
		t.Error("InputDrops or HasTable wrong")
	}
	empty, err := ParseNFTJSON(nil)
	if err != nil || !empty.Listed || empty.InputDrops() {
		t.Errorf("empty ruleset: %+v %v", empty, err)
	}
	if _, err := ParseNFTJSON([]byte("{")); err == nil {
		t.Error("bad JSON accepted")
	}
}

// iptablesCapture is `iptables -S` from a Docker host with ufw-docker.
const iptablesCapture = `-P INPUT DROP
-P FORWARD DROP
-P OUTPUT ACCEPT
-N DOCKER
-N DOCKER-USER
-N ufw-before-input
-N ufw-user-forward
-N ufw-user-input
-N ufw-docker-logging-deny
-A INPUT -j ufw-before-logging-input
-A INPUT -j ufw-before-input
-A FORWARD -j DOCKER-USER
-A DOCKER-USER -j ufw-user-forward
-A DOCKER-USER -s 10.0.0.0/8 -j RETURN
-A DOCKER-USER -p tcp -m tcp --tcp-flags FIN,SYN,RST,ACK SYN -d 172.16.0.0/12 -j ufw-docker-logging-deny
-A DOCKER-USER -j RETURN
`

func TestParseIptablesS(t *testing.T) {
	ipt := ParseIptablesS([]byte(iptablesCapture))
	if ipt.Policies["INPUT"] != "DROP" || ipt.InputRules != 2 || len(ipt.DockerUserRules) != 4 {
		t.Fatalf("%+v", ipt)
	}
	if !ipt.HasChain("DOCKER") || !ipt.HasChain("ufw-user-forward") || ipt.HasChain("NOPE") {
		t.Error("HasChain wrong")
	}
	if got := dockerUserState(ipt, nil); got != "filtered" {
		t.Errorf("dockerUserState = %s", got)
	}
	def := ParseIptablesS([]byte("-P INPUT ACCEPT\n-N DOCKER-USER\n-A DOCKER-USER -j RETURN\n"))
	if got := dockerUserState(def, nil); got != "default" {
		t.Errorf("default chain = %s", got)
	}
	if got := dockerUserState(ParseIptablesS([]byte("-P INPUT ACCEPT\n")), nil); got != "absent" {
		t.Errorf("no chain = %s", got)
	}
	if got := dockerUserState(&Iptables{Installed: true}, nil); got != "" {
		t.Errorf("unlisted = %q", got)
	}
}

func TestDockerBackend(t *testing.T) {
	withDocker := &NFTables{Listed: true, Tables: []NFTTable{{"ip", "docker-bridges"}}}
	plain := &NFTables{Listed: true}
	iptDocker := ParseIptablesS([]byte("-N DOCKER\n"))
	iptPlain := ParseIptablesS([]byte("-P INPUT ACCEPT\n"))
	cases := []struct {
		n    *NFTables
		t    *Iptables
		want string
	}{
		{withDocker, iptPlain, "nftables"},
		{plain, iptDocker, "iptables"},
		{plain, iptPlain, "none"},
		{&NFTables{Installed: true}, &Iptables{Installed: true}, ""},
	}
	for i, c := range cases {
		if got := dockerBackend(c.n, c.t); got != c.want {
			t.Errorf("case %d: got %q want %q", i, got, c.want)
		}
	}
}

const ufwDockerAfterRules = `*filter
:ufw-after-input - [0:0]
COMMIT
# BEGIN UFW AND DOCKER
*filter
:ufw-user-forward - [0:0]
:DOCKER-USER - [0:0]
-A DOCKER-USER -j ufw-user-forward
COMMIT
# END UFW AND DOCKER
`

func TestFirewallCollectorRoot(t *testing.T) {
	sys := newFakeSystem(map[string]string{
		"/etc/ufw/ufw.conf":    "# /etc/ufw/ufw.conf\nENABLED=yes\nLOGLEVEL=low\n",
		"/etc/default/ufw":     "IPV6=yes\nDEFAULT_INPUT_POLICY=\"DROP\"\nDEFAULT_FORWARD_POLICY=\"DROP\"\n",
		"/etc/ufw/after.rules": ufwDockerAfterRules,
		"/etc/ufw/user.rules":  userRulesCapture,
	})
	sys.host.Root = true
	// ufw exists, but the collector must never run it (ufw status writes
	// /run/ufw.lock, which the sandbox refuses).
	sys.cmds["ufw"] = CmdResult{ExitCode: 1, Stderr: []byte("must not run")}
	sys.cmds["nft -j list ruleset"] = CmdResult{Stdout: []byte(nftCapture)}
	sys.cmds["iptables -V"] = CmdResult{Stdout: []byte("iptables v1.8.10 (nf_tables)\n")}
	sys.cmds["iptables -S"] = CmdResult{Stdout: []byte(iptablesCapture)}
	var out Facts
	if err := (firewallCollector{}).Collect(context.Background(), sys, &out); err != nil {
		t.Fatal(err)
	}
	fw := out.Firewall
	if fw.UFW.Source != "live" || fw.UFW.Status != "active" || fw.UFW.Enabled != "yes" || !fw.UFW.RulesKnown || len(fw.UFW.Rules) != 7 || fw.UFW.IPv6 != "yes" {
		t.Errorf("ufw: %+v", fw.UFW)
	}
	if fw.Iptables.Backend != "nf_tables" || !fw.Iptables.Listed {
		t.Errorf("iptables: %+v", fw.Iptables)
	}
	if fw.DockerUser != "filtered" || fw.DockerBackend != "nftables" {
		t.Errorf("docker user %q backend %q", fw.DockerUser, fw.DockerBackend)
	}
	if *fw.UFWDocker != (UFWDocker{InFiles: "present", Loaded: "yes"}) {
		t.Errorf("ufw-docker: %+v", fw.UFWDocker)
	}
	if fw.Firewalld != nil {
		t.Errorf("firewalld reported without firewall-cmd: %+v", fw.Firewalld)
	}
}

func TestFirewallCollectorNonRoot(t *testing.T) {
	sys := newFakeSystem(map[string]string{
		"/etc/ufw/ufw.conf": "ENABLED=yes\n",
		"/etc/default/ufw":  "IPV6=no\nDEFAULT_INPUT_POLICY=\"DROP\"\n",
	})
	// ufw and nft exist but must not be run without root.
	sys.cmds["ufw"] = CmdResult{}
	sys.cmds["nft"] = CmdResult{}
	sys.cmds["iptables -V"] = CmdResult{Stdout: []byte("iptables v1.8.9 (legacy)\n")}
	sys.cmds["firewall-cmd --state"] = CmdResult{Stderr: []byte("not running\n"), ExitCode: 252}
	var out Facts
	if err := (firewallCollector{}).Collect(context.Background(), sys, &out); err != nil {
		t.Fatal(err)
	}
	fw := out.Firewall
	want := &UFW{Installed: true, Source: "files", Status: "active", Enabled: "yes", DefaultIncoming: "deny", IPv6: "no"}
	if !reflect.DeepEqual(fw.UFW, want) {
		t.Errorf("ufw = %+v, want %+v", fw.UFW, want)
	}
	if !fw.NFT.Installed || fw.NFT.Listed || fw.Iptables.Listed || fw.Iptables.Backend != "legacy" {
		t.Errorf("nft %+v iptables %+v", fw.NFT, fw.Iptables)
	}
	if fw.DockerUser != "" || fw.DockerBackend != "" {
		t.Errorf("docker facts claimed without root: %q %q", fw.DockerUser, fw.DockerBackend)
	}
	if *fw.UFWDocker != (UFWDocker{}) {
		t.Errorf("ufw-docker = %+v", fw.UFWDocker)
	}
	if fw.Firewalld == nil || fw.Firewalld.State != "not running" {
		t.Errorf("firewalld = %+v", fw.Firewalld)
	}
}

// TestFirewallCollectorSandboxedRoot is the real run that broke: root,
// UFW active, and every command that would write refused. The collector
// must not depend on ufw at all and must end without an error.
func TestFirewallCollectorSandboxedRoot(t *testing.T) {
	sys := newFakeSystem(map[string]string{
		"/etc/ufw/ufw.conf":   "ENABLED=yes\n",
		"/etc/default/ufw":    "IPV6=yes\nDEFAULT_INPUT_POLICY=\"DROP\"\n",
		"/etc/ufw/user.rules": userRulesCapture,
	})
	sys.host.Root = true
	sys.cmds["ufw status verbose"] = CmdResult{ExitCode: 1, Stderr: []byte("Traceback (most recent call last):\nPermissionError: [Errno 13] Permission denied: '/run/ufw.lock'\n")}
	sys.cmds["nft -j list ruleset"] = CmdResult{Stdout: []byte(nftCapture)}
	sys.cmds["iptables -V"] = CmdResult{Stdout: []byte("iptables v1.8.10 (nf_tables)\n")}
	sys.cmds["iptables -S"] = CmdResult{Stdout: []byte(iptablesCapture)}
	var out Facts
	if err := (firewallCollector{}).Collect(context.Background(), sys, &out); err != nil {
		t.Fatalf("collector must not fail: %v", err)
	}
	u := out.Firewall.UFW
	if u.Source != "live" || u.Status != "active" || u.DefaultIncoming != "deny" || !u.RulesKnown || len(u.Rules) != 7 {
		t.Errorf("ufw = %+v", u)
	}
}

func TestFirewallCollectorLoadedState(t *testing.T) {
	tests := []struct {
		name, conf, iptables, nft string
		wantSource, wantStatus    string
	}{
		{"enabled but not loaded", "ENABLED=yes\n", "-P INPUT ACCEPT\n", "", "live", "inactive"},
		{"disabled and not loaded", "ENABLED=no\n", "-P INPUT ACCEPT\n", "", "live", "inactive"},
		{"loaded seen through nft only", "ENABLED=yes\n", "", nftCapture, "live", "active"},
		{"nothing listed", "ENABLED=no\n", "", "", "files", "inactive"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			sys := newFakeSystem(map[string]string{"/etc/ufw/ufw.conf": tt.conf})
			sys.host.Root = true
			if tt.iptables != "" {
				sys.cmds["iptables -S"] = CmdResult{Stdout: []byte(tt.iptables)}
			}
			if tt.nft != "" {
				sys.cmds["nft -j list ruleset"] = CmdResult{Stdout: []byte(tt.nft)}
			}
			var out Facts
			_ = (firewallCollector{}).Collect(context.Background(), sys, &out)
			if u := out.Firewall.UFW; u.Source != tt.wantSource || u.Status != tt.wantStatus {
				t.Errorf("ufw = %+v, want source %s status %s", u, tt.wantSource, tt.wantStatus)
			}
		})
	}
}

func TestFirewallCollectorNothingInstalled(t *testing.T) {
	var out Facts
	if err := (firewallCollector{}).Collect(context.Background(), newFakeSystem(nil), &out); err != nil {
		t.Fatal(err)
	}
	fw := out.Firewall
	if fw.UFW.Installed || fw.NFT.Installed || fw.Iptables.Installed || fw.UFWDocker != nil {
		t.Errorf("%+v", fw)
	}
}
