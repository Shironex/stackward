package facts

import (
	"fmt"
	"strings"
	"testing"
)

// ufwDockerIptables is the DOCKER-USER chain a standard ufw-docker install
// loads, as iptables -S prints it.
const ufwDockerIptables = `-P INPUT DROP
-P FORWARD DROP
-P OUTPUT ACCEPT
-N DOCKER-USER
-N ufw-user-forward
-N ufw-docker-logging-deny
-A DOCKER-USER -j ufw-user-forward
-A DOCKER-USER -m conntrack --ctstate RELATED,ESTABLISHED -j RETURN
-A DOCKER-USER -m conntrack --ctstate INVALID -j DROP
-A DOCKER-USER -i docker0 -o docker0 -j ACCEPT
-A DOCKER-USER -s 10.0.0.0/8 -j RETURN
-A DOCKER-USER -s 172.16.0.0/12 -j RETURN
-A DOCKER-USER -s 192.168.0.0/16 -j RETURN
-A DOCKER-USER -d 10.0.0.0/8 -m conntrack --ctstate NEW -j ufw-docker-logging-deny
-A DOCKER-USER -d 172.16.0.0/12 -m conntrack --ctstate NEW -j ufw-docker-logging-deny
-A DOCKER-USER -d 192.168.0.0/16 -m conntrack --ctstate NEW -j ufw-docker-logging-deny
-A DOCKER-USER -j RETURN
-A ufw-docker-logging-deny -m limit --limit 3/min --limit-burst 10 -j LOG --log-prefix "[UFW DOCKER BLOCK] "
-A ufw-docker-logging-deny -j DROP
`

func nftRule(expr string) string {
	return `{"rule":{"family":"ip","table":"filter","chain":"DOCKER-USER","handle":1,"expr":[` + expr + `]}}`
}

const nftCounter = `{"counter":{"packets":0,"bytes":0}}`

func nftPrefix(field, addr string, n int) string {
	return fmt.Sprintf(`{"match":{"op":"==","left":{"payload":{"protocol":"ip","field":"%s"}},"right":{"prefix":{"addr":"%s","len":%d}}}}`, field, addr, n)
}

// ufwDockerNFT is the same chain listed by nft -j on an iptables-nft host.
func ufwDockerNFT() string {
	rules := []string{
		nftRule(nftCounter + `,{"jump":{"target":"ufw-user-forward"}}`),
		nftRule(`{"match":{"op":"in","left":{"ct":{"key":"state"}},"right":["established","related"]}},` + nftCounter + `,{"return":null}`),
		nftRule(`{"match":{"op":"in","left":{"ct":{"key":"state"}},"right":"invalid"}},` + nftCounter + `,{"drop":null}`),
		nftRule(`{"match":{"op":"==","left":{"meta":{"key":"iifname"}},"right":"docker0"}},{"match":{"op":"==","left":{"meta":{"key":"oifname"}},"right":"docker0"}},` + nftCounter + `,{"accept":null}`),
	}
	for _, p := range [][2]any{{"10.0.0.0", 8}, {"172.16.0.0", 12}, {"192.168.0.0", 16}} {
		rules = append(rules, nftRule(nftPrefix("saddr", p[0].(string), p[1].(int))+","+nftCounter+`,{"return":null}`))
	}
	for _, p := range [][2]any{{"10.0.0.0", 8}, {"172.16.0.0", 12}, {"192.168.0.0", 16}} {
		rules = append(rules, nftRule(nftPrefix("daddr", p[0].(string), p[1].(int))+
			`,{"match":{"op":"in","left":{"ct":{"key":"state"}},"right":"new"}},`+nftCounter+`,{"jump":{"target":"ufw-docker-logging-deny"}}`))
	}
	rules = append(rules, nftRule(nftCounter+`,{"return":null}`))
	head := `{"table":{"family":"ip","name":"filter","handle":1}},` +
		`{"chain":{"family":"ip","table":"filter","name":"FORWARD","handle":2,"type":"filter","hook":"forward","prio":0,"policy":"drop"}},` +
		`{"chain":{"family":"ip","table":"filter","name":"DOCKER-USER","handle":3}},`
	return `{"nftables":[` + head + strings.Join(rules, ",") + `]}`
}

func iptablesFirewall(rules ...string) *Firewall {
	t := &Iptables{Listed: true, Chains: []string{"DOCKER-USER"}}
	for _, r := range rules {
		t.DockerUserRules = append(t.DockerUserRules, "-A DOCKER-USER "+r)
	}
	return &Firewall{Iptables: t}
}

var canonicalRules = []string{
	"-j ufw-user-forward",
	"-m conntrack --ctstate RELATED,ESTABLISHED -j RETURN",
	"-m conntrack --ctstate INVALID -j DROP",
	"-i docker0 -o docker0 -j ACCEPT",
	"-s 10.0.0.0/8 -j RETURN",
	"-s 172.16.0.0/12 -j RETURN",
	"-s 192.168.0.0/16 -j RETURN",
	"-d 10.0.0.0/8 -m conntrack --ctstate NEW -j ufw-docker-logging-deny",
	"-d 172.16.0.0/12 -m conntrack --ctstate NEW -j ufw-docker-logging-deny",
	"-d 192.168.0.0/16 -m conntrack --ctstate NEW -j ufw-docker-logging-deny",
	"-j RETURN",
}

func TestUFWDockerChainIptables(t *testing.T) {
	fw := &Firewall{Iptables: ParseIptablesS([]byte(ufwDockerIptables))}
	c, why := fw.UFWDockerChain()
	if c == nil || why != "" || c.Source != "iptables" {
		t.Fatalf("canonical chain not recognised: %v %q", c, why)
	}
	for _, port := range []int{443, 8000} {
		if denied, why := c.Denies("tcp", port); !denied || !strings.Contains(why, "route rule") {
			t.Errorf("tcp/%d: denied=%v %q", port, denied, why)
		}
	}
	if denied, _ := c.Denies("udp", 53); !denied {
		t.Error("udp/53 not denied")
	}
}

func TestUFWDockerChainNFT(t *testing.T) {
	n, err := ParseNFTJSON([]byte(ufwDockerNFT()))
	if err != nil {
		t.Fatal(err)
	}
	if !n.DockerUser || len(n.DockerUserRules) != 11 {
		t.Fatalf("DOCKER-USER not read from nft: %v %q", n.DockerUser, n.DockerUserRules)
	}
	want := []string{"jump ufw-user-forward", "ct state established,related return", "ct state invalid drop",
		"iifname docker0 oifname docker0 accept", "ip saddr 10.0.0.0/8 return"}
	for i, w := range want {
		if n.DockerUserRules[i] != w {
			t.Errorf("rule %d = %q, want %q", i, n.DockerUserRules[i], w)
		}
	}
	if got := n.DockerUserRules[7]; got != "ip daddr 10.0.0.0/8 ct state new jump ufw-docker-logging-deny" {
		t.Errorf("deny rule = %q", got)
	}
	// iptables could not be listed: the nft view decides.
	fw := &Firewall{NFT: n, Iptables: &Iptables{Installed: true}}
	c, why := fw.UFWDockerChain()
	if c == nil || c.Source != "nft" {
		t.Fatalf("nft chain not recognised: %q", why)
	}
	if denied, _ := c.Denies("tcp", 8000); !denied {
		t.Error("tcp/8000 not denied")
	}
	if got := dockerUserState(fw.Iptables, n); got != "filtered" {
		t.Errorf("dockerUserState from nft = %q", got)
	}
	sys := newFakeSystem(map[string]string{ufwAfterRules: "# BEGIN UFW AND DOCKER\n"})
	if d := collectUFWDocker(sys, &UFW{Installed: true}, fw.Iptables, n); d.Loaded != "yes" || d.InFiles != "present" {
		t.Errorf("ufw-docker from nft: %+v", d)
	}
	// The text nft list prints, with counters, parses the same way.
	for _, line := range []string{
		"ip daddr 172.16.0.0/12 ct state new counter packets 3 bytes 180 jump ufw-docker-logging-deny",
		`iifname "docker0" oifname "docker0" counter packets 0 bytes 0 accept`,
	} {
		if r := parseUDNFT(line); len(r.unknown) > 0 || r.target == "" {
			t.Errorf("%q: %+v", line, r)
		}
	}
}

func TestUFWDockerChainVariations(t *testing.T) {
	without := func(drop int, extra ...string) []string {
		var out []string
		for i, r := range canonicalRules {
			if i != drop {
				out = append(out, r)
			}
		}
		return append(out, extra...)
	}
	cases := []struct {
		name       string
		rules      []string
		recognised bool
		reason     string // part of the reason when not recognised
		tcp443     bool   // denied
	}{
		{"canonical", canonicalRules, true, "", true},
		{"extra private range", append(append([]string{}, canonicalRules[:10]...),
			"-s 10.10.0.0/16 -j RETURN", "-d 10.10.0.0/16 -m conntrack --ctstate NEW -j ufw-docker-logging-deny", "-j RETURN"), true, "", true},
		{"private source RETURNs after the deny rules", []string{canonicalRules[0], canonicalRules[1], canonicalRules[2], canonicalRules[3],
			canonicalRules[7], canonicalRules[8], canonicalRules[9], canonicalRules[4], canonicalRules[5], canonicalRules[6], canonicalRules[10]}, true, "", true},
		{"iptables -S order of options", []string{"-j ufw-user-forward", "-j RETURN -s 10.0.0.0/8",
			"-j ufw-docker-logging-deny -m conntrack --ctstate NEW -d 172.16.0.0/12",
			"-j ufw-docker-logging-deny -m conntrack --ctstate NEW -d 192.168.0.0/16",
			"-j ufw-docker-logging-deny -m conntrack --ctstate NEW -d 10.0.0.0/8", "-j RETURN"}, true, "", true},
		{"legacy rules without conntrack", []string{"-j ufw-user-forward",
			"-s 10.0.0.0/8 -j RETURN", "-s 172.16.0.0/12 -j RETURN", "-s 192.168.0.0/16 -j RETURN",
			"-p udp -m udp --sport 53 --dport 1024:65535 -j RETURN",
			"-d 192.168.0.0/16 -p tcp -m tcp --tcp-flags FIN,SYN,RST,ACK SYN -j ufw-docker-logging-deny",
			"-d 10.0.0.0/8 -p tcp -m tcp --tcp-flags FIN,SYN,RST,ACK SYN -j ufw-docker-logging-deny",
			"-d 172.16.0.0/12 -p tcp -m tcp --tcp-flags FIN,SYN,RST,ACK SYN -j ufw-docker-logging-deny",
			"-d 192.168.0.0/16 -p udp -m udp --dport 0:32767 -j ufw-docker-logging-deny",
			"-d 10.0.0.0/8 -p udp -m udp --dport 0:32767 -j ufw-docker-logging-deny",
			"-d 172.16.0.0/12 -p udp -m udp --dport 0:32767 -j ufw-docker-logging-deny",
			"-j RETURN"}, true, "", true},
		{"no 192.168 deny rule", without(9), true, "", false},
		{"an ACCEPT for a port before the jump", append([]string{"-p tcp -m tcp --dport 8000 -j ACCEPT"}, canonicalRules...), false, "does not analyse", false},
		{"a RETURN before the jump", append([]string{"-j RETURN"}, canonicalRules...), false, "before it jumps", false},
		{"a public source allowed", without(10, "-s 203.0.113.0/24 -j RETURN", "-j RETURN"), false, "203.0.113.0/24", false},
		{"no deny rule", []string{"-j ufw-user-forward", "-j RETURN"}, false, "no rule that drops", false},
		{"a negated match", append(append([]string{}, canonicalRules[:7]...), "! -d 10.0.0.0/8 -j DROP"), false, "does not analyse", false},
	}
	for _, c := range cases {
		ch, why := iptablesFirewall(c.rules...).UFWDockerChain()
		if (ch != nil) != c.recognised || (!c.recognised && !strings.Contains(why, c.reason)) {
			t.Errorf("%s: recognised=%v %q", c.name, ch != nil, why)
			continue
		}
		if ch == nil {
			continue
		}
		if denied, why := ch.Denies("tcp", 443); denied != c.tcp443 {
			t.Errorf("%s: tcp/443 denied=%v %q", c.name, denied, why)
		}
	}
}

func TestUFWDockerLegacyUDP(t *testing.T) {
	legacy := []string{"-j ufw-user-forward",
		"-p udp -m udp --sport 53 --dport 1024:65535 -j RETURN",
		"-d 10.0.0.0/8 -p udp -m udp --dport 0:32767 -j ufw-docker-logging-deny",
		"-d 172.16.0.0/12 -p udp -m udp --dport 0:32767 -j ufw-docker-logging-deny",
		"-d 192.168.0.0/16 -p udp -m udp --dport 0:32767 -j ufw-docker-logging-deny",
		"-j RETURN"}
	c, why := iptablesFirewall(legacy...).UFWDockerChain()
	if c == nil {
		t.Fatal(why)
	}
	if denied, _ := c.Denies("udp", 53); !denied {
		t.Error("udp/53 should be denied")
	}
	if denied, why := c.Denies("udp", 40000); denied || !strings.Contains(why, "source that sends from port 53") {
		t.Errorf("udp/40000: denied=%v %q", denied, why)
	}
	if denied, _ := c.Denies("tcp", 443); denied {
		t.Error("tcp/443 has no tcp deny rule here and should not be denied")
	}
}

func TestUFWDockerChainNotUFWDocker(t *testing.T) {
	for name, fw := range map[string]*Firewall{
		"nil":                nil,
		"not listed":         {Iptables: &Iptables{Installed: true}},
		"only RETURN":        iptablesFirewall("-j RETURN"),
		"a plain DROP chain": iptablesFirewall("-i eth0 -m conntrack --ctstate NEW -j DROP", "-j RETURN"),
	} {
		if c, why := fw.UFWDockerChain(); c != nil || why != "" {
			t.Errorf("%s: %v %q", name, c, why)
		}
	}
}
