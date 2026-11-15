package checks

import (
	"strings"
	"testing"

	"github.com/Shironex/stackward/internal/facts"
	"github.com/Shironex/stackward/internal/profile"
)

func publish(hostIP string, hostPort, containerPort int) func(*facts.DockerContainer) {
	return func(c *facts.DockerContainer) {
		c.Ports = append(c.Ports, facts.DockerPort{HostIP: hostIP, HostPort: hostPort, ContainerPort: containerPort, Proto: "tcp"})
	}
}

// exposureHost is a Docker host with UFW active (deny), the iptables
// backend, the given DOCKER-USER rules and eth0 on a public address.
func exposureHost(dockerUser string, rules []string, cs ...facts.DockerContainer) *facts.Facts {
	f := dockerHost(cs...)
	fw := netUFW("deny", netSSHTailnet)
	fw.DockerUser, fw.DockerBackend = dockerUser, "iptables"
	fw.Iptables = &facts.Iptables{Installed: true, Listed: true, Chains: []string{"DOCKER", "DOCKER-USER"}, DockerUserRules: rules}
	fw.UFWDocker = &facts.UFWDocker{InFiles: "absent", Loaded: "no"}
	f.Firewall = fw
	f.Listeners = &facts.Listeners{Sockets: []facts.Listener{}, Addresses: []facts.InterfaceAddr{
		{Interface: "eth0", Address: "203.0.113.10", Prefix: 24, Scope: "global"},
		{Interface: "eth1", Address: "10.0.0.5", Prefix: 24, Scope: "global"},
		{Interface: "tailscale0", Address: "100.64.0.7", Prefix: 32, Scope: "global"},
	}}
	return f
}

var dropPublic = []string{
	"-A DOCKER-USER -m conntrack --ctstate RELATED,ESTABLISHED -j RETURN",
	"-A DOCKER-USER -i eth0 -s 198.51.100.0/24 -j RETURN",
	"-A DOCKER-USER -i eth0 -m conntrack --ctstate NEW -j DROP",
	"-A DOCKER-USER -j RETURN",
}

func dkr001(t *testing.T, f *facts.Facts, p profile.Name) Result {
	t.Helper()
	rs := checkPublishedPorts(Input{Facts: f, Profile: p})
	if len(rs) != 1 {
		t.Fatalf("want one result, got %+v", rs)
	}
	return rs[0]
}

func TestDKR001(t *testing.T) {
	db := app("db", publish("0.0.0.0", 5432, 5432))
	web := app("proxy", publish("0.0.0.0", 443, 443))
	nftHost := exposureHost("absent", nil, db)
	nftHost.Firewall.DockerBackend = "nftables"
	nftHost.Firewall.NFT = &facts.NFTables{Installed: true, Listed: true}
	nftDrop := exposureHost("absent", nil, db)
	nftDrop.Firewall.DockerBackend = "nftables"
	nftDrop.Firewall.NFT = &facts.NFTables{Installed: true, Listed: true, Chains: []facts.NFTChain{{Family: "inet", Table: "filter", Name: "forward", Hook: "forward", Policy: "drop"}}}
	ufwDocker := func(rules ...facts.UFWRule) *facts.Facts {
		f := exposureHost("filtered", []string{"-A DOCKER-USER -j ufw-user-forward", "-A DOCKER-USER -j RETURN"}, db)
		f.Firewall.UFWDocker = &facts.UFWDocker{InFiles: "present", Loaded: "yes"}
		f.Firewall.UFW.Rules = append(f.Firewall.UFW.Rules, rules...)
		return f
	}
	iptOff := exposureHost("absent", nil, db)
	iptOff.Docker.Daemon.IPTables = ptrBool(false)
	noFirewall := exposureHost("default", nil, db)
	noFirewall.Firewall = nil
	cases := []struct {
		name string
		f    *facts.Facts
		p    profile.Name
		want Level
	}{
		{"no facts", &facts.Facts{}, profile.Unknown, Unknown},
		{"docker absent", &facts.Facts{Docker: &facts.Docker{}}, profile.Unknown, Skip},
		{"socket denied", denied(), profile.Unknown, Unknown},
		{"no ports", exposureHost("default", nil, app("worker")), profile.Unknown, Pass},
		{"loopback bind", exposureHost("default", nil, app("db", publish("127.0.0.1", 5432, 5432))), profile.Tunnel, Pass},
		{"tailnet bind", exposureHost("default", nil, app("db", publish("100.64.0.7", 5432, 5432))), profile.Tunnel, Pass},
		{"wildcard, default chain", exposureHost("default", []string{"-A DOCKER-USER -j RETURN"}, db), profile.Unknown, Fail},
		{"wildcard v6, no chain", exposureHost("absent", nil, app("db", publish("::", 5432, 5432))), profile.Unknown, Fail},
		{"wildcard, chain not read", exposureHost("", nil, db), profile.Unknown, Unknown},
		{"firewall missing", noFirewall, profile.Unknown, Unknown},
		{"drop on the public interface", exposureHost("filtered", dropPublic, db), profile.Unknown, Pass},
		{"allowlist drop", exposureHost("filtered", []string{"-A DOCKER-USER ! -s 198.51.100.0/24 -j DROP"}, db), profile.Unknown, Pass},
		{"drop only on the private interface", exposureHost("filtered", []string{"-A DOCKER-USER -i eth1 -j DROP", "-A DOCKER-USER -j RETURN"}, db), profile.Unknown, Fail},
		{"port opened before the drop", exposureHost("filtered", []string{"-A DOCKER-USER -i eth0 -p tcp -m tcp --dport 5432 -j RETURN", "-A DOCKER-USER -i eth0 -j DROP"}, db), profile.Unknown, Fail},
		{"other port opened before the drop", exposureHost("filtered", []string{"-A DOCKER-USER -i eth0 -p tcp -m conntrack --ctorigdstport 8080 -j RETURN", "-A DOCKER-USER -i eth0 -j DROP"}, db), profile.Unknown, Pass},
		{"unknown interface", exposureHost("filtered", []string{"-A DOCKER-USER -i ens9 -j DROP"}, db), profile.Unknown, Unknown},
		{"ipset match", exposureHost("filtered", []string{"-A DOCKER-USER -m set --match-set blocklist src -j DROP"}, db), profile.Unknown, Unknown},
		{"custom chain", exposureHost("filtered", []string{"-A DOCKER-USER -j MY-FILTER"}, db), profile.Unknown, Unknown},
		{"ufw-docker, no route rule", ufwDocker(), profile.Unknown, Pass},
		{"ufw-docker, route from anywhere", ufwDocker(facts.UFWRule{Action: "allow", Direction: "fwd", Port: "5432", Proto: "tcp"}), profile.Unknown, Warn},
		{"ufw-docker, route on tailscale0", ufwDocker(netTSRoute, facts.UFWRule{Action: "allow", Direction: "fwd", Port: "5432", Proto: "tcp", Interface: "tailscale0"}), profile.Unknown, Pass},
		{"ufw-docker, route on tunnel profile", ufwDocker(facts.UFWRule{Action: "allow", Direction: "fwd", Port: "5432", Proto: "tcp"}), profile.Tunnel, Fail},
		{"nftables backend, nothing drops", nftHost, profile.Unknown, Fail},
		{"nftables backend, forward drop", nftDrop, profile.Unknown, Unknown},
		{"iptables off, ufw denies", iptOff, profile.Unknown, Pass},
		{"web port on public-web", exposureHost("default", nil, web), profile.PublicWeb, Pass},
		{"web port on tunnel", exposureHost("default", nil, web), profile.Tunnel, Fail},
		{"web port, profile unknown", exposureHost("default", nil, web), profile.Unknown, Warn},
		{"web port, mixed", exposureHost("default", nil, web), profile.Mixed, Warn},
	}
	for _, tc := range cases {
		r := dkr001(t, tc.f, tc.p)
		if r.Level != tc.want {
			t.Errorf("%s: got %s (%s), want %s", tc.name, r.Level, r.Message, tc.want)
		}
	}
}

func TestDKR001Evidence(t *testing.T) {
	f := exposureHost("filtered", dropPublic, app("db", publish("0.0.0.0", 5432, 5432), publish("127.0.0.1", 6379, 6379)))
	r := dkr001(t, f, profile.Unknown)
	if r.Level != Pass {
		t.Fatalf("got %s (%s)", r.Level, r.Message)
	}
	if got := r.Evidence["filtered"].([]string); len(got) != 1 || got[0] != "0.0.0.0:5432->5432/tcp" {
		t.Errorf("filtered = %v", got)
	}
	if got := r.Evidence["published"].([]string); len(got) != 2 {
		t.Errorf("published = %v", got)
	}
	f = exposureHost("default", nil, app("db", publish("0.0.0.0", 5432, 5432)))
	r = dkr001(t, f, profile.Unknown)
	if !strings.Contains(r.Message, "UFW's input rules do not apply") {
		t.Errorf("message should explain the bypass: %s", r.Message)
	}
}

func TestParseIptRule(t *testing.T) {
	r := parseIptRule(`-A DOCKER-USER -i eth0 -p tcp -m comment --comment "allow the office" -m multiport --dports 80,443 -j RETURN`)
	if r.iface != "eth0" || r.proto != "tcp" || r.dport != "80,443" || r.target != "RETURN" || len(r.unsure) != 0 {
		t.Errorf("parsed %+v", r)
	}
	r = parseIptRule("-A DOCKER-USER ! -i docker0 -o docker0 -j DROP")
	if r.iface != "docker0" || !r.ifNeg || len(r.unsure) != 1 {
		t.Errorf("parsed %+v", r)
	}
	if !portIn("8000:8100", 8080) || portIn("22,80", 443) {
		t.Error("portIn")
	}
}
