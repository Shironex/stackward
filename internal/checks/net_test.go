package checks

import (
	"strings"
	"testing"

	"github.com/Shironex/stackward/internal/facts"
	"github.com/Shironex/stackward/internal/profile"
)

func netSock(proto, addr string, port int, procs ...string) facts.Listener {
	return facts.Listener{Proto: proto, Address: addr, Port: port, Processes: procs}
}

func netUFW(def string, rules ...facts.UFWRule) *facts.Firewall {
	return &facts.Firewall{UFW: &facts.UFW{Installed: true, Source: "status", Status: "active", DefaultIncoming: def, IPv6: "yes", RulesKnown: true, Rules: rules}}
}

var (
	netSSHAnywhere = facts.UFWRule{Action: "allow", Direction: "in", Port: "22", Proto: "tcp"}
	netSSHTailnet  = facts.UFWRule{Action: "allow", Direction: "in", Port: "22", Proto: "tcp", Interface: "tailscale0"}
	netWebAnywhere = facts.UFWRule{Action: "allow", Direction: "in", Port: "80,443", Proto: "tcp"}
	netTSRoute     = facts.UFWRule{Action: "allow", Direction: "fwd", Port: "8080", Proto: "tcp", Interface: "tailscale0"}
)

// run evaluates one check and returns its results.
func netRun(t *testing.T, id string, in Input) []Result {
	t.Helper()
	for _, c := range All() {
		if c.ID == id {
			if in.Profile == "" {
				in.Profile = profile.Unknown
			}
			return EvaluateChecks([]Check{c}, in)
		}
	}
	t.Fatalf("check %s not registered", id)
	return nil
}

func netOne(t *testing.T, id string, f *facts.Facts, p profile.Name) Result {
	t.Helper()
	rs := netRun(t, id, Input{Facts: f, Profile: p})
	if len(rs) != 1 {
		t.Fatalf("%s: want one result, got %+v", id, rs)
	}
	return rs[0]
}

func netWithTailnet(t *testing.T, running, known bool) {
	t.Helper()
	tailnetState = func(*facts.Facts) (bool, bool) { return running, known }
	t.Cleanup(func() { tailnetState = profile.Tailnet })
}

type netCase struct {
	name string
	f    *facts.Facts
	p    profile.Name
	want Level
}

func netCases(t *testing.T, id string, cases []netCase) {
	t.Helper()
	for _, c := range cases {
		t.Run(id+" "+c.name, func(t *testing.T) {
			if r := netOne(t, id, c.f, c.p); r.Level != c.want {
				t.Errorf("got %s (%s), want %s", r.Level, r.Message, c.want)
			}
		})
	}
}

func TestNET001(t *testing.T) {
	root := &facts.Host{Root: true}
	netCases(t, "NET-001", []netCase{
		{"no facts", &facts.Facts{}, "", Unknown},
		{"ufw deny", &facts.Facts{Firewall: netUFW("deny")}, "", Pass},
		{"ufw allow", &facts.Facts{Firewall: netUFW("allow")}, "", Fail},
		{"ufw inactive, nothing else", &facts.Facts{Host: root, Firewall: &facts.Firewall{
			UFW:      &facts.UFW{Installed: true, Source: "status", Status: "inactive"},
			NFT:      &facts.NFTables{Installed: true, Listed: true},
			Iptables: &facts.Iptables{Installed: true, Listed: true, Policies: map[string]string{"INPUT": "ACCEPT"}},
		}}, "", Fail},
		{"nothing installed", &facts.Facts{Firewall: &facts.Firewall{UFW: &facts.UFW{}, NFT: &facts.NFTables{}, Iptables: &facts.Iptables{}}}, "", Fail},
		{"nft drop", &facts.Facts{Firewall: &facts.Firewall{NFT: &facts.NFTables{Installed: true, Listed: true,
			Chains: []facts.NFTChain{{Family: "inet", Table: "host", Name: "input", Hook: "input", Policy: "drop"}}}}}, "", Pass},
		{"iptables drop", &facts.Facts{Firewall: &facts.Firewall{Iptables: &facts.Iptables{Installed: true, Listed: true, Policies: map[string]string{"INPUT": "DROP"}}}}, "", Pass},
		{"firewalld", &facts.Facts{Firewall: &facts.Firewall{Firewalld: &facts.Firewalld{Installed: true, State: "running"}}}, "", Pass},
		{"non root files only", &facts.Facts{Firewall: &facts.Firewall{
			UFW: &facts.UFW{Installed: true, Source: "files", Status: "active", DefaultIncoming: "deny"},
			NFT: &facts.NFTables{Installed: true}}}, "", Unknown},
	})
	r := netOne(t, "NET-001", &facts.Facts{Firewall: &facts.Firewall{UFW: &facts.UFW{Installed: true, Source: "files", Status: "active", DefaultIncoming: "deny"}}}, "")
	if !strings.Contains(r.Message, "need root") {
		t.Errorf("non root message should ask for root: %q", r.Message)
	}
}

func TestNET002(t *testing.T) {
	v6 := &facts.Listeners{Addresses: []facts.InterfaceAddr{{Interface: "eth0", Address: "2001:db8::10", Prefix: 64, Scope: "global"}}}
	v4 := &facts.Listeners{Addresses: []facts.InterfaceAddr{{Interface: "eth0", Address: "203.0.113.10", Prefix: 24}}}
	off := func() *facts.Firewall { fw := netUFW("deny"); fw.UFW.IPv6 = "no"; return fw }
	netCases(t, "NET-002", []netCase{
		{"no facts", &facts.Facts{}, "", Unknown},
		{"no ufw", &facts.Facts{Firewall: &facts.Firewall{UFW: &facts.UFW{}}}, "", Skip},
		{"ipv6 yes", &facts.Facts{Firewall: netUFW("deny")}, "", Pass},
		{"ipv6 no with global v6", &facts.Facts{Firewall: off(), Listeners: v6}, "", Fail},
		{"ipv6 no without v6", &facts.Facts{Firewall: off(), Listeners: v4}, "", Pass},
		{"ipv6 no, addresses unread", &facts.Facts{Firewall: off(), Listeners: &facts.Listeners{}}, "", Unknown},
	})
}

func TestNET003(t *testing.T) {
	publicSSH := &facts.Listeners{Sockets: []facts.Listener{netSock("tcp", "0.0.0.0", 22, "sshd"), netSock("tcp", "::", 22, "sshd")}}
	tailnetSSH := &facts.Listeners{Sockets: []facts.Listener{netSock("tcp", "100.101.102.103", 22, "sshd")}}
	open := &facts.Facts{Listeners: publicSSH, Firewall: netUFW("deny", netSSHAnywhere)}
	closed := &facts.Facts{Listeners: publicSSH, Firewall: netUFW("deny", netSSHTailnet)}

	netCases(t, "NET-003", []netCase{
		{"no facts", &facts.Facts{}, "", Unknown},
		{"open, no tailscale facts", open, "", Unknown},
		{"only tailnet rule", closed, "", Pass},
		{"bound to tailnet", &facts.Facts{Listeners: tailnetSSH, Firewall: netUFW("allow")}, "", Pass},
		{"firewall off", &facts.Facts{Listeners: publicSSH, Firewall: netUFW("allow")}, "", Unknown},
		{"nft drop, rules not analysed", &facts.Facts{Listeners: publicSSH, Firewall: &facts.Firewall{NFT: &facts.NFTables{Installed: true, Listed: true,
			Chains: []facts.NFTChain{{Hook: "input", Policy: "drop"}}}}}, "", Unknown},
	})

	netWithTailnet(t, true, true)
	netCases(t, "NET-003", []netCase{
		{"open, tailnet running", open, "", Fail},
		{"open by OpenSSH app profile", &facts.Facts{Listeners: publicSSH, Firewall: netUFW("deny",
			facts.UFWRule{Action: "limit", Direction: "in", Port: "22", Proto: "tcp", App: "OpenSSH"})}, "", Fail},
		{"closed, tailnet running", closed, "", Pass},
	})
	netWithTailnet(t, false, true)
	netCases(t, "NET-003", []netCase{{"open, no tailnet", open, "", Warn}})

	// A custom port is found from the sshd process.
	custom := &facts.Facts{Listeners: &facts.Listeners{Sockets: []facts.Listener{netSock("tcp", "0.0.0.0", 2222, "sshd")}},
		Firewall: netUFW("deny", netSSHAnywhere)}
	if r := netOne(t, "NET-003", custom, ""); r.Level != Pass {
		t.Errorf("port 22 rule must not open sshd on 2222: %s %s", r.Level, r.Message)
	}
}

func TestNET004(t *testing.T) {
	l := &facts.Listeners{ProcessesVisible: true, Sockets: []facts.Listener{
		netSock("tcp", "0.0.0.0", 22, "sshd"),
		netSock("tcp", "::", 22, "sshd"),
		netSock("tcp", "127.0.0.1", 5432, "postgres"),
		netSock("tcp", "0.0.0.0", 6379, "docker-proxy"),
		netSock("tcp", "0.0.0.0", 9100, "node_exporter"),
		netSock("tcp", "100.101.102.103", 8000),
		netSock("udp", "203.0.113.10", 68, "systemd-network"),
	}}
	want := map[string]Level{
		"port:tcp/22": Info, "port:tcp/5432": Info, "port:tcp/6379": Warn,
		"port:tcp/9100": Pass, "port:tcp/8000": Info, "port:udp/68": Info,
	}
	rs := netRun(t, "NET-004", Input{Facts: &facts.Facts{Listeners: l, Firewall: netUFW("deny", netSSHAnywhere)}})
	if len(rs) != len(want) {
		t.Fatalf("got %d results: %+v", len(rs), rs)
	}
	for _, r := range rs {
		if want[r.Subject] != r.Level {
			t.Errorf("%s: got %s (%s), want %s", r.Subject, r.Level, r.Message, want[r.Subject])
		}
	}

	// No firewall: wildcard listeners warn.
	rs = netRun(t, "NET-004", Input{Facts: &facts.Facts{Listeners: l, Firewall: netUFW("allow")}})
	for _, r := range rs {
		if r.Subject == "port:tcp/9100" && r.Level != Warn {
			t.Errorf("unfiltered wildcard listener: %s %s", r.Level, r.Message)
		}
	}
	// Firewall unknown: unknown, never pass.
	rs = netRun(t, "NET-004", Input{Facts: &facts.Facts{Listeners: l}})
	for _, r := range rs {
		if r.Subject == "port:tcp/9100" && r.Level != Unknown {
			t.Errorf("without firewall facts: %s %s", r.Level, r.Message)
		}
	}
	// DOCKER-USER filtering turns the published port into info.
	fw := netUFW("deny")
	fw.DockerUser = "filtered"
	rs = netRun(t, "NET-004", Input{Facts: &facts.Facts{Listeners: l, Firewall: fw}})
	for _, r := range rs {
		if r.Subject == "port:tcp/6379" && r.Level != Info {
			t.Errorf("filtered DOCKER-USER: %s %s", r.Level, r.Message)
		}
	}
	netCases(t, "NET-004", []netCase{
		{"no facts", &facts.Facts{}, "", Unknown},
		{"no sockets", &facts.Facts{Listeners: &facts.Listeners{Sockets: []facts.Listener{}}}, "", Info},
	})
}

func TestNET005(t *testing.T) {
	withWeb := &facts.Facts{Firewall: netUFW("deny", netWebAnywhere, netSSHTailnet)}
	clean := &facts.Facts{Firewall: netUFW("deny", netSSHTailnet)}
	netCases(t, "NET-005", []netCase{
		{"no facts", &facts.Facts{}, profile.Tunnel, Unknown},
		{"unknown profile", withWeb, profile.Unknown, Unknown},
		{"tunnel with web rule", withWeb, profile.Tunnel, Warn},
		{"tailnet with web rule", withWeb, profile.TailnetOnly, Warn},
		{"tunnel clean", clean, profile.Tunnel, Pass},
		{"public web", withWeb, profile.PublicWeb, Skip},
		{"mixed", withWeb, profile.Mixed, Skip},
		{"rules unknown", &facts.Facts{Firewall: &facts.Firewall{UFW: &facts.UFW{Installed: true, Source: "files", Status: "active"}}}, profile.Tunnel, Unknown},
	})
}

func TestNET006(t *testing.T) {
	netCases(t, "NET-006", []netCase{
		{"no facts", &facts.Facts{}, "", Unknown},
		{"not read", &facts.Facts{Firewall: &facts.Firewall{}}, "", Unknown},
		{"filtered", &facts.Facts{Firewall: &facts.Firewall{DockerUser: "filtered"}}, "", Info},
		{"default", &facts.Facts{Firewall: &facts.Firewall{DockerUser: "default"}}, "", Info},
		{"absent", &facts.Facts{Firewall: &facts.Firewall{DockerUser: "absent", DockerBackend: "nftables"}}, "", Info},
	})
}

func TestNET007(t *testing.T) {
	loaded := func(rules ...facts.UFWRule) *facts.Firewall {
		fw := netUFW("deny", rules...)
		fw.UFWDocker = &facts.UFWDocker{InFiles: "present", Loaded: "yes"}
		return fw
	}
	published := &facts.Listeners{Sockets: []facts.Listener{netSock("tcp", "0.0.0.0", 8080, "docker-proxy")}}
	netCases(t, "NET-007", []netCase{
		{"no facts", &facts.Facts{}, "", Unknown},
		{"no ufw", &facts.Facts{Firewall: &facts.Firewall{}}, "", Skip},
		{"not installed", &facts.Facts{Firewall: &facts.Firewall{UFWDocker: &facts.UFWDocker{InFiles: "absent", Loaded: "no"}}}, "", Skip},
		{"unreadable", &facts.Facts{Firewall: &facts.Firewall{UFWDocker: &facts.UFWDocker{}}}, "", Unknown},
		{"in files, not loaded", &facts.Facts{Firewall: &facts.Firewall{UFWDocker: &facts.UFWDocker{InFiles: "present", Loaded: "no"}}}, "", Fail},
		{"in files, live unknown", &facts.Facts{Firewall: &facts.Firewall{UFWDocker: &facts.UFWDocker{InFiles: "present"}}}, "", Unknown},
		{"loaded with route rules", &facts.Facts{Firewall: loaded(netTSRoute)}, "", Pass},
		{"loaded, published, tailnet unknown", &facts.Facts{Firewall: loaded(), Listeners: published}, "", Warn},
		{"loaded, nothing seen", &facts.Facts{Firewall: loaded()}, "", Unknown},
	})
	netWithTailnet(t, false, true)
	netCases(t, "NET-007", []netCase{{"loaded, no tailnet", &facts.Facts{Firewall: loaded(), Listeners: published}, "", Pass}})
}

func TestNET008(t *testing.T) {
	ud := &facts.UFWDocker{InFiles: "present", Loaded: "yes"}
	netCases(t, "NET-008", []netCase{
		{"no facts", &facts.Facts{}, "", Unknown},
		{"no ufw-docker", &facts.Facts{Firewall: &facts.Firewall{UFWDocker: &facts.UFWDocker{InFiles: "absent", Loaded: "no"}}}, "", Skip},
		{"nftables backend", &facts.Facts{Firewall: &facts.Firewall{UFWDocker: ud, DockerBackend: "nftables"}}, "", Warn},
		{"iptables backend", &facts.Facts{Firewall: &facts.Firewall{UFWDocker: ud, DockerBackend: "iptables"}}, "", Pass},
		{"backend unknown", &facts.Facts{Firewall: &facts.Firewall{UFWDocker: &facts.UFWDocker{InFiles: "present"}}}, "", Unknown},
	})
}

func TestNET009(t *testing.T) {
	r := netOne(t, "NET-009", &facts.Facts{Firewall: netUFW("deny")}, profile.Tunnel)
	if r.Level != Unknown || !strings.Contains(r.Message, "stackward probe") || !strings.Contains(r.Message, "cannot be seen from inside") {
		t.Errorf("NET-009 = %s %q", r.Level, r.Message)
	}
}
