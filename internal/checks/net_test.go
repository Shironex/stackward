package checks

import (
	"strings"
	"testing"

	"github.com/Shironex/stackward/internal/facts"
	"github.com/Shironex/stackward/internal/profile"
)

// netPublish is Docker facts with one container publishing tcp port on all
// interfaces.
func netPublish(port int) *facts.Docker {
	return &facts.Docker{Installed: true, API: "ok", Containers: []facts.DockerContainer{{
		Name: "app", Running: true, Ports: []facts.DockerPort{{HostIP: "0.0.0.0", HostPort: port, ContainerPort: port, Proto: "tcp"}},
	}}}
}

// netDockerUserDefault marks the DOCKER-USER chain as present without filtering rules.
func netDockerUserDefault(fw *facts.Firewall) *facts.Firewall {
	fw.DockerUser = "default"
	return fw
}

func netSock(proto, addr string, port int, procs ...string) facts.Listener {
	return facts.Listener{Proto: proto, Address: addr, Port: port, Processes: procs}
}

func netUFW(def string, rules ...facts.UFWRule) *facts.Firewall {
	return &facts.Firewall{UFW: &facts.UFW{Installed: true, Source: "live", Status: "active", DefaultIncoming: def, IPv6: "yes", RulesKnown: true, Rules: rules}}
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
	rs := netRun(t, "NET-004", Input{Facts: &facts.Facts{Listeners: l, Docker: netPublish(6379), Firewall: netDockerUserDefault(netUFW("deny", netSSHAnywhere))}})
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
	rs = netRun(t, "NET-004", Input{Facts: &facts.Facts{Listeners: l, Docker: netPublish(6379), Firewall: fw}})
	for _, r := range rs {
		if r.Subject == "port:tcp/6379" && r.Level != Unknown {
			t.Errorf("DOCKER-USER rules that cannot be read stay unknown: %s %s", r.Level, r.Message)
		}
	}
	// Without the Docker API the container port is unknown: with nothing
	// filtering forwarded traffic the port is open anyway, with DOCKER-USER
	// rules it stays unknown.
	rs = netRun(t, "NET-004", Input{Facts: &facts.Facts{Listeners: l, Firewall: netDockerUserDefault(netUFW("deny"))}})
	for _, r := range rs {
		if r.Subject == "port:tcp/6379" && r.Level != Warn {
			t.Errorf("published port without Docker API, nothing filters: %s %s", r.Level, r.Message)
		}
	}
	rs = netRun(t, "NET-004", Input{Facts: &facts.Facts{Listeners: l, Firewall: fw}})
	for _, r := range rs {
		if r.Subject == "port:tcp/6379" && r.Level != Unknown {
			t.Errorf("published port without Docker API, DOCKER-USER filtered: %s %s", r.Level, r.Message)
		}
	}
	netCases(t, "NET-004", []netCase{
		{"no facts", &facts.Facts{}, "", Unknown},
		{"no sockets", &facts.Facts{Listeners: &facts.Listeners{Sockets: []facts.Listener{}}}, "", Info},
	})
}

// TestExposureContainerPortWithoutProcessNames: under the Landlock sandbox
// ss names no process, so docker-proxy cannot be seen. A wildcard socket on
// a port a container publishes is still a published container port that
// UFW's input rules do not filter, not a socket UFW blocks (a false pass
// seen on an Ubuntu 24.04 runner).
func TestExposureContainerPortWithoutProcessNames(t *testing.T) {
	l := &facts.Listeners{Source: "ss", Sockets: []facts.Listener{netSock("tcp", "0.0.0.0", 8080)}}
	docker := &facts.Docker{Installed: true, API: "ok", Containers: []facts.DockerContainer{{
		Name: "sw-web", Running: true, Ports: []facts.DockerPort{{HostIP: "0.0.0.0", HostPort: 8080, ContainerPort: 8080, Proto: "tcp"}},
	}}}
	f := &facts.Facts{Listeners: l, Firewall: netDockerUserDefault(netUFW("deny", netSSHAnywhere)), Docker: docker}
	if r := netOne(t, "NET-004", f, ""); r.Level != Warn || !strings.Contains(r.Message, "published container port") {
		t.Errorf("container port without process names: %s (%s), want warn", r.Level, r.Message)
	}
	// Without the Docker API the socket is judged by UFW as before.
	f.Docker = &facts.Docker{Installed: true, API: "denied"}
	if r := netOne(t, "NET-004", f, ""); r.Level != Pass {
		t.Errorf("no Docker API: %s (%s), want pass", r.Level, r.Message)
	}
}

// TestExposureDockerdHoldsPublishedPort: Docker without the userland
// proxy (or on the nftables backend) names dockerd as the owner of a
// published port. With a container publishing it in the Docker facts it is
// a published container port, not a host socket UFW filters.
func TestExposureDockerdHoldsPublishedPort(t *testing.T) {
	l := &facts.Listeners{Source: "ss", ProcessesVisible: true, Sockets: []facts.Listener{netSock("tcp", "0.0.0.0", 8080, "dockerd")}}
	docker := &facts.Docker{Installed: true, API: "ok", Containers: []facts.DockerContainer{{
		Name: "sw-web", Running: true, Ports: []facts.DockerPort{{HostIP: "0.0.0.0", HostPort: 8080, ContainerPort: 8080, Proto: "tcp"}},
	}}}
	f := &facts.Facts{Listeners: l, Firewall: netDockerUserDefault(netUFW("deny", netSSHAnywhere)), Docker: docker}
	if r := netOne(t, "NET-004", f, ""); r.Level != Warn || !strings.Contains(r.Message, "published container port") {
		t.Errorf("dockerd holds a published port: %s (%s), want warn", r.Level, r.Message)
	}
	// No container publishes it: a host socket, judged by UFW.
	f.Docker = &facts.Docker{Installed: true, API: "ok"}
	if r := netOne(t, "NET-004", f, ""); r.Level != Pass {
		t.Errorf("dockerd with nothing published: %s (%s), want pass", r.Level, r.Message)
	}
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
		{"loaded, docker publishes without docker-proxy", &facts.Facts{Firewall: loaded(), Docker: &facts.Docker{Installed: true, API: "ok",
			Containers: []facts.DockerContainer{{Name: "web", Ports: []facts.DockerPort{{HostIP: "0.0.0.0", HostPort: 8080, ContainerPort: 80, Proto: "tcp"}}}}}}, "", Warn},
		{"loaded, docker publishes on loopback only", &facts.Facts{Firewall: loaded(), Docker: &facts.Docker{Installed: true, API: "ok",
			Containers: []facts.DockerContainer{{Name: "web", Ports: []facts.DockerPort{{HostIP: "127.0.0.1", HostPort: 8080, ContainerPort: 80}}}}}}, "", Pass},
		{"loaded, docker denied", &facts.Facts{Firewall: loaded(), Docker: &facts.Docker{Installed: true, API: "denied"}}, "", Unknown},
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

// TestExposureUFWOverIptablesNFT is the real run: UFW on iptables-nft puts
// a drop policy input chain into the nft ruleset. Ports must be judged from
// UFW's rules, not reported as "nftables drops by default, but its port
// rules are not analysed".
func TestExposureUFWOverIptablesNFT(t *testing.T) {
	for _, src := range []string{"live", "status"} {
		fw := netUFW("deny", netSSHTailnet, netWebAnywhere)
		fw.UFW.Source = src
		fw.NFT = &facts.NFTables{Installed: true, Listed: true, UFWChains: true,
			Chains: []facts.NFTChain{{Family: "ip", Table: "filter", Name: "INPUT", Hook: "input", Policy: "drop"}}}
		f := &facts.Facts{Firewall: fw, Listeners: &facts.Listeners{Source: "ss", ProcessesVisible: true, Sockets: []facts.Listener{
			netSock("tcp", "0.0.0.0", 22, "sshd"), netSock("tcp", "0.0.0.0", 443, "caddy"),
		}}}
		rs := netRun(t, "NET-004", Input{Facts: f})
		if len(rs) != 2 {
			t.Fatalf("%s: %+v", src, rs)
		}
		for _, r := range rs {
			if r.Level == Unknown || strings.Contains(r.Message, "not analysed") {
				t.Errorf("%s: %s: %s %s", src, r.Subject, r.Level, r.Message)
			}
		}
		if r := netOne(t, "NET-001", f, profile.Unknown); r.Level != Pass || r.Evidence["mechanism"] != "ufw" {
			t.Errorf("%s: NET-001 %s %s", src, r.Level, r.Message)
		}
	}
	// Files only (not root): still unknown, never a pass.
	fw := netUFW("deny", netSSHTailnet)
	fw.UFW.Source = "files"
	f := &facts.Facts{Firewall: fw, Listeners: &facts.Listeners{Source: "ss", Sockets: []facts.Listener{netSock("tcp", "0.0.0.0", 22)}}}
	if r := netRun(t, "NET-004", Input{Facts: f})[0]; r.Level != Unknown {
		t.Errorf("files only: %s %s", r.Level, r.Message)
	}
}

func TestExposureUDPClientSockets(t *testing.T) {
	fw := netUFW("deny", netSSHTailnet)
	socks := []facts.Listener{
		netSock("udp", "0.0.0.0", 41641, "tailscaled"),
		netSock("udp", "::", 41641, "tailscaled"),
		netSock("udp", "0.0.0.0", 52113, "tailscaled"),
		netSock("udp", "0.0.0.0", 48211, "cloudflared"),
		netSock("udp", "0.0.0.0", 51820),                // no process name: unknown owner
		netSock("udp", "0.0.0.0", 40000, "cloudflared"), // shared with a real service
		netSock("udp", "0.0.0.0", 40000, "dnsmasq"),
	}
	run := func(visible bool, fw *facts.Firewall) map[string]Result {
		f := &facts.Facts{Firewall: fw, Listeners: &facts.Listeners{Source: "ss", ProcessesVisible: visible, Sockets: socks}}
		out := map[string]Result{}
		for _, r := range netRun(t, "NET-004", Input{Facts: f}) {
			out[r.Subject] = r
		}
		return out
	}
	// UFW denies by default and allows none of them: closed, a pass.
	for subj, r := range run(true, fw) {
		if r.Level != Pass {
			t.Errorf("deny default: %s: %s %s", subj, r.Level, r.Message)
		}
	}
	// The firewall could not be judged: client sockets get a reason, the
	// rest stay unknown.
	unread := &facts.Firewall{UFW: &facts.UFW{Installed: true, Source: "files", Status: "active"},
		NFT: &facts.NFTables{Installed: true}}
	got := run(true, unread)
	for subj, want := range map[string]Level{
		"port:udp/41641": Info, "port:udp/52113": Info, "port:udp/48211": Info,
		"port:udp/51820": Unknown, "port:udp/40000": Unknown,
	} {
		if got[subj].Level != want {
			t.Errorf("%s: got %s %q, want %s", subj, got[subj].Level, got[subj].Message, want)
		}
	}
	if !strings.Contains(got["port:udp/41641"].Message, "WireGuard") {
		t.Errorf("41641: %s", got["port:udp/41641"].Message)
	}
	// No firewall at all: the real listener warns, the client sockets stay info.
	open := &facts.Firewall{UFW: &facts.UFW{Installed: true, Source: "live", Status: "inactive"}}
	got = run(true, open)
	if got["port:udp/40000"].Level != Warn || got["port:udp/48211"].Level != Info {
		t.Errorf("no firewall: 40000 %s, 48211 %s", got["port:udp/40000"].Level, got["port:udp/48211"].Level)
	}
	// Firewall unknown and names not visible: unknown, never hidden.
	got = run(false, unread)
	if got["port:udp/48211"].Level != Unknown {
		t.Errorf("not root: %s", got["port:udp/48211"].Level)
	}
}
