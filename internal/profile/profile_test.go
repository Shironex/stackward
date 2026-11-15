package profile

import (
	"testing"

	"github.com/Shironex/stackward/internal/facts"
)

func TestParse(t *testing.T) {
	for _, s := range []string{"", "auto"} {
		if n, set, err := Parse(s); n != Unknown || set || err != nil {
			t.Errorf("Parse(%q) = %v %v %v", s, n, set, err)
		}
	}
	for _, n := range All {
		if got, set, err := Parse(string(n)); got != n || !set || err != nil {
			t.Errorf("Parse(%q) = %v %v %v", n, got, set, err)
		}
	}
	if _, _, err := Parse("moat"); err == nil {
		t.Error("unknown profile accepted")
	}
}

type fakeTailnet struct{ running, known bool }

func (f fakeTailnet) TailnetRunning() (bool, bool) { return f.running, f.known }

type fakeTunnel struct{ present, known bool }

func (f fakeTunnel) TunnelPresent() (bool, bool) { return f.present, f.known }

func TestReporters(t *testing.T) {
	if r, k := tailnetOf(fakeTailnet{true, true}); !r || !k {
		t.Error("tailnet reporter ignored")
	}
	if _, k := tailnetOf(struct{}{}); k {
		t.Error("a type without the method must be unknown")
	}
	if p, k := tunnelOf(fakeTunnel{true, true}); !p || !k {
		t.Error("tunnel reporter ignored")
	}
	if _, k := Tailnet(&facts.Facts{Tailscale: &facts.Tailscale{Installed: true}}); k {
		t.Error("Tailscale installed with an unread state must be unknown")
	}
	if r, k := Tailnet(&facts.Facts{Tailscale: &facts.Tailscale{}}); r || !k {
		t.Error("Tailscale not installed must be a known no")
	}
	if p, k := TunnelState(&facts.Facts{Cloudflared: &facts.Cloudflared{Connectors: []facts.CloudflaredConnector{{}}}}); !p || !k {
		t.Error("a running connector must be a known yes")
	}
	if _, k := TunnelState(nil); k {
		t.Error("nil facts must be unknown")
	}
}

func sock(proto, addr string, port int, procs ...string) facts.Listener {
	return facts.Listener{Proto: proto, Address: addr, Port: port, Processes: procs}
}

func activeUFW(rules ...facts.UFWRule) *facts.Firewall {
	return &facts.Firewall{UFW: &facts.UFW{Installed: true, Source: "status", Status: "active", DefaultIncoming: "deny", RulesKnown: true, Rules: rules}}
}

func TestInfer(t *testing.T) {
	web := facts.UFWRule{Action: "allow", Direction: "in", Port: "80,443", Proto: "tcp"}
	tsAddr := []facts.InterfaceAddr{{Interface: "tailscale0", Address: "100.101.102.103", Prefix: 32}}
	cases := []struct {
		name    string
		f       *facts.Facts
		tailnet *fakeTailnet
		tunnel  *fakeTunnel
		want    Name
	}{
		{name: "no listeners", f: &facts.Facts{}, want: Unknown},
		{name: "nothing", f: &facts.Facts{Listeners: &facts.Listeners{Sockets: []facts.Listener{sock("tcp", "0.0.0.0", 22, "sshd")}}}, want: Unknown},
		{name: "public web, no firewall facts", f: &facts.Facts{Listeners: &facts.Listeners{Sockets: []facts.Listener{sock("tcp", "0.0.0.0", 443, "nginx")}}}, want: PublicWeb},
		{name: "web allowed by ufw", f: &facts.Facts{
			Listeners: &facts.Listeners{Sockets: []facts.Listener{sock("tcp", "::", 80, "nginx")}},
			Firewall:  activeUFW(web)}, want: PublicWeb},
		{name: "web blocked by ufw", f: &facts.Facts{
			Listeners: &facts.Listeners{Sockets: []facts.Listener{sock("tcp", "0.0.0.0", 443, "nginx")}},
			Firewall:  activeUFW()}, want: Unknown},
		{name: "docker-proxy skips ufw", f: &facts.Facts{
			Listeners: &facts.Listeners{Sockets: []facts.Listener{sock("tcp", "0.0.0.0", 443, "docker-proxy")}},
			Firewall:  activeUFW()}, want: PublicWeb},
		{name: "loopback proxy and cloudflared", f: &facts.Facts{Listeners: &facts.Listeners{Sockets: []facts.Listener{
			sock("tcp", "127.0.0.1", 443, "docker-proxy"), sock("tcp", "127.0.0.1", 20241, "cloudflared")}}}, want: Tunnel},
		{name: "tunnel from facts", f: &facts.Facts{Listeners: &facts.Listeners{}}, tunnel: &fakeTunnel{true, true}, want: Tunnel},
		{name: "tunnel facts override process", f: &facts.Facts{Listeners: &facts.Listeners{Sockets: []facts.Listener{
			sock("tcp", "127.0.0.1", 20241, "cloudflared")}}}, tunnel: &fakeTunnel{false, true}, want: Unknown},
		{name: "mixed", f: &facts.Facts{Listeners: &facts.Listeners{Sockets: []facts.Listener{
			sock("tcp", "0.0.0.0", 443, "docker-proxy"), sock("tcp", "127.0.0.1", 20241, "cloudflared")}}}, want: Mixed},
		{name: "tailnet address", f: &facts.Facts{Listeners: &facts.Listeners{Addresses: tsAddr}}, want: TailnetOnly},
		{name: "tailscaled socket", f: &facts.Facts{Listeners: &facts.Listeners{Sockets: []facts.Listener{
			sock("udp", "0.0.0.0", 41641, "tailscaled")}}}, want: TailnetOnly},
		{name: "tailnet facts say logged out", f: &facts.Facts{Listeners: &facts.Listeners{Addresses: tsAddr}}, tailnet: &fakeTailnet{false, true}, want: Unknown},
		{name: "tunnel and tailnet", f: &facts.Facts{Listeners: &facts.Listeners{Addresses: tsAddr}}, tunnel: &fakeTunnel{true, true}, want: Tunnel},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			tailnetState = func(*facts.Facts) (bool, bool) {
				if c.tailnet == nil {
					return false, false
				}
				return c.tailnet.running, c.tailnet.known
			}
			tunnelState = func(*facts.Facts) (bool, bool) {
				if c.tunnel == nil {
					return false, false
				}
				return c.tunnel.present, c.tunnel.known
			}
			defer func() { tailnetState, tunnelState = Tailnet, TunnelState }()
			if got := Infer(c.f); got != c.want {
				t.Errorf("Infer = %s, want %s", got, c.want)
			}
		})
	}
}

func TestMixedIsNotAFlagValue(t *testing.T) {
	if _, _, err := Parse(string(Mixed)); err == nil {
		t.Error("mixed is inferred only")
	}
}

// TestInferWithAccessFacts runs Infer over the real Tailscale and
// Cloudflared facts types (no seams), so profile inference is proven to
// read them.
func TestInferWithAccessFacts(t *testing.T) {
	tsAddr := []facts.InterfaceAddr{{Interface: "tailscale0", Address: "100.101.102.103", Prefix: 32}}
	running := &facts.Tailscale{Installed: true, StatusRead: true, BackendState: "Running"}
	loggedOut := &facts.Tailscale{Installed: true, StatusRead: true, BackendState: "NeedsLogin"}
	unread := &facts.Tailscale{Installed: true}
	connector := &facts.Cloudflared{Installed: true, ProcessesRead: true, ProcessesVisible: true,
		Connectors: []facts.CloudflaredConnector{{Container: true, ArgsRead: true, Mode: "named"}}}
	noTunnel := &facts.Cloudflared{ProcessesRead: true, ProcessesVisible: true}
	cloudflaredSock := []facts.Listener{sock("tcp", "127.0.0.1", 20241, "cloudflared")}
	panel := &facts.PaaS{Platforms: []facts.Platform{{Name: facts.PlatformCoolify, Role: facts.RolePanel, DataRoot: facts.CoolifyRoot}}}
	managed := &facts.PaaS{Platforms: []facts.Platform{{Name: facts.PlatformCoolify, Role: facts.RoleManaged, DataRoot: facts.CoolifyRoot}}}
	cases := []struct {
		name string
		f    *facts.Facts
		want Name
	}{
		{"tailnet address, no tailscale facts", &facts.Facts{Listeners: &facts.Listeners{Addresses: tsAddr}}, TailnetOnly},
		{"tailnet address, node running", &facts.Facts{Listeners: &facts.Listeners{Addresses: tsAddr}, Tailscale: running}, TailnetOnly},
		{"tailnet address, node logged out", &facts.Facts{Listeners: &facts.Listeners{Addresses: tsAddr}, Tailscale: loggedOut}, Unknown},
		{"tailnet address, state unread", &facts.Facts{Listeners: &facts.Listeners{Addresses: tsAddr}, Tailscale: unread}, TailnetOnly},
		{"no listener hint, node running", &facts.Facts{Listeners: &facts.Listeners{}, Tailscale: running}, TailnetOnly},
		{"containerised connector, no socket", &facts.Facts{Listeners: &facts.Listeners{}, Cloudflared: connector}, Tunnel},
		{"cloudflared socket, collector saw none", &facts.Facts{Listeners: &facts.Listeners{Sockets: cloudflaredSock}, Cloudflared: noTunnel}, Unknown},
		{"hidden processes, cloudflared container in docker", &facts.Facts{Listeners: &facts.Listeners{}, Cloudflared: &facts.Cloudflared{ProcessesRead: true},
			Docker: &facts.Docker{Installed: true, API: "ok", Containers: []facts.DockerContainer{{Image: "docker.io/cloudflare/cloudflared:2026.10.0@sha256:00", Running: true}}}}, Tunnel},
		{"stopped cloudflared container", &facts.Facts{Listeners: &facts.Listeners{}, Cloudflared: noTunnel,
			Docker: &facts.Docker{Installed: true, API: "ok", Containers: []facts.DockerContainer{{Image: "cloudflare/cloudflared", Running: false}}}}, Unknown},
		{"connector beside public web", &facts.Facts{Listeners: &facts.Listeners{Sockets: []facts.Listener{sock("tcp", "0.0.0.0", 443, "docker-proxy")}}, Cloudflared: connector}, Mixed},
		// The real run: a Coolify panel host, its proxy public on 80/443,
		// cloudflared tunnels beside it.
		{"panel with public proxy and a tunnel", &facts.Facts{Listeners: &facts.Listeners{Sockets: []facts.Listener{
			sock("tcp", "0.0.0.0", 80, "docker-proxy"), sock("tcp", "0.0.0.0", 443, "docker-proxy")}}, Cloudflared: connector, PaaS: panel}, PaaSPanel},
		{"panel container with public proxy", &facts.Facts{Listeners: &facts.Listeners{Sockets: []facts.Listener{sock("tcp", "::", 443, "docker-proxy")}},
			Docker: &facts.Docker{Installed: true, API: "ok", Containers: []facts.DockerContainer{{Image: "ghcr.io/coollabsio/coolify:4.0.0", Running: true}}}}, PaaSPanel},
		{"panel behind the tunnel only", &facts.Facts{Listeners: &facts.Listeners{Sockets: []facts.Listener{sock("tcp", "127.0.0.1", 443, "docker-proxy")}}, Cloudflared: connector, PaaS: panel}, Tunnel},
		{"managed server is not a panel", &facts.Facts{Listeners: &facts.Listeners{Sockets: []facts.Listener{sock("tcp", "0.0.0.0", 443, "docker-proxy")}}, Cloudflared: connector, PaaS: managed}, Mixed},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := Infer(c.f); got != c.want {
				t.Errorf("Infer = %s, want %s", got, c.want)
			}
		})
	}
}
