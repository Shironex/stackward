package checks

import (
	"testing"

	"github.com/Shironex/stackward/internal/facts"
	"github.com/Shironex/stackward/internal/profile"
)

func cfTunnel(n int) *facts.Cloudflared {
	c := &facts.Cloudflared{Installed: true, ProcessesRead: true, ProcessesVisible: true}
	for range n {
		c.Connectors = append(c.Connectors, facts.CloudflaredConnector{Container: true, ArgsRead: true, Mode: "named"})
	}
	return c
}

var (
	cfAbsent = &facts.Cloudflared{ProcessesRead: true, ProcessesVisible: true}
	cfHidden = &facts.Cloudflared{ProcessesRead: true}
)

func TestCF001(t *testing.T) {
	netCases(t, "CF-001", []netCase{
		{"no facts", &facts.Facts{}, "", Unknown},
		{"present", &facts.Facts{Cloudflared: cfTunnel(1)}, "", Info},
		{"absent", &facts.Facts{Cloudflared: cfAbsent}, "", Info},
		{"hidden", &facts.Facts{Cloudflared: cfHidden}, "", Unknown},
	})
}

func TestCF002(t *testing.T) {
	failedUnit := cfTunnel(0)
	failedUnit.Unit = &facts.ServiceUnit{Name: "cloudflared.service", LoadState: "loaded", ActiveState: "failed", UnitFileState: "enabled"}
	activeUnitHidden := &facts.Cloudflared{Installed: true, ProcessesRead: true,
		Unit: &facts.ServiceUnit{Name: "cloudflared.service", LoadState: "loaded", ActiveState: "active"}}
	netCases(t, "CF-002", []netCase{
		{"no facts", &facts.Facts{}, "", Unknown},
		{"two", &facts.Facts{Cloudflared: cfTunnel(2)}, "", Pass},
		{"one", &facts.Facts{Cloudflared: cfTunnel(1)}, "", Warn},
		{"enabled unit failed", &facts.Facts{Cloudflared: failedUnit}, "", Fail},
		{"tunnel profile, none", &facts.Facts{Cloudflared: cfAbsent}, profile.Tunnel, Fail},
		{"no tunnel", &facts.Facts{Cloudflared: cfAbsent}, "", Skip},
		{"hidden", &facts.Facts{Cloudflared: cfHidden}, "", Unknown},
		{"unit active, processes hidden", &facts.Facts{Cloudflared: activeUnitHidden}, "", Unknown},
	})
}

func TestCF003(t *testing.T) {
	l := func(socks ...facts.Listener) *facts.Listeners { return &facts.Listeners{Sockets: socks} }
	loopback := l(netSock("tcp", "127.0.0.1", 443, "docker-proxy"), netSock("tcp", "127.0.0.1", 80, "docker-proxy"))
	published := l(netSock("tcp", "0.0.0.0", 443, "docker-proxy"))
	nginx := l(netSock("tcp", "0.0.0.0", 443, "nginx"))
	filtered := netUFW("deny")
	filtered.DockerUser = "filtered"
	netCases(t, "CF-003", []netCase{
		{"no facts", &facts.Facts{}, "", Unknown},
		{"no tunnel", &facts.Facts{Cloudflared: cfAbsent, Listeners: published}, "", Skip},
		{"tunnel unknown", &facts.Facts{Cloudflared: cfHidden, Listeners: published}, "", Unknown},
		{"listeners missing", &facts.Facts{Cloudflared: cfTunnel(2)}, "", Unknown},
		{"loopback publish", &facts.Facts{Cloudflared: cfTunnel(2), Listeners: loopback, Firewall: netUFW("deny")}, "", Pass},
		{"wildcard publish under ufw", &facts.Facts{Cloudflared: cfTunnel(2), Listeners: published, Firewall: netUFW("deny")}, "", Fail},
		{"wildcard publish, DOCKER-USER filtered", &facts.Facts{Cloudflared: cfTunnel(2), Listeners: published, Firewall: filtered}, "", Unknown},
		{"host proxy blocked by ufw", &facts.Facts{Cloudflared: cfTunnel(2), Listeners: nginx, Firewall: netUFW("deny")}, "", Pass},
		{"host proxy allowed by ufw", &facts.Facts{Cloudflared: cfTunnel(2), Listeners: nginx, Firewall: netUFW("deny", netWebAnywhere)}, "", Fail},
		{"host proxy, firewall unknown", &facts.Facts{Cloudflared: cfTunnel(2), Listeners: nginx}, "", Unknown},
	})
}

func TestCF004(t *testing.T) {
	token := cfTunnel(1)
	token.Connectors[0].TokenInArgs, token.Connectors[0].Mode = true, "token"
	unitToken := cfTunnel(0)
	unitToken.Unit = &facts.ServiceUnit{Name: "cloudflared.service", LoadState: "loaded", ActiveState: "inactive"}
	unitToken.UnitTokenInArgs = true
	unread := cfTunnel(1)
	unread.Connectors[0].ArgsRead = false
	netCases(t, "CF-004", []netCase{
		{"no facts", &facts.Facts{}, "", Unknown},
		{"not installed", &facts.Facts{Cloudflared: cfAbsent}, "", Skip},
		{"token in args", &facts.Facts{Cloudflared: token}, "", Warn},
		{"token in unit", &facts.Facts{Cloudflared: unitToken}, "", Warn},
		{"named", &facts.Facts{Cloudflared: cfTunnel(2)}, "", Pass},
		{"args unread", &facts.Facts{Cloudflared: unread}, "", Unknown},
	})
}

func TestCF005(t *testing.T) {
	netCases(t, "CF-005", []netCase{
		{"no facts", &facts.Facts{}, "", Unknown},
		{"no tunnel", &facts.Facts{Cloudflared: cfAbsent}, "", Skip},
		{"tunnel", &facts.Facts{Cloudflared: cfTunnel(1)}, "", Unknown},
	})
}

// cfDocker is Docker facts with n running cloudflared containers and one
// stopped one.
func cfDocker(api string, n int) *facts.Docker {
	d := &facts.Docker{Installed: true, API: api}
	for range n {
		d.Containers = append(d.Containers, facts.DockerContainer{Name: "tunnel", Image: "cloudflare/cloudflared:2026.10.0", Running: true})
	}
	d.Containers = append(d.Containers, facts.DockerContainer{Name: "old-tunnel", Image: "cloudflare/cloudflared:latest"})
	return d
}

func TestCFCountsDockerContainers(t *testing.T) {
	netCases(t, "CF-001", []netCase{
		{"hidden processes, container seen", &facts.Facts{Cloudflared: cfHidden, Docker: cfDocker("ok", 1)}, "", Info},
		{"hidden processes, docker denied", &facts.Facts{Cloudflared: cfHidden, Docker: cfDocker("denied", 1)}, "", Unknown},
	})
	netCases(t, "CF-002", []netCase{
		{"hidden processes, two containers", &facts.Facts{Cloudflared: cfHidden, Docker: cfDocker("ok", 2)}, "", Pass},
		{"hidden processes, one container", &facts.Facts{Cloudflared: cfHidden, Docker: cfDocker("ok", 1)}, "", Warn},
		{"scan and docker see the same two", &facts.Facts{Cloudflared: cfTunnel(2), Docker: cfDocker("ok", 2)}, "", Pass},
		{"only stopped containers, tunnel profile", &facts.Facts{Cloudflared: cfAbsent, Docker: cfDocker("ok", 0)}, profile.Tunnel, Fail},
	})
	r := netOne(t, "CF-002", &facts.Facts{Cloudflared: cfTunnel(1), Docker: cfDocker("ok", 2)}, "")
	if r.Level != Pass || r.Evidence["connectors"] != 2 || r.Evidence["docker_containers"] != 2 {
		t.Errorf("the larger container count wins, never the sum: %s %v", r.Level, r.Evidence)
	}
}
