package checks

import (
	"reflect"
	"testing"

	"github.com/Shironex/stackward/internal/facts"
	"github.com/Shironex/stackward/internal/profile"
)

func TestExposedHostPorts(t *testing.T) {
	f := &facts.Facts{
		Docker: &facts.Docker{Installed: true, API: "ok"},
		Listeners: &facts.Listeners{ProcessesVisible: true, Sockets: []facts.Listener{
			{Proto: "tcp", Address: "0.0.0.0", Port: 22, Processes: []string{"sshd"}},
			{Proto: "tcp", Address: "::", Port: 22, Processes: []string{"sshd"}},
			{Proto: "tcp", Address: "0.0.0.0", Port: 8080, Processes: []string{"docker-proxy"}},
			{Proto: "tcp", Address: "127.0.0.1", Port: 5432, Processes: []string{"postgres"}},
			{Proto: "tcp", Address: "203.0.113.10", Port: 80, Processes: []string{"nginx"}},
			{Proto: "udp", Address: "0.0.0.0", Port: 68, Processes: []string{"systemd-networkd"}},
			{Proto: "udp", Address: "0.0.0.0", Port: 41641, Processes: []string{"tailscaled"}},
		}},
	}
	want := []HostPort{
		{Proto: "tcp", Port: 22, Processes: []string{"sshd"}},
		{Proto: "tcp", Port: 80, Processes: []string{"nginx"}},
	}
	if got := ExposedHostPorts(f); !reflect.DeepEqual(got, want) {
		t.Errorf("got %+v, want %+v", got, want)
	}
	if ExposedHostPorts(&facts.Facts{}) != nil {
		t.Error("no listener facts must give nil")
	}
}

func TestPublishedPortsFollowDKR001AndTheProfile(t *testing.T) {
	f := &facts.Facts{
		PaaS: &facts.PaaS{Platforms: []facts.Platform{{Name: facts.PlatformCoolify, Role: facts.RolePanel, DataRoot: facts.CoolifyRoot}}},
		Docker: &facts.Docker{Installed: true, API: "ok", Containers: []facts.DockerContainer{
			{Name: "proxy", Running: true, Ports: []facts.DockerPort{{HostIP: "0.0.0.0", HostPort: 443, ContainerPort: 443, Proto: "tcp"}}},
			{Name: "coolify", Running: true, Ports: []facts.DockerPort{{HostIP: "0.0.0.0", HostPort: 8000, ContainerPort: 8080, Proto: "tcp"}}},
			{Name: "db", Running: true, Ports: []facts.DockerPort{{HostIP: "127.0.0.1", HostPort: 5432, ContainerPort: 5432, Proto: "tcp"}}},
		}},
		Listeners: &facts.Listeners{},
		Firewall:  &facts.Firewall{DockerBackend: "iptables", DockerUser: "default", Iptables: &facts.Iptables{Listed: true, DockerUserRules: []string{"-A DOCKER-USER -j RETURN"}}},
	}
	got, ok := PublishedPorts(f, profile.PublicWeb)
	if !ok || len(got) != 2 {
		t.Fatalf("got %+v %v", got, ok)
	}
	if p := got[0]; p.Container != "proxy" || p.Open != "yes" || p.Filter != "none" || !p.Public || p.Panel {
		t.Errorf("proxy %+v", p)
	}
	if p := got[1]; p.Container != "coolify" || p.ContainerPort != 8080 || p.Public || !p.Panel || p.Label != "0.0.0.0:8000->8080/tcp" {
		t.Errorf("panel %+v", p)
	}
	tunnel, _ := PublishedPorts(f, profile.Tunnel)
	if tunnel[0].Public {
		t.Error("443 is not public by design behind a tunnel")
	}
	f.Docker.API = "denied"
	if _, ok := PublishedPorts(f, profile.PublicWeb); ok {
		t.Error("without the Docker API the bindings are unknown")
	}
}
