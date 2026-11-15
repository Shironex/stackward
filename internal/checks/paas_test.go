package checks

import (
	"strings"
	"testing"

	"github.com/Shironex/stackward/internal/facts"
	"github.com/Shironex/stackward/internal/profile"
)

// withPaaSViews swaps the hooks reading other collectors' facts for the test.
func withPaaSViews(t *testing.T, cs []paasContainer, ls []paasListener, filter paasFilter) {
	t.Helper()
	oc, ol, of := readPaaSContainers, readPaaSListeners, readPaaSFilter
	t.Cleanup(func() { readPaaSContainers, readPaaSListeners, readPaaSFilter = oc, ol, of })
	readPaaSContainers = func(*facts.Docker) ([]paasContainer, bool) { return cs, cs != nil }
	readPaaSListeners = func(*facts.Listeners) ([]paasListener, bool) { return ls, ls != nil }
	readPaaSFilter = func(*facts.Firewall, string, int, bool) paasFilter { return filter }
}

func paasCoolifyFacts() *facts.Facts {
	return &facts.Facts{
		PaaS: &facts.PaaS{Platforms: []facts.Platform{{
			Name: facts.PlatformCoolify, Role: facts.RolePanel, DataRoot: facts.CoolifyRoot,
			Evidence: []string{"path:/data/coolify"},
		}}},
		Docker:    &facts.Docker{},
		Listeners: &facts.Listeners{},
		Firewall:  &facts.Firewall{},
	}
}

func paasLevels(rs []Result) string {
	var out []string
	for _, r := range rs {
		out = append(out, r.Subject+"="+string(r.Level))
	}
	return strings.Join(out, " ")
}

func TestPaaSChecksUnknownWithoutFacts(t *testing.T) {
	empty := &facts.Facts{}
	for _, run := range []func(Input) []Result{checkPaaSDetected, checkPaaSProxyExposure, checkPaaSPanelPorts,
		checkPaaSPublicDatabase, checkPaaSSwarmPorts} {
		if got := paasLevels(run(Input{Facts: empty})); got != "=unknown" {
			t.Errorf("empty facts: %s", got)
		}
	}
	// PaaS found but container and listener facts missing or unreadable.
	f := paasCoolifyFacts()
	f.Docker, f.Listeners = nil, nil
	for _, run := range []func(Input) []Result{checkPaaSProxyExposure, checkPaaSPanelPorts, checkPaaSPublicDatabase} {
		rs := run(Input{Facts: f})
		if paasLevels(rs) != "=unknown" || !strings.Contains(rs[0].Message, "did not run") {
			t.Errorf("missing docker or listeners: %s %q", paasLevels(rs), rs[0].Message)
		}
	}
	f = paasCoolifyFacts() // present but this build cannot map them (default hooks)
	for _, run := range []func(Input) []Result{checkPaaSProxyExposure, checkPaaSPanelPorts, checkPaaSPublicDatabase} {
		rs := run(Input{Facts: f})
		if paasLevels(rs) != "=unknown" || !strings.Contains(rs[0].Message, "cannot read") {
			t.Errorf("unmapped docker or listeners: %s %q", paasLevels(rs), rs[0].Message)
		}
	}
}

func TestPaaSChecksSkipWithoutPlatform(t *testing.T) {
	withPaaSViews(t, []paasContainer{}, []paasListener{}, paasFilterUnknown)
	f := &facts.Facts{PaaS: &facts.PaaS{Platforms: []facts.Platform{}}, Docker: &facts.Docker{}, Listeners: &facts.Listeners{}}
	for _, run := range []func(Input) []Result{checkPaaSDetected, checkPaaSProxyExposure, checkPaaSPanelPorts,
		checkPaaSPublicDatabase, checkPaaSSwarmPorts} {
		if got := paasLevels(run(Input{Facts: f})); got != "=skip" {
			t.Errorf("no platform: %s", got)
		}
	}
}

func TestPaaSDetectedRefinedByContainers(t *testing.T) {
	withPaaSViews(t, []paasContainer{
		{Name: "coolify", Image: "ghcr.io/coollabsio/coolify:4.0.0-beta.400"},
		{Name: "dokploy.1.abc", Image: "dokploy/dokploy:v0.20.0", Labels: map[string]string{"com.docker.swarm.service.name": "dokploy"}},
	}, nil, paasFilterUnknown)
	f := paasCoolifyFacts()
	f.PaaS.Platforms[0].Role = facts.RoleUnknown
	rs := checkPaaSDetected(Input{Facts: f})
	if paasLevels(rs) != "file:/data/coolify=info file:/etc/dokploy=info" {
		t.Fatalf("paasLevels = %s", paasLevels(rs))
	}
	if rs[0].Evidence["role"] != facts.RolePanel || rs[0].Evidence["version"] != "4.0.0-beta.400" {
		t.Errorf("coolify evidence = %v", rs[0].Evidence)
	}
	if rs[1].Evidence["version"] != "v0.20.0" || rs[1].Evidence["role"] != facts.RolePanel {
		t.Errorf("dokploy evidence = %v", rs[1].Evidence)
	}
}

func TestPaaSProxyExposure(t *testing.T) {
	proxy := func(ports ...paasPort) []paasContainer {
		return []paasContainer{{Name: "coolify-proxy", Image: "traefik:v3.1", Ports: ports}, {Name: "app", Image: "nginx"}}
	}
	web := []paasPort{{HostIP: "0.0.0.0", HostPort: 80, ContainerPort: 80, Proto: "tcp"}, {HostIP: "::", HostPort: 443, ContainerPort: 443, Proto: "tcp"}}
	dash := paasPort{HostIP: "0.0.0.0", HostPort: 8080, ContainerPort: 8080, Proto: "tcp"}
	loop := []paasPort{{HostIP: "127.0.0.1", HostPort: 443, ContainerPort: 443, Proto: "tcp"}}
	cases := []struct {
		name  string
		ports []paasPort
		prof  profile.Name
		want  Level
	}{
		{"loopback on tunnel", loop, profile.Tunnel, Pass},
		{"wildcard on tunnel", web, profile.Tunnel, Fail},
		{"wildcard on tailnet-only", web, profile.TailnetOnly, Fail},
		{"web on public-web", web, profile.PublicWeb, Pass},
		{"dashboard on public-web", append(append([]paasPort{}, web...), dash), profile.PublicWeb, Warn},
		{"web with unknown profile", web, profile.Unknown, Unknown},
		{"tailnet bind on tunnel", []paasPort{{HostIP: "100.100.1.2", HostPort: 443, ContainerPort: 443}}, profile.Tunnel, Pass},
	}
	for _, c := range cases {
		withPaaSViews(t, proxy(c.ports...), nil, paasFilterUnknown)
		rs := checkPaaSProxyExposure(Input{Facts: paasCoolifyFacts(), Profile: c.prof})
		if len(rs) != 1 || rs[0].Level != c.want || rs[0].Subject != "container:coolify-proxy" {
			t.Errorf("%s: %s %q", c.name, paasLevels(rs), rs[0].Message)
		}
	}
	withPaaSViews(t, []paasContainer{{Name: "app"}}, nil, paasFilterUnknown)
	if got := paasLevels(checkPaaSProxyExposure(Input{Facts: paasCoolifyFacts()})); got != "=skip" {
		t.Errorf("no proxy: %s", got)
	}
}

func TestPaaSPanelPorts(t *testing.T) {
	ls := []paasListener{
		{Proto: "tcp", Addr: "0.0.0.0", Port: 8000, Process: "docker-proxy"},
		{Proto: "tcp6", Addr: "::", Port: 8000, Process: "docker-proxy"},
		{Proto: "tcp", Addr: "127.0.0.1", Port: 6001},
		{Proto: "tcp", Addr: "0.0.0.0", Port: 3000}, // not Dokploy here: ignored
	}
	for _, c := range []struct {
		filter paasFilter
		want   string
	}{
		{paasFilterNone, "port:tcp/6001=pass port:tcp/6002=pass port:tcp/8000=fail"},
		{paasFilterApplied, "port:tcp/6001=pass port:tcp/6002=pass port:tcp/8000=warn"},
		{paasFilterUnknown, "port:tcp/6001=pass port:tcp/6002=pass port:tcp/8000=warn"},
	} {
		withPaaSViews(t, []paasContainer{}, ls, c.filter)
		rs := EvaluateChecks([]Check{{ID: "PAAS-003", Run: checkPaaSPanelPorts}}, Input{Facts: paasCoolifyFacts()})
		if got := paasLevels(rs); got != c.want {
			t.Errorf("filter %s: %s", c.filter, got)
		}
	}
	// A managed server runs no panel.
	f := paasCoolifyFacts()
	f.PaaS.Platforms[0].Role = facts.RoleManaged
	withPaaSViews(t, []paasContainer{}, ls, paasFilterNone)
	if got := paasLevels(checkPaaSPanelPorts(Input{Facts: f})); got != "=skip" {
		t.Errorf("managed: %s", got)
	}
}

func TestPaaSPublicDatabase(t *testing.T) {
	coolifyLabels := map[string]string{"coolify.managed": "true", "coolify.type": "database"}
	cases := []struct {
		name string
		cs   []paasContainer
		want string
	}{
		{"public postgres", []paasContainer{{Name: "db1", Image: "postgres:16-alpine", Labels: coolifyLabels,
			Ports: []paasPort{{HostIP: "0.0.0.0", HostPort: 5432, ContainerPort: 5432}}}}, "container:db1=fail"},
		{"loopback redis", []paasContainer{{Name: "r1", Image: "docker.io/library/redis:7", Labels: coolifyLabels,
			Ports: []paasPort{{HostIP: "127.0.0.1", HostPort: 6379, ContainerPort: 6379}}}}, "host=pass"},
		{"not platform owned", []paasContainer{{Name: "mine", Image: "mysql:8",
			Ports: []paasPort{{HostIP: "0.0.0.0", HostPort: 3306, ContainerPort: 3306}}}}, "host=pass"},
		{"no databases", []paasContainer{{Name: "web", Image: "nginx", Labels: coolifyLabels}}, "host=pass"},
	}
	for _, c := range cases {
		withPaaSViews(t, c.cs, nil, paasFilterUnknown)
		rs := EvaluateChecks([]Check{{ID: "PAAS-004", Run: checkPaaSPublicDatabase}}, Input{Facts: paasCoolifyFacts()})
		if got := paasLevels(rs); got != c.want {
			t.Errorf("%s: %s", c.name, got)
		}
	}
}

func paasDokployFacts() *facts.Facts {
	return &facts.Facts{
		PaaS:      &facts.PaaS{Platforms: []facts.Platform{{Name: facts.PlatformDokploy, Role: facts.RoleUnknown, DataRoot: facts.DokployRoot}}},
		Docker:    &facts.Docker{},
		Listeners: &facts.Listeners{},
	}
}

func TestPaaSSwarmPorts(t *testing.T) {
	ls := []paasListener{
		{Proto: "tcp", Addr: "*", Port: 2377, Process: "dockerd"},
		{Proto: "tcp", Addr: "10.0.0.5", Port: 7946, Process: "dockerd"},
		{Proto: "udp", Addr: "0.0.0.0", Port: 4789},
	}
	for _, c := range []struct {
		filter paasFilter
		want   string
	}{
		{paasFilterNone, "port:tcp/2377=fail port:tcp/7946=pass port:udp/4789=fail port:udp/7946=pass"},
		{paasFilterApplied, "port:tcp/2377=pass port:tcp/7946=pass port:udp/4789=pass port:udp/7946=pass"},
		{paasFilterUnknown, "port:tcp/2377=warn port:tcp/7946=pass port:udp/4789=warn port:udp/7946=pass"},
	} {
		withPaaSViews(t, nil, ls, c.filter)
		rs := EvaluateChecks([]Check{{ID: "PAAS-008", Run: checkPaaSSwarmPorts}}, Input{Facts: paasDokployFacts()})
		if got := paasLevels(rs); got != c.want {
			t.Errorf("filter %s: %s", c.filter, got)
		}
	}
	withPaaSViews(t, nil, ls, paasFilterNone)
	if got := paasLevels(checkPaaSSwarmPorts(Input{Facts: paasCoolifyFacts()})); got != "=skip" {
		t.Errorf("coolify only: %s", got)
	}
}

func TestPaaSHelpers(t *testing.T) {
	for addr, want := range map[string]string{
		"0.0.0.0": paasAddrWildcard, "[::]": paasAddrWildcard, "*": paasAddrWildcard, "127.0.0.53": paasAddrLoopback, "::1": paasAddrLoopback,
		"100.64.0.1": paasAddrTailnet, "fd7a:115c:a1e0::1": paasAddrTailnet, "10.1.2.3": paasAddrPrivate, "fe80::1%eth0": paasAddrPrivate,
		"203.0.113.10": paasAddrPublic, "2001:db8::1": paasAddrPublic, "::ffff:127.0.0.1": paasAddrLoopback, "garbage": paasAddrPublic,
	} {
		if got := paasAddrClass(addr); got != want {
			t.Errorf("paasAddrClass(%q) = %s, want %s", addr, got, want)
		}
	}
	for image, want := range map[string][2]string{
		"ghcr.io/coollabsio/coolify:4.0.0":    {"coollabsio/coolify", "4.0.0"},
		"localhost:5000/app":                  {"app", ""},
		"postgres:16@sha256:0000":             {"postgres", "16"},
		"registry.example.com:5000/a/b:1.2.3": {"a/b", "1.2.3"},
	} {
		if r, tag := paasSplitImage(image); r != want[0] || tag != want[1] {
			t.Errorf("paasSplitImage(%q) = %q %q", image, r, tag)
		}
	}
	for image, want := range map[string]bool{"postgres:16": true, "bitnami/redis:7": true, "clickhouse/clickhouse-server:24": true,
		"postgrest/postgrest": false, "nginx": false} {
		if paasIsDBImage(image) != want {
			t.Errorf("paasIsDBImage(%q) != %v", image, want)
		}
	}
}
