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
		Docker: &facts.Docker{Installed: true, API: "denied",
			APIReason: "cannot open /var/run/docker.sock: permission denied (run with sudo, or as a member of the docker group)"},
		Listeners: &facts.Listeners{},
		Firewall:  &facts.Firewall{},
	}
}

// paasUnfilteredFirewall is a host whose published ports no firewall
// filters: the iptables backend and no rules in DOCKER-USER.
func paasUnfilteredFirewall() *facts.Firewall {
	return &facts.Firewall{DockerBackend: "iptables", DockerUser: "absent"}
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
	f = paasCoolifyFacts() // Docker installed but the socket is denied
	rs := checkPaaSPublicDatabase(Input{Facts: f})
	if paasLevels(rs) != "=unknown" || !strings.Contains(rs[0].Message, "permission denied") {
		t.Errorf("denied docker: %s %q", paasLevels(rs), rs[0].Message)
	}
}

func TestPaaSProxyFromListeners(t *testing.T) {
	// Default hooks: Docker unmapped, listeners mapped from the real facts.
	f := paasCoolifyFacts()
	f.Firewall = paasUnfilteredFirewall()
	f.Listeners = &facts.Listeners{Sockets: []facts.Listener{
		{Proto: "tcp", Address: "0.0.0.0", Port: 443, Processes: []string{"docker-proxy"}},
		{Proto: "tcp", Address: "::", Port: 80, Processes: []string{"docker-proxy"}},
		{Proto: "tcp", Address: "0.0.0.0", Port: 8080},
	}}
	for prof, want := range map[profile.Name]Level{
		profile.Tunnel: Fail, profile.PublicWeb: Pass, profile.Mixed: Warn, profile.Unknown: Unknown,
	} {
		rs := checkPaaSProxyExposure(Input{Facts: f, Profile: prof})
		if len(rs) != 1 || rs[0].Level != want || rs[0].Subject != "host" {
			t.Errorf("%s: %s %q", prof, paasLevels(rs), rs[0].Message)
		}
	}
	f.Listeners = &facts.Listeners{Sockets: []facts.Listener{{Proto: "tcp", Address: "127.0.0.1", Port: 443}}}
	if rs := checkPaaSProxyExposure(Input{Facts: f, Profile: profile.Tunnel}); rs[0].Level != Pass {
		t.Errorf("loopback: %s", paasLevels(rs))
	}
	f.Listeners = &facts.Listeners{Sockets: []facts.Listener{}}
	if rs := checkPaaSProxyExposure(Input{Facts: f, Profile: profile.Tunnel}); rs[0].Level != Pass {
		t.Errorf("nothing on 80 or 443: %s", paasLevels(rs))
	}
}

func TestPaaSFilterFor(t *testing.T) {
	ufw := func(rules ...facts.UFWRule) *facts.Firewall {
		return &facts.Firewall{UFW: &facts.UFW{Installed: true, Source: "status", Status: "active", DefaultIncoming: "deny", RulesKnown: true, Rules: rules}}
	}
	cases := []struct {
		name      string
		fw        *facts.Firewall
		proto     string
		port      int
		viaDocker bool
		want      paasFilter
	}{
		{"no facts", nil, "tcp", 2377, false, paasFilterUnknown},
		{"ufw blocks", ufw(), "tcp", 2377, false, paasFilterApplied},
		{"ufw allows anywhere", ufw(facts.UFWRule{Action: "allow", Direction: "in", Port: "2377", Proto: "tcp"}), "tcp", 2377, false, paasFilterNone},
		{"ufw allows a peer", ufw(facts.UFWRule{Action: "allow", Direction: "in", Port: "2377", Proto: "tcp", From: "198.51.100.7"}), "tcp", 2377, false, paasFilterApplied},
		{"ufw files only", &facts.Firewall{UFW: &facts.UFW{Installed: true, Source: "files", Status: "active"}}, "tcp", 2377, false, paasFilterUnknown},
		{"docker default chain", &facts.Firewall{DockerUser: "default", DockerBackend: "iptables"}, "tcp", 8000, true, paasFilterNone},
		{"docker filtered", &facts.Firewall{DockerUser: "filtered", DockerBackend: "iptables"}, "tcp", 8000, true, paasFilterApplied},
		{"ufw-docker loaded", &facts.Firewall{UFWDocker: &facts.UFWDocker{Loaded: "yes"}}, "tcp", 8000, true, paasFilterApplied},
		{"docker chain unread", &facts.Firewall{}, "tcp", 8000, true, paasFilterUnknown},
		{"ufw does not cover docker", ufw(), "tcp", 8000, true, paasFilterUnknown},
	}
	for _, c := range cases {
		if got := paasFilterFor(c.fw, c.proto, c.port, c.viaDocker); got != c.want {
			t.Errorf("%s: %s, want %s", c.name, got, c.want)
		}
	}
}

func TestPaaSPanelPortProcessDecidesDocker(t *testing.T) {
	// UFW blocks host sockets; the panel port is held by docker-proxy, so
	// UFW does not count and the default DOCKER-USER chain lets it through.
	f := paasCoolifyFacts()
	f.Firewall = &facts.Firewall{DockerUser: "default", DockerBackend: "iptables",
		UFW: &facts.UFW{Installed: true, Source: "status", Status: "active", DefaultIncoming: "deny", RulesKnown: true}}
	f.Listeners = &facts.Listeners{Sockets: []facts.Listener{{Proto: "tcp", Address: "0.0.0.0", Port: 8000, Processes: []string{"docker-proxy"}}}}
	rs := EvaluateChecks([]Check{{ID: "PAAS-003", Run: checkPaaSPanelPorts}}, Input{Facts: f})
	if got := paasLevels(rs); got != "port:tcp/6001=pass port:tcp/6002=pass port:tcp/8000=fail" {
		t.Errorf("docker-proxy: %s", got)
	}
	f.Listeners.Sockets[0].Processes = []string{"php"}
	rs = EvaluateChecks([]Check{{ID: "PAAS-003", Run: checkPaaSPanelPorts}}, Input{Facts: f})
	if got := paasLevels(rs); got != "port:tcp/6001=pass port:tcp/6002=pass port:tcp/8000=warn" {
		t.Errorf("host process behind ufw: %s", got)
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
		{"web on paas-panel", web, profile.PaaSPanel, Pass},
	}
	for _, c := range cases {
		withPaaSViews(t, proxy(c.ports...), nil, paasFilterUnknown)
		pf := paasCoolifyFacts()
		pf.Firewall = paasUnfilteredFirewall()
		rs := checkPaaSProxyExposure(Input{Facts: pf, Profile: c.prof})
		if len(rs) != 1 || rs[0].Level != c.want || rs[0].Subject != "container:coolify-proxy" {
			t.Errorf("%s: %s %q", c.name, paasLevels(rs), rs[0].Message)
		}
	}
	// A panel host with a tunnel beside the public proxy: info that names
	// the tunnel, not a pass and not a warning.
	withPaaSViews(t, proxy(web...), nil, paasFilterUnknown)
	f := paasCoolifyFacts()
	f.Firewall = paasUnfilteredFirewall()
	f.Docker = &facts.Docker{Installed: true, API: "ok", Containers: []facts.DockerContainer{{Name: "tunnel", Image: "cloudflare/cloudflared:2026.10.0", Running: true}}}
	if rs := checkPaaSProxyExposure(Input{Facts: f, Profile: profile.PaaSPanel}); rs[0].Level != Info || !strings.Contains(rs[0].Message, "tunnel") {
		t.Errorf("panel with tunnel: %s %q", rs[0].Level, rs[0].Message)
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
		pf := paasCoolifyFacts()
		pf.Firewall = paasUnfilteredFirewall()
		rs := EvaluateChecks([]Check{{ID: "PAAS-004", Run: checkPaaSPublicDatabase}}, Input{Facts: pf})
		if got := paasLevels(rs); got != c.want {
			t.Errorf("%s: %s", c.name, got)
		}
	}
	// Filtering that cannot be read is unknown, a ufw-docker drop is a warning.
	db := []paasContainer{{Name: "db1", Image: "postgres:16-alpine", Labels: coolifyLabels,
		Ports: []paasPort{{HostIP: "0.0.0.0", HostPort: 5432, ContainerPort: 5432}}}}
	withPaaSViews(t, db, nil, paasFilterUnknown)
	for name, c := range map[string]struct {
		fw   *facts.Firewall
		want string
	}{
		"unreadable":        {&facts.Firewall{DockerBackend: "iptables"}, "container:db1=unknown"},
		"no firewall facts": {nil, "container:db1=unknown"},
	} {
		pf := paasCoolifyFacts()
		pf.Firewall = c.fw
		rs := EvaluateChecks([]Check{{ID: "PAAS-004", Run: checkPaaSPublicDatabase}}, Input{Facts: pf})
		if got := paasLevels(rs); got != c.want {
			t.Errorf("%s: %s", name, got)
		}
	}
	uf := ufwDockerHost(false)
	uf.PaaS = paasCoolifyFacts().PaaS
	withPaaSViews(t, []paasContainer{{Name: "db1", Image: "postgres:16-alpine", Labels: coolifyLabels,
		Ports: []paasPort{{HostIP: "0.0.0.0", HostPort: 8000, ContainerPort: 8000}}}}, nil, paasFilterUnknown)
	if got := paasLevels(checkPaaSPublicDatabase(Input{Facts: uf})); got != "container:db1=warn" {
		t.Errorf("ufw-docker drop: %s", got)
	}
}

func paasDokployFacts() *facts.Facts {
	return &facts.Facts{
		PaaS: &facts.PaaS{Platforms: []facts.Platform{{Name: facts.PlatformDokploy, Role: facts.RoleUnknown, DataRoot: facts.DokployRoot}}},
		Docker: &facts.Docker{Installed: true, API: "denied",
			APIReason: "cannot open /var/run/docker.sock: permission denied (run with sudo, or as a member of the docker group)"},
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
	for addr, want := range map[string]facts.BindClass{
		"0.0.0.0": facts.BindWildcard, "[::]": facts.BindWildcard, "*": facts.BindWildcard, "127.0.0.53": facts.BindLoopback, "::1": facts.BindLoopback,
		"100.64.0.1": facts.BindTailnet, "fd7a:115c:a1e0::1": facts.BindTailnet, "10.1.2.3": facts.BindPrivate, "fe80::1%eth0": facts.BindPrivate,
		"203.0.113.10": facts.BindPublic, "2001:db8::1": facts.BindPublic, "::ffff:127.0.0.1": facts.BindLoopback, "garbage": facts.BindPublic,
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

func TestPaaSContainersFrom(t *testing.T) {
	if cs, ok := paasContainersFrom(&facts.Docker{}); !ok || len(cs) != 0 {
		t.Errorf("not installed: %v %v", cs, ok)
	}
	if _, ok := paasContainersFrom(&facts.Docker{Installed: true, API: "denied"}); ok {
		t.Error("denied socket must not be available")
	}
	d := &facts.Docker{Installed: true, API: "ok", Containers: []facts.DockerContainer{{
		Name: "db1", Image: "postgres:16", Project: "shop", Networks: []string{"coolify"},
		Labels: map[string]string{"coolify.managed": "true"},
		Ports:  []facts.DockerPort{{HostIP: "0.0.0.0", HostPort: 5432, ContainerPort: 5432, Proto: "tcp"}},
	}}}
	cs, ok := paasContainersFrom(d)
	if !ok || len(cs) != 1 || cs[0].Project != "shop" || cs[0].Ports[0].HostPort != 5432 || cs[0].Networks[0] != "coolify" {
		t.Errorf("mapped %+v", cs)
	}
}

func TestPaaSVersionIgnoresLatest(t *testing.T) {
	withPaaSViews(t, []paasContainer{{Name: "coolify", Image: "ghcr.io/coollabsio/coolify:latest"}}, nil, paasFilterUnknown)
	rs := checkPaaSDetected(Input{Facts: paasCoolifyFacts()})
	if rs[0].Evidence["version"] != "" {
		t.Errorf("latest is not a version: %v", rs[0].Evidence["version"])
	}
}

func TestPaaSPublicDatabaseFiltered(t *testing.T) {
	db := []paasContainer{{Name: "db1", Image: "postgres:16-alpine", Labels: map[string]string{"coolify.managed": "true"},
		Ports: []paasPort{{HostIP: "0.0.0.0", HostPort: 5432, ContainerPort: 5432, Proto: "tcp"}}}}
	withPaaSViews(t, db, nil, paasFilterUnknown)
	f := paasCoolifyFacts()
	f.Firewall = &facts.Firewall{DockerUser: "filtered", DockerBackend: "iptables",
		Iptables: &facts.Iptables{Listed: true, DockerUserRules: []string{"-A DOCKER-USER ! -s 198.51.100.0/24 -j DROP"}}}
	if got := paasLevels(checkPaaSPublicDatabase(Input{Facts: f})); got != "container:db1=warn" {
		t.Errorf("filtered: %s", got)
	}
	f.Firewall.DockerUser = "default"
	if got := paasLevels(checkPaaSPublicDatabase(Input{Facts: f})); got != "container:db1=fail" {
		t.Errorf("unfiltered: %s", got)
	}
}

func TestPaaSDefaultNetwork(t *testing.T) {
	app := func(name, project string, nets ...string) paasContainer {
		return paasContainer{Name: name, Image: "ghcr.io/example/" + name + ":1", Project: project, Networks: nets,
			Labels: map[string]string{"coolify.managed": "true", "coolify.projectName": project}}
	}
	internal := paasContainer{Name: "coolify-db", Image: "postgres:15-alpine", Networks: []string{"coolify"}, Labels: map[string]string{}}
	proxy := paasContainer{Name: "coolify-proxy", Image: "traefik:v3.1", Networks: []string{"coolify", "shopnet"}, Labels: map[string]string{"coolify.proxy": "true"}}
	cases := []struct {
		name string
		cs   []paasContainer
		want string
	}{
		{"two projects share coolify", []paasContainer{internal, proxy, app("shop", "shop", "coolify"), app("blog", "blog", "coolify")}, "host=warn"},
		{"one project", []paasContainer{internal, proxy, app("shop-web", "shop", "coolify"), app("shop-db", "shop", "coolify")}, "host=pass"},
		{"own networks", []paasContainer{internal, proxy, app("shop", "shop", "shopnet"), app("blog", "blog", "blognet")}, "host=pass"},
	}
	for _, c := range cases {
		withPaaSViews(t, c.cs, nil, paasFilterUnknown)
		if got := paasLevels(EvaluateChecks([]Check{{ID: "PAAS-005", Run: checkPaaSDefaultNetwork}}, Input{Facts: paasCoolifyFacts()})); got != c.want {
			t.Errorf("%s: %s", c.name, got)
		}
	}
}

func TestPaaSDefaultNetworkWithoutContainers(t *testing.T) {
	if got := paasLevels(checkPaaSDefaultNetwork(Input{Facts: paasCoolifyFacts()})); got != "=unknown" {
		t.Errorf("denied docker: %s", got)
	}
	if got := paasLevels(checkPaaSDefaultNetwork(Input{Facts: &facts.Facts{PaaS: &facts.PaaS{}, Docker: &facts.Docker{}}})); got != "=skip" {
		t.Errorf("no platform: %s", got)
	}
}

// PAAS-002 uses the forward filter DKR-001 and CF-003 use: a proxy published
// on all interfaces but dropped for every outside source is a warning, a
// reachable one fails on a tunnel host, filtering that cannot be read is
// unknown.
func TestPaaSProxyExposureForwardFilter(t *testing.T) {
	web := []paasPort{{HostIP: "0.0.0.0", HostPort: 80, ContainerPort: 80, Proto: "tcp"}, {HostIP: "0.0.0.0", HostPort: 443, ContainerPort: 443, Proto: "tcp"}}
	withPaaSViews(t, []paasContainer{{Name: "coolify-proxy", Image: "traefik:v3.1", Ports: web}}, nil, paasFilterUnknown)
	host := func(fw string, routes ...facts.UFWRule) *facts.Facts {
		f := ufwDockerHost(false, routes...)
		f.PaaS = paasCoolifyFacts().PaaS
		f.Firewall.DockerUser = fw
		return f
	}
	cases := []struct {
		name string
		f    *facts.Facts
		want Level
		msg  string
	}{
		{"ufw-docker drops it", host("filtered"), Warn, "bind to 127.0.0.1"},
		{"route rule allows 443", host("filtered", route443), Fail, "0.0.0.0:443->443/tcp"},
		{"DOCKER-USER needs root", host(""), Unknown, "needs root"},
	}
	for _, c := range cases {
		if c.name == "DOCKER-USER needs root" {
			c.f.Firewall.Iptables.DockerUserRules = nil
			c.f.Firewall.UFWDocker = nil
		}
		rs := checkPaaSProxyExposure(Input{Facts: c.f, Profile: profile.Tunnel})
		if len(rs) != 1 || rs[0].Level != c.want || !strings.Contains(rs[0].Message, c.msg) {
			t.Errorf("%s: %s %q, want %s containing %q", c.name, paasLevels(rs), rs[0].Message, c.want, c.msg)
		}
	}
	// The same host stays consistent with CF-003.
	f := host("filtered")
	f.Cloudflared = cfTunnel(2)
	if r := netOne(t, "CF-003", f, ""); r.Level != Pass {
		t.Errorf("CF-003 = %s (%s), want pass", r.Level, r.Message)
	}
}
