package checks

import (
	"strings"
	"testing"
	"time"

	"github.com/Shironex/stackward/internal/facts"
)

func ptrBool(b bool) *bool { return &b }

// dockerHost is a reachable, healthy Docker host with the given containers.
func dockerHost(cs ...facts.DockerContainer) *facts.Facts {
	return &facts.Facts{CollectedAt: now, Docker: &facts.Docker{
		Installed:  true,
		SocketPath: "/var/run/docker.sock",
		Socket:     &facts.DockerSocket{Perm: "0660", GID: 998, Group: "docker"},
		API:        "ok",
		Version:    &facts.DockerVersion{Version: "29.1.0"},
		Info:       &facts.DockerInfo{LoggingDriver: "json-file"},
		Daemon:     &facts.DockerDaemon{ConfigFound: true, LogDriver: "json-file", LogMaxSize: "10m", Hosts: []facts.DockerHost{{Addr: "fd://", Source: "unit"}}},
		TCPRead:    true,
		Containers: cs,
	}}
}

func denied() *facts.Facts {
	f := dockerHost()
	f.Docker.API = "denied"
	f.Docker.APIReason = "cannot open /var/run/docker.sock: permission denied (run with sudo, or as a member of the docker group)"
	f.Docker.Containers = nil
	return f
}

func app(name string, mod ...func(*facts.DockerContainer)) facts.DockerContainer {
	c := facts.DockerContainer{ID: "aaaaaaaaaaaa", Name: name, Image: "ghcr.io/example/" + name + ":1.0", Running: true, User: "10001"}
	for _, m := range mod {
		m(&c)
	}
	return c
}

func levels(rs []Result) map[string]Level {
	out := map[string]Level{}
	for _, r := range rs {
		subj := r.Subject
		if subj == "" {
			subj = "host"
		}
		out[subj] = r.Level
	}
	return out
}

func only(t *testing.T, rs []Result) Level {
	t.Helper()
	if len(rs) != 1 {
		t.Fatalf("want one result, got %+v", rs)
	}
	return rs[0].Level
}

// TestDKRCommonGates runs every DKR check over not inspected facts, a host
// without Docker and a socket stackward cannot read.
func TestDKRCommonGates(t *testing.T) {
	for _, c := range All() {
		if !strings.HasPrefix(c.ID, "DKR-") {
			continue
		}
		if l := only(t, c.Run(Input{Facts: &facts.Facts{}})); l != Unknown {
			t.Errorf("%s nil facts: %s", c.ID, l)
		}
		if l := only(t, c.Run(Input{Facts: &facts.Facts{Docker: &facts.Docker{API: "absent"}}})); l != Skip {
			t.Errorf("%s not installed: %s", c.ID, l)
		}
		rs := c.Run(Input{Facts: denied()})
		if l := only(t, rs); l != Unknown {
			t.Errorf("%s denied socket: %s, want unknown", c.ID, l)
		} else if !strings.Contains(rs[0].Message, "docker group") {
			t.Errorf("%s denied socket message %q lacks the reason", c.ID, rs[0].Message)
		}
	}
}

func TestDKR002(t *testing.T) {
	cases := []struct {
		name string
		mod  func(*facts.Docker)
		want Level
	}{
		{"socket only", func(*facts.Docker) {}, Pass},
		{"tcp host", func(d *facts.Docker) {
			d.Daemon.Hosts = append(d.Daemon.Hosts, facts.DockerHost{Addr: "tcp://0.0.0.0:2375", Source: "daemon.json"})
		}, Fail},
		{"tcp with tlsverify", func(d *facts.Docker) {
			d.Daemon.Hosts = append(d.Daemon.Hosts, facts.DockerHost{Addr: "tcp://0.0.0.0:2376"})
			d.Daemon.TLSVerify = true
			d.TCP = []facts.DockerTCPListener{{Port: 2376, Bind: "any"}}
		}, Pass},
		{"loopback listener", func(d *facts.Docker) { d.TCP = []facts.DockerTCPListener{{Port: 2375, Bind: "loopback"}} }, Fail},
		{"listener, socket denied", func(d *facts.Docker) {
			d.API = "denied"
			d.TCP = []facts.DockerTCPListener{{Port: 2375, Bind: "any"}}
		}, Fail},
		{"clean, socket denied", func(d *facts.Docker) { d.API = "denied" }, Unknown},
		{"proc not read", func(d *facts.Docker) { d.TCPRead = false }, Unknown},
		{"bad daemon.json", func(d *facts.Docker) { d.Daemon.ConfigError = "invalid JSON" }, Unknown},
	}
	for _, tc := range cases {
		f := dockerHost()
		tc.mod(f.Docker)
		if got := only(t, checkDaemonTCP(Input{Facts: f})); got != tc.want {
			t.Errorf("%s: got %s, want %s", tc.name, got, tc.want)
		}
	}
}

func TestDKR003(t *testing.T) {
	f := dockerHost()
	if got := only(t, checkSocketMode(Input{Facts: f})); got != Pass {
		t.Errorf("0660: %s", got)
	}
	f.Docker.Socket = &facts.DockerSocket{Perm: "0666", WorldWritable: true}
	f.Docker.API = "denied"
	if got := only(t, checkSocketMode(Input{Facts: f})); got != Fail {
		t.Errorf("0666 denied: %s", got)
	}
	f.Docker.Socket = nil
	if got := only(t, checkSocketMode(Input{Facts: f})); got != Unknown {
		t.Errorf("no socket: %s", got)
	}
}

func socketBind(ro bool) func(*facts.DockerContainer) {
	return func(c *facts.DockerContainer) {
		c.Mounts = append(c.Mounts, facts.DockerMount{Type: "bind", Source: "/var/run/docker.sock", Target: "/var/run/docker.sock", ReadOnly: ro})
	}
}

func TestDKR010(t *testing.T) {
	rs := checkSocketMounted(Input{Facts: dockerHost(
		app("clean"),
		app("agent", socketBind(true)),
		app("parent", func(c *facts.DockerContainer) {
			c.Mounts = []facts.DockerMount{{Type: "bind", Source: "/run/", Target: "/host-run"}}
		}),
		app("coolify-proxy", socketBind(true), func(c *facts.DockerContainer) { c.Image = "traefik:v3.1" }),
	)})
	want := map[string]Level{"container:clean": Pass, "container:agent": Fail, "container:parent": Fail, "container:coolify-proxy": Warn}
	got := levels(rs)
	for s, l := range want {
		if got[s] != l {
			t.Errorf("%s: got %s, want %s", s, got[s], l)
		}
	}
	if l := only(t, checkSocketMounted(Input{Facts: dockerHost()})); l != Pass {
		t.Errorf("no containers: %s", l)
	}
}

func TestDKR010ReplicasWorstWins(t *testing.T) {
	grouped := func(c *facts.DockerContainer) { c.Project, c.Service = "shop", "worker" }
	rs := checkSocketMounted(Input{Facts: dockerHost(app("shop-worker-1", grouped), app("shop-worker-2", grouped, socketBind(false)))})
	if len(rs) != 1 || rs[0].Subject != "container:shop/worker" || rs[0].Level != Fail || !strings.Contains(rs[0].Message, "2 replicas") {
		t.Fatalf("got %+v", rs)
	}
}

func TestDKR011(t *testing.T) {
	proxy := func(flags map[string]string, image string) facts.DockerContainer {
		return app("sp", socketBind(true), func(c *facts.DockerContainer) { c.Image = image; c.Flags = flags })
	}
	cases := []struct {
		name string
		c    facts.DockerContainer
		want Level
	}{
		{"reads only", proxy(map[string]string{"CONTAINERS": "1", "POST": "0"}, "tecnativa/docker-socket-proxy:0.3.0"), Pass},
		{"defaults", proxy(nil, "lscr.io/linuxserver/socket-proxy:1.26"), Pass},
		{"post", proxy(map[string]string{"POST": "1"}, "tecnativa/docker-socket-proxy:0.3.0"), Warn},
		{"exec", proxy(map[string]string{"EXEC": "true"}, "tecnativa/docker-socket-proxy:0.3.0"), Warn},
		{"command line", proxy(nil, "wollomatic/socket-proxy:1.5"), Unknown},
	}
	for _, tc := range cases {
		if got := only(t, checkSocketProxyFlags(Input{Facts: dockerHost(tc.c, app("web"))})); got != tc.want {
			t.Errorf("%s: got %s, want %s", tc.name, got, tc.want)
		}
	}
	if got := only(t, checkSocketProxyFlags(Input{Facts: dockerHost(app("web"))})); got != Skip {
		t.Errorf("no proxy: %s", got)
	}
}

func TestDKR012(t *testing.T) {
	bind := func(src string, ro bool) func(*facts.DockerContainer) {
		return func(c *facts.DockerContainer) {
			c.Mounts = append(c.Mounts, facts.DockerMount{Type: "bind", Source: src, Target: "/x", ReadOnly: ro})
		}
	}
	got := levels(checkHostBinds(Input{Facts: dockerHost(
		app("a", bind("/etc", false)), app("b", bind("/home/", true)), app("c", bind("/etc/localtime", true)),
		app("d", func(c *facts.DockerContainer) {
			c.Mounts = []facts.DockerMount{{Type: "volume", Source: "etc", Target: "/etc"}}
		}),
	)}))
	want := map[string]Level{"container:a": Fail, "container:b": Warn, "container:c": Pass, "container:d": Pass}
	for s, l := range want {
		if got[s] != l {
			t.Errorf("%s: got %s, want %s", s, got[s], l)
		}
	}
}

func TestIsRootUser(t *testing.T) {
	for u, want := range map[string]bool{
		"": true, "root": true, "0": true, "00": true, "0:0": true, "root:1000": true, "0:1000": true,
		"1000": false, "1000:0": false, "node": false, "nonroot": false,
	} {
		if got := isRootUser(u); got != want {
			t.Errorf("%q: got %v", u, got)
		}
	}
}

func TestDKR020(t *testing.T) {
	root := func(c *facts.DockerContainer) { c.User = "" }
	got := levels(checkContainerRoot(Input{Facts: dockerHost(
		app("user"),
		app("root", root),
		app("rootpub", root, func(c *facts.DockerContainer) {
			c.Ports = []facts.DockerPort{{ContainerPort: 80, Proto: "tcp", HostIP: "0.0.0.0", HostPort: 80}}
		}),
		app("rootlocal", root, func(c *facts.DockerContainer) {
			c.Ports = []facts.DockerPort{{ContainerPort: 80, Proto: "tcp", HostIP: "127.0.0.1", HostPort: 8080}}
		}),
		app("rootrouted", root, func(c *facts.DockerContainer) { c.ProxyRouted = true }),
		app("rootpriv", func(c *facts.DockerContainer) { c.User = "0:0"; c.Privileged = true }),
	)}))
	want := map[string]Level{"container:user": Pass, "container:root": Warn, "container:rootpub": Fail,
		"container:rootlocal": Warn, "container:rootrouted": Fail, "container:rootpriv": Fail}
	for s, l := range want {
		if got[s] != l {
			t.Errorf("%s: got %s, want %s", s, got[s], l)
		}
	}
}

func TestDKR021and022(t *testing.T) {
	got := levels(checkPrivileged(Input{Facts: dockerHost(app("a"), app("b", func(c *facts.DockerContainer) { c.Privileged = true }))}))
	if got["container:a"] != Pass || got["container:b"] != Fail {
		t.Errorf("privileged: %v", got)
	}
	caps := func(cs ...string) func(*facts.DockerContainer) {
		return func(c *facts.DockerContainer) { c.CapAdd = cs }
	}
	got = levels(checkCapAdd(Input{Facts: dockerHost(app("a"), app("b", caps("CAP_SYS_ADMIN")), app("c", caps("net_raw")), app("d", caps("CHOWN")))}))
	want := map[string]Level{"container:a": Pass, "container:b": Fail, "container:c": Warn, "container:d": Pass}
	for s, l := range want {
		if got[s] != l {
			t.Errorf("caps %s: got %s, want %s", s, got[s], l)
		}
	}
}

func TestDKR023(t *testing.T) {
	got := levels(checkHostNamespaces(Input{Facts: dockerHost(
		app("a"),
		app("b", func(c *facts.DockerContainer) { c.NetworkMode = "host" }),
		app("c", func(c *facts.DockerContainer) { c.NetworkMode = "host"; c.User = "root" }),
		app("d", func(c *facts.DockerContainer) { c.PidMode = "host" }),
		app("e", func(c *facts.DockerContainer) { c.IpcMode = "host" }),
	)}))
	want := map[string]Level{"container:a": Pass, "container:b": Warn, "container:c": Fail, "container:d": Fail, "container:e": Warn}
	for s, l := range want {
		if got[s] != l {
			t.Errorf("%s: got %s, want %s", s, got[s], l)
		}
	}
}

func TestDKR024(t *testing.T) {
	pub := func(c *facts.DockerContainer) { c.ProxyRouted = true }
	f := dockerHost(
		app("a"),
		app("b", func(c *facts.DockerContainer) { c.SecurityOpt = []string{"seccomp=unconfined"} }),
		app("c", pub),
		app("d", pub, func(c *facts.DockerContainer) { c.SecurityOpt = []string{"no-new-privileges:true"} }),
	)
	got := levels(checkSecurityOpt(Input{Facts: f}))
	want := map[string]Level{"container:a": Pass, "container:b": Warn, "container:c": Warn, "container:d": Pass}
	for s, l := range want {
		if got[s] != l {
			t.Errorf("%s: got %s, want %s", s, got[s], l)
		}
	}
	f.Docker.Daemon.NoNewPrivileges = true
	if got := levels(checkSecurityOpt(Input{Facts: f})); got["container:c"] != Pass {
		t.Errorf("daemon wide no-new-privileges ignored: %v", got)
	}
}

func TestDKR030(t *testing.T) {
	in := func(project, service string, nets ...string) func(*facts.DockerContainer) {
		return func(c *facts.DockerContainer) { c.Project, c.Service, c.Networks = project, service, nets }
	}
	f := dockerHost(
		app("shop-web-1", in("shop", "web", "shop_default", "edge")),
		app("shop-db-1", in("shop", "db", "shop_default"), func(c *facts.DockerContainer) { c.Image = "postgres:16" }),
		app("blog-web-1", in("blog", "web", "blog_default", "edge")),
		app("blog-cache-1", in("blog", "cache", "blog_default", "edge"), func(c *facts.DockerContainer) { c.Image = "valkey/valkey:8" }),
		app("stats-web-1", in("stats", "web", "stats_default", "public")),
		app("other-web-1", in("other", "web", "public")),
		app("coolify-proxy", func(c *facts.DockerContainer) {
			c.Image = "traefik:v3.1"
			c.Networks = []string{"edge", "shop_default", "blog_default", "public"}
		}),
		app("lonely", func(c *facts.DockerContainer) { c.Networks = []string{"bridge"} }),
		app("hostnet", func(c *facts.DockerContainer) { c.NetworkMode = "host" }),
	)
	rs := checkSharedNetworks(Input{Facts: f})
	got := levels(rs)
	want := map[string]Level{
		"container:shop/web":      Fail, // shares edge with blog's valkey
		"container:shop/db":       Pass, // same project only
		"container:blog/web":      Warn, // shares edge with shop/web
		"container:blog/cache":    Fail, // a database on a shared network
		"container:stats/web":     Warn,
		"container:other/web":     Warn,
		"container:coolify-proxy": Skip,
		"container:lonely":        Pass, // default bridge is not judged
		"container:hostnet":       Skip,
	}
	for s, l := range want {
		if got[s] != l {
			t.Errorf("%s: got %s, want %s", s, got[s], l)
		}
	}
	for _, r := range rs {
		if r.Subject == "container:shop/web" {
			if peers := r.Evidence["database_peers"].([]string); len(peers) != 1 || peers[0] != "blog/cache" {
				t.Errorf("database peers %v", peers)
			}
		}
	}
}

func TestDKR031(t *testing.T) {
	cases := []struct {
		name string
		mod  func(*facts.Docker)
		want Level
	}{
		{"rotated", func(*facts.Docker) {}, Pass},
		{"no config", func(d *facts.Docker) { d.Daemon = &facts.DockerDaemon{} }, Warn},
		{"local driver", func(d *facts.Docker) { d.Daemon = &facts.DockerDaemon{}; d.Info.LoggingDriver = "local" }, Pass},
		{"unreadable", func(d *facts.Docker) { d.Daemon = &facts.DockerDaemon{ConfigError: "permission denied"} }, Unknown},
		{"not read", func(d *facts.Docker) { d.Daemon = nil }, Unknown},
	}
	for _, tc := range cases {
		f := dockerHost()
		tc.mod(f.Docker)
		if got := only(t, checkLogRotation(Input{Facts: f})); got != tc.want {
			t.Errorf("%s: got %s, want %s", tc.name, got, tc.want)
		}
	}
}

func TestDKR032(t *testing.T) {
	img := func(name, image string) facts.DockerContainer {
		return app(name, func(c *facts.DockerContainer) { c.Image = image })
	}
	got := levels(checkInfraTags(Input{Facts: dockerHost(
		img("proxy", "traefik:v3.1"), img("tunnel", "cloudflare/cloudflared"), img("cs", "crowdsecurity/crowdsec:latest"),
		img("pinned", "cloudflare/cloudflared@sha256:0123"), img("web", "ghcr.io/example/web:latest"),
	)}))
	want := map[string]Level{"container:proxy": Pass, "container:tunnel": Warn, "container:cs": Warn, "container:pinned": Pass}
	for s, l := range want {
		if got[s] != l {
			t.Errorf("%s: got %s, want %s", s, got[s], l)
		}
	}
	if _, ok := got["container:web"]; ok {
		t.Error("an app container was judged as infrastructure")
	}
	if l := only(t, checkInfraTags(Input{Facts: dockerHost(app("web"))})); l != Skip {
		t.Errorf("no infra: %s", l)
	}
}

func TestDKR033(t *testing.T) {
	f := dockerHost()
	if got := only(t, checkIPTables(Input{Facts: f})); got != Pass {
		t.Errorf("default: %s", got)
	}
	f.Docker.Daemon.IPTables = ptrBool(false)
	if got := only(t, checkIPTables(Input{Facts: f})); got != Warn {
		t.Errorf("iptables false: %s", got)
	}
	f.Docker.Daemon = &facts.DockerDaemon{ConfigError: "permission denied"}
	if got := only(t, checkIPTables(Input{Facts: f})); got != Unknown {
		t.Errorf("unreadable: %s", got)
	}
}

func TestDKR034(t *testing.T) {
	for v, want := range map[string]Level{
		"29.1.0": Pass, "30.0.1": Pass, "28.5.2": Warn, "27.5.1": Warn, "26.1.4": Warn,
		"25.0.18": Pass, "20.10.24": Warn, "19.03.15": Warn, "garbage": Unknown,
	} {
		f := dockerHost()
		f.CollectedAt = time.Date(2026, 11, 15, 0, 0, 0, 0, time.UTC)
		f.Docker.Version.Version = v
		if got := only(t, checkEngineSupport(Input{Facts: f})); got != want {
			t.Errorf("%s: got %s, want %s", v, got, want)
		}
	}
	f := dockerHost() // collected 2026-03-01, before 28 left support
	f.Docker.Version.Version = "28.0.0"
	if got := only(t, checkEngineSupport(Input{Facts: f})); got != Pass {
		t.Errorf("28 before its end date: %s", got)
	}
	f.Docker.Version = nil
	if got := only(t, checkEngineSupport(Input{Facts: f})); got != Unknown {
		t.Errorf("no version: %s", got)
	}
}

func TestImageRef(t *testing.T) {
	cases := map[string][3]string{
		"traefik:v3.1":                          {"traefik", "v3.1", ""},
		"ghcr.io:443/example/app:1.2@sha256:ab": {"ghcr.io:443/example/app", "1.2", "sha256:ab"},
		"localhost:5000/app":                    {"localhost:5000/app", "", ""},
		"Postgres":                              {"postgres", "", ""},
	}
	for ref, want := range cases {
		r, tag, d := imageRef(ref)
		if [3]string{r, tag, d} != want {
			t.Errorf("%s: got %q %q %q", ref, r, tag, d)
		}
	}
}
