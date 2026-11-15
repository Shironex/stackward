package checks

import (
	"strings"
	"testing"

	"github.com/Shironex/stackward/internal/facts"
)

// coolifyStack is a Coolify panel host: the panel stack (compose project
// "source"), the proxy and the sentinel started on their own, and one app.
func coolifyStack(detected bool) *facts.Facts {
	sock := facts.DockerMount{Type: "bind", Source: "/var/run/docker.sock", Target: "/var/run/docker.sock"}
	f := dockerHost(
		app("coolify", func(c *facts.DockerContainer) {
			c.Image, c.Project, c.Service, c.User = "ghcr.io/coollabsio/coolify:4.0.0", "source", "coolify", "www-data"
			c.Networks = []string{"coolify"}
		}),
		app("coolify-db", func(c *facts.DockerContainer) {
			c.Image, c.Project, c.Service, c.User = "postgres:15-alpine", "source", "postgres", ""
			c.Networks = []string{"coolify"}
		}),
		app("coolify-proxy", func(c *facts.DockerContainer) {
			c.Image, c.User, c.ProxyRouted = "traefik:v3.1", "", true
			c.Labels = map[string]string{"coolify.proxy": "true"}
			c.Mounts = []facts.DockerMount{sock}
			c.Ports = []facts.DockerPort{{ContainerPort: 80, Proto: "tcp", HostPort: 80}, {ContainerPort: 443, Proto: "tcp", HostPort: 443}}
			c.Networks = []string{"coolify"}
		}),
		app("coolify-sentinel", func(c *facts.DockerContainer) {
			c.Image, c.User, c.PidMode = "ghcr.io/coollabsio/sentinel:0.0.15", "", "host"
			c.Mounts = []facts.DockerMount{sock}
			c.Networks = []string{"coolify"}
		}),
		app("shop-web", func(c *facts.DockerContainer) {
			c.Image, c.User, c.PidMode = "ghcr.io/example/shop:1.0", "", "host"
		}),
	)
	f.PaaS = &facts.PaaS{Platforms: []facts.Platform{}}
	if detected {
		f.PaaS.Platforms = append(f.PaaS.Platforms, facts.Platform{Name: facts.PlatformCoolify, Role: facts.RolePanel, DataRoot: facts.CoolifyRoot})
	} else {
		// No platform on disk and no panel image: plain look alikes.
		for i := range f.Docker.Containers {
			if strings.Contains(f.Docker.Containers[i].Image, "coollabsio") {
				f.Docker.Containers[i].Image = "ghcr.io/example/lookalike:1.0"
			}
		}
	}
	return f
}

func bySubject(rs []Result) map[string]Result {
	out := map[string]Result{}
	for _, r := range rs {
		out[r.Subject] = r
	}
	return out
}

func TestPlatformManagedContainers(t *testing.T) {
	f := coolifyStack(true)
	in := Input{Facts: f}
	cases := []struct {
		check   func(Input) []Result
		subject string
		want    Level
	}{
		{checkHostNamespaces, "container:coolify-sentinel", Warn},
		{checkHostNamespaces, "container:shop-web", Fail},
		{checkContainerRoot, "container:coolify-proxy", Warn},
		{checkContainerRoot, "container:shop-web", Warn},
		{checkSocketMounted, "container:coolify-proxy", Warn},
		{checkSocketMounted, "container:coolify-sentinel", Warn},
	}
	for _, tc := range cases {
		r := bySubject(tc.check(in))[tc.subject]
		if r.Level != tc.want {
			t.Errorf("%s: got %s %q, want %s", tc.subject, r.Level, r.Message, tc.want)
		}
		managed := strings.HasPrefix(tc.subject, "container:coolify")
		if managed != strings.Contains(r.Message, "managed by Coolify") || (managed && r.Evidence["managed_by"] != "coolify") {
			t.Errorf("%s: managed note wrong: %q %v", tc.subject, r.Message, r.Evidence["managed_by"])
		}
	}
	// Privileged stays a fail, platform or not.
	f.Docker.Containers[3].Privileged = true
	if r := bySubject(checkContainerRoot(in))["container:coolify-sentinel"]; r.Level != Fail {
		t.Errorf("privileged sentinel: %s", r.Level)
	}

	// Without the platform detected the names alone change nothing.
	plain := coolifyStack(false)
	if r := bySubject(checkHostNamespaces(Input{Facts: plain}))["container:coolify-sentinel"]; r.Level != Fail || strings.Contains(r.Message, "managed") {
		t.Errorf("undetected platform: %s %q", r.Level, r.Message)
	}
}

func TestPlatformIsOneProject(t *testing.T) {
	f := coolifyStack(true)
	f.Docker.Containers = append(f.Docker.Containers,
		app("coolify-proxy-error-pages", func(c *facts.DockerContainer) { c.Networks = []string{"coolify"} }),
		app("billing", func(c *facts.DockerContainer) {
			c.Project, c.Service, c.Networks = "billing", "api", []string{"coolify"}
		}))
	rs := bySubject(checkSharedNetworks(Input{Facts: f}))
	db := rs["container:source/postgres"]
	if strings.Contains(db.Message, "coolify-sentinel") || strings.Contains(db.Message, "coolify-proxy-error-pages") {
		t.Errorf("platform containers counted as other projects: %q", db.Message)
	}
	// An app of a user project on the platform network still shares it
	// with the platform database.
	if r := rs["container:billing/api"]; r.Level != Fail || !strings.Contains(r.Message, "source/postgres") {
		t.Errorf("app on the platform network: %s %q", r.Level, r.Message)
	}
}

func TestStoppedContainersAreNotLiveFindings(t *testing.T) {
	initC := app("storage-init", func(c *facts.DockerContainer) {
		c.Image, c.User, c.Running = "busybox:1.36", "", false
		c.PidMode = "host"
		c.Mounts = []facts.DockerMount{{Type: "bind", Source: "/", Target: "/host", ReadOnly: true}}
	})
	live := app("worker", func(c *facts.DockerContainer) { c.User = "" })
	in := Input{Facts: dockerHost(initC, live)}
	for name, check := range map[string]func(Input) []Result{
		"DKR-010": checkSocketMounted, "DKR-012": checkHostBinds, "DKR-020": checkContainerRoot, "DKR-023": checkHostNamespaces,
	} {
		r := bySubject(check(in))["container:storage-init"]
		if r.Level != Info || !strings.Contains(r.Message, "only when it starts") || r.Evidence["running"] != false {
			t.Errorf("%s stopped: %s %q", name, r.Level, r.Message)
		}
	}
	if r := bySubject(checkContainerRoot(in))["container:worker"]; r.Level != Warn {
		t.Errorf("running root worker: %s", r.Level)
	}
}

func TestPrivilegeDroppingImages(t *testing.T) {
	cases := []struct {
		image string
		mod   func(*facts.DockerContainer)
		want  Level
	}{
		{"postgres:16-alpine", nil, Info},
		{"docker.io/library/postgres:16", nil, Info},
		{"valkey/valkey:8", nil, Info},
		{"redis:7@sha256:" + strings.Repeat("a", 64), nil, Info},
		{"mariadb:11", nil, Info},
		{"mongo:7", nil, Info},
		{"mysql:8.4", nil, Info},
		{"ghcr.io/example/postgres-backup:1", nil, Warn},
		{"postgres:16", func(c *facts.DockerContainer) { c.Privileged = true }, Fail},
		{"redis:7", func(c *facts.DockerContainer) {
			c.Ports = []facts.DockerPort{{ContainerPort: 6379, Proto: "tcp", HostPort: 6379}}
		}, Fail},
		{"postgres:16", func(c *facts.DockerContainer) { c.User = "root" }, Warn},
	}
	for _, tc := range cases {
		c := app("db", func(c *facts.DockerContainer) { c.Image, c.User = tc.image, "" })
		if tc.mod != nil {
			tc.mod(&c)
		}
		rs := checkContainerRoot(Input{Facts: dockerHost(c)})
		if got := only(t, rs); got != tc.want {
			t.Errorf("%s: got %s %q, want %s", tc.image, got, rs[0].Message, tc.want)
		}
	}
	rs := checkContainerRoot(Input{Facts: dockerHost(app("db", func(c *facts.DockerContainer) { c.Image, c.User = "postgres:16-alpine", "" }))})
	if !strings.Contains(rs[0].Message, "drops to the postgres user; set user: to make it explicit") {
		t.Errorf("message: %q", rs[0].Message)
	}
}

func TestSocketMountMessageForParentFolder(t *testing.T) {
	c := app("alloy", func(c *facts.DockerContainer) {
		c.Mounts = []facts.DockerMount{{Type: "bind", Source: "/", Target: "/host/root", ReadOnly: true}}
	})
	rs := checkSocketMounted(Input{Facts: dockerHost(c)})
	msg := rs[0].Message
	if only(t, rs) != Fail || !strings.Contains(msg, "mounts / (read only), which includes the Docker socket") ||
		!strings.Contains(msg, "a read only mount does not stop connecting to a socket") || strings.Contains(msg, "mounts the Docker socket (/") {
		t.Errorf("got %s %q", rs[0].Level, msg)
	}
}
