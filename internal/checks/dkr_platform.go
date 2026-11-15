package checks

import (
	"fmt"
	"path"
	"strings"

	"github.com/Shironex/stackward/internal/facts"
)

// Platform components and container state shared by the per container DKR
// checks.
//
// A PaaS installs its own containers (the Coolify panel stack, its proxy
// and sentinel; Dokploy's panel, database, Redis and Traefik) with settings
// the panel does not let a user change. stackward keeps reporting what they
// do, but says that the platform manages them and caps those findings at
// warn while the platform is detected. App containers keep their levels.

// platformComponents maps the container (or swarm service) names a platform
// gives its own containers to the platform.
var platformComponents = map[string]string{
	"coolify":                   facts.PlatformCoolify,
	"coolify-db":                facts.PlatformCoolify,
	"coolify-redis":             facts.PlatformCoolify,
	"coolify-realtime":          facts.PlatformCoolify,
	"coolify-proxy":             facts.PlatformCoolify,
	"coolify-proxy-error-pages": facts.PlatformCoolify,
	"coolify-sentinel":          facts.PlatformCoolify,
	"dokploy":                   facts.PlatformDokploy,
	"dokploy-postgres":          facts.PlatformDokploy,
	"dokploy-redis":             facts.PlatformDokploy,
	"dokploy-traefik":           facts.PlatformDokploy,
}

// platformTitles are the display names of the platforms.
var platformTitles = map[string]string{facts.PlatformCoolify: "Coolify", facts.PlatformDokploy: "Dokploy"}

// platformOf names the platform a container belongs to as one of its own
// components, or "". Dokploy runs its panel, database and Redis as swarm
// services, so the service name counts as well as the container name.
func platformOf(c facts.DockerContainer) string {
	if p, ok := platformComponents[strings.ToLower(c.Name)]; ok {
		return p
	}
	if c.Labels != nil {
		if p, ok := platformComponents[strings.ToLower(c.Labels["com.docker.swarm.service.name"])]; ok {
			return p
		}
	}
	return ""
}

// managedBy names the platform that manages c when c is one of its
// components and the platform is detected (on disk, or from its panel or
// managed containers), else "".
func managedBy(f *facts.Facts, c facts.DockerContainer) string {
	p := platformOf(c)
	if p == "" || f == nil || f.Docker == nil {
		return ""
	}
	containers, _ := paasContainersFrom(f.Docker)
	for _, pl := range paasPlatforms(f.PaaS, containers) {
		if pl.Name == p {
			return p
		}
	}
	return ""
}

// componentWhat says what a platform component is, for messages.
func componentWhat(c facts.DockerContainer) string {
	name := strings.ToLower(c.Name)
	switch {
	case strings.Contains(name, "sentinel"):
		return "its sentinel (metrics agent)"
	case roleOf(c) == roleProxy || strings.Contains(name, "proxy") || strings.Contains(name, "traefik"):
		return "its proxy"
	case roleOf(c) == roleDatabase || strings.Contains(name, "-db") || strings.Contains(name, "postgres") || strings.Contains(name, "redis"):
		return "its database"
	}
	return "its panel"
}

// containerCheck is the per container body of a DKR check.
type containerCheck func(d *facts.Docker, c facts.DockerContainer) Result

// posture wraps a per container check that judges how a container runs
// (user, privileges, namespaces, mounts):
//
//   - a container that is not running (a one shot init container that
//     exited, or a stopped one) is info, not a finding: the setting only
//     matters when it starts, and the message says so;
//   - a component of a detected platform keeps its finding but at most warn
//     (privileged stays a fail), with "managed by <platform>" in the
//     message.
//
// Evidence gains "running" and "managed_by" on every result.
func posture(in Input, fn containerCheck) containerCheck {
	return func(d *facts.Docker, c facts.DockerContainer) Result {
		r := fn(d, c)
		if r.Evidence == nil {
			r.Evidence = map[string]any{}
		}
		mgr := managedBy(in.Facts, c)
		r.Evidence["running"] = c.Running
		r.Evidence["managed_by"] = mgr
		if r.Level != Warn && r.Level != Fail {
			return r
		}
		if mgr != "" {
			if r.Level == Fail && !c.Privileged {
				r.Level = Warn
			}
			r.Message += fmt.Sprintf("; managed by %s as %s: expected, a platform default the panel does not let you change", platformTitles[mgr], componentWhat(c))
		}
		if !c.Running {
			r.Level = Info
			r.Message += "; this applies only when it starts (a one shot or stopped container)"
		}
		return r
	}
}

// privilegeDroppingImages are official images whose entrypoint starts as
// root only to fix ownership and then switches to their own user (gosu or
// su-exec), keyed by repository without registry or library prefix.
var privilegeDroppingImages = map[string]string{
	"postgres":        "postgres",
	"postgis/postgis": "postgres",
	"redis":           "redis",
	"valkey/valkey":   "valkey",
	"mysql":           "mysql",
	"mariadb":         "mysql",
	"mongo":           "mongodb",
}

// dropsTo returns the user an official image's entrypoint switches to, or
// "" when the image is not one of them.
func dropsTo(image string) string {
	repo, _, _ := imageRef(image)
	for _, p := range []string{"docker.io/", "index.docker.io/", "registry-1.docker.io/"} {
		repo = strings.TrimPrefix(repo, p)
	}
	repo = strings.TrimPrefix(repo, "library/")
	return privilegeDroppingImages[repo]
}

// socketMountText describes a mount that exposes the Docker socket: the
// socket itself, or a folder that holds it.
func socketMountText(m facts.DockerMount) string {
	src := path.Clean(m.Source)
	if strings.HasSuffix(src, "docker.sock") {
		return "the Docker socket (" + mountText(m) + ")"
	}
	ro := ""
	if m.ReadOnly {
		ro = " (read only)"
	}
	return fmt.Sprintf("%s%s, which includes the Docker socket", src, ro)
}
