package facts

import (
	"context"
	"errors"
	"io/fs"
	"sort"
	"strings"
	"time"
)

// PaaS is what the host disk says about self hosted platforms (Coolify,
// Dokploy): which are installed, in which role, where their data lives and
// what local backup evidence exists (PAAS and BAK groups).
//
// The collector only stats well known paths and lists directories; it never
// reads a file. Container labels, images and published ports come from the
// Docker facts, which the checks combine with this at evaluation time.
type PaaS struct {
	// Platforms lists every platform found. Empty (not nil) means none was
	// found, which is a real answer, not "not inspected".
	Platforms []Platform `json:"platforms"`
}

// Platform names.
const (
	PlatformCoolify = "coolify"
	PlatformDokploy = "dokploy"
)

// Platform roles.
const (
	RolePanel   = "panel"   // runs the control panel
	RoleManaged = "managed" // a server the panel deploys to
	RoleUnknown = "unknown" // installed, role not visible from the disk
)

// Platform is one detected platform.
type Platform struct {
	Name string `json:"name"`
	Role string `json:"role"`
	// DataRoot is the platform's data directory (/data/coolify, /etc/dokploy).
	DataRoot string `json:"data_root"`
	// Evidence lists what was found, as "path:<path>" or "unit:<name>".
	Evidence []string `json:"evidence"`
	// Denied lists well known paths that exist but could not be inspected
	// without more privilege, so the role may be incomplete.
	Denied []string `json:"denied,omitempty"`
	// ProxyDynamicDirs are the reverse proxy's dynamic config folders found.
	ProxyDynamicDirs []string `json:"proxy_dynamic_dirs,omitempty"`
	// Backups is local backup evidence, nil when the platform keeps no
	// backups on the host by design or the folder could not be read.
	Backups *BackupEvidence `json:"backups,omitempty"`
}

// BackupEvidence summarises a platform's local backup folder (names and
// times only, no contents).
type BackupEvidence struct {
	Dir string `json:"dir"`
	// Readable is false when the folder exists but could not be listed.
	Readable bool `json:"readable"`
	// Files counts regular files found (bounded walk).
	Files int `json:"files"`
	// Newest is the newest file modification time, zero when no files.
	Newest time.Time `json:"newest,omitzero"`
	// Truncated is true when the walk stopped at its entry cap.
	Truncated bool `json:"truncated,omitempty"`
}

// Well known platform paths, from the platforms' public documentation.
//
// Coolify: the manual install creates /data/coolify/{source,ssh,applications,
// databases,backups,services,proxy,webhooks-during-maintenance},
// /data/coolify/ssh/{keys,mux} and /data/coolify/proxy/dynamic, puts
// docker-compose.yml and .env in /data/coolify/source, then runs
// chown -R 9999:root and chmod -R 700 on /data/coolify.
// https://coolify.io/docs/start-with-self-hosted (Manual installation)
// Managed servers get /data/coolify (proxy, applications) but no source.
//
// Dokploy: data lives in /etc/dokploy; the Traefik container mounts
// /etc/dokploy/traefik/traefik.yml and /etc/dokploy/traefik/dynamic.
// https://docs.dokploy.com/docs/core/manual-installation
// The applications, compose and ssh folders under /etc/dokploy are the
// APPLICATIONS_PATH, COMPOSE_PATH and SSH_PATH of Dokploy's public source
// (packages/server/src/constants/index.ts).
const (
	CoolifyRoot          = "/data/coolify"
	CoolifySource        = "/data/coolify/source"
	CoolifyCompose       = "/data/coolify/source/docker-compose.yml"
	CoolifyMainEnv       = "/data/coolify/source/.env"
	CoolifySSHKeys       = "/data/coolify/ssh/keys"
	CoolifyApplications  = "/data/coolify/applications"
	CoolifyServices      = "/data/coolify/services"
	CoolifyBackups       = "/data/coolify/backups"
	CoolifyProxyDynamic  = "/data/coolify/proxy/dynamic"
	CoolifyCaddyDynamic  = "/data/coolify/proxy/caddy/dynamic"
	DokployRoot          = "/etc/dokploy"
	DokployTraefikConfig = "/etc/dokploy/traefik/traefik.yml"
	DokployProxyDynamic  = "/etc/dokploy/traefik/dynamic"
	DokployApplications  = "/etc/dokploy/applications"
	DokployCompose       = "/etc/dokploy/compose"
	DokploySSH           = "/etc/dokploy/ssh"
)

// unitDirs are where systemd unit files live. Neither platform ships a
// unit (both run as containers), but an operator added one is recorded.
var unitDirs = []string{"/etc/systemd/system", "/usr/lib/systemd/system", "/lib/systemd/system"}

// backupWalkCap bounds the backup folder walk.
const backupWalkCap = 20000

type paasCollector struct{}

func init() { Register(paasCollector{}) }

func (paasCollector) Name() string    { return "paas" }
func (paasCollector) NeedsRoot() bool { return false }

func (paasCollector) Collect(_ context.Context, sys System, out *Facts) error {
	p := &PaaS{Platforms: []Platform{}}
	units := platformUnits(sys)
	if pl := detectCoolify(sys, units[PlatformCoolify]); pl != nil {
		p.Platforms = append(p.Platforms, *pl)
	}
	if pl := detectDokploy(sys, units[PlatformDokploy]); pl != nil {
		p.Platforms = append(p.Platforms, *pl)
	}
	// Paths this run could not see are recorded per platform (Denied), so
	// a non root run is complete as far as it goes, not an error.
	out.PaaS = p
	return nil
}

// probe reports whether path exists. A permission error counts as
// "exists, denied"; any other error as absent.
func probe(sys System, path string) (exists, denied bool) {
	_, err := sys.Meta(path)
	switch {
	case err == nil:
		return true, false
	case errors.Is(err, fs.ErrPermission):
		return true, true
	}
	return false, false
}

// dirExists reports whether path exists and is a directory (not a link).
func dirExists(sys System, path string) bool {
	m, err := sys.Meta(path)
	return err == nil && m.Mode.IsDir()
}

func detectCoolify(sys System, units []string) *Platform {
	rootFound := dirExists(sys, CoolifyRoot)
	if !rootFound && len(units) == 0 {
		return nil
	}
	pl := &Platform{Name: PlatformCoolify, Role: RoleUnknown, DataRoot: CoolifyRoot}
	if rootFound {
		pl.Evidence = append(pl.Evidence, "path:"+CoolifyRoot)
	}
	for _, u := range units {
		pl.Evidence = append(pl.Evidence, "unit:"+u)
	}

	// The compose file under source/ only exists on the panel host. With
	// the documented chmod 700, a non root run cannot see inside, so the
	// role stays unknown and the denial is recorded.
	exists, denied := probe(sys, CoolifyCompose)
	switch {
	case exists && !denied:
		pl.Role = RolePanel
		pl.Evidence = append(pl.Evidence, "path:"+CoolifyCompose)
	case denied:
		pl.Denied = append(pl.Denied, CoolifyCompose)
	default:
		if _, err := sys.ReadDir(CoolifyRoot); err == nil {
			pl.Role = RoleManaged
		} else if errors.Is(err, fs.ErrPermission) {
			pl.Denied = append(pl.Denied, CoolifyRoot)
		}
	}
	for _, d := range []string{CoolifyProxyDynamic, CoolifyCaddyDynamic} {
		if dirExists(sys, d) {
			pl.ProxyDynamicDirs = append(pl.ProxyDynamicDirs, d)
		} else if _, denied := probe(sys, d); denied {
			addDenied(pl, d)
		}
	}
	if b := backupEvidence(sys, CoolifyBackups); b != nil {
		pl.Backups = b
	} else if _, denied := probe(sys, CoolifyBackups); denied {
		pl.Backups = &BackupEvidence{Dir: CoolifyBackups}
		addDenied(pl, CoolifyBackups)
	}
	return pl
}

func detectDokploy(sys System, units []string) *Platform {
	rootFound := dirExists(sys, DokployRoot)
	if !rootFound && len(units) == 0 {
		return nil
	}
	// Remote servers set up by Dokploy also get /etc/dokploy (Traefik
	// lives there), so the disk alone cannot tell panel from managed
	// server; the checks refine the role from the dokploy service when
	// Docker facts are present.
	pl := &Platform{Name: PlatformDokploy, Role: RoleUnknown, DataRoot: DokployRoot}
	if rootFound {
		pl.Evidence = append(pl.Evidence, "path:"+DokployRoot)
	}
	for _, u := range units {
		pl.Evidence = append(pl.Evidence, "unit:"+u)
	}
	if exists, denied := probe(sys, DokployTraefikConfig); exists && !denied {
		pl.Evidence = append(pl.Evidence, "path:"+DokployTraefikConfig)
	} else if denied {
		addDenied(pl, DokployTraefikConfig)
	}
	if dirExists(sys, DokployProxyDynamic) {
		pl.ProxyDynamicDirs = append(pl.ProxyDynamicDirs, DokployProxyDynamic)
	} else if _, denied := probe(sys, DokployProxyDynamic); denied {
		addDenied(pl, DokployProxyDynamic)
	}
	// Dokploy sends database backups to S3 destinations configured in the
	// panel; there is no local backup folder to look at.
	return pl
}

func addDenied(pl *Platform, path string) {
	for _, d := range pl.Denied {
		if d == path {
			return
		}
	}
	pl.Denied = append(pl.Denied, path)
}

// platformUnits finds systemd unit files whose name starts with a platform
// name.
func platformUnits(sys System) map[string][]string {
	out := map[string][]string{}
	seen := map[string]bool{}
	for _, dir := range unitDirs {
		entries, err := sys.ReadDir(dir)
		if err != nil {
			continue
		}
		for _, e := range entries {
			name := e.Name()
			if seen[name] {
				continue
			}
			for _, pl := range []string{PlatformCoolify, PlatformDokploy} {
				if strings.HasPrefix(name, pl) && (strings.HasSuffix(name, ".service") || strings.HasSuffix(name, ".timer")) {
					seen[name] = true
					out[pl] = append(out[pl], name)
				}
			}
		}
	}
	for k := range out {
		sort.Strings(out[k])
	}
	return out
}

// backupEvidence walks a backup folder counting files and the newest
// modification time. It returns nil when the folder is absent or denied.
func backupEvidence(sys System, dir string) *BackupEvidence {
	if _, err := sys.ReadDir(dir); err != nil {
		return nil
	}
	b := &BackupEvidence{Dir: dir, Readable: true}
	var newest int64
	visited := 0
	walkTree(sys, dir, 6, nil, func(path string, e fs.DirEntry) bool {
		visited++
		if visited > backupWalkCap {
			b.Truncated = true
			return false
		}
		if e.Type().IsRegular() {
			b.Files++
			if m, err := sys.Meta(path); err == nil && m.ModTime > newest {
				newest = m.ModTime
			}
		}
		return true
	}, nil)
	if newest > 0 {
		b.Newest = time.Unix(newest, 0).UTC()
	}
	return b
}

// walkTree visits every entry below root up to maxDepth levels, never
// following symlinks and never descending into directories named in skip.
// visit returns false to stop the whole walk. denied, when not nil, is
// called for directories that could not be listed.
func walkTree(sys System, root string, maxDepth int, skip map[string]bool, visit func(path string, e fs.DirEntry) bool, denied func(path string, err error)) {
	var walk func(dir string, depth int) bool
	walk = func(dir string, depth int) bool {
		entries, err := sys.ReadDir(dir)
		if err != nil {
			if denied != nil && !errors.Is(err, fs.ErrNotExist) {
				denied(dir, err)
			}
			return true
		}
		for _, e := range entries {
			p := strings.TrimSuffix(dir, "/") + "/" + e.Name()
			if !visit(p, e) {
				return false
			}
			if e.IsDir() && e.Type()&fs.ModeSymlink == 0 && depth < maxDepth && !skip[e.Name()] {
				if !walk(p, depth+1) {
					return false
				}
			}
		}
		return true
	}
	walk(root, 1)
}
