package facts

import (
	"context"
	"errors"
	"fmt"
	"io/fs"
	"slices"
	"sort"
	"strconv"
	"strings"
)

// Secrets is metadata (mode, owner, group) of secret bearing files, found
// by name in well known places (SEC group, and BAK-002 for backup tool
// configs). Contents are never read: the collector only lists directories
// and calls System.Meta.
type Secrets struct {
	// PaaSEnvFiles are app and service .env files a platform writes on
	// every deploy (SEC-001).
	PaaSEnvFiles SecretScan `json:"paas_env_files"`
	// PaaSMainEnv is the platform's own main .env (SEC-002).
	PaaSMainEnv SecretScan `json:"paas_main_env"`
	// PaaSSSHKeys is the platform's SSH key folder (Kind "dir") and the
	// files in it (Kind "key") (SEC-003).
	PaaSSSHKeys SecretScan `json:"paas_ssh_keys"`
	// ProxyDynamic lists the files in the proxy's dynamic config folders
	// (SEC-004). Roots are the folders.
	ProxyDynamic SecretScan `json:"proxy_dynamic"`
	// PrivateKeys are private key looking files under /root and /home
	// (Kind "ssh", "key" or "pem") (SEC-005). Roots are the homes walked.
	PrivateKeys SecretScan `json:"private_keys"`
	// DockerConfigs are ~/.docker/config.json files (SEC-006).
	DockerConfigs SecretScan `json:"docker_configs"`
	// WorldWritable are world writable directories under the platform data
	// roots (SEC-007). Roots are the data roots walked.
	WorldWritable SecretScan `json:"world_writable"`
	// BackupConfigs are restic, borg, borgmatic and rclone config files or
	// folders (Kind is the tool) (BAK-002).
	BackupConfigs SecretScan `json:"backup_configs"`
	// BackupTools are backup programs found on the command PATH.
	BackupTools []string `json:"backup_tools"`
}

// SecretScan is one search. Roots empty means there was nothing to search
// (for example no platform installed), which checks report as skip.
type SecretScan struct {
	// Roots are the existing places that were searched.
	Roots []string `json:"roots"`
	// Files are the matches, sorted by path.
	Files []SecretFile `json:"files"`
	// Denied are places that exist but could not be listed or inspected.
	Denied []string `json:"denied,omitempty"`
	// Truncated is true when the search stopped at its entry cap.
	Truncated bool `json:"truncated,omitempty"`
}

// SecretFile is the metadata of one matched path.
type SecretFile struct {
	Path string `json:"path"`
	Kind string `json:"kind,omitempty"`
	Mode Perm   `json:"mode"`
	UID  int    `json:"uid"`
	GID  int    `json:"gid"`
	// Platform names the platform the file belongs to, when there is one.
	Platform string `json:"platform,omitempty"`
}

// Perm is a permission mode (rwx bits plus setuid, setgid and sticky),
// encoded in JSON as an octal string such as "0640" for readable fixtures.
type Perm uint32

// PermOf converts an fs.FileMode to the classic octal permission bits.
func PermOf(m fs.FileMode) Perm {
	p := Perm(m.Perm())
	if m&fs.ModeSetuid != 0 {
		p |= 0o4000
	}
	if m&fs.ModeSetgid != 0 {
		p |= 0o2000
	}
	if m&fs.ModeSticky != 0 {
		p |= 0o1000
	}
	return p
}

// String formats the mode as four octal digits.
func (p Perm) String() string { return fmt.Sprintf("%04o", uint32(p)) }

// MarshalJSON implements json.Marshaler.
func (p Perm) MarshalJSON() ([]byte, error) { return []byte(strconv.Quote(p.String())), nil }

// UnmarshalJSON implements json.Unmarshaler.
func (p *Perm) UnmarshalJSON(b []byte) error {
	s, err := strconv.Unquote(string(b))
	if err != nil {
		return fmt.Errorf("mode: want an octal string such as \"0640\": %w", err)
	}
	v, err := strconv.ParseUint(s, 8, 32)
	if err != nil || v > 0o7777 {
		return fmt.Errorf("mode %q: not an octal permission", s)
	}
	*p = Perm(v)
	return nil
}

// GroupOrOtherReadable reports whether anyone but the owner can read.
func (p Perm) GroupOrOtherReadable() bool { return p&0o044 != 0 }

// OtherReadable reports whether any user can read.
func (p Perm) OtherReadable() bool { return p&0o004 != 0 }

// OtherWritable reports whether any user can write.
func (p Perm) OtherWritable() bool { return p&0o002 != 0 }

// Walk limits. A secrets search that needs more is looking in the wrong place.
const (
	secretWalkCap  = 50000
	homeWalkDepth  = 4
	paasWalkDepth  = 5
	envWalkDepth   = 4
	homesDir       = "/home"
	rootHome       = "/root"
	dockerConfigRP = ".docker/config.json"
)

// IsPaaSKeyName reports whether a file in a platform SSH key folder can be a
// private key. Coolify keeps each key as ssh_key@<id> and takes a flock on
// ssh_key@<id>.lock beside it while writing; Dokploy keeps <name>_rsa and
// <name>_rsa.pub. Public halves, lock files and the ssh client's own files
// are not keys.
func IsPaaSKeyName(name string) bool {
	lower := strings.ToLower(name)
	for _, suffix := range []string{".pub", ".lock", ".tmp"} {
		if strings.HasSuffix(lower, suffix) {
			return false
		}
	}
	switch {
	case strings.HasPrefix(lower, "known_hosts"), lower == "config", lower == "authorized_keys":
		return false
	}
	return true
}

// homeSkipDirs are never descended into when looking for keys: they are
// large and hold dependencies, not a user's keys.
var homeSkipDirs = map[string]bool{
	"node_modules": true, ".git": true, ".cache": true, ".npm": true, ".pnpm-store": true,
	".local": true, ".cargo": true, ".rustup": true, "go": true, ".vscode-server": true,
	"snap": true, ".nvm": true, ".bun": true,
}

// backupTools are looked up on the command PATH (BAK-002).
var backupTools = []string{"borg", "borgmatic", "kopia", "rclone", "restic", "resticprofile"}

// System wide backup tool configs. rclone keeps its config in
// ~/.config/rclone/rclone.conf (https://rclone.org/docs/#config-file),
// borgmatic in /etc/borgmatic/config.yaml or /etc/borgmatic.d
// (https://torsion.org/borgmatic/docs/how-to/set-up-backups/), borg its
// keys and security data in ~/.config/borg (https://borgbackup.readthedocs.io/en/stable/usage/general.html#environment-variables).
// restic has no config file; /etc/restic is a common home for its env files.
var systemBackupConfigs = []struct{ path, kind string }{
	{"/etc/borgmatic/config.yaml", "borgmatic"},
	{"/etc/borgmatic.d", "borgmatic"},
	{"/etc/restic", "restic"},
	{"/etc/resticprofile", "resticprofile"},
	{"/etc/rclone.conf", "rclone"},
}

var homeBackupConfigs = []struct{ rel, kind string }{
	{".config/rclone/rclone.conf", "rclone"},
	{".config/borg", "borg"},
	{".config/borgmatic/config.yaml", "borgmatic"},
}

type secretsCollector struct{}

func init() { Register(secretsCollector{}) }

func (secretsCollector) Name() string    { return "secrets" }
func (secretsCollector) NeedsRoot() bool { return false }

func (secretsCollector) Collect(ctx context.Context, sys System, out *Facts) error {
	s := &Secrets{BackupTools: []string{}}
	coolify, dokploy := dirExists(sys, CoolifyRoot), dirExists(sys, DokployRoot)

	// SEC-001: app and service .env files.
	var envRoots []rootOf
	if coolify {
		envRoots = append(envRoots, rootOf{CoolifyApplications, PlatformCoolify}, rootOf{CoolifyServices, PlatformCoolify})
	}
	if dokploy {
		envRoots = append(envRoots, rootOf{DokployApplications, PlatformDokploy}, rootOf{DokployCompose, PlatformDokploy})
	}
	s.PaaSEnvFiles = scanTrees(sys, envRoots, envWalkDepth, func(_ string, e fs.DirEntry) (string, bool) {
		return "env", e.Type().IsRegular() && IsEnvFileName(e.Name())
	}, nil)

	// SEC-002: Coolify's main .env (Dokploy passes its env to the service
	// and keeps no main .env on the host).
	if coolify {
		s.PaaSMainEnv = scanPaths(sys, []pathOf{{CoolifyMainEnv, "env", PlatformCoolify}})
	} else {
		s.PaaSMainEnv = emptyScan()
	}

	// SEC-003: the SSH key folder and its files.
	var keyDirs []pathOf
	if coolify {
		keyDirs = append(keyDirs, pathOf{CoolifySSHKeys, "dir", PlatformCoolify})
	}
	if dokploy {
		keyDirs = append(keyDirs, pathOf{DokploySSH, "dir", PlatformDokploy})
	}
	s.PaaSSSHKeys = scanPaths(sys, keyDirs)
	for _, d := range keyDirs {
		files := scanTrees(sys, []rootOf{{d.path, d.platform}}, 1, func(_ string, e fs.DirEntry) (string, bool) {
			return "key", e.Type().IsRegular() && IsPaaSKeyName(e.Name())
		}, nil)
		s.PaaSSSHKeys.Files = append(s.PaaSSSHKeys.Files, files.Files...)
		s.PaaSSSHKeys.Denied = appendUnique(s.PaaSSSHKeys.Denied, files.Denied...)
	}
	sortScan(&s.PaaSSSHKeys)

	// SEC-004: everything in the proxy dynamic folders; the check decides
	// which names look like stray backups.
	var dyn []rootOf
	if coolify {
		dyn = append(dyn, rootOf{CoolifyProxyDynamic, PlatformCoolify}, rootOf{CoolifyCaddyDynamic, PlatformCoolify})
	}
	if dokploy {
		dyn = append(dyn, rootOf{DokployProxyDynamic, PlatformDokploy})
	}
	s.ProxyDynamic = scanTrees(sys, dyn, 1, func(_ string, e fs.DirEntry) (string, bool) {
		return "config", e.Type().IsRegular()
	}, nil)

	// SEC-005 and SEC-006: homes.
	homes := homeDirs(sys)
	s.PrivateKeys = scanTrees(sys, homes, homeWalkDepth, func(_ string, e fs.DirEntry) (string, bool) {
		if !e.Type().IsRegular() {
			return "", false
		}
		k := privateKeyKind(e.Name())
		return k, k != ""
	}, homeSkipDirs)
	var dockerCfgs []pathOf
	for _, h := range homes {
		dockerCfgs = append(dockerCfgs, pathOf{h.path + "/" + dockerConfigRP, "docker", ""})
	}
	s.DockerConfigs = scanPaths(sys, dockerCfgs)
	// The homes themselves are the roots searched, even where no file exists.
	s.DockerConfigs.Roots = rootPaths(homes)

	// SEC-007: world writable directories under the platform data roots.
	var dataRoots []rootOf
	if coolify {
		dataRoots = append(dataRoots, rootOf{CoolifyRoot, PlatformCoolify})
	}
	if dokploy {
		dataRoots = append(dataRoots, rootOf{DokployRoot, PlatformDokploy})
	}
	s.WorldWritable = scanTrees(sys, dataRoots, paasWalkDepth, func(path string, e fs.DirEntry) (string, bool) {
		if !e.IsDir() || e.Type()&fs.ModeSymlink != 0 {
			return "", false
		}
		m, err := sys.Meta(path)
		return "dir", err == nil && PermOf(m.Mode).OtherWritable()
	}, nil)

	// BAK-002: backup tool configs and binaries.
	var bak []pathOf
	for _, c := range systemBackupConfigs {
		bak = append(bak, pathOf{c.path, c.kind, ""})
	}
	for _, h := range homes {
		for _, c := range homeBackupConfigs {
			bak = append(bak, pathOf{h.path + "/" + c.rel, c.kind, ""})
		}
	}
	s.BackupConfigs = scanPaths(sys, bak)
	for _, t := range backupTools {
		if _, err := sys.LookPath(t); err == nil {
			s.BackupTools = append(s.BackupTools, t)
		}
	}

	out.Secrets = s
	return ctx.Err()
}

type rootOf struct{ path, platform string }

type pathOf struct{ path, kind, platform string }

func emptyScan() SecretScan { return SecretScan{Roots: []string{}, Files: []SecretFile{}} }

func rootPaths(rs []rootOf) []string {
	out := []string{}
	for _, r := range rs {
		out = append(out, r.path)
	}
	return out
}

// homeDirs returns /root and every directory directly under /home that
// exists. Unlistable homes are still returned so the scan records the
// denial.
func homeDirs(sys System) []rootOf {
	var out []rootOf
	if _, err := sys.Meta(rootHome); err == nil {
		out = append(out, rootOf{rootHome, ""})
	}
	entries, err := sys.ReadDir(homesDir)
	if err != nil {
		return out
	}
	for _, e := range entries {
		if e.IsDir() && e.Type()&fs.ModeSymlink == 0 {
			out = append(out, rootOf{homesDir + "/" + e.Name(), ""})
		}
	}
	return out
}

// scanPaths stats individual paths. Absent paths are dropped silently; a
// permission error lands in Denied. Roots are the paths whose parent
// exists, so "the platform has no such file" and "nothing to look at"
// stay distinct.
func scanPaths(sys System, paths []pathOf) SecretScan {
	s := emptyScan()
	for _, p := range paths {
		m, err := sys.Meta(p.path)
		switch {
		case err == nil:
			s.Roots = appendUnique(s.Roots, p.path)
			s.Files = append(s.Files, fileOf(p.path, p.kind, p.platform, m))
		case errors.Is(err, fs.ErrPermission):
			s.Roots = appendUnique(s.Roots, p.path)
			s.Denied = appendUnique(s.Denied, p.path)
		default:
			if parent := parentDir(p.path); parent != "" {
				if _, perr := sys.Meta(parent); perr == nil {
					s.Roots = appendUnique(s.Roots, p.path)
				}
			}
		}
	}
	sortScan(&s)
	return s
}

// scanTrees walks each existing root and records the entries match accepts.
func scanTrees(sys System, roots []rootOf, depth int, match func(path string, e fs.DirEntry) (string, bool), skip map[string]bool) SecretScan {
	s := emptyScan()
	visited := 0
	for _, r := range roots {
		if _, err := sys.Meta(r.path); err != nil {
			if errors.Is(err, fs.ErrPermission) {
				s.Roots = appendUnique(s.Roots, r.path)
				s.Denied = appendUnique(s.Denied, r.path)
			}
			continue
		}
		s.Roots = appendUnique(s.Roots, r.path)
		walkTree(sys, r.path, depth, skip, func(path string, e fs.DirEntry) bool {
			visited++
			if visited > secretWalkCap {
				s.Truncated = true
				return false
			}
			kind, ok := match(path, e)
			if !ok {
				return true
			}
			m, err := sys.Meta(path)
			if err != nil {
				s.Denied = appendUnique(s.Denied, path)
				return true
			}
			s.Files = append(s.Files, fileOf(path, kind, r.platform, m))
			return true
		}, func(path string, _ error) {
			s.Denied = appendUnique(s.Denied, path)
		})
		if s.Truncated {
			break
		}
	}
	sortScan(&s)
	return s
}

func fileOf(path, kind, platform string, m FileMeta) SecretFile {
	return SecretFile{Path: path, Kind: kind, Mode: PermOf(m.Mode), UID: m.UID, GID: m.GID, Platform: platform}
}

func sortScan(s *SecretScan) {
	sort.Slice(s.Files, func(i, j int) bool { return s.Files[i].Path < s.Files[j].Path })
	sort.Strings(s.Denied)
}

func appendUnique(list []string, items ...string) []string {
	for _, it := range items {
		dup := false
		for _, l := range list {
			if l == it {
				dup = true
				break
			}
		}
		if !dup {
			list = append(list, it)
		}
	}
	return list
}

func parentDir(p string) string {
	i := strings.LastIndex(p, "/")
	if i <= 0 {
		return ""
	}
	return p[:i]
}

// EnvTemplateNames are the .env.<name> suffixes of templates that hold no
// values; IsEnvFileName skips them, and so does the paas-env-perms step.
var EnvTemplateNames = []string{"example", "sample", "template", "dist", "defaults"}

// IsEnvFileName matches ".env" and ".env.<stage>", but not templates that
// hold no values (.env.example, .env.sample, .env.template, .env.dist).
func IsEnvFileName(name string) bool {
	if name == ".env" {
		return true
	}
	rest, ok := strings.CutPrefix(name, ".env.")
	if !ok || rest == "" {
		return false
	}
	return !slices.Contains(EnvTemplateNames, rest)
}

// privateKeyKind classifies a file name as a likely private key: OpenSSH
// default key names without .pub ("ssh"), *.key ("key") and *.pem ("pem",
// which may also be a certificate; the check says so). Empty means no.
func privateKeyKind(name string) string {
	switch {
	case strings.HasPrefix(name, "id_") && !strings.HasSuffix(name, ".pub") &&
		!strings.HasSuffix(name, "-cert") && !strings.Contains(name, "-cert."):
		return "ssh"
	case strings.HasSuffix(name, ".key"):
		return "key"
	case strings.HasSuffix(name, ".pem"):
		return "pem"
	}
	return ""
}
