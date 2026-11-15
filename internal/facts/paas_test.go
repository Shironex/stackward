package facts

import (
	"context"
	"encoding/json"
	"io/fs"
	"reflect"
	"strings"
	"testing"
	"testing/fstest"
	"time"
)

// lockedSystem is a fakeSystem where some directories cannot be listed and
// nothing below them can be stat'ed, like chmod 700 folders seen by a non
// root user. The locked directory itself can still be stat'ed.
type lockedSystem struct {
	*fakeSystem
	locked []string
}

func (s *lockedSystem) under(p string, inclusive bool) bool {
	for _, l := range s.locked {
		if (inclusive && p == l) || strings.HasPrefix(p, l+"/") {
			return true
		}
	}
	return false
}

func (s *lockedSystem) ReadDir(p string) ([]fs.DirEntry, error) {
	if s.under(p, true) {
		return nil, &fs.PathError{Op: "open", Path: p, Err: fs.ErrPermission}
	}
	return s.fakeSystem.ReadDir(p)
}

func (s *lockedSystem) Meta(p string) (FileMeta, error) {
	if s.under(p, false) {
		return FileMeta{}, &fs.PathError{Op: "lstat", Path: p, Err: fs.ErrPermission}
	}
	return s.fakeSystem.Meta(p)
}

// tree builds a fakeSystem from path to mode; a mode with fs.ModeDir makes
// an explicit directory.
func tree(entries map[string]fs.FileMode) *fakeSystem {
	sys := newFakeSystem(nil)
	for p, m := range entries {
		sys.files[strings.TrimPrefix(p, "/")] = &fstest.MapFile{Mode: m, ModTime: time.Unix(1767225600, 0)}
	}
	return sys
}

const dir = fs.ModeDir

func coolifyPanelTree() map[string]fs.FileMode {
	return map[string]fs.FileMode{
		"/data/coolify":                                dir | 0o700,
		"/data/coolify/source":                         dir | 0o700,
		"/data/coolify/source/docker-compose.yml":      0o600,
		"/data/coolify/source/.env":                    0o640,
		"/data/coolify/ssh/keys":                       dir | 0o755,
		"/data/coolify/ssh/keys/ssh_key@example1":      0o600,
		"/data/coolify/ssh/keys/ssh_key@example2":      0o644,
		"/data/coolify/ssh/keys/ssh_key@example.pub":   0o644,
		"/data/coolify/applications/app1/.env":         0o644,
		"/data/coolify/applications/app2/.env":         0o600,
		"/data/coolify/applications/app2/.env.example": 0o644,
		"/data/coolify/services/svc1/.env.production":  0o640,
		"/data/coolify/proxy/dynamic":                  dir | 0o700,
		"/data/coolify/proxy/dynamic/app.yml":          0o644,
		"/data/coolify/proxy/dynamic/app.backup.yml":   0o644,
		"/data/coolify/backups/coolify/db-1.dmp":       0o600,
		"/data/coolify/backups/coolify/db-2.dmp":       0o600,
		"/data/coolify/webhooks-during-maintenance":    dir | 0o777,
	}
}

func TestPaaSCollectorCoolifyPanel(t *testing.T) {
	sys := tree(coolifyPanelTree())
	out := &Facts{}
	if err := (paasCollector{}).Collect(context.Background(), sys, out); err != nil {
		t.Fatal(err)
	}
	if len(out.PaaS.Platforms) != 1 {
		t.Fatalf("platforms = %+v", out.PaaS.Platforms)
	}
	pl := out.PaaS.Platforms[0]
	if pl.Name != PlatformCoolify || pl.Role != RolePanel || pl.DataRoot != CoolifyRoot {
		t.Errorf("platform = %+v", pl)
	}
	if want := []string{"path:/data/coolify", "path:/data/coolify/source/docker-compose.yml"}; !reflect.DeepEqual(pl.Evidence, want) {
		t.Errorf("evidence = %v, want %v", pl.Evidence, want)
	}
	if want := []string{CoolifyProxyDynamic}; !reflect.DeepEqual(pl.ProxyDynamicDirs, want) {
		t.Errorf("dynamic dirs = %v", pl.ProxyDynamicDirs)
	}
	if pl.Backups == nil || !pl.Backups.Readable || pl.Backups.Files != 2 || !pl.Backups.Newest.Equal(time.Unix(1767225600, 0)) {
		t.Errorf("backups = %+v", pl.Backups)
	}
}

func TestPaaSCollectorManagedAndNone(t *testing.T) {
	sys := tree(map[string]fs.FileMode{"/data/coolify/proxy/dynamic": dir | 0o700})
	out := &Facts{}
	_ = (paasCollector{}).Collect(context.Background(), sys, out)
	if got := out.PaaS.Platforms[0].Role; got != RoleManaged {
		t.Errorf("role = %q, want managed", got)
	}

	out = &Facts{}
	_ = (paasCollector{}).Collect(context.Background(), newFakeSystem(nil), out)
	if out.PaaS == nil || out.PaaS.Platforms == nil || len(out.PaaS.Platforms) != 0 {
		t.Errorf("no platform must record an empty list, got %+v", out.PaaS)
	}
	b, _ := json.Marshal(out.PaaS)
	if string(b) != `{"platforms":[]}` {
		t.Errorf("json = %s", b)
	}
}

func TestPaaSCollectorNonRoot(t *testing.T) {
	// The documented chmod -R 700 hides everything below /data/coolify.
	sys := &lockedSystem{fakeSystem: tree(coolifyPanelTree()), locked: []string{"/data/coolify"}}
	out := &Facts{}
	_ = (paasCollector{}).Collect(context.Background(), sys, out)
	pl := out.PaaS.Platforms[0]
	if pl.Role != RoleUnknown {
		t.Errorf("role = %q, want unknown", pl.Role)
	}
	for _, want := range []string{CoolifyCompose, CoolifyProxyDynamic, CoolifyBackups} {
		found := false
		for _, d := range pl.Denied {
			found = found || d == want
		}
		if !found {
			t.Errorf("denied %v lacks %s", pl.Denied, want)
		}
	}
	if pl.Backups == nil || pl.Backups.Readable {
		t.Errorf("backups = %+v, want present and unreadable", pl.Backups)
	}
}

func TestPaaSCollectorDokployAndUnits(t *testing.T) {
	sys := tree(map[string]fs.FileMode{
		"/etc/dokploy":                          dir | 0o755,
		"/etc/dokploy/traefik/traefik.yml":      0o644,
		"/etc/dokploy/traefik/dynamic":          dir | 0o755,
		"/etc/systemd/system/coolify-x.service": 0o644,
		"/etc/systemd/system/other.service":     0o644,
	})
	out := &Facts{}
	_ = (paasCollector{}).Collect(context.Background(), sys, out)
	if len(out.PaaS.Platforms) != 2 {
		t.Fatalf("platforms = %+v", out.PaaS.Platforms)
	}
	c, d := out.PaaS.Platforms[0], out.PaaS.Platforms[1]
	if c.Name != PlatformCoolify || !reflect.DeepEqual(c.Evidence, []string{"unit:coolify-x.service"}) {
		t.Errorf("coolify from unit = %+v", c)
	}
	if d.Name != PlatformDokploy || d.Role != RoleUnknown || d.Backups != nil ||
		!reflect.DeepEqual(d.ProxyDynamicDirs, []string{DokployProxyDynamic}) {
		t.Errorf("dokploy = %+v", d)
	}
}

func TestSecretsCollector(t *testing.T) {
	entries := coolifyPanelTree()
	for p, m := range map[string]fs.FileMode{
		"/root/.ssh/id_ed25519":                  0o600,
		"/root/.ssh/id_ed25519.pub":              0o644,
		"/home/alice/.ssh/id_rsa":                0o640,
		"/home/alice/certs/site.pem":             0o644,
		"/home/alice/certs/site.key":             0o600,
		"/home/alice/node_modules/x/a.key":       0o644, // skipped folder
		"/home/alice/.docker/config.json":        0o644,
		"/home/alice/.config/rclone/rclone.conf": 0o600,
		"/etc/borgmatic/config.yaml":             0o600,
	} {
		entries[p] = m
	}
	sys := tree(entries)
	sys.cmds["restic version"] = CmdResult{}
	out := &Facts{}
	if err := (secretsCollector{}).Collect(context.Background(), sys, out); err != nil {
		t.Fatal(err)
	}
	s := out.Secrets
	paths := func(sc SecretScan) []string {
		var ps []string
		for _, f := range sc.Files {
			ps = append(ps, f.Kind+" "+f.Path+" "+f.Mode.String())
		}
		return ps
	}
	cases := []struct {
		name string
		got  []string
		want []string
	}{
		{"env", paths(s.PaaSEnvFiles), []string{
			"env /data/coolify/applications/app1/.env 0644",
			"env /data/coolify/applications/app2/.env 0600",
			"env /data/coolify/services/svc1/.env.production 0640",
		}},
		{"main env", paths(s.PaaSMainEnv), []string{"env /data/coolify/source/.env 0640"}},
		{"ssh keys", paths(s.PaaSSSHKeys), []string{
			"dir /data/coolify/ssh/keys 0755",
			"key /data/coolify/ssh/keys/ssh_key@example1 0600",
			"key /data/coolify/ssh/keys/ssh_key@example2 0644",
		}},
		{"dynamic", paths(s.ProxyDynamic), []string{
			"config /data/coolify/proxy/dynamic/app.backup.yml 0644",
			"config /data/coolify/proxy/dynamic/app.yml 0644",
		}},
		{"keys", paths(s.PrivateKeys), []string{
			"pem /home/alice/certs/site.pem 0644",
			"key /home/alice/certs/site.key 0600",
			"ssh /home/alice/.ssh/id_rsa 0640",
			"ssh /root/.ssh/id_ed25519 0600",
		}},
		{"docker", paths(s.DockerConfigs), []string{"docker /home/alice/.docker/config.json 0644"}},
		{"world writable", paths(s.WorldWritable), []string{"dir /data/coolify/webhooks-during-maintenance 0777"}},
		{"backup", paths(s.BackupConfigs), []string{
			"borgmatic /etc/borgmatic/config.yaml 0600",
			"rclone /home/alice/.config/rclone/rclone.conf 0600",
		}},
	}
	for _, c := range cases {
		// Sorted by path in the facts; compare as sets of lines.
		if !sameSet(c.got, c.want) {
			t.Errorf("%s:\n got %v\nwant %v", c.name, c.got, c.want)
		}
	}
	if !reflect.DeepEqual(s.BackupTools, []string{"restic"}) {
		t.Errorf("tools = %v", s.BackupTools)
	}
	if want := []string{"/root", "/home/alice"}; !sameSet(s.PrivateKeys.Roots, want) {
		t.Errorf("key roots = %v", s.PrivateKeys.Roots)
	}
}

func TestSecretsCollectorNoPlatform(t *testing.T) {
	out := &Facts{}
	_ = (secretsCollector{}).Collect(context.Background(), newFakeSystem(nil), out)
	s := out.Secrets
	for name, sc := range map[string]SecretScan{"env": s.PaaSEnvFiles, "main": s.PaaSMainEnv, "keys": s.PaaSSSHKeys,
		"dyn": s.ProxyDynamic, "ww": s.WorldWritable, "homes": s.PrivateKeys} {
		if sc.Roots == nil || len(sc.Roots) != 0 || sc.Files == nil {
			t.Errorf("%s: want empty, non nil roots and files, got %+v", name, sc)
		}
	}
}

func TestSecretsCollectorDenied(t *testing.T) {
	sys := &lockedSystem{fakeSystem: tree(coolifyPanelTree()), locked: []string{"/data/coolify"}}
	out := &Facts{}
	_ = (secretsCollector{}).Collect(context.Background(), sys, out)
	s := out.Secrets
	if !reflect.DeepEqual(s.PaaSMainEnv.Denied, []string{CoolifyMainEnv}) || len(s.PaaSMainEnv.Files) != 0 {
		t.Errorf("main env = %+v", s.PaaSMainEnv)
	}
	if !reflect.DeepEqual(s.PaaSEnvFiles.Denied, []string{CoolifyApplications, CoolifyServices}) {
		t.Errorf("env denied = %v", s.PaaSEnvFiles.Denied)
	}
	if !reflect.DeepEqual(s.WorldWritable.Denied, []string{CoolifyRoot}) {
		t.Errorf("world writable denied = %v", s.WorldWritable.Denied)
	}
}

func TestPermJSON(t *testing.T) {
	var p Perm
	if err := json.Unmarshal([]byte(`"1777"`), &p); err != nil || p != 0o1777 {
		t.Fatalf("p=%o err=%v", p, err)
	}
	b, _ := json.Marshal(Perm(0o640))
	if string(b) != `"0640"` {
		t.Errorf("marshal = %s", b)
	}
	for _, bad := range []string{`640`, `"9"`, `"17777"`} {
		if err := json.Unmarshal([]byte(bad), &p); err == nil {
			t.Errorf("%s: want error", bad)
		}
	}
	if PermOf(fs.ModeSticky|fs.ModeSetgid|0o755) != 0o3755 {
		t.Errorf("PermOf lost special bits")
	}
}

func TestNameClassifiers(t *testing.T) {
	for name, want := range map[string]bool{".env": true, ".env.production": true, ".env.example": false, ".envrc": false, "env": false, ".env.": false} {
		if isEnvFileName(name) != want {
			t.Errorf("isEnvFileName(%q) != %v", name, want)
		}
	}
	for name, want := range map[string]string{"id_rsa": "ssh", "id_ed25519.pub": "", "id_ed25519-cert.pub": "", "tls.key": "key", "ca.pem": "pem", "known_hosts": ""} {
		if got := privateKeyKind(name); got != want {
			t.Errorf("privateKeyKind(%q) = %q, want %q", name, got, want)
		}
	}
}

func sameSet(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	m := map[string]int{}
	for _, x := range a {
		m[x]++
	}
	for _, x := range b {
		m[x]--
	}
	for _, v := range m {
		if v != 0 {
			return false
		}
	}
	return true
}
