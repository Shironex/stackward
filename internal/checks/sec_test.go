package checks

import (
	"strings"
	"testing"
	"time"

	"github.com/Shironex/stackward/internal/facts"
)

func secScanOf(roots []string, denied []string, files ...facts.SecretFile) facts.SecretScan {
	if files == nil {
		files = []facts.SecretFile{}
	}
	return facts.SecretScan{Roots: roots, Files: files, Denied: denied}
}

func secFile(path, kind string, mode facts.Perm) facts.SecretFile {
	return facts.SecretFile{Path: path, Kind: kind, Mode: mode}
}

func secEmpty() *facts.Secrets {
	e := secScanOf([]string{}, nil)
	return &facts.Secrets{PaaSEnvFiles: e, PaaSMainEnv: e, PaaSSSHKeys: e, ProxyDynamic: e, PrivateKeys: e,
		DockerConfigs: e, WorldWritable: e, BackupConfigs: e, BackupTools: []string{}}
}

var secCheckFuncs = map[string]func(Input) []Result{
	"SEC-001": checkPaaSEnvFiles, "SEC-002": checkPaaSMainEnv, "SEC-003": checkPaaSSSHKeys, "SEC-004": checkProxyDynamicStrays,
	"SEC-005": checkPrivateKeys, "SEC-006": checkDockerConfig, "SEC-007": checkPaaSWorldWritable,
}

func secRun(id string, s *facts.Secrets, root bool) string {
	f := &facts.Facts{Secrets: s, Host: &facts.Host{Root: root}}
	return paasLevels(EvaluateChecks([]Check{{ID: id, Run: secCheckFuncs[id]}}, Input{Facts: f}))
}

func TestSecChecksUnknownAndSkip(t *testing.T) {
	for id, run := range secCheckFuncs {
		if got := paasLevels(run(Input{Facts: &facts.Facts{}})); got != "=unknown" {
			t.Errorf("%s nil facts: %s", id, got)
		}
		if got := secRun(id, secEmpty(), true); got != "host=skip" {
			t.Errorf("%s nothing to search: %s", id, got)
		}
	}
}

func TestSecChecks(t *testing.T) {
	const apps = "/data/coolify/applications"
	cases := []struct {
		id   string
		set  func(*facts.Secrets)
		want string
	}{
		{"SEC-001", func(s *facts.Secrets) {
			s.PaaSEnvFiles = secScanOf([]string{apps}, nil, secFile(apps+"/a/.env", "env", 0o644), secFile(apps+"/b/.env", "env", 0o600))
		}, "file:/data/coolify/applications/a/.env=fail host=pass"},
		{"SEC-001", func(s *facts.Secrets) { s.PaaSEnvFiles = secScanOf([]string{apps}, nil) }, "host=pass"},
		{"SEC-001", func(s *facts.Secrets) { s.PaaSEnvFiles = secScanOf([]string{apps}, []string{apps}) }, "file:/data/coolify/applications=unknown"},
		{"SEC-002", func(s *facts.Secrets) {
			s.PaaSMainEnv = secScanOf([]string{facts.CoolifyMainEnv}, nil, secFile(facts.CoolifyMainEnv, "env", 0o644))
		}, "file:/data/coolify/source/.env=fail"},
		{"SEC-002", func(s *facts.Secrets) {
			s.PaaSMainEnv = secScanOf([]string{facts.CoolifyMainEnv}, nil, secFile(facts.CoolifyMainEnv, "env", 0o660))
		}, "file:/data/coolify/source/.env=warn"},
		{"SEC-002", func(s *facts.Secrets) {
			s.PaaSMainEnv = secScanOf([]string{facts.CoolifyMainEnv}, nil, secFile(facts.CoolifyMainEnv, "env", 0o640))
		}, "host=pass"},
		{"SEC-003", func(s *facts.Secrets) {
			s.PaaSSSHKeys = secScanOf([]string{facts.CoolifySSHKeys}, nil, secFile(facts.CoolifySSHKeys, "dir", 0o755),
				secFile(facts.CoolifySSHKeys+"/k1", "key", 0o600), secFile(facts.CoolifySSHKeys+"/k2", "key", 0o640))
		}, "file:/data/coolify/ssh/keys=fail file:/data/coolify/ssh/keys/k2=fail host=pass"},
		{"SEC-003", func(s *facts.Secrets) {
			s.PaaSSSHKeys = secScanOf([]string{facts.CoolifySSHKeys}, nil, secFile(facts.CoolifySSHKeys, "dir", 0o700))
		}, "host=pass"},
		{"SEC-003", func(s *facts.Secrets) {
			// Older facts files listed Coolify's lock files as keys.
			s.PaaSSSHKeys = secScanOf([]string{facts.CoolifySSHKeys}, nil, secFile(facts.CoolifySSHKeys, "dir", 0o700),
				secFile(facts.CoolifySSHKeys+"/ssh_key@example1", "key", 0o600), secFile(facts.CoolifySSHKeys+"/ssh_key@example1.lock", "key", 0o644))
		}, "host=pass"},
		{"SEC-004", func(s *facts.Secrets) {
			d := facts.CoolifyProxyDynamic
			s.ProxyDynamic = secScanOf([]string{d}, nil, secFile(d+"/app.yml", "config", 0o644), secFile(d+"/app.yml.bak", "config", 0o644),
				secFile(d+"/app-old.yaml", "config", 0o644))
		}, "file:/data/coolify/proxy/dynamic/app-old.yaml=warn file:/data/coolify/proxy/dynamic/app.yml.bak=warn host=pass"},
		{"SEC-005", func(s *facts.Secrets) {
			s.PrivateKeys = secScanOf([]string{"/root", "/home/alice"}, nil, secFile("/root/.ssh/id_ed25519", "ssh", 0o600),
				secFile("/home/alice/.ssh/id_rsa", "ssh", 0o644), secFile("/home/alice/site.pem", "pem", 0o644), secFile("/home/alice/a.key", "key", 0o600))
		}, "file:/home/alice/.ssh/id_rsa=fail file:/home/alice/site.pem=warn host=pass"},
		{"SEC-006", func(s *facts.Secrets) {
			s.DockerConfigs = secScanOf([]string{"/root"}, nil, secFile("/root/.docker/config.json", "docker", 0o644))
		}, "file:/root/.docker/config.json=warn"},
		{"SEC-006", func(s *facts.Secrets) { s.DockerConfigs = secScanOf([]string{"/root"}, nil) }, "host=pass"},
		{"SEC-007", func(s *facts.Secrets) {
			s.WorldWritable = secScanOf([]string{facts.CoolifyRoot}, nil, secFile("/data/coolify/tmp", "dir", 0o1777))
		}, "file:/data/coolify/tmp=fail"},
		{"SEC-007", func(s *facts.Secrets) { s.WorldWritable = secScanOf([]string{facts.CoolifyRoot}, nil) }, "host=pass"},
	}
	for i, c := range cases {
		s := secEmpty()
		c.set(s)
		if got := secRun(c.id, s, true); got != c.want {
			t.Errorf("%d %s:\n got %s\nwant %s", i, c.id, got, c.want)
		}
	}
}

func TestSecDeniedNamesPathNotSudo(t *testing.T) {
	s := secEmpty()
	s.PaaSMainEnv = secScanOf([]string{facts.CoolifyMainEnv}, []string{facts.CoolifyMainEnv})
	rs := checkPaaSMainEnv(Input{Facts: &facts.Facts{Secrets: s, Host: &facts.Host{}}})
	if len(rs) != 1 || rs[0].Level != Unknown || !strings.Contains(rs[0].Message, facts.CoolifyMainEnv) || strings.Contains(rs[0].Message, "sudo") {
		t.Errorf("got %+v", rs)
	}
	s.PaaSMainEnv.Truncated = true
	if got := paasLevels(checkPaaSMainEnv(Input{Facts: &facts.Facts{Secrets: s}})); got != "file:/data/coolify/source/.env=unknown =unknown" {
		t.Errorf("truncated: %s", got)
	}
}

func TestStrayNames(t *testing.T) {
	for name, want := range map[string]bool{
		"app.yml": false, "app.yml.bak": true, "app.backup.yml": true, "app-old.yml": true, "app.yml~": true,
		"#app.yml#": true, ".app.yml.swp": true, "middlewares.yml": false, "copy-of-app.yaml": true, "default_redirect_503.yaml": false,
	} {
		if secIsStrayName(name) != want {
			t.Errorf("secIsStrayName(%q) != %v", name, want)
		}
	}
}

func TestBakChecks(t *testing.T) {
	if got := paasLevels(checkPlatformBackups(Input{Facts: &facts.Facts{}})); got != "=unknown" {
		t.Errorf("nil paas: %s", got)
	}
	if got := paasLevels(checkPlatformBackups(Input{Facts: &facts.Facts{PaaS: &facts.PaaS{Platforms: []facts.Platform{}}}})); got != "=skip" {
		t.Errorf("no platform: %s", got)
	}
	now := time.Date(2026, 3, 1, 12, 0, 0, 0, time.UTC)
	f := &facts.Facts{CollectedAt: now, PaaS: &facts.PaaS{Platforms: []facts.Platform{
		{Name: facts.PlatformCoolify, DataRoot: facts.CoolifyRoot, Backups: &facts.BackupEvidence{
			Dir: facts.CoolifyBackups, Readable: true, Files: 3, Newest: now.Add(-72 * time.Hour)}},
		{Name: facts.PlatformDokploy, DataRoot: facts.DokployRoot},
	}}}
	rs := checkPlatformBackups(Input{Facts: f})
	if paasLevels(rs) != "file:/data/coolify=info file:/etc/dokploy=info" || rs[0].Evidence["days"] != 3 {
		t.Errorf("got %s %v", paasLevels(rs), rs[0].Evidence)
	}
	f.PaaS.Platforms[0].Backups = &facts.BackupEvidence{Dir: facts.CoolifyBackups}
	if rs := checkPlatformBackups(Input{Facts: f}); rs[0].Level != Unknown {
		t.Errorf("unreadable: %s", paasLevels(rs))
	}
	f.PaaS.Platforms[0].Backups = nil
	if rs := checkPlatformBackups(Input{Facts: f}); rs[0].Level != Info || !strings.Contains(rs[0].Message, "no local evidence") {
		t.Errorf("absent: %+v", rs[0])
	}

	if got := paasLevels(checkBackupTools(Input{Facts: &facts.Facts{}})); got != "=unknown" {
		t.Errorf("nil: %s", got)
	}
	s := secEmpty()
	if rs := checkBackupTools(Input{Facts: &facts.Facts{Secrets: s}}); rs[0].Level != Info || !strings.HasPrefix(rs[0].Message, "no ") {
		t.Errorf("none: %+v", rs[0])
	}
	s.BackupTools = []string{"restic"}
	s.BackupConfigs = secScanOf([]string{"/etc/restic"}, nil, secFile("/etc/restic", "restic", 0o700))
	if rs := checkBackupTools(Input{Facts: &facts.Facts{Secrets: s}}); !strings.Contains(rs[0].Message, "tools: restic; 1 config") {
		t.Errorf("found: %+v", rs[0])
	}
}
