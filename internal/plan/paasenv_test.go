package plan

import (
	"fmt"
	"io/fs"
	"slices"
	"sort"
	"strings"
	"testing"

	"github.com/Shironex/stackward/internal/checks"
	"github.com/Shironex/stackward/internal/facts"
)

func envFile(p string, mode facts.Perm, uid int, platform string) facts.SecretFile {
	return facts.SecretFile{Path: p, Kind: "env", Mode: mode, UID: uid, Platform: platform}
}

// coolifyEnvFacts is a Coolify panel with one open app .env, one closed
// one and an open main .env, all owned by uid 9999 as the installer sets.
func coolifyEnvFacts(main facts.Perm, mainUID int, apps ...facts.SecretFile) *facts.Facts {
	return &facts.Facts{
		PaaS: &facts.PaaS{Platforms: []facts.Platform{{Name: facts.PlatformCoolify, Role: facts.RolePanel, DataRoot: facts.CoolifyRoot}}},
		Secrets: &facts.Secrets{
			PaaSEnvFiles: facts.SecretScan{Roots: []string{facts.CoolifyApplications, facts.CoolifyServices}, Files: apps},
			PaaSMainEnv:  facts.SecretScan{Roots: []string{facts.CoolifyMainEnv}, Files: []facts.SecretFile{envFile(facts.CoolifyMainEnv, main, mainUID, "coolify")}},
		},
	}
}

func envLevels(sec1, sec2 checks.Level) map[string]checks.Level {
	return map[string]checks.Level{"SEC-001": sec1, "SEC-002": sec2}
}

const wantCoolifyService = "[Service]\nType=oneshot\n" +
	"ExecStart=/usr/bin/find /data/coolify/applications -xdev -ignore_readdir_race -maxdepth 4 -type f ( -name .env -o -name .env.* ) ! -name .env.example ! -name .env.sample ! -name .env.template ! -name .env.dist ! -name .env.defaults ( -uid 0 -o -uid 9999 ) -perm /077 -exec chmod go-rwx {} +\n" +
	"ExecStart=/usr/bin/find /data/coolify/services -xdev -ignore_readdir_race -maxdepth 4 -type f ( -name .env -o -name .env.* ) ! -name .env.example ! -name .env.sample ! -name .env.template ! -name .env.dist ! -name .env.defaults ( -uid 0 -o -uid 9999 ) -perm /077 -exec chmod go-rwx {} +\n" +
	"ExecStart=/usr/bin/find /data/coolify/source/.env -maxdepth 0 -type f -uid 9999 -perm /027 -exec chmod g-w,o-rwx {} +\n" +
	"NoNewPrivileges=yes\nPrivateNetwork=yes\nPrivateTmp=yes\nProtectHome=yes\nProtectSystem=strict\n" +
	"ReadWritePaths=-/data/coolify/applications -/data/coolify/services -/data/coolify/source/.env\n" +
	"CapabilityBoundingSet=CAP_DAC_READ_SEARCH CAP_FOWNER\n"

func TestPaaSEnvPlanCases(t *testing.T) {
	open := coolifyEnvFacts(0o644, coolifyUID,
		envFile("/data/coolify/applications/a1/.env", 0o644, coolifyUID, "coolify"),
		envFile("/data/coolify/applications/b2/.env", 0o600, coolifyUID, "coolify"))
	// Passing checks: no step.
	if out := planPaaSEnv(Input{Facts: open, Results: results(envLevels(checks.Pass, checks.Pass))}); out.Step != nil || out.Kind != SkipPassing {
		t.Errorf("pass: %+v", out)
	}
	// Unknown checks, or a report alone: no step and a reason.
	if out := planPaaSEnv(Input{Facts: open, Results: results(envLevels(checks.Unknown, checks.Unknown))}); out.Step != nil || out.Kind != SkipUnknown || out.Reason == "" {
		t.Errorf("unknown: %+v", out)
	}
	if out := planPaaSEnv(Input{Results: results(envLevels(checks.Fail, checks.Fail))}); out.Step != nil || out.Kind != SkipUnknown {
		t.Errorf("report alone: %+v", out)
	}
	// No platform detected: refused as manual, whatever the scans say.
	none := coolifyEnvFacts(0o644, coolifyUID, envFile("/data/coolify/applications/a1/.env", 0o644, 0, "coolify"))
	none.PaaS.Platforms = nil
	if out := planPaaSEnv(Input{Facts: none, Results: results(envLevels(checks.Fail, checks.Fail))}); out.Step != nil || out.Kind != SkipManual {
		t.Errorf("no platform: %+v", out)
	}

	out := planPaaSEnv(Input{Facts: open, Results: results(envLevels(checks.Fail, checks.Fail))})
	if out.Step == nil {
		t.Fatalf("open files: %+v", out)
	}
	s := complete(mustLookup(t, paasEnvID), *out.Step)
	if !slices.Equal(s.Fixes, paasEnvFixes) || !s.OptIn || s.Risk != Networking || len(s.Restarts) != 0 {
		t.Errorf("fixes %v opt in %v risk %s restarts %v", s.Fixes, s.OptIn, s.Risk, s.Restarts)
	}
	wantTouches := []string{"file-mode:/data/coolify/applications", "file-mode:/data/coolify/services", "file-mode:/data/coolify/source/.env",
		"service:stackward-paas-env-perms.service", "service:stackward-paas-env-perms.timer"}
	if !slices.Equal(s.Touches, wantTouches) {
		t.Errorf("touches %v", s.Touches)
	}
	if len(s.Edits) != 3 || !strings.HasSuffix(s.Edits[0].New, wantCoolifyService) {
		t.Errorf("service unit:\n%s", s.Edits[0].New)
	}
	for _, e := range s.Edits {
		if e.Action != Create || e.Mode != "0644" || !strings.HasPrefix(e.Path, "/etc/systemd/system/") {
			t.Errorf("edit %s %s %s", e.Action, e.Path, e.Mode)
		}
	}
	if !strings.Contains(s.Edits[1].New, "OnUnitActiveSec=1min\n") || !strings.HasSuffix(s.Edits[2].New, "[Unit]\nWants=stackward-paas-env-perms.timer\n") {
		t.Errorf("timer or drop-in:\n%s\n%s", s.Edits[1].New, s.Edits[2].New)
	}
	units := s.Edits[0].New + s.Edits[1].New + s.Edits[2].New
	for _, bad := range []string{"cat ", "cp ", "chown", "grep", "\u2013", "\u2014", "[Install]"} {
		if strings.Contains(units, bad) {
			t.Errorf("the units contain %q", bad)
		}
	}
	notes := strings.Join(s.Notes, "\n")
	for _, want := range []string{"workaround", "never reads", "stackward undo --run", "uid 9999", "g-w,o-rwx", "bind mounts"} {
		if !strings.Contains(notes, want) {
			t.Errorf("notes lack %q:\n%s", want, notes)
		}
	}
	if err := Authorize(s); err != nil {
		t.Errorf("its own step refused: %v", err)
	}
	if reason := NeverTouchedVeto(s); reason != "" {
		t.Errorf("never touched refuses its own step: %s", reason)
	}
}

func TestPaaSEnvLeavesOtherOwnersAlone(t *testing.T) {
	// The main .env owned by root: the container reads it as 9999 through
	// the other bits, so closing it would stop the panel.
	f := coolifyEnvFacts(0o664, 0, envFile("/data/coolify/applications/a1/.env", 0o640, 1000, "coolify"))
	out := planPaaSEnv(Input{Facts: f, Results: results(envLevels(checks.Fail, checks.Fail))})
	if out.Step != nil || out.Kind != SkipManual || !strings.Contains(out.Reason, "/data/coolify/source/.env (uid 0)") || !strings.Contains(out.Reason, "(uid 1000)") {
		t.Fatalf("other owners: %+v", out)
	}
	// One covered file is enough for SEC-001; the rest is named.
	f.Secrets.PaaSEnvFiles.Files = append(f.Secrets.PaaSEnvFiles.Files, envFile("/data/coolify/services/s1/.env.production", 0o644, 0, "coolify"))
	out = planPaaSEnv(Input{Facts: f, Results: results(envLevels(checks.Fail, checks.Fail))})
	if out.Step == nil || !slices.Equal(out.Step.Fixes, []string{"SEC-001"}) {
		t.Fatalf("mixed: %+v", out)
	}
	if notes := strings.Join(out.Step.Notes, "\n"); !strings.Contains(notes, "Left alone") || !strings.Contains(notes, "a1/.env (uid 1000)") {
		t.Errorf("notes:\n%s", notes)
	}
}

func TestPaaSEnvDokploy(t *testing.T) {
	f := &facts.Facts{
		PaaS: &facts.PaaS{Platforms: []facts.Platform{{Name: facts.PlatformDokploy, Role: facts.RolePanel, DataRoot: facts.DokployRoot}}},
		Secrets: &facts.Secrets{
			PaaSEnvFiles: facts.SecretScan{Roots: []string{facts.DokployApplications, facts.DokployCompose},
				Files: []facts.SecretFile{envFile("/etc/dokploy/compose/web-1/code/.env", 0o644, 0, "dokploy")}},
			PaaSMainEnv: facts.SecretScan{Roots: []string{}, Files: []facts.SecretFile{}},
		},
	}
	out := planPaaSEnv(Input{Facts: f, Results: results(envLevels(checks.Fail, checks.Skip))})
	if out.Step == nil {
		t.Fatalf("dokploy: %+v", out)
	}
	s := complete(mustLookup(t, paasEnvID), *out.Step)
	if !slices.Equal(s.Fixes, []string{"SEC-001"}) || !strings.Contains(s.Edits[0].New, "/etc/dokploy/compose -xdev") || strings.Contains(s.Edits[0].New, "9999") {
		t.Errorf("fixes %v\n%s", s.Fixes, s.Edits[0].New)
	}
	if err := Authorize(s); err != nil {
		t.Errorf("refused: %v", err)
	}
}

func paasEnvTestStep(t *testing.T) Step {
	t.Helper()
	f := coolifyEnvFacts(0o644, coolifyUID, envFile("/data/coolify/applications/a1/.env", 0o644, coolifyUID, "coolify"))
	out := planPaaSEnv(Input{Facts: f, Results: results(envLevels(checks.Fail, checks.Fail))})
	if out.Step == nil {
		t.Fatalf("no step: %+v", out)
	}
	return complete(mustLookup(t, paasEnvID), *out.Step)
}

func TestPaaSEnvAuthorizeRefusesTampering(t *testing.T) {
	good := paasEnvTestStep(t)
	clone := func() Step {
		s := good
		s.Touches = slices.Clone(good.Touches)
		s.Edits = slices.Clone(good.Edits)
		s.Commands = slices.Clone(good.Commands)
		s.Undo.Commands = slices.Clone(good.Undo.Commands)
		s.Fixes = slices.Clone(good.Fixes)
		return s
	}
	retarget := func(s *Step, i int, content string) {
		e := newEdit(s.Edits[i].Path, Create, "0644", "", content)
		s.Edits[i] = e
	}
	cases := map[string]func(s *Step){
		"another folder":      func(s *Step) { s.Touches[0] = "file-mode:/data/coolify/ssh/keys" },
		"out of order":        func(s *Step) { s.Touches[0], s.Touches[1] = s.Touches[1], s.Touches[0] },
		"a duplicate":         func(s *Step) { s.Touches[1] = s.Touches[0] },
		"no folder":           func(s *Step) { s.Touches = s.Touches[3:] },
		"an extra touch":      func(s *Step) { s.Touches = append(s.Touches, "service:docker") },
		"a widened find":      func(s *Step) { retarget(s, 0, strings.Replace(s.Edits[0].New, "-maxdepth 4", "-maxdepth 9", 1)) },
		"a chown":             func(s *Step) { retarget(s, 0, strings.Replace(s.Edits[0].New, "chmod go-rwx", "chown root", 1)) },
		"a content read":      func(s *Step) { retarget(s, 0, s.Edits[0].New+"ExecStartPost=/usr/bin/cat /data/coolify/source/.env\n") },
		"another unit path":   func(s *Step) { s.Edits[1].Path = "/etc/systemd/system/docker.service" },
		"a replace":           func(s *Step) { s.Edits[2].Action = Replace },
		"a validate command":  func(s *Step) { s.Edits[0].Validate = []string{"sh", "-c"} },
		"an extra command":    func(s *Step) { s.Commands = append(s.Commands, cmd("x", "systemctl", "restart", "docker")) },
		"an enable":           func(s *Step) { s.Commands[2] = cmd("x", "systemctl", "enable", "--now", paasEnvUnit+".timer") },
		"a wider undo rm":     func(s *Step) { s.Undo.Commands[1] = cmd("x", "rm", "-rf", "/etc/systemd/system") },
		"a restart":           func(s *Step) { s.Restarts = []string{"docker"} },
		"a fix it cannot do":  func(s *Step) { s.Touches = append(s.Touches[:2:2], s.Touches[3:]...) },
		"a missing undo step": func(s *Step) { s.Undo.Commands = s.Undo.Commands[1:] },
	}
	for name, mutate := range cases {
		s := clone()
		mutate(&s)
		if err := Authorize(s); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
}

// treeReader is a fake host with files, folders and modes, for Check and
// Pin.
type treeReader struct {
	files map[string]string
	meta  map[string]PathInfo
}

func newTreeReader() *treeReader {
	return &treeReader{files: map[string]string{}, meta: map[string]PathInfo{}}
}

func (r *treeReader) dir(p string) {
	r.meta[p] = PathInfo{Exists: true, Dir: true, Perm: 0o700, UID: coolifyUID}
}

func (r *treeReader) file(p string, perm fs.FileMode, uid int) {
	r.meta[p] = PathInfo{Exists: true, Regular: true, Perm: perm, UID: uid}
}

func (r *treeReader) ReadFile(p string) ([]byte, error) {
	s, ok := r.files[p]
	if !ok {
		return nil, fmt.Errorf("%s: %w", p, fs.ErrNotExist)
	}
	return []byte(s), nil
}

func (r *treeReader) ReadDir(p string) ([]string, error) {
	var out []string
	for k := range r.meta {
		if rest, ok := strings.CutPrefix(k, p+"/"); ok && !strings.Contains(rest, "/") {
			out = append(out, rest)
		}
	}
	sort.Strings(out)
	return out, nil
}

func (r *treeReader) PathInfo(p string) (PathInfo, error) {
	if m, ok := r.meta[p]; ok {
		return m, nil
	}
	return PathInfo{UID: -1}, nil
}

func TestPaaSEnvCheckJudgesUnitsAndModes(t *testing.T) {
	s := paasEnvTestStep(t)
	r := newTreeReader()
	for _, d := range []string{facts.CoolifyRoot, facts.CoolifyApplications, facts.CoolifyServices, facts.CoolifySource, "/data/coolify/applications/a1"} {
		r.dir(d)
	}
	r.file(facts.CoolifyMainEnv, 0o700, coolifyUID)
	r.file("/data/coolify/applications/a1/.env", 0o600, coolifyUID)
	r.file("/data/coolify/applications/a1/.env.example", 0o644, coolifyUID) // a template, not judged
	r.file("/data/coolify/applications/a1/notes.txt", 0o644, coolifyUID)    // not an .env name
	r.file("/data/coolify/services/other-owner.env", 0o644, 1000)           // not an .env name either

	if applied, _, err := Check(r, s); err != nil || applied {
		t.Fatalf("no units yet: applied %v %v", applied, err)
	}
	if err := Pin(r, s); err != nil {
		t.Errorf("pin with the platform installed: %v", err)
	}
	for _, e := range s.Edits {
		r.files[e.Path] = e.New
	}
	if applied, why, err := Check(r, s); err != nil || !applied || why == "" {
		t.Fatalf("units and closed files: applied %v %q %v", applied, why, err)
	}
	// A deploy opened a file again: not applied, so apply runs it now.
	r.file("/data/coolify/applications/a1/.env", 0o644, coolifyUID)
	if applied, _, _ := Check(r, s); applied {
		t.Error("an open covered file counts as applied")
	}
	// An open file of another owner is not the timer's: still applied.
	r.file("/data/coolify/applications/a1/.env", 0o600, coolifyUID)
	r.dir("/data/coolify/services/s1")
	r.file("/data/coolify/services/s1/.env", 0o644, 1000)
	if applied, _, _ := Check(r, s); !applied {
		t.Error("an open file the timer leaves alone makes the step not applied")
	}
	// The main .env: group read stays allowed, group write does not.
	r.file(facts.CoolifyMainEnv, 0o640, coolifyUID)
	if applied, _, _ := Check(r, s); !applied {
		t.Error("a group readable main .env counts as open")
	}
	r.file(facts.CoolifyMainEnv, 0o660, coolifyUID)
	if applied, _, _ := Check(r, s); applied {
		t.Error("a group writable main .env counts as closed")
	}
	// A changed unit: not applied.
	r.files[paasEnvTimer] = "changed"
	if applied, _, _ := Check(r, s); applied {
		t.Error("a changed timer counts as applied")
	}

	// Coolify gone since the plan: refused.
	delete(r.meta, facts.CoolifyRoot)
	if err := Pin(r, s); err == nil || !strings.Contains(err.Error(), "not installed") {
		t.Errorf("pin without the platform: %v", err)
	}
}

// The exception in the never touched list names exactly the folders the
// step can cover, so the two cannot drift apart.
func TestPaaSEnvExceptionMatchesItsRules(t *testing.T) {
	var want []string
	for _, r := range envRules {
		want = append(want, fileModeKind+r.root)
	}
	i := slices.IndexFunc(NeverTouchedExceptions, func(x NeverTouchedException) bool { return x.Step == paasEnvID })
	if i < 0 || NeverTouchedExceptions[i].Entry != "paas-data" || !slices.Equal(NeverTouchedExceptions[i].Targets, want) {
		t.Errorf("exception %+v, want the targets %v", NeverTouchedExceptions, want)
	}
}
