package plan

import (
	"strings"
	"testing"
	"time"

	"github.com/Shironex/stackward/internal/checks"
	"github.com/Shironex/stackward/internal/facts"
	"github.com/Shironex/stackward/internal/redact"
	"github.com/Shironex/stackward/internal/report"
)

func results(levels map[string]checks.Level) []checks.Result {
	var out []checks.Result
	for id, l := range levels {
		out = append(out, checks.Result{ID: id, Subject: "host", Level: l})
	}
	return out
}

func strp(s string) *string { return &s }

func TestInputLevelIsTheWorst(t *testing.T) {
	in := Input{Results: []checks.Result{
		{ID: "A-001", Subject: "x", Level: checks.Pass},
		{ID: "A-001", Subject: "y", Level: checks.Warn},
		{ID: "A-001", Subject: "z", Level: checks.Unknown},
	}}
	if l, ok := in.Level("A-001"); !ok || l != checks.Warn {
		t.Errorf("worst level %s %v, want warn", l, ok)
	}
	if _, ok := in.Level("B-001"); ok {
		t.Error("a check without results must report not found")
	}
}

// --- journald-cap

func journalFacts(j *facts.Journal) *facts.Facts { return &facts.Facts{Journal: j} }

func TestJournaldCap(t *testing.T) {
	warn := results(map[string]checks.Level{"LOG-001": checks.Warn})
	persistent := &facts.Journal{Storage: "auto", PersistentDir: true, Persistent: true}

	// Pass: no step.
	out := planJournaldCap(Input{Facts: journalFacts(&facts.Journal{SystemMaxUse: "1G", Persistent: true}), Results: results(map[string]checks.Level{"LOG-001": checks.Pass})})
	if out.Step != nil || out.Kind != SkipPassing {
		t.Fatalf("pass: %+v", out)
	}
	// Unknown facts: no step and a reason.
	for name, in := range map[string]Input{
		"report alone":     {Results: warn},
		"journal missing":  {Facts: &facts.Facts{}, Results: warn},
		"check unknown":    {Facts: journalFacts(persistent), Results: results(map[string]checks.Level{"LOG-001": checks.Unknown})},
		"check not in run": {Facts: journalFacts(persistent)},
	} {
		out := planJournaldCap(in)
		if out.Step != nil || out.Kind != SkipUnknown || out.Reason == "" {
			t.Errorf("%s: %+v", name, out)
		}
	}
	// Volatile journal: a person has to decide first.
	if out := planJournaldCap(Input{Facts: journalFacts(&facts.Journal{Storage: "volatile"}), Results: warn}); out.Kind != SkipManual {
		t.Errorf("volatile: %+v", out)
	}
	// Fail: the exact drop-in.
	out = planJournaldCap(Input{Facts: journalFacts(persistent), Results: warn})
	if out.Step == nil {
		t.Fatalf("warn: no step: %+v", out)
	}
	e := out.Step.Edits[0]
	wantDiff := "--- /dev/null\n+++ b/etc/systemd/journald.conf.d/90-stackward-journal-cap.conf\n@@ -0,0 +1,5 @@\n" +
		"+# Written by stackward: plan step journald-cap, fixes LOG-001.\n" +
		"+# Caps the persistent journal. Remove this file and restart\n" +
		"+# systemd-journald to undo.\n" +
		"+[Journal]\n" +
		"+SystemMaxUse=1G\n"
	if e.Path != journaldDropin || e.Action != Create || e.Mode != "0644" || e.Diff != wantDiff {
		t.Errorf("edit %+v\ndiff:\n%s", e, e.Diff)
	}
	if got := out.Step.Restarts; len(got) != 1 || got[0] != "systemd-journald" {
		t.Errorf("restarts %v", got)
	}
}

// --- sysctl-hardening

func sysctlInput(values map[string]string, levels map[string]checks.Level) Input {
	return Input{
		Facts:   &facts.Facts{Sysctl: &facts.Sysctl{Values: values, DockerPresent: true}},
		Results: results(levels),
	}
}

func goodSysctls() map[string]string {
	v := map[string]string{"net.ipv4.ip_forward": "1", "net.ipv4.conf.all.rp_filter": "2", "net.ipv4.conf.default.rp_filter": "2"}
	for _, k := range []string{"net.ipv4.conf.all.accept_redirects", "net.ipv4.conf.default.accept_redirects", "net.ipv6.conf.all.accept_redirects",
		"net.ipv6.conf.default.accept_redirects", "net.ipv4.conf.all.send_redirects", "net.ipv4.conf.all.accept_source_route",
		"net.ipv4.conf.default.accept_source_route", "net.ipv6.conf.all.accept_source_route"} {
		v[k] = "0"
	}
	for _, k := range []string{"net.ipv4.tcp_syncookies", "net.ipv4.icmp_echo_ignore_broadcasts", "net.ipv4.conf.all.log_martians",
		"kernel.kptr_restrict", "kernel.dmesg_restrict", "kernel.unprivileged_bpf_disabled", "kernel.yama.ptrace_scope",
		"fs.protected_hardlinks", "fs.protected_symlinks", "fs.protected_fifos", "fs.protected_regular"} {
		v[k] = "1"
	}
	return v
}

func TestSysctlHardening(t *testing.T) {
	pass := map[string]checks.Level{"KRN-002": checks.Pass, "KRN-003": checks.Pass, "KRN-004": checks.Pass}
	if out := planSysctlHardening(sysctlInput(goodSysctls(), pass)); out.Step != nil || out.Kind != SkipPassing {
		t.Fatalf("pass: %+v", out)
	}
	warn := map[string]checks.Level{"KRN-002": checks.Pass, "KRN-003": checks.Warn, "KRN-004": checks.Warn}
	if out := planSysctlHardening(Input{Results: results(warn)}); out.Step != nil || out.Kind != SkipUnknown {
		t.Fatalf("no facts: %+v", out)
	}
	unknown := map[string]checks.Level{"KRN-002": checks.Unknown, "KRN-003": checks.Unknown, "KRN-004": checks.Unknown}
	if out := planSysctlHardening(sysctlInput(map[string]string{}, unknown)); out.Step != nil || out.Kind != SkipUnknown {
		t.Fatalf("unknown: %+v", out)
	}

	v := goodSysctls()
	v["net.ipv4.ip_forward"] = "0" // never touched, even when "off"
	v["net.ipv4.conf.all.send_redirects"] = "1"
	v["kernel.unprivileged_bpf_disabled"] = "0"
	in := sysctlInput(v, warn)
	in.Facts.Sysctl.Configured = map[string]facts.SysctlSetting{"net.ipv4.conf.all.send_redirects": {Value: "1", File: "/etc/sysctl.conf"}}
	out := planSysctlHardening(in)
	if out.Step == nil {
		t.Fatalf("warn: no step: %+v", out)
	}
	s := out.Step
	wantDiff := "--- /dev/null\n+++ b/etc/sysctl.d/90-stackward-hardening.conf\n@@ -0,0 +1,6 @@\n" +
		"+# Written by stackward: plan step sysctl-hardening, fixes KRN-003, KRN-004.\n" +
		"+# Hardening values only: net.ipv4.ip_forward and the other settings\n" +
		"+# Docker needs are never set here. Remove this file to undo at the\n" +
		"+# next boot.\n" +
		"+net.ipv4.conf.all.send_redirects = 0\n" +
		"+kernel.unprivileged_bpf_disabled = 1\n"
	if s.Edits[0].Diff != wantDiff {
		t.Errorf("diff:\n%s", s.Edits[0].Diff)
	}
	if strings.Join(s.Fixes, ",") != "KRN-003,KRN-004" {
		t.Errorf("fixes %v", s.Fixes)
	}
	for _, target := range s.Touches {
		if strings.Contains(target, "ip_forward") {
			t.Errorf("the step touches %s", target)
		}
	}
	notes := strings.Join(s.Notes, "\n")
	for _, want := range []string{"/etc/sysctl.conf sets net.ipv4.conf.all.send_redirects = 1", "cannot be lowered again without a reboot"} {
		if !strings.Contains(notes, want) {
			t.Errorf("notes miss %q:\n%s", want, notes)
		}
	}
	// No undo for a value the kernel will not lower.
	for _, c := range s.Undo.Commands {
		if strings.Contains(strings.Join(c.Args, " "), "unprivileged_bpf_disabled") {
			t.Errorf("undo lowers unprivileged_bpf_disabled: %v", c.Args)
		}
	}

	// Only ufw resets the value: a drop-in would not help.
	ufw := sysctlInput(goodSysctls(), map[string]checks.Level{"KRN-002": checks.Pass, "KRN-003": checks.Warn, "KRN-004": checks.Pass})
	ufw.Facts.Sysctl.UFW = map[string]string{"net.ipv4.conf.all.log_martians": "0"}
	if out := planSysctlHardening(ufw); out.Step != nil || out.Kind != SkipManual || !strings.Contains(out.Reason, "/etc/ufw/sysctl.conf") {
		t.Errorf("ufw only: %+v", out)
	}
	// The drop-in exists already: someone has to look.
	again := sysctlInput(v, warn)
	again.Facts.Sysctl.Configured = map[string]facts.SysctlSetting{"kernel.kptr_restrict": {Value: "1", File: sysctlDropin}}
	if out := planSysctlHardening(again); out.Step != nil || out.Kind != SkipManual {
		t.Errorf("existing drop-in: %+v", out)
	}
}

// --- docker-log-rotation

func dockerInput(dd *facts.DockerDaemon, l checks.Level) Input {
	return Input{
		Facts:   &facts.Facts{Docker: &facts.Docker{Installed: true, Daemon: dd}},
		Results: results(map[string]checks.Level{"DKR-031": l}),
	}
}

func TestDockerLogRotation(t *testing.T) {
	if out := planDockerLogRotation(dockerInput(&facts.DockerDaemon{ConfigFound: true, LogMaxSize: "10m"}, checks.Pass)); out.Step != nil || out.Kind != SkipPassing {
		t.Fatalf("pass: %+v", out)
	}
	for name, in := range map[string]Input{
		"report alone":  {Results: results(map[string]checks.Level{"DKR-031": checks.Warn})},
		"no daemon":     {Facts: &facts.Facts{Docker: &facts.Docker{Installed: true}}, Results: results(map[string]checks.Level{"DKR-031": checks.Warn})},
		"old facts":     dockerInput(&facts.DockerDaemon{ConfigFound: true}, checks.Warn),
		"check unknown": dockerInput(&facts.DockerDaemon{ConfigFound: true, Content: strp("{}")}, checks.Unknown),
	} {
		if out := planDockerLogRotation(in); out.Step != nil || out.Kind != SkipUnknown || out.Reason == "" {
			t.Errorf("%s: %+v", name, out)
		}
	}
	if out := planDockerLogRotation(dockerInput(&facts.DockerDaemon{ConfigError: "invalid JSON"}, checks.Warn)); out.Kind != SkipManual {
		t.Errorf("broken file: %+v", out)
	}

	old := "{\n    \"live-restore\": true,\n    \"log-opts\": {\n        \"labels\": \"project\"\n    }\n}\n"
	out := planDockerLogRotation(dockerInput(&facts.DockerDaemon{ConfigFound: true, Content: strp(old)}, checks.Warn))
	if out.Step == nil {
		t.Fatalf("warn: no step: %+v", out)
	}
	s := out.Step
	e := s.Edits[0]
	wantDiff := "--- a/etc/docker/daemon.json\n+++ b/etc/docker/daemon.json\n@@ -1,6 +1,9 @@\n" +
		" {\n" +
		"     \"live-restore\": true,\n" +
		"     \"log-opts\": {\n" +
		"-        \"labels\": \"project\"\n" +
		"-    }\n" +
		"+        \"labels\": \"project\",\n" +
		"+        \"max-size\": \"10m\",\n" +
		"+        \"max-file\": \"3\"\n" +
		"+    },\n" +
		"+    \"log-driver\": \"json-file\"\n" +
		" }\n"
	if e.Action != Replace || e.Diff != wantDiff || e.OldSHA256 != sha(old) {
		t.Errorf("edit %+v\ndiff:\n%s", e, e.Diff)
	}
	if strings.Join(e.Validate, " ") != "dockerd --validate --config-file" {
		t.Errorf("validate %v", e.Validate)
	}
	if strings.Join(s.Restarts, ",") != "docker" || !strings.Contains(strings.Join(s.Notes, " "), "Restarting Docker") {
		t.Errorf("the restart must be named: %v %v", s.Restarts, s.Notes)
	}
	if g, _ := Lookup("docker-log-rotation"); g.Risk != Networking || !g.OptIn {
		t.Errorf("docker-log-rotation must be networking and opt in: %+v", g)
	}

	// No daemon.json yet: create one.
	out = planDockerLogRotation(dockerInput(&facts.DockerDaemon{}, checks.Warn))
	if out.Step == nil || out.Step.Edits[0].Action != Create || !strings.Contains(out.Step.Edits[0].New, `"max-size": "10m"`) {
		t.Errorf("absent file: %+v", out)
	}
}

func TestMergeLogRotation(t *testing.T) {
	cases := []struct {
		name, old, want string
		err             bool
	}{
		{"empty", "", "{\n  \"log-driver\": \"json-file\",\n  \"log-opts\": {\n    \"max-size\": \"10m\",\n    \"max-file\": \"3\"\n  }\n}\n", false},
		{"one line keeps every key", `{"bip": "192.0.2.1/24", "log-driver": "json-file", "log-opts": {"max-file": "5"}}`,
			"{\n  \"bip\": \"192.0.2.1/24\",\n  \"log-driver\": \"json-file\",\n  \"log-opts\": {\n    \"max-file\": \"5\",\n    \"max-size\": \"10m\"\n  }\n}\n", false},
		{"tabs and numbers kept", "{\n\t\"mtu\": 1450,\n\t\"dns\": [\"192.0.2.53\"]\n}\n",
			"{\n\t\"mtu\": 1450,\n\t\"dns\": [\"192.0.2.53\"],\n\t\"log-driver\": \"json-file\",\n\t\"log-opts\": {\n\t\t\"max-size\": \"10m\",\n\t\t\"max-file\": \"3\"\n\t}\n}\n", false},
		{"duplicate key", `{"a": 1, "a": 2}`, "", true},
		{"not an object", `["a"]`, "", true},
		{"trailing data", `{} {}`, "", true},
	}
	for _, tc := range cases {
		got, _, err := mergeLogRotation(tc.old)
		if (err != nil) != tc.err {
			t.Errorf("%s: err %v", tc.name, err)
			continue
		}
		if !tc.err && got != tc.want {
			t.Errorf("%s:\n%s\nwant:\n%s", tc.name, got, tc.want)
		}
	}
	done := "{\"log-driver\": \"json-file\", \"log-opts\": {\"max-size\": \"1m\", \"max-file\": \"2\"}}\n"
	if got, touched, _ := mergeLogRotation(done); got != done || touched != nil {
		t.Errorf("a configured file must stay byte for byte: %q %v", got, touched)
	}
}

// --- diff

func TestDiff(t *testing.T) {
	if Diff("a", "b", "x\n", "x\n") != "" {
		t.Error("equal input must give no diff")
	}
	old := "1\n2\n3\n4\n5\n6\n7\n8\n9\n10\n11\n12\n"
	nw := "1\n2\nthree\n4\n5\n6\n7\n8\n9\n10\n11\ntwelve"
	want := "--- a/f\n+++ b/f\n@@ -1,6 +1,6 @@\n 1\n 2\n-3\n+three\n 4\n 5\n 6\n@@ -9,4 +9,4 @@\n 9\n 10\n 11\n-12\n+twelve\n\\ No newline at end of file\n"
	if got := Diff("a/f", "b/f", old, nw); got != want {
		t.Errorf("got:\n%s\nwant:\n%s", got, want)
	}
}

// --- Build

func testReport() *report.Report {
	return &report.Report{
		Schema: report.SchemaID, Tool: report.Tool{Name: "stackward", Version: "test"},
		GeneratedAt: "2026-03-01T12:00:00Z", Host: report.Host{HostnameHash: "sha256:0123456789abcdef"},
	}
}

func TestBuildVetoRefusesAStep(t *testing.T) {
	in := Input{Facts: journalFacts(&facts.Journal{Persistent: true}), Results: results(map[string]checks.Level{"LOG-001": checks.Warn})}
	g, _ := Lookup("journald-cap")
	neverTouched := func(s Step) string {
		for _, target := range s.Touches {
			if strings.HasPrefix(target, "service:systemd-journald") {
				return "systemd-journald is on the never touched list"
			}
		}
		return ""
	}
	p := BuildWith([]Generator{g}, in, testReport(), Options{Version: "test", Vetoes: []Veto{neverTouched}})
	if len(p.Steps) != 0 || len(p.Skipped) != 1 || p.Skipped[0].Kind != SkipRefused {
		t.Fatalf("veto ignored: %+v", p)
	}
	p = BuildWith([]Generator{g}, in, testReport(), Options{Version: "test"})
	if len(p.Steps) != 1 || p.Summary.Safe != 1 || strings.Join(p.Summary.Restarts, ",") != "systemd-journald" {
		t.Fatalf("plan %+v", p)
	}
	if err := p.Validate(); err != nil {
		t.Error(err)
	}
}

func TestBuildRedactsFileContent(t *testing.T) {
	// Assembled at run time so secret scanners do not flag the source.
	cred := "ci:" + "s3cr" + "et-" + "value"
	old := `{"registry-mirrors": ["https://` + cred + `@mirror.example.com"]}`
	in := dockerInput(&facts.DockerDaemon{ConfigFound: true, Content: strp(old)}, checks.Warn)
	g, _ := Lookup("docker-log-rotation")
	p := BuildWith([]Generator{g}, in, testReport(), Options{Version: "test"})
	if len(p.Steps) != 1 {
		t.Fatalf("plan %+v", p)
	}
	e := p.Steps[0].Edits[0]
	for _, field := range []string{e.Old, e.New, e.Diff} {
		if strings.Contains(field, "s3cret") || !strings.Contains(field, redact.Mask) {
			t.Errorf("secret not masked: %s", field)
		}
	}
	if !e.Redacted || e.OldSHA256 != sha(old) {
		t.Errorf("redacted %v, old hash must be of the real content", e.Redacted)
	}
	if err := p.Validate(); err != nil {
		t.Errorf("a redacted plan is still valid: %v", err)
	}
}

func TestValidateCatchesTampering(t *testing.T) {
	in := Input{Facts: journalFacts(&facts.Journal{Persistent: true}), Results: results(map[string]checks.Level{"LOG-001": checks.Warn})}
	g, _ := Lookup("journald-cap")
	p := BuildWith([]Generator{g}, in, testReport(), Options{Version: "test"})
	p.Steps[0].Edits[0].New += "SystemMaxUse=0\n"
	if p.Validate() == nil {
		t.Error("edited content with a stale hash passed")
	}
	p = BuildWith([]Generator{g}, in, testReport(), Options{Version: "test"})
	p.Steps[0].Risk = Safe
	p.Steps[0].ID = "made-up"
	if p.Validate() == nil {
		t.Error("an unknown step id passed")
	}
}

func TestRegistry(t *testing.T) {
	gens := Generators()
	if len(gens) < 3 {
		t.Fatalf("generators %v", gens)
	}
	for i := 1; i < len(gens); i++ {
		if gens[i-1].Risk.rank() > gens[i].Risk.rank() {
			t.Errorf("%s (%s) sorts before %s (%s)", gens[i-1].ID, gens[i-1].Risk, gens[i].ID, gens[i].Risk)
		}
	}
	defer func() {
		if recover() == nil {
			t.Error("a duplicate id must panic")
		}
	}()
	Register(Generator{ID: "journald-cap", Title: "x", Fixes: []string{"LOG-001"}, Risk: Safe, Plan: planJournaldCap})
}

// Generators must not depend on the clock: the same input gives the same
// plan, which is what makes golden plans possible.
func TestBuildIsDeterministic(t *testing.T) {
	in := sysctlInput(map[string]string{"kernel.kptr_restrict": "0"}, map[string]checks.Level{"KRN-002": checks.Pass, "KRN-003": checks.Pass, "KRN-004": checks.Warn})
	in.Facts.CollectedAt = time.Date(2026, 3, 1, 12, 0, 0, 0, time.UTC)
	a := Build(in, testReport(), Options{Version: "test"})
	b := Build(in, testReport(), Options{Version: "test"})
	if a.Steps[0].Edits[0].NewSHA256 != b.Steps[0].Edits[0].NewSHA256 || len(a.Skipped) != len(b.Skipped) {
		t.Error("two builds over the same input differ")
	}
}

// The default registry holds no test-only step: those are registered by
// tests and the scenario binary only (package txntest), and the only
// access-critical steps are the account and sshd steps and the fail2ban jail.
func TestDefaultRegistryHasNoTestAccessSteps(t *testing.T) {
	real := map[string]bool{AdminUserID: true, PaaSUserID: true, LockDefaultUserID: true, SSHDHardeningID: true, "fail2ban-sshd": true}
	for _, g := range Generators() {
		if g.Risk == AccessCritical && !real[g.ID] {
			t.Errorf("access-critical step %s in the default registry; add it to cmd/stackward's realAccessCritical once it is a real step", g.ID)
		}
		if strings.HasPrefix(g.ID, "txn-test") {
			t.Errorf("test step %s in the default registry", g.ID)
		}
	}
}
