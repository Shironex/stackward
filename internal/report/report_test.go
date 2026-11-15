package report

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/Shironex/stackward/internal/catalog"
	"github.com/Shironex/stackward/internal/checks"
	"github.com/Shironex/stackward/internal/facts"
	"github.com/Shironex/stackward/internal/profile"
	"github.com/Shironex/stackward/internal/sandbox"
	"github.com/Shironex/stackward/internal/schemacheck"
)

func sample(t *testing.T) *Report {
	t.Helper()
	cat, err := catalog.Load()
	if err != nil {
		t.Fatal(err)
	}
	secret := "hunter" + "2-not-real"
	f := &facts.Facts{
		CollectedAt: time.Date(2026, 3, 1, 12, 0, 0, 0, time.UTC),
		Host:        &facts.Host{Hostname: "host.example.com", UID: 1000, EUID: 1000},
		OS:          &facts.OS{ID: "ubuntu", VersionID: "24.04", PrettyName: "Ubuntu 24.04.1 LTS"},
		Kernel:      &facts.Kernel{Release: "6.8.0-45-generic"},
		Collectors: []facts.CollectorStatus{
			{Name: "os", Status: facts.StatusOK},
			{Name: "ssh", Status: facts.StatusFailed, Error: "sshd -T: exit 255 --password " + secret},
		},
	}
	results := []checks.Result{
		{ID: "SYS-001", Subject: "host", Level: checks.Pass, Message: "ubuntu 24.04 is a tested release"},
		{ID: "SYS-002", Subject: "host", Level: checks.Fail, Message: "reboot pending for 20 days",
			Evidence: map[string]any{"days": 20, "packages": []string{"linux-base"}, "db_password": secret}},
		{ID: "SYS-003", Subject: "host", Level: checks.Unknown, Message: "DB_PASSWORD=" + secret},
	}
	return Build(f, results, cat, Meta{
		Version: "test", Sandbox: sandbox.Status{State: sandbox.Unavailable, Reason: "test"},
		Profile: profile.Unknown, ProfileSource: "inferred", ChecksRun: 3,
	})
}

func TestBuild(t *testing.T) {
	r := sample(t)
	if r.Host.Hostname != "" || r.Host.HostnameHash != HashHostname("host.example.com") {
		t.Errorf("hostname must be hashed by default: %+v", r.Host)
	}
	if r.Summary != (Summary{Fail: 1, Unknown: 1, Pass: 1}) {
		t.Errorf("summary = %+v", r.Summary)
	}
	c := r.Coverage
	if c.Checked != 2 || c.Unknown != 1 || c.Skipped != 0 || c.Results != 3 || c.Checks != 3 || c.Root {
		t.Errorf("coverage = %+v", c)
	}
	if r.Results[1].Title == "" || r.Results[1].Severity == "" || r.Results[1].Fix.Hint == "" {
		t.Errorf("catalog not folded in: %+v", r.Results[1])
	}
}

func TestBuildRedacts(t *testing.T) {
	var buf bytes.Buffer
	r := sample(t)
	if err := WriteJSON(&buf, r); err != nil {
		t.Fatal(err)
	}
	if err := WriteText(&buf, r, TextOptions{Passing: true}); err != nil {
		t.Fatal(err)
	}
	if strings.Contains(buf.String(), "hunter2") {
		t.Fatalf("planted secret reached output:\n%s", buf.String())
	}
	if !strings.Contains(buf.String(), "[REDACTED]") {
		t.Fatal("expected redaction markers")
	}
}

func TestExitCode(t *testing.T) {
	r := &Report{Summary: Summary{Warn: 1}}
	if r.ExitCode(FailOnFail) != ExitOK || r.ExitCode(FailOnWarn) != ExitFindings || r.ExitCode(FailOnNever) != ExitOK {
		t.Error("warn only")
	}
	r.Summary.Fail = 1
	if r.ExitCode(FailOnFail) != ExitFindings || r.ExitCode(FailOnNever) != ExitOK {
		t.Error("with a fail")
	}
	r = &Report{Summary: Summary{Unknown: 5, Pass: 1}}
	if r.ExitCode(FailOnWarn) != ExitOK {
		t.Error("unknown alone does not trip the threshold")
	}
}

func TestJSONMatchesSchema(t *testing.T) {
	schema, err := os.ReadFile(filepath.Join("..", "..", "schema", "report.v1.json"))
	if err != nil {
		t.Fatal(err)
	}
	var buf bytes.Buffer
	if err := WriteJSON(&buf, sample(t)); err != nil {
		t.Fatal(err)
	}
	for _, e := range schemacheck.Validate(schema, buf.Bytes()) {
		t.Error(e)
	}
	// And the validator is not vacuous: a broken document fails.
	bad := strings.Replace(buf.String(), `"level": "fail"`, `"level": "bad"`, 1)
	if len(schemacheck.Validate(schema, []byte(bad))) == 0 {
		t.Error("schema check accepted an invalid level")
	}
}

func TestText(t *testing.T) {
	var buf bytes.Buffer
	if err := WriteText(&buf, sample(t), TextOptions{}); err != nil {
		t.Fatal(err)
	}
	out := buf.String()
	for _, want := range []string{
		"root:      no, run with sudo for full coverage",
		"sandbox:   unavailable (test)",
		"collector: ssh failed:",
		"SYS  System  (1 passing or skipped not shown)",
		"FAIL    SYS-002  No reboot pending [moderate]",
		"fix: Reboot in a maintenance window",
		"summary: 1 fail, 0 warn, 1 unknown, 0 info, 1 pass, 0 skip",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("missing %q in:\n%s", want, out)
		}
	}
	if strings.Contains(out, "\x1b[") {
		t.Error("colors without Color option")
	}
}

func sampleProbe(t *testing.T) *Report {
	t.Helper()
	cat, err := catalog.Load()
	if err != nil {
		t.Fatal(err)
	}
	f := &facts.Facts{
		CollectedAt: time.Date(2026, 3, 1, 12, 0, 0, 0, time.UTC),
		Collectors:  []facts.CollectorStatus{{Name: "tcp", Status: facts.StatusOK}},
	}
	results := []checks.Result{{ID: "SYS-001", Subject: "port:tcp/22", Level: checks.Warn, Message: "open"}}
	secret := "hunter" + "2-not-real"
	return Build(f, results, cat, Meta{
		Version: "test", Sandbox: sandbox.Status{State: sandbox.Unavailable, Reason: "test"},
		Profile: profile.Unknown, ProfileSource: "inferred", ChecksRun: 1,
		Probe: &Probe{
			Target:    "203.0.113.10",
			Addresses: []ProbeAddress{{Address: "203.0.113.10", Family: "ipv4"}},
			Families:  []ProbeFamily{{Family: "ipv4", Status: "probed"}, {Family: "ipv6", Status: "no-address", Detail: "the target is an IPv4 address"}},
			Ports: []ProbePort{
				{Address: "203.0.113.10", Family: "ipv4", Port: 22, State: "open", Banner: "SSH-2.0-OpenSSH_9.6 password=" + secret},
				{Address: "203.0.113.10", Family: "ipv4", Port: 80, State: "closed"},
			},
			Notes: []string{"profile unknown: judged conservatively"},
		},
	})
}

func TestProbeReport(t *testing.T) {
	r := sampleProbe(t)
	if r.Probe == nil || strings.Contains(r.Probe.Ports[0].Banner, "hunter") {
		t.Fatalf("probe section missing or not redacted: %+v", r.Probe)
	}
	schema, err := os.ReadFile(filepath.Join("..", "..", "schema", "report.v1.json"))
	if err != nil {
		t.Fatal(err)
	}
	var buf bytes.Buffer
	if err := WriteJSON(&buf, r); err != nil {
		t.Fatal(err)
	}
	for _, e := range schemacheck.Validate(schema, buf.Bytes()) {
		t.Error(e)
	}
	bad := strings.Replace(buf.String(), `"state": "open"`, `"state": "ajar"`, 1)
	if len(schemacheck.Validate(schema, []byte(bad))) == 0 {
		t.Error("schema check accepted an invalid port state")
	}
	buf.Reset()
	if err := WriteText(&buf, r, TextOptions{}); err != nil {
		t.Fatal(err)
	}
	out := buf.String()
	for _, want := range []string{
		"stackward test probe (",
		"target:    203.0.113.10",
		"addresses: 203.0.113.10 (ipv4)",
		"ipv6:      no-address: the target is an IPv4 address",
		"open:      tcp/22 on 203.0.113.10",
		"note:      profile unknown: judged conservatively",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("missing %q in:\n%s", want, out)
		}
	}
	if strings.Contains(out, "root:") || strings.Contains(out, "kernel:") {
		t.Errorf("probe header must not print host lines:\n%s", out)
	}
	// Audit reports never carry the probe section.
	buf.Reset()
	if err := WriteJSON(&buf, sample(t)); err != nil {
		t.Fatal(err)
	}
	if strings.Contains(buf.String(), `"probe"`) {
		t.Error("audit report has a probe section")
	}
}
