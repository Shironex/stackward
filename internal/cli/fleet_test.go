package cli

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/Shironex/stackward/internal/audit"
	"github.com/Shironex/stackward/internal/facts"
	"github.com/Shironex/stackward/internal/fleet"
	"github.com/Shironex/stackward/internal/report"
	"github.com/Shironex/stackward/internal/sandbox"
	"github.com/Shironex/stackward/internal/schemacheck"
)

// fakeFleet puts the fleet package's fake ssh on PATH, and a stand in for
// the binary behind the fleetLoadBinaries seam. It returns the directory
// of ssh call logs and the remote TMPDIR.
func fakeFleet(t *testing.T) (calls, remoteTmp string) {
	t.Helper()
	dir := t.TempDir()
	calls, remoteTmp = filepath.Join(dir, "calls"), filepath.Join(dir, "tmp")
	pathDir := filepath.Join(dir, "path")
	for _, d := range []string{calls, remoteTmp, pathDir} {
		if err := os.MkdirAll(d, 0o755); err != nil {
			t.Fatal(err)
		}
	}
	testdata, err := filepath.Abs(filepath.Join("..", "fleet", "testdata"))
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(filepath.Join(testdata, "fakessh.sh"), filepath.Join(pathDir, "ssh")); err != nil {
		t.Fatal(err)
	}
	fh, err := os.Open(fixture("debian-12-reboot-overdue"))
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = fh.Close() }()
	f, err := facts.Load(fh)
	if err != nil {
		t.Fatal(err)
	}
	rep, err := audit.Evaluate(f, audit.Options{Version: "test", Sandbox: sandbox.Status{State: sandbox.Landlock, ABI: 4}})
	if err != nil {
		t.Fatal(err)
	}
	var b bytes.Buffer
	if err := report.WriteJSON(&b, rep); err != nil {
		t.Fatal(err)
	}
	reportPath := filepath.Join(dir, "report.json")
	if err := os.WriteFile(reportPath, b.Bytes(), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", pathDir+string(os.PathListSeparator)+os.Getenv("PATH"))
	t.Setenv("FAKE_SSH_LOG", calls)
	t.Setenv("FAKE_SSH_TMP", remoteTmp)
	t.Setenv("FAKE_BIN_LOG", filepath.Join(dir, "bin.log"))
	t.Setenv("FAKE_REPORT", reportPath)
	t.Setenv("FAKE_SSH_DOWN", "")
	t.Setenv("FAKE_SSH_ARM", "")
	old := fleetLoadBinaries
	fleetLoadBinaries = func([]string, string) ([]fleet.Binary, error) {
		return []fleet.Binary{{Path: filepath.Join(testdata, "fakebinary.sh"), Arch: fleet.AMD64}}, nil
	}
	t.Cleanup(func() { fleetLoadBinaries = old })
	return calls, remoteTmp
}

func countEntries(t *testing.T, dir string) int {
	t.Helper()
	ents, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	return len(ents)
}

func TestAuditSSHJSON(t *testing.T) {
	_, remoteTmp := fakeFleet(t)
	root := filepath.Join("..", "..", "schema")
	fleetSchema, err := os.ReadFile(filepath.Join(root, "fleet.v1.json"))
	if err != nil {
		t.Fatal(err)
	}
	reportSchema, err := os.ReadFile(filepath.Join(root, "report.v1.json"))
	if err != nil {
		t.Fatal(err)
	}
	work := t.TempDir()
	t.Chdir(work)
	code, out, errs := run("audit", "--ssh", "--json", "--fail-on", "never", "web1", "admin@db1")
	if code != report.ExitOK {
		t.Fatalf("exit %d, stderr %s", code, errs)
	}
	for _, e := range schemacheck.Validate(fleetSchema, []byte(out)) {
		t.Error(e)
	}
	var doc struct {
		Hosts []struct {
			Host   string          `json:"host"`
			Report json.RawMessage `json:"report"`
		} `json:"hosts"`
	}
	if err := json.Unmarshal([]byte(out), &doc); err != nil {
		t.Fatal(err)
	}
	if len(doc.Hosts) != 2 || doc.Hosts[0].Host != "web1" || doc.Hosts[1].Host != "admin@db1" {
		t.Fatalf("hosts %+v", doc.Hosts)
	}
	for _, h := range doc.Hosts {
		for _, e := range schemacheck.Validate(reportSchema, h.Report) {
			t.Errorf("%s: %v", h.Host, e)
		}
	}
	if n := countEntries(t, remoteTmp); n != 0 {
		t.Errorf("%d entries left on the remote", n)
	}
	// No host name is kept anywhere but the report on stdout.
	if n := countEntries(t, work); n != 0 {
		t.Errorf("the run wrote %d files into the working directory", n)
	}
	// The findings decide the exit code with the default --fail-on.
	if code, _, _ := run("audit", "--ssh", "--json", "web1"); code != report.ExitFindings {
		t.Errorf("exit %d, want %d", code, report.ExitFindings)
	}
}

func TestAuditSSHPartialFailureText(t *testing.T) {
	fakeFleet(t)
	t.Setenv("FAKE_SSH_DOWN", "down1")
	code, out, errs := run("audit", "--ssh", "--plain", "--fail-on", "never", "web1", "down1")
	if code != report.ExitError {
		t.Fatalf("exit %d, want %d when a host fails", code, report.ExitError)
	}
	for _, want := range []string{
		"fleet audit", "hosts:     2 (1 audited, 1 failed)",
		"web1  audited  linux/amd64", "coverage: ", "down1  error",
		"error: ssh failed (exit 255)", "=== web1 ===",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("text misses %q:\n%s", want, out)
		}
	}
	if !strings.Contains(errs, "down1: ssh failed") {
		t.Errorf("stderr must name the failed host: %s", errs)
	}
}

func TestAuditSSHMarkdownOut(t *testing.T) {
	fakeFleet(t)
	hosts := filepath.Join(t.TempDir(), "hosts")
	if err := os.WriteFile(hosts, []byte("# fleet\nweb1\nweb2 # second\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	out := filepath.Join(t.TempDir(), "fleet.md")
	code, stdout, errs := run("audit", "--ssh-hosts", hosts, "--md", "--out", out, "--fail-on", "never")
	if code != report.ExitOK || stdout != "" {
		t.Fatalf("exit %d, stdout %q, stderr %s", code, stdout, errs)
	}
	b, err := os.ReadFile(out)
	if err != nil {
		t.Fatal(err)
	}
	md := string(b)
	for _, want := range []string{"# stackward ", "| Host | Status | Fail | Warn | Unknown | Coverage |", "| web1 | audited |", "## Host web2", "### stackward test audit", "checks, "} {
		if !strings.Contains(md, want) {
			t.Errorf("markdown misses %q:\n%s", want, md)
		}
	}
}

func TestAuditSSHRefusesInjection(t *testing.T) {
	calls, _ := fakeFleet(t)
	badFile := filepath.Join(t.TempDir(), "hosts")
	if err := os.WriteFile(badFile, []byte("web1\n-oProxyCommand=touch /tmp/owned\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	cases := []struct {
		args []string
		want string
	}{
		{[]string{"--ssh", "--", "-oProxyCommand=touch /tmp/owned"}, "starts with '-'"},
		{[]string{"--ssh", "web1", "--json"}, "starts with '-'"},
		{[]string{"--ssh", "web1;id"}, "refused"},
		{[]string{"--ssh", "$(id)"}, "refused"},
		{[]string{"--ssh", "web1 -oProxyCommand=x"}, "refused"},
		{[]string{"--ssh-hosts", badFile}, "line 2"},
	}
	for _, tc := range cases {
		code, _, errs := run(append([]string{"audit"}, tc.args...)...)
		if code != report.ExitError || !strings.Contains(errs, tc.want) {
			t.Errorf("%q: exit %d, stderr %q, want %q", tc.args, code, errs, tc.want)
		}
	}
	if n := countEntries(t, calls); n != 0 {
		t.Errorf("ssh was started %d times for refused hosts", n)
	}
}

func TestAuditSSHFlagChecks(t *testing.T) {
	calls, _ := fakeFleet(t)
	for _, args := range [][]string{
		{"--ssh"},
		{"--ssh", "--facts", fixture("ubuntu-2404-clean"), "web1"},
		{"--ssh", "--dump-facts", "web1"},
		{"--ssh", "--no-sandbox", "web1"},
		{"--ssh", "--provider", "hetzner", "web1"},
		{"--ssh", "--ssh-parallel", "0", "web1"},
		{"--ssh", "--ssh-parallel", "99", "web1"},
		{"--ssh", "--ssh-timeout", "0s", "web1"},
		{"--ssh-sudo"},
		{"--ssh-binary", "x"},
		{"--ssh-hosts", "does-not-exist"},
		{"web1"},
	} {
		code, _, errs := run(append([]string{"audit"}, args...)...)
		if code != report.ExitError {
			t.Errorf("%q: exit %d, want %d (stderr %s)", args, code, report.ExitError, errs)
		}
	}
	if n := countEntries(t, calls); n != 0 {
		t.Errorf("ssh was started %d times", n)
	}
}
