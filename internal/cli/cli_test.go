package cli

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/Shironex/stackward/internal/facts"
	"github.com/Shironex/stackward/internal/report"
	"github.com/Shironex/stackward/internal/schemacheck"
)

// Every audit call in these tests passes --no-sandbox: Landlock cannot be
// undone, and confining the test process would break every later test.

func fixture(name string) string {
	return filepath.Join("..", "..", "test", "fixtures", name, "facts.json")
}

func run(args ...string) (int, string, string) {
	var out, errb bytes.Buffer
	code := Run(args, &out, &errb)
	return code, out.String(), errb.String()
}

func TestAuditFromFactsJSON(t *testing.T) {
	code, out, errs := run("audit", "--no-sandbox", "--facts", fixture("debian-12-reboot-overdue"), "--json")
	if code != report.ExitFindings {
		t.Fatalf("exit %d, want %d (a fail is present); stderr %s", code, report.ExitFindings, errs)
	}
	schema, err := os.ReadFile(filepath.Join("..", "..", "schema", "report.v1.json"))
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range schemacheck.Validate(schema, []byte(out)) {
		t.Error(e)
	}
	if !strings.Contains(out, `"state": "disabled"`) {
		t.Errorf("--no-sandbox must show in coverage:\n%s", out)
	}
}

func TestAuditExitCodes(t *testing.T) {
	cases := []struct {
		args []string
		want int
	}{
		{[]string{"--facts", fixture("debian-12-reboot-overdue"), "--fail-on", "never"}, report.ExitOK},
		{[]string{"--facts", fixture("ubuntu-2404-clean")}, report.ExitOK},
		{[]string{"--facts", fixture("ubuntu-2404-clean"), "--fail-on", "warn"}, report.ExitOK},
		{[]string{"--facts", fixture("nonroot-partial"), "--fail-on", "warn"}, report.ExitOK},
		{[]string{"--format", "yaml"}, report.ExitError},
		{[]string{"--fail-on", "sometimes"}, report.ExitError},
		{[]string{"--profile", "moat"}, report.ExitError},
		{[]string{"--facts", "does-not-exist.json"}, report.ExitError},
		{[]string{"stray"}, report.ExitError},
	}
	for _, tc := range cases {
		code, _, errs := run(append([]string{"audit", "--no-sandbox"}, tc.args...)...)
		if code != tc.want {
			t.Errorf("%v: exit %d, want %d (stderr %s)", tc.args, code, tc.want, errs)
		}
	}
}

func TestAuditText(t *testing.T) {
	code, out, _ := run("audit", "--no-sandbox", "--facts", fixture("debian-12-reboot-overdue"), "--profile", "tunnel", "--show-hostname")
	if code != report.ExitFindings {
		t.Fatalf("exit %d", code)
	}
	for _, want := range []string{"host:      db1.example.com", "profile:   tunnel (flag)", "FAIL    SYS-002"} {
		if !strings.Contains(out, want) {
			t.Errorf("missing %q in\n%s", want, out)
		}
	}
}

func TestAuditOut(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "report.json")
	code, out, _ := run("audit", "--no-sandbox", "--facts", fixture("ubuntu-2404-clean"), "--json", "--out", path)
	if code != report.ExitOK || out != "" {
		t.Fatalf("exit %d, stdout %q", code, out)
	}
	b, err := os.ReadFile(path)
	if err != nil || !bytes.Contains(b, []byte(`"schema": "stackward.report.v1"`)) {
		t.Fatalf("report file: %v %s", err, b)
	}
	if fi, _ := os.Stat(path); fi.Mode().Perm() != 0o600 {
		t.Errorf("report mode %v, want 0600", fi.Mode().Perm())
	}

	target := filepath.Join(dir, "target")
	if err := os.WriteFile(target, []byte("keep"), 0o600); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(dir, "link.json")
	if err := os.Symlink(target, link); err != nil {
		t.Skip("symlinks unavailable:", err)
	}
	code, _, _ = run("audit", "--no-sandbox", "--facts", fixture("ubuntu-2404-clean"), "--out", link)
	if code != report.ExitError {
		t.Errorf("--out through a symlink: exit %d, want %d", code, report.ExitError)
	}
	if b, _ := os.ReadFile(target); string(b) != "keep" {
		t.Errorf("symlink target overwritten: %q", b)
	}
}

func TestDumpFactsRoundTrip(t *testing.T) {
	code, out, errs := run("audit", "--no-sandbox", "--facts", fixture("nonroot-partial"), "--dump-facts")
	if code != report.ExitOK {
		t.Fatalf("exit %d: %s", code, errs)
	}
	f, err := facts.Load(strings.NewReader(out))
	if err != nil {
		t.Fatalf("dump does not load back: %v\n%s", err, out)
	}
	if f.Host.Hostname != report.HashHostname("box.example.com") {
		t.Errorf("hostname not hashed in dump: %q", f.Host.Hostname)
	}
	if strings.Contains(out, "not-a-real-value") {
		t.Errorf("planted secret survived the dump:\n%s", out)
	}
}

func TestAuditLiveHost(t *testing.T) {
	// The real collectors on whatever machine runs the tests: no panic, a
	// valid report, and a defined exit code.
	code, out, errs := run("audit", "--no-sandbox", "--json")
	if code != report.ExitOK && code != report.ExitFindings {
		t.Fatalf("exit %d: %s", code, errs)
	}
	schema, _ := os.ReadFile(filepath.Join("..", "..", "schema", "report.v1.json"))
	for _, e := range schemacheck.Validate(schema, []byte(out)) {
		t.Error(e)
	}
}

func TestExplain(t *testing.T) {
	code, out, _ := run("explain", "sys-002")
	if code != report.ExitOK || !strings.Contains(out, "SYS-002  No reboot pending") || !strings.Contains(out, "Why it matters") {
		t.Errorf("explain: %d\n%s", code, out)
	}
	code, out, _ = run("explain")
	if code != report.ExitOK || !strings.HasPrefix(out, "SYS  System\n") || !strings.Contains(out, "SYS-003") {
		t.Errorf("explain list: %d\n%s", code, out)
	}
	if code, _, _ := run("explain", "NOPE-001"); code != report.ExitError {
		t.Errorf("unknown id: exit %d", code)
	}
}

func TestCommands(t *testing.T) {
	if code, out, _ := run("version"); code != report.ExitOK || !strings.HasPrefix(out, "stackward ") {
		t.Errorf("version: %d %q", code, out)
	}
	if code, _, _ := run(); code != report.ExitError {
		t.Error("no args")
	}
	if code, _, _ := run("frobnicate"); code != report.ExitError {
		t.Error("unknown command")
	}
	if code, out, _ := run("help"); code != report.ExitOK || !strings.Contains(out, "Exit codes") {
		t.Error("help")
	}
}

func TestWrap(t *testing.T) {
	got := wrap("one two three four", 10, "  ")
	if got != "  one two\n  three\n  four" {
		t.Errorf("%q", got)
	}
}

func TestAuditMarkdown(t *testing.T) {
	for _, flag := range [][]string{{"--md"}, {"--format", "md"}} {
		args := append([]string{"audit", "--no-sandbox", "--facts", fixture("debian-12-reboot-overdue")}, flag...)
		code, out, errs := run(args...)
		if code != report.ExitFindings || errs != "" {
			t.Fatalf("%v: code %d, stderr %q", flag, code, errs)
		}
		if !strings.HasPrefix(out, "# stackward ") || !strings.Contains(out, "## Summary") {
			t.Errorf("%v: not Markdown output:\n%s", flag, out)
		}
	}
}
