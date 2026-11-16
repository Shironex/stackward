package cli

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/Shironex/stackward/internal/report"
	"github.com/Shironex/stackward/internal/schemacheck"
	"github.com/Shironex/stackward/schema"
)

// Every diff and audit call here passes --no-sandbox, like cli_test.go.

// listenerReport is a report of the listener diff scenario.
func listenerReport(file string) string {
	return filepath.Join("..", "..", "test", "diff", "listener", file)
}

func TestDiffCommand(t *testing.T) {
	oldR, newR := listenerReport("old.json"), listenerReport("new.json")
	code, out, errs := run("diff", "--no-sandbox", oldR, newR)
	if code != report.ExitFindings || !strings.Contains(out, "DRIFT") || !strings.Contains(out, "port:tcp/8080") {
		t.Fatalf("exit %d, stderr %s\n%s", code, errs, out)
	}
	// Flags may follow the files.
	code, out, _ = run("diff", oldR, newR, "--no-sandbox", "--json", "--fail-on-drift", "never")
	if code != report.ExitOK {
		t.Errorf("--fail-on-drift never: exit %d", code)
	}
	for _, e := range schemacheck.Validate(schema.Diff, []byte(out)) {
		t.Error(e)
	}
	code, out, _ = run("diff", "--no-sandbox", "--md", oldR, oldR)
	if code != report.ExitOK || !strings.Contains(out, "No drift and no changed findings.") {
		t.Errorf("a report against itself: exit %d\n%s", code, out)
	}
	outFile := filepath.Join(t.TempDir(), "diff.md")
	if code, _, errs := run("diff", "--no-sandbox", "--md", "--out", outFile, oldR, newR); code != report.ExitFindings {
		t.Errorf("--out: exit %d %s", code, errs)
	}
	if b, err := os.ReadFile(outFile); err != nil || !strings.HasPrefix(string(b), "# stackward diff") {
		t.Errorf("--out file: %v %q", err, b)
	}
}

func TestDiffErrors(t *testing.T) {
	dir := t.TempDir()
	facts := fixture("ubuntu-2404-clean")
	other := filepath.Join(dir, "other.json")
	if code, _, errs := run("audit", "--no-sandbox", "--facts", fixture("debian-12-reboot-overdue"), "--json", "--out", other, "--fail-on", "never"); code != 0 {
		t.Fatalf("audit: %d %s", code, errs)
	}
	oldR := listenerReport("old.json")
	cases := []struct {
		name string
		args []string
		want string
	}{
		{"one file", []string{oldR}, "give two report files"},
		{"three files", []string{oldR, oldR, oldR}, "give two report files"},
		{"bad format", []string{"--format", "yaml", oldR, oldR}, "--format"},
		{"bad threshold", []string{"--fail-on-drift", "warn", oldR, oldR}, "--fail-on-drift"},
		{"missing file", []string{oldR, filepath.Join(dir, "nope.json")}, "nope.json"},
		{"a facts file", []string{oldR, facts}, "facts file"},
		{"a directory", []string{oldR, dir}, "not a regular file"},
		{"another host", []string{oldR, other}, "different hosts"},
	}
	for _, tc := range cases {
		code, _, errs := run(append([]string{"diff", "--no-sandbox"}, tc.args...)...)
		if code != report.ExitError || !strings.Contains(errs, tc.want) {
			t.Errorf("%s: exit %d, stderr %q, want it to mention %q", tc.name, code, errs, tc.want)
		}
	}
	if code, _, errs := run("diff", "--no-sandbox", "--force-host", "--fail-on-drift", "never", oldR, other); code != report.ExitOK {
		t.Errorf("--force-host: exit %d %s", code, errs)
	}
}

// TestAuditBaseline: audit --baseline prints the diff, and its exit code
// follows --fail-on-drift; an explicit --fail-on counts too.
func TestAuditBaseline(t *testing.T) {
	dir := t.TempDir()
	base := filepath.Join(dir, "base.json")
	f := fixture("debian-12-reboot-overdue") // has a fail
	if code, _, errs := run("audit", "--no-sandbox", "--facts", f, "--json", "--out", base, "--fail-on", "never"); code != 0 {
		t.Fatalf("audit: %d %s", code, errs)
	}
	code, out, errs := run("audit", "--no-sandbox", "--facts", f, "--baseline", base)
	if code != report.ExitOK || !strings.HasPrefix(out, "stackward diff: 0 drift items") {
		t.Errorf("same facts: exit %d (an old fail is not new), stderr %s\n%s", code, errs, out)
	}
	if code, _, _ := run("audit", "--no-sandbox", "--facts", f, "--baseline", base, "--fail-on", "fail"); code != report.ExitFindings {
		t.Errorf("explicit --fail-on fail: exit %d, want 1", code)
	}
	code, out, _ = run("audit", "--no-sandbox", "--facts", f, "--baseline", base, "--json")
	if code != report.ExitOK {
		t.Errorf("--json: exit %d", code)
	}
	for _, e := range schemacheck.Validate(schema.Diff, []byte(out)) {
		t.Error(e)
	}
	if code, _, errs := run("audit", "--no-sandbox", "--facts", fixture("ubuntu-2404-clean"), "--baseline", base); code != report.ExitError || !strings.Contains(errs, "different hosts") {
		t.Errorf("another host: exit %d %s", code, errs)
	}
	for _, args := range [][]string{
		{"--fail-on-drift", "drift"},
		{"--force-host"},
		{"--baseline", base, "--dump-facts"},
		{"--baseline", base, "--fail-on-drift", "sometimes"},
		{"--baseline", filepath.Join(dir, "missing.json")},
	} {
		if code, _, _ := run(append([]string{"audit", "--no-sandbox", "--facts", f}, args...)...); code != report.ExitError {
			t.Errorf("%v: exit %d, want 2", args, code)
		}
	}
}

// TestOutIsNotAnInput: --out naming one of the reports (or the baseline)
// is refused before that file is truncated.
func TestOutIsNotAnInput(t *testing.T) {
	dir := t.TempDir()
	orig, err := os.ReadFile(listenerReport("old.json"))
	if err != nil {
		t.Fatal(err)
	}
	base := filepath.Join(dir, "base.json")
	if err := os.WriteFile(base, orig, 0o600); err != nil {
		t.Fatal(err)
	}
	for _, args := range [][]string{
		{"diff", "--no-sandbox", "--out", base, base, listenerReport("new.json")},
		{"diff", "--no-sandbox", "--out", base, listenerReport("new.json"), base},
		{"audit", "--no-sandbox", "--facts", fixture("ubuntu-2404-clean"), "--force-host", "--baseline", base, "--out", base},
	} {
		code, _, errs := run(args...)
		if code != report.ExitError || !strings.Contains(errs, "also an input") {
			t.Errorf("%v: exit %d, stderr %q", args, code, errs)
		}
		if got, _ := os.ReadFile(base); !bytes.Equal(got, orig) {
			t.Fatalf("%v: the input was changed", args)
		}
	}
}
