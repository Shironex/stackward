package cli

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/Shironex/stackward/internal/report"
)

func TestAuditTextfile(t *testing.T) {
	dir := t.TempDir()
	repPath := filepath.Join(dir, "report.json")
	promPath := filepath.Join(dir, "stackward.prom.tmp")
	// A leftover temporary file with a private mode is made readable.
	if err := os.WriteFile(promPath, []byte("stale stale stale stale stale\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	code, out, errs := run("audit", "--no-sandbox", "--facts", fixture("debian-12-reboot-overdue"),
		"--format", "json", "--fail-on", "never", "--out", repPath, "--textfile", promPath)
	if code != report.ExitOK || out != "" {
		t.Fatalf("exit %d, stdout %q, stderr %s", code, out, errs)
	}
	b, err := os.ReadFile(promPath)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(b, []byte("stale")) || !bytes.Contains(b, []byte(`stackward_results{level="fail"} `)) {
		t.Errorf("textfile not rewritten:\n%s", b)
	}
	if fi, _ := os.Stat(promPath); fi.Mode().Perm() != 0o644 {
		t.Errorf("textfile mode %v, want 0644", fi.Mode().Perm())
	}
	if fi, _ := os.Stat(repPath); fi.Mode().Perm() != 0o600 {
		t.Errorf("report mode %v, want 0600", fi.Mode().Perm())
	}
}

func TestAuditTextfileRefusalsAndSymlink(t *testing.T) {
	dir := t.TempDir()
	code, _, errs := run("audit", "--no-sandbox", "--facts", fixture("ubuntu-2404-clean"), "--dump-facts", "--textfile", filepath.Join(dir, "x.prom"))
	if code != report.ExitError || !strings.Contains(errs, "--dump-facts") {
		t.Errorf("--textfile with --dump-facts: exit %d, stderr %q", code, errs)
	}
	if _, err := os.Stat(filepath.Join(dir, "x.prom")); err == nil {
		t.Error("a refused run created the textfile")
	}

	target := filepath.Join(dir, "target")
	if err := os.WriteFile(target, []byte("keep"), 0o600); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(dir, "link.prom")
	if err := os.Symlink(target, link); err != nil {
		t.Skip("symlinks unavailable:", err)
	}
	// A planted symlink is unlinked and replaced, never followed.
	code, _, errs = run("audit", "--no-sandbox", "--facts", fixture("ubuntu-2404-clean"), "--textfile", link)
	if code != report.ExitOK {
		t.Errorf("--textfile over a symlink: exit %d, want %d; stderr %s", code, report.ExitOK, errs)
	}
	if fi, err := os.Lstat(link); err != nil || !fi.Mode().IsRegular() {
		t.Errorf("symlink not replaced by a regular file: %v", err)
	}
	if b, _ := os.ReadFile(target); string(b) != "keep" {
		t.Errorf("symlink target overwritten: %q", b)
	}
}
