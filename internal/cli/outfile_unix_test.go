//go:build unix

package cli

import (
	"os"
	"path/filepath"
	"syscall"
	"testing"
	"time"

	"github.com/Shironex/stackward/internal/report"
)

// runWithin fails the test when the audit does not return in time: a FIFO
// at an output path must never block the run.
func runWithin(t *testing.T, args ...string) (int, string) {
	t.Helper()
	type res struct {
		code int
		errs string
	}
	done := make(chan res, 1)
	go func() {
		code, _, errs := run(args...)
		done <- res{code, errs}
	}()
	select {
	case r := <-done:
		return r.code, r.errs
	case <-time.After(20 * time.Second):
		t.Fatal("audit blocked on an output path")
		return 0, ""
	}
}

func TestOutputRefusesHardLinkAndFIFO(t *testing.T) {
	dir := t.TempDir()
	target := filepath.Join(dir, "target")
	if err := os.WriteFile(target, []byte("keep"), 0o600); err != nil {
		t.Fatal(err)
	}
	hard := filepath.Join(dir, "hard.json")
	if err := os.Link(target, hard); err != nil {
		t.Skip("hard links unavailable:", err)
	}
	code, errs := runWithin(t, "audit", "--no-sandbox", "--facts", fixture("ubuntu-2404-clean"), "--json", "--out", hard)
	if code != report.ExitError {
		t.Errorf("--out through a hard link: exit %d, want %d; stderr %s", code, report.ExitError, errs)
	}
	if b, _ := os.ReadFile(target); string(b) != "keep" {
		t.Errorf("hard link target changed: %q", b)
	}

	fifo := filepath.Join(dir, "fifo.json")
	if err := syscall.Mkfifo(fifo, 0o600); err != nil {
		t.Skip("FIFOs unavailable:", err)
	}
	code, errs = runWithin(t, "audit", "--no-sandbox", "--facts", fixture("ubuntu-2404-clean"), "--json", "--out", fifo)
	if code != report.ExitError {
		t.Errorf("--out to a FIFO: exit %d, want %d; stderr %s", code, report.ExitError, errs)
	}
}

func TestTextfileReplacesHardLinkAndFIFO(t *testing.T) {
	dir := t.TempDir()
	target := filepath.Join(dir, "target")
	if err := os.WriteFile(target, []byte("keep"), 0o644); err != nil {
		t.Fatal(err)
	}
	hard := filepath.Join(dir, "hard.prom.tmp")
	if err := os.Link(target, hard); err != nil {
		t.Skip("hard links unavailable:", err)
	}
	fifo := filepath.Join(dir, "fifo.prom.tmp")
	if err := syscall.Mkfifo(fifo, 0o644); err != nil {
		t.Skip("FIFOs unavailable:", err)
	}
	for _, p := range []string{hard, fifo} {
		code, errs := runWithin(t, "audit", "--no-sandbox", "--facts", fixture("ubuntu-2404-clean"), "--json", "--out", filepath.Join(dir, "r.json"), "--textfile", p)
		if code != report.ExitOK {
			t.Fatalf("--textfile %s: exit %d; stderr %s", p, code, errs)
		}
		fi, err := os.Lstat(p)
		if err != nil || !fi.Mode().IsRegular() || fi.Mode().Perm() != 0o644 {
			t.Errorf("%s is not a fresh 0644 regular file: %v %v", p, fi.Mode(), err)
		}
		if st, ok := fi.Sys().(*syscall.Stat_t); ok && st.Nlink != 1 {
			t.Errorf("%s still has %d links", p, st.Nlink)
		}
	}
	if b, _ := os.ReadFile(target); string(b) != "keep" {
		t.Errorf("hard link target changed: %q", b)
	}
}
