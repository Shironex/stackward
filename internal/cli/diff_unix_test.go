//go:build unix

package cli

import (
	"path/filepath"
	"strings"
	"syscall"
	"testing"

	"github.com/Shironex/stackward/internal/report"
)

// TestDiffRefusesFIFO: a FIFO given as a report is refused at once instead
// of hanging the run on a reader that never comes.
func TestDiffRefusesFIFO(t *testing.T) {
	fifo := filepath.Join(t.TempDir(), "report.json")
	if err := syscall.Mkfifo(fifo, 0o600); err != nil {
		t.Skip("mkfifo:", err)
	}
	code, _, errs := run("diff", "--no-sandbox", listenerReport("old.json"), fifo)
	if code != report.ExitError || !strings.Contains(errs, "not a regular file") {
		t.Errorf("exit %d, stderr %q", code, errs)
	}
	if code, _, _ := run("audit", "--no-sandbox", "--facts", fixture("ubuntu-2404-clean"), "--baseline", fifo); code != report.ExitError {
		t.Errorf("--baseline FIFO: exit %d", code)
	}
}
