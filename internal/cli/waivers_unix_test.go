//go:build unix

package cli

import (
	"path/filepath"
	"strings"
	"syscall"
	"testing"
)

func TestWaiversFIFORefused(t *testing.T) {
	p := filepath.Join(t.TempDir(), "fifo.yml")
	if err := syscall.Mkfifo(p, 0o600); err != nil {
		t.Skip(err)
	}
	// Would block forever on open if the type were not checked first.
	if _, err := loadWaivers(p); err == nil || !strings.Contains(err.Error(), "not a regular file") {
		t.Errorf("err = %v", err)
	}
}
