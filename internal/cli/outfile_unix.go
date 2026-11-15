//go:build unix

package cli

import (
	"fmt"
	"os"
	"syscall"
)

// createOutput opens the report file for writing. It refuses to follow a
// symlink at the final path component, so a root run cannot be tricked into
// overwriting another file through a planted link, and creates the file
// readable by its owner only.
func createOutput(path string) (*os.File, error) {
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_TRUNC|syscall.O_NOFOLLOW, 0o600)
	if err != nil {
		return nil, fmt.Errorf("--out: %w", err)
	}
	fi, err := f.Stat()
	if err != nil || !fi.Mode().IsRegular() {
		_ = f.Close()
		return nil, fmt.Errorf("--out: %s is not a regular file", path)
	}
	return f, nil
}
