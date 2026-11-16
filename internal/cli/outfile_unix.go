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
	return openOutput("--out", path, 0o600, false)
}

// createTextfile opens the Prometheus textfile for writing, with the same
// symlink refusal as createOutput. The file is made readable by everyone
// (0644, also when it already existed with another mode): node_exporter
// usually runs as its own user, and the file holds counts only.
func createTextfile(path string) (*os.File, error) {
	return openOutput("--textfile", path, 0o644, true)
}

// openOutput opens path for writing, creating it with mode. forceMode also
// sets mode on a file that already existed (--out keeps the mode the user
// gave an existing file, as it always did).
func openOutput(flagName, path string, mode os.FileMode, forceMode bool) (*os.File, error) {
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_TRUNC|syscall.O_NOFOLLOW, mode)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", flagName, err)
	}
	fi, err := f.Stat()
	if err != nil || !fi.Mode().IsRegular() {
		_ = f.Close()
		return nil, fmt.Errorf("%s: %s is not a regular file", flagName, path)
	}
	if forceMode && fi.Mode().Perm() != mode {
		if err := f.Chmod(mode); err != nil {
			_ = f.Close()
			return nil, fmt.Errorf("%s: %w", flagName, err)
		}
	}
	return f, nil
}
