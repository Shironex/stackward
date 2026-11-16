//go:build unix

package cli

import (
	"errors"
	"fmt"
	"os"
	"syscall"
)

// createOutput opens the report file for writing. It refuses to follow a
// symlink at the final path component, so a root run cannot be tricked into
// overwriting another file through a planted link, refuses anything but a
// regular file with a single link (a hard link to another file, a FIFO that
// would block the run, a device), and creates the file readable by its owner
// only. An existing file keeps its mode.
func createOutput(path string) (*os.File, error) {
	return openOutput("--out", path, 0o600, false)
}

// createTextfile opens the Prometheus textfile for writing. The textfile
// directory is often shared with other programs, so whatever is at the path
// is unlinked first (a planted symlink, hard link or FIFO goes away, its
// target is left alone) and the file is created fresh with O_EXCL. It is
// made readable by everyone (0644, despite the umask): node_exporter usually
// runs as its own user, and the file holds counts only.
func createTextfile(path string) (*os.File, error) {
	return openOutput("--textfile", path, 0o644, true)
}

// openOutput opens path for writing with the checks above. fresh unlinks
// what is at path and creates a new file with mode; otherwise an existing
// regular file is truncated after the checks, keeping its mode.
func openOutput(flagName, path string, mode os.FileMode, fresh bool) (*os.File, error) {
	flags := os.O_WRONLY | os.O_CREATE | syscall.O_NOFOLLOW | syscall.O_NONBLOCK
	if fresh {
		if err := syscall.Unlink(path); err != nil && !errors.Is(err, syscall.ENOENT) {
			return nil, fmt.Errorf("%s: removing the old %s: %w", flagName, path, err)
		}
		flags |= os.O_EXCL
	}
	f, err := os.OpenFile(path, flags, mode)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", flagName, err)
	}
	fail := func(err error) (*os.File, error) {
		_ = f.Close()
		return nil, fmt.Errorf("%s: %w", flagName, err)
	}
	fi, err := f.Stat()
	if err != nil {
		return fail(err)
	}
	if !fi.Mode().IsRegular() {
		return fail(fmt.Errorf("%s is not a regular file", path))
	}
	if st, ok := fi.Sys().(*syscall.Stat_t); ok && st.Nlink > 1 {
		return fail(fmt.Errorf("%s has other hard links; refusing to write through it", path))
	}
	if fresh && fi.Mode().Perm() != mode {
		if err := f.Chmod(mode); err != nil {
			return fail(err)
		}
	}
	if !fresh {
		if err := f.Truncate(0); err != nil {
			return fail(err)
		}
	}
	return f, nil
}
