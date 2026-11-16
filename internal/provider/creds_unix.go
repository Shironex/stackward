//go:build unix

package provider

import (
	"errors"
	"fmt"
	"io/fs"
	"os"
	"syscall"
)

// openNoFollow opens path read only and refuses a symlink at the last
// component (O_NOFOLLOW), so the checks run on the file that is read.
func openNoFollow(path string) (*os.File, error) {
	fh, err := os.OpenFile(path, os.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_NONBLOCK, 0)
	if errors.Is(err, syscall.ELOOP) {
		return nil, fmt.Errorf("is a symlink; point the variable at the file itself")
	}
	return fh, err
}

// fileOwner returns the owning uid of fi.
func fileOwner(fi fs.FileInfo) (int, bool) {
	st, ok := fi.Sys().(*syscall.Stat_t)
	if !ok {
		return 0, false
	}
	return int(st.Uid), true
}
