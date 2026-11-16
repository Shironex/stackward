//go:build !unix

package provider

import (
	"fmt"
	"io/fs"
	"os"
)

// openNoFollow opens path read only after refusing a symlink. stackward
// audits Linux hosts; this variant only keeps other builds compiling.
func openNoFollow(path string) (*os.File, error) {
	fi, err := os.Lstat(path)
	if err != nil {
		return nil, err
	}
	if fi.Mode()&fs.ModeSymlink != 0 {
		return nil, fmt.Errorf("is a symlink; point the variable at the file itself")
	}
	return os.Open(path)
}

// fileOwner is unknown outside Unix.
func fileOwner(fs.FileInfo) (int, bool) { return 0, false }
