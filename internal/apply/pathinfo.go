package apply

import (
	"errors"
	"io/fs"
	"os"

	"github.com/Shironex/stackward/internal/plan"
)

// PathInfo implements plan.TreeReader for the host: the metadata of p,
// without following a final symlink and without reading content.
func (h *dirHost) PathInfo(p string) (plan.PathInfo, error) {
	rp, err := h.real(p)
	if err != nil {
		return plan.PathInfo{}, err
	}
	fi, err := os.Lstat(rp)
	if errors.Is(err, fs.ErrNotExist) {
		return plan.PathInfo{UID: -1}, nil
	}
	if err != nil {
		return plan.PathInfo{}, err
	}
	uid, _ := owner(fi)
	return plan.PathInfo{
		Exists:  true,
		Regular: fi.Mode().IsRegular(),
		Dir:     fi.IsDir(),
		Symlink: fi.Mode()&fs.ModeSymlink != 0,
		Perm:    fi.Mode().Perm(),
		UID:     uid,
	}, nil
}

// The host is a plan.TreeReader, so mode judging checks see the files.
var _ plan.TreeReader = (*dirHost)(nil)
