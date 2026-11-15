//go:build unix

package apply

import (
	"io/fs"
	"syscall"
)

// noFollow makes an open fail on a symlink at the final path component.
const noFollow = syscall.O_NOFOLLOW

// owner returns the uid and gid of fi, or -1, -1 when unknown.
func owner(fi fs.FileInfo) (uid, gid int) {
	if st, ok := fi.Sys().(*syscall.Stat_t); ok {
		return int(st.Uid), int(st.Gid)
	}
	return -1, -1
}
