//go:build unix

package facts

import (
	"io/fs"
	"syscall"
)

func fillOwner(m *FileMeta, fi fs.FileInfo) {
	if st, ok := fi.Sys().(*syscall.Stat_t); ok {
		m.UID = int(st.Uid)
		m.GID = int(st.Gid)
	}
}
