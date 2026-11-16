//go:build unix

package cli

import (
	"errors"
	"fmt"
	"os"
	"syscall"
)

// openWaivers opens the waivers file without following a symlink and
// without blocking on a FIFO, then checks what it opened: a regular file,
// not writable by group or others, and for the implicit default file
// (checkOwner) owned by the user running stackward or by root. Otherwise
// anyone who can drop a .stackward.yml where root runs an audit could
// accept findings for it. A file named with --waivers is the operator's
// own choice, so its owner is not checked.
func openWaivers(path string, checkOwner bool) (*os.File, error) {
	if fi, err := os.Lstat(path); err != nil {
		return nil, err
	} else if fi.Mode()&os.ModeSymlink != 0 {
		return nil, errors.New("is a symlink; name the file it points to with --waivers")
	}
	fh, err := os.OpenFile(path, os.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_NONBLOCK, 0)
	if err != nil {
		return nil, err
	}
	if err := checkWaiversFile(fh, checkOwner); err != nil {
		_ = fh.Close()
		return nil, err
	}
	return fh, nil
}

func checkWaiversFile(fh *os.File, checkOwner bool) error {
	fi, err := fh.Stat()
	if err != nil {
		return err
	}
	if !fi.Mode().IsRegular() {
		return errors.New("not a regular file")
	}
	if perm := fi.Mode().Perm(); perm&0o022 != 0 {
		return fmt.Errorf("writable by group or others (mode %04o); run chmod go-w on it", perm)
	}
	st, ok := fi.Sys().(*syscall.Stat_t)
	if !checkOwner || !ok {
		return nil
	}
	if euid := os.Geteuid(); int64(st.Uid) != int64(euid) && st.Uid != 0 {
		return fmt.Errorf("owned by uid %d, not by you (uid %d) or root; the default file is only read when it is yours. "+
			"Under sudo in your own checkout, pass it explicitly with --waivers %s, or chown it to root", st.Uid, euid, fh.Name())
	}
	return nil
}
