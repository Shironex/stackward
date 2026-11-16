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
// not writable by group or others, owned by someone ownerAllowed accepts.
// Otherwise anyone who can drop a file where root runs an audit (a shared
// checkout, a predictable /tmp path) could accept findings for it.
func openWaivers(path string) (*os.File, error) {
	if fi, err := os.Lstat(path); err != nil {
		return nil, err
	} else if fi.Mode()&os.ModeSymlink != 0 {
		return nil, errors.New("is a symlink")
	}
	fh, err := os.OpenFile(path, os.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_NONBLOCK, 0)
	if err != nil {
		return nil, err
	}
	if err := checkWaiversFile(fh); err != nil {
		_ = fh.Close()
		return nil, err
	}
	return fh, nil
}

func checkWaiversFile(fh *os.File) error {
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
	if !ok {
		return nil
	}
	euid := os.Geteuid()
	allowed, sudoOwner := ownerAllowed(int64(st.Uid), int64(euid), os.Getenv("SUDO_UID"))
	switch {
	case allowed:
		return nil
	case sudoOwner:
		return fmt.Errorf("owned by uid %d, the user who ran sudo, but stackward runs as uid %d; run it as root with sudo, or pass it with --waivers as uid %d", st.Uid, euid, st.Uid)
	}
	return fmt.Errorf("owned by uid %d, not by you (uid %d) or root; chown it if it is meant for this run", st.Uid, euid)
}
