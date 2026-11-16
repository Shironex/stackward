//go:build unix

package cli

import (
	"fmt"
	"os"
	"syscall"
)

// checkWaiversFile refuses a waivers file another user could have written:
// it must be owned by the user running stackward or by root, and not be
// writable by group or others. Otherwise anyone who can drop a
// .stackward.yml where root runs an audit could accept findings for it.
func checkWaiversFile(fi os.FileInfo) error {
	if perm := fi.Mode().Perm(); perm&0o022 != 0 {
		return fmt.Errorf("writable by group or others (mode %04o); run chmod go-w on it", perm)
	}
	st, ok := fi.Sys().(*syscall.Stat_t)
	if !ok {
		return nil
	}
	if euid := os.Geteuid(); int64(st.Uid) != int64(euid) && st.Uid != 0 {
		return fmt.Errorf("owned by uid %d, not by you (uid %d) or root", st.Uid, euid)
	}
	return nil
}
