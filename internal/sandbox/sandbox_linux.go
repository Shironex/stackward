//go:build linux

package sandbox

import (
	"errors"
	"fmt"
	"syscall"
	"unsafe"

	"golang.org/x/sys/unix"
)

// rulesetAttr mirrors struct landlock_ruleset_attr up to the fields we use.
// The size passed to the kernel depends on the ABI, so older kernels never
// see fields they do not know.
type rulesetAttr struct {
	handledFS  uint64
	handledNet uint64
}

// writeRights are every filesystem right that changes something.
func writeRights(abi int) uint64 {
	r := uint64(unix.LANDLOCK_ACCESS_FS_WRITE_FILE |
		unix.LANDLOCK_ACCESS_FS_REMOVE_DIR |
		unix.LANDLOCK_ACCESS_FS_REMOVE_FILE |
		unix.LANDLOCK_ACCESS_FS_MAKE_CHAR |
		unix.LANDLOCK_ACCESS_FS_MAKE_DIR |
		unix.LANDLOCK_ACCESS_FS_MAKE_REG |
		unix.LANDLOCK_ACCESS_FS_MAKE_SOCK |
		unix.LANDLOCK_ACCESS_FS_MAKE_FIFO |
		unix.LANDLOCK_ACCESS_FS_MAKE_BLOCK |
		unix.LANDLOCK_ACCESS_FS_MAKE_SYM)
	if abi >= 2 {
		r |= unix.LANDLOCK_ACCESS_FS_REFER
	}
	if abi >= 3 {
		r |= unix.LANDLOCK_ACCESS_FS_TRUNCATE
	}
	return r
}

// devNullRights keep /dev/null writable: many inspection commands send
// their noise there, and writing to it changes nothing.
func devNullRights(abi int) uint64 {
	r := uint64(unix.LANDLOCK_ACCESS_FS_WRITE_FILE)
	if abi >= 3 {
		r |= unix.LANDLOCK_ACCESS_FS_TRUNCATE
	}
	return r
}

func apply(opts Options) Status {
	abi, err := landlockABI()
	if err != nil {
		return Status{State: Unavailable, Reason: err.Error()}
	}
	st := Status{State: Landlock, ABI: abi}

	attr := rulesetAttr{handledFS: writeRights(abi)}
	size := unsafe.Sizeof(attr.handledFS)
	if abi >= 4 && !opts.AllowNetwork {
		// Deny all TCP bind and connect: audit makes no network calls.
		// Unix sockets (the Docker API) are not affected.
		attr.handledNet = unix.LANDLOCK_ACCESS_NET_BIND_TCP | unix.LANDLOCK_ACCESS_NET_CONNECT_TCP
		size = unsafe.Sizeof(attr)
		st.Network = true
	}
	fd, _, errno := unix.Syscall(unix.SYS_LANDLOCK_CREATE_RULESET, uintptr(unsafe.Pointer(&attr)), size, 0) //nolint:gosec // G103: Landlock syscall ABI, audited
	if errno != 0 {
		return failed(st, "create ruleset", errno)
	}
	defer func() { _ = unix.Close(int(fd)) }()

	if err := allowDevNull(int(fd), abi); err != nil {
		return failed(st, "allow /dev/null", err)
	}

	// Landlock applies per thread; a Go program has many. AllThreadsSyscall
	// applies both calls to every thread at once. It needs a cgo free build
	// (the release builds are static, CGO_ENABLED=0).
	if _, _, errno := syscall.AllThreadsSyscall(unix.SYS_PRCTL, unix.PR_SET_NO_NEW_PRIVS, 1, 0); errno != 0 {
		if errno == syscall.ENOTSUP {
			return Status{State: Unavailable, ABI: abi, Reason: "built with cgo; Landlock needs a CGO_ENABLED=0 build"}
		}
		return failed(st, "set no_new_privs", errno)
	}
	if _, _, errno := syscall.AllThreadsSyscall(unix.SYS_LANDLOCK_RESTRICT_SELF, fd, 0, 0); errno != 0 {
		return failed(st, "restrict self", errno)
	}
	return st
}

func landlockABI() (int, error) {
	v, _, errno := unix.Syscall(unix.SYS_LANDLOCK_CREATE_RULESET, 0, 0, unix.LANDLOCK_CREATE_RULESET_VERSION)
	switch {
	case errno == unix.ENOSYS:
		return 0, errors.New("kernel has no Landlock (needs Linux 5.13+)")
	case errno == unix.EOPNOTSUPP:
		return 0, errors.New("landlock is disabled in this kernel (not in the lsm= list)")
	case errno != 0:
		return 0, fmt.Errorf("landlock version query: %w", errno)
	case int(v) < 1:
		return 0, fmt.Errorf("landlock reported ABI %d", int(v))
	}
	return int(v), nil
}

func allowDevNull(rulesetFD, abi int) error {
	fd, err := unix.Open("/dev/null", unix.O_PATH|unix.O_CLOEXEC, 0)
	if err != nil {
		return err
	}
	defer func() { _ = unix.Close(fd) }()
	//nolint:gosec // G115: file descriptors fit in int32
	pb := unix.LandlockPathBeneathAttr{Allowed_access: devNullRights(abi), Parent_fd: int32(fd)}
	//nolint:gosec // G103: Landlock syscall ABI, audited
	_, _, errno := unix.Syscall6(unix.SYS_LANDLOCK_ADD_RULE, uintptr(rulesetFD),
		unix.LANDLOCK_RULE_PATH_BENEATH, uintptr(unsafe.Pointer(&pb)), 0, 0, 0)
	if errno != 0 {
		return errno
	}
	return nil
}

func failed(st Status, step string, err error) Status {
	return Status{State: Failed, ABI: st.ABI, Reason: fmt.Sprintf("%s: %v", step, err)}
}
