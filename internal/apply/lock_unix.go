//go:build unix

package apply

import (
	"errors"
	"io"
	"os"
	"strings"
	"syscall"
	"time"
)

// holderLimit caps what is read back as the holder's name.
const holderLimit = 256

func (h *dirHost) Lock(p, holder string) (func() error, error) {
	rp, err := h.real(p)
	if err != nil {
		return nil, err
	}
	if err := h.MkdirAll(lockDir(p), 0o700); err != nil {
		return nil, err
	}
	f, err := os.OpenFile(rp, os.O_RDWR|os.O_CREATE|noFollow, 0o600)
	if err != nil {
		return nil, err
	}
	if err := syscall.Flock(int(f.Fd()), syscall.LOCK_EX|syscall.LOCK_NB); err != nil {
		defer func() { _ = f.Close() }()
		if errors.Is(err, syscall.EWOULDBLOCK) {
			return nil, &HeldError{Holder: readHolder(f)}
		}
		return nil, err
	}
	// The lock is ours: whatever a dead holder left in the file is stale.
	if err := f.Truncate(0); err != nil {
		_ = f.Close()
		return nil, err
	}
	if _, err := f.WriteAt([]byte(holder+"\n"), 0); err != nil {
		_ = f.Close()
		return nil, err
	}
	return func() error {
		_ = f.Truncate(0)
		// Closing the file drops the flock. The file stays: removing it
		// would let a waiting run lock a file that no longer has a name.
		return f.Close()
	}, nil
}

// readHolder reads the holder's name; the holder writes it right after it
// locks, so an empty file is read again for a moment.
func readHolder(f *os.File) string {
	for range 20 {
		b, _ := io.ReadAll(io.NewSectionReader(f, 0, holderLimit))
		if s := strings.TrimSpace(string(b)); s != "" {
			return s
		}
		time.Sleep(5 * time.Millisecond)
	}
	return ""
}
