package apply

import (
	"errors"
	"fmt"
	"path"
)

// RunLockPath is the lock every run that changes the host takes: apply and
// undo today, and the access-critical transaction later ("only one
// transaction at a time"). It lives under /run, so a reboot clears it.
const RunLockPath = "/run/stackward/apply.lock"

// HeldError is the refusal of a second run: another process holds the lock.
type HeldError struct {
	// Holder is what the holder wrote into the lock file: its run id (an
	// undo writes "undo of RUN_ID"). Empty when the file could not be read.
	Holder string
}

func (e *HeldError) Error() string {
	if e.Holder == "" {
		return "another stackward run holds the lock " + RunLockPath
	}
	return fmt.Sprintf("another stackward run holds the lock %s (run %s); wait for it to finish", RunLockPath, e.Holder)
}

// IsHeld reports whether err is a refusal because the lock is held.
func IsHeld(err error) bool {
	var h *HeldError
	return errors.As(err, &h)
}

// AcquireRunLock takes the run lock for holder (a run id) through the host
// seam and returns the function that releases it. Take it before the first
// read a run depends on and keep it until the run ends.
func AcquireRunLock(h Host, holder string) (release func() error, err error) {
	return h.Lock(RunLockPath, holder)
}

// lockDir is the directory of a lock file.
func lockDir(p string) string { return path.Dir(p) }
