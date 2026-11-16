//go:build unix

package cli

import (
	"os"
	"syscall"
)

// openInput opens a file stackward only reads (a report for diff or
// --baseline) without blocking, so a FIFO cannot hang the run, and refuses
// anything but a regular file (a device such as /dev/zero would never
// end).
func openInput(path string) (*os.File, error) {
	fh, err := os.OpenFile(path, os.O_RDONLY|syscall.O_NONBLOCK, 0)
	if err != nil {
		return nil, err
	}
	return checkRegular(fh)
}
