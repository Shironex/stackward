//go:build !unix

package cli

import (
	"os"
)

// openInput opens a file stackward only reads (a report for diff or
// --baseline) and refuses anything but a regular file.
func openInput(path string) (*os.File, error) {
	fh, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	return checkRegular(fh)
}
