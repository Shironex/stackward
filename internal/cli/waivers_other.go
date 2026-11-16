//go:build !unix

package cli

import (
	"errors"
	"os"
)

// openWaivers opens the waivers file; outside Unix there is no owner or
// mode to check, only the file type.
func openWaivers(path string) (*os.File, error) {
	fh, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	fi, err := fh.Stat()
	if err == nil && !fi.Mode().IsRegular() {
		err = errors.New("not a regular file")
	}
	if err != nil {
		_ = fh.Close()
		return nil, err
	}
	return fh, nil
}
