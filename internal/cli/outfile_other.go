//go:build !unix

package cli

import (
	"fmt"
	"os"
)

func createOutput(path string, inputs ...*os.File) (*os.File, error) {
	return openOutput("--out", path, 0o600, inputs)
}

func createTextfile(path string) (*os.File, error) {
	return openOutput("--textfile", path, 0o644, nil)
}

// openOutput opens path for writing and truncates it only after checking
// it is none of inputs, the files the run reads.
func openOutput(flagName, path string, mode os.FileMode, inputs []*os.File) (*os.File, error) {
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE, mode)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", flagName, err)
	}
	fi, err := f.Stat()
	if err == nil {
		err = notAnInput(fi, inputs)
	}
	if err == nil {
		err = f.Truncate(0)
	}
	if err != nil {
		_ = f.Close()
		return nil, fmt.Errorf("%s: %w", flagName, err)
	}
	return f, nil
}
