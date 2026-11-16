//go:build !unix

package cli

import (
	"fmt"
	"os"
)

func createOutput(path string) (*os.File, error) {
	return openOutput("--out", path, 0o600)
}

func createTextfile(path string) (*os.File, error) {
	return openOutput("--textfile", path, 0o644)
}

func openOutput(flagName, path string, mode os.FileMode) (*os.File, error) {
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, mode)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", flagName, err)
	}
	return f, nil
}
