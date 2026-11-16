//go:build !unix

package cli

import "os"

// checkWaiversFile has no owner to check outside Unix.
func checkWaiversFile(os.FileInfo) error { return nil }
