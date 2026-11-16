//go:build !unix

package cli

import "os"

// openWaivers opens the waivers file; outside Unix there is no owner or
// mode to check, only the file type.
func openWaivers(path string) (*os.File, error) { return openInput(path) }
