//go:build !unix

package cli

import "io"

// terminalWidth is unknown off Unix; the report uses its default width.
func terminalWidth(io.Writer) int { return 0 }
