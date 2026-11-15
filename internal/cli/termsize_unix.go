//go:build unix

package cli

import (
	"io"
	"os"

	"golang.org/x/sys/unix"
)

// terminalWidth returns the column count of the terminal w writes to, or 0
// when w is not a terminal or the size is unknown. It only reads the size.
func terminalWidth(w io.Writer) int {
	f, ok := w.(*os.File)
	if !ok {
		return 0
	}
	ws, err := unix.IoctlGetWinsize(int(f.Fd()), unix.TIOCGWINSZ)
	if err != nil {
		return 0
	}
	return int(ws.Col)
}
