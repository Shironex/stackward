package cli

import (
	"io"
	"os"
	"strconv"

	"github.com/Shironex/stackward/internal/report"
)

// textOptions decides how a text report looks. Colors, Unicode marks and the
// summary box only go to a terminal: never into an --out file, a pipe or with
// --plain. NO_COLOR drops the colors only; TERM=dumb drops both. The width
// is COLUMNS, else the terminal's, else report.DefaultTextWidth (always for
// a file, so a saved report does not depend on the window it was run in).
// Call it before the sandbox is applied.
func textOptions(stdout io.Writer, toFile, plain bool) report.TextOptions {
	tty := !toFile && !plain && isTerminal(stdout)
	o := report.TextOptions{
		Fancy: tty && os.Getenv("TERM") != "dumb",
		Color: tty && colorEnv(),
		Width: report.DefaultTextWidth,
	}
	if toFile {
		return o
	}
	if n, err := strconv.Atoi(os.Getenv("COLUMNS")); err == nil && n > 0 {
		o.Width = n
	} else if n := terminalWidth(stdout); n > 0 {
		o.Width = n
	}
	return o
}
