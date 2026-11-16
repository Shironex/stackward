package cli

import (
	"errors"
	"fmt"
	"io/fs"
	"os"

	"github.com/Shironex/stackward/internal/waiver"
)

// waiversHelp is the help text of --waivers on audit and tui.
const waiversHelp = "file of accepted findings, each with a reason and an expiry (default: " + waiver.DefaultFile +
	" in the working directory, when it exists); shown as accepted, never hidden"

// loadWaivers reads the waivers file. It runs before the sandbox, like
// every other file stackward opens. An empty path means the default file
// in the working directory, which may be missing; a named file must exist.
// The file decides how findings are counted and so the exit code, so it is
// treated as untrusted input: it must be a regular file, owned by the user
// running stackward or by root and not writable by others (see
// checkWaiversFile), and the strict parser in package waiver reads at most
// waiver.MaxFileBytes of it. Any problem is an error, never a silent skip.
func loadWaivers(path string) ([]waiver.Waiver, error) {
	explicit := path != ""
	if !explicit {
		path = waiver.DefaultFile
	}
	fail := func(err error) ([]waiver.Waiver, error) { return nil, fmt.Errorf("waivers file %s: %w", path, err) }
	before, err := os.Stat(path)
	if err != nil {
		if !explicit && errors.Is(err, fs.ErrNotExist) {
			return nil, nil
		}
		return fail(err)
	}
	// Checked before opening, so a FIFO cannot block the open.
	if !before.Mode().IsRegular() {
		return fail(errors.New("not a regular file"))
	}
	fh, err := os.Open(path)
	if err != nil {
		return fail(err)
	}
	defer func() { _ = fh.Close() }()
	fi, err := fh.Stat()
	if err != nil {
		return fail(err)
	}
	if !os.SameFile(before, fi) {
		return fail(errors.New("changed while it was opened"))
	}
	if err := checkWaiversFile(fi); err != nil {
		return fail(err)
	}
	ws, err := waiver.Load(fh)
	if err != nil {
		return fail(err)
	}
	return ws, nil
}
