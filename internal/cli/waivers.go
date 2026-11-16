package cli

import (
	"errors"
	"fmt"
	"io/fs"

	"github.com/Shironex/stackward/internal/report"
	"github.com/Shironex/stackward/internal/waiver"
)

// waiversHelp is the help text of --waivers on audit and tui.
const waiversHelp = "file of accepted findings, each with a reason and an expiry (default: " + waiver.DefaultFile +
	" in the working directory, when it exists); shown as accepted, never hidden"

// loadWaivers reads the waivers file. It runs before the sandbox, like
// every other file stackward opens. An empty path means the default file
// in the working directory, which may be missing; a named file must exist.
//
// The file decides how findings are counted and so the exit code, so it is
// treated as untrusted input: it must not be a symlink and must be a
// regular file not writable by group or others (openWaivers), the default
// file must also be owned by the user running stackward or by root, the
// strict parser in package waiver reads at most waiver.MaxFileBytes of it,
// and no subject may hold a secret (report.CheckWaivers). Any problem is an
// error, never a silent skip.
func loadWaivers(path string) ([]waiver.Waiver, error) {
	explicit := path != ""
	if !explicit {
		path = waiver.DefaultFile
	}
	fail := func(err error) ([]waiver.Waiver, error) { return nil, fmt.Errorf("waivers file %s: %w", path, err) }
	fh, err := openWaivers(path, !explicit)
	if err != nil {
		if !explicit && errors.Is(err, fs.ErrNotExist) {
			return nil, nil
		}
		return fail(err)
	}
	defer func() { _ = fh.Close() }()
	ws, err := waiver.Load(fh)
	if err == nil {
		err = report.CheckWaivers(ws)
	}
	if err != nil {
		return fail(err)
	}
	return ws, nil
}
