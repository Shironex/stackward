package cli

import (
	"errors"
	"fmt"
	"io/fs"
	"strconv"

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
// treated as untrusted input: it must not be a symlink, must be a regular
// file not writable by group or others and owned by someone allowed to
// decide for this run (openWaivers, ownerAllowed), the strict parser in
// package waiver reads at most waiver.MaxFileBytes of it, and no subject
// may hold a secret (report.CheckWaivers). Any problem is an error, never a
// silent skip.
func loadWaivers(path string) ([]waiver.Waiver, error) {
	explicit := path != ""
	if !explicit {
		path = waiver.DefaultFile
	}
	fail := func(err error) ([]waiver.Waiver, error) { return nil, fmt.Errorf("waivers file %s: %w", path, err) }
	fh, err := openWaivers(path)
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

// ownerAllowed decides whether a waivers file owned by uid may be read by a
// run with effective uid euid. sudoUID is the SUDO_UID environment value.
// The owner must be the user running stackward, root, or, in a run as root
// under sudo, the user who ran sudo (so sudo in your own checkout works).
// SUDO_UID counts only when it parses as a positive integer. The rule is
// the same for the default file and for one named with --waivers: anyone
// else who could write the file could accept findings for this run.
// sudoOwner reports whether uid is the SUDO_UID user, which the error
// message uses.
func ownerAllowed(uid, euid int64, sudoUID string) (ok, sudoOwner bool) {
	sudo, err := strconv.ParseInt(sudoUID, 10, 64)
	sudoOwner = err == nil && sudo > 0 && uid == sudo
	if uid == euid || uid == 0 {
		return true, sudoOwner
	}
	return euid == 0 && sudoOwner, sudoOwner
}
