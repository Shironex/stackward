package fleet

import (
	"bufio"
	"bytes"
	"fmt"
	"regexp"
	"strings"
	"time"

	"github.com/Shironex/stackward/internal/profile"
)

// Exit codes of the remote script itself, beside the audit's own 0 and 2.
const (
	exitSetup       = 97 // the temporary directory or the upload failed
	exitInterrupted = 98 // the script got HUP, INT, TERM or PIPE
)

// archCommand is the remote command that reports the architecture.
const archCommand = "uname -m"

// tmpMarker starts the stderr line on which the script names its directory,
// so the local side can clean up when the connection breaks.
const tmpMarker = "stackward-ssh-tmp "

// RemoteArgs are the audit flags passed on to the remote run. Only these
// exist, and each is validated, so nothing the user typed reaches the
// remote shell as free text.
type RemoteArgs struct {
	Profile      string        // --profile, "" or "auto" for inference
	Timeout      time.Duration // --timeout per collector, 0 for the default
	ShowHostname bool          // --show-hostname
}

// safeArg is what a single remote argument may contain.
var safeArg = regexp.MustCompile(`^[A-Za-z0-9.=-]+$`)

// args returns the remote audit arguments. The audit runs with --json and
// --fail-on never: the fleet judges --fail-on locally, and any exit but 0
// is an error.
func (r RemoteArgs) args() ([]string, error) {
	out := []string{"audit", "--json", "--fail-on", "never"}
	if r.Profile != "" && r.Profile != "auto" {
		if _, _, err := profile.Parse(r.Profile); err != nil {
			return nil, err
		}
		out = append(out, "--profile", r.Profile)
	}
	if r.Timeout > 0 {
		out = append(out, "--timeout", r.Timeout.String())
	}
	if r.ShowHostname {
		out = append(out, "--show-hostname")
	}
	for _, a := range out {
		if !safeArg.MatchString(a) {
			return nil, fmt.Errorf("remote argument %q refused", a)
		}
	}
	return out, nil
}

// remoteScript is the POSIX sh program that runs on the host. It is one
// line with no single quote, so it survives being wrapped in sh -c '...'
// by any login shell (sh, bash, zsh, fish, csh).
//
//   - umask 077 and mktemp -d: a fresh directory only this user can enter;
//   - the EXIT trap removes it however the script ends, and the signal trap
//     turns HUP, INT, TERM and PIPE (the connection went away) into an exit
//     so the EXIT trap runs;
//   - the binary arrives on standard input and is the only file written;
//   - the audit is not exec'd, so the trap still runs after it.
func remoteScript(sudo bool, args []string) string {
	run := `"$d/stackward" ` + strings.Join(args, " ")
	if sudo {
		run = "sudo -n -- " + run
	}
	return strings.Join([]string{
		"umask 077",
		`d=$(mktemp -d "${TMPDIR:-/tmp}/stackward.XXXXXXXXXX") || exit 97`,
		`trap "rm -rf \"$d\"" EXIT`,
		`trap "exit 98" HUP INT TERM PIPE`,
		`echo "` + tmpMarker + `$d" >&2`,
		`{ chmod 700 "$d" && cat > "$d/stackward" && chmod 700 "$d/stackward"; } || exit 97`,
		run,
	}, "; ")
}

// remoteCommand wraps a script for the remote login shell.
func remoteCommand(script string) string { return "sh -c '" + script + "'" }

// tmpDirPattern is what the script's directory looks like. Anything else
// is never put into a cleanup command.
var tmpDirPattern = regexp.MustCompile(`^/[A-Za-z0-9._/-]*/stackward\.[A-Za-z0-9]{6,}$`)

// tmpDirFrom finds the directory the script announced on stderr.
func tmpDirFrom(stderr []byte) (string, bool) {
	sc := bufio.NewScanner(bytes.NewReader(stderr))
	for sc.Scan() {
		line := sc.Text()
		if !strings.HasPrefix(line, tmpMarker) {
			continue
		}
		d := strings.TrimPrefix(line, tmpMarker)
		if !tmpDirPattern.MatchString(d) || strings.Contains(d, "/../") || strings.Contains(d, "//") {
			return "", false
		}
		return d, true
	}
	return "", false
}

// cleanupCommand removes a directory tmpDirFrom accepted.
func cleanupCommand(dir string) string { return "rm -rf -- '" + dir + "'" }

// stripMarker drops the directory line from stderr shown to the user.
func stripMarker(stderr []byte) string {
	var keep []string
	for _, l := range strings.Split(string(stderr), "\n") {
		if !strings.HasPrefix(l, tmpMarker) && strings.TrimSpace(l) != "" {
			keep = append(keep, l)
		}
	}
	return strings.Join(keep, "\n")
}
