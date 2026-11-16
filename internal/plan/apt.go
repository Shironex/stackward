package plan

import (
	"errors"
	"io/fs"
	"slices"
	"strings"
	"time"

	"github.com/Shironex/stackward/internal/facts"
)

// Package installs. A step that installs a package runs the install before
// its edits (Step.Before), so a failed install stops the step before any
// file is written: nothing is left for the undo but the package. When the
// audit saw the package lists empty (a fresh cloud image) or stale, an
// apt-get update runs first, named in the plan like every command.

// aptListsMaxAge is the age past which the package lists count as stale,
// the same age UPD-006 calls stale.
const aptListsMaxAge = 3 * 24 * time.Hour

var aptUpdate = aptGet("update")

func aptInstall(pkg string) []string { return aptGet("install", "-y", pkg) }

func aptPurge(pkg string) []string { return aptGet("purge", "-y", pkg) }

// pkgInstall is the package install of a step.
type pkgInstall struct {
	pkg string
	// refresh runs apt-get update before the install.
	refresh bool
}

// planInstall decides from the facts whether the install of pkg needs an
// apt-get update first. note says why it does, or what to do when the
// lists could not be judged; it is "" when the lists are fresh.
func planInstall(f *facts.Facts, pkg string) (p pkgInstall, note string) {
	p.pkg = pkg
	var u *facts.Updates
	var now time.Time
	if f != nil {
		u, now = f.Updates, f.CollectedAt
	}
	if need, why := u.ListsRefresh(now, aptListsMaxAge); need {
		p.refresh = true
		return p, "Runs apt-get update first: " + why + ", so apt-get install would not find " + pkg + " or its current version. It only refreshes the package lists; nothing is upgraded."
	}
	if u == nil || u.Lists == nil || !u.Lists.Read {
		return p, "The audit could not judge the apt package lists. If they are old or empty, run apt update first, or the install fails, nothing is written and the step stops."
	}
	return p, ""
}

// commands are the Before commands: the update when asked, then the
// install.
func (p pkgInstall) commands() [][]string {
	if p.refresh {
		return [][]string{aptUpdate, aptInstall(p.pkg)}
	}
	return [][]string{aptInstall(p.pkg)}
}

// before renders the Before commands of a step.
func (p pkgInstall) before() []Command {
	var out []Command
	for _, c := range p.commands() {
		why := "install " + p.pkg + " before any file is written (named here so nothing is installed silently)"
		if slices.Equal(c, aptUpdate) {
			why = "refresh the empty or stale package lists, so the install finds " + p.pkg
		}
		out = append(out, cmd(why, c...))
	}
	return out
}

// installOf reads the package install of a step back for Authorize: the
// Before commands must be one of the two shapes the step writes for pkg.
// A step without Before installs nothing (ok false). legacy is the shape
// of plans from 0.2.0-rc.1, where the install was the first command after
// the edits; it is still accepted so runs made from those plans can be
// undone. rest are the commands after the install.
func installOf(s Step, pkg string) (ok bool, rest []Command, err error) {
	switch {
	case len(s.Before) == 0 && len(s.Commands) > 0 && slices.Equal(s.Commands[0].Args, aptInstall(pkg)):
		return true, s.Commands[1:], nil
	case len(s.Before) == 0:
		return false, s.Commands, nil
	}
	for _, refresh := range []bool{false, true} {
		p := pkgInstall{pkg: pkg, refresh: refresh}
		if wantCommands("before", s.Before, p.commands()...) == nil {
			return true, s.Commands, nil
		}
	}
	got := make([]string, len(s.Before))
	for i, c := range s.Before {
		got[i] = strings.Join(c.Args, " ")
	}
	return false, nil, errors.New("before: " + strings.Join(got, "; ") + " is not the install the step runs (apt-get install -y " + pkg + ", after apt-get update when the lists were stale)")
}

// installs reports whether step s installs pkg, in either shape installOf
// accepts.
func installs(s Step, pkg string) bool {
	for _, c := range slices.Concat(s.Before, s.Commands) {
		if slices.Equal(c.Args, aptInstall(pkg)) {
			return true
		}
	}
	return false
}

// dpkgStatusOf returns the Status line dpkg's status file has for pkg
// ("install ok installed"), or "" when it lists no such package. A
// missing status file lists none.
func dpkgStatusOf(r Reader, pkg string) (string, error) {
	b, err := r.ReadFile(dpkgStatus)
	if errors.Is(err, fs.ErrNotExist) {
		return "", nil
	}
	if err != nil {
		return "", err
	}
	for _, para := range strings.Split(string(b), "\n\n") {
		var name, status string
		for _, line := range strings.Split(para, "\n") {
			if v, ok := strings.CutPrefix(line, "Package: "); ok {
				name = strings.TrimSpace(v)
			} else if v, ok := strings.CutPrefix(line, "Status: "); ok {
				status = strings.TrimSpace(v)
			}
		}
		if name == pkg {
			return status, nil
		}
	}
	return "", nil
}
