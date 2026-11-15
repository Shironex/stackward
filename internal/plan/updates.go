package plan

import (
	"errors"
	"fmt"
	"io/fs"
	"slices"
	"strings"

	"github.com/Shironex/stackward/internal/checks"
	"github.com/Shironex/stackward/internal/facts"
)

// unattended-upgrades and unattended-upgrades-install: turn on automatic
// updates (UPD-001) with an apt.conf.d drop-in that sorts after the
// distribution's 20auto-upgrades, and enable apt-daily-upgrade.timer when
// the audit saw it disabled. The main apt configuration is never edited.
// When the package is missing, only the opt in install step plans: it
// names the apt-get install in the plan, so nothing is installed unless
// the owner selects it by id. Neither step touches the reboot policy; that
// is the separate, opt in unattended-upgrades-reboot step.

const (
	uuDropin   = "/etc/apt/apt.conf.d/90stackward-unattended-upgrades"
	uuPackage  = "unattended-upgrades"
	uuTimer    = "apt-daily-upgrade.timer"
	dpkgStatus = "/var/lib/dpkg/status"
)

func init() {
	Register(Generator{
		ID:    "unattended-upgrades",
		Title: "Turn on unattended-upgrades with an apt.conf.d drop-in",
		Fixes: []string{"UPD-001"},
		Risk:  Safe,
		Plan:  planUnattended,

		Authorize:        authorizeUnattended,
		Check:            checkUnattended,
		CommandsOnChange: true,
	})
	Register(Generator{
		ID:    "unattended-upgrades-install",
		Title: "Install unattended-upgrades and turn it on with an apt.conf.d drop-in",
		Fixes: []string{"UPD-001"},
		Risk:  Safe,
		OptIn: true,
		Plan:  planUnattendedInstall,

		Authorize: authorizeUnattendedInstall,
		Check:     checkUnattendedInstall,
	})
}

// uuContent is the whole drop-in, the same on every host.
const uuContent = "// Written by stackward: plan step unattended-upgrades, fixes UPD-001.\n" +
	"// Turns on the daily package list update and unattended-upgrades.\n" +
	"// Remove this file to undo.\n" +
	"APT::Periodic::Update-Package-Lists \"1\";\n" +
	"APT::Periodic::Unattended-Upgrade \"1\";\n"

var (
	uuRemove      = []string{"rm", "-f", uuDropin}
	aptValidate   = []string{"apt-config", "dump", "-c"}
	timerEnable   = []string{"systemctl", "enable", uuTimer}
	timerStart    = []string{"systemctl", "start", uuTimer}
	timerStop     = []string{"systemctl", "stop", uuTimer}
	timerDisable  = []string{"systemctl", "disable", uuTimer}
	uuInstall     = aptGet("install", "-y", uuPackage)
	uuPurge       = aptGet("purge", "-y", uuPackage)
	uuTouches     = []string{"file:" + uuDropin}
	uuTimerTouch  = "service:" + uuTimer
	aptLockWaitOp = "DPkg::Lock::Timeout=120"
)

// aptGet is an apt-get call that never asks a question and waits up to
// two minutes for a dpkg lock held by a running apt job.
func aptGet(args ...string) []string {
	return append([]string{"env", "DEBIAN_FRONTEND=noninteractive", "apt-get", "-o", aptLockWaitOp}, args...)
}

// timerPlan is what the step does to apt-daily-upgrade.timer, decided
// from the facts: nothing (enabled or unknown), enable it, or enable and
// start it. Undo reverses exactly what ran.
type timerPlan int

const (
	timerKeep timerPlan = iota
	timerEnableOnly
	timerEnableStart
)

func timerPlanOf(u *facts.Updates) timerPlan {
	switch {
	case u.TimerEnabled == nil || *u.TimerEnabled:
		return timerKeep
	case u.TimerActive != nil && *u.TimerActive:
		return timerEnableOnly
	}
	return timerEnableStart
}

func (t timerPlan) commands() [][]string {
	switch t {
	case timerEnableOnly:
		return [][]string{timerEnable}
	case timerEnableStart:
		return [][]string{timerEnable, timerStart}
	}
	return nil
}

func (t timerPlan) undo() [][]string {
	switch t {
	case timerEnableOnly:
		return [][]string{timerDisable}
	case timerEnableStart:
		return [][]string{timerStop, timerDisable}
	}
	return nil
}

// uuGate runs the shared part of both steps: the check gate and the
// facts both need.
func uuGate(in Input) (*facts.Updates, Outcome, bool) {
	if out, need := checkGate(in, []string{"UPD-001"}); !need {
		return nil, out, false
	}
	if in.Facts == nil || in.Facts.Updates == nil {
		return nil, Skip(SkipUnknown, "the updates facts are missing (planning from a report alone, or the updates collector did not run)"), false
	}
	u := in.Facts.Updates
	if !u.Apt {
		return nil, Skip(SkipPassing, "not an apt host"), false
	}
	return u, Outcome{}, true
}

func planUnattended(in Input) Outcome {
	u, out, ok := uuGate(in)
	if !ok {
		return out
	}
	if !u.UnattendedInstalled {
		return Skip(SkipPassing, "does not apply: unattended-upgrades is not installed; the opt in step unattended-upgrades-install installs it")
	}
	s := uuStep(u, false)
	return Outcome{Step: &s}
}

func planUnattendedInstall(in Input) Outcome {
	u, out, ok := uuGate(in)
	if !ok {
		return out
	}
	if u.UnattendedInstalled {
		return Skip(SkipPassing, "does not apply: unattended-upgrades is already installed; the step unattended-upgrades turns it on")
	}
	s := uuStep(u, true)
	return Outcome{Step: &s}
}

// uuStep builds either step. install adds the package install in front
// and its purge at the end of the undo.
func uuStep(u *facts.Updates, install bool) Step {
	t := timerPlanOf(u)
	cmds, undo := uuCommands(t, install)
	e := newEdit(uuDropin, Create, "0644", "", uuContent)
	e.Validate = append([]string{}, aptValidate...)
	touches := append([]string{}, uuTouches...)
	if t != timerKeep {
		touches = append(touches, uuTimerTouch)
	}
	s := Step{
		Touches: touches,
		Edits:   []FileEdit{e},
		Undo: Undo{
			Description: "Remove the drop-in; unattended-upgrades then follows the distribution's own settings again.",
		},
	}
	for _, c := range cmds {
		s.Commands = append(s.Commands, cmd(uuWhy(c), c...))
	}
	for _, c := range undo {
		s.Undo.Commands = append(s.Undo.Commands, cmd(uuUndoWhy(c), c...))
	}
	if t != timerKeep {
		s.Undo.Description += " The timer goes back to disabled, as the audit saw it."
	}
	if install {
		s.Undo.Description += " The package is purged; packages apt installed with it stay."
		s.Notes = append(s.Notes,
			"Installs the unattended-upgrades package (and what it depends on) from the configured apt sources with apt-get install. Nothing else is upgraded on purpose, but apt may upgrade a dependency the package needs. If the package lists are old, run apt update first, or the install fails and nothing else changes.")
	}
	s.Notes = append(s.Notes, rebootDecisionNote(u),
		"Only the origins allowed in 50unattended-upgrades are installed; UPD-003 checks that the security pocket is among them.",
		"A file that sorts after 90stackward-unattended-upgrades in /etc/apt/apt.conf.d can still turn it off; the next audit's UPD-001 says so.")
	return s
}

// rebootDecisionNote states the reboot policy the step leaves in place.
// It never changes it: that is the opt in step unattended-upgrades-reboot.
func rebootDecisionNote(u *facts.Updates) string {
	if u.AutomaticReboot {
		at := ""
		if u.AutomaticRebootTime != "" {
			at = " at " + u.AutomaticRebootTime
		}
		return "Reboot decision: automatic reboot is already on" + at + " (Unattended-Upgrade::Automatic-Reboot); stackward keeps that choice."
	}
	return "Reboot decision: automatic reboot stays off, so updates that need a reboot (a kernel, libc) wait for you and SYS-002 reports them. To let unattended-upgrades reboot at " + rebootTime + " (host time) instead, apply the opt in step unattended-upgrades-reboot."
}

func uuCommands(t timerPlan, install bool) (cmds, undo [][]string) {
	if install {
		cmds = append(cmds, uuInstall)
	}
	cmds = append(cmds, t.commands()...)
	undo = append([][]string{uuRemove}, t.undo()...)
	if install {
		undo = append(undo, uuPurge)
	}
	return cmds, undo
}

func uuWhy(c []string) string {
	switch {
	case slices.Equal(c, uuInstall):
		return "install unattended-upgrades (named here so nothing is installed silently)"
	case slices.Equal(c, timerEnable):
		return "enable the daily unattended-upgrades timer, disabled when audited"
	}
	return "start the timer now"
}

func uuUndoWhy(c []string) string {
	switch {
	case slices.Equal(c, uuRemove):
		return "remove the drop-in"
	case slices.Equal(c, uuPurge):
		return "remove the package the step installed"
	case slices.Equal(c, timerStop):
		return "stop the timer again"
	}
	return "disable the timer again"
}

func authorizeUnattended(s Step) error        { return authorizeUU(s, false) }
func authorizeUnattendedInstall(s Step) error { return authorizeUU(s, true) }

func authorizeUU(s Step, install bool) error {
	e, err := wantOneEdit(s, uuDropin, Create)
	if err != nil {
		return err
	}
	if err := wantContent(e, uuContent); err != nil {
		return err
	}
	if err := wantValidate(e, aptValidate); err != nil {
		return err
	}
	if err := wantRestarts(s); err != nil {
		return err
	}
	// The timer part is one of three shapes; the commands pick it and
	// the undo must reverse exactly that one.
	var errs []error
	for _, t := range []timerPlan{timerKeep, timerEnableOnly, timerEnableStart} {
		cmds, undo := uuCommands(t, install)
		err := wantCommands("commands", s.Commands, cmds...)
		if err == nil {
			return wantCommands("undo", s.Undo.Commands, undo...)
		}
		errs = append(errs, err)
	}
	return fmt.Errorf("the commands are not ones the step runs: %w", errs[0])
}

// checkUnattended: applied when the drop-in holds exactly the planned
// content; the timer commands follow the write in the same run.
func checkUnattended(r Reader, s Step) (bool, string, error) {
	ok, err := FileHolds(r, uuDropin, s.Edits[0].NewSHA256)
	if err != nil || !ok {
		return false, "", err
	}
	return true, uuDropin + " already holds the planned content", nil
}

// checkUnattendedInstall: applied when the drop-in is in place and dpkg
// lists the package as installed. Its commands run whenever it is not,
// so a failed install is retried by the next apply.
func checkUnattendedInstall(r Reader, s Step) (bool, string, error) {
	ok, err := FileHolds(r, uuDropin, s.Edits[0].NewSHA256)
	if err != nil || !ok {
		return false, "", err
	}
	installed, err := dpkgInstalled(r, uuPackage)
	if err != nil || !installed {
		return false, "", err
	}
	return true, uuDropin + " already holds the planned content and unattended-upgrades is installed", nil
}

// dpkgInstalled reports whether dpkg's status file lists pkg as
// installed ("install ok installed"). A missing status file means no.
func dpkgInstalled(r Reader, pkg string) (bool, error) {
	b, err := r.ReadFile(dpkgStatus)
	if errors.Is(err, fs.ErrNotExist) {
		return false, nil
	}
	if err != nil {
		return false, err
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
			return status == "install ok installed", nil
		}
	}
	return false, nil
}

// failing returns the ids among ids whose worst result is warn or fail.
func failing(in Input, ids []string) []string {
	var out []string
	for _, id := range ids {
		if l, ok := in.Level(id); ok && (l == checks.Warn || l == checks.Fail) {
			out = append(out, id)
		}
	}
	return out
}
