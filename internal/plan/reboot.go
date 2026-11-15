package plan

import (
	"fmt"
	"slices"
	"strings"
	"time"

	"github.com/Shironex/stackward/internal/checks"
	"github.com/Shironex/stackward/internal/facts"
)

// unattended-upgrades-reboot: the reboot decision. Apply never reboots a
// host. This opt in step writes an apt.conf.d drop-in that lets
// unattended-upgrades reboot at a fixed window (rebootTime, host time)
// after a run that leaves /var/run/reboot-required. It plans when a
// reboot is pending or overdue (SYS-002, SYS-003, UPD-004), or when
// unattended-upgrades is being turned on now (UPD-001), because then the
// reboot policy is a choice to make now. Without it, automatic reboot
// stays off and the plan says so.

const (
	rebootDropin = "/etc/apt/apt.conf.d/91stackward-automatic-reboot"
	rebootTime   = "04:00"
)

var rebootFixes = []string{"SYS-002", "SYS-003", "UPD-004"}

func init() {
	Register(Generator{
		ID:    "unattended-upgrades-reboot",
		Title: "Let unattended-upgrades reboot at " + rebootTime + " (host time) when an update needs it",
		Fixes: rebootFixes,
		// Networking: a reboot at the window stops every service on the
		// host for a while, though never during apply itself.
		Risk:  Networking,
		OptIn: true,
		Plan:  planReboot,

		Authorize: authorizeReboot,
		Check:     checkReboot,
	})
}

// rebootContent is the whole drop-in, the same on every host.
const rebootContent = "// Written by stackward: plan step unattended-upgrades-reboot.\n" +
	"// Lets unattended-upgrades reboot the host at " + rebootTime + " (host time)\n" +
	"// when an update needs a reboot. Remove this file to undo.\n" +
	"Unattended-Upgrade::Automatic-Reboot \"true\";\n" +
	"Unattended-Upgrade::Automatic-Reboot-Time \"" + rebootTime + "\";\n"

var rebootRemove = []string{"rm", "-f", rebootDropin}

func planReboot(in Input) Outcome {
	fixes := failing(in, rebootFixes)
	if len(fixes) == 0 {
		l, found := in.Level("UPD-004")
		if !found || l == checks.Unknown || len(failing(in, []string{"UPD-001"})) == 0 {
			out, _ := checkGate(in, rebootFixes)
			return out
		}
		// No reboot is due, but automatic updates are being turned on:
		// UPD-004, the reboot policy, is the decision to make now.
		fixes = []string{"UPD-004"}
	}
	if in.Facts == nil || in.Facts.Updates == nil {
		return Skip(SkipUnknown, "the updates facts are missing (planning from a report alone, or the updates collector did not run)")
	}
	u := in.Facts.Updates
	if !u.Apt {
		return Skip(SkipPassing, "not an apt host: unattended-upgrades does not apply")
	}
	if u.AutomaticReboot {
		return Skip(SkipManual, "unattended-upgrades already reboots automatically%s; that was the owner's choice, so stackward keeps it (reboot by hand if one is overdue)", atTime(u.AutomaticRebootTime))
	}
	e := newEdit(rebootDropin, Create, "0644", "", rebootContent)
	e.Validate = append([]string{}, aptValidate...)
	return Outcome{Step: &Step{
		Fixes:   fixes,
		Touches: []string{"file:" + rebootDropin},
		Edits:   []FileEdit{e},
		Undo: Undo{
			Description: "Remove the drop-in; automatic reboot is off again and reboots wait for you.",
			Commands:    []Command{cmd("remove the drop-in", rebootRemove...)},
		},
		Notes: rebootNotes(in.Facts, slices.Contains(fixes, "SYS-003")),
	}}
}

func atTime(t string) string {
	if t == "" {
		return ""
	}
	return " at " + t
}

// rebootNotes say when the reboot can happen, so it is never a surprise.
// kernelBehind is true when SYS-003 says the running kernel is older
// than the newest installed one.
func rebootNotes(f *facts.Facts, kernelBehind bool) []string {
	u := f.Updates
	notes := []string{
		"This is the reboot decision. stackward apply never reboots the host: this step only writes a setting. With it, unattended-upgrades reboots the host at " + rebootTime + " host time after a run that leaves /var/run/reboot-required. Without it, automatic reboot stays off and reboots wait for you.",
		"Logged in users do not hold the reboot back (Unattended-Upgrade::Automatic-Reboot-WithUsers is true unless set otherwise).",
	}
	if r := f.Reboot; r != nil && r.Required {
		notes = append(notes, "A reboot is pending now"+pendingSince(f.CollectedAt, r)+": after this step the next unattended-upgrades run may reboot the host at "+rebootTime+". To reboot at a time you pick instead, skip this step and reboot by hand.")
	} else if kernelBehind {
		notes = append(notes, "The running kernel is older than the newest installed one (SYS-003), but no reboot is marked pending, so unattended-upgrades will not reboot for it; reboot by hand once.")
	}
	if !u.UnattendedInstalled {
		notes = append(notes, "unattended-upgrades is not installed: this setting takes effect once it is (the opt in step unattended-upgrades-install).")
	}
	return notes
}

func pendingSince(now time.Time, r *facts.Reboot) string {
	var parts []string
	if !r.Since.IsZero() && !now.IsZero() {
		days := int(now.Sub(r.Since).Hours() / 24)
		parts = append(parts, fmt.Sprintf("for %d days", days))
	}
	if len(r.Packages) > 0 {
		parts = append(parts, "asked for by "+strings.Join(r.Packages, ", "))
	}
	if len(parts) == 0 {
		return ""
	}
	return " (" + strings.Join(parts, ", ") + ")"
}

func authorizeReboot(s Step) error {
	e, err := wantOneEdit(s, rebootDropin, Create)
	if err != nil {
		return err
	}
	if err := wantContent(e, rebootContent); err != nil {
		return err
	}
	if err := wantValidate(e, aptValidate); err != nil {
		return err
	}
	if err := wantRestarts(s); err != nil {
		return err
	}
	if err := wantCommands("commands", s.Commands); err != nil {
		return err
	}
	return wantCommands("undo", s.Undo.Commands, rebootRemove)
}

// checkReboot: applied when the drop-in holds exactly the planned content.
func checkReboot(r Reader, s Step) (bool, string, error) {
	ok, err := FileHolds(r, rebootDropin, s.Edits[0].NewSHA256)
	if err != nil || !ok {
		return false, "", err
	}
	return true, rebootDropin + " already holds the planned content", nil
}
