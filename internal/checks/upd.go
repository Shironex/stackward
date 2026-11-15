package checks

import (
	"fmt"
	"strconv"
	"strings"
	"time"
)

// UPD checks read what the updates collector gathers (facts/updates.go).

const (
	// lastRunStale is how long since the last unattended-upgrades run before UPD-002 warns.
	lastRunStale = 3 * 24 * time.Hour
	// eolWarnWindow is how far ahead UPD-005 warns about end of support.
	eolWarnWindow = 90 * 24 * time.Hour
	// listsStale is when UPD-006 says its answer rests on old package lists.
	listsStale = 3 * 24 * time.Hour
)

func init() {
	Register(Check{ID: "UPD-001", Run: checkUnattendedEnabled})
	Register(Check{ID: "UPD-002", Run: checkUnattendedRecent})
	Register(Check{ID: "UPD-003", Run: checkSecurityPocket})
	Register(Check{ID: "UPD-004", Run: checkRebootPolicy})
	Register(Check{ID: "UPD-005", Run: checkSupportedRelease})
	Register(Check{ID: "UPD-006", Run: checkPendingSecurity})
}

// eolEntry is the last day of support for one release.
type eolEntry struct {
	id      string
	version string
	end     time.Time
}

func day(y int, m time.Month, d int) time.Time { return time.Date(y, m, d, 0, 0, 0, 0, time.UTC) }

// eolTable is the embedded end of support table used by UPD-005.
//
// Source: https://endoflife.date (api/ubuntu.json and api/debian.json), which
// follows Canonical's release cycle and Debian's release and LTS pages.
// Ubuntu dates are the end of standard security maintenance (Ubuntu Pro adds
// up to 10 more years, not counted here). Debian dates are the end of LTS,
// the last security support, not the shorter regular support.
//
// Update path: when Ubuntu or Debian announce a release or move a date,
// edit this table, bump nothing else, and run `go test ./internal/checks/`
// (TestEOLTableIsSane checks ordering and uniqueness). Do this before each
// stackward release and after each Ubuntu LTS (April of even years) and
// Debian release. Releases missing from the table make UPD-005 answer
// unknown, never pass.
var eolTable = []eolEntry{
	{"ubuntu", "18.04", day(2023, time.May, 31)},
	{"ubuntu", "20.04", day(2025, time.May, 31)},
	{"ubuntu", "22.04", day(2027, time.June, 1)},
	{"ubuntu", "24.04", day(2029, time.May, 31)},
	{"ubuntu", "24.10", day(2025, time.July, 10)},
	{"ubuntu", "25.04", day(2026, time.January, 17)},
	{"ubuntu", "25.10", day(2026, time.July, 1)},
	{"ubuntu", "26.04", day(2031, time.May, 29)},
	{"ubuntu", "26.10", day(2027, time.July, 1)},
	{"debian", "10", day(2024, time.June, 30)},
	{"debian", "11", day(2026, time.August, 31)},
	{"debian", "12", day(2028, time.June, 30)},
	{"debian", "13", day(2030, time.June, 30)},
}

func lookupEOL(id, version string) (eolEntry, bool) {
	for _, e := range eolTable {
		if e.id == id && e.version == version {
			return e, true
		}
	}
	return eolEntry{}, false
}

func checkUnattendedEnabled(in Input) []Result {
	u := in.Facts.Updates
	if u == nil {
		return []Result{NotInspected(in.Facts, "updates")}
	}
	if !u.Apt {
		return One(Skip, "apt not found: this check covers Debian family hosts", map[string]any{"apt": false})
	}
	ev := map[string]any{"installed": u.UnattendedInstalled, "periodic": u.PeriodicUnattended, "timer_enabled": boolPtr(u.TimerEnabled)}
	if !u.UnattendedInstalled {
		return One(Fail, "unattended-upgrades is not installed: security updates are not applied automatically", ev)
	}
	if u.ConfigSource == "" {
		return One(Unknown, "could not read the apt configuration", ev)
	}
	var problems []string
	if n, err := strconv.Atoi(strings.TrimSpace(u.PeriodicUnattended)); err != nil || n <= 0 {
		problems = append(problems, "APT::Periodic::Unattended-Upgrade is not enabled")
	}
	if u.TimerEnabled != nil && !*u.TimerEnabled {
		problems = append(problems, "apt-daily-upgrade.timer is not enabled")
	}
	switch {
	case len(problems) > 0:
		return One(Fail, "unattended-upgrades is installed but off: "+strings.Join(problems, "; "), ev)
	case u.TimerEnabled == nil:
		return One(Unknown, "unattended-upgrades is configured; could not read the state of apt-daily-upgrade.timer", ev)
	}
	return One(Pass, "unattended-upgrades is installed and enabled", ev)
}

func boolPtr(b *bool) any {
	if b == nil {
		return nil
	}
	return *b
}

// uuApplies handles the shared guards of the checks that need
// unattended-upgrades to be installed; it returns a result to stop at.
func uuApplies(in Input) ([]Result, bool) {
	u := in.Facts.Updates
	switch {
	case u == nil:
		return []Result{NotInspected(in.Facts, "updates")}, false
	case !u.Apt:
		return One(Skip, "apt not found: this check covers Debian family hosts", map[string]any{"apt": false}), false
	case !u.UnattendedInstalled:
		return One(Skip, "unattended-upgrades is not installed (see UPD-001)", map[string]any{"installed": false}), false
	}
	return nil, true
}

func checkUnattendedRecent(in Input) []Result {
	if r, ok := uuApplies(in); !ok {
		return r
	}
	u, f := in.Facts.Updates, in.Facts
	if u.LastRun.IsZero() {
		return One(Warn, "no unattended-upgrades run on record (no apt stamp or log found)", map[string]any{"last_run": nil, "days": nil})
	}
	age := f.CollectedAt.Sub(u.LastRun)
	days := int(age.Hours() / 24)
	ev := map[string]any{"last_run": u.LastRun.UTC().Format(time.RFC3339), "days": days}
	if age > lastRunStale {
		return One(Warn, fmt.Sprintf("unattended-upgrades last ran %d days ago", days), ev)
	}
	return One(Pass, fmt.Sprintf("unattended-upgrades ran %d days ago", days), ev)
}

func checkSecurityPocket(in Input) []Result {
	if r, ok := uuApplies(in); !ok {
		return r
	}
	u := in.Facts.Updates
	if u.ConfigSource == "" {
		return One(Unknown, "could not read the apt configuration", map[string]any{"origins": []string{}})
	}
	origins := nonNil(u.AllowedOrigins)
	ev := map[string]any{"origins": origins}
	for _, o := range origins {
		if strings.Contains(strings.ToLower(o), "security") {
			return One(Pass, "the security pocket is in the allowed origins", ev)
		}
	}
	return One(Warn, "the security pocket is not in Allowed-Origins or Origins-Pattern: security updates will not be installed automatically", ev)
}

func checkRebootPolicy(in Input) []Result {
	u, f := in.Facts.Updates, in.Facts
	if u == nil {
		return []Result{NotInspected(f, "updates")}
	}
	if !u.Apt {
		return One(Skip, "apt not found: this check covers Debian family hosts", map[string]any{"apt": false})
	}
	policy := "automatic reboot is off"
	if u.AutomaticReboot {
		policy = "automatic reboot is on"
		if u.AutomaticRebootTime != "" {
			policy += " at " + u.AutomaticRebootTime
		}
	}
	ev := map[string]any{"automatic_reboot": u.AutomaticReboot, "reboot_required": f.Reboot != nil && f.Reboot.Required, "days": nil}
	if f.Reboot != nil && f.Reboot.Required && !f.Reboot.Since.IsZero() {
		age := f.CollectedAt.Sub(f.Reboot.Since)
		ev["days"] = int(age.Hours() / 24)
		if age >= rebootOverdue && !u.AutomaticReboot {
			return One(Warn, fmt.Sprintf("reboot pending for %d days and %s: pick a window or a manual routine", int(age.Hours()/24), policy), ev)
		}
	}
	return One(Info, policy, ev)
}

func checkSupportedRelease(in Input) []Result {
	o := in.Facts.OS
	if o == nil {
		return []Result{NotInspected(in.Facts, "os")}
	}
	if o.ID != "ubuntu" && o.ID != "debian" {
		return One(Skip, fmt.Sprintf("no end of support table for %s", o.ID), map[string]any{"id": o.ID})
	}
	e, ok := lookupEOL(o.ID, o.VersionID)
	if !ok {
		return One(Unknown, fmt.Sprintf("%s %s is not in the end of support table", o.ID, orUnknown(o.VersionID)), map[string]any{"id": o.ID, "version_id": o.VersionID})
	}
	left := e.end.Sub(in.Facts.CollectedAt)
	days := int(left.Hours() / 24)
	ev := map[string]any{"id": o.ID, "version_id": o.VersionID, "end_of_support": e.end.Format("2006-01-02"), "days_left": days}
	switch {
	case left < 0:
		return One(Fail, fmt.Sprintf("%s %s reached end of support on %s", o.ID, o.VersionID, ev["end_of_support"]), ev)
	case left <= eolWarnWindow:
		return One(Warn, fmt.Sprintf("%s %s reaches end of support on %s (%d days)", o.ID, o.VersionID, ev["end_of_support"], days), ev)
	}
	return One(Pass, fmt.Sprintf("%s %s is supported until %s", o.ID, o.VersionID, ev["end_of_support"]), ev)
}

func checkPendingSecurity(in Input) []Result {
	u, f := in.Facts.Updates, in.Facts
	if u == nil {
		return []Result{NotInspected(f, "updates")}
	}
	if !u.Apt {
		return One(Skip, "apt not found: this check covers Debian family hosts", map[string]any{"apt": false})
	}
	if !u.PendingChecked {
		return One(Unknown, "could not simulate `apt-get upgrade`", map[string]any{"pending_security": nil})
	}
	ev := map[string]any{"pending_security": u.PendingSecurity, "pending_total": u.PendingTotal,
		"packages": nonNil(u.PendingSecurityPkgs), "lists_updated": nil}
	note := ""
	if !u.ListsUpdated.IsZero() {
		ev["lists_updated"] = u.ListsUpdated.UTC().Format(time.RFC3339)
		if age := f.CollectedAt.Sub(u.ListsUpdated); age > listsStale {
			note = fmt.Sprintf(" (package lists are %d days old)", int(age.Hours()/24))
		}
	}
	if u.PendingSecurity > 0 {
		return One(Warn, fmt.Sprintf("%d pending security update(s)%s", u.PendingSecurity, note), ev)
	}
	return One(Pass, "no pending security updates"+note, ev)
}
