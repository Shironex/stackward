package checks

import (
	"fmt"
	"strconv"
	"strings"
	"time"
	"unicode"
)

// SYS checks read what the os collector gathers (facts/os.go).

// testedReleases are the distribution releases stackward is tested on.
var testedReleases = map[string][]string{
	"ubuntu": {"22.04", "24.04", "26.04"},
	"debian": {"12", "13"},
}

// rebootOverdue is how long a pending reboot may wait before SYS-002 fails.
const rebootOverdue = 14 * 24 * time.Hour

func init() {
	Register(Check{ID: "SYS-001", Run: checkTestedDistro})
	Register(Check{ID: "SYS-002", Run: checkRebootPending})
	Register(Check{ID: "SYS-003", Run: checkRunningKernel})
}

func testedList() []string {
	var out []string
	for _, id := range []string{"ubuntu", "debian"} {
		for _, v := range testedReleases[id] {
			out = append(out, id+" "+v)
		}
	}
	return out
}

func checkTestedDistro(in Input) []Result {
	o := in.Facts.OS
	if o == nil {
		return []Result{NotInspected(in.Facts, "os")}
	}
	ev := map[string]any{"id": o.ID, "version_id": o.VersionID, "pretty_name": o.PrettyName, "tested": testedList()}
	for _, v := range testedReleases[o.ID] {
		if v == o.VersionID {
			return One(Pass, fmt.Sprintf("%s %s is a tested release", o.ID, o.VersionID), ev)
		}
	}
	if o.Family() == "debian" {
		return One(Warn, fmt.Sprintf("%s %s is not a tested release; some results may be unknown", o.ID, orUnknown(o.VersionID)), ev)
	}
	return One(Skip, fmt.Sprintf("%s is not a tested distribution family; many results may be unknown", o.ID), ev)
}

func checkRebootPending(in Input) []Result {
	f := in.Facts
	if f.Reboot == nil || f.OS == nil {
		return []Result{NotInspected(f, "os")}
	}
	if f.OS.Family() != "debian" {
		return One(Unknown, fmt.Sprintf("no reboot marker is known for %s", f.OS.ID), nil)
	}
	r := f.Reboot
	if !r.Required {
		return One(Pass, "no reboot pending", map[string]any{"required": false})
	}
	ev := map[string]any{"required": true, "packages": r.Packages}
	if r.Since.IsZero() || f.CollectedAt.IsZero() {
		return One(Warn, "reboot pending (age unknown)", ev)
	}
	age := f.CollectedAt.Sub(r.Since)
	days := int(age.Hours() / 24)
	ev["since"] = r.Since.UTC().Format(time.RFC3339)
	ev["days"] = days
	if age >= rebootOverdue {
		return One(Fail, fmt.Sprintf("reboot pending for %d days", days), ev)
	}
	return One(Warn, fmt.Sprintf("reboot pending for %d days", days), ev)
}

func checkRunningKernel(in Input) []Result {
	k := in.Facts.Kernel
	if k == nil {
		return []Result{NotInspected(in.Facts, "os")}
	}
	if len(k.Installed) == 0 {
		return One(Unknown, "could not list installed kernels in /boot", map[string]any{"running": k.Release})
	}
	newest := k.Installed[0]
	for _, v := range k.Installed[1:] {
		if compareVersions(v, newest) > 0 {
			newest = v
		}
	}
	ev := map[string]any{"running": k.Release, "newest": newest, "installed": k.Installed}
	if compareVersions(k.Release, newest) >= 0 {
		return One(Pass, fmt.Sprintf("running the newest installed kernel %s", k.Release), ev)
	}
	return One(Warn, fmt.Sprintf("running kernel %s is older than installed %s", k.Release, newest), ev)
}

func orUnknown(s string) string {
	if s == "" {
		return "(no version)"
	}
	return s
}

// compareVersions orders version strings such as "6.8.0-45-generic" by
// comparing runs of digits numerically and everything else as text.
func compareVersions(a, b string) int {
	as, bs := splitVersion(a), splitVersion(b)
	for i := 0; i < len(as) && i < len(bs); i++ {
		x, y := as[i], bs[i]
		xn, xerr := strconv.ParseUint(x, 10, 64)
		yn, yerr := strconv.ParseUint(y, 10, 64)
		switch {
		case xerr == nil && yerr == nil:
			if xn != yn {
				if xn < yn {
					return -1
				}
				return 1
			}
		case x != y:
			return strings.Compare(x, y)
		}
	}
	switch {
	case len(as) < len(bs):
		return -1
	case len(as) > len(bs):
		return 1
	}
	return 0
}

func splitVersion(s string) []string {
	var parts []string
	start := 0
	for i := 1; i <= len(s); i++ {
		if i == len(s) || unicode.IsDigit(rune(s[i])) != unicode.IsDigit(rune(s[i-1])) {
			parts = append(parts, s[start:i])
			start = i
		}
	}
	return parts
}
