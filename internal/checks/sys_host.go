package checks

import (
	"fmt"
)

// SYS-004 and SYS-005 read the clock and disk collectors.

const (
	diskWarnPercent = 85
	diskFailPercent = 95
)

func init() {
	Register(Check{ID: "SYS-004", Run: checkTimeSync})
	Register(Check{ID: "SYS-005", Run: checkDiskUsage})
}

func checkTimeSync(in Input) []Result {
	c := in.Facts.Clock
	if c == nil {
		return []Result{NotInspected(in.Facts, "clock")}
	}
	ev := map[string]any{"ntp_synchronized": c.NTPSynchronized, "ntp_enabled": c.NTPEnabled, "can_ntp": c.CanNTP}
	if c.NTPSynchronized {
		return One(Pass, "the clock is synchronized", ev)
	}
	msg := "the clock is not synchronized"
	switch {
	case !c.CanNTP:
		msg += " and no time sync service is available"
	case !c.NTPEnabled:
		msg += " and time sync is switched off"
	}
	return One(Warn, msg+": TLS, TOTP and log timestamps depend on correct time", ev)
}

func checkDiskUsage(in Input) []Result {
	d := in.Facts.Disk
	if d == nil {
		return []Result{NotInspected(in.Facts, "disk")}
	}
	// One result per filesystem; paths on the same one are listed together.
	type fsUse struct {
		paths []string
		pct   int
		used  int64
		total int64
	}
	byMount := map[string]*fsUse{}
	var order []string
	for _, m := range d.Mounts {
		u, ok := byMount[m.Mount]
		if !ok {
			u = &fsUse{pct: m.UsedPercent, used: m.UsedKB, total: m.TotalKB}
			byMount[m.Mount] = u
			order = append(order, m.Mount)
		}
		u.paths = append(u.paths, m.Path)
	}
	if len(order) == 0 {
		return One(Unknown, "no filesystem usage recorded", map[string]any{"mounts": 0})
	}
	var out []Result
	for _, mount := range order {
		u := byMount[mount]
		lvl := Pass
		switch {
		case u.pct > diskFailPercent:
			lvl = Fail
		case u.pct > diskWarnPercent:
			lvl = Warn
		}
		out = append(out, Result{Subject: "mount:" + mount, Level: lvl,
			Message:  fmt.Sprintf("%s is %d%% full (holds %v)", mount, u.pct, u.paths),
			Evidence: map[string]any{"paths": u.paths, "used_percent": u.pct, "used_kb": u.used, "total_kb": u.total}})
	}
	return out
}
