package checks

import (
	"fmt"
	"strings"
)

// LOG checks read what the journal collector gathers (facts/journal.go).

// proxyLogLimit is the size above which an unrotated proxy log warns.
const proxyLogLimit = 1 << 30

func init() {
	Register(Check{ID: "LOG-001", Run: checkJournalCap})
	Register(Check{ID: "LOG-002", Run: checkProxyLogRotation})
	Register(Check{ID: "LOG-003", Run: checkJournalSize})
	Register(Check{ID: "LOG-004", Run: checkMonitoringAgent})
	Register(Check{ID: "LOG-005", Run: checkJournalPersistent})
}

func checkJournalCap(in Input) []Result {
	j := in.Facts.Journal
	if j == nil {
		return []Result{NotInspected(in.Facts, "journal")}
	}
	ev := map[string]any{"system_max_use": j.SystemMaxUse, "storage": j.Storage}
	switch {
	case j.SystemMaxUse != "":
		return One(Pass, "journald SystemMaxUse is capped at "+j.SystemMaxUse, ev)
	case !j.Persistent:
		return One(Skip, "the journal is volatile (in /run); SystemMaxUse does not apply (see LOG-005)", ev)
	}
	return One(Warn, "journald SystemMaxUse is not set: the journal may grow to 10 percent of the disk (up to 4G)", ev)
}

func checkProxyLogRotation(in Input) []Result {
	j := in.Facts.Journal
	if j == nil {
		return []Result{NotInspected(in.Facts, "journal")}
	}
	if len(j.ProxyLogs) == 0 {
		return One(Skip, "no proxy access logs in the usual /var/log locations", map[string]any{"logs": 0})
	}
	var out []Result
	for _, l := range j.ProxyLogs {
		if l.SizeBytes > proxyLogLimit && !l.Rotated {
			out = append(out, Result{Subject: "file:" + l.Path, Level: Warn,
				Message:  fmt.Sprintf("%s is %s and no logrotate rule covers it", l.Path, humanBytes(l.SizeBytes)),
				Evidence: map[string]any{"size_bytes": l.SizeBytes, "rotated": l.Rotated}})
		}
	}
	if len(out) == 0 {
		return One(Pass, "no proxy log over 1 GiB without a logrotate rule", map[string]any{"logs": len(j.ProxyLogs)})
	}
	return out
}

func checkJournalSize(in Input) []Result {
	j := in.Facts.Journal
	if j == nil {
		return []Result{NotInspected(in.Facts, "journal")}
	}
	if !j.DiskUsageChecked {
		return One(Unknown, "could not read the journal size (`journalctl --disk-usage`)", map[string]any{"bytes": nil})
	}
	return One(Info, "the journal uses "+humanBytes(j.DiskUsageBytes), map[string]any{"bytes": j.DiskUsageBytes})
}

func checkMonitoringAgent(in Input) []Result {
	j := in.Facts.Journal
	if j == nil {
		return []Result{NotInspected(in.Facts, "journal")}
	}
	agents, labels := monitoringAgents(in.Facts)
	ev := map[string]any{"agents": nonNil(agents)}
	if len(agents) == 0 {
		return One(Info, "no metrics agent found (node exporter, Alloy, Netdata and similar); consider monitoring with alerts for disk and SSH logins", ev)
	}
	return One(Info, "metrics agent found: "+strings.Join(labels, ", "), ev)
}

func checkJournalPersistent(in Input) []Result {
	j := in.Facts.Journal
	if j == nil {
		return []Result{NotInspected(in.Facts, "journal")}
	}
	ev := map[string]any{"storage": j.Storage, "persistent_dir": j.PersistentDir}
	if j.Persistent {
		return One(Pass, "the journal is persistent across reboots", ev)
	}
	return One(Warn, "the journal is volatile: logs are lost at reboot, which is when you need them", ev)
}

// humanBytes formats a size with a binary unit.
func humanBytes(n int64) string {
	const unit = 1024
	if n < unit {
		return fmt.Sprintf("%d B", n)
	}
	div, exp := int64(unit), 0
	for m := n / unit; m >= unit; m /= unit {
		div *= unit
		exp++
	}
	return fmt.Sprintf("%.1f %ciB", float64(n)/float64(div), "KMGTPE"[exp])
}
