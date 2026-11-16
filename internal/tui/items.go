package tui

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"sort"
	"strings"

	"github.com/Shironex/stackward/internal/catalog"
	"github.com/Shironex/stackward/internal/checks"
	"github.com/Shironex/stackward/internal/redact"
	"github.com/Shironex/stackward/internal/report"
)

// maxReportBytes caps a saved report read with --report. Real reports are
// tens of kilobytes; the cap keeps a wrong path from eating memory.
const maxReportBytes = 32 << 20

// LoadReport reads a saved report.v1 JSON document. Unknown fields are
// accepted (a newer stackward may add optional ones), a different schema id
// is not. Free text is redacted again, so a hand edited report cannot put a
// secret on screen that stackward itself would have masked.
func LoadReport(r io.Reader) (*report.Report, error) {
	b, err := io.ReadAll(io.LimitReader(r, maxReportBytes+1))
	if err != nil {
		return nil, err
	}
	if len(b) > maxReportBytes {
		return nil, fmt.Errorf("report is larger than %d MiB", maxReportBytes>>20)
	}
	var rep report.Report
	if err := json.Unmarshal(b, &rep); err != nil {
		return nil, fmt.Errorf("not a report.v1 JSON document: %w", err)
	}
	if rep.Schema != report.SchemaID {
		switch {
		case strings.HasPrefix(rep.Schema, "stackward.facts."):
			return nil, errors.New("this is a facts file; pass it with --facts instead")
		case rep.Schema == "":
			return nil, errors.New("not a stackward report (no schema field)")
		}
		return nil, fmt.Errorf("unsupported report schema %q (want %s)", rep.Schema, report.SchemaID)
	}
	for i := range rep.Waivers {
		w := &rep.Waivers[i]
		w.Subject, w.Reason = redact.String(w.Subject), redact.String(w.Reason)
	}
	for i := range rep.Results {
		it := &rep.Results[i]
		it.Subject, it.Message = redact.String(it.Subject), redact.String(it.Message)
		if it.Waiver != nil {
			cp := *it.Waiver
			cp.Reason = redact.String(cp.Reason)
			it.Waiver = &cp
		}
		if it.Group == "" {
			it.Group = catalog.GroupOf(it.ID)
		}
		if it.Subject == "" {
			it.Subject = "host"
		}
		if len(it.Evidence) > 0 {
			if ev, ok := redact.Value(it.Evidence).(map[string]any); ok {
				it.Evidence = ev
			}
		}
	}
	return &rep, nil
}

// accepted is the level the browser shows for a fail or warn result a
// waiver accepts. It is not a check level: the report keeps the real one,
// which the detail pane shows next to it.
const accepted checks.Level = "accepted"

// shownLevel is the level a result is listed, sorted and filtered under.
func shownLevel(it report.Item) checks.Level {
	if it.Accepted() {
		return accepted
	}
	return it.Level
}

// listLevels is the order of levels in the list, worst first; accepted
// findings come after info.
var listLevels = []checks.Level{checks.Fail, checks.Warn, checks.Unknown, checks.Info, accepted, checks.Pass, checks.Skip}

// levelRank orders levels worst first; unknown level strings sort last.
func levelRank(l checks.Level) int {
	for i, v := range listLevels {
		if v == l {
			return i
		}
	}
	return len(listLevels)
}

// badgeWidth is the width of the level badge of the list: the longest
// level word of the results, at least "UNKNOWN".
func badgeWidth(items []report.Item) int {
	w := len(checks.Unknown)
	for _, it := range items {
		w = max(w, len(shownLevel(it)))
	}
	return w
}

// hiddenByDefault reports whether a level stays out of the list until the
// passing toggle is on.
func hiddenByDefault(l checks.Level) bool { return l == checks.Pass || l == checks.Skip }

// sortItems orders results so the worst come first: groups by their worst
// level (ties in catalog order), then within a group by level, id and
// subject. The order does not depend on filters, so groups stay put while
// the user narrows the list.
func sortItems(items []report.Item) []report.Item {
	out := append([]report.Item(nil), items...)
	worst := map[string]int{}
	for _, it := range out {
		r := levelRank(shownLevel(it))
		if w, ok := worst[it.Group]; !ok || r < w {
			worst[it.Group] = r
		}
	}
	sort.SliceStable(out, func(i, j int) bool {
		a, b := out[i], out[j]
		if a.Group != b.Group {
			if wa, wb := worst[a.Group], worst[b.Group]; wa != wb {
				return wa < wb
			}
			if ga, gb := catalog.GroupRank(a.Group), catalog.GroupRank(b.Group); ga != gb {
				return ga < gb
			}
			return a.Group < b.Group
		}
		if la, lb := levelRank(shownLevel(a)), levelRank(shownLevel(b)); la != lb {
			return la < lb
		}
		if a.ID != b.ID {
			return catalog.Less(a.ID, b.ID)
		}
		return a.Subject < b.Subject
	})
	return out
}

// filter is what narrows the list.
type filter struct {
	level   checks.Level // "" shows every level
	passing bool         // show pass and skip results
	query   string       // case insensitive substring
}

// matches reports whether it passes the filter.
func (f filter) matches(it report.Item) bool {
	switch {
	case f.level != "" && shownLevel(it) != f.level:
		return false
	case f.level == "" && !f.passing && hiddenByDefault(shownLevel(it)):
		return false
	}
	q := strings.ToLower(strings.TrimSpace(f.query))
	if q == "" {
		return true
	}
	for _, field := range []string{it.ID, it.Title, it.Subject, it.Message, it.Group, catalog.GroupName(it.Group), string(it.Level), string(shownLevel(it))} {
		if strings.Contains(strings.ToLower(field), q) {
			return true
		}
	}
	return false
}

// levelCycle is the order the level key steps through. Accepted joins it
// when the report has accepted results, pass and skip while passing
// results are shown.
func levelCycle(passing, withAccepted bool) []checks.Level {
	c := []checks.Level{"", checks.Fail, checks.Warn, checks.Unknown, checks.Info}
	if withAccepted {
		c = append(c, accepted)
	}
	if passing {
		c = append(c, checks.Pass, checks.Skip)
	}
	return c
}

// nextLevel returns the level after cur in the cycle.
func nextLevel(cur checks.Level, passing, withAccepted bool) checks.Level {
	c := levelCycle(passing, withAccepted)
	for i, l := range c {
		if l == cur {
			return c[(i+1)%len(c)]
		}
	}
	return ""
}

// row is one line of the list: a group header or a result.
type row struct {
	group  string
	item   int // index into model.items, -1 for a header
	shown  int // header: results shown in the group
	hidden int // header: results of the group the filter hides
}

func (r row) header() bool { return r.item < 0 }

// buildRows lays out the filtered results under their group headers.
func buildRows(items []report.Item, f filter) []row {
	var rows []row
	hdr := -1
	for i, it := range items {
		if hdr < 0 || rows[hdr].group != it.Group {
			rows = append(rows, row{group: it.Group, item: -1})
			hdr = len(rows) - 1
		}
		if f.matches(it) {
			rows = append(rows, row{group: it.Group, item: i})
			rows[hdr].shown++
		} else {
			rows[hdr].hidden++
		}
	}
	// Drop headers of groups with nothing shown.
	out := rows[:0]
	for _, r := range rows {
		if r.header() && r.shown == 0 {
			continue
		}
		out = append(out, r)
	}
	return out
}
