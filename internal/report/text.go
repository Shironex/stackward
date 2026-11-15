package report

import (
	"fmt"
	"io"
	"sort"
	"strings"

	"github.com/Shironex/stackward/internal/catalog"
	"github.com/Shironex/stackward/internal/checks"
)

// TextOptions tunes WriteText. The zero value is plain output for a pipe:
// no ANSI, ASCII only, wrapped at DefaultTextWidth.
type TextOptions struct {
	// Color adds ANSI colors and bold or dim text.
	Color bool
	// Fancy uses Unicode marks and box lines (a terminal). Without it the
	// output is ASCII only.
	Fancy bool
	// Width is the line width to wrap at; 0 means DefaultTextWidth.
	Width int
	// Passing lists passing and skipped results too, and every info result
	// in full (--all).
	Passing bool
	// Info lists every info result in full instead of one line each.
	Info bool
	// Group lays the results out by catalog group instead of by level.
	Group bool
}

// indent is the left margin of every line.
const indent = "  "

// infoCap is how many results of one check a compact list shows before it
// says how many more there are.
const infoCap = 8

// sectionLevels is the order of the level layout.
var sectionLevels = []checks.Level{checks.Fail, checks.Warn, checks.Unknown, checks.Info, checks.Pass, checks.Skip}

// severityRank orders results inside a level, most severe first.
var severityRank = map[catalog.Severity]int{
	catalog.Critical: 0, catalog.High: 1, catalog.Moderate: 2, catalog.Low: 3, catalog.Info: 4,
}

// textWriter accumulates the report.
type textWriter struct {
	b  strings.Builder
	o  TextOptions
	st style
	w  int
}

func (t *textWriter) line(s string) {
	t.b.WriteString(strings.TrimRight(s, " "))
	t.b.WriteByte('\n')
}

func (t *textWriter) blank() { t.b.WriteByte('\n') }

// hang writes text after a styled lead, wrapped to the report width, with
// every following line indented to where the text starts. lead is already
// styled; leadWidth is its display width. paint styles each text line.
func (t *textWriter) hang(lead string, leadWidth int, text string, paint func(string) string) {
	pad := strings.Repeat(" ", leadWidth)
	for i, l := range wrapWords(text, max(t.w-leadWidth, 10)) {
		if i == 0 {
			t.line(lead + paint(l))
			continue
		}
		t.line(pad + paint(l))
	}
}

func plainText(s string) string { return s }

// WriteText writes the human report: the header, a summary box with the
// counts and the worst results, then the results ordered fail, warn, unknown
// and info (or by catalog group with Group), then the counts again.
func WriteText(w io.Writer, r *Report, o TextOptions) error {
	t := &textWriter{o: o, st: newStyle(o), w: o.Width}
	if t.w <= 0 {
		t.w = DefaultTextWidth
	}
	t.w = max(t.w, minTextWidth)

	t.header(r)
	t.summaryBox(r)
	if o.Group {
		t.byGroup(r)
	} else {
		t.byLevel(r)
	}
	s := r.Summary
	t.blank()
	t.hang(indent+t.st.dim("summary: "), width(indent)+9,
		fmt.Sprintf("%d fail, %d warn, %d unknown, %d info, %d pass, %d skip", s.Fail, s.Warn, s.Unknown, s.Info, s.Pass, s.Skip), plainText)
	t.hang(indent+t.st.dim("explain any check with: "), width(indent)+24, "stackward explain <id>", plainText)
	_, err := io.WriteString(w, t.b.String())
	return err
}

// byLevel writes one section per level, most urgent first.
func (t *textWriter) byLevel(r *Report) {
	for _, l := range sectionLevels {
		items := ofLevel(r.Results, l)
		if len(items) == 0 || (!t.o.Passing && (l == checks.Pass || l == checks.Skip)) {
			continue
		}
		if l == checks.Fail || l == checks.Warn || l == checks.Unknown {
			bySeverity(items)
		}
		label := fmt.Sprintf("%s (%d)", strings.ToUpper(string(l)), len(items))
		compact := t.compactLevel(l)
		if l == checks.Info && compact {
			label += ", one line each; --info lists them in full"
		}
		t.section(label, l)
		if compact {
			t.compactList(items, l)
			continue
		}
		seen := map[string]ruleFix{}
		for _, it := range items {
			t.result(it, false, !t.o.Passing && repeatsRuleFix(seen, it))
		}
	}
}

// ruleFix is the rule and fix lines a check printed in one section.
type ruleFix struct{ rule, fix string }

// repeatsRuleFix reports whether a result's rule and fix were already
// printed by an earlier row of the same check in this section, and records
// them when not. Rows whose lines differ keep their own.
func repeatsRuleFix(seen map[string]ruleFix, it Item) bool {
	cur := ruleFix{it.Title, it.Fix.Hint}
	prev, ok := seen[it.ID]
	if !ok {
		seen[it.ID] = cur
	}
	return ok && prev == cur
}

// compactLevel reports whether results of level l get one line each.
func (t *textWriter) compactLevel(l checks.Level) bool {
	switch l {
	case checks.Info:
		return !t.o.Info && !t.o.Passing
	case checks.Pass, checks.Skip:
		return true
	}
	return false
}

// byGroup writes one section per catalog group, in catalog order, the
// layout of the report before results were ordered by level.
func (t *textWriter) byGroup(r *Report) {
	groups := map[string][]Item{}
	for _, it := range r.Results {
		groups[it.Group] = append(groups[it.Group], it)
	}
	ids := make([]string, 0, len(groups))
	for g := range groups {
		ids = append(ids, g)
	}
	sort.Slice(ids, func(i, j int) bool { return catalog.GroupRank(ids[i]) < catalog.GroupRank(ids[j]) })
	for _, g := range ids {
		t.group(g, groups[g])
	}
}

func (t *textWriter) group(g string, items []Item) {
	hidden := 0
	for _, it := range items {
		if it.Level == checks.Pass || it.Level == checks.Skip {
			hidden++
		}
	}
	label := g + "  " + catalog.GroupName(g)
	if hidden > 0 && !t.o.Passing {
		label += fmt.Sprintf(", %d passing or skipped not shown", hidden)
	}
	t.section(label, "")
	for _, l := range sectionLevels {
		lv := ofLevel(items, l)
		if len(lv) == 0 || (!t.o.Passing && (l == checks.Pass || l == checks.Skip)) {
			continue
		}
		if t.compactLevel(l) {
			t.compactList(lv, l)
			continue
		}
		for _, it := range lv {
			t.result(it, true, false)
		}
	}
}

// section writes a blank line and a rule with a label in it.
func (t *textWriter) section(label string, l checks.Level) {
	t.blank()
	lead := t.st.box.rule + t.st.box.rule + " "
	label = truncateWords(label, t.w-width(indent)-width(lead)-3, t.st.box.ellipsis)
	rest := max(t.w-width(indent)-width(lead)-width(label)-1, 2)
	styled := t.st.bold(label)
	if l != "" {
		styled = t.st.levelBold(l, label)
	}
	t.line(indent + t.st.dim(lead) + styled + " " + t.st.dim(strings.Repeat(t.st.box.rule, rest)))
}

// result writes one result in full: the mark and what was found, then the
// check id, severity and subject, the rule it was measured against and the
// fix. withLevel puts the level word in front of the id (group layout,
// where no section names the level). brief leaves out the rule and the fix,
// which an earlier row of the same check in the section already gave.
func (t *textWriter) result(it Item, withLevel, brief bool) {
	st := t.st
	t.blank()
	lead := indent + st.mark(it.Level) + " "
	leadWidth := width(indent) + width(st.marks[it.Level]) + 1
	t.hang(lead, leadWidth, Headline(it), plainText)

	sub := strings.Repeat(" ", leadWidth)
	t.hang(sub, leadWidth, metaLine(it, withLevel, st.box.sep), st.dim)
	if brief {
		return
	}
	actionable := it.Level == checks.Fail || it.Level == checks.Warn || it.Level == checks.Unknown
	if actionable && it.Message != "" && it.Title != "" {
		t.labelled(sub, leadWidth, "rule:", it.Title, st.dim)
	}
	if (it.Level == checks.Fail || it.Level == checks.Warn) && it.Fix.Hint != "" {
		t.labelled(sub, leadWidth, "fix:", it.Fix.Hint, plainText)
	}
}

// labelled writes "label text" with the text wrapped under itself.
func (t *textWriter) labelled(sub string, subWidth int, label, text string, paint func(string) string) {
	const labelWidth = 6 // "rule: "
	t.hang(sub+t.st.dim(fmt.Sprintf("%-*s", labelWidth, label)), subWidth+labelWidth, text, paint)
}

// metaLine is the dimmed line under a headline: id, severity and subject.
// The subject is left out when the headline starts with it; severity is left
// out of info, pass and skip results, where it would read as a finding.
func metaLine(it Item, withLevel bool, sep string) string {
	var parts []string
	if withLevel {
		parts = append(parts, strings.ToUpper(string(it.Level)))
	}
	parts = append(parts, it.ID)
	switch it.Level {
	case checks.Fail, checks.Warn, checks.Unknown:
		if it.Severity != "" {
			sev := string(it.Severity)
			if ExpectedLowered(it) {
				sev += ", expected"
			}
			parts = append(parts, sev)
		}
	}
	if subj := ShortSubject(it.Subject); subj != "" && !NamesSubject(it.Message, subj) {
		parts = append(parts, it.Subject)
	}
	return strings.Join(parts, sep)
}

// compactList writes results of one level with one line per result, joined
// per check: a check with one result is one line, a check with several gets
// a heading with its title and count and at most infoCap lines (all of them
// for passing and skipped results, which only --all shows).
func (t *textWriter) compactList(items []Item, l checks.Level) {
	st := t.st
	order, byID := groupByCheck(items)
	idw := 0
	for _, id := range order {
		idw = max(idw, width(id))
	}
	t.blank()
	for _, id := range order {
		its := byID[id]
		lead := indent + st.mark(l) + " " + fmt.Sprintf("%-*s", idw, id) + "  "
		leadWidth := width(indent) + width(st.marks[l]) + 1 + idw + 2
		if len(its) == 1 {
			t.hang(lead, leadWidth, compactText(its[0]), plainText)
			continue
		}
		title := its[0].Title
		if title == "" {
			title = id
		}
		t.hang(lead, leadWidth, fmt.Sprintf("%s (%d results)", title, len(its)), st.dim)
		pad := strings.Repeat(" ", leadWidth)
		shown := its
		if l == checks.Info && len(its) > infoCap {
			shown = its[:infoCap-1]
		}
		for _, it := range shown {
			t.hang(pad, leadWidth, compactText(it), plainText)
		}
		if more := len(its) - len(shown); more > 0 {
			t.hang(pad, leadWidth, fmt.Sprintf("and %d more; --info lists them", more), st.dim)
		}
	}
}

// compactText is the one line of a compact result: the headline, after the
// short subject when the headline does not start with it.
func compactText(it Item) string {
	h := Headline(it)
	if subj := ShortSubject(it.Subject); subj != "" && !NamesSubject(it.Message, subj) {
		return subj + ": " + h
	}
	return h
}

// groupByCheck keeps the first-seen order of check ids.
func groupByCheck(items []Item) ([]string, map[string][]Item) {
	var order []string
	byID := map[string][]Item{}
	for _, it := range items {
		if _, ok := byID[it.ID]; !ok {
			order = append(order, it.ID)
		}
		byID[it.ID] = append(byID[it.ID], it)
	}
	return order, byID
}

// bySeverity sorts results most severe first, keeping report order within a
// severity.
func bySeverity(items []Item) {
	sort.SliceStable(items, func(i, j int) bool { return severityRank[items[i].Severity] < severityRank[items[j].Severity] })
}

func ofLevel(items []Item, l checks.Level) []Item {
	var out []Item
	for _, it := range items {
		if it.Level == l {
			out = append(out, it)
		}
	}
	return out
}
