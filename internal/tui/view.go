package tui

import (
	"encoding/json"
	"fmt"
	"sort"
	"strings"

	tea "charm.land/bubbletea/v2"
	"github.com/charmbracelet/x/ansi"

	"github.com/Shironex/stackward/internal/catalog"
	"github.com/Shironex/stackward/internal/checks"
	"github.com/Shironex/stackward/internal/report"
	"github.com/Shironex/stackward/internal/sandbox"
)

// Smallest usable terminal. 80x24 is the target; below this the panes no
// longer hold a readable line.
const (
	minWidth  = 60
	minHeight = 16
	// header (3 lines), the two rules and the footer.
	chromeHeight = 6
	gutter       = " │ "
)

// dims returns the list width, the detail width and the body height.
func (m Model) dims() (lw, dw, bh int) {
	lw = min(max(m.width*48/100, 36), 64)
	dw = max(m.width-lw-ansi.StringWidth(gutter), 10)
	bh = max(m.height-chromeHeight, 1)
	return lw, dw, bh
}

// listHeight is the number of result rows the list shows (the body minus
// the pane title).
func (m Model) listHeight() int {
	_, _, bh := m.dims()
	return bh - 1
}

// View renders the whole screen.
func (m Model) View() tea.View {
	v := tea.NewView(m.render())
	v.AltScreen = true
	v.WindowTitle = "stackward"
	return v
}

// render returns the screen as text, exactly m.height lines of at most
// m.width cells.
func (m Model) render() string {
	if m.width < minWidth || m.height < minHeight {
		return m.tooSmall()
	}
	lw, dw, bh := m.dims()
	lines := make([]string, 0, m.height)
	lines = append(lines, m.header()...)
	lines = append(lines, m.st.rule.Render(strings.Repeat("─", m.width)))

	var body []string
	if m.help {
		body = m.helpLines(m.width, bh)
	} else {
		left, right := m.listLines(lw, bh), m.detailLines(dw, bh)
		sep := m.st.rule.Render(gutter)
		for i := range bh {
			body = append(body, fit(left[i], lw)+sep+fit(right[i], dw))
		}
	}
	lines = append(lines, body...)
	lines = append(lines, m.st.rule.Render(strings.Repeat("─", m.width)), m.footer())
	for i, l := range lines {
		lines[i] = fit(l, m.width)
	}
	return strings.Join(lines, "\n")
}

func (m Model) tooSmall() string {
	msg := []string{
		m.st.brand.Render("stackward"),
		"",
		m.st.text.Render(fmt.Sprintf("needs a terminal of at least %dx%d", minWidth, minHeight)),
		m.st.quiet.Render(fmt.Sprintf("this one is %dx%d; resize it, or press q to quit", m.width, m.height)),
	}
	var out []string
	for range max(0, (m.height-len(msg))/2) {
		out = append(out, "")
	}
	for _, l := range msg {
		pad := max(0, (m.width-ansi.StringWidth(l))/2)
		out = append(out, strings.Repeat(" ", pad)+l)
	}
	for len(out) < m.height {
		out = append(out, "")
	}
	for i := range out {
		out[i] = ansi.Truncate(out[i], max(m.width, 0), "")
	}
	return strings.Join(out[:max(m.height, 0)], "\n")
}

// header is three lines: what was audited, how, and the counts.
func (m Model) header() []string {
	r, st := m.rep, m.st
	dot := st.faint.Render(" · ")
	label := func(k, v string) string { return st.quiet.Render(k+" ") + st.text.Render(v) }

	host := r.Host.HostnameHash
	if r.Host.Hostname != "" {
		host = r.Host.Hostname
		if !m.opts.ShowHostname {
			host = report.HashHostname(r.Host.Hostname)
		}
	}
	l1 := " " + st.brand.Render("stackward") + " " + st.quiet.Render(r.Tool.Version) + dot + label("host", orDash(host))
	if osName := strings.TrimSpace(r.Host.OS); osName != "" {
		l1 += dot + st.text.Render(osName)
	}
	l1 = spread(l1, st.faint.Render(m.opts.Source+" "), m.width)

	root := st.text.Render("yes")
	if !r.Coverage.Root {
		root = st.warnText.Render("no (use sudo)")
	}
	l2 := " " + label("profile", fmt.Sprintf("%s (%s)", r.Profile.Name, r.Profile.Source)) +
		dot + label("sandbox", sandboxShort(r.Coverage.Sandbox)) +
		dot + st.quiet.Render("root ") + root

	s := r.Summary
	counts := []struct {
		n int
		l checks.Level
	}{{s.Fail, checks.Fail}, {s.Warn, checks.Warn}, {s.Unknown, checks.Unknown}, {s.Info, checks.Info}, {s.Pass, checks.Pass}, {s.Skip, checks.Skip}}
	var parts []string
	for _, c := range counts {
		txt := fmt.Sprintf("%d %s", c.n, c.l)
		if c.n == 0 {
			parts = append(parts, st.faint.Render(txt))
			continue
		}
		parts = append(parts, st.levelStyle(c.l).Render(txt))
	}
	cov := r.Coverage
	right := ""
	if cov.Results > 0 && cov.Unknown*2 > cov.Results {
		right = st.warnText.Render("mostly unknown ")
	}
	l3 := spread(" "+st.text.Render(fmt.Sprintf("%d results", cov.Results))+"  "+strings.Join(parts, "  "), right, m.width)
	return []string{l1, l2, l3}
}

// sandboxShort is the sandbox state as one word; audit prints the details.
func sandboxShort(s sandbox.Status) string {
	if s.State == "" {
		return "-"
	}
	return string(s.State)
}

// listLines renders the list pane: a title row and the visible rows.
func (m Model) listLines(w, h int) []string {
	st := m.st
	out := make([]string, 0, h)

	shown := 0
	for _, r := range m.rows {
		if !r.header() {
			shown++
		}
	}
	title := st.quiet.Render("FINDINGS")
	if m.focus == listPane {
		title = st.section.Render("FINDINGS")
	}
	title += st.faint.Render(fmt.Sprintf("  %d of %d", shown, len(m.items)))
	var tags []string
	if m.f.level != "" {
		tags = append(tags, "level "+string(m.f.level))
	}
	if m.f.passing {
		tags = append(tags, "+passing")
	}
	if m.f.query != "" {
		tags = append(tags, "/"+m.f.query)
	}
	out = append(out, spread(title, st.accentS.Render(strings.Join(tags, " ")), w))

	if len(m.rows) == 0 {
		return padLines(append(out, m.emptyList(w)...), h)
	}
	idw := 0
	for _, r := range m.rows {
		if !r.header() {
			idw = max(idw, len(m.items[r.item].ID))
		}
	}
	end := min(m.top+h-1, len(m.rows))
	for i := m.top; i < end; i++ {
		out = append(out, m.rowLine(m.rows[i], i == m.cursor, idw, w))
	}
	return padLines(out, h)
}

// rowLine renders one list row.
func (m Model) rowLine(r row, sel bool, idw, w int) string {
	st := m.st
	if r.header() {
		left := st.section.Render(catalog.GroupName(r.group))
		if name := catalog.GroupName(r.group); name != r.group {
			left += st.faint.Render(" " + r.group)
		}
		right := fmt.Sprintf("%d", r.shown)
		if r.hidden > 0 {
			right = fmt.Sprintf("%d of %d", r.shown, r.shown+r.hidden)
		}
		return spread(left, st.faint.Render(right), w)
	}
	it := m.items[r.item]
	badge := fmt.Sprintf("%-7s", strings.ToUpper(string(it.Level)))
	id := fmt.Sprintf("%-*s", idw, it.ID)
	subj := shortSubject(it.Subject)
	if subj != "" {
		// Keep the tail of a long subject (the file name, the service):
		// it is what tells two rows of the same check apart.
		avail := w - 2 - len(badge) - 1 - idw - 1 - 3
		if lim := max(avail*2/5, 8); ansi.StringWidth(subj) > lim {
			subj = ansi.TruncateLeft(subj, ansi.StringWidth(subj)-lim+1, "…")
		}
	}
	if sel && m.focus == listPane {
		// One flat reversed bar: nested colors inside reverse video are
		// hard to read, and reverse survives NO_COLOR.
		txt := "› " + badge + " " + id + " "
		if subj != "" {
			txt += subj + " · "
		}
		txt += it.Title
		return st.selected.Render(fit(txt, w))
	}
	marker := "  "
	if sel {
		marker = st.marker.Render("› ")
	}
	line := marker + st.levelStyle(it.Level).Render(badge) + " " + st.text.Render(id) + " "
	if subj != "" {
		line += st.quiet.Render(subj) + st.faint.Render(" · ")
	}
	titleStyle := st.text
	if sel {
		titleStyle = st.bold
	}
	return line + titleStyle.Render(it.Title)
}

// shortSubject drops the kind prefix of a subject ("container:app/web"
// gives "app/web") and hides the default "host".
func shortSubject(s string) string {
	if s == "" || s == "host" {
		return ""
	}
	if _, rest, ok := strings.Cut(s, ":"); ok && rest != "" {
		return rest
	}
	return s
}

// emptyList explains an empty list and how to get results back.
func (m Model) emptyList(w int) []string {
	st := m.st
	var head, hint string
	switch {
	case len(m.items) == 0:
		head, hint = "This report has no results.", "Nothing was checked; run stackward audit to see why."
	case m.f.query != "":
		head, hint = fmt.Sprintf("No result matches %q.", m.f.query), "esc clears the filter"
	case m.f.level != "":
		head, hint = fmt.Sprintf("No %s results.", m.f.level), "l moves to the next level, a shows passing results"
	default:
		head, hint = "Nothing needs attention: every result passed or was skipped.", "a lists them"
	}
	out := []string{""}
	for _, l := range wrapText(head, w-2) {
		out = append(out, " "+st.text.Render(l))
	}
	for _, l := range wrapText(hint, w-2) {
		out = append(out, " "+st.quiet.Render(l))
	}
	return out
}

// detailLines renders the detail pane: a title row and the viewport.
func (m Model) detailLines(w, h int) []string {
	st := m.st
	title := st.quiet.Render("DETAIL")
	if m.focus == detailPane {
		title = st.section.Render("DETAIL")
	}
	pos := ""
	if total := m.detail.TotalLineCount(); total > h-1 {
		first := m.detail.YOffset() + 1
		last := min(m.detail.YOffset()+h-1, total)
		pos = fmt.Sprintf("%d-%d of %d", first, last, total)
	}
	out := []string{spread(title, st.faint.Render(pos), w)}
	vp := m.detail
	vp.SetHeight(h - 1)
	vp.SetWidth(w)
	out = append(out, strings.Split(vp.View(), "\n")...)
	return padLines(out, h)
}

// detailContent renders everything known about the selected result,
// including the catalog text "stackward explain" prints.
func (m Model) detailContent(w int) string {
	st := m.st
	it, ok := m.selected()
	if !ok {
		return "" // the list explains why it is empty
	}
	e, known := m.cat.Lookup(it.ID)
	var b []string
	add := func(lines ...string) { b = append(b, lines...) }

	add(st.brand.Render(it.ID) + st.faint.Render("  "+catalog.GroupName(it.Group)))
	for _, l := range wrapText(it.Title, w) {
		add(st.bold.Render(l))
	}
	add(st.levelStyle(it.Level).Render(strings.ToUpper(string(it.Level))) +
		st.faint.Render(" · ") + st.text.Render(string(it.Severity)) + st.quiet.Render(" severity"))
	if it.Subject != "host" {
		for i, l := range wrapText(it.Subject, w-8) {
			lead := "        "
			if i == 0 {
				lead = st.quiet.Render("subject ")
			}
			add(lead + st.text.Render(l))
		}
	}
	if it.Message != "" {
		add("")
		for _, l := range wrapText(it.Message, w) {
			add(st.text.Render(l))
		}
	}

	sectionHead := func(head, body string) {
		if strings.TrimSpace(body) == "" {
			return
		}
		add("", head)
		for _, l := range wrapText(body, w-2) {
			add("  " + st.text.Render(l))
		}
	}
	section := func(name, body string) { sectionHead(st.section.Render(name), body) }
	if len(it.Evidence) > 0 {
		add("", st.section.Render("EVIDENCE"))
		add(m.evidenceLines(it.Evidence, w)...)
	}
	fix, docs := it.Fix.Hint, it.Fix.Docs
	if known {
		section("WHY IT MATTERS", e.Rationale)
		fix, docs = e.Fix, e.Docs
	}
	sectionHead(st.section.Render("FIX")+st.faint.Render("  y copies it"), fix)
	if known {
		section("VERIFY BY HAND", e.Verify)
		section("WHAT A FIX CAN BREAK", e.Breaks)
		if e.NeedsRoot {
			section("ROOT", "The full result needs sudo.")
		}
	}
	section("MORE", docs)
	if !known {
		add("", st.faint.Render("This build's catalog does not know "+it.ID+"; showing the saved report's text."))
	}
	return strings.Join(b, "\n")
}

// evidenceLines prints evidence as "key value" pairs, sorted by key, with
// values wrapped under a hanging indent.
func (m Model) evidenceLines(ev map[string]any, w int) []string {
	st := m.st
	keys := make([]string, 0, len(ev))
	kw := 0
	for k := range ev {
		keys = append(keys, k)
		kw = max(kw, ansi.StringWidth(k))
	}
	sort.Strings(keys)
	kw = min(kw, max(w/2, 8))
	var out []string
	for _, k := range keys {
		val := evidenceValue(ev[k])
		vw := w - 2 - kw - 2
		if vw < 12 || ansi.StringWidth(k) > kw {
			// Too narrow for two columns: key on its own line.
			out = append(out, "  "+st.quiet.Render(k))
			for _, l := range wrapText(val, w-4) {
				out = append(out, "    "+st.text.Render(l))
			}
			continue
		}
		key := fit(k, kw)
		for i, l := range wrapText(val, vw) {
			if i == 0 {
				out = append(out, "  "+st.quiet.Render(key)+"  "+st.text.Render(l))
				continue
			}
			out = append(out, strings.Repeat(" ", 2+kw+2)+st.text.Render(l))
		}
	}
	return out
}

// evidenceValue renders one evidence value: strings as they are, lists of
// strings comma separated, anything else as compact JSON.
func evidenceValue(v any) string {
	switch x := v.(type) {
	case string:
		if x == "" {
			return `""`
		}
		return x
	case nil:
		return "null"
	case []any:
		parts := make([]string, 0, len(x))
		for _, e := range x {
			s, ok := e.(string)
			if !ok {
				parts = nil
				break
			}
			parts = append(parts, s)
		}
		if parts != nil {
			if len(parts) == 0 {
				return "none"
			}
			return strings.Join(parts, ", ")
		}
	}
	b, err := json.Marshal(v)
	if err != nil {
		return fmt.Sprint(v)
	}
	return string(b)
}

// footer shows the filter input, a status line or the key hints.
func (m Model) footer() string {
	st := m.st
	switch {
	case m.editing:
		return " " + m.input.View() + st.faint.Render("   enter keeps · esc clears")
	case m.status != "":
		return " " + st.accentS.Render(m.status)
	}
	type hint struct{ k, v string }
	var hints []hint
	if m.help {
		hints = []hint{{"?", "close help"}, {"q", "quit"}}
	} else {
		hints = []hint{{"tab", "pane"}, {"/", "filter"}, {"l", "level"}, {"a", "passing"}, {"g", "group"}, {"y", "copy fix"}}
	}
	tail := []hint{{"?", "help"}, {"q", "quit"}}
	if m.help {
		tail = nil
	}
	render := func(hs []hint) string {
		parts := make([]string, 0, len(hs))
		for _, h := range hs {
			parts = append(parts, st.key.Render(h.k)+" "+st.quiet.Render(h.v))
		}
		return " " + strings.Join(parts, "  ")
	}
	for n := len(hints); n >= 0; n-- {
		line := render(append(append([]hint{}, hints[:n]...), tail...))
		if ansi.StringWidth(line) <= m.width {
			return line
		}
	}
	return render(tail)
}

// helpLines is the key reference that replaces the body while ? is open.
func (m Model) helpLines(w, h int) []string {
	st := m.st
	keys := [][2]string{
		{"↑ ↓  j k", "move between results, or scroll the detail pane"},
		{"pgup pgdn", "a page up or down"},
		{"home end", "first or last"},
		{"tab", "switch between the list and the detail pane"},
		{"enter  esc", "open the detail pane, go back"},
		{"/", "filter by id, title, subject or message"},
		{"l", "cycle the level: all, fail, warn, unknown, info"},
		{"a", "show or hide passing and skipped results"},
		{"g  G", "next or previous group"},
		{"y", "copy the fix to the clipboard (OSC 52)"},
		{"?", "close this help"},
		{"q", "quit"},
	}
	out := []string{st.section.Render(" KEYS"), ""}
	kw := 12
	for _, k := range keys {
		for i, l := range wrapText(k[1], w-kw-4) {
			key := ""
			if i == 0 {
				key = k[0]
			}
			out = append(out, "  "+st.key.Render(fit(key, kw))+"  "+st.text.Render(l))
		}
	}
	out = append(out, "")
	for _, l := range wrapText("stackward tui only reads. It writes no file, runs no command and changes nothing on the host. Unknown means could not inspect; it is never a pass.", w-4) {
		out = append(out, "  "+st.quiet.Render(l))
	}
	return padLines(out, h)
}

// wrapText wraps plain text to w cells, breaking long words (URLs, paths)
// when they do not fit. Paragraph breaks are kept.
func wrapText(s string, w int) []string {
	if w < 1 {
		w = 1
	}
	s = strings.TrimRight(s, "\n")
	if s == "" {
		return nil
	}
	return strings.Split(ansi.Wrap(s, w, ""), "\n")
}

// fit truncates s to w cells (with an ellipsis) and pads it with spaces to
// exactly w cells. It understands ANSI styling.
func fit(s string, w int) string {
	if w <= 0 {
		return ""
	}
	if ansi.StringWidth(s) > w {
		s = ansi.Truncate(s, w, "…")
	}
	if pad := w - ansi.StringWidth(s); pad > 0 {
		s += strings.Repeat(" ", pad)
	}
	return s
}

// spread puts left and right on one line of w cells; the right part is
// dropped when both do not fit.
func spread(left, right string, w int) string {
	lw, rw := ansi.StringWidth(left), ansi.StringWidth(right)
	if right == "" || lw+2+rw > w {
		return fit(left, w)
	}
	return left + strings.Repeat(" ", w-lw-rw) + right
}

func padLines(lines []string, h int) []string {
	for len(lines) < h {
		lines = append(lines, "")
	}
	return lines[:h]
}

func orDash(s string) string {
	if s == "" {
		return "-"
	}
	return s
}
