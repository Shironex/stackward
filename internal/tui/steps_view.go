package tui

import (
	"fmt"
	"strings"

	tea "charm.land/bubbletea/v2"
	"charm.land/lipgloss/v2"
	"github.com/charmbracelet/x/ansi"

	"github.com/Shironex/stackward/internal/checks"
)

// unchanged is said wherever a choice is made: nothing changes on the host
// until the review is confirmed.
const unchanged = "nothing has changed yet"

// View renders the whole screen.
func (m StepsModel) View() tea.View {
	v := tea.NewView(m.render())
	v.AltScreen = true
	v.WindowTitle = "stackward steps"
	return v
}

// render returns the screen as text, exactly m.height lines of at most
// m.width cells.
func (m StepsModel) render() string {
	if m.width < minWidth || m.height < minHeight {
		return tooSmallScreen(m.st, m.width, m.height)
	}
	lw, dw, bh := paneDims(m.width, m.height)
	rule := m.st.rule.Render(strings.Repeat("─", m.width))
	lines := make([]string, 0, m.height)
	lines = append(lines, m.header()...)
	lines = append(lines, rule)
	switch m.mode {
	case modeHelp:
		lines = append(lines, m.stepsHelp(m.width, bh)...)
	case modeDialog:
		lines = append(lines, m.dialogLines(m.width, bh)...)
	case modeReview:
		lines = append(lines, m.reviewLines(m.width, bh)...)
	default:
		left, right := m.stepListLines(lw, bh), m.detailPane(dw, bh)
		sep := m.st.rule.Render(gutter)
		for i := range bh {
			lines = append(lines, fit(left[i], lw)+sep+fit(right[i], dw))
		}
	}
	lines = append(lines, rule, m.stepsFooter())
	for i, l := range lines {
		lines[i] = fit(l, m.width)
	}
	return strings.Join(lines, "\n")
}

// header is three lines: the plan, the steps by class, and the selection.
func (m StepsModel) header() []string {
	st := m.st
	dot := st.faint.Render(" · ")
	l := m.list
	l1 := " " + st.brand.Render("stackward") + " " + st.quiet.Render(l.ToolVersion) + dot + st.text.Render("step list") +
		dot + st.quiet.Render("host ") + st.text.Render(orDash(l.Host))
	l1 = spreadKeepRight(l1, st.faint.Render("plan "+l.PlanFile+" "), m.width)

	count := map[string]int{}
	optIn := 0
	for _, s := range l.Steps {
		count[s.Class]++
		if s.OptIn {
			optIn++
		}
	}
	l2 := " " + st.text.Render(fmt.Sprintf("%d steps", len(l.Steps))) + st.quiet.Render(fmt.Sprintf(": %d safe, %d networking, %d access-critical, %d opt in",
		count[ClassSafe], count[ClassNetworking], count[ClassAccessCritical], optIn))
	l2 = spread(l2, st.faint.Render("facts from "+orDash(l.GeneratedAt)+" "), m.width)

	ids := m.selectedIDs()
	l3 := " " + st.text.Render(fmt.Sprintf("%d selected", len(ids)))
	if m.selectionIsAccessCritical() {
		l3 += dot + st.warnText.Render("access-critical: runs alone, in a rollback transaction")
	}
	l3 = spread(l3, st.faint.Render(unchanged+" "), m.width)
	return []string{l1, l2, l3}
}

func (m StepsModel) selectionIsAccessCritical() bool {
	for _, s := range m.list.Steps {
		if m.sel[s.ID] && s.Class == ClassAccessCritical {
			return true
		}
	}
	return false
}

// classTitle is the group header of a risk class.
func classTitle(c string) string {
	switch c {
	case ClassSafe:
		return "SAFE"
	case ClassNetworking:
		return "NETWORKING"
	case ClassAccessCritical:
		return "ACCESS-CRITICAL"
	}
	return strings.ToUpper(c)
}

// stepListLines renders the list pane: a title row and the visible rows.
func (m StepsModel) stepListLines(w, h int) []string {
	st := m.st
	title := st.quiet.Render("STEPS")
	if m.focus == listPane {
		title = st.section.Render("STEPS")
	}
	out := []string{spread(title, st.faint.Render(fmt.Sprintf("%d of %d selected", len(m.selectedIDs()), len(m.list.Steps))), w)}
	if len(m.rows) == 0 {
		out = append(out, "")
		for _, l := range wrapText("This plan has no steps: nothing to apply.", w-2) {
			out = append(out, " "+st.text.Render(l))
		}
		for _, l := range wrapText(fmt.Sprintf("%d checks have no step; stackward plan lists why.", m.list.NotPlanned), w-2) {
			out = append(out, " "+st.quiet.Render(l))
		}
		return padLines(out, h)
	}
	end := min(m.top+h-1, len(m.rows))
	for i := m.top; i < end; i++ {
		out = append(out, m.stepRowLine(m.rows[i], i == m.cursor, w))
	}
	return padLines(out, h)
}

// stepTag is the short state shown at the end of a row.
func stepTag(s StepItem) string {
	switch {
	case s.Blocked != "":
		return "cannot run"
	case s.Applied:
		return "applied"
	case s.OptIn:
		return "opt in"
	}
	return ""
}

func (m StepsModel) stepRowLine(r stepRow, cur bool, w int) string {
	st := m.st
	if r.header() {
		n := 0
		for _, s := range m.list.Steps {
			if s.Class == r.class {
				n++
			}
		}
		head := st.section.Render(classTitle(r.class))
		if r.class != ClassSafe {
			head = st.warnText.Bold(true).Render(classTitle(r.class))
		}
		return spread(head, st.faint.Render(fmt.Sprint(n)), w)
	}
	s := m.list.Steps[r.step]
	box := "[ ]"
	if m.sel[s.ID] {
		box = "[x]"
	}
	tag := stepTag(s)
	if cur && m.focus == listPane {
		return st.selected.Render(fit(spreadKeepRight("› "+box+" "+s.ID, tag, w), w))
	}
	marker := "  "
	if cur {
		marker = st.marker.Render("› ")
	}
	idStyle := st.text
	if cur {
		idStyle = st.bold
	}
	tagStyle := st.quiet
	if s.Blocked != "" {
		tagStyle = st.levelStyle(checks.Fail)
	}
	return spreadKeepRight(marker+st.accentS.Render(box)+" "+idStyle.Render(s.ID), tagStyle.Render(tag), w)
}

// detailPane renders the title row and the detail viewport.
func (m StepsModel) detailPane(w, h int) []string {
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
	out = append(out, strings.Split(m.detail.View(), "\n")...)
	return padLines(out, h)
}

// classWarning is what a networking or access-critical step can do to the
// host, in plain words; "" for a safe step.
func (m StepsModel) classWarning(s StepItem) string {
	switch s.Class {
	case ClassNetworking:
		if len(s.Restarts) > 0 {
			return "Networking: it restarts " + strings.Join(s.Restarts, ", ") + ", which can interrupt traffic (running containers stop and start)."
		}
		return "Networking: it can interrupt traffic or the host; read its notes."
	case ClassAccessCritical:
		return fmt.Sprintf("Access-critical: it changes SSH, the firewall or accounts. It runs alone, inside a rollback transaction: unless you confirm from a new SSH session within %s, a timer undoes it. Make sure you can log in to the provider console first.", orDash(m.opts.ConfirmWithin))
	}
	return ""
}

// stepDetail renders everything about the step under the cursor: what it
// changes, why, the diff, the undo and, for an access-critical step, the
// lockout guard's proof or refusal.
func (m StepsModel) stepDetail(w int) string {
	i, ok := m.current()
	if !ok {
		return ""
	}
	st, s := m.st, m.list.Steps[i]
	var b []string
	add := func(lines ...string) { b = append(b, lines...) }
	para := func(style func(...string) string, text string) {
		for _, l := range wrapText(text, w) {
			add(style(l))
		}
	}
	// hanging wraps one line at w, its continuation lines indented by
	// more, so a long path or command still reads as one entry.
	hanging := func(style func(...string) string, first, more, l string) {
		for j, part := range strings.Split(ansi.Wrap(l, max(w-len(more), 1), "/"), "\n") {
			lead := more
			if j == 0 {
				lead = first
			}
			add(lead + style(part))
		}
	}
	section := func(name string, lines []string) {
		if len(lines) == 0 {
			return
		}
		add("", st.section.Render(name))
		for _, l := range lines {
			hanging(st.text.Render, "  ", "    ", l)
		}
	}

	classStyle := st.accentS.Bold(true)
	if s.Class != ClassSafe {
		classStyle = st.warnText.Bold(true)
	}
	add(st.brand.Render(s.ID) + "  " + classStyle.Render(strings.ToUpper(s.Class)))
	para(st.bold.Render, s.Title)
	if s.OptIn {
		para(st.warnText.Render, "Opt in: off until you select it.")
	}
	if s.Blocked != "" {
		para(st.levelStyle(checks.Fail).Render, "Cannot run now: "+s.Blocked)
	} else if s.Applied {
		para(st.accentS.Render, "Already applied: "+orDash(s.AppliedWhy)+". Apply would skip it.")
	}
	if warn := m.classWarning(s); warn != "" {
		add("")
		para(st.warnText.Render, warn)
	}

	var why []string
	for _, id := range s.Fixes {
		line := id
		if m.cat != nil {
			if c, found := m.cat.Lookup(id); found {
				line += " " + c.Title
			}
		}
		why = append(why, line)
	}
	section("WHY: THE CHECKS IT FIXES", why)
	section("WHAT IT CHANGES", s.Changes)
	if len(s.Diff) > 0 {
		add("", st.section.Render("DIFF"))
		for _, l := range s.Diff {
			hanging(diffStyle(st, l).Render, "  ", "   ", l)
		}
	}
	section("UNDO", s.Undo)
	section("NOTES", s.Notes)
	if s.Class == ClassAccessCritical {
		section("LOCKOUT GUARD", guardWords(s))
	}
	return strings.Join(b, "\n")
}

// guardWords says what the lockout guard found, in plain words.
func guardWords(s StepItem) []string {
	g := s.Guard
	switch {
	case g == nil && s.Blocked != "":
		return []string{"Refused: " + s.Blocked}
	case g == nil:
		return []string{"Not checked: apply proves a second way in right before it runs, and refuses the step without one."}
	case !g.Needed:
		return []string{"This step closes or narrows no way in, so no second way in has to be proven."}
	}
	out := []string{"Proven from this host's live state; apply proves it again right before it runs."}
	if len(g.Narrows) > 0 {
		out = append(out, "This step "+strings.Join(g.Narrows, ", ")+".")
	}
	for _, w := range g.Ways {
		out = append(out, "A second way in stays: "+w+".")
	}
	if len(g.ConfirmFrom) > 0 {
		out = append(out, "The confirming session must come from "+strings.Join(g.ConfirmFrom, ", ")+".")
	}
	return out
}

// dialogLines asks before a networking or access-critical step, or a step
// apply would refuse beside the others, joins the selection.
func (m StepsModel) dialogLines(w, h int) []string {
	st := m.st
	s := m.list.Steps[m.dialog.step]
	out := []string{st.warnText.Bold(true).Render(" SELECT " + s.ID + "?"), ""}
	para := func(style func(...string) string, text string) {
		for _, l := range wrapText(text, w-4) {
			out = append(out, "  "+style(l))
		}
	}
	para(st.bold.Render, s.Title)
	if warn := m.classWarning(s); warn != "" {
		out = append(out, "")
		para(st.warnText.Render, warn)
	}
	if m.dialog.conflict != "" {
		out = append(out, "")
		para(st.text.Render, "Apply would refuse it beside the steps already selected: "+m.dialog.conflict)
		out = append(out, "")
		para(st.text.Render, "y selects "+s.ID+" alone and clears the other selected steps.")
	}
	out = append(out, "")
	para(st.quiet.Render, "Selecting changes nothing. Apply runs only after the review screen and your y there.")
	return padLines(out, h)
}

// reviewLines renders the review: what apply would do, before anything
// changes.
func (m StepsModel) reviewLines(w, h int) []string {
	st := m.st
	title := st.section.Render(" REVIEW")
	if m.review.AccessCritical {
		title += st.warnText.Render("  access-critical transaction")
	}
	pos := ""
	if total := m.revVP.TotalLineCount(); total > h-1 {
		first := m.revVP.YOffset() + 1
		last := min(m.revVP.YOffset()+h-1, total)
		pos = fmt.Sprintf("%d-%d of %d ", first, last, total)
	}
	out := []string{spread(title, st.faint.Render(pos), w)}
	out = append(out, strings.Split(m.revVP.View(), "\n")...)
	return padLines(out, h)
}

// reviewContent is the review text, wrapped to w with a hanging indent.
func (m StepsModel) reviewContent(w int) string {
	st := m.st
	var b []string
	wrapLine := func(style func(...string) string, l string) {
		indent := len(l) - len(strings.TrimLeft(l, " "))
		lead := strings.Repeat(" ", indent+1)
		for j, part := range wrapText(strings.TrimLeft(l, " "), w-len(lead)-1) {
			if j > 0 {
				lead = strings.Repeat(" ", indent+4)
			}
			b = append(b, lead+style(part))
		}
	}
	if r := m.review.Refused; r != "" {
		wrapLine(st.levelStyle(checks.Fail).Render, "Apply would refuse this selection; nothing can be applied:")
		wrapLine(st.text.Render, "  "+r)
		b = append(b, "")
	}
	for _, l := range strings.Split(strings.TrimRight(m.review.Text, "\n"), "\n") {
		if strings.TrimSpace(l) == "" {
			b = append(b, "")
			continue
		}
		style := st.text.Render
		if !strings.HasPrefix(l, " ") && strings.HasSuffix(l, ":") {
			style = st.section.Render
		}
		wrapLine(style, l)
	}
	return strings.Join(b, "\n")
}

// diffStyle colors a diff line by its first character.
func diffStyle(st styles, l string) lipgloss.Style {
	switch {
	case strings.HasPrefix(l, "+++"), strings.HasPrefix(l, "---"), strings.HasPrefix(l, "@@"):
		return st.faint
	case strings.HasPrefix(l, "+"):
		return st.accentS
	case strings.HasPrefix(l, "-"):
		return st.levelStyle(checks.Fail)
	}
	return st.quiet
}

// stepsFooter shows the status or the keys of the current screen.
func (m StepsModel) stepsFooter() string {
	st := m.st
	if m.status != "" {
		return " " + st.accentS.Render(ansi.Truncate(m.status, max(m.width-2, 1), "…"))
	}
	quit := []hint{{"q", "quit"}}
	switch m.mode {
	case modeHelp:
		return keyHints(st, m.width, []hint{{"?", "close help"}}, quit)
	case modeDialog:
		return keyHints(st, m.width, []hint{{"y", "select"}, {"n", "cancel"}}, nil)
	case modeReview:
		var hs []hint
		switch {
		case m.review.Refused != "":
		case m.review.ToRun == 0:
			hs = append(hs, hint{"", "nothing to do"})
		case m.review.AccessCritical:
			hs = append(hs, hint{"y", "apply in a transaction"})
		default:
			hs = append(hs, hint{"y", fmt.Sprintf("apply %d step(s)", m.review.ToRun)})
		}
		hs = append(hs, hint{"esc", "back"}, hint{"↑↓", "scroll"})
		return keyHints(st, m.width, hs, quit)
	}
	return keyHints(st, m.width, []hint{{"space", "select"}, {"enter", "review"}, {"tab", "pane"}, {"↑↓", "move"}}, []hint{{"?", "help"}, {"q", "quit"}})
}

// stepsHelp is the key reference of the step list.
func (m StepsModel) stepsHelp(w, h int) []string {
	st := m.st
	keys := [][2]string{
		{"↑ ↓  j k", "move between steps, or scroll the detail pane"},
		{"space  x", "select or deselect the step under the cursor"},
		{"tab", "switch between the list and the detail pane"},
		{"enter", "review the selection: what apply will do"},
		{"y", "on the review: apply; in a question: yes"},
		{"esc  n", "go back, or answer no"},
		{"?", "close this help"},
		{"q", "quit without applying anything"},
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
	for _, l := range wrapText("Selecting changes nothing. Safe steps start selected, opt in, networking and access-critical steps start off. Networking and access-critical steps ask before they join the selection. Apply runs only after the review screen and your y there, with the same code as stackward apply, and prints what it did when the list closes.", w-4) {
		out = append(out, "  "+st.quiet.Render(l))
	}
	return padLines(out, h)
}
