// Package tui is the interactive findings browser behind "stackward tui"
// and the guided step list behind "stackward tui --plan". It writes nothing
// to disk, runs no command and opens no connection. The browser only reads
// a report; the one thing it can send anywhere is the fix text of the
// selected check, to the terminal clipboard over OSC 52, and only when the
// user presses the copy key. The step list only presents steps the CLI
// judged and returns the reader's choice; the CLI applies it with the code
// of stackward apply.
package tui

import (
	"fmt"
	"io"

	"charm.land/bubbles/v2/textinput"
	"charm.land/bubbles/v2/viewport"
	tea "charm.land/bubbletea/v2"
	"github.com/charmbracelet/colorprofile"

	"github.com/Shironex/stackward/internal/catalog"
	"github.com/Shironex/stackward/internal/checks"
	"github.com/Shironex/stackward/internal/report"
)

// Options tunes the browser.
type Options struct {
	// ShowHostname prints a hostname found in the report instead of its
	// hash, like audit --show-hostname.
	ShowHostname bool
	// NoColor drops colors (NO_COLOR, TERM=dumb). Bold and reverse stay,
	// so the cursor row is still visible.
	NoColor bool
	// Source says where the report came from, for the header ("live
	// audit", "facts.json", "report.json").
	Source string
}

// Run shows the browser on in and out until the user quits.
func Run(rep *report.Report, o Options, in io.Reader, out io.Writer) error {
	m, err := New(rep, o)
	if err != nil {
		return err
	}
	opts := []tea.ProgramOption{tea.WithInput(in), tea.WithOutput(out)}
	if o.NoColor {
		opts = append(opts, tea.WithColorProfile(colorprofile.Ascii))
	}
	_, err = tea.NewProgram(m, opts...).Run()
	return err
}

type pane int

const (
	listPane pane = iota
	detailPane
)

// Model is the Bubble Tea model of the browser.
type Model struct {
	rep   *report.Report
	cat   *catalog.Catalog
	opts  Options
	items []report.Item // every result, in list order
	// badgeW is the width of the level badge in the list.
	badgeW int

	f       filter
	rows    []row
	cursor  int // index into rows of the selected result, -1 when none
	top     int // first visible row of the list
	focus   pane
	help    bool
	editing bool // the filter input has focus
	input   textinput.Model
	detail  viewport.Model
	status  string

	width, height int
	dark          bool
	st            styles
}

// New builds the model for a report.
func New(rep *report.Report, o Options) (Model, error) {
	if rep == nil {
		return Model{}, fmt.Errorf("tui: no report")
	}
	cat, err := catalog.Default()
	if err != nil {
		return Model{}, err
	}
	in := textinput.New()
	in.Prompt = "/"
	in.Placeholder = "id, title, subject or message"
	in.CharLimit = 64
	m := Model{
		rep: rep, cat: cat, opts: o,
		items:  sortItems(rep.Results),
		badgeW: badgeWidth(rep.Results),
		input:  in,
		detail: viewport.New(),
		dark:   true,
		st:     newStyles(true),
		width:  80, height: 24,
	}
	m.detail.SoftWrap = false
	m.rebuild()
	return m, nil
}

// Init asks the terminal for its background so the palette fits it.
func (m Model) Init() tea.Cmd { return tea.RequestBackgroundColor }

// Update handles one message.
func (m Model) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	switch msg := msg.(type) {
	case tea.WindowSizeMsg:
		m.width, m.height = msg.Width, msg.Height
		m.layout()
		return m, nil
	case tea.BackgroundColorMsg:
		m.dark = msg.IsDark()
		m.st = newStyles(m.dark)
		m.refreshDetail(false)
		return m, nil
	case tea.KeyPressMsg:
		return m.key(msg)
	}
	if m.editing {
		var cmd tea.Cmd
		m.input, cmd = m.input.Update(msg)
		return m, cmd
	}
	return m, nil
}

func (m Model) key(msg tea.KeyPressMsg) (tea.Model, tea.Cmd) {
	k := msg.String()
	if k == "ctrl+c" {
		return m, tea.Quit
	}
	m.status = ""
	if m.editing {
		return m.editKey(msg)
	}
	if m.help {
		switch k {
		case "q":
			return m, tea.Quit
		case "?", "esc", "enter":
			m.help = false
		}
		return m, nil
	}
	switch k {
	case "q":
		return m, tea.Quit
	case "?":
		m.help = true
	case "tab", "shift+tab":
		m.toggleFocus()
	case "enter", "right":
		if m.cursor >= 0 {
			m.focus = detailPane
		}
	case "esc", "left":
		switch {
		case m.focus == detailPane:
			m.focus = listPane
		case m.f.query != "":
			m.f.query = ""
			m.input.SetValue("")
			m.rebuild()
		}
	case "/":
		m.editing = true
		m.input.SetValue(m.f.query)
		m.input.CursorEnd()
		return m, m.input.Focus()
	case "l":
		m.f.level = nextLevel(m.f.level, m.f.passing, m.rep.Summary.Accepted > 0)
		m.rebuild()
	case "a":
		m.f.passing = !m.f.passing
		if !m.f.passing && hiddenByDefault(m.f.level) {
			m.f.level = ""
		}
		m.rebuild()
	case "g":
		m.jumpGroup(1)
	case "G":
		m.jumpGroup(-1)
	case "y":
		return m, m.copyFix()
	default:
		if m.focus == detailPane {
			m.scrollDetail(k)
		} else {
			m.moveList(k)
		}
	}
	return m, nil
}

// editKey handles keys while the filter input has focus: the list follows
// every keystroke, enter keeps the filter, esc drops it.
func (m Model) editKey(msg tea.KeyPressMsg) (tea.Model, tea.Cmd) {
	switch msg.String() {
	case "enter", "tab":
		m.editing = false
		m.input.Blur()
		return m, nil
	case "esc":
		m.editing = false
		m.input.Blur()
		m.input.SetValue("")
		m.f.query = ""
		m.rebuild()
		return m, nil
	case "up", "down":
		m.moveList(msg.String())
		return m, nil
	}
	var cmd tea.Cmd
	m.input, cmd = m.input.Update(msg)
	if v := m.input.Value(); v != m.f.query {
		m.f.query = v
		m.rebuild()
	}
	return m, cmd
}

func (m *Model) toggleFocus() {
	if m.focus == listPane && m.cursor >= 0 {
		m.focus = detailPane
	} else {
		m.focus = listPane
	}
}

// copyFix sends the selected check's fix to the clipboard over OSC 52. It
// never shells out to a clipboard tool.
func (m *Model) copyFix() tea.Cmd {
	it, ok := m.selected()
	if !ok {
		m.status = "nothing selected to copy"
		return nil
	}
	fix := m.fixText(it)
	if fix == "" {
		m.status = it.ID + " has no fix text"
		return nil
	}
	m.status = "copied the fix for " + it.ID + " (OSC 52, if the terminal allows it)"
	return tea.SetClipboard(fix)
}

// fixText is the catalog fix of a result, or the hint saved in the report
// when this build's catalog does not know the id.
func (m Model) fixText(it report.Item) string {
	if e, ok := m.cat.Lookup(it.ID); ok {
		return e.Fix
	}
	return it.Fix.Hint
}

// selected returns the result under the cursor.
func (m Model) selected() (report.Item, bool) {
	if m.cursor < 0 || m.cursor >= len(m.rows) || m.rows[m.cursor].header() {
		return report.Item{}, false
	}
	return m.items[m.rows[m.cursor].item], true
}

// rebuild recomputes the rows after a filter change and keeps the cursor on
// the same result when it is still shown.
func (m *Model) rebuild() {
	keep := -1
	if _, ok := m.selected(); ok {
		keep = m.rows[m.cursor].item
	}
	m.rows = buildRows(m.items, m.f)
	m.cursor = -1
	for i, r := range m.rows {
		if r.header() {
			continue
		}
		if m.cursor < 0 || r.item == keep {
			m.cursor = i
		}
		if r.item == keep {
			break
		}
	}
	if m.cursor < 0 {
		m.focus = listPane
	}
	m.top = 0
	m.scrollList()
	m.refreshDetail(true)
}

// moveList moves the cursor over results, skipping group headers.
func (m *Model) moveList(k string) {
	if m.cursor < 0 {
		return
	}
	step := 0
	switch k {
	case "up", "k":
		step = -1
	case "down", "j":
		step = 1
	case "pgup", "ctrl+u":
		step = -max(1, m.listHeight()-1)
	case "pgdown", "ctrl+d", "space":
		step = max(1, m.listHeight()-1)
	case "home":
		step = -len(m.rows)
	case "end":
		step = len(m.rows)
	default:
		return
	}
	m.moveBy(step)
}

// moveBy moves the cursor step results (not rows) and clamps at the ends.
func (m *Model) moveBy(step int) {
	idx := m.resultIndexes()
	pos := 0
	for i, r := range idx {
		if r == m.cursor {
			pos = i
		}
	}
	pos = min(max(pos+step, 0), len(idx)-1)
	if idx[pos] != m.cursor {
		m.cursor = idx[pos]
		m.scrollList()
		m.refreshDetail(true)
	}
}

func (m Model) resultIndexes() []int {
	var idx []int
	for i, r := range m.rows {
		if !r.header() {
			idx = append(idx, i)
		}
	}
	return idx
}

// jumpGroup moves to the first result of the next (dir 1) or previous
// (dir -1) group, wrapping around.
func (m *Model) jumpGroup(dir int) {
	if m.cursor < 0 {
		return
	}
	var heads []int
	cur := 0
	for i, r := range m.rows {
		if r.header() {
			if i < m.cursor {
				cur = len(heads)
			}
			heads = append(heads, i)
		}
	}
	if len(heads) == 0 {
		return
	}
	next := heads[(cur+dir+len(heads))%len(heads)]
	m.cursor = next + 1
	m.focus = listPane
	// Put the group header at the top of the list where the rows allow.
	m.top = max(0, min(next, len(m.rows)-m.listHeight()))
	m.scrollList()
	m.refreshDetail(true)
}

func (m *Model) scrollDetail(k string) {
	switch k {
	case "up", "k":
		m.detail.ScrollUp(1)
	case "down", "j":
		m.detail.ScrollDown(1)
	case "pgup", "ctrl+u":
		m.detail.PageUp()
	case "pgdown", "ctrl+d", "space":
		m.detail.PageDown()
	case "home":
		m.detail.GotoTop()
	case "end":
		m.detail.GotoBottom()
	}
}

// scrollList keeps the cursor row (and the header above it, where it
// fits) inside the visible window.
func (m *Model) scrollList() {
	h := m.listHeight()
	if h <= 0 || m.cursor < 0 {
		m.top = 0
		return
	}
	want := m.cursor
	if want > 0 && m.rows[want-1].header() {
		want--
	}
	if want < m.top {
		m.top = want
	}
	if m.cursor >= m.top+h {
		m.top = m.cursor - h + 1
	}
	m.top = max(0, min(m.top, len(m.rows)-h))
}

// layout applies the window size to the panes.
func (m *Model) layout() {
	_, dw, bh := m.dims()
	m.detail.SetWidth(dw)
	m.detail.SetHeight(bh)
	m.input.SetWidth(max(10, min(48, m.width-34)))
	m.scrollList()
	m.refreshDetail(false)
}

// refreshDetail renders the selected result into the detail pane; top
// scrolls it back to the start (a new selection).
func (m *Model) refreshDetail(top bool) {
	_, dw, _ := m.dims()
	m.detail.SetContent(m.detailContent(dw))
	if top {
		m.detail.GotoTop()
	}
}

// Selected returns the id and subject under the cursor, for tests.
func (m Model) Selected() (id, subject string) {
	if it, ok := m.selected(); ok {
		return it.ID, it.Subject
	}
	return "", ""
}

// Level returns the active level filter, for tests.
func (m Model) Level() checks.Level { return m.f.level }
