package tui

import (
	"io"
	"slices"

	"charm.land/bubbles/v2/viewport"
	tea "charm.land/bubbletea/v2"
	"github.com/charmbracelet/colorprofile"

	"github.com/Shironex/stackward/internal/catalog"
)

// Risk classes as the step list shows them. They are the plan's own words
// (plan.Safe, plan.Networking, plan.AccessCritical); the CLI fills them from
// the step's generator, never from the plan file.
const (
	ClassSafe           = "safe"
	ClassNetworking     = "networking"
	ClassAccessCritical = "access-critical"
)

// StepList is what the guided step list shows: the steps of a saved plan,
// as the CLI found them on this host. The step list only presents them and
// collects choices; it changes nothing. The CLI applies the choice
// afterwards with the same code as stackward apply.
type StepList struct {
	PlanFile    string
	Host        string // the plan's host, as the plan names it
	ToolVersion string // the stackward that wrote the plan
	GeneratedAt string // when the plan's facts were collected
	NotPlanned  int    // checks the plan has no step for
	Steps       []StepItem
}

// StepItem is one planned step, with everything a reader needs before
// selecting it.
type StepItem struct {
	ID    string
	Title string
	Class string // ClassSafe, ClassNetworking or ClassAccessCritical
	OptIn bool   // off by default, runs only when selected
	// Fixes are the check ids the step makes pass.
	Fixes []string
	// Changes are the files the step creates or replaces and the commands
	// it runs, one line each, as apply prints them.
	Changes []string
	// Diff is the unified diff of every file edit.
	Diff     []string
	Restarts []string
	// Undo says how the step is reversed: the description, then the
	// commands.
	Undo  []string
	Notes []string
	// Applied is true when the step's check found the change in place.
	Applied    bool
	AppliedWhy string
	// Blocked, when set, says why apply would refuse the step now (a file
	// changed since the audit, the lockout guard, an open transaction).
	// A blocked step cannot be selected.
	Blocked string
	// Guard is the lockout guard's proof for an access-critical step; nil
	// for other steps and when the guard refused (Blocked says why).
	Guard *GuardProof
}

// GuardProof is what the lockout guard proved about one step from this
// host's live state.
type GuardProof struct {
	// Needed is false when the step closes or narrows no way in.
	Needed bool
	// Narrows says what the step closes or narrows.
	Narrows []string
	// Ways are the second ways in that survive the step.
	Ways []string
	// ConfirmFrom lists the networks the confirming session must come
	// from.
	ConfirmFrom []string
}

// Review is what apply would do with a selection, as the CLI worked it out
// with apply's own code.
type Review struct {
	// Text is what apply prints before it asks: the preview and, for
	// access-critical steps, the guard proof and the transaction.
	Text string
	// ToRun counts the selected steps that are not already applied.
	ToRun int
	// AccessCritical is true when the selection runs as a transaction.
	AccessCritical bool
	// Refused, when set, is why apply would refuse the selection;
	// nothing can be applied then.
	Refused string
}

// StepsOptions tunes the step list.
type StepsOptions struct {
	NoColor bool
	// ConfirmWithin is the transaction's deadline, for the warnings
	// ("5m0s").
	ConfirmWithin string
	// Allowed reports whether apply accepts a selection (apply.Select):
	// access-critical steps run alone, for example. The step list asks it
	// rather than knowing the rules.
	Allowed func(ids []string) error
	// Review works out what apply would do with a selection. It only
	// reads.
	Review func(ids []string) Review
}

// Choice is what the reader decided.
type Choice struct {
	// Apply is true only after the review screen was confirmed.
	Apply bool
	// Steps are the selected step ids, in plan order.
	Steps []string
}

// RunSteps shows the step list until the reader quits or confirms the
// review, and returns the choice.
func RunSteps(list StepList, o StepsOptions, in io.Reader, out io.Writer) (Choice, error) {
	m := NewSteps(list, o)
	opts := []tea.ProgramOption{tea.WithInput(in), tea.WithOutput(out)}
	if o.NoColor {
		opts = append(opts, tea.WithColorProfile(colorprofile.Ascii))
	}
	fm, err := tea.NewProgram(m, opts...).Run()
	if err != nil {
		return Choice{}, err
	}
	sm, ok := fm.(StepsModel)
	if !ok {
		return Choice{}, nil
	}
	return sm.Choice(), nil
}

type stepsMode int

const (
	modeList stepsMode = iota
	modeHelp
	modeDialog
	modeReview
)

// stepRow is one line of the list: a class header or a step.
type stepRow struct {
	class string
	step  int // index into list.Steps, -1 for a header
}

func (r stepRow) header() bool { return r.step < 0 }

// stepDialog asks before a step joins the selection: a networking or
// access-critical warning, or a selection apply would refuse.
type stepDialog struct {
	step     int
	conflict string // why apply refuses the step beside the others
}

// StepsModel is the Bubble Tea model of the step list.
type StepsModel struct {
	list   StepList
	cat    *catalog.Catalog // check titles for the WHY section; nil shows ids only
	opts   StepsOptions
	rows   []stepRow
	cursor int // row of the step under the cursor, -1 when there is none
	top    int
	focus  pane
	mode   stepsMode
	sel    map[string]bool
	dialog stepDialog
	review Review
	detail viewport.Model
	revVP  viewport.Model
	status string
	choice Choice

	width, height int
	dark          bool
	st            styles
}

// classOrder is the order of the groups: the least risky first.
var classOrder = []string{ClassSafe, ClassNetworking, ClassAccessCritical}

// NewSteps builds the step list. Safe steps that are not opt in, not
// already applied and not blocked start selected, like --all-safe;
// everything else starts off.
func NewSteps(list StepList, o StepsOptions) StepsModel {
	m := StepsModel{
		list: list, opts: o,
		sel:    map[string]bool{},
		detail: viewport.New(),
		revVP:  viewport.New(),
		dark:   true,
		st:     newStyles(true),
		width:  80, height: 24,
		cursor: -1,
	}
	m.cat, _ = catalog.Default()
	m.detail.SoftWrap = false
	m.revVP.SoftWrap = false
	for _, c := range classOrder {
		first := true
		for i, s := range list.Steps {
			if s.Class != c {
				continue
			}
			if first {
				m.rows = append(m.rows, stepRow{class: c, step: -1})
				first = false
			}
			m.rows = append(m.rows, stepRow{class: c, step: i})
			if m.cursor < 0 {
				m.cursor = len(m.rows) - 1
			}
		}
	}
	for _, s := range list.Steps {
		if s.Class == ClassSafe && !s.OptIn && !s.Applied && s.Blocked == "" {
			m.sel[s.ID] = true
		}
	}
	if m.allowed(m.selectedIDs()) != nil {
		m.sel = map[string]bool{}
	}
	m.refreshDetail(true)
	return m
}

// Init asks the terminal for its background so the palette fits it.
func (m StepsModel) Init() tea.Cmd { return tea.RequestBackgroundColor }

// Update handles one message.
func (m StepsModel) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	switch msg := msg.(type) {
	case tea.WindowSizeMsg:
		m.width, m.height = msg.Width, msg.Height
		m.refreshDetail(false)
		m.refreshReview(false)
		return m, nil
	case tea.BackgroundColorMsg:
		m.dark = msg.IsDark()
		m.st = newStyles(m.dark)
		m.refreshDetail(false)
		m.refreshReview(false)
		return m, nil
	case tea.KeyPressMsg:
		return m.key(msg.String())
	}
	return m, nil
}

func (m StepsModel) key(k string) (tea.Model, tea.Cmd) {
	if k == "ctrl+c" {
		return m, tea.Quit
	}
	m.status = ""
	switch m.mode {
	case modeHelp:
		switch k {
		case "q":
			return m, tea.Quit
		case "?", "esc", "enter":
			m.mode = modeList
		}
		return m, nil
	case modeDialog:
		return m.dialogKey(k)
	case modeReview:
		return m.reviewKey(k)
	}
	switch k {
	case "q":
		return m, tea.Quit
	case "?":
		m.mode = modeHelp
	case "tab", "shift+tab":
		if m.focus == listPane && m.cursor >= 0 {
			m.focus = detailPane
		} else {
			m.focus = listPane
		}
	case "esc", "left":
		m.focus = listPane
	case "right":
		if m.cursor >= 0 {
			m.focus = detailPane
		}
	case "space", "x":
		m.toggle()
	case "enter":
		m.openReview()
	default:
		if m.focus == detailPane {
			scrollView(&m.detail, k)
		} else {
			m.move(k)
		}
	}
	return m, nil
}

func (m StepsModel) dialogKey(k string) (tea.Model, tea.Cmd) {
	switch k {
	case "y":
		s := m.list.Steps[m.dialog.step]
		if m.dialog.conflict != "" {
			only := []string{s.ID}
			if err := m.allowed(only); err != nil {
				m.status = err.Error()
				m.mode = modeList
				return m, nil
			}
			m.sel = map[string]bool{}
		}
		m.sel[s.ID] = true
		m.status = "selected " + s.ID
		m.mode = modeList
	case "n", "esc":
		m.status = "not selected"
		m.mode = modeList
	case "q":
		return m, tea.Quit
	}
	return m, nil
}

func (m StepsModel) reviewKey(k string) (tea.Model, tea.Cmd) {
	switch k {
	case "y":
		if m.review.Refused != "" || m.review.ToRun == 0 {
			return m, nil
		}
		m.choice = Choice{Apply: true, Steps: m.selectedIDs()}
		return m, tea.Quit
	case "esc", "n", "backspace", "left":
		m.mode = modeList
	case "q":
		return m, tea.Quit
	default:
		scrollView(&m.revVP, k)
	}
	return m, nil
}

// toggle selects or deselects the step under the cursor. A step joins the
// selection at once only when it is safe and apply accepts it beside the
// others; a networking or access-critical step, or one apply would refuse
// beside the others, asks first.
func (m *StepsModel) toggle() {
	i, ok := m.current()
	if !ok {
		return
	}
	s := m.list.Steps[i]
	if m.sel[s.ID] {
		delete(m.sel, s.ID)
		m.status = "deselected " + s.ID
		return
	}
	if s.Blocked != "" {
		m.status = s.ID + " cannot run now; the detail pane says why"
		return
	}
	conflict := ""
	if err := m.allowed(append(m.selectedIDs(), s.ID)); err != nil {
		conflict = err.Error()
	}
	if conflict == "" && s.Class == ClassSafe {
		m.sel[s.ID] = true
		m.status = "selected " + s.ID
		return
	}
	m.dialog = stepDialog{step: i, conflict: conflict}
	m.mode = modeDialog
}

// openReview asks the CLI what apply would do with the selection.
func (m *StepsModel) openReview() {
	ids := m.selectedIDs()
	if len(ids) == 0 {
		m.status = "nothing selected; space selects the step under the cursor"
		return
	}
	if m.opts.Review == nil {
		m.review = Review{Refused: "this step list cannot review a selection"}
	} else {
		m.review = m.opts.Review(ids)
	}
	m.mode = modeReview
	m.refreshReview(true)
}

func (m StepsModel) allowed(ids []string) error {
	if m.opts.Allowed == nil || len(ids) == 0 {
		return nil
	}
	return m.opts.Allowed(ids)
}

// selectedIDs returns the selected step ids in plan order.
func (m StepsModel) selectedIDs() []string {
	var ids []string
	for _, s := range m.list.Steps {
		if m.sel[s.ID] {
			ids = append(ids, s.ID)
		}
	}
	return ids
}

// current returns the index of the step under the cursor.
func (m StepsModel) current() (int, bool) {
	if m.cursor < 0 || m.cursor >= len(m.rows) || m.rows[m.cursor].header() {
		return 0, false
	}
	return m.rows[m.cursor].step, true
}

// move moves the cursor over steps, skipping class headers.
func (m *StepsModel) move(k string) {
	if m.cursor < 0 {
		return
	}
	var idx []int
	pos := 0
	for i, r := range m.rows {
		if r.header() {
			continue
		}
		if i == m.cursor {
			pos = len(idx)
		}
		idx = append(idx, i)
	}
	page := max(1, m.listHeight()-1)
	switch k {
	case "up", "k":
		pos--
	case "down", "j":
		pos++
	case "pgup", "ctrl+u":
		pos -= page
	case "pgdown", "ctrl+d":
		pos += page
	case "home", "g":
		pos = 0
	case "end", "G":
		pos = len(idx) - 1
	default:
		return
	}
	pos = min(max(pos, 0), len(idx)-1)
	if idx[pos] != m.cursor {
		m.cursor = idx[pos]
		m.scrollList()
		m.refreshDetail(true)
	}
}

// scrollList keeps the cursor row, and the header above it, in view.
func (m *StepsModel) scrollList() {
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

func (m StepsModel) listHeight() int {
	_, _, bh := paneDims(m.width, m.height)
	return bh - 1
}

// refreshDetail renders the step under the cursor into the detail pane;
// top scrolls it back to the start.
func (m *StepsModel) refreshDetail(top bool) {
	_, dw, bh := paneDims(m.width, m.height)
	m.detail.SetWidth(dw)
	m.detail.SetHeight(max(bh-1, 1))
	m.detail.SetContent(m.stepDetail(dw))
	if top {
		m.detail.GotoTop()
	}
	m.scrollList()
}

// refreshReview renders the review into its viewport.
func (m *StepsModel) refreshReview(top bool) {
	_, _, bh := paneDims(m.width, m.height)
	m.revVP.SetWidth(m.width)
	m.revVP.SetHeight(max(bh-1, 1))
	m.revVP.SetContent(m.reviewContent(m.width))
	if top {
		m.revVP.GotoTop()
	}
}

// scrollView scrolls a viewport by a key.
func scrollView(v *viewport.Model, k string) {
	switch k {
	case "up", "k":
		v.ScrollUp(1)
	case "down", "j":
		v.ScrollDown(1)
	case "pgup", "ctrl+u":
		v.PageUp()
	case "pgdown", "ctrl+d", "space":
		v.PageDown()
	case "home", "g":
		v.GotoTop()
	case "end", "G":
		v.GotoBottom()
	}
}

// Choice returns what the reader decided: Apply is false unless the review
// was confirmed.
func (m StepsModel) Choice() Choice { return m.choice }

// Selected returns the selected step ids in plan order, for tests.
func (m StepsModel) Selected() []string { return slices.Clone(m.selectedIDs()) }
