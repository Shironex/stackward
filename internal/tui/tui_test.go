package tui

import (
	"bytes"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	tea "charm.land/bubbletea/v2"
	"github.com/charmbracelet/colorprofile"
	"github.com/charmbracelet/x/ansi"
	"github.com/charmbracelet/x/exp/golden"
	"github.com/charmbracelet/x/exp/teatest/v2"

	"github.com/Shironex/stackward/internal/checks"
	"github.com/Shironex/stackward/internal/report"
)

// The screens are compared as plain text (styling stripped) at a fixed
// size; run "go test ./internal/tui/ -update" to rewrite the golden files
// after an intended change, then read every one of them.

func fixtureReport(t *testing.T, name string) *report.Report {
	t.Helper()
	fh, err := os.Open(filepath.Join("..", "..", "test", "fixtures", name, "expected.json"))
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = fh.Close() }()
	rep, err := LoadReport(fh)
	if err != nil {
		t.Fatal(err)
	}
	return rep
}

// key turns a key name into the message the terminal would send.
func key(k string) tea.KeyPressMsg {
	switch k {
	case "tab":
		return tea.KeyPressMsg{Code: tea.KeyTab}
	case "enter":
		return tea.KeyPressMsg{Code: tea.KeyEnter}
	case "esc":
		return tea.KeyPressMsg{Code: tea.KeyEscape}
	case "down":
		return tea.KeyPressMsg{Code: tea.KeyDown}
	case "up":
		return tea.KeyPressMsg{Code: tea.KeyUp}
	case "ctrl+c":
		return tea.KeyPressMsg{Code: 'c', Mod: tea.ModCtrl}
	case "pgdown":
		return tea.KeyPressMsg{Code: tea.KeyPgDown}
	}
	r := []rune(k)[0]
	return tea.KeyPressMsg{Code: r, Text: k}
}

// drive runs the model in a test program at w x h, presses keys, quits and
// returns the final model.
func drive(t *testing.T, rep *report.Report, o Options, w, h int, keys ...string) Model {
	t.Helper()
	m, err := New(rep, o)
	if err != nil {
		t.Fatal(err)
	}
	tm := teatest.NewTestModel(t, m, teatest.WithInitialTermSize(w, h))
	for _, k := range keys {
		tm.Send(key(k))
	}
	tm.Send(key("ctrl+c")) // quits from every mode, the filter input too
	fm, ok := tm.FinalModel(t, teatest.WithFinalTimeout(5*time.Second)).(Model)
	if !ok {
		t.Fatal("final model is not a tui.Model")
	}
	return fm
}

// recount refreshes the summary and coverage after a test trimmed results.
func recount(r *report.Report) {
	r.Summary = report.Summary{}
	r.Coverage.Results, r.Coverage.Checked, r.Coverage.Unknown, r.Coverage.Skipped = len(r.Results), 0, 0, 0
	for _, it := range r.Results {
		switch it.Level {
		case checks.Pass:
			r.Summary.Pass++
			r.Coverage.Checked++
		case checks.Skip:
			r.Summary.Skip++
			r.Coverage.Skipped++
		}
	}
}

func screen(m Model) string { return ansi.Strip(m.render()) + "\n" }

func TestScreens(t *testing.T) {
	passOnly := fixtureReport(t, "ubuntu-2404-clean")
	var kept []report.Item
	for _, it := range passOnly.Results {
		if it.Level == checks.Pass || it.Level == checks.Skip {
			kept = append(kept, it)
		}
	}
	passOnly.Results = kept
	recount(passOnly)

	empty := fixtureReport(t, "ubuntu-2404-clean")
	empty.Results = nil
	recount(empty)

	cases := []struct {
		name string
		rep  *report.Report
		w, h int
		keys []string
	}{
		{"main", fixtureReport(t, "paas-coolify-panel-root"), 80, 24, nil},
		{"detail_scrolled", fixtureReport(t, "paas-coolify-panel-root"), 80, 24, []string{"j", "tab", "pgdown"}},
		{"level_fail", fixtureReport(t, "paas-coolify-panel-root"), 80, 24, []string{"l"}},
		{"group_jump_passing", fixtureReport(t, "paas-coolify-panel-root"), 80, 24, []string{"a", "g", "g"}},
		{"filter", fixtureReport(t, "paas-coolify-panel-root"), 80, 24, []string{"/", "e", "x", "p", "o", "enter"}},
		{"filter_editing", fixtureReport(t, "paas-coolify-panel-root"), 80, 24, []string{"/", "s", "s", "h"}},
		{"filter_no_match", fixtureReport(t, "paas-coolify-panel-root"), 80, 24, []string{"/", "z", "z", "z", "enter"}},
		{"help", fixtureReport(t, "paas-coolify-panel-root"), 80, 24, []string{"?"}},
		{"nonroot_all_unknown", fixtureReport(t, "usr-nonroot"), 80, 24, nil},
		{"all_passing_hidden", passOnly, 80, 24, nil},
		{"no_results", empty, 80, 24, nil},
		{"wide", fixtureReport(t, "dkr-shared-db-socket"), 120, 32, nil},
		{"too_small", fixtureReport(t, "paas-coolify-panel-root"), 50, 12, nil},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			m := drive(t, tc.rep, Options{Source: "report expected.json"}, tc.w, tc.h, tc.keys...)
			out := screen(m)
			lines := strings.Split(strings.TrimSuffix(out, "\n"), "\n")
			if len(lines) != tc.h {
				t.Errorf("screen has %d lines, want %d", len(lines), tc.h)
			}
			for i, l := range lines {
				if n := ansi.StringWidth(l); n > tc.w {
					t.Errorf("line %d is %d cells wide, more than %d: %q", i+1, n, tc.w, l)
				}
			}
			golden.RequireEqual(t, out)
		})
	}
}

func TestResizeKeepsSelection(t *testing.T) {
	rep := fixtureReport(t, "paas-coolify-panel-root")
	m, err := New(rep, Options{})
	if err != nil {
		t.Fatal(err)
	}
	var tm tea.Model = m
	tm, _ = tm.Update(tea.WindowSizeMsg{Width: 80, Height: 24})
	for range 12 {
		tm, _ = tm.Update(key("j"))
	}
	id, subj := tm.(Model).Selected()
	tm, _ = tm.Update(tea.WindowSizeMsg{Width: 100, Height: 18})
	if gid, gsubj := tm.(Model).Selected(); gid != id || gsubj != subj {
		t.Errorf("selection moved on resize: %s %s, want %s %s", gid, gsubj, id, subj)
	}
	out := ansi.Strip(tm.(Model).render())
	if !strings.Contains(out, id) {
		t.Errorf("selected row %s scrolled out of view after resize:\n%s", id, out)
	}
}

func TestWorstFirst(t *testing.T) {
	rep := fixtureReport(t, "paas-coolify-panel-root")
	m, err := New(rep, Options{})
	if err != nil {
		t.Fatal(err)
	}
	if id, _ := m.Selected(); id == "" || m.items[0].Level != checks.Fail {
		t.Fatalf("first result is %s (%s), want a fail", id, m.items[0].Level)
	}
	// Within a group, levels never get better and then worse again.
	for i := 1; i < len(m.items); i++ {
		a, b := m.items[i-1], m.items[i]
		if a.Group == b.Group && levelRank(a.Level) > levelRank(b.Level) {
			t.Errorf("%s %s sorted before %s %s", a.ID, a.Level, b.ID, b.Level)
		}
	}
}

func TestLevelCycle(t *testing.T) {
	var seen []checks.Level
	l := checks.Level("")
	for range 6 {
		l = nextLevel(l, false, false)
		seen = append(seen, l)
	}
	want := []checks.Level{checks.Fail, checks.Warn, checks.Unknown, checks.Info, "", checks.Fail}
	for i := range want {
		if seen[i] != want[i] {
			t.Fatalf("cycle %v, want %v", seen, want)
		}
	}
	if nextLevel(checks.Info, true, false) != checks.Pass {
		t.Error("with passing shown, the cycle must reach pass")
	}
	if nextLevel(checks.Info, false, true) != accepted || nextLevel(accepted, true, true) != checks.Pass {
		t.Error("with accepted results, the cycle must reach accepted after info")
	}
	rep := fixtureReport(t, "paas-coolify-panel-root")
	fm := drive(t, rep, Options{}, 80, 24, "a", "l", "l", "l", "l", "l", "a")
	if fm.Level() != "" {
		t.Errorf("hiding passing results while the pass level is active must reset the level, got %q", fm.Level())
	}
}

func TestCopyOnlyOnKey(t *testing.T) {
	rep := fixtureReport(t, "paas-coolify-panel-root")
	m, err := New(rep, Options{})
	if err != nil {
		t.Fatal(err)
	}
	for _, k := range []string{"j", "k", "l", "a", "g", "tab", "?"} {
		var tm tea.Model = m
		_, cmd := tm.Update(key(k))
		if cmd != nil {
			if _, isClip := clipboardText(cmd()); isClip {
				t.Errorf("key %q wrote the clipboard", k)
			}
		}
	}
	_, cmd := m.Update(key("y"))
	if cmd == nil {
		t.Fatal("y returned no command")
	}
	text, ok := clipboardText(cmd())
	if !ok {
		t.Fatalf("y returned %T, want an OSC 52 clipboard write", cmd())
	}
	id, _ := m.Selected()
	if e, _ := m.cat.Lookup(id); text != e.Fix {
		t.Errorf("copied %q, want the catalog fix of %s", text, id)
	}
}

// clipboardText unwraps the message tea.SetClipboard produces (its type
// is unexported).
func clipboardText(msg tea.Msg) (string, bool) {
	if fmt.Sprintf("%T", msg) != "tea.setClipboardMsg" {
		return "", false
	}
	return reflect.ValueOf(msg).String(), true
}

// TestNoColor runs the real program with the color profile NO_COLOR picks
// and checks that no color reaches the terminal while the cursor row stays
// visible (reverse video).
func TestNoColor(t *testing.T) {
	rep := fixtureReport(t, "paas-coolify-panel-root")
	m, err := New(rep, Options{NoColor: true})
	if err != nil {
		t.Fatal(err)
	}
	tm := teatest.NewTestModel(t, m, teatest.WithInitialTermSize(80, 24),
		teatest.WithProgramOptions(tea.WithColorProfile(colorprofile.Ascii)))
	teatest.WaitFor(t, tm.Output(), func(b []byte) bool { return bytes.Contains(b, []byte("FINDINGS")) },
		teatest.WithDuration(5*time.Second))
	tm.Send(key("q"))
	out, err := io.ReadAll(tm.FinalOutput(t, teatest.WithFinalTimeout(5*time.Second)))
	if err != nil {
		t.Fatal(err)
	}
	for _, sgr := range []string{"38;2;", "38;5;", "\x1b[3", "\x1b[9"} {
		if bytes.Contains(out, []byte(sgr)) {
			t.Errorf("NO_COLOR output contains the color sequence %q", sgr)
		}
	}
}

func TestLoadReport(t *testing.T) {
	cases := []struct {
		name, in, err string
	}{
		{"facts file", `{"schema":"stackward.facts.v1"}`, "pass it with --facts"},
		{"no schema", `{"collected_at":"2026-03-01T12:00:00Z"}`, "no schema field"},
		{"other schema", `{"schema":"stackward.report.v9"}`, "unsupported report schema"},
		{"not json", `hello`, "not a report.v1"},
	}
	for _, tc := range cases {
		_, err := LoadReport(strings.NewReader(tc.in))
		if err == nil || !strings.Contains(err.Error(), tc.err) {
			t.Errorf("%s: error %v, want %q", tc.name, err, tc.err)
		}
	}
	// A planted secret in a hand edited report is masked on load.
	secret := "ghp_" + strings.Repeat("A1b2", 9)
	in := `{"schema":"stackward.report.v1","results":[{"id":"SEC-001","level":"fail","message":"token ` + secret +
		`","evidence":{"value":"` + secret + `"}}]}`
	rep, err := LoadReport(strings.NewReader(in))
	if err != nil {
		t.Fatal(err)
	}
	it := rep.Results[0]
	if strings.Contains(it.Message, secret) || strings.Contains(evidenceValue(it.Evidence["value"]), secret) {
		t.Errorf("secret survived loading: %+v", it)
	}
	if it.Group != "SEC" || it.Subject != "host" {
		t.Errorf("defaults not filled: group %q subject %q", it.Group, it.Subject)
	}
}
