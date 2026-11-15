package tui

import (
	"fmt"
	"strings"
	"testing"

	"github.com/charmbracelet/x/ansi"
	"github.com/charmbracelet/x/exp/golden"

	"github.com/Shironex/stackward/internal/report"
)

// detailOf returns the detail text of the socket proxy warning, rendered the
// way the pane shows it.
func detailOf(t *testing.T, rep *report.Report, w int) string {
	t.Helper()
	m, err := New(rep, Options{})
	if err != nil {
		t.Fatal(err)
	}
	for i, r := range m.rows {
		if !r.header() && m.items[r.item].ID == socketProxyID && m.items[r.item].Subject == socketProxySubject {
			m.cursor = i
			return ansi.Strip(m.detailContent(w))
		}
	}
	t.Fatalf("%s %s is not in the list", socketProxyID, socketProxySubject)
	return ""
}

// The DKR-010 warning of the socket proxy has an empty managed_by in its
// evidence.
const (
	socketProxyID      = "DKR-010"
	socketProxySubject = "container:socket-proxy"
)

func TestRootSectionFollowsTheRun(t *testing.T) {
	rootRun := fixtureReport(t, "dkr-shared-db-socket")
	rootRun.Coverage.Root = true
	got := detailOf(t, rootRun, 60)
	if strings.Contains(got, "needs sudo") {
		t.Errorf("a root run still tells the user to use sudo:\n%s", got)
	}
	if !strings.Contains(got, "ROOT") || !strings.Contains(got, "this run had it") {
		t.Errorf("a root run does not say it had root:\n%s", got)
	}

	plain := fixtureReport(t, "dkr-shared-db-socket")
	plain.Coverage.Root = false
	if got := detailOf(t, plain, 60); !strings.Contains(got, "The full result needs sudo.") {
		t.Errorf("a run without root lost the sudo advice:\n%s", got)
	}
}

func TestEmptyEvidenceValuesAreHidden(t *testing.T) {
	rep := fixtureReport(t, "dkr-shared-db-socket")
	got := detailOf(t, rep, 60)
	if strings.Contains(got, `""`) || strings.Contains(got, "managed_by") {
		t.Errorf("an empty evidence value is printed:\n%s", got)
	}
	for _, want := range []string{"role", "socket-proxy", "image"} {
		if !strings.Contains(got, want) {
			t.Errorf("evidence lost %q:\n%s", want, got)
		}
	}

	// All values empty: no EVIDENCE heading either.
	for i := range rep.Results {
		if it := &rep.Results[i]; it.ID == socketProxyID && it.Subject == socketProxySubject {
			it.Evidence = map[string]any{"role": "", "managed_by": ""}
		}
	}
	if got := detailOf(t, rep, 60); strings.Contains(got, "EVIDENCE") {
		t.Errorf("an evidence section with nothing in it:\n%s", got)
	}
}

func TestRowSaysWhatWasFound(t *testing.T) {
	rep := fixtureReport(t, "dkr-shared-db-socket")
	m, err := New(rep, Options{})
	if err != nil {
		t.Fatal(err)
	}
	for _, r := range m.rows {
		if r.header() {
			continue
		}
		it := m.items[r.item]
		if it.Message == "" {
			continue
		}
		line := ansi.Strip(m.rowLine(r, false, 8, 200))
		if strings.Contains(line, it.Title) && !strings.Contains(it.Message, it.Title) {
			t.Errorf("row of %s %s shows the check title next to %s:\n%s", it.ID, it.Subject, it.Level, line)
		}
		if !strings.Contains(line, it.Message) {
			t.Errorf("row of %s %s does not show the result message:\n%s", it.ID, it.Subject, line)
		}
	}
	if got := detailOf(t, rep, 70); !strings.Contains(got, "rule No container mounts the Docker socket") {
		t.Errorf("the detail pane does not mark the title as the rule:\n%s", got)
	}
}

// The header is checked as its three lines at the widths a terminal
// commonly has; the source label on the right must be whole or absent.
func TestHeaderAtWidths(t *testing.T) {
	for _, w := range []int{80, 120, 200} {
		rep := fixtureReport(t, "dkr-shared-db-socket")
		rep.Host.OS = "Debian GNU/Linux 13 (trixie) on a long distribution name"
		m := drive(t, rep, Options{Source: "live audit"}, w, 24)
		lines := m.header()
		for i, l := range lines {
			lines[i] = ansi.Strip(fit(l, w))
			if n := ansi.StringWidth(lines[i]); n != w {
				t.Errorf("width %d: header line %d is %d cells", w, i+1, n)
			}
		}
		if w >= 120 && !strings.Contains(lines[0], "live audit") {
			t.Errorf("width %d: the source label is missing: %q", w, lines[0])
		}
		if strings.Contains(lines[0], "live aud") && !strings.Contains(lines[0], "live audit") {
			t.Errorf("width %d: the source label is cut: %q", w, lines[0])
		}
		t.Run(fmt.Sprintf("w%d", w), func(t *testing.T) {
			golden.RequireEqual(t, strings.Join(lines, "\n")+"\n")
		})
	}
}

func TestRowDropsSubjectTheMessageNames(t *testing.T) {
	rep := fixtureReport(t, "dkr-shared-db-socket")
	m, err := New(rep, Options{})
	if err != nil {
		t.Fatal(err)
	}
	var named, unnamed int
	for _, r := range m.rows {
		if r.header() {
			continue
		}
		it := m.items[r.item]
		subj := report.ShortSubject(it.Subject)
		line := ansi.Strip(m.rowLine(r, false, 8, 200))
		switch {
		case subj != "" && report.NamesSubject(it.Message, subj):
			named++
			if strings.Contains(line, subj+" · ") {
				t.Errorf("row of %s %s repeats the subject the message starts with:\n%s", it.ID, it.Subject, line)
			}
		case subj != "" && it.Message != "":
			unnamed++
			if !strings.Contains(line, subj+" · ") {
				t.Errorf("row of %s %s lost a subject the message does not name:\n%s", it.ID, it.Subject, line)
			}
		}
	}
	if named == 0 || unnamed == 0 {
		t.Fatalf("fixture covers %d rows that name the subject and %d that do not, want both", named, unnamed)
	}
}
