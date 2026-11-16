package tui

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/charmbracelet/x/ansi"
	"github.com/charmbracelet/x/exp/golden"

	"github.com/Shironex/stackward/internal/report"
)

// waivedReport is the saved report of the waiver golden scenario: two
// accepted findings, one expired waiver, one stale and one for an unknown
// check.
func waivedReport(t *testing.T) *report.Report {
	t.Helper()
	fh, err := os.Open(filepath.Join("..", "..", "test", "waivers", "usr-accepted", "expected.json"))
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

func TestWaiverScreen(t *testing.T) {
	m := drive(t, waivedReport(t), Options{Source: "report expected.json"}, 100, 30, "l", "l", "l", "l", "l")
	if m.Level() != accepted {
		t.Fatalf("five presses of l must reach the accepted level, got %q", m.Level())
	}
	out := screen(m)
	for _, want := range []string{"3 accepted", "review 5 waivers", "ACCEPTED USR-004", "ACCEPTED USR-005", "ACCEPTED USR-006", "level accepted"} {
		if !strings.Contains(out, want) {
			t.Errorf("missing %q in:\n%s", want, out)
		}
	}
	if strings.Contains(out, "FAIL     USR-004") {
		t.Errorf("the accepted fail is listed as a fail:\n%s", out)
	}
	golden.RequireEqual(t, out)
	for _, w := range []int{60, 80} {
		if l2 := ansi.Strip(strings.Split(screen(drive(t, waivedReport(t), Options{}, w, 24)), "\n")[1]); !strings.Contains(l2, "review 5 waivers") {
			t.Errorf("width %d: the header drops the waivers to review: %q", w, l2)
		}
	}
}

func TestWaiverDetail(t *testing.T) {
	m, err := New(waivedReport(t), Options{})
	if err != nil {
		t.Fatal(err)
	}
	details := map[string]string{}
	for i, r := range m.rows {
		if r.header() {
			continue
		}
		if it := m.items[r.item]; it.Waiver != nil {
			m.cursor = i
			details[it.ID+" "+it.Subject] = ansi.Strip(m.detailContent(80))
		}
	}
	for key, want := range map[string][]string{
		"USR-004 file:/etc/sudoers.d/deploy": {"ACCEPTED · FAIL · high severity", "WAIVER", "accepted until 2026-03-01: the deploy tool"},
		"USR-006 user:carol":                 {"WARN · low severity", "expired after 2026-02-01, the finding is back"},
		"USR-002 user:ubuntu":                {"FAIL · critical severity", "not accepted, the waiver covers up to warn only"},
	} {
		for _, w := range want {
			if !strings.Contains(details[key], w) {
				t.Errorf("%s: missing %q in:\n%s", key, w, details[key])
			}
		}
	}
	// The default list hides nothing a waiver touched.
	shown := map[string]bool{}
	for _, r := range m.rows {
		if !r.header() {
			shown[m.items[r.item].ID+" "+m.items[r.item].Subject] = true
		}
	}
	for _, k := range []string{"USR-004 file:/etc/sudoers.d/deploy", "USR-005 user:alice", "USR-006 user:carol"} {
		if !shown[k] {
			t.Errorf("%s is not in the default list", k)
		}
	}
}
