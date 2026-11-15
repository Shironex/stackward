package test

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/charmbracelet/x/ansi"

	"github.com/Shironex/stackward/internal/probe"
	"github.com/Shironex/stackward/internal/profile"
	"github.com/Shironex/stackward/internal/report"
	"github.com/Shironex/stackward/internal/sandbox"
)

// textGoldens are the text report goldens of the showcase fixture: fails,
// warnings, unknowns and many NET-004 info results. The terminal form (Fancy
// and Color) is checked at 80 and 120 columns, plain output (a pipe) at the
// default width, and the group layout and --all once each.
var textGoldens = map[string]report.TextOptions{
	"expected-80.txt":    {Fancy: true, Color: true, Width: 80},
	"expected-120.txt":   {Fancy: true, Color: true, Width: 120},
	"expected-plain.txt": {},
	"expected-group.txt": {Group: true},
	"expected-all.txt":   {Passing: true},
}

const textFixture = "showcase-coolify-tunnel"

func TestGoldenText(t *testing.T) {
	dir := filepath.Join("fixtures", textFixture)
	rep := evaluate(t, filepath.Join(dir, "facts.json"))
	for name, o := range textGoldens {
		t.Run(name, func(t *testing.T) {
			var buf bytes.Buffer
			if err := report.WriteText(&buf, rep, o); err != nil {
				t.Fatal(err)
			}
			path := filepath.Join(dir, name)
			if *update {
				if err := os.WriteFile(path, buf.Bytes(), 0o644); err != nil {
					t.Fatal(err)
				}
				return
			}
			want, err := os.ReadFile(path)
			if err != nil {
				t.Fatalf("%v (run: go test ./test/ -update)", err)
			}
			if !bytes.Equal(buf.Bytes(), want) {
				t.Errorf("text report differs from %s (rerun with -update and review the diff)\n--- got\n%s", path, buf.Bytes())
			}
		})
	}
}

// TestTextFitsWidth renders the rich audit fixture and a probe report (with
// the self target warning) at several widths, on a terminal and plain, and
// checks that no line is wider than the width: ANSI stripped, every rune
// counted at its display width.
func TestTextFitsWidth(t *testing.T) {
	reports := map[string]*report.Report{
		"audit": evaluate(t, filepath.Join("fixtures", textFixture, "facts.json")),
		"probe": probeReport(t, filepath.Join("..", "internal", "probe", "testdata", "tunnel-origin-bypass", "facts.json")),
	}
	for name, rep := range reports {
		for _, w := range []int{60, 80, 120} {
			for _, tty := range []bool{true, false} {
				for _, o := range []report.TextOptions{{}, {Passing: true}, {Group: true}} {
					o.Width, o.Fancy, o.Color = w, tty, tty
					t.Run(fmt.Sprintf("%s/%d/tty=%v/all=%v/group=%v", name, w, tty, o.Passing, o.Group), func(t *testing.T) {
						var buf bytes.Buffer
						if err := report.WriteText(&buf, rep, o); err != nil {
							t.Fatal(err)
						}
						for i, l := range strings.Split(buf.String(), "\n") {
							if got := ansi.StringWidth(ansi.Strip(l)); got > w {
								t.Errorf("line %d is %d cells wide, over %d: %q", i+1, got, w, ansi.Strip(l))
							}
						}
					})
				}
			}
		}
	}
}

func probeReport(t *testing.T, path string) *report.Report {
	t.Helper()
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var f probe.Facts
	if err := json.Unmarshal(raw, &f); err != nil {
		t.Fatal(err)
	}
	rep, err := probe.Evaluate(&f, probe.EvalOptions{
		Version: "test", Sandbox: sandbox.Status{State: sandbox.Unavailable, Reason: "golden test"},
		Profile: profile.Tunnel, ProfileSet: true,
	})
	if err != nil {
		t.Fatal(err)
	}
	rep.Probe.SelfTarget = true
	return rep
}
