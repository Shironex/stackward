package report

import (
	"bytes"
	"strings"
	"testing"

	"github.com/Shironex/stackward/internal/checks"
)

// unescapedPipes counts the pipes GFM reads as cell borders: those not
// preceded by an odd run of backslashes.
func unescapedPipes(line string) int {
	n, slashes := 0, 0
	for _, c := range line {
		switch {
		case c == '\\':
			slashes++
			continue
		case c == '|' && slashes%2 == 0:
			n++
		}
		slashes = 0
	}
	return n
}

func TestFleetMarkdownTableCellsHoldHostPipes(t *testing.T) {
	probe := `S4 \| [click](https://e.example/s4) <img src=https://e.example/t.gif> https://e.example/auto \|`
	rep := &Report{Schema: SchemaID, Tool: Tool{Name: "stackward", Version: "1.0.0"}}
	for _, l := range []checks.Level{checks.Info, checks.Unknown, checks.Pass} {
		rep.Results = append(rep.Results, Item{
			ID: "SYS-002", Group: "SYS", Title: "No reboot pending", Level: l,
			Subject: probe, Message: "R " + probe,
		})
	}
	rep.Results = append(rep.Results, Item{ID: "SYS-001", Group: "SYS", Title: "Empty subject", Level: checks.Info})
	rep.Recount()
	f := NewFleet("1.0.0", "2026-01-01T00:00:00Z", []FleetHost{{Host: "web1", Status: FleetAudited, Report: rep}})
	var b bytes.Buffer
	if err := WriteFleetMarkdown(&b, f, MarkdownOptions{Passing: true}); err != nil {
		t.Fatal(err)
	}
	rows, empty := 0, false
	for _, line := range strings.Split(b.String(), "\n") {
		if strings.HasPrefix(line, "| [SYS-001]") {
			empty = true
			if !strings.Contains(line, " | Empty subject | - | ") {
				t.Errorf("an empty untrusted subject must render as -: %s", line)
			}
		}
		if strings.HasPrefix(line, "| [SYS-002]") {
			rows++
			if n := unescapedPipes(line); n != 5 {
				t.Errorf("compact row has %d cell borders, want 5: %s", n, line)
			}
		}
		if strings.HasPrefix(line, "| `web1`") {
			if n := unescapedPipes(line); n != 7 {
				t.Errorf("host row has %d cell borders, want 7: %s", n, line)
			}
		}
	}
	if !empty {
		t.Error("no row for the empty subject")
	}
	if rows != 3 {
		t.Fatalf("%d compact rows, want 3:\n%s", rows, b.String())
	}
	// A local report keeps the escaped pipe it always had.
	var local bytes.Buffer
	if err := WriteMarkdown(&local, rep, MarkdownOptions{Passing: true}); err != nil {
		t.Fatal(err)
	}
	if strings.Contains(local.String(), "∣") {
		t.Error("a local report must not change")
	}
}
