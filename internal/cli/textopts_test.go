package cli

import (
	"bytes"
	"os"
	"strings"
	"testing"

	"github.com/Shironex/stackward/internal/report"
)

func TestTextOptionsOffATerminal(t *testing.T) {
	t.Setenv("COLUMNS", "")
	var buf bytes.Buffer
	if o := textOptions(&buf, false, false); o.Fancy || o.Color || o.Width != report.DefaultTextWidth {
		t.Errorf("pipe: %+v", o)
	}
	t.Setenv("COLUMNS", "72")
	if o := textOptions(&buf, false, false); o.Width != 72 {
		t.Errorf("COLUMNS not honoured: %+v", o)
	}
	if o := textOptions(&buf, true, false); o.Width != report.DefaultTextWidth {
		t.Errorf("an --out file must not take the window width: %+v", o)
	}
	t.Setenv("COLUMNS", "wide")
	if o := textOptions(&buf, false, false); o.Width != report.DefaultTextWidth {
		t.Errorf("bad COLUMNS: %+v", o)
	}
	// A regular file is never a terminal, even as stdout.
	f, err := os.CreateTemp(t.TempDir(), "out")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = f.Close() }()
	if o := textOptions(f, false, false); o.Fancy || o.Color {
		t.Errorf("regular file: %+v", o)
	}
}

func TestAuditTextLayoutFlags(t *testing.T) {
	t.Setenv("COLUMNS", "")
	base := []string{"audit", "--no-sandbox", "--facts", fixture("showcase-coolify-tunnel")}
	_, byLevel, _ := run(base...)
	_, grouped, _ := run(append(base, "--group")...)
	_, info, _ := run(append(base, "--info")...)
	_, plain, _ := run(append(base, "--plain")...)
	if !strings.Contains(byLevel, "-- FAIL (4) --") || strings.Contains(byLevel, "-- NET  Firewall and exposure") {
		t.Errorf("default layout is not by level:\n%s", byLevel)
	}
	if !strings.Contains(grouped, "-- NET  Firewall and exposure") || strings.Contains(grouped, "-- FAIL (4) --") {
		t.Errorf("--group layout is not by group:\n%s", grouped)
	}
	if !strings.Contains(byLevel, "(7 results)") || strings.Contains(info, "(7 results)") {
		t.Error("--info must list NET-004 in full")
	}
	if plain != byLevel {
		t.Error("--plain must match the pipe output")
	}
	if code, _, errs := run("probe", "-h"); code != report.ExitOK || !strings.Contains(errs, "-plain") {
		t.Errorf("probe has no --plain flag: %s", errs)
	}
}
