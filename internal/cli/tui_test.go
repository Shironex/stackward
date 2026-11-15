package cli

import (
	"path/filepath"
	"strings"
	"testing"

	"github.com/Shironex/stackward/internal/report"
)

// The browser itself is tested in internal/tui with teatest. These tests
// cover the flags and inputs, which all fail before a terminal is needed
// (test output is never a terminal), so no sandbox is ever applied here.

func savedReport(name string) string {
	return filepath.Join("..", "..", "test", "fixtures", name, "expected.json")
}

func TestTUIInputErrors(t *testing.T) {
	cases := []struct {
		args []string
		want string
	}{
		{[]string{"--report", savedReport("ubuntu-2404-clean"), "--facts", fixture("ubuntu-2404-clean")}, "not both"},
		{[]string{"--report", savedReport("ubuntu-2404-clean"), "--profile", "tunnel"}, "already has one"},
		{[]string{"--report", fixture("ubuntu-2404-clean")}, "pass it with --facts"},
		{[]string{"--report", "does-not-exist.json"}, "does-not-exist.json"},
		{[]string{"--facts", "does-not-exist.json"}, "does-not-exist.json"},
		{[]string{"--profile", "moat"}, "moat"},
		{[]string{"stray"}, "unexpected argument"},
		// Valid inputs still need a terminal to draw on.
		{[]string{"--report", savedReport("ubuntu-2404-clean")}, "needs a terminal"},
		{[]string{"--no-sandbox", "--facts", fixture("ubuntu-2404-clean")}, "needs a terminal"},
	}
	for _, tc := range cases {
		code, out, errs := run(append([]string{"tui"}, tc.args...)...)
		if code != report.ExitError || !strings.Contains(errs, tc.want) {
			t.Errorf("tui %v: exit %d stderr %q, want exit %d and %q", tc.args, code, errs, report.ExitError, tc.want)
		}
		if out != "" {
			t.Errorf("tui %v wrote to stdout: %q", tc.args, out)
		}
	}
}

func TestTUIHelp(t *testing.T) {
	code, _, errs := run("tui", "-h")
	if code != report.ExitOK || !strings.Contains(errs, "-report") || !strings.Contains(errs, "only reads") {
		t.Errorf("tui -h: exit %d %q", code, errs)
	}
	if _, out, _ := run("help"); !strings.Contains(out, "stackward tui") {
		t.Error("usage does not list tui")
	}
}

func TestLoadSavedReport(t *testing.T) {
	rep, err := loadReport(savedReport("paas-coolify-panel-root"))
	if err != nil {
		t.Fatal(err)
	}
	if rep.Schema != report.SchemaID || len(rep.Results) == 0 {
		t.Errorf("loaded %q with %d results", rep.Schema, len(rep.Results))
	}
}
