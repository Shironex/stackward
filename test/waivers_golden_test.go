package test

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"

	"github.com/Shironex/stackward/internal/audit"
	"github.com/Shironex/stackward/internal/facts"
	"github.com/Shironex/stackward/internal/report"
	"github.com/Shironex/stackward/internal/schemacheck"
	"github.com/Shironex/stackward/internal/waiver"
)

// TestGoldenWaivers runs each scenario under waivers/ (facts.json plus a
// waivers.yml) through the pipeline and compares the JSON, Markdown and
// plain text reports with expected.json, expected.md and expected.txt. The
// scenarios live outside fixtures/ because TestGolden renders every
// fixture without waivers.
func TestGoldenWaivers(t *testing.T) {
	schema, err := os.ReadFile(filepath.Join("..", "schema", "report.v1.json"))
	if err != nil {
		t.Fatal(err)
	}
	dirs, err := filepath.Glob(filepath.Join("waivers", "*", "waivers.yml"))
	if err != nil || len(dirs) == 0 {
		t.Fatalf("no waiver scenarios found (%v)", err)
	}
	for _, wp := range dirs {
		dir := filepath.Dir(wp)
		t.Run(filepath.Base(dir), func(t *testing.T) {
			fh, err := os.Open(wp)
			if err != nil {
				t.Fatal(err)
			}
			ws, err := waiver.Load(fh)
			_ = fh.Close()
			if err != nil {
				t.Fatal(err)
			}
			o := goldenOptions
			o.Waivers = ws
			rep := evaluateWith(t, filepath.Join(dir, "facts.json"), o)
			outputs := map[string]func(*bytes.Buffer) error{
				"expected.json": func(b *bytes.Buffer) error { return report.WriteJSON(b, rep) },
				"expected.md":   func(b *bytes.Buffer) error { return report.WriteMarkdown(b, rep, report.MarkdownOptions{}) },
				"expected.txt":  func(b *bytes.Buffer) error { return report.WriteText(b, rep, report.TextOptions{}) },
			}
			for name, write := range outputs {
				var buf bytes.Buffer
				if err := write(&buf); err != nil {
					t.Fatal(err)
				}
				if name == "expected.json" {
					for _, e := range schemacheck.Validate(schema, buf.Bytes()) {
						t.Errorf("report does not match schema: %v", e)
					}
				}
				compareGolden(t, filepath.Join(dir, name), buf.Bytes())
			}
		})
	}
}

func evaluateWith(t *testing.T, factsPath string, o audit.Options) *report.Report {
	t.Helper()
	fh, err := os.Open(factsPath)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = fh.Close() }()
	f, err := facts.Load(fh)
	if err != nil {
		t.Fatal(err)
	}
	rep, err := audit.Evaluate(f, o)
	if err != nil {
		t.Fatal(err)
	}
	return rep
}
