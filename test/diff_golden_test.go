package test

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"

	"github.com/Shironex/stackward/internal/diff"
	"github.com/Shironex/stackward/internal/report"
	"github.com/Shironex/stackward/internal/schemacheck"
)

// TestGoldenDiff compares each scenario under diff/ (old.json and
// new.json, two report.v1 files) and checks the JSON, Markdown and text
// diff against expected.json, expected.md and expected.txt. There is one
// scenario per drift kind (listener, authorized-key, sudoer,
// root-container) and one for changes of waiver state.
func TestGoldenDiff(t *testing.T) {
	schema, err := os.ReadFile(filepath.Join("..", "schema", "diff.v1.json"))
	if err != nil {
		t.Fatal(err)
	}
	dirs, err := filepath.Glob(filepath.Join("diff", "*", "old.json"))
	if err != nil || len(dirs) == 0 {
		t.Fatalf("no diff scenarios found (%v)", err)
	}
	for _, p := range dirs {
		dir := filepath.Dir(p)
		t.Run(filepath.Base(dir), func(t *testing.T) {
			d, err := diff.Compare(loadDiffReport(t, filepath.Join(dir, "old.json")), loadDiffReport(t, filepath.Join(dir, "new.json")), diff.Options{Version: "test"})
			if err != nil {
				t.Fatal(err)
			}
			outputs := map[string]func(*bytes.Buffer) error{
				"expected.json": func(b *bytes.Buffer) error { return diff.WriteJSON(b, d) },
				"expected.md":   func(b *bytes.Buffer) error { return diff.WriteMarkdown(b, d) },
				"expected.txt":  func(b *bytes.Buffer) error { return diff.WriteText(b, d) },
			}
			for name, write := range outputs {
				var buf bytes.Buffer
				if err := write(&buf); err != nil {
					t.Fatal(err)
				}
				if name == "expected.json" {
					for _, e := range schemacheck.Validate(schema, buf.Bytes()) {
						t.Errorf("diff does not match schema: %v", e)
					}
				}
				compareGolden(t, filepath.Join(dir, name), buf.Bytes())
			}
		})
	}
}

func loadDiffReport(t *testing.T, path string) *report.Report {
	t.Helper()
	fh, err := os.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = fh.Close() }()
	rep, err := diff.LoadReport(fh)
	if err != nil {
		t.Fatalf("%s: %v", path, err)
	}
	return rep
}
