// Package test holds the golden tests: every directory under fixtures/ is a
// scenario with a facts.json (what the collectors would gather, as written by
// `stackward audit --dump-facts`) and an expected.json (the report). The test
// runs the real pipeline over the facts and compares byte for byte.
//
// After an intended change, regenerate and review the diff:
//
//	go test ./test/ -update
package test

import (
	"bytes"
	"encoding/json"
	"flag"
	"os"
	"path/filepath"
	"testing"

	"github.com/Shironex/stackward/internal/audit"
	"github.com/Shironex/stackward/internal/checks"
	"github.com/Shironex/stackward/internal/facts"
	"github.com/Shironex/stackward/internal/report"
	"github.com/Shironex/stackward/internal/sandbox"
	"github.com/Shironex/stackward/internal/schemacheck"
)

var update = flag.Bool("update", false, "rewrite expected.json files from the current output")

// goldenOptions are fixed so reports do not depend on the machine or build.
var goldenOptions = audit.Options{
	Version: "test",
	Sandbox: sandbox.Status{State: sandbox.Unavailable, Reason: "golden test"},
}

func TestGolden(t *testing.T) {
	schema, err := os.ReadFile(filepath.Join("..", "schema", "report.v1.json"))
	if err != nil {
		t.Fatal(err)
	}
	dirs, err := filepath.Glob(filepath.Join("fixtures", "*", "facts.json"))
	if err != nil {
		t.Fatal(err)
	}
	if len(dirs) == 0 {
		t.Fatal("no fixtures found: the golden test would pass vacuously")
	}
	for _, factsPath := range dirs {
		dir := filepath.Dir(factsPath)
		t.Run(filepath.Base(dir), func(t *testing.T) {
			got := render(t, factsPath)
			for _, e := range schemacheck.Validate(schema, got) {
				t.Errorf("report does not match schema: %v", e)
			}
			expPath := filepath.Join(dir, "expected.json")
			if *update {
				if err := os.WriteFile(expPath, got, 0o644); err != nil {
					t.Fatal(err)
				}
				return
			}
			want, err := os.ReadFile(expPath)
			if err != nil {
				t.Fatalf("%v (run: go test ./test/ -update)", err)
			}
			if !bytes.Equal(got, want) {
				t.Errorf("report differs from %s (rerun with -update and review the diff)\n--- got\n%s", expPath, got)
			}
		})
	}
}

// markdownFixtures have a Markdown golden (expected.md) next to expected.json.
// "all" lists passing and skipped results too, like --all.
var markdownFixtures = map[string]bool{
	"net-firewall-off-public": false,
	"ssh-nonroot-partial":     false,
	"usr-bad":                 true,
}

func TestGoldenMarkdown(t *testing.T) {
	for name, all := range markdownFixtures {
		t.Run(name, func(t *testing.T) {
			dir := filepath.Join("fixtures", name)
			rep := evaluate(t, filepath.Join(dir, "facts.json"))
			var buf bytes.Buffer
			if err := report.WriteMarkdown(&buf, rep, report.MarkdownOptions{Passing: all}); err != nil {
				t.Fatal(err)
			}
			expPath := filepath.Join(dir, "expected.md")
			if *update {
				if err := os.WriteFile(expPath, buf.Bytes(), 0o644); err != nil {
					t.Fatal(err)
				}
				return
			}
			want, err := os.ReadFile(expPath)
			if err != nil {
				t.Fatalf("%v (run: go test ./test/ -update)", err)
			}
			if !bytes.Equal(buf.Bytes(), want) {
				t.Errorf("markdown differs from %s (rerun with -update and review the diff)\n--- got\n%s", expPath, buf.Bytes())
			}
		})
	}
}

// textfileFixtures have a Prometheus textfile golden (expected.prom) next to
// expected.json: the metric names and labels are a public interface.
var textfileFixtures = []string{"net-firewall-off-public", "ssh-nonroot-partial", "ubuntu-2404-clean"}

func TestGoldenTextfile(t *testing.T) {
	for _, name := range textfileFixtures {
		t.Run(name, func(t *testing.T) {
			dir := filepath.Join("fixtures", name)
			rep := evaluate(t, filepath.Join(dir, "facts.json"))
			var buf bytes.Buffer
			if err := report.WriteTextfile(&buf, rep); err != nil {
				t.Fatal(err)
			}
			expPath := filepath.Join(dir, "expected.prom")
			if *update {
				if err := os.WriteFile(expPath, buf.Bytes(), 0o644); err != nil {
					t.Fatal(err)
				}
				return
			}
			want, err := os.ReadFile(expPath)
			if err != nil {
				t.Fatalf("%v (run: go test ./test/ -update)", err)
			}
			if !bytes.Equal(buf.Bytes(), want) {
				t.Errorf("textfile differs from %s (rerun with -update and review the diff)\n--- got\n%s", expPath, buf.Bytes())
			}
		})
	}
}

func evaluate(t *testing.T, factsPath string) *report.Report {
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
	rep, err := audit.Evaluate(f, goldenOptions)
	if err != nil {
		t.Fatal(err)
	}
	return rep
}

func render(t *testing.T, factsPath string) []byte {
	t.Helper()
	rep := evaluate(t, factsPath)
	var buf bytes.Buffer
	if err := report.WriteJSON(&buf, rep); err != nil {
		t.Fatal(err)
	}
	return buf.Bytes()
}

// TestFixturesCoverEveryLevel keeps the scenarios honest: together they must
// exercise pass, warn, fail, unknown and skip at least once.
func TestFixturesCoverEveryLevel(t *testing.T) {
	paths, _ := filepath.Glob(filepath.Join("fixtures", "*", "facts.json"))
	seen := map[checks.Level]bool{}
	for _, p := range paths {
		var rep report.Report
		if err := json.Unmarshal(render(t, p), &rep); err != nil {
			t.Fatal(err)
		}
		for _, r := range rep.Results {
			seen[r.Level] = true
		}
	}
	for _, l := range []checks.Level{checks.Pass, checks.Warn, checks.Fail, checks.Unknown, checks.Skip} {
		if !seen[l] {
			t.Errorf("no fixture produces a %s result", l)
		}
	}
}
