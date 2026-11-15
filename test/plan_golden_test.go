package test

import (
	"bytes"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/Shironex/stackward/internal/facts"
	"github.com/Shironex/stackward/internal/plan"
	"github.com/Shironex/stackward/internal/schemacheck"
)

// Every fixture named plan-* also has golden plan outputs next to its
// expected.json: plan.json (the plan.v1 document), plan.txt (the summary)
// and plan.sh (--emit-script). Regenerate with go test ./test/ -update.

func TestGoldenPlans(t *testing.T) {
	schema, err := os.ReadFile(filepath.Join("..", "schema", "plan.v1.json"))
	if err != nil {
		t.Fatal(err)
	}
	dirs, _ := filepath.Glob(filepath.Join("fixtures", "plan-*"))
	if len(dirs) == 0 {
		t.Fatal("no plan fixtures found: the golden test would pass vacuously")
	}
	for _, dir := range dirs {
		t.Run(filepath.Base(dir), func(t *testing.T) {
			p := goldenPlan(t, filepath.Join(dir, "facts.json"))
			if err := p.Validate(); err != nil {
				t.Errorf("plan breaks an invariant: %v", err)
			}
			outputs := map[string]func(*bytes.Buffer) error{
				"plan.json": func(b *bytes.Buffer) error { return plan.WriteJSON(b, p) },
				"plan.txt":  func(b *bytes.Buffer) error { return plan.WriteText(b, p) },
				"plan.sh":   func(b *bytes.Buffer) error { return plan.WriteScript(b, p) },
			}
			for name, write := range outputs {
				var buf bytes.Buffer
				if err := write(&buf); err != nil {
					t.Fatal(err)
				}
				if name == "plan.json" {
					for _, e := range schemacheck.Validate(schema, buf.Bytes()) {
						t.Errorf("plan does not match schema: %v", e)
					}
				}
				compareGolden(t, filepath.Join(dir, name), buf.Bytes())
			}
		})
	}
}

// TestGoldenPlanScriptsParse runs sh -n (parse only, nothing executes) on
// every golden script.
func TestGoldenPlanScriptsParse(t *testing.T) {
	sh, err := exec.LookPath("sh")
	if err != nil {
		t.Skip("no sh on this machine")
	}
	scripts, _ := filepath.Glob(filepath.Join("fixtures", "plan-*", "plan.sh"))
	for _, s := range scripts {
		if out, err := exec.Command(sh, "-n", s).CombinedOutput(); err != nil {
			t.Errorf("%s does not parse: %v\n%s", s, err, out)
		}
	}
}

// TestGoldenPlanMatchesScript checks that the script follows the plan step
// for step: one function per step in plan order, every command, every
// written file and every precondition hash.
func TestGoldenPlanMatchesScript(t *testing.T) {
	dirs, _ := filepath.Glob(filepath.Join("fixtures", "plan-*"))
	for _, dir := range dirs {
		var p plan.Plan
		b, err := os.ReadFile(filepath.Join(dir, "plan.json"))
		if err != nil {
			t.Fatal(err)
		}
		if err := json.Unmarshal(b, &p); err != nil {
			t.Fatal(err)
		}
		sb, err := os.ReadFile(filepath.Join(dir, "plan.sh"))
		if err != nil {
			t.Fatal(err)
		}
		script := string(sb)
		last := 0
		for _, s := range p.Steps {
			fn := "step_" + strings.ReplaceAll(s.ID, "-", "_") + "() {"
			at := strings.Index(script, fn)
			if at < last {
				t.Errorf("%s: %s missing or out of order in plan.sh", dir, fn)
				continue
			}
			last = at
			body := script[at+len(fn):]
			if next := strings.Index(body, "() {\n"); next >= 0 {
				body = body[:next]
			}
			for _, e := range s.Edits {
				if !strings.Contains(body, e.New) {
					t.Errorf("%s: step %s does not write the planned content of %s", dir, s.ID, e.Path)
				}
				if len(e.Validate) > 0 && !strings.Contains(body, strings.Join(e.Validate, " ")) {
					t.Errorf("%s: step %s does not validate %s", dir, s.ID, e.Path)
				}
				if e.Action == plan.Replace && !strings.Contains(body, e.OldSHA256) {
					t.Errorf("%s: step %s does not check the old hash of %s", dir, s.ID, e.Path)
				}
			}
			for _, c := range s.Commands {
				if !strings.Contains(body, strings.Join(c.Args, " ")) {
					t.Errorf("%s: step %s does not run %v", dir, s.ID, c.Args)
				}
			}
		}
	}
}

func goldenPlan(t *testing.T, factsPath string) *plan.Plan {
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
	rep := evaluate(t, factsPath)
	return plan.Build(plan.Input{Facts: f, Results: plan.ResultsFromReport(rep)}, rep, plan.Options{
		Version: "test", Sandbox: goldenOptions.Sandbox, SourceKind: plan.FromFacts,
	})
}

func compareGolden(t *testing.T, path string, got []byte) {
	t.Helper()
	if *update {
		if err := os.WriteFile(path, got, 0o644); err != nil {
			t.Fatal(err)
		}
		return
	}
	want, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("%v (run: go test ./test/ -update)", err)
	}
	if !bytes.Equal(got, want) {
		t.Errorf("output differs from %s (rerun with -update and review the diff)\n--- got\n%s", path, got)
	}
}
