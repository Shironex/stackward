package probe

import (
	"bytes"
	"encoding/json"
	"flag"
	"os"
	"path/filepath"
	"testing"

	"github.com/Shironex/stackward/internal/profile"
	"github.com/Shironex/stackward/internal/report"
	"github.com/Shironex/stackward/internal/sandbox"
	"github.com/Shironex/stackward/internal/schemacheck"
)

var update = flag.Bool("update", false, "rewrite testdata expected files from the current output")

// goldenProfiles is the --profile of each scenario under testdata; a
// missing entry means auto.
var goldenProfiles = map[string]profile.Name{
	"tunnel-origin-bypass": profile.Tunnel,
	"public-web-clean":     profile.PublicWeb,
}

// TestGolden evaluates every testdata/<scenario>/facts.json and compares
// the JSON and text reports byte for byte (go test ./internal/probe -update
// rewrites them; review the diff).
func TestGolden(t *testing.T) {
	schema, err := os.ReadFile(filepath.Join("..", "..", "schema", "report.v1.json"))
	if err != nil {
		t.Fatal(err)
	}
	paths, _ := filepath.Glob(filepath.Join("testdata", "*", "facts.json"))
	if len(paths) == 0 {
		t.Fatal("no probe scenarios")
	}
	for _, p := range paths {
		dir := filepath.Dir(p)
		name := filepath.Base(dir)
		t.Run(name, func(t *testing.T) {
			raw, err := os.ReadFile(p)
			if err != nil {
				t.Fatal(err)
			}
			var f Facts
			dec := json.NewDecoder(bytes.NewReader(raw))
			dec.DisallowUnknownFields()
			if err := dec.Decode(&f); err != nil {
				t.Fatal(err)
			}
			prof, set := goldenProfiles[name]
			rep, err := Evaluate(&f, EvalOptions{
				Version: "test", Sandbox: sandbox.Status{State: sandbox.Unavailable, Reason: "golden test"},
				Profile: prof, ProfileSet: set,
			})
			if err != nil {
				t.Fatal(err)
			}
			var js, txt bytes.Buffer
			if err := report.WriteJSON(&js, rep); err != nil {
				t.Fatal(err)
			}
			if err := report.WriteText(&txt, rep, report.TextOptions{Passing: true}); err != nil {
				t.Fatal(err)
			}
			for _, e := range schemacheck.Validate(schema, js.Bytes()) {
				t.Errorf("schema: %v", e)
			}
			compare(t, filepath.Join(dir, "expected.json"), js.Bytes())
			compare(t, filepath.Join(dir, "expected.txt"), txt.Bytes())
		})
	}
}

func compare(t *testing.T, path string, got []byte) {
	t.Helper()
	if *update {
		if err := os.WriteFile(path, got, 0o644); err != nil {
			t.Fatal(err)
		}
		return
	}
	want, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("%v (run: go test ./internal/probe -update)", err)
	}
	if !bytes.Equal(got, want) {
		t.Errorf("%s differs (rerun with -update and review)\n--- got\n%s", path, got)
	}
}
