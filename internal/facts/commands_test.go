package facts

import (
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

// runCallRE finds the command name of every sys.Run call in a collector.
var runCallRE = regexp.MustCompile(`sys\.Run\(ctx, "([a-z0-9-]+)"`)

// TestCommandTableListsEveryCommand keeps the command table in
// docs/safety.md complete: every program a collector starts must be listed
// there with whether it writes, so a command that would fail under the no
// writes sandbox is reviewed before it ships.
func TestCommandTableListsEveryCommand(t *testing.T) {
	doc, err := os.ReadFile(filepath.Join("..", "..", "docs", "safety.md"))
	if err != nil {
		t.Fatal(err)
	}
	_, table, ok := strings.Cut(string(doc), "## Commands stackward runs")
	if !ok {
		t.Fatal("docs/safety.md has no \"Commands stackward runs\" section")
	}
	files, err := filepath.Glob("*.go")
	if err != nil {
		t.Fatal(err)
	}
	seen := map[string]bool{}
	for _, f := range files {
		if strings.HasSuffix(f, "_test.go") {
			continue
		}
		b, err := os.ReadFile(f)
		if err != nil {
			t.Fatal(err)
		}
		for _, m := range runCallRE.FindAllStringSubmatch(string(b), -1) {
			seen[m[1]] = true
		}
	}
	if len(seen) == 0 {
		t.Fatal("found no sys.Run calls; the pattern is stale")
	}
	if seen["ufw"] {
		t.Error("a collector runs ufw, which writes /run/ufw.lock and fails under the sandbox")
	}
	for name := range seen {
		if !strings.Contains(table, "| `"+name) && !strings.Contains(table, ", `"+name) {
			t.Errorf("collectors run %q but docs/safety.md does not list it", name)
		}
	}
}
