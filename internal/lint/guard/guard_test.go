package guard_test

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"golang.org/x/tools/go/analysis/analysistest"

	"github.com/Shironex/stackward/internal/lint/guard"
)

var testAllow = []guard.Entry{
	{Pkg: "allowedfs", Allow: []guard.Category{guard.FSWrite}, Why: "test"},
	{Pkg: "onefile", Files: []string{"ok.go"}, Allow: []guard.Category{guard.Exec}, Why: "test"},
}

func TestForbiddenAndAllowed(t *testing.T) {
	a := guard.New(testAllow)
	analysistest.Run(t, analysistest.TestData(), a, "forbidden", "allowedfs", "onefile", "openflags")
}

func TestDefaultAllowlistEntriesExplainThemselves(t *testing.T) {
	for _, e := range guard.DefaultAllowlist {
		if strings.TrimSpace(e.Why) == "" || len(e.Allow) == 0 || e.Pkg == "" {
			t.Errorf("allowlist entry %+v needs a package, categories and a reason", e)
		}
	}
}

func writeTestPkg(t *testing.T, name string, codeLines int) string {
	t.Helper()
	root := t.TempDir()
	dir := filepath.Join(root, "src", name)
	if err := os.MkdirAll(dir, 0o750); err != nil {
		t.Fatal(err)
	}
	var b strings.Builder
	b.WriteString("package " + name + "\n\n// comments and blank lines do not count\n\n")
	for i := 0; i < codeLines-1; i++ {
		fmt.Fprintf(&b, "var v%d = %d\n\n// c\n", i, i)
	}
	if err := os.WriteFile(filepath.Join(dir, name+"_test.go"), []byte(b.String()), 0o600); err != nil {
		t.Fatal(err)
	}
	return root
}

func TestTestFileLength(t *testing.T) {
	under := writeTestPkg(t, "under", guard.MaxTestFileLines)
	analysistest.Run(t, under, guard.TestLength, "under")

	over := writeTestPkg(t, "over", guard.MaxTestFileLines+1)
	// The finding sits on the package clause, line 1 of the file.
	src := filepath.Join(over, "src", "over", "over_test.go")
	body, err := os.ReadFile(src)
	if err != nil {
		t.Fatal(err)
	}
	marked := strings.Replace(string(body), "package over\n", "package over // want `test file has 1001 lines of code`\n", 1)
	if err := os.WriteFile(src, []byte(marked), 0o600); err != nil {
		t.Fatal(err)
	}
	analysistest.Run(t, over, guard.TestLength, "over")
}
