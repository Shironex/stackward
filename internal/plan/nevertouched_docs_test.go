package plan

import (
	"os"
	"strings"
	"testing"
)

// docs/safety.md lists every entry by id, so the public contract and the
// code cannot drift apart.
func TestNeverTouchedIsDocumented(t *testing.T) {
	b, err := os.ReadFile("../../docs/safety.md")
	if err != nil {
		t.Fatal(err)
	}
	seen := map[string]bool{}
	for _, it := range NeverTouched {
		if seen[it.ID] {
			t.Errorf("duplicate id %s", it.ID)
		}
		seen[it.ID] = true
		if it.What == "" || it.Why == "" || len(it.Targets) == 0 {
			t.Errorf("%s needs what, why and targets", it.ID)
		}
		if !strings.Contains(string(b), "| `"+it.ID+"` |") {
			t.Errorf("docs/safety.md does not list %s in the never touched table", it.ID)
		}
	}
	for _, x := range NeverTouchedExceptions {
		if !seen[x.Entry] {
			t.Errorf("exception for %s names unknown entry %s", x.Step, x.Entry)
		}
		if x.What == "" || len(x.Targets) == 0 {
			t.Errorf("exception for %s needs what and targets", x.Step)
		}
		if !strings.Contains(string(b), "| `"+x.Step+"` | `"+x.Entry+"` |") {
			t.Errorf("docs/safety.md does not list the exception of %s in %s", x.Step, x.Entry)
		}
		for _, tg := range x.Targets {
			if strings.ContainsAny(tg, "*?") {
				t.Errorf("exception target %s of %s is a pattern; exceptions name exact targets", tg, x.Step)
			}
			if !strings.Contains(string(b), "`"+strings.TrimPrefix(tg, "file-mode:")+"`") {
				t.Errorf("docs/safety.md does not name %s in the exception of %s", tg, x.Step)
			}
		}
	}
}
