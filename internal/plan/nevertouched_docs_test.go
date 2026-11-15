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
}
