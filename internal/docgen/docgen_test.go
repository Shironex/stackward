package docgen

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/Shironex/stackward/internal/catalog"
)

const pagesDir = "../../docs/checks"

// TestCommittedPagesAreCurrent fails when docs/checks differs from the
// catalog. Fix it with: go run ./cmd/docgen
func TestCommittedPagesAreCurrent(t *testing.T) {
	cat, err := catalog.Default()
	if err != nil {
		t.Fatal(err)
	}
	problems, err := Check(cat, pagesDir)
	if err != nil {
		t.Fatal(err)
	}
	if len(problems) > 0 {
		t.Fatalf("docs/checks is stale, run `go run ./cmd/docgen`:\n  %s", strings.Join(problems, "\n  "))
	}
}

func TestRenderCoversEveryEntry(t *testing.T) {
	cat, err := catalog.Default()
	if err != nil {
		t.Fatal(err)
	}
	pages := Render(cat)
	if len(pages) != len(cat.Entries())+1 {
		t.Fatalf("got %d pages for %d entries", len(pages), len(cat.Entries()))
	}
	idx := string(pages["index.md"])
	for _, e := range cat.Entries() {
		body, ok := pages[e.ID+".md"]
		if !ok {
			t.Fatalf("no page for %s", e.ID)
		}
		if !strings.Contains(string(body), e.Rationale) || !strings.Contains(string(body), e.Fix) {
			t.Errorf("%s page lacks rationale or fix", e.ID)
		}
		if !strings.Contains(idx, "["+e.ID+"]("+e.ID+".md)") {
			t.Errorf("index lacks %s", e.ID)
		}
	}
}

func TestPagesHaveNoDashesOrRealNames(t *testing.T) {
	cat, err := catalog.Default()
	if err != nil {
		t.Fatal(err)
	}
	for name, body := range Render(cat) {
		if strings.ContainsAny(string(body), "\u2013\u2014") {
			t.Errorf("%s contains an en or em dash; fix the catalog prose", name)
		}
	}
}

func TestWriteAndCheckRoundTrip(t *testing.T) {
	cat, err := catalog.Default()
	if err != nil {
		t.Fatal(err)
	}
	dir := filepath.Join(t.TempDir(), "checks")
	if err := Write(cat, dir); err != nil {
		t.Fatal(err)
	}
	if p, err := Check(cat, dir); err != nil || len(p) != 0 {
		t.Fatalf("fresh pages reported stale: %v %v", p, err)
	}
	first := cat.Entries()[0].ID + ".md"
	if err := os.WriteFile(filepath.Join(dir, first), []byte("edited"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "ZZZ-999.md"), []byte("orphan"), 0o644); err != nil {
		t.Fatal(err)
	}
	p, err := Check(cat, dir)
	if err != nil || len(p) != 2 {
		t.Fatalf("want 2 problems, got %v %v", p, err)
	}
	if err := Write(cat, dir); err != nil {
		t.Fatal(err)
	}
	if p, _ := Check(cat, dir); len(p) != 0 {
		t.Fatalf("write did not repair: %v", p)
	}
}
