package checks

import (
	"strings"
	"testing"

	"github.com/Shironex/stackward/internal/catalog"
	"github.com/Shironex/stackward/internal/facts"
)

// TestCatalogMatchesRegistry is the contract between checks and catalog:
// every registered check has a catalog entry and every catalog entry has a
// registered check. PRB checks run in probe, not audit, so they are exempt.
func TestCatalogMatchesRegistry(t *testing.T) {
	cat, err := catalog.Load()
	if err != nil {
		t.Fatal(err)
	}
	registered := map[string]bool{}
	for _, c := range All() {
		registered[c.ID] = true
		if _, ok := cat.Lookup(c.ID); !ok {
			t.Errorf("check %s is registered but has no catalog entry", c.ID)
		}
	}
	if len(registered) == 0 {
		t.Fatal("no checks registered")
	}
	for _, e := range cat.Entries() {
		if e.Group == "PRB" {
			continue
		}
		if !registered[e.ID] {
			t.Errorf("catalog entry %s has no registered check", e.ID)
		}
	}
}

// TestNilFactsNeverPass runs every check over empty facts: with nothing
// inspected, no check may pass.
func TestNilFactsNeverPass(t *testing.T) {
	for _, r := range Evaluate(Input{Facts: &facts.Facts{}}) {
		if r.Level == Pass {
			t.Errorf("%s passed with no facts: %s", r.ID, r.Message)
		}
	}
}

func TestEvaluateGuards(t *testing.T) {
	cs := []Check{
		{ID: "SYS-901", Run: func(Input) []Result { return nil }},
		{ID: "SYS-902", Run: func(Input) []Result { panic("nil map") }},
		{ID: "SYS-903", Run: func(Input) []Result { return One("great", "x", nil) }},
		{ID: "SSH-900", Run: func(Input) []Result {
			return []Result{{Subject: "user:b", Level: Pass}, {Subject: "user:a", Level: Fail}}
		}},
	}
	rs := EvaluateChecks(cs, Input{Facts: &facts.Facts{}})
	var got []string
	for _, r := range rs {
		got = append(got, r.ID+" "+r.Subject+" "+string(r.Level))
	}
	want := []string{
		"SYS-901 host unknown", "SYS-902 host unknown", "SYS-903 host unknown",
		"SSH-900 user:a fail", "SSH-900 user:b pass",
	}
	if strings.Join(got, "\n") != strings.Join(want, "\n") {
		t.Fatalf("got\n%s\nwant\n%s", strings.Join(got, "\n"), strings.Join(want, "\n"))
	}
	if !strings.Contains(rs[1].Message, "nil map") {
		t.Errorf("panic text lost: %q", rs[1].Message)
	}
}

func TestNotInspectedMessages(t *testing.T) {
	f := &facts.Facts{Collectors: []facts.CollectorStatus{
		{Name: "ssh", Status: facts.StatusSkipped, Reason: "needs root; run with sudo for full coverage"},
		{Name: "docker", Status: facts.StatusFailed, Error: "permission denied"},
	}}
	cases := map[string]string{
		"ssh":    "run with sudo",
		"docker": "docker collector failed: permission denied",
		"nope":   "did not run",
	}
	for c, want := range cases {
		r := NotInspected(f, c)
		if r.Level != Unknown || !strings.Contains(r.Message, want) {
			t.Errorf("%s: %+v, want message containing %q", c, r, want)
		}
	}
}

func TestRegisterPanics(t *testing.T) {
	for _, c := range []Check{
		{ID: "sys-1", Run: func(Input) []Result { return nil }},
		{ID: "SYS-999"},
		{ID: "SYS-001", Run: func(Input) []Result { return nil }}, // duplicate
	} {
		func() {
			defer func() {
				if recover() == nil {
					t.Errorf("Register(%q) did not panic", c.ID)
				}
			}()
			Register(c)
		}()
	}
}
