package report

import (
	"strings"
	"testing"

	"github.com/Shironex/stackward/internal/catalog"
	"github.com/Shironex/stackward/internal/checks"
)

func TestShortenGeneratedNames(t *testing.T) {
	for in, want := range map[string]string{
		"alloy-a2arfozauvzagw6if1eisq30 runs as root":                   "alloy runs as root",
		"alloy-a2arfozauvzagw6if1eisq30-1 runs as root":                 "alloy-1 runs as root",
		"app-a2arfozauvzagw6if1eisq30-123456789012 is exposed.":         "app is exposed.",
		"my-api-a2arfozauvzagw6if1eisq30, and web-1":                    "my-api, and web-1",
		"alloy runs as root":                                            "alloy runs as root",
		"shop-web-1 mounts /etc":                                        "shop-web-1 mounts /etc",
		"web-abcdefghijklmnopqrstuvwx is plain letters":                 "web-abcdefghijklmnopqrstuvwx is plain letters",
		"web-a2arfozauvzagw6if1eisq3 is 23 chars":                       "web-a2arfozauvzagw6if1eisq3 is 23 chars",
		"web-A2arfozauvzagw6if1eisq30 has upper case":                   "web-A2arfozauvzagw6if1eisq30 has upper case",
		"a2arfozauvzagw6if1eisq30 alone is not a suffixed name":         "a2arfozauvzagw6if1eisq30 alone is not a suffixed name",
		"reboot pending since today":                                    "reboot pending since today",
		"mounts /var/run/docker.sock from x-a2arfozauvzagw6if1eisq30/y": "mounts /var/run/docker.sock from x/y",
	} {
		if got := ShortenGeneratedNames(in); got != want {
			t.Errorf("ShortenGeneratedNames(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestExpectedSeverity(t *testing.T) {
	it := Item{ID: "DKR-010", Level: checks.Warn, Severity: catalog.Critical, Message: "x", Evidence: map[string]any{"managed_by": "coolify"}}
	if got := metaLine(it, false, " | "); !strings.Contains(got, "critical, expected") {
		t.Errorf("managed warn: %q", got)
	}
	it.Evidence = map[string]any{"managed_by": ""}
	if got := metaLine(it, false, " | "); strings.Contains(got, "expected") {
		t.Errorf("unmanaged warn: %q", got)
	}
	it.Level, it.Evidence = checks.Fail, map[string]any{"managed_by": "coolify"}
	if got := metaLine(it, false, " | "); strings.Contains(got, "expected") {
		t.Errorf("fail stays plain: %q", got)
	}
}

func TestRuleFixOncePerCheck(t *testing.T) {
	mk := func(msg string) Item {
		return Item{ID: "DKR-020", Title: "No docker.sock", Level: checks.Warn, Severity: catalog.High, Message: msg, Fix: Fix{Hint: "remove the mount"}}
	}
	r := &Report{Results: []Item{mk("a mounts it"), mk("b mounts it")}}
	var b, all strings.Builder
	if err := WriteText(&b, r, TextOptions{}); err != nil {
		t.Fatal(err)
	}
	if err := WriteText(&all, r, TextOptions{Passing: true}); err != nil {
		t.Fatal(err)
	}
	if n := strings.Count(b.String(), "fix:  remove the mount"); n != 1 {
		t.Errorf("default output has %d fix lines, want 1:\n%s", n, b.String())
	}
	if n := strings.Count(all.String(), "fix:  remove the mount"); n != 2 {
		t.Errorf("--all output has %d fix lines, want 2", n)
	}
}
