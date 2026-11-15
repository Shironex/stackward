package report

import (
	"bytes"
	"fmt"
	"strings"
	"testing"

	"github.com/Shironex/stackward/internal/catalog"
	"github.com/Shironex/stackward/internal/checks"
)

func writeText(t *testing.T, r *Report, o TextOptions) string {
	t.Helper()
	var buf bytes.Buffer
	if err := WriteText(&buf, r, o); err != nil {
		t.Fatal(err)
	}
	return buf.String()
}

// exposureReport has a fail, a warning and more NET-004 info results than a
// compact list shows.
func exposureReport() *Report {
	r := &Report{Schema: SchemaID, Tool: Tool{Name: "stackward", Version: "test"}, Coverage: Coverage{Root: true}}
	add := func(it Item) {
		it.Group = catalog.GroupOf(it.ID)
		r.Results = append(r.Results, it)
		r.count(it.Level)
	}
	add(Item{ID: "SYS-002", Title: "No reboot pending", Level: checks.Warn, Severity: catalog.Moderate, Subject: "host",
		Message: "a reboot has been pending for 20 days", Fix: Fix{Hint: "Reboot in a maintenance window."}})
	add(Item{ID: "DKR-001", Title: "Published container ports do not bypass the host firewall", Level: checks.Fail,
		Severity: catalog.Critical, Subject: "container:shop/web", Message: "shop-web-1 is reachable from anywhere past the host firewall",
		Fix: Fix{Hint: strings.Repeat("Publish on 127.0.0.1 or the tailnet address instead. ", 4) +
			"See https://docs.docker.com/engine/network/packet-filtering-firewalls/#docker-on-a-router-and-other-hosts"}})
	for i := range 12 {
		port := 9000 + i
		add(Item{ID: "NET-004", Title: "Exposure: every listening socket and who can reach it", Level: checks.Info,
			Severity: catalog.Moderate, Subject: fmt.Sprintf("port:tcp/%d", port),
			Message: fmt.Sprintf("tcp/%d (app) listens on loopback addresses only", port)})
	}
	return r
}

func TestTextOrdersBySummaryThenLevel(t *testing.T) {
	out := writeText(t, exposureReport(), TextOptions{})
	box, fail, warn, info := strings.Index(out, "+- Summary"), strings.Index(out, "-- FAIL (1)"), strings.Index(out, "-- WARN (1)"), strings.Index(out, "-- INFO (12)")
	if box < 0 || fail < 0 || warn < 0 || info < 0 || box >= fail || fail >= warn || warn >= info {
		t.Fatalf("want summary, fail, warn, info in that order:\n%s", out)
	}
	// The message is the headline; the title is the rule.
	for _, want := range []string{
		"  x shop-web-1 is reachable from anywhere past the host firewall\n    DKR-001, critical, container:shop/web\n    rule: Published container ports",
		"x critical  DKR-001  shop-web-1 is reachable",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("missing %q in:\n%s", want, out)
		}
	}
}

func TestTextCompactsInfo(t *testing.T) {
	out := writeText(t, exposureReport(), TextOptions{})
	if n := strings.Count(out, "listens on loopback addresses only"); n != infoCap-1 {
		t.Errorf("compact list shows %d NET-004 lines, want %d:\n%s", n, infoCap-1, out)
	}
	for _, want := range []string{"i NET-004  Exposure: every listening socket and who can reach it (12 results)", "and 5 more; --info lists them"} {
		if !strings.Contains(out, want) {
			t.Errorf("missing %q in:\n%s", want, out)
		}
	}
	if strings.Contains(out, "[moderate]") || strings.Contains(out, "NET-004, moderate") {
		t.Errorf("an info result carries a severity tag:\n%s", out)
	}
	for _, o := range []TextOptions{{Info: true}, {Passing: true}} {
		full := writeText(t, exposureReport(), o)
		if n := strings.Count(full, "listens on loopback addresses only"); n != 12 {
			t.Errorf("%+v: %d NET-004 results shown, want all 12", o, n)
		}
	}
}

func TestTextWrapsWithHangingIndent(t *testing.T) {
	for _, w := range []int{80, 120} {
		out := writeText(t, exposureReport(), TextOptions{Width: w})
		lines := strings.Split(out, "\n")
		for _, l := range lines {
			if width(l) > w {
				t.Errorf("width %d: line of %d cells: %q", w, width(l), l)
			}
		}
		fix := false
		for i, l := range lines {
			if strings.HasPrefix(l, "    fix:  Publish") {
				fix = true
				if !strings.HasPrefix(lines[i+1], strings.Repeat(" ", 10)) || lines[i+1][10] == ' ' {
					t.Errorf("width %d: fix continuation not under the fix text: %q", w, lines[i+1])
				}
			}
		}
		if !fix {
			t.Fatalf("width %d: no fix line:\n%s", w, out)
		}
		// The URL is longer than a line at 80 but is kept whole when it fits.
		if w == 120 && !strings.Contains(out, "https://docs.docker.com/engine/network/packet-filtering-firewalls/#docker-on-a-router-and-other-hosts") {
			t.Errorf("width %d: URL was cut:\n%s", w, out)
		}
	}
}

func TestTextPlainAndTerminal(t *testing.T) {
	plain := writeText(t, exposureReport(), TextOptions{})
	if strings.Contains(plain, "\x1b[") {
		t.Error("ANSI in plain output")
	}
	for _, r := range plain {
		if r > 127 {
			t.Fatalf("plain output is not ASCII: %q", r)
		}
	}
	// NO_COLOR on a terminal: symbols and box, no ANSI.
	noColor := writeText(t, exposureReport(), TextOptions{Fancy: true})
	if strings.Contains(noColor, "\x1b[") || !strings.Contains(noColor, "╭─ Summary") || !strings.Contains(noColor, "✗ shop-web-1") {
		t.Errorf("fancy without color:\n%s", noColor)
	}
	tty := writeText(t, exposureReport(), TextOptions{Fancy: true, Color: true})
	if !strings.Contains(tty, "\x1b[1;31m✗\x1b[0m") {
		t.Errorf("no colored fail mark:\n%s", tty)
	}
}

func TestTextGroupLayout(t *testing.T) {
	out := writeText(t, exposureReport(), TextOptions{Group: true})
	sys, net, dkr := strings.Index(out, "-- SYS  System"), strings.Index(out, "-- NET  Firewall"), strings.Index(out, "-- DKR  Docker")
	if sys < 0 || net < 0 || dkr < 0 || sys >= net || net >= dkr {
		t.Fatalf("groups not in catalog order:\n%s", out)
	}
	if !strings.Contains(out, "    FAIL, DKR-001, critical") {
		t.Errorf("group layout must name the level:\n%s", out)
	}
}

func TestTextProbeSelfTarget(t *testing.T) {
	r := sampleProbe(t)
	r.Probe.SelfTarget = true
	out := writeText(t, r, TextOptions{Width: 80})
	want := "  WARNING:   target is this machine, not an outside view: results do not show\n             what the internet sees\n"
	if !strings.Contains(out, want) {
		t.Errorf("missing self target warning %q in:\n%s", want, out)
	}
	if strings.Index(out, "WARNING:") > strings.Index(out, "target:") {
		t.Error("the warning must come before the target")
	}
	if strings.Contains(out, "stackward tui") || !strings.Contains(out, "stackward probe <host> --json") {
		t.Errorf("probe hints:\n%s", out)
	}
}

func TestWrapWords(t *testing.T) {
	for _, tc := range []struct {
		in   string
		w    int
		want []string
	}{
		{"one two three four", 9, []string{"one two", "three", "four"}},
		{"a https://example.com/a/very/long/path b", 12, []string{"a", "https://exam", "ple.com/a/ve", "ry/long/path", "b"}},
		{"keep\n\nparagraphs", 20, []string{"keep", "", "paragraphs"}},
	} {
		if got := wrapWords(tc.in, tc.w); strings.Join(got, "|") != strings.Join(tc.want, "|") {
			t.Errorf("wrapWords(%q, %d) = %q, want %q", tc.in, tc.w, got, tc.want)
		}
	}
}

func TestTruncateWords(t *testing.T) {
	for _, tc := range []struct {
		in   string
		w    int
		want string
	}{
		{"short", 10, "short"},
		{"coolify is reachable from anywhere", 24, "coolify is reachable..."},
		{"averyveryverylongword", 10, "averyve..."},
	} {
		if got := truncateWords(tc.in, tc.w, "..."); got != tc.want {
			t.Errorf("truncateWords(%q, %d) = %q, want %q", tc.in, tc.w, got, tc.want)
		}
	}
}
