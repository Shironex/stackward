package report

import (
	"bytes"
	"strings"
	"testing"

	"github.com/Shironex/stackward/internal/checks"
	"github.com/Shironex/stackward/internal/sandbox"
)

func mdFixture() *Report {
	return &Report{
		Tool:     Tool{Name: "stackward", Version: "test"},
		Host:     Host{HostnameHash: "sha256:0123456789abcdef"},
		Coverage: Coverage{Sandbox: sandbox.Status{State: sandbox.Unavailable}},
		Summary:  Summary{Fail: 1, Unknown: 1, Pass: 1},
		Results: []Item{
			{ID: "SSH-003", Group: "SSH", Title: "Unknown *one*", Level: checks.Unknown, Severity: "high", Subject: "host",
				Message: "not inspected: ssh collector skipped"},
			{ID: "SSH-001", Group: "SSH", Title: "Bad | title", Level: checks.Fail, Severity: "high", Subject: "file:/a|b",
				Message:  "<script>x</script> [link](http://example.com)",
				Evidence: map[string]any{"line": "a | b `tick` ``", "n": 3},
				Fix:      Fix{Hint: "Do the `thing`."}},
			{ID: "SSH-002", Group: "SSH", Title: "Fine", Level: checks.Pass, Severity: "low", Subject: "host"},
		},
	}
}

func TestMarkdownEscapesAndOrders(t *testing.T) {
	var b bytes.Buffer
	if err := WriteMarkdown(&b, mdFixture(), MarkdownOptions{}); err != nil {
		t.Fatal(err)
	}
	out := b.String()
	for _, want := range []string{
		`Bad \| title`, `Unknown \*one\*`, "&lt;script&gt;", `\[link\](http://example.com)`,
		"``` a | b `tick` `` ```", "- **Fix:** Do the `thing`.", "run with sudo", "1 check not inspected", "| [SSH-003](",
		"[SSH-001](" + CheckDocsBase + "SSH-001.md)",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("missing %q in\n%s", want, out)
		}
	}
	if strings.Contains(out, "SSH-002") {
		t.Error("passing result shown without Passing")
	}
	if strings.Index(out, "SSH-001") > strings.Index(out, "SSH-003") {
		t.Error("fail must come before unknown")
	}
	if strings.Contains(out, "### UNKNOWN") {
		t.Error("unknown must be compact, not a section")
	}
}

func TestMarkdownPassingAndHostname(t *testing.T) {
	r := mdFixture()
	r.Host = Host{Hostname: "web_1.example.com"}
	var b bytes.Buffer
	if err := WriteMarkdown(&b, r, MarkdownOptions{Passing: true}); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(b.String(), "SSH-002") || !strings.Contains(b.String(), `web\_1.example.com`) {
		t.Errorf("unexpected output:\n%s", b.String())
	}
}
