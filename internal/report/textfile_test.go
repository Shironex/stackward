package report

import (
	"bytes"
	"strings"
	"testing"

	"github.com/Shironex/stackward/internal/facts"
	"github.com/Shironex/stackward/internal/sandbox"
)

func TestWriteTextfile(t *testing.T) {
	r := &Report{
		Tool:        Tool{Name: "stackward", Version: "1.2.3\"x\\\n"},
		GeneratedAt: "2026-11-16T10:00:00Z",
		Profile:     Profile{Name: "tunnel"},
		Summary:     Summary{Fail: 2, Warn: 1, Unknown: 1, Pass: 6},
		Coverage: Coverage{
			Checked: 9, Unknown: 1, Root: true,
			Sandbox:    sandbox.Status{State: sandbox.Landlock},
			Collectors: []CollectorCoverage{{Status: facts.StatusOK}, {Status: facts.StatusOK}, {Status: facts.StatusPartial}},
		},
	}
	var buf bytes.Buffer
	if err := WriteTextfile(&buf, r); err != nil {
		t.Fatal(err)
	}
	got := buf.String()
	for _, want := range []string{
		`stackward_results{level="fail"} 2`,
		`stackward_results{level="skip"} 0`,
		"stackward_last_run_timestamp_seconds 1794823200",
		"stackward_coverage_ratio 0.9",
		"stackward_run_as_root 1",
		"stackward_sandbox_confined 1",
		`stackward_collectors{status="ok"} 2`,
		`stackward_collectors{status="partial"} 1`,
		`stackward_collectors{status="timeout"} 0`,
		`stackward_info{version="1.2.3\"x\\\n",profile="tunnel"} 1`,
	} {
		if !strings.Contains(got, want+"\n") {
			t.Errorf("textfile lacks %q:\n%s", want, got)
		}
	}
	// Every sample line belongs to a metric announced by HELP and TYPE.
	typed := map[string]bool{}
	for _, l := range strings.Split(strings.TrimSuffix(got, "\n"), "\n") {
		if name, ok := strings.CutPrefix(l, "# TYPE "); ok {
			typed[strings.Fields(name)[0]] = true
			continue
		}
		if strings.HasPrefix(l, "#") {
			continue
		}
		name, _, _ := strings.Cut(l, "{")
		name, _, _ = strings.Cut(name, " ")
		if !typed[name] {
			t.Errorf("sample %q has no TYPE line before it", l)
		}
	}
}

func TestWriteTextfileEmptyAndBadTime(t *testing.T) {
	var buf bytes.Buffer
	if err := WriteTextfile(&buf, &Report{GeneratedAt: "not a time"}); err != nil {
		t.Fatal(err)
	}
	got := buf.String()
	for _, want := range []string{
		"stackward_last_run_timestamp_seconds 0", "stackward_coverage_ratio 0",
		"stackward_run_as_root 0", "stackward_sandbox_confined 0",
	} {
		if !strings.Contains(got, want+"\n") {
			t.Errorf("textfile lacks %q:\n%s", want, got)
		}
	}
}
