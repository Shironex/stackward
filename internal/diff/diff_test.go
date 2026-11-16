package diff

import (
	"bytes"
	"encoding/json"
	"errors"
	"strings"
	"testing"

	"github.com/Shironex/stackward/internal/checks"
	"github.com/Shironex/stackward/internal/report"
	"github.com/Shironex/stackward/internal/schemacheck"
	"github.com/Shironex/stackward/schema"
)

const hostA, hostB = "sha256:0123456789abcdef", "sha256:fedcba9876543210"

// doc is a minimal valid report.v1 document as a map, for tests to bend.
func doc(host string, results ...map[string]any) map[string]any {
	rs := []any{}
	for _, r := range results {
		rs = append(rs, r)
	}
	h := map[string]any{}
	if host != "" {
		h["hostname_hash"] = host
	}
	return map[string]any{
		"schema": report.SchemaID, "tool": map[string]any{"name": "stackward", "version": "test"},
		"generated_at": "2026-11-01T12:00:00Z", "host": h,
		"profile":  map[string]any{"name": "public-web", "source": "inferred"},
		"coverage": map[string]any{"checks": 1, "results": 1, "checked": 1, "unknown": 0, "skipped": 0, "root": true, "sandbox": map[string]any{"state": "disabled"}, "collectors": []any{}},
		"summary":  map[string]any{"fail": 0, "warn": 0, "unknown": 0, "info": 0, "pass": 0, "skip": 0},
		"results":  rs,
	}
}

func result(id, subject string, level checks.Level, message string) map[string]any {
	group, _, _ := strings.Cut(id, "-")
	return map[string]any{"id": id, "group": group, "title": "t", "level": string(level),
		"severity": "high", "subject": subject, "message": message, "fix": map[string]any{"hint": "h"}}
}

func encode(t *testing.T, v any) []byte {
	t.Helper()
	b, err := json.Marshal(v)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func load(t *testing.T, v any) *report.Report {
	t.Helper()
	r, err := LoadReport(bytes.NewReader(encode(t, v)))
	if err != nil {
		t.Fatal(err)
	}
	return r
}

func TestLoadReportRefuses(t *testing.T) {
	probe := doc(hostA)
	probe["probe"] = map[string]any{"target": "192.0.2.1", "addresses": []any{}, "families": []any{}, "ports": []any{}}
	extra := doc(hostA)
	extra["surprise"] = true
	badID := doc(hostA, result("NET-004", "port:tcp/22", checks.Info, "m"))
	badID["results"].([]any)[0].(map[string]any)["id"] = "NET-004](javascript:x)"
	cases := []struct {
		name string
		in   []byte
		want string
	}{
		{"not json", []byte("{"), "not a JSON document"},
		{"two values", append(encode(t, doc(hostA)), []byte(" {}")...), "more than one JSON value"},
		{"array", []byte("[]"), "not a JSON object"},
		{"no schema", []byte(`{"results": []}`), "no schema field"},
		{"facts file", []byte(`{"schema": "stackward.facts.v1"}`), "facts file"},
		{"other schema", []byte(`{"schema": "stackward.plan.v1"}`), "unsupported report schema"},
		{"unknown field", encode(t, extra), `unexpected property "surprise"`},
		{"bad check id", encode(t, badID), "does not match schema"},
		{"probe report", encode(t, probe), "probe report"},
		{"too large", append([]byte(`{"schema":"`), bytes.Repeat([]byte("a"), MaxReportBytes)...), "larger than"},
	}
	for _, tc := range cases {
		_, err := LoadReport(bytes.NewReader(tc.in))
		if err == nil || !strings.Contains(err.Error(), tc.want) {
			t.Errorf("%s: err = %v, want it to mention %q", tc.name, err, tc.want)
		}
	}
}

// TestLoadReportCleans: control and invisible format characters are
// replaced and secrets are redacted in every string, evidence included,
// before anything renders them.
func TestLoadReportCleans(t *testing.T) {
	r := result("NET-004", "port:tcp/22\x1b[31m", checks.Warn, "token="+"hunter2"+"hunter2 \u202eevil")
	r["evidence"] = map[string]any{"processes": []any{"sshd\x07"}, "api_key": "abcd" + "efgh" + "1234" + "5678"} // built up so secret scanners skip it
	rep := load(t, doc(hostA, r))
	it := rep.Results[0]
	for _, s := range []string{it.Subject, it.Message, it.Evidence["processes"].([]any)[0].(string)} {
		if strings.ContainsAny(s, "\x1b\x07\u202e") {
			t.Errorf("control or format character kept: %q", s)
		}
	}
	if strings.Contains(it.Message, "hunter2") || it.Evidence["api_key"] != "[REDACTED]" {
		t.Errorf("secret kept: %q %v", it.Message, it.Evidence)
	}
}

func TestCompareHost(t *testing.T) {
	a, b, none := load(t, doc(hostA)), load(t, doc(hostB)), load(t, doc(""))
	for _, pair := range [][2]*report.Report{{a, b}, {a, none}, {none, none}} {
		if _, err := Compare(pair[0], pair[1], Options{}); !errors.Is(err, ErrHost) {
			t.Errorf("want a host mismatch, got %v", err)
		}
		d, err := Compare(pair[0], pair[1], Options{ForceHost: true})
		if err != nil || d.SameHost || !strings.Contains(strings.Join(d.Notes, " "), "--force-host") {
			t.Errorf("--force-host: %v %+v", err, d)
		}
	}
	shown := doc("")
	shown["host"] = map[string]any{"hostname": "web1.example.com"}
	same := doc(report.HashHostname("web1.example.com"))
	d, err := Compare(load(t, shown), load(t, same), Options{})
	if err != nil || !d.SameHost || d.Old.Host != d.New.Host {
		t.Errorf("a shown hostname is matched by its hash, never printed: %v %+v", err, d)
	}
}

func accepted(r map[string]any, status string) map[string]any {
	r["waiver"] = map[string]any{"status": status, "level": "warn", "reason": "r", "expires": "2026-12-31"}
	return r
}

// TestAcceptedIsNeverFixedOrNew: a finding a waiver accepts is neither a
// new finding nor described as fixed; an expired waiver makes it new.
func TestAcceptedIsNeverFixedOrNew(t *testing.T) {
	old := load(t, doc(hostA, result("USR-005", "user:deploy", checks.Warn, "m")))
	cur := load(t, doc(hostA, accepted(result("USR-005", "user:deploy", checks.Warn, "m"), report.WaiverAccepted)))
	d, err := Compare(old, cur, Options{})
	if err != nil {
		t.Fatal(err)
	}
	c := d.Changes[0]
	if c.NewFinding || strings.Contains(Describe(c), "fixed") || c.What[0] != WhatWaiver {
		t.Errorf("accepted change: %+v %q", c, Describe(c))
	}
	if d.Tripped(FailOnAny) {
		t.Error("accepting a finding must not trip --fail-on-drift")
	}
	d, _ = Compare(cur, load(t, doc(hostA, accepted(result("USR-005", "user:deploy", checks.Warn, "m"), report.WaiverExpired))), Options{})
	if !d.Changes[0].NewFinding || !d.Tripped(FailOnAny) || d.Tripped(FailOnFail) {
		t.Errorf("an expired waiver brings the warning back as new: %+v", d.Changes)
	}
	added := load(t, doc(hostA, accepted(result("USR-005", "user:deploy", checks.Warn, "m"), report.WaiverAccepted)))
	d, _ = Compare(load(t, doc(hostA)), added, Options{})
	if d.Changes[0].NewFinding || !strings.Contains(Describe(d.Changes[0]), "accepted") {
		t.Errorf("an added accepted finding: %+v", d.Changes[0])
	}
}

func TestThresholds(t *testing.T) {
	warn := load(t, doc(hostA, result("USR-006", "user:a", checks.Warn, "m")))
	fail := load(t, doc(hostA, result("USR-006", "user:a", checks.Fail, "m")))
	empty := load(t, doc(hostA))
	cases := []struct {
		old, cur *report.Report
		t        FailOn
		want     bool
	}{
		{empty, warn, FailOnAny, true},
		{empty, warn, FailOnFail, false},
		{empty, fail, FailOnFail, true},
		{warn, fail, FailOnFail, true}, // a warning that became a fail
		{fail, warn, FailOnAny, false}, // milder is not new
		{empty, fail, FailOnDrift, false},
		{empty, fail, FailOnNever, false},
		{warn, empty, FailOnAny, false}, // removed is never new
	}
	for i, tc := range cases {
		d, err := Compare(tc.old, tc.cur, Options{})
		if err != nil {
			t.Fatal(err)
		}
		if got := d.Tripped(tc.t); got != tc.want {
			t.Errorf("case %d (%s): tripped = %v, want %v (%+v)", i, tc.t, got, tc.want, d.Changes)
		}
	}
	if _, err := ParseFailOn("warn"); err == nil {
		t.Error("warn is not a --fail-on-drift value")
	}
}

func TestDriftTripsEveryThresholdButNever(t *testing.T) {
	l := result("NET-004", "port:tcp/8080", checks.Info, "m")
	l["evidence"] = map[string]any{"class": "wildcard", "processes": []any{"node"}}
	d, err := Compare(load(t, doc(hostA)), load(t, doc(hostA, l)), Options{})
	if err != nil {
		t.Fatal(err)
	}
	if len(d.Drift) != 1 || d.Drift[0].Kind != DriftListener {
		t.Fatalf("drift = %+v", d.Drift)
	}
	for _, th := range []FailOn{FailOnAny, FailOnFail, FailOnDrift} {
		if !d.Tripped(th) {
			t.Errorf("%s: drift should trip", th)
		}
	}
	if d.Tripped(FailOnNever) || d.ExitCode(FailOnNever) != report.ExitOK || d.ExitCode(FailOnDrift) != report.ExitFindings {
		t.Error("never must not trip; exit codes 0 and 1")
	}
}

// TestNoiseIsNotListed: a passing result appearing, or info changing to
// pass, is not a change; a loopback listener is not drift.
func TestNoiseIsNotListed(t *testing.T) {
	lo := result("NET-004", "port:tcp/9000", checks.Info, "m")
	lo["evidence"] = map[string]any{"class": "loopback"}
	d, err := Compare(load(t, doc(hostA, result("SYS-001", "host", checks.Info, "m"))),
		load(t, doc(hostA, result("SYS-001", "host", checks.Pass, "m"), result("DKR-021", "container:a/b", checks.Pass, "m"), lo)), Options{})
	if err != nil {
		t.Fatal(err)
	}
	if len(d.Changes) != 0 || len(d.Drift) != 0 {
		t.Errorf("want no changes or drift: %+v %+v", d.Changes, d.Drift)
	}
}

// TestMarkdownEscapes: values from a report file render literally in
// Markdown: no HTML, links or table breaks.
func TestMarkdownEscapes(t *testing.T) {
	r := result("USR-004", "file:/etc/sudoers.d/x|y`z", checks.Warn, "<img src=x onerror=alert(1)> [a](http://example.com) | **b**")
	r["evidence"] = map[string]any{"nopasswd": []any{"<b>evil</b> (line 1)"}}
	d, err := Compare(load(t, doc(hostA)), load(t, doc(hostA, r)), Options{})
	if err != nil {
		t.Fatal(err)
	}
	var b bytes.Buffer
	if err := WriteMarkdown(&b, d); err != nil {
		t.Fatal(err)
	}
	out := b.String()
	// "<b>evil</b>" may stay inside its code span, where it is literal.
	out = strings.ReplaceAll(out, "`<b>evil</b>`", "")
	for _, bad := range []string{"<img", "<b>", "[a](", "**b**"} {
		if strings.Contains(out, bad) {
			t.Errorf("markdown kept %q:\n%s", bad, out)
		}
	}
	for _, line := range strings.Split(out, "\n") {
		if strings.HasPrefix(line, "| [USR-004]") && strings.Count(strings.ReplaceAll(line, `\|`, ""), "|") != 6 {
			t.Errorf("a value broke the table row: %s", line)
		}
	}
}

func TestDiffMatchesSchema(t *testing.T) {
	d, err := Compare(load(t, doc(hostA)), load(t, doc(hostA, result("USR-006", "user:a", checks.Warn, "m"))), Options{Version: "test"})
	if err != nil {
		t.Fatal(err)
	}
	var b bytes.Buffer
	if err := WriteJSON(&b, d); err != nil {
		t.Fatal(err)
	}
	for _, e := range schemacheck.Validate(schema.Diff, b.Bytes()) {
		t.Error(e)
	}
}

// TestCoverageLost: a drift check that judged the baseline and is unknown,
// skip or missing now is listed and trips every threshold but never; one
// that was never judged, or still is, is not.
func TestCoverageLost(t *testing.T) {
	old := load(t, doc(hostA,
		result("NET-004", "port:tcp/22", checks.Info, "m"),
		result("DKR-020", "container:a/b", checks.Pass, "m"),
		result("USR-004", "host", checks.Unknown, "needs root"),
		result("SSH-014", "user:a", checks.Pass, "m")))
	cur := load(t, doc(hostA,
		result("NET-004", "host", checks.Unknown, "listeners not inspected"),
		result("USR-004", "host", checks.Unknown, "needs root"),
		result("SSH-014", "user:a", checks.Pass, "m")))
	d, err := Compare(old, cur, Options{})
	if err != nil {
		t.Fatal(err)
	}
	got := []string{}
	for _, l := range d.CoverageLost {
		got = append(got, l.Check+"="+l.Now)
	}
	if strings.Join(got, ",") != "NET-004=unknown,DKR-020=missing" || d.Summary.CoverageLost != 2 {
		t.Fatalf("coverage lost = %v", got)
	}
	for _, th := range []FailOn{FailOnAny, FailOnFail, FailOnDrift} {
		if !d.Tripped(th) {
			t.Errorf("%s: lost coverage should trip", th)
		}
	}
	if d.Tripped(FailOnNever) {
		t.Error("never must not trip")
	}
	var b bytes.Buffer
	if err := WriteText(&b, d); err != nil || !strings.Contains(b.String(), "LOST COVERAGE") {
		t.Errorf("text: %v\n%s", err, b.String())
	}
}
