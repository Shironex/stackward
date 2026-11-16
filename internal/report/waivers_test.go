package report

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/Shironex/stackward/internal/catalog"
	"github.com/Shironex/stackward/internal/checks"
	"github.com/Shironex/stackward/internal/facts"
	"github.com/Shironex/stackward/internal/profile"
	"github.com/Shironex/stackward/internal/sandbox"
	"github.com/Shironex/stackward/internal/schemacheck"
	"github.com/Shironex/stackward/internal/waiver"
)

var waiverDay = time.Date(2026, 3, 1, 12, 0, 0, 0, time.UTC)

// waivedReport builds a report over a fixed set of results with ws applied
// at collected.
func waivedReport(t *testing.T, collected time.Time, ws []waiver.Waiver) *Report {
	t.Helper()
	cat, err := catalog.Load()
	if err != nil {
		t.Fatal(err)
	}
	f := &facts.Facts{CollectedAt: collected, Host: &facts.Host{Hostname: "host.example.com", UID: 0, EUID: 0}}
	results := []checks.Result{
		{ID: "NET-004", Subject: "port:tcp/443", Level: checks.Warn, Message: "tcp/443 is open to anywhere",
			Evidence: map[string]any{"port": 443}},
		{ID: "NET-004", Subject: "port:tcp/22", Level: checks.Warn, Message: "tcp/22 is open to anywhere"},
		{ID: "SYS-001", Subject: "host", Level: checks.Pass, Message: "tested release"},
		{ID: "SYS-002", Subject: "host", Level: checks.Fail, Message: "reboot pending for 20 days"},
		{ID: "SYS-003", Subject: "host", Level: checks.Unknown, Message: "not inspected"},
	}
	return Build(f, results, cat, Meta{
		Version: "test", Sandbox: sandbox.Status{State: sandbox.Unavailable, Reason: "test"},
		Profile: profile.Unknown, ProfileSource: "inferred", ChecksRun: 4, Waivers: ws,
	})
}

func w(check, subject, expires string) waiver.Waiver {
	return waiver.Waiver{Check: check, Subject: subject, Level: waiver.LevelWarn, Reason: "accepted for " + subject, Expires: expires}
}

// withFail sets level: fail.
func withFail(v waiver.Waiver) waiver.Waiver {
	v.Level = waiver.LevelFail
	return v
}

func TestWaiverAccepts(t *testing.T) {
	plain := waivedReport(t, waiverDay, nil)
	r := waivedReport(t, waiverDay, []waiver.Waiver{w("NET-004", "port:tcp/443", "2026-03-01"), withFail(w("SYS-002", "host", "2027-01-01"))})

	if r.Summary != (Summary{Warn: 1, Accepted: 2, Unknown: 1, Pass: 1}) {
		t.Errorf("summary = %+v", r.Summary)
	}
	if r.Coverage.Accepted != 2 || r.Coverage.Checked != plain.Coverage.Checked {
		t.Errorf("coverage = %+v; accepted results must still count as checked (%d)", r.Coverage, plain.Coverage.Checked)
	}
	if r.ExitCode(FailOnFail) != ExitOK || r.ExitCode(FailOnWarn) != ExitFindings {
		t.Error("an accepted fail must not trip --fail-on fail; the open warning still trips --fail-on warn")
	}
	for i, it := range r.Results {
		got := it
		got.Waiver = nil
		if !reflect.DeepEqual(got, plain.Results[i]) {
			t.Errorf("result %d changed beyond the waiver:\n got %+v\nwant %+v", i, got, plain.Results[i])
		}
	}
	if !r.Results[0].Accepted() || r.Results[1].Accepted() || !r.Results[3].Accepted() {
		t.Errorf("accepted flags wrong: %+v", r.Results)
	}
	if got := r.Results[0].Waiver; *got != (ResultWaiver{Status: WaiverAccepted, Level: "warn", Reason: "accepted for port:tcp/443", Expires: "2026-03-01"}) {
		t.Errorf("waiver = %+v", got)
	}
	for _, e := range r.Waivers {
		if e.Status != WaiverApplied || e.Results != 1 {
			t.Errorf("entry = %+v", e)
		}
	}
}

func TestWaiverStates(t *testing.T) {
	r := waivedReport(t, waiverDay, []waiver.Waiver{
		w("NET-004", "port:tcp/22", "2026-02-28"), // expired the day before
		w("NET-004", "port:tcp/8080", "2027-01-01"),
		w("SYS-001", "host", "2027-01-01"), // matches a pass only
		w("SYS-003", "host", "2027-01-01"), // matches an unknown only
		w("ZZZ-999", "host", "2027-01-01"),
		withFail(w("SYS-002", "host", "2027-01-01")),
	})
	want := []string{WaiverExpired, WaiverStale, WaiverStale, WaiverStale, WaiverUnknownCheck, WaiverApplied}
	for i, e := range r.Waivers {
		if e.Status != want[i] {
			t.Errorf("waiver %d (%s %s) = %s, want %s", i, e.Check, e.Subject, e.Status, want[i])
		}
	}
	if len(WaiversToReview(r.Waivers)) != 5 {
		t.Errorf("to review = %+v", WaiversToReview(r.Waivers))
	}
	if WaiversLine(r.Waivers) != "1 applied, 1 expired, 3 stale, 1 for an unknown check" {
		t.Errorf("line = %q", WaiversLine(r.Waivers))
	}
	expired := r.Results[1]
	if expired.Level != checks.Warn || expired.Accepted() || expired.Waiver == nil || expired.Waiver.Status != WaiverExpired {
		t.Errorf("an expired waiver must leave the finding at its level and say so: %+v", expired)
	}
	if r.Summary.Warn != 2 || r.Summary.Accepted != 1 {
		t.Errorf("summary = %+v", r.Summary)
	}
	if r.Results[2].Waiver != nil || r.Results[4].Waiver != nil {
		t.Error("pass and unknown results are never waived")
	}
}

func TestWaiverWithoutCollectionTime(t *testing.T) {
	r := waivedReport(t, time.Time{}, []waiver.Waiver{withFail(w("SYS-002", "host", "2099-01-01"))})
	if r.Summary.Accepted != 0 || r.Summary.Fail != 1 || r.Waivers[0].Status != WaiverExpired {
		t.Errorf("without a collection time no waiver may apply: %+v %+v", r.Summary, r.Waivers)
	}
}

func TestWaiverRedacts(t *testing.T) {
	secret := "hunter" + "2-not-real"
	ws := []waiver.Waiver{{Check: "SYS-002", Subject: "host", Level: waiver.LevelFail, Reason: "DB_PASSWORD=" + secret, Expires: "2027-01-01"}}
	r := waivedReport(t, waiverDay, ws)
	var buf bytes.Buffer
	if err := WriteJSON(&buf, r); err != nil {
		t.Fatal(err)
	}
	if err := WriteMarkdown(&buf, r, MarkdownOptions{}); err != nil {
		t.Fatal(err)
	}
	if err := WriteText(&buf, r, TextOptions{}); err != nil {
		t.Fatal(err)
	}
	if strings.Contains(buf.String(), "hunter2") {
		t.Fatalf("planted secret in a waiver reason reached output:\n%s", buf.String())
	}
}

func TestWaiverJSONMatchesSchema(t *testing.T) {
	schema, err := os.ReadFile(filepath.Join("..", "..", "schema", "report.v1.json"))
	if err != nil {
		t.Fatal(err)
	}
	r := waivedReport(t, waiverDay, []waiver.Waiver{
		w("NET-004", "port:tcp/443", "2027-01-01"), w("NET-004", "port:tcp/22", "2026-01-01"),
		w("NET-004", "port:tcp/1", "2027-01-01"), w("ZZZ-999", "host", "2027-01-01"),
	})
	var buf bytes.Buffer
	if err := WriteJSON(&buf, r); err != nil {
		t.Fatal(err)
	}
	for _, e := range schemacheck.Validate(schema, buf.Bytes()) {
		t.Error(e)
	}
	var doc map[string]any
	if err := json.Unmarshal(buf.Bytes(), &doc); err != nil {
		t.Fatal(err)
	}
	if doc["summary"].(map[string]any)["accepted"] != float64(1) {
		t.Errorf("summary.accepted missing: %v", doc["summary"])
	}
	bad := strings.Replace(buf.String(), `"status": "accepted"`, `"status": "hidden"`, 1)
	if len(schemacheck.Validate(schema, []byte(bad))) == 0 {
		t.Error("schema accepted an invalid waiver status")
	}
	// Without waivers the report keeps its old shape: no new keys.
	buf.Reset()
	if err := WriteJSON(&buf, waivedReport(t, waiverDay, nil)); err != nil {
		t.Fatal(err)
	}
	for _, key := range []string{`"waiver`, `"accepted"`} {
		if strings.Contains(buf.String(), key) {
			t.Errorf("a report without waivers carries %s", key)
		}
	}
}

func TestWaiverText(t *testing.T) {
	r := waivedReport(t, waiverDay, []waiver.Waiver{
		withFail(w("SYS-002", "host", "2027-01-01")), w("NET-004", "port:tcp/22", "2026-01-01"), w("ZZZ-999", "host", "2027-01-01"),
	})
	for _, o := range []TextOptions{{}, {Group: true}} {
		out := writeText(t, r, o)
		for _, want := range []string{
			"waivers:   1 applied, 1 expired, 1 for an unknown check",
			"coverage:  4 checks, 5 results: 4 checked (1 accepted by a waiver), 1 unknown, 0 skipped",
			"x reboot pending for 20 days\n    ACCEPTED FAIL, SYS-002, moderate\n    waiver: accepted until 2027-01-01: accepted for host\n",
			"waiver: expired after 2026-01-01, the finding is back: accepted for port:tcp/22",
			"ZZZ-999 on host: no check has this id",
			"summary: 0 fail, 2 warn, 1 unknown, 0 info, 1 pass, 0 skip, 1 accepted",
		} {
			if !strings.Contains(out, want) {
				t.Errorf("group=%v: missing %q in:\n%s", o.Group, want, out)
			}
		}
		if strings.Contains(out, "FAIL (") || strings.Contains(out, "Fails, most severe first") {
			t.Errorf("group=%v: an accepted fail is listed as a fail:\n%s", o.Group, out)
		}
	}
	if out := writeText(t, r, TextOptions{}); !strings.Contains(out, "ACCEPTED (1)") {
		t.Errorf("level layout has no accepted section:\n%s", out)
	}
}

func TestWaiverMarkdown(t *testing.T) {
	r := waivedReport(t, waiverDay, []waiver.Waiver{withFail(w("SYS-002", "host", "2027-01-01")), w("NET-004", "port:tcp/9", "2027-01-01")})
	var buf bytes.Buffer
	if err := WriteMarkdown(&buf, r, MarkdownOptions{}); err != nil {
		t.Fatal(err)
	}
	out := buf.String()
	for _, want := range []string{
		"- **Waivers:** 1 applied, 1 stale\n",
		"| accepted | 1 |\n",
		"## Accepted\n",
		"| fail moderate | `host` | reboot pending for 20 days | accepted for host | 2027-01-01 |",
		"## Waivers to review\n",
		"| NET-004 | `port:tcp/9` | no fail or warn result has this subject",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("missing %q in:\n%s", want, out)
		}
	}
	if strings.Contains(out, "### FAIL") {
		t.Errorf("an accepted fail is listed as an open finding:\n%s", out)
	}
}

// A waiver for a warning never accepts a fail on the same subject.
func TestWaiverLevelExceeded(t *testing.T) {
	r := waivedReport(t, waiverDay, []waiver.Waiver{w("SYS-002", "host", "2027-01-01")})
	it := r.Results[3]
	if it.Accepted() || it.Waiver == nil || it.Waiver.Status != WaiverLevelExceeded || r.Waivers[0].Status != WaiverLevelExceeded {
		t.Errorf("result %+v, entry %+v", it, r.Waivers[0])
	}
	if r.Summary.Fail != 1 || r.Summary.Accepted != 0 || r.ExitCode(FailOnFail) != ExitFindings {
		t.Errorf("the fail must count and trip --fail-on: %+v", r.Summary)
	}
	if !strings.Contains(AcceptedNote(it.Waiver), "not accepted, the waiver covers up to warn only") {
		t.Errorf("note = %q", AcceptedNote(it.Waiver))
	}
}

func TestWaiverLongLived(t *testing.T) {
	r := waivedReport(t, waiverDay, []waiver.Waiver{w("NET-004", "port:tcp/443", "2027-03-02"), w("NET-004", "port:tcp/22", "2027-03-01")})
	if r.Waivers[0].Status != WaiverLongLived || !r.Results[0].Accepted() {
		t.Errorf("a far expiry still applies and is listed: %+v %+v", r.Waivers[0], r.Results[0].Waiver)
	}
	if r.Waivers[1].Status != WaiverApplied {
		t.Errorf("exactly a year is not long-lived: %+v", r.Waivers[1])
	}
	if got := WaiversToReview(r.Waivers); len(got) != 1 || got[0].Status != WaiverLongLived {
		t.Errorf("to review = %+v", got)
	}
}

// Matching uses the raw subject: two subjects that redact alike stay apart,
// a waiver naming the redacted text matches nothing, and a waiver matching
// more than one result accepts none.
func TestWaiverRawSubjectAndAmbiguity(t *testing.T) {
	cat, err := catalog.Load()
	if err != nil {
		t.Fatal(err)
	}
	f := &facts.Facts{CollectedAt: waiverDay}
	results := []checks.Result{
		{ID: "USR-004", Subject: "file:/etc/sudoers.d/token=alpha", Level: checks.Warn},
		{ID: "USR-004", Subject: "file:/etc/sudoers.d/token=omega", Level: checks.Warn},
		{ID: "USR-005", Subject: "user:bob", Level: checks.Warn},
		{ID: "USR-005", Subject: "user:bob", Level: checks.Warn},
	}
	r := Build(f, results, cat, Meta{Waivers: []waiver.Waiver{
		w("USR-004", "file:/etc/sudoers.d/token=alpha", "2027-01-01"),
		w("USR-004", "file:/etc/sudoers.d/token=[REDACTED]", "2027-01-01"),
		w("USR-005", "user:bob", "2027-01-01"),
	}})
	if !r.Results[0].Accepted() || r.Results[1].Accepted() {
		t.Errorf("raw subjects must stay apart: %+v %+v", r.Results[0].Waiver, r.Results[1].Waiver)
	}
	if r.Waivers[1].Status != WaiverStale {
		t.Errorf("a waiver naming the redacted subject must match nothing: %+v", r.Waivers[1])
	}
	if r.Waivers[2].Status != WaiverAmbiguous || r.Waivers[2].Results != 2 || r.Results[2].Waiver != nil || r.Results[3].Waiver != nil {
		t.Errorf("ambiguous waiver: %+v", r.Waivers[2])
	}
	var buf bytes.Buffer
	if err := WriteJSON(&buf, r); err != nil {
		t.Fatal(err)
	}
	if strings.Contains(buf.String(), "alpha") || strings.Contains(buf.String(), "omega") {
		t.Errorf("a raw subject reached the JSON:\n%s", buf.String())
	}
	if err := CheckWaivers([]waiver.Waiver{{Subject: "file:/etc/sudoers.d/token=alpha", Line: 7}}); err == nil || !strings.Contains(err.Error(), "line 7") {
		t.Errorf("CheckWaivers = %v", err)
	}
	if err := CheckWaivers([]waiver.Waiver{{Subject: "user:bob"}}); err != nil {
		t.Errorf("CheckWaivers(plain) = %v", err)
	}
}
