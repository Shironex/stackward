package report

import (
	"fmt"
	"strings"
	"time"

	"github.com/Shironex/stackward/internal/catalog"
	"github.com/Shironex/stackward/internal/checks"
	"github.com/Shironex/stackward/internal/redact"
	"github.com/Shironex/stackward/internal/waiver"
)

// States of a result's waiver (Item.Waiver.Status).
const (
	// WaiverAccepted: the finding is accepted until the expiry. Its level
	// and evidence are unchanged; it is counted as accepted instead of
	// fail or warn and does not trip --fail-on.
	WaiverAccepted = "accepted"
	// WaiverExpired: the waiver ran out, so the finding counts at its real
	// level again. Also the state of an expired entry in Report.Waivers.
	WaiverExpired = "expired"
	// WaiverLevelExceeded: the result is worse than the waiver's level (a
	// fail under a waiver for a warning), so it counts at its real level.
	// Also the state of such an entry in Report.Waivers.
	WaiverLevelExceeded = "level-exceeded"
)

// States of an entry of the waivers file (WaiverEntry.Status) besides
// WaiverExpired and WaiverLevelExceeded.
const (
	// WaiverApplied: the waiver accepted its finding.
	WaiverApplied = "applied"
	// WaiverLongLived: the waiver accepted its finding, but expires more
	// than a year after the audit; listed for review, still applied.
	WaiverLongLived = "long-lived"
	// WaiverStale: the check is known but no fail or warn result has the
	// waiver's subject (the finding was fixed, or the subject is wrong).
	WaiverStale = "stale"
	// WaiverAmbiguous: more than one result has the waiver's check and
	// subject, so it accepts none of them.
	WaiverAmbiguous = "ambiguous"
	// WaiverUnknownCheck: no check has the waiver's id.
	WaiverUnknownCheck = "unknown-check"
)

// ResultWaiver is the waiver that matched a result.
type ResultWaiver struct {
	// Status is accepted, expired or level-exceeded.
	Status string `json:"status"`
	// Level is the worst level the waiver accepts: warn or fail.
	Level  string `json:"level"`
	Reason string `json:"reason"`
	// Expires is the last day the waiver holds, YYYY-MM-DD (UTC).
	Expires string `json:"expires"`
}

// WaiverEntry is one entry of the waivers file and what became of it.
type WaiverEntry struct {
	Check   string `json:"check"`
	Subject string `json:"subject"`
	Level   string `json:"level"`
	Reason  string `json:"reason"`
	Expires string `json:"expires"`
	// Status is applied, long-lived, expired, level-exceeded, stale,
	// ambiguous or unknown-check.
	Status string `json:"status"`
	// Results is how many results have the waiver's check and subject, at
	// any level.
	Results int `json:"results"`
}

// Accepted reports whether a waiver accepts this result.
func (it Item) Accepted() bool { return it.Waiver != nil && it.Waiver.Status == WaiverAccepted }

// waivable reports whether a waiver may accept a result of level l. Only
// findings can be accepted: an unknown is never turned into anything that
// reads as settled, and a pass needs no waiver.
func waivable(l checks.Level) bool { return l == checks.Fail || l == checks.Warn }

// CheckWaivers refuses waivers the report could not match safely: a subject
// that secret redaction would change. Matching uses the raw subject, so two
// subjects that redact to the same text stay apart, and the report prints
// only the redacted one; a waiver naming a subject that holds a secret
// would put that secret in the waivers file and the report.
func CheckWaivers(ws []waiver.Waiver) error {
	for _, w := range ws {
		if redact.String(w.Subject) != w.Subject {
			return fmt.Errorf("line %d: subject looks like it holds a secret (redaction would change it); name a subject without one", w.Line)
		}
	}
	return nil
}

// applyWaivers matches every waiver to the results with its check id and
// exact raw subject, marks the result and lists the waivers with their
// state in r.Waivers. now is when the facts were collected, so a replayed
// facts file judges expiry the same way every time. Evidence and levels are
// never touched.
func applyWaivers(r *Report, ws []waiver.Waiver, cat *catalog.Catalog, now time.Time) {
	for _, w := range ws {
		e := WaiverEntry{
			Check: w.Check, Subject: redact.String(w.Subject), Level: w.Level, Reason: redact.String(w.Reason), Expires: w.Expires,
		}
		if _, known := cat.Lookup(w.Check); !known {
			e.Status = WaiverUnknownCheck
			r.Waivers = append(r.Waivers, e)
			continue
		}
		var match *Item
		for i := range r.Results {
			if it := &r.Results[i]; it.ID == w.Check && it.rawSubject == w.Subject {
				match = it
				e.Results++
			}
		}
		e.Status = waiverState(w, match, e.Results, now)
		if s := resultState(e.Status, match, e.Results); s != "" {
			match.Waiver = &ResultWaiver{Status: s, Level: e.Level, Reason: e.Reason, Expires: e.Expires}
		}
		r.Waivers = append(r.Waivers, e)
	}
}

// waiverState is the state of a known check's waiver; match is the last
// result with its check and subject and n how many there are.
func waiverState(w waiver.Waiver, match *Item, n int, now time.Time) string {
	switch {
	case n > 1:
		return WaiverAmbiguous
	case w.ExpiredAt(now):
		return WaiverExpired
	case n == 0 || !waivable(match.Level):
		return WaiverStale
	case !w.Covers(string(match.Level)):
		return WaiverLevelExceeded
	case w.LongLivedAt(now):
		return WaiverLongLived
	}
	return WaiverApplied
}

// resultState is what an entry state means for its matched result: the
// state to note on it, or "" when no result gets a note. An expired waiver
// notes its result only when there is exactly one and it is a finding.
func resultState(entry string, match *Item, n int) string {
	switch entry {
	case WaiverApplied, WaiverLongLived:
		return WaiverAccepted
	case WaiverLevelExceeded:
		return WaiverLevelExceeded
	case WaiverExpired:
		if n == 1 && waivable(match.Level) {
			return WaiverExpired
		}
	}
	return ""
}

// WaiversLine sums up the waivers file: how many waivers are in each state.
// It is empty when the report has no waivers.
func WaiversLine(ws []WaiverEntry) string {
	if len(ws) == 0 {
		return ""
	}
	n := map[string]int{}
	for _, w := range ws {
		n[w.Status]++
	}
	var parts []string
	for _, s := range []struct{ status, word string }{
		{WaiverApplied, "applied"}, {WaiverLongLived, "long-lived"}, {WaiverExpired, "expired"},
		{WaiverLevelExceeded, "level-exceeded"}, {WaiverStale, "stale"}, {WaiverAmbiguous, "ambiguous"},
		{WaiverUnknownCheck, "for an unknown check"},
	} {
		if n[s.status] > 0 {
			parts = append(parts, fmt.Sprintf("%d %s", n[s.status], s.word))
		}
	}
	return strings.Join(parts, ", ")
}

// WaiversToReview are the waivers that need a decision: every state but
// applied. A long-lived waiver still applies but is listed so its far
// expiry gets a second look.
func WaiversToReview(ws []WaiverEntry) []WaiverEntry {
	var out []WaiverEntry
	for _, w := range ws {
		if w.Status != WaiverApplied {
			out = append(out, w)
		}
	}
	return out
}

// WaiverProblem says in words what is wrong with a waiver that did not
// apply.
func WaiverProblem(w WaiverEntry) string {
	switch w.Status {
	case WaiverExpired:
		return fmt.Sprintf("expired after %s; a finding it covered counts at its real level again", w.Expires)
	case WaiverLongLived:
		return fmt.Sprintf("still applies, but expires %s, more than a year after this audit", w.Expires)
	case WaiverLevelExceeded:
		return fmt.Sprintf("accepts up to %s, but the result is worse, so it counts at its real level; set level: fail only if that is accepted too", w.Level)
	case WaiverAmbiguous:
		return fmt.Sprintf("%d results have this check and subject, so it accepts none of them", w.Results)
	case WaiverStale:
		return "no fail or warn result has this subject; the finding is fixed or the subject is wrong"
	case WaiverUnknownCheck:
		return "no check has this id"
	}
	return w.Status
}

// AcceptedNote is the line a renderer shows for a result's waiver.
func AcceptedNote(w *ResultWaiver) string {
	switch w.Status {
	case WaiverAccepted:
		return fmt.Sprintf("accepted until %s: %s", w.Expires, w.Reason)
	case WaiverLevelExceeded:
		return fmt.Sprintf("not accepted, the waiver covers up to %s only: %s", w.Level, w.Reason)
	}
	return fmt.Sprintf("expired after %s, the finding is back: %s", w.Expires, w.Reason)
}
