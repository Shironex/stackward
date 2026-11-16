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
)

// States of an entry of the waivers file (WaiverEntry.Status) besides
// WaiverExpired.
const (
	// WaiverApplied: the waiver accepted at least one finding.
	WaiverApplied = "applied"
	// WaiverStale: the check is known but no fail or warn result has the
	// waiver's subject (the finding was fixed, or the subject is wrong).
	WaiverStale = "stale"
	// WaiverUnknownCheck: no check has the waiver's id.
	WaiverUnknownCheck = "unknown-check"
)

// ResultWaiver is the waiver that matched a result.
type ResultWaiver struct {
	// Status is accepted or expired.
	Status string `json:"status"`
	Reason string `json:"reason"`
	// Expires is the last day the waiver holds, YYYY-MM-DD (UTC).
	Expires string `json:"expires"`
}

// WaiverEntry is one entry of the waivers file and what became of it.
type WaiverEntry struct {
	Check   string `json:"check"`
	Subject string `json:"subject"`
	Reason  string `json:"reason"`
	Expires string `json:"expires"`
	// Status is applied, expired, stale or unknown-check.
	Status string `json:"status"`
	// Results is how many fail or warn results the waiver matched: the
	// ones it accepted, or for an expired waiver the ones that are back.
	Results int `json:"results"`
}

// Accepted reports whether a waiver accepts this result.
func (it Item) Accepted() bool { return it.Waiver != nil && it.Waiver.Status == WaiverAccepted }

// waivable reports whether a waiver may accept a result of level l. Only
// findings can be accepted: an unknown is never turned into anything that
// reads as settled, and a pass needs no waiver.
func waivable(l checks.Level) bool { return l == checks.Fail || l == checks.Warn }

// applyWaivers matches every waiver to the results with its check id and
// exact subject, marks those results and lists the waivers with their state
// in r.Waivers. now is when the facts were collected, so a replayed facts
// file judges expiry the same way every time. Evidence and levels are never
// touched.
func applyWaivers(r *Report, ws []waiver.Waiver, cat *catalog.Catalog, now time.Time) {
	for _, w := range ws {
		e := WaiverEntry{
			Check: w.Check, Subject: redact.String(w.Subject), Reason: redact.String(w.Reason), Expires: w.Expires,
		}
		if _, known := cat.Lookup(w.Check); !known {
			e.Status = WaiverUnknownCheck
			r.Waivers = append(r.Waivers, e)
			continue
		}
		state := WaiverAccepted
		if w.ExpiredAt(now) {
			state = WaiverExpired
		}
		for i := range r.Results {
			it := &r.Results[i]
			if it.ID != w.Check || it.Subject != e.Subject || !waivable(it.Level) {
				continue
			}
			it.Waiver = &ResultWaiver{Status: state, Reason: e.Reason, Expires: e.Expires}
			e.Results++
		}
		switch {
		case state == WaiverExpired:
			e.Status = WaiverExpired
		case e.Results == 0:
			e.Status = WaiverStale
		default:
			e.Status = WaiverApplied
		}
		r.Waivers = append(r.Waivers, e)
	}
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
		{WaiverApplied, "applied"}, {WaiverExpired, "expired"}, {WaiverStale, "stale"}, {WaiverUnknownCheck, "for an unknown check"},
	} {
		if n[s.status] > 0 {
			parts = append(parts, fmt.Sprintf("%d %s", n[s.status], s.word))
		}
	}
	return strings.Join(parts, ", ")
}

// WaiversToReview are the waivers that did not apply: expired, stale or for
// an unknown check. Each needs a decision (renew, fix or remove).
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
		if w.Results > 0 {
			return fmt.Sprintf("expired after %s; %s back at its real level", w.Expires, plural(w.Results, "finding is", "findings are"))
		}
		return fmt.Sprintf("expired after %s", w.Expires)
	case WaiverStale:
		return "no fail or warn result has this subject; the finding is fixed or the subject is wrong"
	case WaiverUnknownCheck:
		return "no check has this id"
	}
	return w.Status
}

// AcceptedNote is the line a renderer shows for a result's waiver.
func AcceptedNote(w *ResultWaiver) string {
	if w.Status == WaiverAccepted {
		return fmt.Sprintf("accepted until %s: %s", w.Expires, w.Reason)
	}
	return fmt.Sprintf("expired after %s, the finding is back: %s", w.Expires, w.Reason)
}
