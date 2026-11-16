package diff

import (
	"encoding/json"
	"fmt"
	"regexp"
	"sort"
	"strings"

	"github.com/Shironex/stackward/internal/checks"
	"github.com/Shironex/stackward/internal/facts"
	"github.com/Shironex/stackward/internal/report"
)

// Drift kinds.
const (
	DriftListener      = "listener"
	DriftAuthorizedKey = "authorized-key"
	DriftSudoer        = "sudoer"
	DriftRootContainer = "root-container"
)

// The checks whose evidence drift is read from.
const (
	checkListeners = "NET-004" // one result per listening port: binds, class, processes
	checkKeys      = "SSH-014" // one result per user with keys: keys, fingerprints
	checkSudoers   = "USR-004" // one result per sudoers file with NOPASSWD rules: nopasswd
	checkRoot      = "DKR-020" // one result per container: container, root, privileged, public
)

// Drift is one change on the host that matters whatever its level. A
// waiver does not silence drift: accepting it means a new baseline.
type Drift struct {
	Kind    string `json:"kind"`
	Check   string `json:"check"`
	Subject string `json:"subject"`
	// Value names what is new: the port, the key fingerprint, the sudoers
	// principal or the container.
	Value  string `json:"value"`
	Detail string `json:"detail"`
}

// driftChecks are the checks drift is read from, in drift kind order.
var driftChecks = []struct{ id, kind string }{
	{checkListeners, DriftListener}, {checkKeys, DriftAuthorizedKey}, {checkSudoers, DriftSudoer}, {checkRoot, DriftRootContainer},
}

// LostCoverage is a drift check the baseline could judge (some result was
// pass, info, warn or fail) and the new report cannot: all its results are
// unknown or skip, or it has none. Drift of that kind would go unseen, so
// it trips --fail-on-drift like drift does.
type LostCoverage struct {
	Check string `json:"check"`
	Kind  string `json:"kind"`
	// Now is unknown, skip or missing.
	Now    string `json:"now"`
	Detail string `json:"detail"`
}

// coverageLost compares how far each drift check could see.
func coverageLost(old, cur []report.Item) []LostCoverage {
	out := []LostCoverage{}
	for _, c := range driftChecks {
		if judged(old, c.id) != "" {
			continue
		}
		now := judged(cur, c.id)
		if now == "" {
			continue
		}
		out = append(out, LostCoverage{Check: c.id, Kind: c.kind, Now: now,
			Detail: fmt.Sprintf("%s judged the baseline and is %s now: a new %s would not show", c.id, now, driftWord[c.kind])})
	}
	return out
}

// judged returns "" when a result of check id has a level that judges
// (pass, info, warn, fail), else what the check is: unknown, skip or
// missing (no result).
func judged(items []report.Item, id string) string {
	state := "missing"
	for _, it := range items {
		if it.ID != id {
			continue
		}
		switch it.Level {
		case checks.Unknown:
			state = "unknown"
		case checks.Skip:
			if state == "missing" {
				state = "skip"
			}
		default:
			return ""
		}
	}
	return state
}

var driftOrder = map[string]int{DriftListener: 0, DriftAuthorizedKey: 1, DriftSudoer: 2, DriftRootContainer: 3}

// drift derives the drift items from the evidence of the four checks.
func drift(old, cur []report.Item) []Drift {
	out := []Drift{}
	out = append(out, listenerDrift(byCheck(old, checkListeners), byCheck(cur, checkListeners))...)
	out = append(out, keyDrift(byCheck(old, checkKeys), byCheck(cur, checkKeys))...)
	out = append(out, sudoerDrift(byCheck(old, checkSudoers), byCheck(cur, checkSudoers))...)
	out = append(out, rootDrift(byCheck(old, checkRoot), byCheck(cur, checkRoot))...)
	sort.SliceStable(out, func(i, j int) bool {
		a, b := out[i], out[j]
		if a.Kind != b.Kind {
			return driftOrder[a.Kind] < driftOrder[b.Kind]
		}
		if a.Subject != b.Subject {
			return a.Subject < b.Subject
		}
		return a.Value < b.Value
	})
	return out
}

// byCheck maps the results of one check by subject (the first one wins;
// a check gives one result per subject).
func byCheck(items []report.Item, id string) map[string]report.Item {
	m := map[string]report.Item{}
	for _, it := range items {
		if _, seen := m[it.Subject]; it.ID == id && !seen {
			m[it.Subject] = it
		}
	}
	return m
}

// subjects returns the keys of m with prefix, sorted.
func subjects(m map[string]report.Item, prefix string) []string {
	var out []string
	for s := range m {
		if strings.HasPrefix(s, prefix) {
			out = append(out, s)
		}
	}
	sort.Strings(out)
	return out
}

// listenerDrift: a port that listens beyond loopback now and did not, or
// that now listens on a wildcard or public address and did not before. A
// loopback only listener is reachable from this machine alone and is not
// drift.
func listenerDrift(old, cur map[string]report.Item) []Drift {
	var out []Drift
	for _, s := range subjects(cur, "port:") {
		n := cur[s]
		class := evString(n, "class")
		who := ""
		if procs := evStrings(n, "processes"); len(procs) > 0 {
			who = " (" + strings.Join(procs, ", ") + ")"
		}
		d := Drift{Kind: DriftListener, Check: checkListeners, Subject: s, Value: strings.TrimPrefix(s, "port:")}
		o, had := old[s]
		switch {
		case facts.BindClass(class) == facts.BindLoopback:
			continue // reachable from this machine only
		case !had:
			d.Detail = fmt.Sprintf("new listener on %s addresses%s", orUnknown(class), who)
		case facts.BindClass(class).Exposed() && !facts.BindClass(evString(o, "class")).Exposed():
			d.Detail = fmt.Sprintf("now listens on %s addresses%s, was %s", class, who, orUnknown(evString(o, "class")))
		default:
			continue
		}
		out = append(out, d)
	}
	return out
}

// keyDrift: a fingerprint a user's authorized keys did not have. When
// either report has no fingerprints (one written before they were kept),
// a key count that grew is reported instead.
func keyDrift(old, cur map[string]report.Item) []Drift {
	var out []Drift
	for _, s := range subjects(cur, "user:") {
		n := cur[s]
		o, had := old[s]
		newFps, newHasFps := evList(n, "fingerprints")
		oldFps, oldHasFps := evList(o, "fingerprints")
		if newHasFps && (oldHasFps || !had) {
			known := map[string]bool{}
			for _, fp := range oldFps {
				known[fp] = true
			}
			for _, fp := range newFps {
				if !known[fp] {
					out = append(out, Drift{Kind: DriftAuthorizedKey, Check: checkKeys, Subject: s, Value: fp,
						Detail: "new authorized key for " + strings.TrimPrefix(s, "user:")})
				}
			}
			continue
		}
		now, okNow := evInt(n, "keys")
		was, okWas := 0, true
		if had {
			was, okWas = evInt(o, "keys")
		}
		if okNow && okWas && now > was {
			out = append(out, Drift{Kind: DriftAuthorizedKey, Check: checkKeys, Subject: s,
				Detail: fmt.Sprintf("%s has %s, was %d (a report has no fingerprints to compare)", strings.TrimPrefix(s, "user:"), count(now, "authorized key", "authorized keys"), was)})
		}
	}
	return out
}

// lineSuffix is the " (line N)" USR-004 puts after each NOPASSWD principal.
var lineSuffix = regexp.MustCompile(` \(line [0-9]+\)$`)

// sudoerDrift: a principal with a NOPASSWD sudo rule that no sudoers file
// of the baseline gave one. Moving a rule to another file or line is not
// drift.
func sudoerDrift(old, cur map[string]report.Item) []Drift {
	known := map[string]bool{}
	for _, s := range subjects(old, "") {
		for _, p := range evStrings(old[s], "nopasswd") {
			known[lineSuffix.ReplaceAllString(p, "")] = true
		}
	}
	var out []Drift
	for _, s := range subjects(cur, "") {
		for _, p := range evStrings(cur[s], "nopasswd") {
			who := lineSuffix.ReplaceAllString(p, "")
			if known[who] {
				continue
			}
			known[who] = true
			out = append(out, Drift{Kind: DriftSudoer, Check: checkSudoers, Subject: s, Value: who,
				Detail: fmt.Sprintf("new NOPASSWD sudo rule for %s in %s", who, strings.TrimPrefix(s, "file:"))})
		}
	}
	return out
}

// rootDrift: a container that runs as root now and did not, or was not
// there.
func rootDrift(old, cur map[string]report.Item) []Drift {
	var out []Drift
	for _, s := range subjects(cur, "container:") {
		n := cur[s]
		if !evBool(n, "root") || evBool(old[s], "root") {
			continue
		}
		name := evString(n, "container")
		if name == "" {
			name = strings.TrimPrefix(s, "container:")
		}
		var extra []string
		if evBool(n, "privileged") {
			extra = append(extra, "privileged")
		}
		if evBool(n, "public") {
			extra = append(extra, "reachable from outside")
		}
		detail := name + " runs as root"
		if _, had := old[s]; had {
			detail = name + " runs as root now, and did not"
		}
		if len(extra) > 0 {
			detail += " (" + strings.Join(extra, ", ") + ")"
		}
		out = append(out, Drift{Kind: DriftRootContainer, Check: checkRoot, Subject: s, Value: name, Detail: detail})
	}
	return out
}

func orUnknown(s string) string {
	if s == "" {
		return "unknown"
	}
	return s
}

// The evidence helpers read decoded JSON values defensively: a field of
// the wrong type reads as absent.

func evString(it report.Item, k string) string {
	s, _ := it.Evidence[k].(string)
	return s
}

func evBool(it report.Item, k string) bool {
	b, _ := it.Evidence[k].(bool)
	return b
}

func evInt(it report.Item, k string) (int, bool) {
	switch v := it.Evidence[k].(type) {
	case float64:
		return int(v), true
	case int:
		return v, true
	case json.Number:
		n, err := v.Int64()
		return int(n), err == nil
	}
	return 0, false
}

// evList returns the strings of a list field and whether the field is
// there at all.
func evList(it report.Item, k string) ([]string, bool) {
	raw, ok := it.Evidence[k]
	if !ok {
		return nil, false
	}
	var out []string
	switch v := raw.(type) {
	case []any:
		for _, e := range v {
			if s, ok := e.(string); ok {
				out = append(out, s)
			}
		}
	case []string:
		out = v
	default:
		return nil, false
	}
	return out, true
}

func evStrings(it report.Item, k string) []string {
	out, _ := evList(it, k)
	return out
}
