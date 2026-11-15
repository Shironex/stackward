// Package checks holds the pure checks: functions from Facts to results.
// Checks never touch the host, the clock or the network; everything they
// judge comes from their Input, so a saved facts file always gives the same
// report. One file per group (sys.go, ssh.go, ...), each registering its
// checks from init.
package checks

import (
	"fmt"
	"sort"
	"sync"

	"github.com/Shironex/stackward/internal/catalog"
	"github.com/Shironex/stackward/internal/facts"
	"github.com/Shironex/stackward/internal/profile"
)

// Level is the outcome of one check for one subject.
type Level string

// Levels. Unknown means "could not inspect" and is never counted as a pass.
const (
	Pass    Level = "pass"
	Warn    Level = "warn"
	Fail    Level = "fail"
	Unknown Level = "unknown"
	Skip    Level = "skip" // not applicable on this host
	Info    Level = "info" // informational, no judgement
)

// Levels lists every level in report order (worst first).
var Levels = []Level{Fail, Warn, Unknown, Info, Pass, Skip}

// Valid reports whether l is a known level.
func (l Level) Valid() bool {
	for _, v := range Levels {
		if l == v {
			return true
		}
	}
	return false
}

// Result is one finding: one check, one subject.
type Result struct {
	// ID is filled by Evaluate from the check; checks may leave it empty.
	ID string `json:"id"`
	// Subject names what the result is about: "host" (the default),
	// "container:<project>/<service>", "port:<proto>/<port>",
	// "file:<path>", "user:<name>".
	Subject string `json:"subject"`
	Level   Level  `json:"level"`
	// Message is one line for a human, specific to this host.
	Message string `json:"message"`
	// Evidence is the data the verdict rests on. Each check keeps a fixed
	// set of keys. Never put secret values here; output is redacted as a
	// safety net, not as the plan.
	Evidence map[string]any `json:"evidence,omitempty"`
}

// Input is everything a check may look at.
type Input struct {
	Facts *facts.Facts
	// Profile is the ingress profile, inferred or given with --profile.
	Profile profile.Name
}

// Check is one registered check.
type Check struct {
	// ID must have a catalog entry (internal/catalog/data/<group>.json).
	ID string
	// Run returns at least one result. Returning none, panicking or
	// returning an invalid level all turn into an unknown result.
	Run func(Input) []Result
}

var (
	mu       sync.Mutex
	registry = map[string]Check{}
)

// Register adds a check. Call it from init in the group file. It panics on
// a malformed or duplicate id, so a broken registration fails every test.
func Register(c Check) {
	mu.Lock()
	defer mu.Unlock()
	if !catalog.IDPattern.MatchString(c.ID) {
		panic(fmt.Sprintf("checks: invalid id %q", c.ID))
	}
	if c.Run == nil {
		panic(fmt.Sprintf("checks: %s has no Run", c.ID))
	}
	if _, dup := registry[c.ID]; dup {
		panic(fmt.Sprintf("checks: %s registered twice", c.ID))
	}
	registry[c.ID] = c
}

// All returns every registered check in report order.
func All() []Check {
	mu.Lock()
	defer mu.Unlock()
	out := make([]Check, 0, len(registry))
	for _, c := range registry {
		out = append(out, c)
	}
	sort.Slice(out, func(i, j int) bool { return catalog.Less(out[i].ID, out[j].ID) })
	return out
}

// Evaluate runs every registered check over in.
func Evaluate(in Input) []Result { return EvaluateChecks(All(), in) }

// EvaluateChecks runs the given checks and returns results in report order:
// group, then id, then subject. It enforces the rules every check relies
// on, so one broken check cannot hide its own failure as a pass.
func EvaluateChecks(cs []Check, in Input) []Result {
	var out []Result
	for _, c := range cs {
		for _, r := range runSafe(c, in) {
			r.ID = c.ID
			if r.Subject == "" {
				r.Subject = "host"
			}
			if !r.Level.Valid() {
				r = Result{ID: c.ID, Subject: r.Subject, Level: Unknown,
					Message: fmt.Sprintf("check returned invalid level %q", r.Level)}
			}
			out = append(out, r)
		}
	}
	sort.SliceStable(out, func(i, j int) bool {
		if out[i].ID != out[j].ID {
			return catalog.Less(out[i].ID, out[j].ID)
		}
		return out[i].Subject < out[j].Subject
	})
	return out
}

func runSafe(c Check, in Input) (rs []Result) {
	defer func() {
		if r := recover(); r != nil {
			rs = []Result{{Level: Unknown, Message: fmt.Sprintf("check failed internally: %v", r)}}
		}
	}()
	rs = c.Run(in)
	if len(rs) == 0 {
		rs = []Result{{Level: Unknown, Message: "check produced no result"}}
	}
	return rs
}

// NotInspected returns the unknown result for a check whose facts are
// missing, saying why in words a user can act on (for example "needs root;
// run with sudo for full coverage"). collector is the collector that owns
// the missing facts.
func NotInspected(f *facts.Facts, collector string) Result {
	r := Result{Level: Unknown, Evidence: map[string]any{"collector": collector}}
	st, ok := f.CollectorStatus(collector)
	switch {
	case !ok:
		r.Message = fmt.Sprintf("not inspected: the %s collector did not run", collector)
	case st.Status == facts.StatusSkipped:
		r.Message = fmt.Sprintf("not inspected: %s collector skipped (%s)", collector, st.Reason)
	case st.Error != "":
		r.Message = fmt.Sprintf("not inspected: %s collector %s: %s", collector, st.Status, st.Error)
	default:
		r.Message = fmt.Sprintf("not inspected: %s collector recorded nothing", collector)
	}
	r.Evidence["collector_status"] = string(st.Status)
	if !ok {
		r.Evidence["collector_status"] = "missing"
	}
	return r
}

// One wraps a single result, for checks about the host as a whole.
func One(level Level, message string, evidence map[string]any) []Result {
	return []Result{{Level: level, Message: message, Evidence: evidence}}
}
