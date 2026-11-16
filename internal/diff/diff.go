// Package diff compares two report.v1 documents of one host: the results
// that were added, removed or changed (level or waiver state), and drift,
// the changes that matter whatever their level: a new listener, a new
// authorized key, a new sudoer, a new root container. It only reads the
// two reports; the JSON shape is schema/diff.v1.json.
package diff

import (
	"errors"
	"fmt"
	"sort"

	"github.com/Shironex/stackward/internal/catalog"
	"github.com/Shironex/stackward/internal/checks"
	"github.com/Shironex/stackward/internal/report"
)

// SchemaID names the JSON shape of a diff.
const SchemaID = "stackward.diff.v1"

// Kinds of a change.
const (
	Added   = "added"
	Removed = "removed"
	Changed = "changed"
)

// What changed about a result that is in both reports.
const (
	WhatLevel  = "level"
	WhatWaiver = "waiver"
)

// Diff is the diff.v1 document.
type Diff struct {
	Schema string      `json:"schema"`
	Tool   report.Tool `json:"tool"`
	// Old is the baseline, New the report compared with it.
	Old Side `json:"old"`
	New Side `json:"new"`
	// SameHost is false only when --force-host compared two hosts.
	SameHost bool `json:"same_host"`
	// Notes are caveats the reader needs (root on one side only, another
	// profile, another stackward version).
	Notes   []string `json:"notes,omitempty"`
	Summary Summary  `json:"summary"`
	Drift   []Drift  `json:"drift"`
	// CoverageLost lists the drift checks the baseline could judge and the
	// new report cannot, so drift of that kind would go unseen.
	CoverageLost []LostCoverage `json:"coverage_lost"`
	Changes      []Change       `json:"changes"`
}

// Side describes one of the two reports.
type Side struct {
	GeneratedAt string `json:"generated_at"`
	ToolVersion string `json:"tool_version"`
	// Host is the hostname hash; a report written with --show-hostname is
	// hashed here, so a diff never prints a hostname.
	Host    string `json:"host"`
	Profile string `json:"profile"`
	Root    bool   `json:"root"`
}

// Summary counts the diff.
type Summary struct {
	Drift        int `json:"drift"`
	CoverageLost int `json:"coverage_lost"`
	Added        int `json:"added"`
	Removed      int `json:"removed"`
	Changed      int `json:"changed"`
	// NewFindings counts changes with NewFinding set.
	NewFindings int `json:"new_findings"`
}

// Change is one result that was added, removed or changed.
type Change struct {
	Kind     string `json:"kind"`
	ID       string `json:"id"`
	Group    string `json:"group"`
	Title    string `json:"title"`
	Severity string `json:"severity"`
	Subject  string `json:"subject"`
	// What lists what changed (level, waiver); set for changed only.
	What []string `json:"what,omitempty"`
	Old  *State   `json:"old,omitempty"`
	New  *State   `json:"new,omitempty"`
	// NewFinding: the result is an open fail or warn now (not accepted by
	// a waiver) and was not open before, or was open at a milder level.
	NewFinding bool `json:"new_finding"`
}

// State is a result as one report has it.
type State struct {
	Level checks.Level `json:"level"`
	// Waiver is the result's waiver status (accepted, expired,
	// level-exceeded), empty when no waiver matched it.
	Waiver string `json:"waiver,omitempty"`
	// Expires is the waiver's last day.
	Expires string `json:"expires,omitempty"`
	Message string `json:"message"`
}

// Options tune Compare.
type Options struct {
	// Version is this stackward's version, written into the diff.
	Version string
	// ForceHost compares reports from different or unknown hosts.
	ForceHost bool
}

// ErrHost is returned when the reports are not from the same host.
var ErrHost = errors.New("host mismatch")

// Compare diffs two loaded reports. Both must come from LoadReport (or
// report.Build), so their strings are redacted.
func Compare(old, cur *report.Report, o Options) (*Diff, error) {
	d := &Diff{
		Schema: SchemaID, Tool: report.Tool{Name: "stackward", Version: o.Version},
		Old: side(old), New: side(cur), Drift: []Drift{}, CoverageLost: []LostCoverage{}, Changes: []Change{},
	}
	d.SameHost = d.Old.Host != "" && d.Old.Host == d.New.Host
	if !d.SameHost && !o.ForceHost {
		if d.Old.Host == "" || d.New.Host == "" {
			return nil, fmt.Errorf("%w: a report names no host, so they cannot be matched; pass --force-host to compare them anyway", ErrHost)
		}
		return nil, fmt.Errorf("%w: the reports are from different hosts (%s and %s); pass --force-host to compare them anyway", ErrHost, d.Old.Host, d.New.Host)
	}
	d.Notes = notes(d)
	d.Changes = changes(old.Results, cur.Results)
	d.Drift = drift(old.Results, cur.Results)
	d.Summary.Drift = len(d.Drift)
	d.CoverageLost = coverageLost(old.Results, cur.Results)
	d.Summary.CoverageLost = len(d.CoverageLost)
	for _, c := range d.Changes {
		switch c.Kind {
		case Added:
			d.Summary.Added++
		case Removed:
			d.Summary.Removed++
		default:
			d.Summary.Changed++
		}
		if c.NewFinding {
			d.Summary.NewFindings++
		}
	}
	return d, nil
}

func side(r *report.Report) Side {
	s := Side{GeneratedAt: r.GeneratedAt, ToolVersion: r.Tool.Version, Host: r.Host.HostnameHash,
		Profile: string(r.Profile.Name), Root: r.Coverage.Root}
	if s.Host == "" && r.Host.Hostname != "" {
		s.Host = report.HashHostname(r.Host.Hostname)
	}
	return s
}

// notes are the caveats of comparing these two reports.
func notes(d *Diff) []string {
	var out []string
	if !d.SameHost {
		out = append(out, "the reports are not known to be from the same host (compared with --force-host)")
	}
	switch {
	case d.Old.Root && !d.New.Root:
		out = append(out, "the baseline ran as root and the new report did not: results that need root can read as removed or unknown, not fixed")
	case !d.Old.Root && d.New.Root:
		out = append(out, "the new report ran as root and the baseline did not: some additions and drift may only be newly visible")
	}
	if d.Old.Profile != d.New.Profile {
		out = append(out, fmt.Sprintf("the ingress profile changed from %s to %s, which changes how exposure is judged", d.Old.Profile, d.New.Profile))
	}
	if d.Old.ToolVersion != d.New.ToolVersion {
		out = append(out, fmt.Sprintf("the reports come from different stackward versions (%s and %s): changed checks can show as changes", d.Old.ToolVersion, d.New.ToolVersion))
	}
	if d.Old.GeneratedAt != "" && d.New.GeneratedAt != "" && d.New.GeneratedAt < d.Old.GeneratedAt {
		out = append(out, "the new report is older than the baseline; check the order of the files")
	}
	return out
}

// key matches a result across reports: check id and subject.
type key struct{ id, subject string }

// index groups results by key, in report order.
func index(items []report.Item) (map[key][]report.Item, []key) {
	m := map[key][]report.Item{}
	var order []key
	for _, it := range items {
		k := key{it.ID, it.Subject}
		if _, seen := m[k]; !seen {
			order = append(order, k)
		}
		m[k] = append(m[k], it)
	}
	return m, order
}

// changes pairs the results of both reports by check id and subject (the
// n-th result with a key in one report with the n-th in the other) and
// keeps what changed in a way a reader acts on.
func changes(old, cur []report.Item) []Change {
	om, oorder := index(old)
	nm, norder := index(cur)
	out := []Change{}
	for _, k := range norder {
		for i, n := range nm[k] {
			if i >= len(om[k]) {
				if noteworthy(n) {
					out = append(out, newChange(Added, n, nil, &n))
				}
				continue
			}
			o := om[k][i]
			if c, ok := changed(o, n); ok {
				out = append(out, c)
			}
		}
	}
	for _, k := range oorder {
		for i, o := range om[k] {
			if i >= len(nm[k]) && noteworthy(o) {
				out = append(out, newChange(Removed, o, &o, nil))
			}
		}
	}
	sort.SliceStable(out, func(i, j int) bool {
		a, b := out[i], out[j]
		if ga, gb := catalog.GroupRank(a.Group), catalog.GroupRank(b.Group); ga != gb {
			return ga < gb
		}
		if a.ID != b.ID {
			return a.ID < b.ID
		}
		return a.Subject < b.Subject
	})
	return out
}

// noteworthy results are listed when they appear or disappear: findings,
// unknowns and anything a waiver matched. A pass, info or skip result
// coming or going (a new container's passing checks) is not listed.
func noteworthy(it report.Item) bool {
	return isFinding(it.Level) || it.Level == checks.Unknown || it.Waiver != nil
}

func isFinding(l checks.Level) bool { return l == checks.Fail || l == checks.Warn }

// open reports whether a result counts against the host: a fail or warn
// that no waiver accepts.
func open(it report.Item) bool { return isFinding(it.Level) && !it.Accepted() }

// changed compares the same result in both reports.
func changed(o, n report.Item) (Change, bool) {
	var what []string
	if o.Level != n.Level && (noteworthy(o) || noteworthy(n)) {
		what = append(what, WhatLevel)
	}
	if waiverKey(o) != waiverKey(n) {
		what = append(what, WhatWaiver)
	}
	if len(what) == 0 {
		return Change{}, false
	}
	c := newChange(Changed, n, &o, &n)
	c.What = what
	return c, true
}

func waiverKey(it report.Item) string {
	if it.Waiver == nil {
		return ""
	}
	return it.Waiver.Status + "|" + it.Waiver.Level + "|" + it.Waiver.Expires
}

// levelRank orders the finding levels; NewFinding uses it to tell a warn
// that became a fail.
var levelRank = map[checks.Level]int{checks.Warn: 1, checks.Fail: 2}

func newChange(kind string, it report.Item, o, n *report.Item) Change {
	c := Change{Kind: kind, ID: it.ID, Group: it.Group, Title: it.Title, Severity: string(it.Severity), Subject: it.Subject}
	if c.Group == "" {
		c.Group = catalog.GroupOf(it.ID)
	}
	if o != nil {
		c.Old = state(*o)
	}
	if n != nil {
		c.New = state(*n)
		c.NewFinding = open(*n) && (o == nil || !open(*o) || levelRank[n.Level] > levelRank[o.Level])
	}
	return c
}

func state(it report.Item) *State {
	s := &State{Level: it.Level, Message: it.Message}
	if it.Waiver != nil {
		s.Waiver, s.Expires = it.Waiver.Status, it.Waiver.Expires
	}
	return s
}

// FailOn is the --fail-on-drift threshold.
type FailOn string

// Thresholds of --fail-on-drift.
const (
	// FailOnAny: a new fail or warn finding, any drift, or a drift
	// check that lost coverage.
	FailOnAny FailOn = "any"
	// FailOnFail: a new fail finding, any drift, or a drift check that
	// lost coverage.
	FailOnFail FailOn = "fail"
	// FailOnDrift: drift, or a drift check that lost coverage.
	FailOnDrift FailOn = "drift"
	// FailOnNever: always exit 0.
	FailOnNever FailOn = "never"
)

// ParseFailOn checks a --fail-on-drift value.
func ParseFailOn(s string) (FailOn, error) {
	switch f := FailOn(s); f {
	case FailOnAny, FailOnFail, FailOnDrift, FailOnNever:
		return f, nil
	}
	return "", fmt.Errorf("--fail-on-drift must be any, fail, drift or never, not %q", s)
}

// Tripped reports whether the diff reaches the threshold.
func (d *Diff) Tripped(t FailOn) bool {
	if t == FailOnNever {
		return false
	}
	if len(d.Drift) > 0 || len(d.CoverageLost) > 0 {
		return true
	}
	for _, c := range d.Changes {
		if !c.NewFinding {
			continue
		}
		if t == FailOnAny || t == FailOnFail && c.New.Level == checks.Fail {
			return true
		}
	}
	return false
}

// ExitCode is report.ExitFindings when the diff reaches the threshold.
func (d *Diff) ExitCode(t FailOn) int {
	if d.Tripped(t) {
		return report.ExitFindings
	}
	return report.ExitOK
}
