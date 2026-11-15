// Package plan turns an audit into a plan: the exact changes that would fix
// the findings, as data, without changing anything. Generators (one per
// step id) are pure functions of the facts and the check results; Build runs
// them, applies policy vetoes, redacts the result and returns the plan.v1
// document described by schema/plan.v1.json. Change both together.
package plan

import (
	"fmt"

	"github.com/Shironex/stackward/internal/checks"
	"github.com/Shironex/stackward/internal/redact"
	"github.com/Shironex/stackward/internal/report"
	"github.com/Shironex/stackward/internal/sandbox"
)

// SchemaID names the JSON shape. Adding an optional field keeps it; a
// rename, a removal or a changed meaning needs plan.v2.
const SchemaID = "stackward.plan.v1"

// Source kinds: where the facts and results came from.
const (
	FromLive        = "live"         // audited this host now
	FromFacts       = "facts"        // a saved facts file (--facts)
	FromReport      = "report"       // a saved report alone (--report)
	FromReportFacts = "report+facts" // a saved report and its facts file
)

// Plan is the plan.v1 document.
type Plan struct {
	Schema string      `json:"schema"`
	Tool   report.Tool `json:"tool"`
	// GeneratedAt is when the facts behind the plan were collected (the
	// report's generated_at), so the same input gives the same plan.
	GeneratedAt string         `json:"generated_at"`
	Host        report.Host    `json:"host"`
	Source      Source         `json:"source"`
	Sandbox     sandbox.Status `json:"sandbox"`
	Summary     Summary        `json:"summary"`
	// Steps are the planned changes, safe first.
	Steps []Step `json:"steps"`
	// Skipped lists every generator that planned nothing, and why.
	Skipped []Skipped `json:"skipped"`
}

// Source says what the plan was made from.
type Source struct {
	Kind string `json:"kind"`
	// Facts is false when only a report was given: every step that needs
	// file contents is then skipped as unknown.
	Facts  bool         `json:"facts"`
	Report SourceReport `json:"report"`
}

// SourceReport identifies the report the plan answers: the one loaded with
// --report, or the one evaluated in process.
type SourceReport struct {
	Schema      string         `json:"schema"`
	ToolVersion string         `json:"tool_version"`
	GeneratedAt string         `json:"generated_at"`
	Profile     report.Profile `json:"profile"`
	Summary     report.Summary `json:"summary"`
}

// Summary counts the planned steps.
type Summary struct {
	Steps          int `json:"steps"`
	Safe           int `json:"safe"`
	Networking     int `json:"networking"`
	AccessCritical int `json:"access_critical"`
	OptIn          int `json:"opt_in"`
	// Restarts lists every service a planned step restarts, in plan order.
	Restarts []string `json:"restarts"`
	Skipped  int      `json:"skipped"`
}

// Options carries what the plan needs beyond the input.
type Options struct {
	Version    string
	Sandbox    sandbox.Status
	SourceKind string
	// Vetoes are policies that may refuse a planned step.
	Vetoes []Veto
}

// Build runs every registered generator over in and assembles the plan.
// rep is the report the plan answers (loaded or evaluated in process); it
// gives the host, the time and the source fields. Every free text field and
// all file content pass through redaction here.
func Build(in Input, rep *report.Report, o Options) *Plan {
	return BuildWith(Generators(), in, rep, o)
}

// BuildWith is Build over an explicit generator list (tests).
func BuildWith(gens []Generator, in Input, rep *report.Report, o Options) *Plan {
	p := &Plan{
		Schema:      SchemaID,
		Tool:        report.Tool{Name: "stackward", Version: o.Version},
		GeneratedAt: rep.GeneratedAt,
		Host:        rep.Host,
		Source: Source{
			Kind:  o.SourceKind,
			Facts: in.Facts != nil,
			Report: SourceReport{
				Schema: rep.Schema, ToolVersion: rep.Tool.Version, GeneratedAt: rep.GeneratedAt,
				Profile: rep.Profile, Summary: rep.Summary,
			},
		},
		Sandbox: o.Sandbox,
		Steps:   []Step{},
		Skipped: []Skipped{},
	}
	p.Sandbox.Reason = redact.String(p.Sandbox.Reason)
	for _, g := range gens {
		out := g.Plan(in)
		if out.Step == nil {
			p.Skipped = append(p.Skipped, skipped(g, out.Kind, out.Reason))
			continue
		}
		s := complete(g, *out.Step)
		if reason := vetoed(o.Vetoes, s); reason != "" {
			p.Skipped = append(p.Skipped, skipped(g, SkipRefused, reason))
			continue
		}
		p.Steps = append(p.Steps, redactStep(s))
	}
	p.summarize()
	return p
}

// ResultsFromReport turns report items back into check results, so a saved
// report can drive the generators.
func ResultsFromReport(rep *report.Report) []checks.Result {
	out := make([]checks.Result, 0, len(rep.Results))
	for _, it := range rep.Results {
		out = append(out, checks.Result{ID: it.ID, Subject: it.Subject, Level: it.Level, Message: it.Message})
	}
	return out
}

// complete fills the fields a generator owns and normalizes empty lists so
// the JSON always has the same shape.
func complete(g Generator, s Step) Step {
	s.ID, s.Title, s.Risk, s.OptIn = g.ID, g.Title, g.Risk, g.OptIn
	if !subset(s.Fixes, g.Fixes) || len(s.Fixes) == 0 {
		s.Fixes = g.Fixes
	}
	s.Fixes = append([]string{}, s.Fixes...)
	s.Restarts = nonNil(s.Restarts)
	s.Touches = nonNil(s.Touches)
	s.Notes = nonNil(s.Notes)
	if s.Edits == nil {
		s.Edits = []FileEdit{}
	}
	if s.Commands == nil {
		s.Commands = []Command{}
	}
	if s.Undo.Commands == nil {
		s.Undo.Commands = []Command{}
	}
	return s
}

func skipped(g Generator, kind, reason string) Skipped {
	return Skipped{ID: g.ID, Title: g.Title, Fixes: append([]string{}, g.Fixes...), Kind: kind, Reason: redact.String(reason)}
}

func vetoed(vetoes []Veto, s Step) string {
	for _, v := range vetoes {
		if reason := v(s); reason != "" {
			return reason
		}
	}
	return ""
}

// redactStep masks secret shaped values in every free text field. Hashes
// are left alone: they were taken before redaction and say what the host
// really holds.
func redactStep(s Step) Step {
	s.Title = redact.String(s.Title)
	s.Touches = redactAll(s.Touches)
	s.Notes = redactAll(s.Notes)
	s.Commands = redactCommands(s.Commands)
	s.Undo.Description = redact.String(s.Undo.Description)
	s.Undo.Commands = redactCommands(s.Undo.Commands)
	edits := make([]FileEdit, len(s.Edits))
	for i, e := range s.Edits {
		old, nw, diff := redact.String(e.Old), redact.String(e.New), redact.String(e.Diff)
		if old != e.Old || nw != e.New || diff != e.Diff {
			e.Redacted = true
		}
		e.Path, e.Old, e.New, e.Diff = redact.String(e.Path), old, nw, diff
		edits[i] = e
	}
	s.Edits = edits
	return s
}

func redactCommands(cs []Command) []Command {
	out := make([]Command, len(cs))
	for i, c := range cs {
		out[i] = Command{Args: redactAll(c.Args), Why: redact.String(c.Why)}
	}
	return out
}

func redactAll(ss []string) []string {
	out := make([]string, len(ss))
	for i, s := range ss {
		out[i] = redact.String(s)
	}
	return out
}

func (p *Plan) summarize() {
	p.Summary.Restarts = []string{}
	seen := map[string]bool{}
	for _, s := range p.Steps {
		p.Summary.Steps++
		switch s.Risk {
		case Safe:
			p.Summary.Safe++
		case Networking:
			p.Summary.Networking++
		case AccessCritical:
			p.Summary.AccessCritical++
		}
		if s.OptIn {
			p.Summary.OptIn++
		}
		for _, r := range s.Restarts {
			if !seen[r] {
				seen[r] = true
				p.Summary.Restarts = append(p.Summary.Restarts, r)
			}
		}
	}
	p.Summary.Skipped = len(p.Skipped)
}

// Validate checks the invariants every plan must keep, whatever produced
// it: unique known step ids, a risk class, the checks fixed, and edits whose
// hashes match their content unless redacted. Apply will refuse a plan that
// fails it; tests run it on every golden plan.
func (p *Plan) Validate() error {
	seen := map[string]bool{}
	for _, s := range p.Steps {
		if seen[s.ID] {
			return fmt.Errorf("step %s appears twice", s.ID)
		}
		seen[s.ID] = true
		g, ok := Lookup(s.ID)
		if !ok {
			return fmt.Errorf("step %s is not a known step", s.ID)
		}
		if s.Risk != g.Risk {
			return fmt.Errorf("step %s: risk %q, the step is %q", s.ID, s.Risk, g.Risk)
		}
		if len(s.Fixes) == 0 || !subset(s.Fixes, g.Fixes) {
			return fmt.Errorf("step %s: fixes %v are not among %v", s.ID, s.Fixes, g.Fixes)
		}
		if len(s.Edits) == 0 && len(s.Commands) == 0 {
			return fmt.Errorf("step %s changes nothing", s.ID)
		}
		for _, e := range s.Edits {
			if err := e.validate(); err != nil {
				return fmt.Errorf("step %s: %w", s.ID, err)
			}
		}
	}
	return nil
}

func (e FileEdit) validate() error {
	switch e.Action {
	case Create:
		if e.OldSHA256 != "" || e.Old != "" {
			return fmt.Errorf("%s: a created file has no old content", e.Path)
		}
	case Replace:
		if !e.Redacted && e.OldSHA256 != sha(e.Old) {
			return fmt.Errorf("%s: old content does not match old_sha256", e.Path)
		}
	default:
		return fmt.Errorf("%s: unknown action %q", e.Path, e.Action)
	}
	if !e.Redacted && e.NewSHA256 != sha(e.New) {
		return fmt.Errorf("%s: new content does not match new_sha256", e.Path)
	}
	return nil
}

func subset(a, b []string) bool {
	in := map[string]bool{}
	for _, s := range b {
		in[s] = true
	}
	for _, s := range a {
		if !in[s] {
			return false
		}
	}
	return true
}

func nonNil(s []string) []string {
	if s == nil {
		return []string{}
	}
	return s
}
