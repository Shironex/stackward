// Package report turns check results into the report.v1 document and renders
// it as text or JSON. The JSON shape is specified by schema/report.v1.json;
// change both together.
package report

import (
	"crypto/sha256"
	"encoding/hex"
	"time"

	"github.com/Shironex/stackward/internal/catalog"
	"github.com/Shironex/stackward/internal/checks"
	"github.com/Shironex/stackward/internal/facts"
	"github.com/Shironex/stackward/internal/profile"
	"github.com/Shironex/stackward/internal/redact"
	"github.com/Shironex/stackward/internal/sandbox"
	"github.com/Shironex/stackward/internal/waiver"
)

// SchemaID names the JSON shape. A breaking change gets a new id and a new
// schema file; adding an optional field does not.
const SchemaID = "stackward.report.v1"

// Exit codes of stackward audit.
const (
	ExitOK       = 0 // no result at or above the --fail-on threshold
	ExitFindings = 1 // at least one result at or above the threshold
	ExitError    = 2 // the tool itself failed (bad flags, unreadable input, write error)
)

// Report is the report.v1 document.
type Report struct {
	Schema string `json:"schema"`
	Tool   Tool   `json:"tool"`
	// GeneratedAt is when the facts were collected (RFC 3339, UTC).
	GeneratedAt string   `json:"generated_at"`
	Host        Host     `json:"host"`
	Profile     Profile  `json:"profile"`
	Coverage    Coverage `json:"coverage"`
	Summary     Summary  `json:"summary"`
	Results     []Item   `json:"results"`
	// Waivers lists every entry of the waivers file and what became of
	// it; absent when no waivers file was read or it had no entries.
	Waivers []WaiverEntry `json:"waivers,omitempty"`
	// Probe is set by `stackward probe` only; audit reports never carry it.
	Probe *Probe `json:"probe,omitempty"`
}

// Probe describes what `stackward probe` looked at from outside: the target
// as given, the addresses it resolved to, how each address family went and
// every port it tried.
type Probe struct {
	Target string `json:"target"`
	// Hostname is the --hostname checked over HTTPS, if any.
	Hostname string `json:"hostname,omitempty"`
	// SelfTarget is true when the target is the machine probe ran on
	// (loopback or a local interface address): the results are then not an
	// outside view.
	SelfTarget bool           `json:"self_target,omitempty"`
	Addresses  []ProbeAddress `json:"addresses"`
	Families   []ProbeFamily  `json:"families"`
	Ports      []ProbePort    `json:"ports"`
	// Notes are caveats the reader needs (for example a skipped TLS
	// verification or an address family this machine cannot reach).
	Notes []string `json:"notes,omitempty"`
}

// ProbeAddress is one resolved address of the target.
type ProbeAddress struct {
	Address string `json:"address"`
	Family  string `json:"family"`
}

// ProbeFamily is how one address family went: probed, no-address or
// unreachable (this machine has no route to it).
type ProbeFamily struct {
	Family string `json:"family"`
	Status string `json:"status"`
	Detail string `json:"detail,omitempty"`
}

// ProbePort is one TCP connect attempt.
type ProbePort struct {
	Address string `json:"address"`
	Family  string `json:"family"`
	Port    int    `json:"port"`
	// State is open, closed (refused), filtered (no answer), unreachable or
	// error.
	State  string `json:"state"`
	Banner string `json:"banner,omitempty"`
}

// Tool identifies the producer.
type Tool struct {
	Name    string `json:"name"`
	Version string `json:"version"`
}

// Host describes the audited machine without identifying it by default.
type Host struct {
	// HostnameHash is "sha256:" and the first 16 hex digits of the
	// hostname's SHA-256, so reports from one host can be matched up.
	HostnameHash string `json:"hostname_hash,omitempty"`
	// Hostname is only set with --show-hostname.
	Hostname string `json:"hostname,omitempty"`
	OS       string `json:"os,omitempty"`
	OSID     string `json:"os_id,omitempty"`
	Version  string `json:"os_version,omitempty"`
	Kernel   string `json:"kernel,omitempty"`
}

// Profile is the ingress profile and where it came from.
type Profile struct {
	Name profile.Name `json:"name"`
	// Source is "inferred" or "flag".
	Source string `json:"source"`
}

// Coverage says how much of the host was actually inspected. Counts are of
// results, not checks: a check can produce one result per subject.
type Coverage struct {
	Checks  int `json:"checks"`
	Results int `json:"results"`
	Checked int `json:"checked"` // pass, warn, fail, info
	// Accepted counts the checked results a waiver accepts.
	Accepted   int                 `json:"accepted,omitempty"`
	Unknown    int                 `json:"unknown"`
	Skipped    int                 `json:"skipped"`
	Root       bool                `json:"root"`
	Sandbox    sandbox.Status      `json:"sandbox"`
	Collectors []CollectorCoverage `json:"collectors"`
}

// CollectorCoverage is how one collector ended.
type CollectorCoverage struct {
	Name   string       `json:"name"`
	Status facts.Status `json:"status"`
	Reason string       `json:"reason,omitempty"`
	Error  string       `json:"error,omitempty"`
}

// Summary counts results by level. A fail or warn result a waiver accepts
// is counted as Accepted, not as Fail or Warn.
type Summary struct {
	Fail     int `json:"fail"`
	Warn     int `json:"warn"`
	Accepted int `json:"accepted,omitempty"`
	Unknown  int `json:"unknown"`
	Info     int `json:"info"`
	Pass     int `json:"pass"`
	Skip     int `json:"skip"`
}

// Item is one result with its catalog entry folded in.
type Item struct {
	ID       string           `json:"id"`
	Group    string           `json:"group"`
	Title    string           `json:"title"`
	Level    checks.Level     `json:"level"`
	Severity catalog.Severity `json:"severity"`
	Subject  string           `json:"subject"`
	Message  string           `json:"message"`
	Evidence map[string]any   `json:"evidence,omitempty"`
	Fix      Fix              `json:"fix"`
	// Waiver is set when an entry of the waivers file matches this result:
	// accepted, or expired with the finding back at its level. Level and
	// evidence are always the real ones.
	Waiver *ResultWaiver `json:"waiver,omitempty"`
	// rawSubject is the subject before redaction, which waivers match on
	// so two subjects that redact alike stay apart. Never rendered.
	rawSubject string
}

// Fix is the short fix hint and an optional docs link.
type Fix struct {
	Hint string `json:"hint"`
	Docs string `json:"docs,omitempty"`
}

// Meta is what the report needs that is not in facts or results.
type Meta struct {
	Version       string
	Sandbox       sandbox.Status
	Profile       profile.Name
	ProfileSource string
	ShowHostname  bool
	ChecksRun     int
	// Probe marks a probe report and describes its target.
	Probe *Probe
	// Waivers are the entries of the waivers file, if one was read.
	Waivers []waiver.Waiver
}

// Build assembles a report. Results must already be in report order (as
// checks.Evaluate returns them). Every free text field and every evidence
// value passes through redaction here, so no renderer can skip it.
func Build(f *facts.Facts, results []checks.Result, cat *catalog.Catalog, m Meta) *Report {
	r := &Report{
		Schema:  SchemaID,
		Tool:    Tool{Name: "stackward", Version: m.Version},
		Profile: Profile{Name: m.Profile, Source: m.ProfileSource},
		Results: make([]Item, 0, len(results)),
	}
	if !f.CollectedAt.IsZero() {
		r.GeneratedAt = f.CollectedAt.UTC().Format(time.RFC3339)
	}
	if f.Host != nil && f.Host.Hostname != "" {
		if m.ShowHostname {
			r.Host.Hostname = f.Host.Hostname
		} else {
			r.Host.HostnameHash = HashHostname(f.Host.Hostname)
		}
	}
	if f.OS != nil {
		r.Host.OS, r.Host.OSID, r.Host.Version = f.OS.PrettyName, f.OS.ID, f.OS.VersionID
	}
	if f.Kernel != nil {
		r.Host.Kernel = f.Kernel.Release
	}

	for _, res := range results {
		it := Item{
			ID: res.ID, Group: catalog.GroupOf(res.ID), Level: res.Level,
			Subject: redact.String(res.Subject), Message: redact.String(res.Message), rawSubject: res.Subject,
		}
		if e, ok := cat.Lookup(res.ID); ok {
			it.Title, it.Severity, it.Fix = e.Title, e.Severity, Fix{Hint: e.Fix, Docs: e.Docs}
		} else {
			it.Title, it.Severity = res.ID, catalog.Info
		}
		if len(res.Evidence) > 0 {
			it.Evidence, _ = redact.Value(toAny(res.Evidence)).(map[string]any)
		}
		r.Results = append(r.Results, it)
	}
	applyWaivers(r, m.Waivers, cat, f.CollectedAt)
	for _, it := range r.Results {
		r.count(it)
	}

	if m.Probe != nil {
		r.Probe = redactProbe(m.Probe)
	}

	r.Coverage.Checks = m.ChecksRun
	r.Coverage.Results = len(results)
	r.Coverage.Root = f.IsRoot()
	r.Coverage.Sandbox = m.Sandbox
	r.Coverage.Sandbox.Reason = redact.String(m.Sandbox.Reason)
	r.Coverage.Collectors = make([]CollectorCoverage, 0, len(f.Collectors))
	for _, c := range f.Collectors {
		r.Coverage.Collectors = append(r.Coverage.Collectors, CollectorCoverage{
			Name: c.Name, Status: c.Status, Reason: redact.String(c.Reason), Error: redact.String(c.Error),
		})
	}
	return r
}

func (r *Report) count(it Item) {
	if it.Accepted() {
		r.Summary.Accepted++
		r.Coverage.Accepted++
		r.Coverage.Checked++
		return
	}
	switch it.Level {
	case checks.Fail:
		r.Summary.Fail++
		r.Coverage.Checked++
	case checks.Warn:
		r.Summary.Warn++
		r.Coverage.Checked++
	case checks.Pass:
		r.Summary.Pass++
		r.Coverage.Checked++
	case checks.Info:
		r.Summary.Info++
		r.Coverage.Checked++
	case checks.Unknown:
		r.Summary.Unknown++
		r.Coverage.Unknown++
	case checks.Skip:
		r.Summary.Skip++
		r.Coverage.Skipped++
	}
}

// redactProbe copies p with every free text field redacted.
func redactProbe(p *Probe) *Probe {
	cp := *p
	cp.Addresses = append([]ProbeAddress{}, p.Addresses...)
	cp.Families = make([]ProbeFamily, len(p.Families))
	for i, f := range p.Families {
		f.Detail = redact.String(f.Detail)
		cp.Families[i] = f
	}
	cp.Ports = make([]ProbePort, len(p.Ports))
	for i, pt := range p.Ports {
		pt.Banner = redact.String(pt.Banner)
		cp.Ports[i] = pt
	}
	cp.Notes = nil
	for _, n := range p.Notes {
		cp.Notes = append(cp.Notes, redact.String(n))
	}
	return &cp
}

// HashHostname returns the hostname_hash form of a hostname.
func HashHostname(name string) string {
	sum := sha256.Sum256([]byte(name))
	return "sha256:" + hex.EncodeToString(sum[:])[:16]
}

// FailOn is the --fail-on threshold.
type FailOn string

// Thresholds.
const (
	FailOnFail  FailOn = "fail"
	FailOnWarn  FailOn = "warn"
	FailOnNever FailOn = "never"
)

// ExitCode returns ExitFindings when a result reaches the threshold.
func (r *Report) ExitCode(t FailOn) int {
	switch t {
	case FailOnNever:
		return ExitOK
	case FailOnWarn:
		if r.Summary.Fail+r.Summary.Warn > 0 {
			return ExitFindings
		}
	default:
		if r.Summary.Fail > 0 {
			return ExitFindings
		}
	}
	return ExitOK
}
