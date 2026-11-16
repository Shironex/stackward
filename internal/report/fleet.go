package report

import (
	"encoding/json"
	"fmt"
	"io"
	"strings"
)

// FleetSchemaID names the JSON shape of a fleet report (stackward audit
// --ssh), specified by schema/fleet.v1.json. Each audited host carries its
// own report.v1 document.
const FleetSchemaID = "stackward.fleet.v1"

// Host statuses in a fleet report.
const (
	FleetAudited = "audited"
	FleetError   = "error"
)

// Fleet is the combined report of an audit over ssh.
type Fleet struct {
	Schema string `json:"schema"`
	Tool   Tool   `json:"tool"`
	// GeneratedAt is when the fleet run started (RFC 3339, UTC).
	GeneratedAt string       `json:"generated_at"`
	Summary     FleetSummary `json:"summary"`
	Hosts       []FleetHost  `json:"hosts"`
}

// FleetSummary counts hosts, and results over every audited host.
type FleetSummary struct {
	Hosts   int     `json:"hosts"`
	Audited int     `json:"audited"`
	Failed  int     `json:"failed"`
	Results Summary `json:"results"`
}

// FleetHost is one host of the run.
type FleetHost struct {
	// Host is the name as the user gave it to ssh.
	Host string `json:"host"`
	// Status is audited or error.
	Status string `json:"status"`
	// Arch is the host's architecture, once known.
	Arch string `json:"arch,omitempty"`
	// Error says why the host has no report.
	Error string `json:"error,omitempty"`
	// Cleanup is set when the removal of the temporary directory could not
	// be confirmed after a failure.
	Cleanup string  `json:"cleanup,omitempty"`
	Report  *Report `json:"report,omitempty"`
}

// NewFleet assembles a fleet report and its summary.
func NewFleet(version, generatedAt string, hosts []FleetHost) *Fleet {
	f := &Fleet{Schema: FleetSchemaID, Tool: Tool{Name: "stackward", Version: version}, GeneratedAt: generatedAt, Hosts: hosts}
	f.Summary.Hosts = len(hosts)
	for _, h := range hosts {
		if h.Status != FleetAudited || h.Report == nil {
			f.Summary.Failed++
			continue
		}
		f.Summary.Audited++
		s, t := &f.Summary.Results, h.Report.Summary
		s.Fail += t.Fail
		s.Warn += t.Warn
		s.Unknown += t.Unknown
		s.Info += t.Info
		s.Pass += t.Pass
		s.Skip += t.Skip
	}
	if f.Hosts == nil {
		f.Hosts = []FleetHost{}
	}
	return f
}

// ExitCode is ExitError when a host could not be audited, else the worst
// exit code of the hosts' reports for the threshold.
func (f *Fleet) ExitCode(t FailOn) int {
	if f.Summary.Failed > 0 {
		return ExitError
	}
	code := ExitOK
	for _, h := range f.Hosts {
		code = max(code, h.Report.ExitCode(t))
	}
	return code
}

// WriteFleetJSON writes the fleet report as indented JSON.
func WriteFleetJSON(w io.Writer, f *Fleet) error {
	b, err := json.MarshalIndent(f, "", "  ")
	if err != nil {
		return err
	}
	_, err = w.Write(append(b, '\n'))
	return err
}

func summaryCounts(s Summary) string {
	return fmt.Sprintf("%d fail, %d warn, %d unknown, %d info, %d pass, %d skip", s.Fail, s.Warn, s.Unknown, s.Info, s.Pass, s.Skip)
}

// hostCoverage is a host's coverage line with its root state.
func hostCoverage(r *Report) string {
	return fmt.Sprintf("%s, root: %s", CoverageLine(r.Coverage), yesNo(r.Coverage.Root))
}

// WriteFleetText writes the fleet overview, one block per host with its
// coverage line or its error, then each audited host's full text report.
func WriteFleetText(w io.Writer, f *Fleet, o TextOptions) error {
	var b strings.Builder
	p := func(format string, a ...any) { fmt.Fprintf(&b, format, a...) }
	p("stackward %s fleet audit\n", f.Tool.Version)
	p("%shosts:     %d (%d audited, %d failed)\n", indent, f.Summary.Hosts, f.Summary.Audited, f.Summary.Failed)
	p("%sstarted:   %s\n", indent, f.GeneratedAt)
	p("%sresults:   %s\n", indent, summaryCounts(f.Summary.Results))
	for _, h := range f.Hosts {
		p("\n%s%s  %s", indent, h.Host, h.Status)
		if h.Arch != "" {
			p("  linux/%s", h.Arch)
		}
		p("\n")
		if h.Report != nil {
			s := h.Report.Summary
			p("%s%s%d fail, %d warn, %d unknown\n", indent, indent, s.Fail, s.Warn, s.Unknown)
			p("%s%scoverage: %s\n", indent, indent, hostCoverage(h.Report))
		}
		if h.Error != "" {
			p("%s%serror: %s\n", indent, indent, h.Error)
		}
		if h.Cleanup != "" {
			p("%s%scleanup: %s\n", indent, indent, h.Cleanup)
		}
	}
	if _, err := io.WriteString(w, b.String()); err != nil {
		return err
	}
	for _, h := range f.Hosts {
		if h.Report == nil {
			continue
		}
		if _, err := fmt.Fprintf(w, "\n=== %s ===\n\n", h.Host); err != nil {
			return err
		}
		if err := WriteText(w, h.Report, o); err != nil {
			return err
		}
	}
	return nil
}

// WriteFleetMarkdown writes the fleet report as GitHub flavoured Markdown:
// a table of hosts with their counts and coverage lines, the errors, then
// each audited host's report one heading level down.
func WriteFleetMarkdown(w io.Writer, f *Fleet, o MarkdownOptions) error {
	var b strings.Builder
	p := func(format string, a ...any) { fmt.Fprintf(&b, format, a...) }
	p("# stackward %s fleet audit\n\n", mdEscape(f.Tool.Version))
	p("- **Hosts:** %d (%d audited, %d failed)\n", f.Summary.Hosts, f.Summary.Audited, f.Summary.Failed)
	p("- **Started:** %s\n", mdOrDash(f.GeneratedAt))
	p("- **Results:** %s\n", summaryCounts(f.Summary.Results))
	p("\n| Host | Status | Fail | Warn | Unknown | Coverage |\n|---|---|---|---|---|---|\n")
	for _, h := range f.Hosts {
		if h.Report == nil {
			p("| %s | %s | - | - | - | - |\n", mdEscape(h.Host), h.Status)
			continue
		}
		s := h.Report.Summary
		p("| %s | %s | %d | %d | %d | %s |\n", mdEscape(h.Host), h.Status, s.Fail, s.Warn, s.Unknown, mdEscape(hostCoverage(h.Report)))
	}
	var problems []FleetHost
	for _, h := range f.Hosts {
		if h.Error != "" || h.Cleanup != "" {
			problems = append(problems, h)
		}
	}
	if len(problems) > 0 {
		p("\n## Hosts not audited\n\n")
		for _, h := range problems {
			if h.Error != "" {
				p("- **%s:** %s\n", mdEscape(h.Host), mdEscape(h.Error))
			}
			if h.Cleanup != "" {
				p("- **%s cleanup:** %s\n", mdEscape(h.Host), mdEscape(h.Cleanup))
			}
		}
	}
	for _, h := range f.Hosts {
		if h.Report == nil {
			continue
		}
		var hb strings.Builder
		if err := WriteMarkdown(&hb, h.Report, o); err != nil {
			return err
		}
		p("\n## Host %s\n\n", mdEscape(h.Host))
		for _, line := range strings.Split(strings.TrimRight(hb.String(), "\n"), "\n") {
			if strings.HasPrefix(line, "#") {
				line = "##" + line
			}
			p("%s\n", line)
		}
	}
	_, err := io.WriteString(w, b.String())
	return err
}
