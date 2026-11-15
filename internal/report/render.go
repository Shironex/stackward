package report

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"sort"
	"strings"

	"github.com/Shironex/stackward/internal/catalog"
	"github.com/Shironex/stackward/internal/checks"
	"github.com/Shironex/stackward/internal/sandbox"
)

// toAny normalizes evidence to plain JSON values (maps, slices, strings,
// json.Number, bools) so redaction can walk every string in it.
func toAny(v map[string]any) any {
	b, err := json.Marshal(v)
	if err != nil {
		return map[string]any{"error": "evidence could not be encoded: " + err.Error()}
	}
	dec := json.NewDecoder(bytes.NewReader(b))
	dec.UseNumber()
	var out any
	if err := dec.Decode(&out); err != nil {
		return map[string]any{"error": "evidence could not be decoded: " + err.Error()}
	}
	return out
}

// WriteJSON writes the report as indented JSON. Struct field order is kept
// and evidence keys are sorted, so the same input gives the same bytes.
func WriteJSON(w io.Writer, r *Report) error {
	b, err := json.MarshalIndent(r, "", "  ")
	if err != nil {
		return err
	}
	_, err = w.Write(append(b, '\n'))
	return err
}

// TextOptions tunes WriteText.
type TextOptions struct {
	// Color adds ANSI colors to levels.
	Color bool
	// Passing lists passing and skipped results too, not just counts.
	Passing bool
}

var levelColor = map[checks.Level]string{
	checks.Fail: "\x1b[31m", checks.Warn: "\x1b[33m", checks.Unknown: "\x1b[35m",
	checks.Info: "\x1b[36m", checks.Pass: "\x1b[32m", checks.Skip: "\x1b[90m",
}

// WriteText writes the human report: a header with coverage, then results
// grouped in catalog order, then the summary line.
func WriteText(w io.Writer, r *Report, o TextOptions) error {
	var b strings.Builder
	p := func(format string, a ...any) { fmt.Fprintf(&b, format, a...) }

	if r.Probe != nil {
		writeProbeHeader(p, r)
	} else {
		writeAuditHeader(p, r)
	}
	for _, c := range r.Coverage.Collectors {
		if c.Status == "ok" {
			continue
		}
		detail := c.Reason
		if c.Error != "" {
			detail = joinNonEmpty(detail, c.Error)
		}
		p("collector: %s %s: %s\n", c.Name, c.Status, detail)
	}

	groups := map[string][]Item{}
	for _, it := range r.Results {
		groups[it.Group] = append(groups[it.Group], it)
	}
	ids := make([]string, 0, len(groups))
	for g := range groups {
		ids = append(ids, g)
	}
	sort.Slice(ids, func(i, j int) bool { return catalog.GroupRank(ids[i]) < catalog.GroupRank(ids[j]) })

	for _, g := range ids {
		var shown []Item
		hidden := 0
		for _, it := range groups[g] {
			if !o.Passing && (it.Level == checks.Pass || it.Level == checks.Skip) {
				hidden++
				continue
			}
			shown = append(shown, it)
		}
		p("\n%s  %s", g, catalog.GroupName(g))
		if hidden > 0 {
			p("  (%d passing or skipped not shown)", hidden)
		}
		p("\n")
		for _, it := range shown {
			lvl := strings.ToUpper(string(it.Level))
			if o.Color {
				lvl = levelColor[it.Level] + lvl + "\x1b[0m"
			}
			subject := ""
			if it.Subject != "host" {
				subject = " " + it.Subject
			}
			p("  %-7s %s%s  %s [%s]\n", lvl, it.ID, subject, it.Title, it.Severity)
			if it.Message != "" {
				p("          %s\n", it.Message)
			}
			if it.Level == checks.Fail || it.Level == checks.Warn {
				p("          fix: %s\n", it.Fix.Hint)
			}
		}
	}

	s := r.Summary
	p("\nsummary: %d fail, %d warn, %d unknown, %d info, %d pass, %d skip\n", s.Fail, s.Warn, s.Unknown, s.Info, s.Pass, s.Skip)
	p("explain any check with: stackward explain <id>\n")
	_, err := io.WriteString(w, b.String())
	return err
}

type printer func(format string, a ...any)

func writeAuditHeader(p printer, r *Report) {
	p("stackward %s audit (%s)\n", r.Tool.Version, r.Schema)
	host := r.Host.HostnameHash
	if r.Host.Hostname != "" {
		host = r.Host.Hostname
	}
	p("host:      %s\n", orDash(host))
	p("os:        %s\n", orDash(strings.TrimSpace(r.Host.OS)))
	p("kernel:    %s\n", orDash(r.Host.Kernel))
	p("collected: %s\n", orDash(r.GeneratedAt))
	p("profile:   %s (%s)\n", r.Profile.Name, r.Profile.Source)
	root := "yes"
	if !r.Coverage.Root {
		root = "no, run with sudo for full coverage"
	}
	p("root:      %s\n", root)
	p("sandbox:   %s\n", sandboxLine(r.Coverage.Sandbox))
	writeCoverageLine(p, r)
}

// writeProbeHeader replaces the host block of an audit with the target, its
// addresses, each address family and the ports that answered.
func writeProbeHeader(p printer, r *Report) {
	pr := r.Probe
	p("stackward %s probe (%s)\n", r.Tool.Version, r.Schema)
	p("target:    %s\n", orDash(pr.Target))
	p("hostname:  %s\n", orDash(pr.Hostname))
	addrs := make([]string, 0, len(pr.Addresses))
	for _, a := range pr.Addresses {
		addrs = append(addrs, a.Address+" ("+a.Family+")")
	}
	p("addresses: %s\n", orDash(strings.Join(addrs, ", ")))
	for _, f := range pr.Families {
		line := f.Status
		if f.Detail != "" {
			line += ": " + f.Detail
		}
		p("%-10s %s\n", f.Family+":", line)
	}
	p("probed:    %s\n", orDash(r.GeneratedAt))
	p("profile:   %s (%s)\n", r.Profile.Name, r.Profile.Source)
	p("sandbox:   %s\n", sandboxLine(r.Coverage.Sandbox))
	var open []string
	for _, pt := range pr.Ports {
		if pt.State == "open" {
			open = append(open, fmt.Sprintf("tcp/%d on %s", pt.Port, pt.Address))
		}
	}
	p("open:      %s\n", orDash(strings.Join(open, ", ")))
	for _, n := range pr.Notes {
		p("note:      %s\n", n)
	}
	writeCoverageLine(p, r)
}

func writeCoverageLine(p printer, r *Report) {
	p("coverage:  %d checked, %d unknown, %d skipped (%d checks)\n",
		r.Coverage.Checked, r.Coverage.Unknown, r.Coverage.Skipped, r.Coverage.Checks)
}

func sandboxLine(s sandbox.Status) string {
	switch {
	case s.State == sandbox.Landlock && s.Network:
		return fmt.Sprintf("landlock (abi %d, no writes, no tcp)", s.ABI)
	case s.State == sandbox.Landlock:
		return fmt.Sprintf("landlock (abi %d, no writes)", s.ABI)
	case s.Reason != "":
		return fmt.Sprintf("%s (%s)", s.State, s.Reason)
	}
	return orDash(string(s.State))
}

func orDash(s string) string {
	if s == "" {
		return "-"
	}
	return s
}

func joinNonEmpty(a, b string) string {
	if a == "" {
		return b
	}
	return a + "; " + b
}
