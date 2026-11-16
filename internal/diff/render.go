package diff

import (
	"encoding/json"
	"fmt"
	"io"
	"strings"

	"github.com/Shironex/stackward/internal/checks"
	"github.com/Shironex/stackward/internal/report"
)

// Every string a renderer prints came from a report file. LoadReport
// already cleaned control characters and redacted secrets; Markdown output
// escapes free text and keeps subjects and values in code spans, like the
// report renderer.

// WriteJSON writes the diff as indented diff.v1 JSON.
func WriteJSON(w io.Writer, d *Diff) error {
	b, err := json.MarshalIndent(d, "", "  ")
	if err != nil {
		return err
	}
	_, err = w.Write(append(b, '\n'))
	return err
}

// Headline sums up the diff in one line.
func Headline(d *Diff) string {
	s := d.Summary
	line := fmt.Sprintf("%s, %d added, %d removed, %d changed, %s",
		count(s.Drift, "drift item", "drift items"), s.Added, s.Removed, s.Changed,
		count(s.NewFindings, "new finding", "new findings"))
	if s.CoverageLost > 0 {
		line += ", " + count(s.CoverageLost, "drift check lost coverage", "drift checks lost coverage")
	}
	return line
}

func count(n int, one, many string) string {
	if n == 1 {
		return "1 " + one
	}
	return fmt.Sprintf("%d %s", n, many)
}

func sideLine(s Side) string {
	root := "not root"
	if s.Root {
		root = "root"
	}
	return fmt.Sprintf("%s (stackward %s, profile %s, %s)", orDash(s.GeneratedAt), orDash(s.ToolVersion), orDash(s.Profile), root)
}

func orDash(s string) string {
	if s == "" {
		return "-"
	}
	return s
}

// hostLine names the host, or both when --force-host compared two.
func hostLine(d *Diff) string {
	if d.SameHost {
		return d.New.Host
	}
	return fmt.Sprintf("%s (baseline) and %s (new)", orDash(d.Old.Host), orDash(d.New.Host))
}

// driftWord is how a drift kind reads in a sentence or a table.
var driftWord = map[string]string{
	DriftListener: "listener", DriftAuthorizedKey: "authorized key", DriftSudoer: "sudoer", DriftRootContainer: "root container",
}

// LevelLabel is how a result's level reads: the real level, and accepted
// when a waiver accepts it.
func LevelLabel(s *State) string {
	if s == nil {
		return "-"
	}
	if s.Waiver == report.WaiverAccepted {
		return string(s.Level) + " (accepted)"
	}
	return string(s.Level)
}

// Describe says in words what happened to a result. An accepted finding is
// never called fixed, and a removed result is "no longer reported", not
// fixed: the container or user may simply be gone.
func Describe(c Change) string {
	switch c.Kind {
	case Added:
		if c.New.Waiver == report.WaiverAccepted {
			return fmt.Sprintf("new, accepted by a waiver until %s: %s", c.New.Expires, c.New.Message)
		}
		return "new: " + c.New.Message
	case Removed:
		return fmt.Sprintf("no longer reported (was %s: %s)", LevelLabel(c.Old), c.Old.Message)
	}
	var parts []string
	for _, w := range c.What {
		switch w {
		case WhatLevel:
			p := fmt.Sprintf("%s to %s", c.Old.Level, c.New.Level)
			if c.New.Level == checks.Pass && isFinding(c.Old.Level) {
				p += ", fixed"
			}
			parts = append(parts, p)
		case WhatWaiver:
			parts = append(parts, waiverChange(c.Old, c.New))
		}
	}
	return strings.Join(parts, "; ") + ": " + c.New.Message
}

// waiverChange says how the waiver state of a result moved.
func waiverChange(o, n *State) string {
	switch {
	case n.Waiver == report.WaiverAccepted && o.Waiver == report.WaiverAccepted:
		return fmt.Sprintf("waiver renewed until %s (was %s)", n.Expires, o.Expires)
	case n.Waiver == report.WaiverAccepted:
		return fmt.Sprintf("now accepted by a waiver until %s, still %s", n.Expires, n.Level)
	case n.Waiver == report.WaiverExpired:
		return fmt.Sprintf("waiver expired after %s, the finding counts again", n.Expires)
	case n.Waiver == report.WaiverLevelExceeded:
		return fmt.Sprintf("the waiver does not cover %s, the finding counts", n.Level)
	case o.Waiver != "" && n.Waiver == "":
		return "no waiver matches it any more"
	}
	return fmt.Sprintf("waiver %s to %s", orDash(o.Waiver), orDash(n.Waiver))
}

// changeLevel is the level a change is listed under: the new one, or the
// old one for a removed result.
func changeLevel(c Change) *State {
	if c.New != nil {
		return c.New
	}
	return c.Old
}

// WriteText writes the diff as plain text, without colors.
func WriteText(w io.Writer, d *Diff) error {
	var b strings.Builder
	p := func(format string, a ...any) { fmt.Fprintf(&b, format, a...) }
	p("stackward diff: %s\n", Headline(d))
	p("Host:     %s\n", hostLine(d))
	p("Baseline: %s\n", sideLine(d.Old))
	p("New:      %s\n", sideLine(d.New))
	if len(d.Notes) > 0 {
		p("\nNOTES\n")
		for _, n := range d.Notes {
			p("  - %s\n", n)
		}
	}
	if len(d.Drift) > 0 {
		p("\nDRIFT\n")
		for _, x := range d.Drift {
			p("  %s  %s  %s\n      %s\n", strings.ToUpper(driftWord[x.Kind]), x.Check, x.Subject, driftDetail(x))
		}
	}
	if len(d.CoverageLost) > 0 {
		p("\nLOST COVERAGE\n")
		for _, l := range d.CoverageLost {
			p("  %s  %s\n      %s\n", strings.ToUpper(l.Now), l.Check, l.Detail)
		}
	}
	for _, sec := range []struct{ kind, title string }{{Added, "ADDED"}, {Removed, "REMOVED"}, {Changed, "CHANGED"}} {
		items := ofKind(d.Changes, sec.kind)
		if len(items) == 0 {
			continue
		}
		p("\n%s\n", sec.title)
		for _, c := range items {
			mark := ""
			if c.NewFinding {
				mark = "  [new finding]"
			}
			p("  %s  %s  %s%s\n      %s\n", strings.ToUpper(LevelLabel(changeLevel(c))), c.ID, c.Subject, mark, Describe(c))
		}
	}
	if quiet(d) {
		p("\nNo drift and no changed findings.\n")
	}
	_, err := io.WriteString(w, b.String())
	return err
}

// quiet reports whether the diff has nothing to list.
func quiet(d *Diff) bool { return len(d.Drift) == 0 && len(d.Changes) == 0 && len(d.CoverageLost) == 0 }

func driftDetail(x Drift) string {
	if x.Kind == DriftAuthorizedKey && x.Value != "" {
		return x.Detail + ": " + x.Value
	}
	return x.Detail
}

func ofKind(cs []Change, kind string) []Change {
	var out []Change
	for _, c := range cs {
		if c.Kind == kind {
			out = append(out, c)
		}
	}
	return out
}

// WriteMarkdown writes the diff as GitHub flavoured Markdown, for an issue
// or a CI summary.
func WriteMarkdown(w io.Writer, d *Diff) error {
	var b strings.Builder
	p := func(format string, a ...any) { fmt.Fprintf(&b, format, a...) }
	md, code := report.MarkdownText, report.MarkdownCode
	p("# stackward diff\n\n")
	p("- **Host:** %s\n", md(hostLine(d)))
	p("- **Baseline:** %s\n", md(sideLine(d.Old)))
	p("- **New:** %s\n", md(sideLine(d.New)))
	for _, n := range d.Notes {
		p("- **Note:** %s\n", md(n))
	}
	s := d.Summary
	p("\n## Summary\n\n| Change | Count |\n|---|---|\n")
	p("| drift | %d |\n| drift checks that lost coverage | %d |\n| added | %d |\n| removed | %d |\n| changed | %d |\n| new findings | %d |\n",
		s.Drift, s.CoverageLost, s.Added, s.Removed, s.Changed, s.NewFindings)
	if len(d.Drift) > 0 {
		p("\n## Drift\n\n| Kind | Check | Subject | What | Detail |\n|---|---|---|---|---|\n")
		for _, x := range d.Drift {
			p("| %s | %s | %s | %s | %s |\n", md(driftWord[x.Kind]), checkLink(x.Check), code(x.Subject), code(x.Value), md(x.Detail))
		}
	}
	if len(d.CoverageLost) > 0 {
		p("\n## Lost coverage\n\n| Check | Now | Detail |\n|---|---|---|\n")
		for _, l := range d.CoverageLost {
			p("| %s | %s | %s |\n", checkLink(l.Check), md(l.Now), md(l.Detail))
		}
	}
	for _, sec := range []struct{ kind, title string }{{Added, "Added"}, {Removed, "Removed"}, {Changed, "Changed"}} {
		items := ofKind(d.Changes, sec.kind)
		if len(items) == 0 {
			continue
		}
		p("\n## %s\n\n| Check | Level | Subject | New finding | What happened |\n|---|---|---|---|---|\n", sec.title)
		for _, c := range items {
			p("| %s | %s | %s | %s | %s |\n", checkLink(c.ID), md(LevelLabel(changeLevel(c))), code(c.Subject), yesNo(c.NewFinding), md(Describe(c)))
		}
	}
	if quiet(d) {
		p("\nNo drift and no changed findings.\n")
	}
	_, err := io.WriteString(w, b.String())
	return err
}

// checkLink links a check id to its page. The id matched the report schema
// pattern ^[A-Z]{2,4}-[0-9]{3}$ when the file was loaded, so it is safe in
// a link.
func checkLink(id string) string {
	return fmt.Sprintf("[%s](%s%s.md)", id, report.CheckDocsBase, id)
}

func yesNo(b bool) string {
	if b {
		return "yes"
	}
	return ""
}
