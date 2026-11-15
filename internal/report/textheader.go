package report

import (
	"fmt"
	"strings"

	"github.com/Shironex/stackward/internal/checks"
)

// keyWidth is the width of the "key:" column of the header.
const keyWidth = 11

// warnSGR paints the self target warning and a run without root.
const warnSGR = "1;33"

// header writes the title line and the key and value block: the host for an
// audit, the target for a probe, then collectors that did not end ok.
func (t *textWriter) header(r *Report) {
	kind := "audit"
	if r.Probe != nil {
		kind = "probe"
	}
	title := "stackward " + kind + "  "
	t.hang(indent+t.st.bold(title), width(indent)+width(title), r.Tool.Version+" ("+r.Schema+")", t.st.dim)
	t.blank()
	if r.Probe != nil {
		t.probeHeader(r)
	} else {
		t.auditHeader(r)
	}
	for _, c := range r.Coverage.Collectors {
		if c.Status == "ok" {
			continue
		}
		detail := c.Reason
		if c.Error != "" {
			detail = joinNonEmpty(detail, c.Error)
		}
		t.kv("collector", fmt.Sprintf("%s %s: %s", c.Name, c.Status, detail))
	}
}

// kv writes one "key: value" line, the value wrapped under itself.
func (t *textWriter) kv(key, value string) { t.kvPaint(key, value, plainText) }

func (t *textWriter) kvPaint(key, value string, paint func(string) string) {
	t.hang(indent+t.st.dim(fmt.Sprintf("%-*s", keyWidth, key+":")), width(indent)+keyWidth, value, paint)
}

func (t *textWriter) warnPaint(s string) string { return t.st.sgr(warnSGR, s) }

func (t *textWriter) auditHeader(r *Report) {
	host := r.Host.HostnameHash
	if r.Host.Hostname != "" {
		host = r.Host.Hostname
	}
	t.kv("host", orDash(host))
	t.kv("os", orDash(strings.TrimSpace(r.Host.OS)))
	t.kv("kernel", orDash(r.Host.Kernel))
	t.kv("collected", orDash(r.GeneratedAt))
	t.kv("profile", fmt.Sprintf("%s (%s)", r.Profile.Name, r.Profile.Source))
	if r.Coverage.Root {
		t.kv("root", "yes")
	} else {
		t.kvPaint("root", "no", t.warnPaint)
	}
	t.kv("sandbox", sandboxLine(r.Coverage.Sandbox))
	t.kv("coverage", CoverageLine(r.Coverage))
	if n := NotRootNote(r); n != "" {
		t.kv("note", n)
	}
}

// probeHeader replaces the host block of an audit with the target, its
// addresses, each address family and the ports that answered.
func (t *textWriter) probeHeader(r *Report) {
	pr := r.Probe
	if pr.SelfTarget {
		t.hang(indent+t.warnPaint(fmt.Sprintf("%-*s", keyWidth, "WARNING:")), width(indent)+keyWidth,
			"target is this machine, not an outside view: results do not show what the internet sees", t.warnPaint)
	}
	t.kv("target", orDash(pr.Target))
	t.kv("hostname", orDash(pr.Hostname))
	addrs := make([]string, 0, len(pr.Addresses))
	for _, a := range pr.Addresses {
		addrs = append(addrs, a.Address+" ("+a.Family+")")
	}
	t.kv("addresses", orDash(strings.Join(addrs, ", ")))
	for _, f := range pr.Families {
		line := f.Status
		if f.Detail != "" {
			line += ": " + f.Detail
		}
		t.kv(f.Family, line)
	}
	t.kv("probed", orDash(r.GeneratedAt))
	t.kv("profile", fmt.Sprintf("%s (%s)", r.Profile.Name, r.Profile.Source))
	t.kv("sandbox", sandboxLine(r.Coverage.Sandbox))
	var open []string
	for _, pt := range pr.Ports {
		if pt.State == "open" {
			open = append(open, fmt.Sprintf("tcp/%d on %s", pt.Port, pt.Address))
		}
	}
	t.kv("open", orDash(strings.Join(open, ", ")))
	for _, n := range pr.Notes {
		t.kv("note", n)
	}
	t.kv("coverage", CoverageLine(r.Coverage))
}

// boxLine is one styled line inside the summary box and its display width.
type boxLine struct {
	text string
	w    int
}

// topListLen is how many of the worst results the summary box names.
const topListLen = 5

// summaryBox writes the box that opens the results: the counts per level,
// the fails (or else the warnings) most severe first, and where to dig in.
func (t *textWriter) summaryBox(r *Report) {
	limit := t.w - width(indent) - 4 // the borders and their padding
	lines := t.countLines(r.Summary, limit)
	lines = append(lines, boxLine{})
	lines = append(lines, t.topList(r, limit)...)
	lines = append(lines, boxLine{})
	lines = append(lines, t.hintLines(r, limit)...)
	t.box("Summary", lines)
}

// countLines are the counts per level, wrapped between counts.
func (t *textWriter) countLines(s Summary, limit int) []boxLine {
	counts := []struct {
		l checks.Level
		n int
	}{{checks.Fail, s.Fail}, {checks.Warn, s.Warn}, {checks.Unknown, s.Unknown}, {checks.Info, s.Info}, {checks.Pass, s.Pass}, {checks.Skip, s.Skip}}
	const gap = "   "
	var out []boxLine
	var cur boxLine
	for _, c := range counts {
		plain := fmt.Sprintf("%s %d %s", t.st.marks[c.l], c.n, c.l)
		styled := t.st.dim(plain)
		if c.n > 0 {
			styled = t.st.mark(c.l) + " " + t.st.levelBold(c.l, fmt.Sprintf("%d %s", c.n, c.l))
		}
		if cur.w > 0 && cur.w+len(gap)+width(plain) > limit {
			out, cur = append(out, cur), boxLine{}
		}
		if cur.w > 0 {
			cur.text, cur.w = cur.text+gap, cur.w+len(gap)
		}
		cur.text, cur.w = cur.text+styled, cur.w+width(plain)
	}
	return append(out, cur)
}

// topList names the fails, most severe first; with no fail, the warnings.
func (t *textWriter) topList(r *Report, limit int) []boxLine {
	level, head := checks.Fail, "Fails, most severe first"
	items := ofLevel(r.Results, checks.Fail)
	if len(items) == 0 {
		level, head = checks.Warn, "No fails. Warnings, most severe first"
		items = ofLevel(r.Results, checks.Warn)
	}
	if len(items) == 0 {
		msg := "No fails and no warnings."
		if r.Summary.Unknown > 0 {
			msg = fmt.Sprintf("No fails and no warnings, but %s could not be inspected.", plural(r.Summary.Unknown, "result", "results"))
		}
		return t.wrapBox(msg, limit, plainText)
	}
	bySeverity(items)
	out := []boxLine{{t.st.bold(head), width(head)}}
	idw, sevw := 0, 0
	for _, it := range items {
		idw, sevw = max(idw, width(it.ID)), max(sevw, width(string(it.Severity)))
	}
	for i, it := range items {
		if i == topListLen {
			more := fmt.Sprintf("and %d more below", len(items)-i)
			out = append(out, boxLine{t.st.dim(more), width(more)})
			break
		}
		lead := fmt.Sprintf("%s %-*s  %-*s  ", t.st.marks[level], sevw, it.Severity, idw, it.ID)
		text := truncateWords(Headline(it), limit-width(lead), t.st.box.ellipsis)
		styled := t.st.mark(level) + " " + t.st.level(level, fmt.Sprintf("%-*s", sevw, it.Severity)) + "  " +
			t.st.bold(fmt.Sprintf("%-*s", idw, it.ID)) + "  " + text
		out = append(out, boxLine{styled, width(lead) + width(text)})
	}
	return out
}

// hintLines say how to dig into the results.
func (t *textWriter) hintLines(r *Report, limit int) []boxLine {
	type hint struct{ cmd, what string }
	var hints []hint
	if r.Probe != nil {
		hints = []hint{
			{"stackward explain <id>", "why a check matters and how to fix it"},
			{"stackward probe <host> --json", "the report as JSON for scripts"},
		}
		if !t.o.Passing {
			hints = append(hints, hint{"stackward probe <host> --all", "passing results too"})
		}
	} else {
		hints = []hint{
			{"stackward tui", "browse every result"},
			{"stackward explain <id>", "why a check matters and how to fix it"},
			{"stackward audit --md", "the report as Markdown for an issue"},
		}
		if !t.o.Passing {
			hints = append(hints, hint{"stackward audit --all", "passing results and every info in full"})
		}
	}
	cw := 0
	for _, h := range hints {
		cw = max(cw, width(h.cmd))
	}
	head := "Dig in"
	out := []boxLine{{t.st.bold(head), width(head)}}
	for _, h := range hints {
		lead := fmt.Sprintf("  %-*s  ", cw, h.cmd)
		what := truncateWords(h.what, limit-width(lead), t.st.box.ellipsis)
		out = append(out, boxLine{"  " + fmt.Sprintf("%-*s", cw, h.cmd) + "  " + t.st.dim(what), width(lead) + width(what)})
	}
	return out
}

func (t *textWriter) wrapBox(text string, limit int, paint func(string) string) []boxLine {
	var out []boxLine
	for _, l := range wrapWords(text, limit) {
		out = append(out, boxLine{paint(l), width(l)})
	}
	return out
}

// box draws lines in a frame as wide as the widest line, with the title in
// the top edge.
func (t *textWriter) box(title string, lines []boxLine) {
	bx := t.st.box
	inner := width(title) + 4
	for _, l := range lines {
		inner = max(inner, l.w)
	}
	t.blank()
	top := bx.h + " "
	t.line(indent + t.st.dim(bx.tl+top) + t.st.bold(title) + t.st.dim(" "+strings.Repeat(bx.h, inner+2-width(top)-width(title)-1)+bx.tr))
	for _, l := range lines {
		t.line(indent + t.st.dim(bx.v) + " " + l.text + strings.Repeat(" ", inner-l.w) + " " + t.st.dim(bx.v))
	}
	t.line(indent + t.st.dim(bx.bl+strings.Repeat(bx.h, inner+2)+bx.br))
}
