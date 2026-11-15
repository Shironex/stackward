package plan

import (
	"encoding/json"
	"fmt"
	"io"
	"regexp"
	"strings"
)

// WriteJSON writes the plan as indented JSON. Struct field order is kept,
// so the same input gives the same bytes.
func WriteJSON(w io.Writer, p *Plan) error {
	b, err := json.MarshalIndent(p, "", "  ")
	if err != nil {
		return err
	}
	_, err = w.Write(append(b, '\n'))
	return err
}

// WriteText writes the human summary: header, every step with its diff,
// commands, restarts, notes and undo, then what was not planned.
func WriteText(w io.Writer, p *Plan) error {
	var b strings.Builder
	pf := func(format string, a ...any) { fmt.Fprintf(&b, format, a...) }
	pf("stackward plan: nothing on this host was changed\n")
	pf("host:      %s\n", hostLine(p))
	pf("source:    %s\n", sourceLine(p))
	pf("sandbox:   %s\n", p.Sandbox.State)
	sm := p.Summary
	pf("steps:     %d planned (%d safe, %d networking, %d access-critical), %d opt in, %d not planned\n",
		sm.Steps, sm.Safe, sm.Networking, sm.AccessCritical, sm.OptIn, sm.Skipped)
	if len(sm.Restarts) > 0 {
		pf("restarts:  %s\n", strings.Join(sm.Restarts, ", "))
	}
	for i, s := range p.Steps {
		pf("\n%d. %s  [%s]  fixes %s\n", i+1, s.ID, s.Risk, strings.Join(s.Fixes, ", "))
		pf("   %s\n", s.Title)
		if s.OptIn {
			pf("   opt in: applied only when selected by id\n")
		}
		for _, e := range s.Edits {
			mode := ""
			if e.Mode != "" {
				mode = " (" + e.Mode + ")"
			}
			pf("   %-8s %s%s\n", e.Action, e.Path, mode)
			if len(e.Validate) > 0 {
				pf("            checked first with: %s <new file>\n", shellJoin(e.Validate))
			}
			if e.Redacted {
				pf("            content redacted in this plan: a secret shaped value was masked\n")
			}
			for _, l := range strings.Split(strings.TrimSuffix(e.Diff, "\n"), "\n") {
				pf("            %s\n", l)
			}
		}
		for _, c := range s.Commands {
			pf("   run      %s\n", shellJoin(c.Args))
			pf("            # %s\n", c.Why)
		}
		for _, r := range s.Restarts {
			pf("   restarts %s\n", r)
		}
		for _, n := range s.Notes {
			pf("   note     %s\n", n)
		}
		pf("   undo     %s\n", s.Undo.Description)
		for _, c := range s.Undo.Commands {
			pf("            %s\n", shellJoin(c.Args))
		}
	}
	if len(p.Skipped) > 0 {
		pf("\nNot planned:\n")
		for _, s := range p.Skipped {
			pf("  %-20s %-8s %s\n", s.ID, s.Kind, s.Reason)
		}
	}
	pf("\nReview every step. Save the plan with --out FILE, or print it as a shell script with --emit-script.\n")
	_, err := io.WriteString(w, b.String())
	return err
}

func hostLine(p *Plan) string {
	h := p.Host.HostnameHash
	if p.Host.Hostname != "" {
		h = p.Host.Hostname
	}
	if h == "" {
		h = "unknown"
	}
	if p.Host.OS != "" {
		h += "  " + p.Host.OS
	}
	return h
}

func sourceLine(p *Plan) string {
	kind := map[string]string{
		FromLive: "live audit", FromFacts: "facts file", FromReport: "report file (no facts)", FromReportFacts: "report and facts files",
	}[p.Source.Kind]
	if kind == "" {
		kind = p.Source.Kind
	}
	r := p.Source.Report
	return fmt.Sprintf("%s, report by stackward %s, facts from %s", kind, r.ToolVersion, orUnknown(r.GeneratedAt))
}

func orUnknown(s string) string {
	if s == "" {
		return "an unknown time"
	}
	return s
}

// WriteScript writes a POSIX shell script that does what the plan says,
// step for step, for people who prefer to read and run shell themselves.
// stackward never runs it. Each step is a function; the calls at the end
// run the steps that are not opt in, and opt in calls are commented out.
func WriteScript(w io.Writer, p *Plan) error {
	var b strings.Builder
	pf := func(format string, a ...any) { fmt.Fprintf(&b, format, a...) }
	pf("#!/bin/sh\n")
	pf("# stackward plan as a shell script (%s, stackward %s).\n", p.Schema, p.Tool.Version)
	pf("# Host: %s. Source: %s.\n", hostLine(p), sourceLine(p))
	pf("#\n")
	pf("# stackward never runs this script. Read every step, then run it as root\n")
	pf("# on the host it was planned for. Each step first checks that the files\n")
	pf("# it changes still hold what the audit saw, and stops otherwise. Opt in\n")
	pf("# steps are commented out at the bottom: remove the \"# \" to run one.\n")
	pf("set -eu\n")
	for i, s := range p.Steps {
		pf("\n# %d/%d %s [%s] fixes %s\n", i+1, len(p.Steps), s.ID, s.Risk, strings.Join(s.Fixes, ", "))
		pf("# %s\n", s.Title)
		for _, r := range s.Restarts {
			pf("# Restarts %s.\n", r)
		}
		for _, n := range s.Notes {
			comment(&b, "Note: "+n)
		}
		comment(&b, "Undo: "+s.Undo.Description)
		for _, c := range s.Undo.Commands {
			pf("#   %s\n", shellJoin(c.Args))
		}
		pf("%s() {\n", funcName(s.ID))
		for _, e := range s.Edits {
			writeEditScript(&b, s.ID, e)
		}
		for _, c := range s.Commands {
			pf("\t# %s\n", c.Why)
			pf("\t%s\n", shellJoin(c.Args))
		}
		pf("}\n")
	}
	if len(p.Skipped) > 0 {
		pf("\n# Not planned:\n")
		for _, s := range p.Skipped {
			comment(&b, fmt.Sprintf("%s (%s): %s", s.ID, s.Kind, s.Reason))
		}
	}
	pf("\n")
	if len(p.Steps) == 0 {
		pf("echo \"stackward: the plan has no steps; nothing to do\"\n")
	}
	for _, s := range p.Steps {
		if s.OptIn {
			pf("# %s  # opt in: %s, restarts %s\n", funcName(s.ID), s.Risk, orNone(s.Restarts))
			continue
		}
		pf("%s\n", funcName(s.ID))
	}
	_, err := io.WriteString(w, b.String())
	return err
}

func writeEditScript(b *strings.Builder, id string, e FileEdit) {
	pf := func(format string, a ...any) { fmt.Fprintf(b, format, a...) }
	path := shellQuote(e.Path)
	tmp := shellQuote(e.Path + ".stackward-new")
	if e.Redacted {
		pf("\t# %s %s: content redacted in the plan\n", e.Action, e.Path)
		pf("\techo %s >&2\n", shellQuote("stackward: step "+id+" was redacted in this plan (a secret shaped value was masked); edit "+e.Path+" by hand"))
		pf("\texit 1\n")
		return
	}
	switch e.Action {
	case Create:
		pf("\t# create %s (%s)\n", e.Path, e.Mode)
		pf("\tif [ -e %s ]; then\n", path)
		pf("\t\techo %s >&2\n", shellQuote("stackward: "+e.Path+" exists, the plan expected it absent; plan again"))
		pf("\t\texit 1\n")
		pf("\tfi\n")
		pf("\tmkdir -p %s\n", shellQuote(dirOf(e.Path)))
		writeContent(b, tmp, e.New)
		pf("\tchmod %s %s\n", e.Mode, tmp)
	case Replace:
		pf("\t# replace %s; the diff is in the plan\n", e.Path)
		pf("\tif ! echo %s | sha256sum -c --status -; then\n", shellQuote(e.OldSHA256+"  "+e.Path))
		pf("\t\techo %s >&2\n", shellQuote("stackward: "+e.Path+" changed since the audit; plan again"))
		pf("\t\texit 1\n")
		pf("\tfi\n")
		pf("\t[ -e %s ] || cp -p %s %s\n", shellQuote(e.Path+".orig"), path, shellQuote(e.Path+".orig"))
		pf("\tcp -p %s %s\n", path, tmp)
		writeContent(b, tmp, e.New)
	}
	if len(e.Validate) > 0 {
		pf("\tif ! %s %s; then\n", shellJoin(e.Validate), tmp)
		pf("\t\trm -f %s\n", tmp)
		pf("\t\techo %s >&2\n", shellQuote("stackward: the new "+e.Path+" failed validation; nothing was changed"))
		pf("\t\texit 1\n")
		pf("\tfi\n")
	}
	pf("\tmv %s %s\n", tmp, path)
}

// writeContent writes content to path with a quoted here document (no
// expansion), or printf when the content has no final newline.
func writeContent(b *strings.Builder, path, content string) {
	if !strings.HasSuffix(content, "\n") {
		fmt.Fprintf(b, "\tprintf '%%s' %s > %s\n", shellQuote(content), path)
		return
	}
	delim := "STACKWARD_EOF"
	for n := 1; strings.Contains("\n"+content, "\n"+delim+"\n"); n++ {
		delim = fmt.Sprintf("STACKWARD_EOF_%d", n)
	}
	fmt.Fprintf(b, "\tcat > %s <<'%s'\n%s%s\n", path, delim, content, delim)
}

func comment(b *strings.Builder, text string) {
	for _, l := range wrap(text, 74) {
		b.WriteString("# " + l + "\n")
	}
}

// wrap breaks text into lines of at most width bytes on spaces.
func wrap(text string, width int) []string {
	var lines []string
	line := ""
	for _, word := range strings.Fields(text) {
		if line != "" && len(line)+1+len(word) > width {
			lines = append(lines, line)
			line = ""
		}
		if line != "" {
			line += " "
		}
		line += word
	}
	return append(lines, line)
}

func dirOf(p string) string {
	i := strings.LastIndex(p, "/")
	if i <= 0 {
		return "/"
	}
	return p[:i]
}

func funcName(id string) string { return "step_" + strings.ReplaceAll(id, "-", "_") }

func orNone(s []string) string {
	if len(s) == 0 {
		return "nothing"
	}
	return strings.Join(s, ", ")
}

var shellSafe = regexp.MustCompile(`^[A-Za-z0-9_./=:,+@%-]+$`)

// shellQuote quotes s for a POSIX shell when it needs quoting.
func shellQuote(s string) string {
	if shellSafe.MatchString(s) {
		return s
	}
	return "'" + strings.ReplaceAll(s, "'", `'\''`) + "'"
}

func shellJoin(args []string) string {
	q := make([]string, len(args))
	for i, a := range args {
		q[i] = shellQuote(a)
	}
	return strings.Join(q, " ")
}
