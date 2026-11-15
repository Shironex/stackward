package apply

import (
	"fmt"
	"io"
	"strings"

	"github.com/Shironex/stackward/internal/plan"
)

// SandboxNote is printed in every apply and undo header.
const SandboxNote = "none: apply writes files and runs commands, so the Landlock sandbox of audit, probe and plan is not applied"

// WritePreview prints what a run will do before it asks: every step that
// will run with its edits, commands and restarts, the steps already in
// place, and the steps not selected.
func WritePreview(w io.Writer, planFile string, p *plan.Plan, sel Selection, prepared []Prepared) error {
	var b strings.Builder
	pf := func(format string, a ...any) { fmt.Fprintf(&b, format, a...) }
	pf("stackward apply: this changes the host\n")
	pf("plan:      %s (stackward %s, facts from %s)\n", planFile, orNone(p.Tool.Version), orNone(p.GeneratedAt))
	pf("host:      %s, the plan's host\n", hostOf(p))
	pf("sandbox:   %s\n", SandboxNote)
	var run, done []Prepared
	for _, pr := range prepared {
		if pr.Applied {
			done = append(done, pr)
		} else {
			run = append(run, pr)
		}
	}
	if len(run) > 0 {
		pf("\nWill apply:\n")
	}
	var restarts []string
	seen := map[string]bool{}
	for i, pr := range run {
		s := pr.Step
		pf("%d. %s  [%s]  fixes %s\n", i+1, s.ID, s.Risk, strings.Join(s.Fixes, ", "))
		pf("   %s\n", s.Title)
		for _, e := range s.Edits {
			mode := ""
			if e.Mode != "" {
				mode = " (" + e.Mode + ")"
			}
			pf("   %-8s %s%s\n", e.Action, e.Path, mode)
			if len(e.Validate) > 0 {
				pf("            checked first with: %s <new file>\n", strings.Join(e.Validate, " "))
			}
		}
		for _, c := range s.Commands {
			pf("   run      %s\n", strings.Join(c.Args, " "))
		}
		for _, r := range s.Restarts {
			pf("   restarts %s\n", r)
			if !seen[r] {
				seen[r] = true
				restarts = append(restarts, r)
			}
		}
		for _, n := range s.Notes {
			pf("   note     %s\n", n)
		}
	}
	if len(done) > 0 {
		pf("\nAlready applied (nothing to do):\n")
		for _, pr := range done {
			pf("   %-20s %s\n", pr.Step.ID, pr.Why)
		}
	}
	if len(sel.NotRun) > 0 {
		pf("\nNot selected:\n")
		for _, n := range sel.NotRun {
			pf("   %-20s %s\n", n.ID, n.Reason)
		}
	}
	if len(run) > 0 {
		pf("\nrestarts:  %s\n", orNone(strings.Join(restarts, ", ")))
		pf("backups:   FILE.orig the first time a file is replaced, and every overwritten file under %s/<run-id>/\n", BackupRoot)
	}
	_, err := io.WriteString(w, b.String())
	return err
}

// ToRun counts the prepared steps that are not already applied.
func ToRun(prepared []Prepared) int {
	n := 0
	for _, p := range prepared {
		if !p.Applied {
			n++
		}
	}
	return n
}

// WriteResult prints how a run ended and how to undo it.
func WriteResult(w io.Writer, j *Journal) error {
	var b strings.Builder
	pf := func(format string, a ...any) { fmt.Fprintf(&b, format, a...) }
	pf("\nrun:       %s (%s)\n", j.RunID, j.Status)
	pf("journal:   %s\n", JournalPath(j.RunID))
	for _, s := range j.Steps {
		line := s.Status
		if s.Reason != "" {
			line += ": " + s.Reason
		}
		pf("   %-20s %s\n", s.ID, line)
	}
	if lines := UndoScript(j); len(lines) > 0 {
		pf("\nTo undo this run:\n   sudo stackward undo --run %s\nor by hand, as root:\n", j.RunID)
		for _, l := range lines {
			pf("   %s\n", l)
		}
		pf("FILE.orig copies stay in place either way.\n")
	}
	_, err := io.WriteString(w, b.String())
	return err
}

func hostOf(p *plan.Plan) string {
	if p.Host.Hostname != "" {
		return p.Host.Hostname
	}
	return orNone(p.Host.HostnameHash)
}
