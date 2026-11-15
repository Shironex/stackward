package cli

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/Shironex/stackward/internal/apply"
	"github.com/Shironex/stackward/internal/audit"
	"github.com/Shironex/stackward/internal/facts"
	"github.com/Shironex/stackward/internal/plan"
	"github.com/Shironex/stackward/internal/profile"
	"github.com/Shironex/stackward/internal/report"
	"github.com/Shironex/stackward/internal/sandbox"
	"github.com/Shironex/stackward/internal/version"
)

type planFlags struct {
	reportFile   string
	factsFile    string
	out          string
	jsonOut      bool
	emitScript   bool
	profile      string
	timeout      time.Duration
	showHostname bool
	noSandbox    bool
}

// runPlan audits the host (or loads a saved report or facts file) with the
// same pipeline and sandbox as audit, then writes the plan. It changes
// nothing: the only file it writes is --out, opened before the sandbox.
func runPlan(args []string, stdout, stderr io.Writer) int {
	var pf planFlags
	fs := flag.NewFlagSet("plan", flag.ContinueOnError)
	fs.SetOutput(stderr)
	fs.StringVar(&pf.reportFile, "report", "", "plan from a saved report.v1 JSON file (add --facts with the same audit's facts for file edits)")
	fs.StringVar(&pf.factsFile, "facts", "", "plan from a saved facts file instead of this host")
	fs.StringVar(&pf.out, "out", "", "write the plan.v1 JSON to this file (the only file stackward writes)")
	fs.BoolVar(&pf.jsonOut, "json", false, "print the plan.v1 JSON instead of the summary")
	fs.BoolVar(&pf.emitScript, "emit-script", false, "print the plan as a shell script to read and run yourself (stackward never runs it)")
	fs.StringVar(&pf.profile, "profile", "auto", "ingress profile: auto, tunnel, public-web, tailnet-only or paas-panel")
	fs.DurationVar(&pf.timeout, "timeout", facts.DefaultTimeout, "time limit for each collector")
	fs.BoolVar(&pf.showHostname, "show-hostname", false, "print the hostname instead of its hash")
	fs.BoolVar(&pf.noSandbox, "no-sandbox", false, "do not apply the Landlock self sandbox (debugging only)")
	fs.Usage = func() {
		fmt.Fprintf(stderr, "Usage: stackward plan [flags]\n\nWrite down the changes that would fix the findings: file edits as diffs,\ncommands, a risk class and an undo for every step. Nothing on the host\nchanges. Part of the upcoming 0.2; apply is not released yet.\n\nFlags:\n")
		fs.PrintDefaults()
		fmt.Fprintf(stderr, "\nExit codes: 0 plan written, 2 error.\n")
	}
	if err := fs.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return report.ExitOK
		}
		return report.ExitError
	}
	fail := func(format string, a ...any) int {
		fmt.Fprintf(stderr, "stackward plan: "+format+"\n", a...)
		return report.ExitError
	}
	if fs.NArg() > 0 {
		return fail("unexpected argument %q", fs.Arg(0))
	}
	if pf.jsonOut && pf.emitScript {
		return fail("give --json or --emit-script, not both")
	}
	prof, profSet, err := profile.Parse(pf.profile)
	if err != nil {
		return fail("%v", err)
	}
	if pf.reportFile != "" && profSet {
		return fail("--profile applies when checks run; a saved report already has one")
	}

	// Everything that needs a file descriptor is opened before the
	// sandbox: afterwards no new file can be created.
	var outFile *os.File
	if pf.out != "" {
		if outFile, err = createOutput(pf.out); err != nil {
			return fail("%v", err)
		}
		defer func() { _ = outFile.Close() }()
	}
	var loadedRep *report.Report
	var loaded *facts.Facts
	if pf.reportFile != "" {
		if loadedRep, err = loadReport(pf.reportFile); err != nil {
			return fail("%v", err)
		}
	}
	if pf.factsFile != "" {
		if loaded, err = loadFacts(pf.factsFile); err != nil {
			return fail("%v", err)
		}
	}

	var sys facts.System
	var sess apply.Session
	if loadedRep == nil && loaded == nil {
		sys = hostSystem(pf.noSandbox)
		// The lockout guard needs the planning session's source. Reading
		// it walks /proc up to sshd, which the sandbox forbids.
		sess = planSession()
	}

	sb := sandbox.Apply(sandbox.Options{Disabled: pf.noSandbox})

	f := loaded
	if f == nil && loadedRep == nil {
		fmt.Fprintln(stderr, "stackward: auditing this host (read only)...")
		ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
		f = facts.Run(ctx, sys, facts.Collectors(), facts.RunOptions{Timeout: pf.timeout})
		stop()
	}
	auditOpts := audit.Options{Version: version.String(), Sandbox: sb, Profile: prof, ProfileSet: profSet, ShowHostname: pf.showHostname}
	rep := loadedRep
	if f != nil {
		evaluated, err := audit.Evaluate(f, auditOpts)
		if err != nil {
			return fail("%v", err)
		}
		if rep == nil {
			rep = evaluated
		} else if err := sameAudit(rep, evaluated); err != nil {
			return fail("%v", err)
		}
	}

	p := plan.Build(plan.Input{Facts: f, Results: plan.ResultsFromReport(rep)}, rep, plan.Options{
		Version: version.String(), Sandbox: sb, SourceKind: planSource(pf),
		Vetoes: []plan.Veto{plan.LockoutVeto(apply.GuardInput(f, sess))},
	})

	if outFile != nil {
		if err := plan.WriteJSON(outFile, p); err != nil {
			return fail("writing %s: %v", pf.out, err)
		}
	}
	switch {
	case pf.jsonOut:
		err = plan.WriteJSON(stdout, p)
	case pf.emitScript:
		err = plan.WriteScript(stdout, p)
	default:
		err = plan.WriteText(stdout, p)
	}
	if err != nil {
		return fail("writing the plan: %v", err)
	}
	return report.ExitOK
}

// planSession reads the session plan runs in (a variable, so tests never
// read the real /proc).
var planSession = func() apply.Session { return apply.ReadSession("/proc", os.Getpid(), os.Getenv) }

func planSource(pf planFlags) string {
	switch {
	case pf.reportFile != "" && pf.factsFile != "":
		return plan.FromReportFacts
	case pf.reportFile != "":
		return plan.FromReport
	case pf.factsFile != "":
		return plan.FromFacts
	}
	return plan.FromLive
}

// sameAudit refuses a report and a facts file that come from different
// audits: the plan would edit files the report never judged.
func sameAudit(loaded, fromFacts *report.Report) error {
	if loaded.GeneratedAt != fromFacts.GeneratedAt || hostKey(loaded.Host) != hostKey(fromFacts.Host) {
		return fmt.Errorf("the report (%s) and the facts (%s) come from different audits or hosts; give the facts of the audit that wrote the report",
			orDash(loaded.GeneratedAt), orDash(fromFacts.GeneratedAt))
	}
	return nil
}

// hostKey is the hostname hash of a report host, whether the report shows
// the hostname or only its hash.
func hostKey(h report.Host) string {
	if h.Hostname != "" {
		return report.HashHostname(h.Hostname)
	}
	return h.HostnameHash
}

func orDash(s string) string {
	if s == "" {
		return "no time"
	}
	return s
}
