// Package cli implements the stackward command line. It uses the standard
// library flag package only: users run this binary as root, so every
// dependency is attack surface we would rather not carry.
package cli

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"os/signal"
	"runtime"
	"strings"
	"syscall"
	"time"

	"github.com/Shironex/stackward/internal/audit"
	"github.com/Shironex/stackward/internal/catalog"
	"github.com/Shironex/stackward/internal/facts"
	"github.com/Shironex/stackward/internal/profile"
	"github.com/Shironex/stackward/internal/report"
	"github.com/Shironex/stackward/internal/sandbox"
	"github.com/Shironex/stackward/internal/version"
)

const usage = `stackward audits a Linux server running Docker, a PaaS, tunnels and
intrusion prevention, and reports what is exposed and misconfigured.
It only reads: it never changes the host it audits.

Usage:
  stackward audit [flags]     audit this host (sudo gives full coverage)
  stackward explain [id]      explain a check, or list every check
  stackward version           print the version
  stackward probe <host>      check a host from outside (run from another machine)
  stackward tui [flags]       browse the findings in the terminal

Run "stackward audit -h", "stackward probe -h" or "stackward tui -h" for their flags.

Exit codes: 0 no finding at or above --fail-on, 1 findings, 2 error.
`

// Run executes the command line args (without the program name) and returns
// the process exit code.
func Run(args []string, stdout, stderr io.Writer) int {
	if len(args) == 0 {
		_, _ = io.WriteString(stderr, usage)
		return report.ExitError
	}
	switch args[0] {
	case "audit":
		return runAudit(args[1:], stdout, stderr)
	case "explain":
		return runExplain(args[1:], stdout, stderr)
	case "version", "--version":
		return runVersion(stdout)
	case "tui":
		return runTUI(args[1:], stdout, stderr)
	case "probe":
		return runProbe(args[1:], stdout, stderr)
	case "help", "-h", "--help":
		_, _ = io.WriteString(stdout, usage)
		return report.ExitOK
	}
	fmt.Fprintf(stderr, "stackward: unknown command %q\n\n%s", args[0], usage)
	return report.ExitError
}

func runVersion(w io.Writer) int {
	v := version.String()
	if c := version.Commit(); c != "" {
		v += " (" + c + ")"
	}
	fmt.Fprintf(w, "stackward %s %s/%s %s\n", v, runtime.GOOS, runtime.GOARCH, runtime.Version())
	return report.ExitOK
}

type auditFlags struct {
	format       string
	jsonOut      bool
	mdOut        bool
	out          string
	failOn       string
	dumpFacts    bool
	factsFile    string
	profile      string
	timeout      time.Duration
	showHostname bool
	noSandbox    bool
	all          bool
	info         bool
	group        bool
	plain        bool
}

func runAudit(args []string, stdout, stderr io.Writer) int {
	var af auditFlags
	fs := flag.NewFlagSet("audit", flag.ContinueOnError)
	fs.SetOutput(stderr)
	fs.StringVar(&af.format, "format", "text", "output format: text, json or md")
	fs.BoolVar(&af.jsonOut, "json", false, "shorthand for --format json")
	fs.BoolVar(&af.mdOut, "md", false, "shorthand for --format md (Markdown for issues and handover notes)")
	fs.StringVar(&af.out, "out", "", "write the report to this file (the only file stackward writes)")
	fs.StringVar(&af.failOn, "fail-on", "fail", "exit 1 when a result is at or above: fail, warn or never")
	fs.BoolVar(&af.dumpFacts, "dump-facts", false, "print the collected facts as redacted JSON instead of a report (for bug reports)")
	fs.StringVar(&af.factsFile, "facts", "", "evaluate checks over a saved facts file instead of this host")
	fs.StringVar(&af.profile, "profile", "auto", "ingress profile: auto, tunnel, public-web, tailnet-only or paas-panel")
	fs.DurationVar(&af.timeout, "timeout", facts.DefaultTimeout, "time limit for each collector")
	fs.BoolVar(&af.showHostname, "show-hostname", false, "print the hostname instead of its hash")
	fs.BoolVar(&af.noSandbox, "no-sandbox", false, "do not apply the Landlock self sandbox (debugging only)")
	fs.BoolVar(&af.all, "all", false, "text and md output: list passing and skipped results too (text: and every info result in full)")
	fs.BoolVar(&af.info, "info", false, "text output: list every info result in full instead of one line each")
	fs.BoolVar(&af.group, "group", false, "text output: lay results out by check group instead of fail, warn, unknown, info")
	fs.BoolVar(&af.plain, "plain", false, "text output: no colors, Unicode or box lines, as when piped (NO_COLOR drops only colors)")
	fs.Usage = func() {
		fmt.Fprintf(stderr, "Usage: stackward audit [flags]\n\nFlags:\n")
		fs.PrintDefaults()
		fmt.Fprintf(stderr, "\nExit codes: 0 no finding at or above --fail-on, 1 findings, 2 error.\n")
	}
	if err := fs.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return report.ExitOK
		}
		return report.ExitError
	}
	if fs.NArg() > 0 {
		fmt.Fprintf(stderr, "stackward audit: unexpected argument %q\n", fs.Arg(0))
		return report.ExitError
	}
	if af.jsonOut {
		af.format = "json"
	}
	if af.mdOut {
		af.format = "md"
	}
	if af.format != "text" && af.format != "json" && af.format != "md" {
		fmt.Fprintf(stderr, "stackward audit: --format must be text, json or md, not %q\n", af.format)
		return report.ExitError
	}
	failOn := report.FailOn(af.failOn)
	if failOn != report.FailOnFail && failOn != report.FailOnWarn && failOn != report.FailOnNever {
		fmt.Fprintf(stderr, "stackward audit: --fail-on must be fail, warn or never, not %q\n", af.failOn)
		return report.ExitError
	}
	prof, profSet, err := profile.Parse(af.profile)
	if err != nil {
		fmt.Fprintf(stderr, "stackward audit: %v\n", err)
		return report.ExitError
	}

	// Everything that needs a file descriptor is opened before the
	// sandbox: afterwards no new file can be created.
	w := stdout
	var outFile *os.File
	if af.out != "" {
		outFile, err = createOutput(af.out)
		if err != nil {
			fmt.Fprintf(stderr, "stackward audit: %v\n", err)
			return report.ExitError
		}
		defer func() { _ = outFile.Close() }()
		w = outFile
	}
	textOpts := textOptions(stdout, outFile != nil, af.plain)
	textOpts.Passing, textOpts.Info, textOpts.Group = af.all, af.info, af.group
	var loaded *facts.Facts
	if af.factsFile != "" {
		loaded, err = loadFacts(af.factsFile)
		if err != nil {
			fmt.Fprintf(stderr, "stackward audit: %v\n", err)
			return report.ExitError
		}
	}

	var sys facts.System
	if loaded == nil {
		sys = hostSystem(af.noSandbox)
	}

	sb := sandbox.Apply(sandbox.Options{Disabled: af.noSandbox})

	f := loaded
	if f == nil {
		ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
		defer stop()
		f = facts.Run(ctx, sys, facts.Collectors(), facts.RunOptions{Timeout: af.timeout})
	}

	if af.dumpFacts {
		if err := audit.DumpFacts(w, f, af.showHostname); err != nil {
			fmt.Fprintf(stderr, "stackward audit: %v\n", err)
			return report.ExitError
		}
		return report.ExitOK
	}

	rep, err := audit.Evaluate(f, audit.Options{
		Version: version.String(), Sandbox: sb, Profile: prof, ProfileSet: profSet, ShowHostname: af.showHostname,
	})
	if err != nil {
		fmt.Fprintf(stderr, "stackward audit: %v\n", err)
		return report.ExitError
	}
	switch af.format {
	case "json":
		err = report.WriteJSON(w, rep)
	case "md":
		err = report.WriteMarkdown(w, rep, report.MarkdownOptions{Passing: af.all})
	default:
		err = report.WriteText(w, rep, textOpts)
	}
	if err != nil {
		fmt.Fprintf(stderr, "stackward audit: writing report: %v\n", err)
		return report.ExitError
	}
	return rep.ExitCode(failOn)
}

// hostSystem returns the System the collectors read the live host
// through. Call it right before sandbox.Apply: when the sandbox will be
// applied it first takes the read only socket ownership snapshot, because
// afterwards Landlock hides every other process's /proc/<pid>/fd and so
// which process holds which socket (see facts.SocketOwners).
func hostSystem(noSandbox bool) facts.System {
	sys := facts.System(facts.NewHostSystem())
	if noSandbox {
		return sys // ss -p names the owners itself
	}
	return facts.WithSocketOwners(sys, facts.SnapshotSocketOwners("/proc", facts.DefaultSnapshotLimits))
}

func loadFacts(path string) (*facts.Facts, error) {
	fh, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer func() { _ = fh.Close() }()
	return facts.Load(fh)
}

func runExplain(args []string, stdout, stderr io.Writer) int {
	cat, err := catalog.Default()
	if err != nil {
		fmt.Fprintf(stderr, "stackward explain: %v\n", err)
		return report.ExitError
	}
	if len(args) == 0 {
		group := ""
		for _, e := range cat.Entries() {
			if e.Group != group {
				if group != "" {
					fmt.Fprintln(stdout)
				}
				group = e.Group
				fmt.Fprintf(stdout, "%s  %s\n", group, catalog.GroupName(group))
			}
			fmt.Fprintf(stdout, "  %-9s %-9s %s\n", e.ID, e.Severity, e.Title)
		}
		return report.ExitOK
	}
	if len(args) > 1 {
		fmt.Fprintln(stderr, "stackward explain: give one check id")
		return report.ExitError
	}
	id := strings.ToUpper(strings.TrimSpace(args[0]))
	e, ok := cat.Lookup(id)
	if !ok {
		fmt.Fprintf(stderr, "stackward explain: unknown check %q; run \"stackward explain\" to list them\n", args[0])
		return report.ExitError
	}
	var b strings.Builder
	fmt.Fprintf(&b, "%s  %s\n", e.ID, e.Title)
	fmt.Fprintf(&b, "group:    %s (%s)\n", e.Group, catalog.GroupName(e.Group))
	fmt.Fprintf(&b, "severity: %s\n", e.Severity)
	if e.NeedsRoot {
		b.WriteString("root:     full result needs sudo\n")
	}
	section := func(title, body string) {
		if body == "" {
			return
		}
		fmt.Fprintf(&b, "\n%s\n%s\n", title, wrap(body, 76, "  "))
	}
	section("Why it matters", e.Rationale)
	section("Verify by hand", e.Verify)
	section("Fix", e.Fix)
	section("What a fix can break", e.Breaks)
	if e.Docs != "" {
		fmt.Fprintf(&b, "\nMore: %s\n", e.Docs)
	}
	_, _ = io.WriteString(stdout, b.String())
	return report.ExitOK
}

// wrap breaks text into lines of at most width runes, each indented.
func wrap(text string, width int, indent string) string {
	var lines []string
	for _, para := range strings.Split(text, "\n") {
		line := indent
		for _, word := range strings.Fields(para) {
			if len(line) > len(indent) && len(line)+1+len(word) > width {
				lines = append(lines, line)
				line = indent
			}
			if len(line) > len(indent) {
				line += " "
			}
			line += word
		}
		lines = append(lines, line)
	}
	return strings.Join(lines, "\n")
}
