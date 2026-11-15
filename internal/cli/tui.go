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

	tea "charm.land/bubbletea/v2"

	"github.com/Shironex/stackward/internal/audit"
	"github.com/Shironex/stackward/internal/facts"
	"github.com/Shironex/stackward/internal/profile"
	"github.com/Shironex/stackward/internal/report"
	"github.com/Shironex/stackward/internal/sandbox"
	"github.com/Shironex/stackward/internal/tui"
	"github.com/Shironex/stackward/internal/version"
)

type tuiFlags struct {
	reportFile   string
	factsFile    string
	profile      string
	timeout      time.Duration
	showHostname bool
	noSandbox    bool
}

// tuiSession is what the browser needs, gathered before it starts.
type tuiSession struct {
	rep    *report.Report
	opts   tui.Options
	in     *os.File
	closer func()
}

// runTUI audits the host (or loads saved facts or a saved report) with the
// same pipeline and sandbox as audit, then opens the findings browser.
func runTUI(args []string, stdout, stderr io.Writer) int {
	s, code := prepareTUI(args, stdout, stderr)
	if s == nil {
		return code
	}
	defer s.closer()
	if err := tui.Run(s.rep, s.opts, s.in, stdout); err != nil && !errors.Is(err, tea.ErrProgramKilled) {
		fmt.Fprintf(stderr, "stackward tui: %v\n", err)
		return report.ExitError
	}
	return report.ExitOK
}

// prepareTUI parses flags, opens every file and the terminal, applies the
// sandbox and builds the report. A nil session means stop with code.
func prepareTUI(args []string, stdout, stderr io.Writer) (*tuiSession, int) {
	var tf tuiFlags
	fs := flag.NewFlagSet("tui", flag.ContinueOnError)
	fs.SetOutput(stderr)
	fs.StringVar(&tf.reportFile, "report", "", "browse a saved report.v1 JSON file instead of auditing this host")
	fs.StringVar(&tf.factsFile, "facts", "", "evaluate checks over a saved facts file instead of this host")
	fs.StringVar(&tf.profile, "profile", "auto", "ingress profile: auto, tunnel, public-web, tailnet-only or paas-panel")
	fs.DurationVar(&tf.timeout, "timeout", facts.DefaultTimeout, "time limit for each collector")
	fs.BoolVar(&tf.showHostname, "show-hostname", false, "print the hostname instead of its hash")
	fs.BoolVar(&tf.noSandbox, "no-sandbox", false, "do not apply the Landlock self sandbox (debugging only)")
	fs.Usage = func() {
		fmt.Fprintf(stderr, "Usage: stackward tui [flags]\n\nBrowse the findings of an audit in the terminal. It only reads: no file\nis written and nothing on the host changes.\n\nFlags:\n")
		fs.PrintDefaults()
	}
	if err := fs.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return nil, report.ExitOK
		}
		return nil, report.ExitError
	}
	fail := func(format string, a ...any) (*tuiSession, int) {
		fmt.Fprintf(stderr, "stackward tui: "+format+"\n", a...)
		return nil, report.ExitError
	}
	if fs.NArg() > 0 {
		return fail("unexpected argument %q", fs.Arg(0))
	}
	if tf.reportFile != "" && tf.factsFile != "" {
		return fail("give --report or --facts, not both")
	}
	prof, profSet, err := profile.Parse(tf.profile)
	if err != nil {
		return fail("%v", err)
	}
	if tf.reportFile != "" && profSet {
		return fail("--profile applies when checks run; a saved report already has one")
	}
	// Open everything before the sandbox: afterwards no file can be
	// opened for writing, and the terminal is opened read and write.
	var loadedRep *report.Report
	var loaded *facts.Facts
	source := "live audit"
	switch {
	case tf.reportFile != "":
		loadedRep, err = loadReport(tf.reportFile)
		source = "report " + tf.reportFile
	case tf.factsFile != "":
		loaded, err = loadFacts(tf.factsFile)
		source = "facts " + tf.factsFile
	}
	if err != nil {
		return fail("%v", err)
	}
	if !isTerminal(stdout) {
		return fail("needs a terminal; use \"stackward audit\" for plain or JSON output")
	}
	in, closeIn, err := terminalInput()
	if err != nil {
		return fail("%v", err)
	}

	sb := sandbox.Apply(sandbox.Options{Disabled: tf.noSandbox})

	rep := loadedRep
	if rep == nil {
		f := loaded
		if f == nil {
			fmt.Fprintln(stderr, "stackward: auditing this host (read only)...")
			ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
			f = facts.Run(ctx, facts.NewHostSystem(), facts.Collectors(), facts.RunOptions{Timeout: tf.timeout})
			stop()
		}
		rep, err = audit.Evaluate(f, audit.Options{
			Version: version.String(), Sandbox: sb, Profile: prof, ProfileSet: profSet, ShowHostname: tf.showHostname,
		})
		if err != nil {
			closeIn()
			return fail("%v", err)
		}
	}
	return &tuiSession{
		rep:    rep,
		opts:   tui.Options{ShowHostname: tf.showHostname, NoColor: !colorEnv(), Source: source},
		in:     in,
		closer: closeIn,
	}, report.ExitOK
}

func loadReport(path string) (*report.Report, error) {
	fh, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer func() { _ = fh.Close() }()
	rep, err := tui.LoadReport(fh)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	return rep, nil
}

// terminalInput returns stdin when it is a terminal, otherwise the
// controlling terminal, opened now because the sandbox forbids it later.
func terminalInput() (*os.File, func(), error) {
	if isTerminal(os.Stdin) {
		return os.Stdin, func() {}, nil
	}
	in, _, err := tea.OpenTTY()
	if err != nil {
		return nil, nil, fmt.Errorf("needs a terminal to read keys from: %w", err)
	}
	return in, func() { _ = in.Close() }, nil
}

// isTerminal reports whether w is a character device (a terminal).
func isTerminal(w any) bool {
	f, ok := w.(*os.File)
	if !ok {
		return false
	}
	fi, err := f.Stat()
	return err == nil && fi.Mode()&os.ModeCharDevice != 0
}

// colorEnv reports whether the environment allows color.
func colorEnv() bool {
	return os.Getenv("NO_COLOR") == "" && os.Getenv("TERM") != "dumb"
}
