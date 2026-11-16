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

	"github.com/Shironex/stackward/internal/apply"
	"github.com/Shironex/stackward/internal/audit"
	"github.com/Shironex/stackward/internal/facts"
	"github.com/Shironex/stackward/internal/profile"
	"github.com/Shironex/stackward/internal/report"
	"github.com/Shironex/stackward/internal/sandbox"
	"github.com/Shironex/stackward/internal/tui"
	"github.com/Shironex/stackward/internal/version"
	"github.com/Shironex/stackward/internal/waiver"
)

type tuiFlags struct {
	reportFile   string
	factsFile    string
	profile      string
	timeout      time.Duration
	showHostname bool
	noSandbox    bool
	waivers      string
	// The step list: a saved plan, the transaction deadline and --plain.
	planFile string
	within   time.Duration
	plain    bool
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
	return runTUIEnv(args, stdout, stderr, hostApplyEnv())
}

// runTUIEnv opens the findings browser, or with --plan the guided step
// list, which applies through env like stackward apply.
func runTUIEnv(args []string, stdout, stderr io.Writer, env applyEnv) int {
	tf, ok, code := parseTUIFlags(args, stderr)
	if !ok {
		return code
	}
	if tf.planFile != "" {
		return runSteps(tf, env, stdout, stderr)
	}
	s, code := prepareTUI(tf, stdout, stderr)
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

// parseTUIFlags parses the flags of tui. ok is false when tui must stop
// with code.
func parseTUIFlags(args []string, stderr io.Writer) (tf tuiFlags, ok bool, code int) {
	fs := flag.NewFlagSet("tui", flag.ContinueOnError)
	fs.SetOutput(stderr)
	fs.StringVar(&tf.reportFile, "report", "", "browse a saved report.v1 JSON file instead of auditing this host")
	fs.StringVar(&tf.factsFile, "facts", "", "evaluate checks over a saved facts file instead of this host")
	fs.StringVar(&tf.profile, "profile", "auto", "ingress profile: auto, tunnel, public-web, tailnet-only or paas-panel")
	fs.DurationVar(&tf.timeout, "timeout", facts.DefaultTimeout, "time limit for each collector")
	fs.BoolVar(&tf.showHostname, "show-hostname", false, "print the hostname instead of its hash")
	fs.BoolVar(&tf.noSandbox, "no-sandbox", false, "do not apply the Landlock self sandbox (debugging only)")
	fs.StringVar(&tf.waivers, "waivers", "", waiversHelp)
	fs.StringVar(&tf.planFile, "plan", "", "open the guided step list over this plan file (stackward plan --out writes one); applies only what you confirm (root)")
	fs.DurationVar(&tf.within, "confirm-within", apply.DefaultConfirmWithin, fmt.Sprintf("with --plan, access-critical steps: roll back unless confirmed within this time (%s to %s)", apply.MinConfirmWithin, apply.MaxConfirmWithin))
	fs.BoolVar(&tf.plain, "plain", false, "with --plan: print the plan as text instead of opening the list, as without a terminal")
	fs.Usage = func() {
		fmt.Fprintf(stderr, "Usage: stackward tui [flags]\n       stackward tui --plan PLAN.json [--confirm-within 5m] [--plain]\n\nBrowse the findings of an audit in the terminal. It only reads: no file\nis written and nothing on the host changes.\n\nWith --plan, choose plan steps in a guided list instead: each step shows\nwhat it changes, why, its diff and its undo. Nothing changes until you\nconfirm the review screen; then the steps run with the same code as\nstackward apply, with backups and a journal. Needs root. Without a\nterminal it prints the plan as text.\n\nFlags:\n")
		fs.PrintDefaults()
	}
	stop := func(c int) (tuiFlags, bool, int) { return tf, false, c }
	if err := fs.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return stop(report.ExitOK)
		}
		return stop(report.ExitError)
	}
	if err := checkTUIFlags(fs, tf); err != nil {
		fmt.Fprintf(stderr, "stackward tui: %v\n", err)
		return stop(report.ExitError)
	}
	return tf, true, report.ExitOK
}

// checkTUIFlags refuses stray arguments and flags that do not go together.
func checkTUIFlags(fs *flag.FlagSet, tf tuiFlags) error {
	if fs.NArg() > 0 {
		return fmt.Errorf("unexpected argument %q", fs.Arg(0))
	}
	set := map[string]bool{}
	fs.Visit(func(f *flag.Flag) { set[f.Name] = true })
	if tf.planFile != "" {
		for _, n := range []string{"report", "facts", "profile", "timeout", "show-hostname", "no-sandbox", "waivers"} {
			if set[n] {
				return fmt.Errorf("--%s does not go with --plan: the step list reads a saved plan; give it to stackward plan instead", n)
			}
		}
		return nil
	}
	for _, n := range []string{"confirm-within", "plain"} {
		if set[n] {
			return fmt.Errorf("--%s goes with --plan (the step list); the findings browser needs a terminal, stackward audit --plain prints the findings", n)
		}
	}
	return nil
}

// prepareTUI opens every file and the terminal, applies the sandbox and
// builds the report. A nil session means stop with code.
func prepareTUI(tf tuiFlags, stdout, stderr io.Writer) (*tuiSession, int) {
	fail := func(format string, a ...any) (*tuiSession, int) {
		fmt.Fprintf(stderr, "stackward tui: "+format+"\n", a...)
		return nil, report.ExitError
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
	if tf.reportFile != "" && tf.waivers != "" {
		return fail("--waivers applies when checks run; a saved report already shows its waivers")
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
	var ws []waiver.Waiver
	if loadedRep == nil {
		if ws, err = loadWaivers(tf.waivers); err != nil {
			return fail("%v", err)
		}
	}
	if !isTerminal(stdout) {
		return fail("needs a terminal; use \"stackward audit\" for plain or JSON output")
	}
	in, closeIn, err := terminalInput()
	if err != nil {
		return fail("%v", err)
	}

	var sys facts.System
	if loadedRep == nil && loaded == nil {
		sys = hostSystem(tf.noSandbox)
	}

	sb := sandbox.Apply(sandbox.Options{Disabled: tf.noSandbox})

	rep := loadedRep
	if rep == nil {
		f := loaded
		if f == nil {
			fmt.Fprintln(stderr, "stackward: auditing this host (read only)...")
			ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
			f = facts.Run(ctx, sys, facts.Collectors(), facts.RunOptions{Timeout: tf.timeout})
			stop()
		}
		rep, err = audit.Evaluate(f, audit.Options{
			Version: version.String(), Sandbox: sb, Profile: prof, ProfileSet: profSet, ShowHostname: tf.showHostname,
			Waivers: ws,
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
