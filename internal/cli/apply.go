package cli

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"os/signal"
	"runtime"
	"slices"
	"strings"
	"syscall"
	"time"

	"github.com/Shironex/stackward/internal/apply"
	"github.com/Shironex/stackward/internal/facts"
	"github.com/Shironex/stackward/internal/plan"
	"github.com/Shironex/stackward/internal/report"
	"github.com/Shironex/stackward/internal/version"
)

// Exit codes of apply and undo: 0 done (or nothing to do), 1 a step failed
// part way (the journal and the undo are printed), 2 refused or an error
// before anything changed.
const exitStepFailed = 1

// maxPlanBytes caps the plan file apply reads.
const maxPlanBytes = 16 << 20

// applyEnv is everything apply and undo take from the machine, so tests
// can run them against a temporary directory with a fake root and fake
// commands. Only hostApplyEnv touches the real host.
type applyEnv struct {
	host     apply.Host
	goos     string
	euid     func() int
	hostname func() (string, error)
	stdin    io.Reader
	isTTY    func() bool
	now      func() time.Time
	runID    string
	// session reads the login session this command runs in (transaction
	// and confirm); exe is the path of the running binary, which the
	// rollback timer runs a copy of; sleep waits (the timer's lock retry).
	session func() apply.Session
	exe     func() (string, error)
	sleep   func(time.Duration)
	// liveFacts reads the facts the lockout guard proves from (sshd,
	// accounts, Tailscale, listeners, firewall) from the host, read only.
	liveFacts func(ctx context.Context) *facts.Facts
}

func hostApplyEnv() applyEnv {
	return applyEnv{
		host:     apply.NewHost("/", nil),
		goos:     runtime.GOOS,
		euid:     os.Geteuid,
		hostname: os.Hostname,
		stdin:    os.Stdin,
		isTTY: func() bool {
			fi, err := os.Stdin.Stat()
			return err == nil && fi.Mode()&os.ModeCharDevice != 0
		},
		now:       time.Now,
		session:   func() apply.Session { return apply.ReadSession("/proc", os.Getpid(), os.Getenv) },
		exe:       os.Executable,
		sleep:     time.Sleep,
		liveFacts: guardFacts,
	}
}

// guardCollectors are the collectors the lockout guard reads.
var guardCollectors = []string{"ssh", "users", "tailscale", "listeners", "firewall"}

// guardFacts runs the guard's collectors on this host. Apply writes, so
// it runs without the Landlock sandbox, but the collectors only read.
func guardFacts(ctx context.Context) *facts.Facts {
	var cs []facts.Collector
	for _, c := range facts.Collectors() {
		if slices.Contains(guardCollectors, c.Name()) {
			cs = append(cs, c)
		}
	}
	return facts.Run(ctx, hostSystem(true), cs, facts.RunOptions{Timeout: facts.DefaultTimeout})
}

// stepFlags collects repeated --step values.
type stepFlags []string

func (s *stepFlags) String() string { return strings.Join(*s, ",") }
func (s *stepFlags) Set(v string) error {
	*s = append(*s, v)
	return nil
}

// parseInterleaved parses flags given before and after positional
// arguments ("apply plan.json --step x" as well as "apply --step x plan.json").
func parseInterleaved(fs *flag.FlagSet, args []string) ([]string, error) {
	var pos []string
	for {
		if err := fs.Parse(args); err != nil {
			return nil, err
		}
		if fs.NArg() == 0 {
			return pos, nil
		}
		pos = append(pos, fs.Arg(0))
		args = fs.Args()[1:]
	}
}

func runApply(args []string, stdout, stderr io.Writer) int {
	return runApplyEnv(args, stdout, stderr, hostApplyEnv())
}

func runApplyEnv(args []string, stdout, stderr io.Writer, env applyEnv) int {
	var steps stepFlags
	var allSafe, yes bool
	var within time.Duration
	fs := flag.NewFlagSet("apply", flag.ContinueOnError)
	fs.SetOutput(stderr)
	fs.Var(&steps, "step", "apply this step id (repeatable); opt in, networking and access-critical steps run only when named")
	fs.BoolVar(&allSafe, "all-safe", false, "apply every safe step that is not opt in")
	fs.BoolVar(&yes, "yes", false, "do not ask before applying (needed when stdin is not a terminal)")
	fs.DurationVar(&within, "confirm-within", apply.DefaultConfirmWithin, fmt.Sprintf("access-critical steps: roll back unless confirmed within this time (%s to %s)", apply.MinConfirmWithin, apply.MaxConfirmWithin))
	fs.Usage = func() {
		fmt.Fprintf(stderr, "Usage: stackward apply [--step ID]... [--all-safe] [--confirm-within 5m] [--yes] PLAN.json\n\nApply the selected steps of a plan written by stackward plan on this host.\nEvery file is checked against the plan first; FILE.orig is kept the first\ntime a file is replaced, every overwrite is backed up under\n%s/<run-id>/, and a run journal records it all.\nAccess-critical steps (SSH, firewall, users) run only when named, in a run\nof their own, inside a transaction: a systemd timer rolls them back unless\nstackward confirm runs from a new SSH session before the deadline.\nNeeds root. No Landlock sandbox: it writes.\n\nFlags:\n", apply.BackupRoot)
		fs.PrintDefaults()
		fmt.Fprintf(stderr, "\nExit codes: 0 applied (a transaction: applied, validated and waiting for confirm) or nothing to do,\n1 a step failed (undo printed) or a transaction rolled back at once, 2 refused or error (nothing changed).\n")
	}
	pos, err := parseInterleaved(fs, args)
	if err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return report.ExitOK
		}
		return report.ExitError
	}
	fail := func(format string, a ...any) int {
		fmt.Fprintf(stderr, "stackward apply: "+format+"\n", a...)
		return report.ExitError
	}
	if len(pos) != 1 {
		return fail("give exactly one plan file (stackward plan --out plan.json writes one)")
	}
	planFile := pos[0]
	if err := apply.CheckConfirmWithin(within); err != nil {
		return fail("%v", err)
	}
	if err := needRootOnLinux(env, "apply"); err != nil {
		return fail("%v; nothing was changed", err)
	}
	runID := env.runID
	if runID == "" {
		runID = apply.NewRunID(env.now())
	}
	release, err := apply.AcquireRunLock(env.host, runID)
	if err != nil {
		return fail("%v; nothing was changed", err)
	}
	defer func() { _ = release() }()
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	if code := finishPendingRestarts(ctx, env, yes, stdout, stderr); code >= 0 {
		return code
	}
	p, sum, err := loadPlan(planFile)
	if err != nil {
		return fail("%v", err)
	}
	hostname, err := env.hostname()
	if err != nil {
		hostname = ""
	}
	if err := apply.CheckPlan(p, hostname); err != nil {
		return fail("%v; nothing was changed", err)
	}
	sel, err := apply.Select(p, steps, allSafe)
	if err != nil {
		return fail("%v; nothing was changed", err)
	}
	if len(sel.Steps) == 0 {
		for _, n := range sel.NotRun {
			fmt.Fprintf(stdout, "not selected: %s (%s)\n", n.ID, n.Reason)
		}
		fmt.Fprintln(stdout, "stackward apply: no step selected; nothing was changed")
		return report.ExitOK
	}
	prepared, err := apply.Prepare(env.host, sel.Steps)
	if err != nil {
		return fail("%v; nothing was changed", err)
	}
	if sel.AccessCritical() {
		return applyTransaction(ctx, env, txnApply{
			planFile: planFile, plan: p, sum: sum, sel: sel, prepared: prepared,
			hostname: hostname, runID: runID, within: within, yes: yes,
		}, stdout, stderr)
	}
	if err := apply.WritePreview(stdout, planFile, p, sel, prepared); err != nil {
		return fail("%v", err)
	}
	n := apply.ToRun(prepared)
	if n == 0 {
		fmt.Fprintln(stdout, "\nstackward apply: nothing to do, every selected step is already applied; nothing was changed")
		return report.ExitOK
	}
	if ok, err := confirm(env, yes, stdout, fmt.Sprintf("\nApply %d step(s) on this host? [y/N] ", n)); !ok {
		if err != nil {
			return fail("%v; nothing was changed", err)
		}
		fmt.Fprintln(stdout, "stackward apply: not confirmed; nothing was changed")
		return report.ExitError
	}

	j, runErr := apply.Execute(ctx, prepared, apply.Options{
		Host: env.host, Version: version.String(), Now: env.now, RunID: runID,
		Plan: apply.PlanRef{
			File: planFile, SHA256: sum, Schema: p.Schema, ToolVersion: p.Tool.Version, GeneratedAt: p.GeneratedAt,
		},
		HostRef:  report.Host{HostnameHash: report.HashHostname(hostname)},
		Progress: func(format string, a ...any) { fmt.Fprintf(stdout, "  "+format+"\n", a...) },
	})
	if j == nil {
		return fail("%v; nothing was changed", runErr)
	}
	_ = apply.WriteResult(stdout, j)
	if runErr != nil {
		fmt.Fprintf(stderr, "stackward apply: %v\nThe run stopped there; later steps did not run. The undo is printed above.\n", runErr)
		return exitStepFailed
	}
	return report.ExitOK
}

func runUndo(args []string, stdout, stderr io.Writer) int {
	return runUndoEnv(args, stdout, stderr, hostApplyEnv())
}

func runUndoEnv(args []string, stdout, stderr io.Writer, env applyEnv) int {
	var runID, txnID string
	var yes, timer, boot bool
	fs := flag.NewFlagSet("undo", flag.ContinueOnError)
	fs.SetOutput(stderr)
	fs.StringVar(&runID, "run", "", "the run id to undo, as apply printed it")
	fs.StringVar(&txnID, "transaction", "", "roll back this open access-critical transaction now and stop its timer")
	fs.BoolVar(&yes, "yes", false, "do not ask before undoing (needed when stdin is not a terminal)")
	fs.BoolVar(&timer, "by-timer", false, "set only by the rollback timer: wait for the run lock, do nothing unless the transaction is still open, and leave the rollback to be acknowledged")
	fs.BoolVar(&boot, "by-boot", false, "set only by the boot rollback unit: like --by-timer, at boot, and remove the unit")
	fs.Usage = func() {
		fmt.Fprintf(stderr, "Usage: stackward undo --run RUN_ID [--yes]\n       stackward undo --transaction ID [--yes]\n\nReverse an apply run from its journal: restore every file it changed from\nthe backup (or remove the files it created), then run the steps' undo\ncommands. A file that changed after the run is not touched. --transaction\nrolls back an open access-critical transaction now; its rollback timer\nruns the same. Needs root.\n\nFlags:\n")
		fs.PrintDefaults()
		fmt.Fprintf(stderr, "\nExit codes: 0 undone, 1 failed part way, 2 refused or error (nothing changed).\n")
	}
	if err := fs.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return report.ExitOK
		}
		return report.ExitError
	}
	fail := func(format string, a ...any) int {
		fmt.Fprintf(stderr, "stackward undo: "+format+"\n", a...)
		return report.ExitError
	}
	if fs.NArg() > 0 {
		return fail("unexpected argument %q", fs.Arg(0))
	}
	by := byPerson
	switch {
	case timer && boot:
		return fail("give --by-timer or --by-boot, not both")
	case timer:
		by = byTimer
	case boot:
		by = byBoot
	}
	switch {
	case runID != "" && txnID != "":
		return fail("give --run or --transaction, not both")
	case txnID != "":
		return undoTransaction(env, txnID, yes, by, stdout, stderr)
	case by != byPerson:
		return fail("--by-timer and --by-boot go with --transaction")
	case runID == "":
		return fail("give the run to undo with --run RUN_ID (apply prints it)")
	}
	if err := needRootOnLinux(env, "undo"); err != nil {
		return fail("%v; nothing was changed", err)
	}
	release, err := apply.AcquireRunLock(env.host, "undo of "+runID)
	if err != nil {
		return fail("%v; nothing was changed", err)
	}
	defer func() { _ = release() }()
	t, err := apply.LoadTxn(env.host)
	if err != nil {
		return fail("%v; nothing was changed", err)
	}
	if t != nil && t.ID == runID && t.Status == apply.TxnOpen {
		return fail("run %s is an open transaction; roll it back with sudo stackward undo --transaction %s, which also stops its timer; nothing was changed", runID, runID)
	}
	j, err := apply.LoadJournal(env.host, runID)
	if err != nil {
		return fail("%v", err)
	}
	if why := hostMismatch(env, "run", runID, j.Host.HostnameHash); why != "" {
		return fail("%s", why)
	}
	lines := apply.UndoScript(j)
	if len(lines) == 0 || j.Status == apply.RunUndone {
		fmt.Fprintf(stdout, "stackward undo: run %s (%s) has nothing to undo\n", runID, j.Status)
		return report.ExitOK
	}
	fmt.Fprintf(stdout, "stackward undo: run %s (%s)\nsandbox:   %s\n\nWill do, newest change first:\n", runID, j.Status, apply.SandboxNote)
	for _, l := range lines {
		fmt.Fprintf(stdout, "   %s\n", l)
	}
	if ok, err := confirm(env, yes, stdout, "\nUndo this run? [y/N] "); !ok {
		if err != nil {
			return fail("%v; nothing was changed", err)
		}
		fmt.Fprintln(stdout, "stackward undo: not confirmed; nothing was changed")
		return report.ExitError
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	changed, err := apply.Undo(ctx, j, apply.UndoOptions{
		Host: env.host, Now: env.now,
		Progress: func(format string, a ...any) { fmt.Fprintf(stdout, "  "+format+"\n", a...) },
	})
	if err != nil {
		if !changed {
			return fail("%v; nothing was changed", err)
		}
		fmt.Fprintf(stderr, "stackward undo: %v\nThe undo stopped part way; the journal %s says what was restored.\n", err, apply.JournalPath(runID))
		return exitStepFailed
	}
	fmt.Fprintf(stdout, "stackward undo: run %s undone; the journal %s says what was restored\n", runID, apply.JournalPath(runID))
	return report.ExitOK
}

// finishPendingRestarts finishes, before anything else, the restarts that an
// earlier run left undone (its files written, its commands not run). It
// returns -1 when apply may go on, or the exit code to stop with.
func finishPendingRestarts(ctx context.Context, env applyEnv, yes bool, stdout, stderr io.Writer) int {
	pending, warnings, err := apply.FindPending(env.host)
	for _, w := range warnings {
		fmt.Fprintf(stderr, "stackward apply: warning: %s\n", w)
	}
	if err != nil {
		fmt.Fprintf(stderr, "stackward apply: looking for pending restarts: %v; nothing was changed\n", err)
		return report.ExitError
	}
	if len(pending) == 0 {
		return -1
	}
	fmt.Fprintf(stdout, "Pending restarts: an earlier run wrote these files but its restart did not finish. They are finished first:\n")
	for _, p := range pending {
		fmt.Fprintf(stdout, "  step %s of run %s:", p.StepID, p.RunID)
		for _, c := range p.Commands {
			fmt.Fprintf(stdout, " %s;", strings.Join(c, " "))
		}
		fmt.Fprintln(stdout)
	}
	ok, err := confirm(env, yes, stdout, "\nFinish the pending restarts now? [y/N] ")
	if !ok {
		if err != nil {
			fmt.Fprintf(stderr, "stackward apply: %v; nothing was changed\n", err)
		} else {
			fmt.Fprintln(stdout, "stackward apply: not confirmed; nothing was changed")
		}
		return report.ExitError
	}
	err = apply.FinishPending(ctx, pending, apply.PendingOptions{
		Host: env.host, Now: env.now,
		Progress: func(format string, a ...any) { fmt.Fprintf(stdout, "  "+format+"\n", a...) },
	})
	if err != nil {
		fmt.Fprintf(stderr, "stackward apply: %v\nThe pending restart is still pending; nothing else was applied.\n", err)
		return exitStepFailed
	}
	return -1
}

// needRootOnLinux refuses to change anything off Linux or without root.
func needRootOnLinux(env applyEnv, what string) error {
	if env.goos != "linux" {
		return fmt.Errorf("%s changes a Linux host and does not run on %s", what, env.goos)
	}
	if euid := env.euid(); euid != 0 {
		return fmt.Errorf("%s needs root (effective uid 0, this is %d): it writes files under /etc and %s and restarts services; run it with sudo", what, euid, apply.BackupRoot)
	}
	return nil
}

// confirm asks on a terminal; --yes skips the question. Without a terminal
// and without --yes it refuses, so a pipe never applies by accident.
func confirm(env applyEnv, yes bool, w io.Writer, question string) (bool, error) {
	if yes {
		return true, nil
	}
	if !env.isTTY() {
		return false, errors.New("stdin is not a terminal, so there is no one to ask; read the preview and pass --yes")
	}
	fmt.Fprint(w, question)
	line, err := bufio.NewReader(env.stdin).ReadString('\n')
	if err != nil && line == "" {
		return false, nil
	}
	a := strings.ToLower(strings.TrimSpace(line))
	return a == "y" || a == "yes", nil
}

// loadPlan reads a plan file strictly: unknown fields are refused, so a
// plan from a newer stackward is not applied with parts of it ignored.
func loadPlan(file string) (*plan.Plan, string, error) {
	f, err := os.Open(file)
	if err != nil {
		return nil, "", err
	}
	defer func() { _ = f.Close() }()
	b, err := io.ReadAll(io.LimitReader(f, maxPlanBytes+1))
	if err != nil {
		return nil, "", err
	}
	if len(b) > maxPlanBytes {
		return nil, "", fmt.Errorf("%s is larger than %d MiB; that is not a plan", file, maxPlanBytes>>20)
	}
	dec := json.NewDecoder(bytes.NewReader(b))
	dec.DisallowUnknownFields()
	var p plan.Plan
	if err := dec.Decode(&p); err != nil {
		return nil, "", fmt.Errorf("reading %s: %w (plan again with this stackward)", file, err)
	}
	if dec.More() {
		return nil, "", fmt.Errorf("reading %s: data after the plan", file)
	}
	return &p, plan.SHA256(b), nil
}
