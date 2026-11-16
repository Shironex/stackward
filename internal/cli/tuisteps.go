package cli

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	tea "charm.land/bubbletea/v2"

	"github.com/Shironex/stackward/internal/apply"
	"github.com/Shironex/stackward/internal/facts"
	"github.com/Shironex/stackward/internal/plan"
	"github.com/Shironex/stackward/internal/report"
	"github.com/Shironex/stackward/internal/tui"
)

// reviewHolder is what the run lock names while the step list reads the
// transaction state.
const reviewHolder = "stackward tui step list (reading only)"

// runSteps opens the guided step list over a saved plan. The list only
// presents the steps and collects a choice; when the reader confirms the
// review, the list closes and applySelected runs the choice, the same code
// as stackward apply. Without a terminal, or with --plain, it prints the
// plan as text and applies nothing.
func runSteps(tf tuiFlags, env applyEnv, stdout, stderr io.Writer) int {
	fail := func(format string, a ...any) int {
		fmt.Fprintf(stderr, "stackward tui: "+format+"\n", a...)
		return report.ExitError
	}
	p, _, err := loadPlan(tf.planFile)
	if err != nil {
		return fail("%v", err)
	}
	if why := plainReason(tf.plain, isTerminal(stdout)); why != "" {
		if err := plan.WriteText(stdout, p); err != nil {
			return fail("writing the plan: %v", err)
		}
		fmt.Fprintf(stderr, "stackward tui: %s, so this is the plan as text and nothing was applied; apply steps with: sudo stackward apply --step ID %s\n", why, tf.planFile)
		return report.ExitOK
	}
	if err := apply.CheckConfirmWithin(tf.within); err != nil {
		return fail("%v", err)
	}
	if err := needRootOnLinux(env, "the step list"); err != nil {
		return fail("%v; nothing was changed", err)
	}
	hostname, err := env.hostname()
	if err != nil {
		hostname = ""
	}
	if err := apply.CheckPlan(p, hostname); err != nil {
		return fail("%v; nothing was changed", err)
	}
	in, closeIn, err := terminalInput()
	if err != nil {
		return fail("%v", err)
	}
	defer closeIn()
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	b, list, err := newStepsBackend(ctx, env, tf.planFile, p, tf.within, stderr)
	if err != nil {
		return fail("%v; nothing was changed", err)
	}
	choice, err := tui.RunSteps(list, b.options(!colorEnv()), in, stdout)
	if err != nil && !errors.Is(err, tea.ErrProgramKilled) {
		return fail("%v; nothing was changed", err)
	}
	return b.applyChoice(choice, stdout, stderr)
}

// plainReason says why the step list prints the plan as text instead of
// opening, or "" when it opens.
func plainReason(plain, tty bool) string {
	switch {
	case plain:
		return "--plain was given"
	case !tty:
		return "the output is not a terminal"
	}
	return ""
}

// stepsBackend is the CLI side of the step list: it judges every step on
// this host with apply's own read only code (Prepare, the transaction
// state, the lockout guard) and works out the review with apply.Select and
// apply.WritePreview. It changes nothing; applyChoice hands the choice to
// applySelected.
type stepsBackend struct {
	env      applyEnv
	planFile string
	plan     *plan.Plan
	within   time.Duration
	// runID is the id apply will use, so the review can name the
	// transaction, its timer and the commands to confirm or roll it back.
	runID string
	sess  apply.Session
	// live are the facts the lockout guard proves from, read once when
	// the list opens; nil when no step needs a proof.
	live *facts.Facts
}

// newStepsBackend judges the plan's steps on this host and returns the list
// to show.
func newStepsBackend(ctx context.Context, env applyEnv, planFile string, p *plan.Plan, within time.Duration, stderr io.Writer) (*stepsBackend, tui.StepList, error) {
	b := &stepsBackend{env: env, planFile: planFile, plan: p, within: within, runID: env.runID, sess: env.session()}
	if b.runID == "" {
		b.runID = apply.NewRunID(env.now())
	}
	if apply.NeedsProof(p.Steps) {
		fmt.Fprintln(stderr, "stackward: reading this host's SSH, accounts and firewall for the lockout guard (read only)...")
		b.live = env.liveFacts(ctx)
	}
	release, err := apply.AcquireRunLock(env.host, reviewHolder)
	if err != nil {
		return nil, tui.StepList{}, err
	}
	defer func() { _ = release() }()
	t, err := apply.LoadTxn(env.host)
	if err != nil {
		return nil, tui.StepList{}, err
	}
	list := tui.StepList{
		PlanFile: planFile, Host: hostOfPlan(p), ToolVersion: p.Tool.Version,
		GeneratedAt: p.GeneratedAt, NotPlanned: len(p.Skipped),
	}
	for _, s := range p.Steps {
		g, ok := plan.Lookup(s.ID)
		if !ok {
			return nil, tui.StepList{}, fmt.Errorf("step %s is not a known step", s.ID)
		}
		it := stepItem(s, g)
		b.judge(&it, s, g, t)
		list.Steps = append(list.Steps, it)
	}
	return b, list, nil
}

// judge fills what apply would find on this host now: already applied, or
// why it would refuse the step, and the lockout guard's proof.
func (b *stepsBackend) judge(it *tui.StepItem, s plan.Step, g plan.Generator, t *apply.Txn) {
	prepared, err := apply.Prepare(b.env.host, []plan.Step{s})
	if err != nil {
		it.Blocked = err.Error()
	} else {
		it.Applied, it.AppliedWhy = prepared[0].Applied, prepared[0].Why
	}
	if g.Risk != plan.AccessCritical || it.Blocked != "" {
		return
	}
	if why := t.Blocks(b.env.now()); why != "" {
		it.Blocked = why
		return
	}
	if why, err := apply.StaleBootUnits(b.env.host, t); err != nil || why != "" {
		it.Blocked = errOr(err, why)
		return
	}
	if !plan.NeedsProof(s) {
		it.Guard = &tui.GuardProof{}
		return
	}
	proofs, err := apply.GuardAccess([]plan.Step{s}, b.live, b.sess)
	if err != nil {
		it.Blocked = "the lockout guard cannot prove a second way in: " + err.Error()
		return
	}
	p := proofs[0]
	it.Guard = &tui.GuardProof{Needed: p.Needed, Narrows: p.Narrows, Ways: p.Ways, ConfirmFrom: p.ConfirmFrom}
}

// stepItem is a plan step as the list shows it. The title, the checks it
// fixes, the risk class and opt in come from the step's generator, like
// apply.Select takes them, never from the plan file.
func stepItem(s plan.Step, g plan.Generator) tui.StepItem {
	it := tui.StepItem{
		ID: s.ID, Title: g.Title, Class: string(g.Risk), OptIn: g.OptIn,
		Fixes: g.Fixes, Restarts: s.Restarts, Notes: s.Notes,
	}
	for _, c := range s.Before {
		it.Changes = append(it.Changes, "first run "+strings.Join(c.Args, " "))
	}
	for _, e := range s.Edits {
		line := e.Action + " " + e.Path
		if e.Mode != "" {
			line += " (" + e.Mode + ")"
		}
		it.Changes = append(it.Changes, line)
		if len(e.Validate) > 0 {
			it.Changes = append(it.Changes, "checked first with: "+strings.Join(e.Validate, " ")+" <new file>")
		}
		if e.Redacted {
			it.Changes = append(it.Changes, "content redacted in this plan: a secret shaped value was masked, so apply refuses it")
		}
		if d := strings.TrimSuffix(e.Diff, "\n"); d != "" {
			it.Diff = append(it.Diff, strings.Split(d, "\n")...)
		}
	}
	for _, c := range s.Commands {
		it.Changes = append(it.Changes, "run "+strings.Join(c.Args, " "))
	}
	for _, r := range s.Restarts {
		it.Changes = append(it.Changes, "restarts "+r)
	}
	it.Undo = append(it.Undo, s.Undo.Description)
	for _, c := range s.Undo.Commands {
		it.Undo = append(it.Undo, strings.Join(c.Args, " "))
	}
	return it
}

// options are the list's hooks into apply's own code.
func (b *stepsBackend) options(noColor bool) tui.StepsOptions {
	return tui.StepsOptions{
		NoColor:       noColor,
		ConfirmWithin: b.within.String(),
		Allowed: func(ids []string) error {
			_, err := apply.Select(b.plan, ids, false)
			return err
		},
		Review: b.review,
	}
}

// review works out what apply would do with ids, with apply's own
// selection, checks and preview, and the guard and transaction text of
// stackward apply. It only reads.
func (b *stepsBackend) review(ids []string) tui.Review {
	var w strings.Builder
	refuse := func(err error) tui.Review { return tui.Review{Text: w.String(), Refused: err.Error()} }
	sel, err := apply.Select(b.plan, ids, false)
	if err != nil {
		return refuse(err)
	}
	release, err := apply.AcquireRunLock(b.env.host, reviewHolder)
	if err != nil {
		return refuse(err)
	}
	defer func() { _ = release() }()
	pending, warnings, err := apply.FindPending(b.env.host)
	if err != nil {
		return refuse(fmt.Errorf("looking for pending restarts: %w", err))
	}
	prepared, err := apply.Prepare(b.env.host, sel.Steps)
	if err != nil {
		return refuse(err)
	}
	ac := sel.AccessCritical()
	if ac {
		w.WriteString(consoleReminder)
	}
	for _, warn := range warnings {
		fmt.Fprintf(&w, "warning: %s\n", warn)
	}
	if len(pending) > 0 {
		writePending(&w, pending)
		w.WriteString("\n")
	}
	if err := apply.WritePreview(&w, b.planFile, b.plan, sel, prepared); err != nil {
		return refuse(err)
	}
	r := tui.Review{ToRun: apply.ToRun(prepared), AccessCritical: ac}
	if r.ToRun == 0 {
		w.WriteString("\nNothing to do: every selected step is already applied.\n")
		r.Text = w.String()
		return r
	}
	if ac {
		if err := b.reviewTransaction(&w, sel.Steps); err != nil {
			return refuse(err)
		}
	}
	w.WriteString("\nOn y the step list closes and stackward apply runs these steps, checking every one again first, and prints what it does.\n")
	r.Text = w.String()
	return r
}

// reviewTransaction writes the guard proof and how the transaction
// protects the change, or returns why apply would not open it.
func (b *stepsBackend) reviewTransaction(w io.Writer, steps []plan.Step) error {
	t, err := apply.LoadTxn(b.env.host)
	if err != nil {
		return err
	}
	if why := t.Blocks(b.env.now()); why != "" {
		return errors.New(why)
	}
	if why, err := apply.StaleBootUnits(b.env.host, t); err != nil || why != "" {
		return errors.New(errOr(err, why))
	}
	var confirmFrom []string
	if apply.NeedsProof(steps) {
		proofs, err := apply.GuardAccess(steps, b.live, b.sess)
		if err != nil {
			return err
		}
		fmt.Fprintf(w, "\nlockout guard: a second way in, proven from this host's live state when the list opened (apply proves it again):\n")
		writeProofs(w, steps, proofs)
		confirmFrom = apply.ConfirmFrom(proofs)
	}
	writeTxnPlan(w, b.runID, b.within, "the ports it listens on now", confirmFrom)
	fmt.Fprintf(w, `
After apply, transaction %[1]s is OPEN until its deadline:
   keep this session open, and from a NEW SSH session to this host run
      sudo stackward confirm %[1]s
   if the new session cannot log in, do nothing: the change rolls back at the deadline
   from the provider console instead:
      sudo stackward confirm --console %[1]s
   to roll back now:
      sudo stackward undo --transaction %[1]s
`, b.runID)
	return nil
}

// applyChoice runs a confirmed choice with applySelected, the code of
// stackward apply. The review screen was the confirmation, so apply does
// not ask again; it still checks everything again before it changes
// anything, and refuses with the reason when the host moved on.
func (b *stepsBackend) applyChoice(c tui.Choice, stdout, stderr io.Writer) int {
	if !c.Apply || len(c.Steps) == 0 {
		fmt.Fprintln(stdout, "stackward tui: nothing was applied")
		return report.ExitOK
	}
	fmt.Fprintf(stdout, "stackward tui: applying %s, confirmed on the review screen, with the code of stackward apply\n\n", strings.Join(c.Steps, ", "))
	env := b.env
	env.runID = b.runID
	return applySelected(env, applyRequest{planFile: b.planFile, steps: c.Steps, within: b.within, yes: true}, stdout, stderr)
}

// hostOfPlan is the plan's host as the plan names it.
func hostOfPlan(p *plan.Plan) string {
	if p.Host.Hostname != "" {
		return p.Host.Hostname
	}
	return p.Host.HostnameHash
}
