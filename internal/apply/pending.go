package apply

import (
	"context"
	"fmt"
	"slices"
	"time"

	"github.com/Shironex/stackward/internal/plan"
)

// Pending is a step of an earlier run whose files are in place but whose
// restart or load commands did not finish.
type Pending struct {
	RunID  string
	StepID string
	// Commands are the step's commands, as the journal recorded the step.
	Commands [][]string

	journal *Journal
	index   int
}

// FindPending lists the steps of earlier runs still marked restart-pending,
// oldest run first. A journal that cannot be read is named in warnings, not
// an error, so one damaged journal does not stop every later apply.
func FindPending(h Host) (pending []Pending, warnings []string, err error) {
	names, err := h.ReadDir(BackupRoot)
	if err != nil {
		return nil, nil, err
	}
	slices.Sort(names)
	for _, n := range names {
		if !ValidRunID(n) {
			continue
		}
		j, lerr := LoadJournal(h, n)
		if lerr != nil {
			warnings = append(warnings, lerr.Error())
			continue
		}
		if j.Status == RunUndone || rolledBack(j) {
			continue
		}
		for i, js := range j.Steps {
			if !js.RestartPending {
				continue
			}
			var cmds [][]string
			for _, c := range js.Step.Commands {
				cmds = append(cmds, c.Args)
			}
			pending = append(pending, Pending{RunID: j.RunID, StepID: js.ID, Commands: cmds, journal: j, index: i})
		}
	}
	return pending, warnings, nil
}

// rolledBack reports whether the run was a transaction that rolled back,
// or tried to: its files are the rollback's business, and finishing a
// restart would load something the rollback meant to take away.
func rolledBack(j *Journal) bool {
	return j.Transaction != nil && (j.Transaction.Status == TxnRolledBack || j.Transaction.Status == TxnRollbackFailed)
}

// PendingOptions configure FinishPending.
type PendingOptions struct {
	Host           Host
	Now            func() time.Time
	CommandTimeout time.Duration
	Progress       func(format string, a ...any)
}

// FinishPending runs the commands of every pending step, in the order
// FindPending gave, and records them in the journal of the run they belong
// to. Each step is authorized again, and its files must still hold what the
// run wrote: a step whose file changed since is dropped from the pending
// list (its restart would load something else than the run wrote) and
// reported through Progress. The first failing command stops it; the step
// stays pending.
func FinishPending(ctx context.Context, pending []Pending, o PendingOptions) error {
	if o.Now == nil {
		o.Now = time.Now
	}
	if o.CommandTimeout == 0 {
		o.CommandTimeout = 5 * time.Minute
	}
	if o.Progress == nil {
		o.Progress = func(string, ...any) {}
	}
	for _, p := range pending {
		js := &p.journal.Steps[p.index]
		r := &runner{h: o.Host, o: Options{Now: o.Now, CommandTimeout: o.CommandTimeout}, j: p.journal}
		if err := plan.Authorize(js.Step); err != nil {
			return fmt.Errorf("refusing to finish the pending restart of %s from run %s: %w", p.StepID, p.RunID, err)
		}
		inPlace := true
		for _, f := range js.Files {
			if !f.Changed {
				continue
			}
			ok, err := plan.FileHolds(o.Host, f.Path, f.NewSHA256)
			if err != nil {
				return err
			}
			inPlace = inPlace && ok
		}
		if !inPlace {
			o.Progress("%s (run %s): a file changed since the run wrote it, so its pending restart is dropped", p.StepID, p.RunID)
			js.RestartPending = false
			if err := r.save(); err != nil {
				return err
			}
			continue
		}
		o.Progress("%s (run %s): finishing the pending restart", p.StepID, p.RunID)
		for _, c := range js.Step.Commands {
			if err := r.command(ctx, js, KindCommand, c.Args); err != nil {
				return fmt.Errorf("finishing the pending restart of step %s from run %s: %w", p.StepID, p.RunID, err)
			}
		}
		js.RestartPending = false
		if err := r.save(); err != nil {
			return err
		}
		o.Progress("%s (run %s): restart finished", p.StepID, p.RunID)
	}
	return nil
}
