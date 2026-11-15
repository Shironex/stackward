package apply

import (
	"context"
	"errors"
	"fmt"
	"io/fs"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/Shironex/stackward/internal/plan"
)

// touched reports whether a journal step changed anything: a file, or a
// command that ran.
func touched(js JournalStep) bool {
	return slices.ContainsFunc(js.Files, func(f JournalFile) bool { return f.Changed }) ||
		slices.ContainsFunc(js.Commands, func(c JournalCommand) bool { return c.Kind == KindCommand })
}

// undoCommands are the step's own undo commands that undo runs after the
// files are restored. File removals are left out: undo restores and
// removes files itself, from the journal, and only the ones this run
// changed.
func undoCommands(s plan.Step) [][]string {
	var out [][]string
	for _, c := range s.Undo.Commands {
		if len(c.Args) > 0 && c.Args[0] == "rm" {
			continue
		}
		out = append(out, c.Args)
	}
	return out
}

// UndoScript returns the shell commands that reverse a run, newest change
// first, for the reader to run by hand. It is printed when a run fails and
// after every run.
func UndoScript(j *Journal) []string {
	var out []string
	for i := len(j.Steps) - 1; i >= 0; i-- {
		js := j.Steps[i]
		if !touched(js) {
			continue
		}
		out = append(out, "# step "+js.ID)
		for k := len(js.Files) - 1; k >= 0; k-- {
			f := js.Files[k]
			if !f.Changed || f.Undone {
				continue
			}
			if f.Action == plan.Replace {
				out = append(out, "cp -p "+shellQuote(BackupPath(j.RunID, f.Path))+" "+shellQuote(f.Path))
			} else {
				out = append(out, "rm -f "+shellQuote(f.Path))
			}
		}
		for _, args := range undoCommands(js.Step) {
			q := make([]string, len(args))
			for n, a := range args {
				q[n] = shellQuote(a)
			}
			out = append(out, strings.Join(q, " "))
		}
	}
	return out
}

// errAlreadyUndone is the refusal to undo a run twice.
var errAlreadyUndone = errors.New("already undone")

// UndoOptions configure Undo.
type UndoOptions struct {
	Host           Host
	Now            func() time.Time
	CommandTimeout time.Duration
	Progress       func(format string, a ...any)
}

// Undo reverses a run from its journal: every file the run changed is
// restored from its backup (or removed when the run created it), newest
// first, then each touched step's undo commands run. Every step is
// authorized again and every file must still hold what the run wrote;
// otherwise nothing is restored. FILE.orig copies are kept. changed says
// whether anything on the host changed before an error.
func Undo(ctx context.Context, j *Journal, o UndoOptions) (changed bool, err error) {
	if o.Now == nil {
		o.Now = time.Now
	}
	if o.CommandTimeout == 0 {
		o.CommandTimeout = 5 * time.Minute
	}
	if o.Progress == nil {
		o.Progress = func(string, ...any) {}
	}
	if j.Status == RunUndone {
		return false, fmt.Errorf("run %s was %w at %s", j.RunID, errAlreadyUndone, j.UndoneAt)
	}
	h := o.Host
	// Check everything first, so a refusal changes nothing.
	for _, js := range j.Steps {
		if !touched(js) {
			continue
		}
		if js.Step.ID != js.ID {
			return false, fmt.Errorf("journal step %s holds step %s", js.ID, js.Step.ID)
		}
		if err := plan.Authorize(js.Step); err != nil {
			return false, fmt.Errorf("refusing to undo: %w", err)
		}
		for _, f := range js.Files {
			if !f.Changed || f.Undone {
				continue
			}
			if !slices.ContainsFunc(js.Step.Edits, func(e plan.FileEdit) bool { return e.Path == f.Path && e.Action == f.Action }) {
				return false, fmt.Errorf("refusing to undo: step %s does not edit %s", js.ID, f.Path)
			}
			ok, err := plan.FileHolds(h, f.Path, f.NewSHA256)
			if err != nil {
				return false, err
			}
			if !ok {
				return false, fmt.Errorf("refusing to undo: %s changed after run %s; restore it by hand from %s", f.Path, j.RunID, BackupPath(j.RunID, f.Path))
			}
			if f.Action == plan.Replace {
				ok, err := plan.FileHolds(h, BackupPath(j.RunID, f.Path), f.OldSHA256)
				if err != nil {
					return false, err
				}
				if !ok {
					return false, fmt.Errorf("refusing to undo: the backup %s does not hold the old content", BackupPath(j.RunID, f.Path))
				}
			}
		}
	}

	r := &runner{h: h, o: Options{Now: o.Now, CommandTimeout: o.CommandTimeout}, j: j}
	for i := len(j.Steps) - 1; i >= 0; i-- {
		js := &j.Steps[i]
		if !touched(*js) {
			continue
		}
		o.Progress("%s: undoing", js.ID)
		for k := len(js.Files) - 1; k >= 0; k-- {
			f := &js.Files[k]
			if !f.Changed || f.Undone {
				continue
			}
			if err := restore(h, j.RunID, *f); err != nil {
				_ = r.save()
				return changed, fmt.Errorf("step %s: restoring %s: %w", js.ID, f.Path, err)
			}
			changed = true
			f.Undone = true
			if err := r.save(); err != nil {
				return changed, err
			}
		}
		for _, args := range undoCommands(js.Step) {
			changed = true
			if err := r.command(ctx, js, KindUndo, args); err != nil {
				return changed, fmt.Errorf("step %s: %w", js.ID, err)
			}
		}
		js.RestartPending = false // the undo restored the files and ran its commands
		o.Progress("%s: undone", js.ID)
	}
	j.Status, j.UndoneAt = RunUndone, stamp(o.Now())
	return true, r.save()
}

// restore puts one file back as it was before the run.
func restore(h Host, runID string, f JournalFile) error {
	if f.Action == plan.Create {
		return h.Remove(f.Path)
	}
	b, err := h.ReadFile(BackupPath(runID, f.Path))
	if err != nil {
		return err
	}
	mode, err := strconv.ParseUint(f.Mode, 8, 32)
	if err != nil || mode&^0o777 != 0 {
		return fmt.Errorf("bad mode %q in the journal", f.Mode)
	}
	return h.WriteAtomic(f.Path, b, FileState{Mode: fs.FileMode(mode), UID: f.UID, GID: f.GID}, nil)
}

var shellSafe = regexp.MustCompile(`^[A-Za-z0-9_./=:,+@%-]+$`)

// shellQuote quotes s for a POSIX shell when it needs quoting.
func shellQuote(s string) string {
	if shellSafe.MatchString(s) {
		return s
	}
	return "'" + strings.ReplaceAll(s, "'", `'\''`) + "'"
}
