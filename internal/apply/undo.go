package apply

import (
	"context"
	"errors"
	"fmt"
	"io/fs"
	"path"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/Shironex/stackward/internal/plan"
)

// touched reports whether a journal step changed anything: a file, a
// directory created for one, or a command that ran.
func touched(js JournalStep) bool {
	return slices.ContainsFunc(js.Files, func(f JournalFile) bool { return f.Changed || len(f.CreatedDirs) > 0 }) ||
		slices.ContainsFunc(js.Commands, func(c JournalCommand) bool { return c.Kind == KindCommand || c.Kind == KindBefore })
}

// ran are the step commands a journal step started, before and after its
// edits, whatever their exit.
func ran(js JournalStep) [][]string {
	var out [][]string
	for _, c := range js.Commands {
		if c.Kind == KindCommand || c.Kind == KindBefore {
			out = append(out, c.Args)
		}
	}
	return out
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
		for k := len(js.Files) - 1; k >= 0; k-- {
			dirs := js.Files[k].CreatedDirs
			for d := len(dirs) - 1; d >= 0; d-- {
				out = append(out, "rmdir --ignore-fail-on-non-empty "+shellQuote(dirs[d]))
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
	// Check everything first, so a refusal changes nothing.
	if err := checkUndoable(o.Host, j); err != nil {
		return false, err
	}

	r := &runner{h: o.Host, o: Options{Now: o.Now, CommandTimeout: o.CommandTimeout}, j: j}
	for i := len(j.Steps) - 1; i >= 0; i-- {
		js := &j.Steps[i]
		if !touched(*js) {
			continue
		}
		o.Progress("%s: undoing", js.ID)
		stepChanged, err := undoStep(ctx, r, o, js)
		changed = changed || stepChanged
		if err != nil {
			return changed, err
		}
		o.Progress("%s: undone", js.ID)
	}
	j.Status, j.UndoneAt = RunUndone, stamp(o.Now())
	return true, r.save()
}

// checkUndoable authorizes every touched step again and checks that every
// file it changed still holds what the run wrote. It changes nothing.
func checkUndoable(h Host, j *Journal) error {
	for _, js := range j.Steps {
		if !touched(js) {
			continue
		}
		if js.Step.ID != js.ID {
			return fmt.Errorf("journal step %s holds step %s", js.ID, js.Step.ID)
		}
		if err := plan.Authorize(js.Step); err != nil {
			return fmt.Errorf("refusing to undo: %w", err)
		}
		for _, f := range js.Files {
			if err := checkFileUndoable(h, j.RunID, js, f); err != nil {
				return err
			}
		}
	}
	return nil
}

// checkFileUndoable is checkUndoable for one file of a step.
func checkFileUndoable(h Host, runID string, js JournalStep, f JournalFile) error {
	for _, d := range f.CreatedDirs {
		if !path.IsAbs(d) || path.Clean(d) != d || !strings.HasPrefix(f.Path, d+"/") {
			return fmt.Errorf("refusing to undo: step %s lists %s as a directory it created for %s, which is not a parent of it", js.ID, d, f.Path)
		}
	}
	if !f.Changed || f.Undone {
		return nil
	}
	if !slices.ContainsFunc(js.Step.Edits, func(e plan.FileEdit) bool { return e.Path == f.Path && e.Action == f.Action }) {
		return fmt.Errorf("refusing to undo: step %s does not edit %s", js.ID, f.Path)
	}
	ok, err := plan.FileHolds(h, f.Path, f.NewSHA256)
	if err != nil {
		return err
	}
	if !ok {
		return fmt.Errorf("refusing to undo: %s changed after run %s; restore it by hand from %s", f.Path, runID, BackupPath(runID, f.Path))
	}
	if f.Action == plan.Replace {
		ok, err := plan.FileHolds(h, BackupPath(runID, f.Path), f.OldSHA256)
		if err != nil {
			return err
		}
		if !ok {
			return fmt.Errorf("refusing to undo: the backup %s does not hold the old content", BackupPath(runID, f.Path))
		}
	}
	return nil
}

// undoStep restores the files of one step (newest first), removes the
// directories it created and runs its undo commands. changed says whether
// anything on the host changed before an error.
func undoStep(ctx context.Context, r *runner, o UndoOptions, js *JournalStep) (changed bool, err error) {
	h, j := o.Host, r.j
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
	// The files a pending restart would load are restored: there is
	// nothing left to restart, whatever the undo commands do next.
	js.RestartPending = false
	for k := len(js.Files) - 1; k >= 0; k-- {
		removed, err := removeCreatedDirs(h, js.Files[k].CreatedDirs)
		changed = changed || removed
		if err != nil {
			_ = r.save()
			return changed, fmt.Errorf("step %s: %w", js.ID, err)
		}
	}
	if err := r.save(); err != nil {
		return changed, err
	}
	cmdChanged, err := runUndoCommands(ctx, r, o, js)
	return changed || cmdChanged, err
}

// runUndoCommands runs the undo commands of a step, skipping those
// plan.UndoSkip finds nothing left to undo for.
func runUndoCommands(ctx context.Context, r *runner, o UndoOptions, js *JournalStep) (changed bool, err error) {
	done := ran(*js)
	for _, args := range undoCommands(js.Step) {
		skip, err := plan.UndoSkip(o.Host, args, done)
		if err != nil {
			return changed, fmt.Errorf("step %s: %w", js.ID, err)
		}
		if skip != "" {
			o.Progress("%s: skipping %s: %s", js.ID, strings.Join(args, " "), skip)
			js.Commands = append(js.Commands, JournalCommand{Kind: KindUndo, Args: redactAll(args), Skipped: skip})
			if err := r.save(); err != nil {
				return changed, err
			}
			continue
		}
		changed = true
		if err := r.command(ctx, js, KindUndo, args); err != nil {
			return changed, fmt.Errorf("step %s: %w", js.ID, err)
		}
	}
	return changed, nil
}

// removeCreatedDirs removes the directories apply created for a new file,
// innermost first, while they are empty: a directory something else wrote
// into since is kept. It reports whether it removed one.
func removeCreatedDirs(h Host, dirs []string) (bool, error) {
	removed := false
	for d := len(dirs) - 1; d >= 0; d-- {
		st, err := h.Stat(dirs[d])
		if err != nil {
			return removed, err
		}
		if !st.Exists {
			continue
		}
		if st.Symlink || st.Regular {
			return removed, nil
		}
		names, err := h.ReadDir(dirs[d])
		if err != nil || len(names) > 0 {
			return removed, err
		}
		if err := h.Remove(dirs[d]); err != nil {
			return removed, fmt.Errorf("removing the directory %s it created: %w", dirs[d], err)
		}
		removed = true
	}
	return removed, nil
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
