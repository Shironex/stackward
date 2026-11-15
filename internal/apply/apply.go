// Package apply runs the selected steps of a plan on a host: it checks
// every precondition before it changes anything, keeps FILE.orig and a per
// run backup of every file it overwrites, writes atomically, runs the
// commands without a shell and records it all in a run journal. All host
// access goes through Host, so tests run against a temporary directory.
// It is the only code in stackward that writes to a system.
package apply

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"io/fs"
	"path"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/Shironex/stackward/internal/plan"
	"github.com/Shironex/stackward/internal/redact"
	"github.com/Shironex/stackward/internal/report"
)

// accessCriticalNote is why an access-critical step that was not named
// does not run.
const accessCriticalNote = "access-critical: runs only with --step %s, in a run of its own, inside the rollback transaction"

// CheckPlan refuses a plan that is not for this tool, this schema or this
// host. hostname is this host's name; the plan may hold it or its hash.
func CheckPlan(p *plan.Plan, hostname string) error {
	if p.Schema != plan.SchemaID {
		return fmt.Errorf("the plan has schema %q, this stackward applies %q; plan again with this version", p.Schema, plan.SchemaID)
	}
	if p.Tool.Name != "stackward" {
		return fmt.Errorf("the plan was written by %q, not stackward", p.Tool.Name)
	}
	if hostname == "" {
		return errors.New("cannot read this host's name to compare it with the plan's host")
	}
	want := p.Host.HostnameHash
	if p.Host.Hostname != "" {
		want = report.HashHostname(p.Host.Hostname)
	}
	if got := report.HashHostname(hostname); want != got {
		return fmt.Errorf("the plan is for host %s, this host is %s; plan again on this host (there is no override)", orNone(want), got)
	}
	if err := p.Validate(); err != nil {
		return fmt.Errorf("the plan is not valid: %w", err)
	}
	return nil
}

// NotRun is a planned step that was not selected, and why.
type NotRun struct {
	ID     string
	Reason string
}

// Selection is what the flags chose from a plan.
type Selection struct {
	Steps  []plan.Step // in plan order
	NotRun []NotRun
}

// Select picks steps by id (--step) and every safe step that is not opt in
// (--all-safe). The risk class and opt in come from the registered
// generator, not the plan file. An access-critical step runs only when
// named, and only with other access-critical steps: those run inside the
// rollback transaction, and its rollback must undo exactly them. An
// unknown id is refused.
func Select(p *plan.Plan, ids []string, allSafe bool) (Selection, error) {
	if len(ids) == 0 && !allSafe {
		return Selection{}, fmt.Errorf("choose the steps to apply with --step ID (repeatable) or --all-safe; this plan has %s", stepList(p))
	}
	named := map[string]bool{}
	var access, other []string
	for _, id := range ids {
		if !slices.ContainsFunc(p.Steps, func(s plan.Step) bool { return s.ID == id }) {
			return Selection{}, fmt.Errorf("step %s is not in this plan; it has %s", id, stepList(p))
		}
		g, _ := plan.Lookup(id)
		if g.Risk == plan.AccessCritical {
			access = append(access, id)
		} else {
			other = append(other, id)
		}
		named[id] = true
	}
	if len(access) > 0 && (len(other) > 0 || allSafe) {
		with := "--all-safe"
		if len(other) > 0 {
			with = strings.Join(other, ", ")
		}
		return Selection{}, fmt.Errorf("access-critical steps (%s) run inside the rollback transaction, in a run of their own; apply %s in a separate run first", strings.Join(access, ", "), with)
	}
	var sel Selection
	for _, s := range p.Steps {
		g, ok := plan.Lookup(s.ID)
		if !ok {
			return Selection{}, fmt.Errorf("step %s is not a known step", s.ID)
		}
		switch {
		case named[s.ID]:
			sel.Steps = append(sel.Steps, s)
		case g.Risk == plan.AccessCritical:
			sel.NotRun = append(sel.NotRun, NotRun{s.ID, fmt.Sprintf(accessCriticalNote, s.ID)})
		case g.Risk == plan.Networking:
			sel.NotRun = append(sel.NotRun, NotRun{s.ID, fmt.Sprintf("networking (restarts %s): runs only with --step %s", orNone(strings.Join(s.Restarts, ", ")), s.ID)})
		case g.OptIn:
			sel.NotRun = append(sel.NotRun, NotRun{s.ID, "opt in: runs only with --step " + s.ID})
		case allSafe:
			sel.Steps = append(sel.Steps, s)
		default:
			sel.NotRun = append(sel.NotRun, NotRun{s.ID, "not selected"})
		}
	}
	return sel, nil
}

// AccessCritical reports whether the selection holds access-critical
// steps (then it holds nothing else, see Select): it must run as a
// transaction.
func (s Selection) AccessCritical() bool {
	for _, st := range s.Steps {
		if g, ok := plan.Lookup(st.ID); ok && g.Risk == plan.AccessCritical {
			return true
		}
	}
	return false
}

func stepList(p *plan.Plan) string {
	if len(p.Steps) == 0 {
		return "no steps"
	}
	ids := make([]string, len(p.Steps))
	for i, s := range p.Steps {
		ids[i] = s.ID
	}
	return "steps " + strings.Join(ids, ", ")
}

// Prepared is a selected step after authorization and its check.
type Prepared struct {
	Step plan.Step
	// Applied is true when the check found the change already in place.
	Applied bool
	Why     string
}

// Prepare authorizes every selected step, runs its check, pins what the
// step's undo restores to the host as it is now and verifies the
// precondition of every edit of a step that still has to run. It only
// reads; any error means nothing was changed.
func Prepare(h Host, steps []plan.Step) ([]Prepared, error) {
	out := make([]Prepared, 0, len(steps))
	for _, s := range steps {
		if err := plan.Authorize(s); err != nil {
			return nil, err
		}
		applied, why, err := plan.Check(h, s)
		if err != nil {
			return nil, fmt.Errorf("step %s: %w", s.ID, err)
		}
		if !applied {
			if err := plan.Pin(h, s); err != nil {
				return nil, fmt.Errorf("step %s: %w", s.ID, err)
			}
			for _, e := range s.Edits {
				if _, err := precondition(h, e); err != nil {
					return nil, fmt.Errorf("step %s: %w", s.ID, err)
				}
			}
		}
		out = append(out, Prepared{Step: s, Applied: applied, Why: why})
	}
	return out, nil
}

// fileNow is a file as apply found it right before an edit.
type fileNow struct {
	st FileState
	// done is true when the file already holds the new content.
	done bool
}

// precondition checks that e may be applied to the file as it is now:
// absent for create, holding exactly old_sha256 for replace, or already
// holding new_sha256. A symlink or a non regular file is refused.
func precondition(h Host, e plan.FileEdit) (fileNow, error) {
	st, err := h.Stat(e.Path)
	if err != nil {
		return fileNow{}, err
	}
	switch {
	case st.Symlink:
		return fileNow{}, fmt.Errorf("%s is a symlink; stackward does not write through links", e.Path)
	case st.Exists && !st.Regular:
		return fileNow{}, fmt.Errorf("%s is not a regular file", e.Path)
	case !st.Exists && e.Action == plan.Create:
		return fileNow{st: st}, nil
	case !st.Exists:
		return fileNow{}, fmt.Errorf("%s no longer exists; the plan expected the content the audit saw; plan again", e.Path)
	}
	b, err := h.ReadFile(e.Path)
	if err != nil {
		return fileNow{}, err
	}
	sum := plan.SHA256(b)
	switch {
	case sum == e.NewSHA256:
		return fileNow{st: st, done: true}, nil
	case e.Action == plan.Create:
		return fileNow{}, fmt.Errorf("%s exists now; the plan expected it absent; plan again", e.Path)
	case sum != e.OldSHA256:
		return fileNow{}, fmt.Errorf("%s changed since the audit (its SHA-256 is %s, the plan expected %s); plan again", e.Path, sum[:12], e.OldSHA256[:min(12, len(e.OldSHA256))])
	}
	return fileNow{st: st}, nil
}

// Options configure Execute.
type Options struct {
	Host    Host
	Version string
	// Now is the clock (tests fix it); RunID is generated when empty.
	Now   func() time.Time
	RunID string
	Plan  PlanRef
	// HostRef is the host as the journal names it.
	HostRef report.Host
	// CommandTimeout limits each command (default 5 minutes).
	CommandTimeout time.Duration
	// Progress, when set, is told about each step as it starts and ends.
	Progress func(format string, a ...any)
	// Transaction, when set, marks the run as an access-critical
	// transaction in its journal from the first write on.
	Transaction *JournalTxn
}

// NewRunID returns a run id: the UTC time and six random hex digits.
func NewRunID(now time.Time) string {
	var b [3]byte
	_, _ = rand.Read(b[:])
	return now.UTC().Format("20060102T150405Z") + "-" + hex.EncodeToString(b[:])
}

// Execute applies every prepared step that is not already applied, in
// order, and returns the journal. The first failure stops the run; the
// journal then says what was done and the error says what failed.
func Execute(ctx context.Context, prepared []Prepared, o Options) (*Journal, error) {
	if o.Now == nil {
		o.Now = time.Now
	}
	if o.RunID == "" {
		o.RunID = NewRunID(o.Now())
	}
	if o.CommandTimeout == 0 {
		o.CommandTimeout = 5 * time.Minute
	}
	if o.Progress == nil {
		o.Progress = func(string, ...any) {}
	}
	h := o.Host
	j := &Journal{
		Schema: JournalSchema, Tool: report.Tool{Name: "stackward", Version: o.Version},
		RunID: o.RunID, Status: RunRunning, StartedAt: stamp(o.Now()),
		Host: o.HostRef, Plan: o.Plan, Selected: []string{}, BackupDir: RunDir(o.RunID),
		Steps: []JournalStep{}, Transaction: o.Transaction,
	}
	for _, p := range prepared {
		j.Selected = append(j.Selected, p.Step.ID)
		js := JournalStep{ID: p.Step.ID, Status: StepNotRun, Step: redactStep(p.Step), Files: []JournalFile{}, Commands: []JournalCommand{}}
		if p.Applied {
			js.Status, js.Reason = StepAlready, p.Why
		}
		j.Steps = append(j.Steps, js)
	}
	if err := h.MkdirAll(BackupRoot, 0o700); err != nil {
		return nil, fmt.Errorf("creating %s: %w", BackupRoot, err)
	}
	if err := h.MkdirAll(j.BackupDir, 0o700); err != nil {
		return nil, fmt.Errorf("creating %s: %w", j.BackupDir, err)
	}
	if err := writeJournal(h, j); err != nil {
		return nil, fmt.Errorf("writing the journal: %w", err)
	}
	r := &runner{h: h, o: o, j: j}
	for i, p := range prepared {
		if p.Applied {
			continue
		}
		o.Progress("%s: applying", p.Step.ID)
		if err := r.step(ctx, i, p.Step); err != nil {
			j.Steps[i].Status, j.Steps[i].Reason = StepFailed, err.Error()
			j.Status, j.Error, j.FinishedAt = RunFailed, fmt.Sprintf("step %s: %v", p.Step.ID, err), stamp(o.Now())
			if werr := writeJournal(h, j); werr != nil {
				return j, fmt.Errorf("step %s: %w (and the journal could not be saved: %w)", p.Step.ID, err, werr)
			}
			return j, fmt.Errorf("step %s: %w", p.Step.ID, err)
		}
		o.Progress("%s: applied", p.Step.ID)
	}
	j.Status, j.FinishedAt = RunOK, stamp(o.Now())
	return j, writeJournal(h, j)
}

type runner struct {
	h Host
	o Options
	j *Journal
}

func (r *runner) save() error { return writeJournal(r.h, r.j) }

// step applies one step: its edits in order, then its commands.
func (r *runner) step(ctx context.Context, i int, s plan.Step) error {
	js := &r.j.Steps[i]
	start := r.o.Now()
	js.StartedAt = stamp(start)
	defer func() { js.DurationMS = r.o.Now().Sub(start).Milliseconds() }()
	changed := false
	pending := len(s.Commands) > 0
	for _, e := range s.Edits {
		c, err := r.edit(ctx, js, e, pending)
		if err != nil {
			return err
		}
		changed = changed || c
	}
	if plan.RunsCommandsOnChange(s.ID) && !changed {
		js.Status, js.Reason = StepApplied, "every file already held the planned content, so the commands (restarts) were not run"
		return r.save()
	}
	for _, c := range s.Commands {
		if err := r.command(ctx, js, KindCommand, c.Args); err != nil {
			return err
		}
	}
	js.RestartPending = false
	js.Status = StepApplied
	return r.save()
}

// edit applies one file edit and reports whether it changed the file.
// With pending, the step is marked restart-pending before the file is
// written, so a failure or a crash before its commands ran leaves the mark.
func (r *runner) edit(ctx context.Context, js *JournalStep, e plan.FileEdit, pending bool) (bool, error) {
	h := r.h
	now, err := precondition(h, e)
	if err != nil {
		return false, err
	}
	jf := JournalFile{Path: e.Path, Action: e.Action, OldSHA256: e.OldSHA256, NewSHA256: e.NewSHA256}
	if now.done {
		jf.Mode, jf.UID, jf.GID = modeString(now.st.Mode), now.st.UID, now.st.GID
		js.Files = append(js.Files, jf)
		return false, r.save()
	}
	var write FileState
	switch e.Action {
	case plan.Replace:
		write = FileState{Mode: now.st.Mode, UID: now.st.UID, GID: now.st.GID}
		orig := e.Path + ".orig"
		ost, err := h.Stat(orig)
		if err != nil {
			return false, err
		}
		jf.Orig = orig
		if !ost.Exists {
			if err := h.CopyNew(e.Path, orig); err != nil {
				return false, fmt.Errorf("keeping %s: %w", orig, err)
			}
			jf.OrigCreated = true
		}
		jf.Backup = BackupPath(r.j.RunID, e.Path)
		if err := h.MkdirAll(path.Dir(jf.Backup), 0o700); err != nil {
			return false, fmt.Errorf("creating the backup directory: %w", err)
		}
		if err := h.CopyNew(e.Path, jf.Backup); err != nil {
			return false, fmt.Errorf("backing up %s: %w", e.Path, err)
		}
	case plan.Create:
		mode, err := strconv.ParseUint(e.Mode, 8, 32)
		if err != nil || mode&^0o777 != 0 {
			return false, fmt.Errorf("%s: bad mode %q", e.Path, e.Mode)
		}
		write = FileState{Mode: fs.FileMode(mode), UID: -1, GID: -1}
		if err := h.MkdirAll(path.Dir(e.Path), 0o755); err != nil {
			return false, fmt.Errorf("creating the directory of %s: %w", e.Path, err)
		}
	}
	jf.Mode, jf.UID, jf.GID = modeString(write.Mode), write.UID, write.GID
	var check func(string) error
	if len(e.Validate) > 0 {
		check = func(staged string) error {
			args := append(append([]string{}, e.Validate...), staged)
			if err := r.command(ctx, js, KindValidate, args); err != nil {
				return fmt.Errorf("the new %s failed validation, so it was not changed: %w", e.Path, err)
			}
			return nil
		}
	}
	wasPending := js.RestartPending
	if pending {
		js.RestartPending = true
		if err := r.save(); err != nil {
			js.RestartPending = wasPending
			return false, err
		}
	}
	if err := h.WriteAtomic(e.Path, []byte(e.New), write, check); err != nil {
		if written, _ := plan.FileHolds(h, e.Path, e.NewSHA256); !written {
			js.RestartPending = wasPending
		}
		js.Files = append(js.Files, jf)
		_ = r.save()
		return false, err
	}
	jf.Changed = true
	js.Files = append(js.Files, jf)
	if ok, err := plan.FileHolds(h, e.Path, e.NewSHA256); err != nil || !ok {
		_ = r.save()
		return true, fmt.Errorf("%s does not hold the planned content after the write", e.Path)
	}
	return true, r.save()
}

// command runs args and records it; a non zero exit is an error.
func (r *runner) command(ctx context.Context, js *JournalStep, kind string, args []string) error {
	ctx, cancel := context.WithTimeout(ctx, r.o.CommandTimeout)
	defer cancel()
	res := r.h.Run(ctx, args)
	jc := JournalCommand{Kind: kind, Args: redactAll(args), ExitCode: res.ExitCode, DurationMS: res.Duration.Milliseconds(), Output: redactedOutput(res.Output)}
	if res.Err != nil {
		jc.Error = redact.String(res.Err.Error())
	}
	js.Commands = append(js.Commands, jc)
	if err := r.save(); err != nil {
		return err
	}
	switch {
	case res.Err != nil:
		return fmt.Errorf("%s: %w", strings.Join(args, " "), res.Err)
	case res.ExitCode != 0:
		msg := strings.TrimSpace(jc.Output)
		if i := strings.IndexByte(msg, '\n'); i >= 0 {
			msg = msg[:i]
		}
		return fmt.Errorf("%s exited %d: %s", strings.Join(args, " "), res.ExitCode, msg)
	}
	return nil
}

// redactStep masks secret shaped values in the content a journal keeps.
// Apply refuses steps whose plan content was redacted, so this changes
// nothing for a plan stackward wrote.
func redactStep(s plan.Step) plan.Step {
	edits := make([]plan.FileEdit, len(s.Edits))
	for i, e := range s.Edits {
		e.Old, e.New, e.Diff = redact.String(e.Old), redact.String(e.New), redact.String(e.Diff)
		edits[i] = e
	}
	s.Edits = edits
	return s
}

func redactAll(ss []string) []string {
	out := make([]string, len(ss))
	for i, s := range ss {
		out[i] = redact.String(s)
	}
	return out
}

func modeString(m fs.FileMode) string { return fmt.Sprintf("%04o", m.Perm()) }

func stamp(t time.Time) string { return t.UTC().Format(time.RFC3339) }

func orNone(s string) string {
	if s == "" {
		return "nothing"
	}
	return s
}
