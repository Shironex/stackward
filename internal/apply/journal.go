package apply

import (
	"encoding/json"
	"fmt"
	"path"
	"regexp"

	"github.com/Shironex/stackward/internal/plan"
	"github.com/Shironex/stackward/internal/redact"
	"github.com/Shironex/stackward/internal/report"
)

// JournalSchema names the JSON shape of a run journal, described by
// schema/journal.v1.json. Change both together.
const JournalSchema = "stackward.journal.v1"

// BackupRoot holds one directory per run: the journal and a copy of every
// file the run overwrote, at its own path below the run directory.
const BackupRoot = "/var/backups/stackward"

// Run statuses.
const (
	RunRunning = "running" // the run is in progress, or died without a word
	RunOK      = "ok"      // every selected step is applied
	RunFailed  = "failed"  // a step failed; the run stopped there
	RunUndone  = "undone"  // stackward undo reversed the run
)

// Step statuses.
const (
	StepApplied = "applied" // the step ran to the end
	StepFailed  = "failed"  // the step stopped part way; see its files and commands
	StepAlready = "already" // the check found it in place; nothing ran
	StepNotRun  = "not-run" // an earlier step failed first
)

// Command kinds.
const (
	KindValidate = "validate" // checks a staged file before it is moved into place
	KindBefore   = "before"   // a step command before the edits (a package install)
	KindCommand  = "command"  // a step command, after the edits
	KindUndo     = "undo"     // run by stackward undo
	KindCheck    = "check"    // a transaction check after the steps ran
)

// Journal is the record of one apply run: what was selected, every file
// changed (with its backup), every command run with its exit code, and the
// timings. Content is redacted; the hashes are of the real bytes.
type Journal struct {
	Schema     string      `json:"schema"`
	Tool       report.Tool `json:"tool"`
	RunID      string      `json:"run_id"`
	Status     string      `json:"status"`
	StartedAt  string      `json:"started_at"`
	FinishedAt string      `json:"finished_at"`
	UndoneAt   string      `json:"undone_at,omitempty"`
	Host       report.Host `json:"host"`
	Plan       PlanRef     `json:"plan"`
	Selected   []string    `json:"selected"`
	// BackupDir is where the overwritten files are kept.
	BackupDir string        `json:"backup_dir"`
	Steps     []JournalStep `json:"steps"`
	// Error is why the run failed, when it did.
	Error string `json:"error,omitempty"`
	// Transaction is set when the run was an access-critical transaction
	// (see txn.go); the state file under StateDir is the authority, this
	// is the record that stays with the run.
	Transaction *JournalTxn `json:"transaction,omitempty"`
}

// JournalTxn is the transaction a run belongs to, as the journal keeps it.
type JournalTxn struct {
	Status    string `json:"status"`
	Deadline  string `json:"deadline"`
	TimerUnit string `json:"timer_unit"`
	// ConfirmedVia is ViaSSH or ViaConsole.
	ConfirmedAt  string `json:"confirmed_at,omitempty"`
	ConfirmedVia string `json:"confirmed_via,omitempty"`
	RolledBackAt string `json:"rolled_back_at,omitempty"`
	Cause        string `json:"cause,omitempty"`
	// Checks are the validation commands run after the steps (sshd -t,
	// sshd -T, ss).
	Checks []JournalCommand `json:"checks"`
}

// PlanRef identifies the plan a run applied.
type PlanRef struct {
	File        string `json:"file"`
	SHA256      string `json:"sha256"`
	Schema      string `json:"schema"`
	ToolVersion string `json:"tool_version"`
	GeneratedAt string `json:"generated_at"`
}

// JournalStep is one selected step.
type JournalStep struct {
	ID         string `json:"id"`
	Status     string `json:"status"`
	Reason     string `json:"reason,omitempty"`
	StartedAt  string `json:"started_at,omitempty"`
	DurationMS int64  `json:"duration_ms"`
	// Step is the plan step as applied, with its old and new file content
	// redacted, so undo can authorize it again and knows its undo
	// commands.
	Step plan.Step `json:"step"`
	// RestartPending is set from the moment a file of the step is written
	// until its commands have run: when it is still set, the files are in
	// place but the restart or load did not finish. The next apply runs
	// the commands first (see FindPending).
	RestartPending bool             `json:"restart_pending,omitempty"`
	Files          []JournalFile    `json:"files"`
	Commands       []JournalCommand `json:"commands"`
}

// JournalFile is one file a step edited.
type JournalFile struct {
	Path   string `json:"path"`
	Action string `json:"action"`
	// Changed is false when the file already held the new content. The
	// old and new content (redacted) are in the step's edit of the same
	// path; the hashes here are of the real bytes.
	Changed   bool   `json:"changed"`
	OldSHA256 string `json:"old_sha256,omitempty"`
	NewSHA256 string `json:"new_sha256"`
	// Mode, UID and GID are what the file was written with.
	Mode string `json:"mode"`
	UID  int    `json:"uid"`
	GID  int    `json:"gid"`
	// Backup is the copy of the old file in this run's directory, and
	// Orig the FILE.orig copy (OrigCreated when this run wrote it).
	Backup      string `json:"backup,omitempty"`
	Orig        string `json:"orig,omitempty"`
	OrigCreated bool   `json:"orig_created"`
	// Undone is set by stackward undo once the file is restored.
	Undone bool `json:"undone,omitempty"`
	// CreatedDirs are the directories apply created for a new file,
	// outermost first; undo removes them again when they are empty.
	CreatedDirs []string `json:"created_dirs,omitempty"`
}

// JournalCommand is one command run, with its outcome.
type JournalCommand struct {
	Kind       string   `json:"kind"`
	Args       []string `json:"args"`
	ExitCode   int      `json:"exit_code"`
	DurationMS int64    `json:"duration_ms"`
	// Output is stdout and stderr, redacted and cut to 4 KiB.
	Output string `json:"output,omitempty"`
	Error  string `json:"error,omitempty"`
}

var runIDPattern = regexp.MustCompile(`^[0-9]{8}T[0-9]{6}Z-[0-9a-f]{6}$`)

// ValidRunID reports whether id has the shape apply gives run ids, so a
// run id given on the command line cannot name another directory.
func ValidRunID(id string) bool { return runIDPattern.MatchString(id) }

// RunDir is the directory of run id.
func RunDir(id string) string { return path.Join(BackupRoot, id) }

// JournalPath is the journal of run id.
func JournalPath(id string) string { return path.Join(RunDir(id), "journal.json") }

// BackupPath is where run id keeps the old copy of p.
func BackupPath(id, p string) string { return path.Join(RunDir(id), p) }

// writeJournal saves j atomically, readable by root only.
func writeJournal(h Host, j *Journal) error {
	b, err := json.MarshalIndent(j, "", "  ")
	if err != nil {
		return err
	}
	return h.WriteAtomic(JournalPath(j.RunID), append(b, '\n'), FileState{Mode: 0o600, UID: -1, GID: -1}, nil)
}

// SaveJournal saves j, as every change to it is saved.
func SaveJournal(h Host, j *Journal) error { return writeJournal(h, j) }

// LoadJournal reads the journal of run id.
func LoadJournal(h Host, id string) (*Journal, error) {
	if !ValidRunID(id) {
		return nil, fmt.Errorf("%q is not a run id (they look like 20260301T120000Z-1a2b3c)", id)
	}
	b, err := h.ReadFile(JournalPath(id))
	if err != nil {
		return nil, fmt.Errorf("reading the journal of run %s: %w", id, err)
	}
	var j Journal
	if err := json.Unmarshal(b, &j); err != nil {
		return nil, fmt.Errorf("reading the journal of run %s: %w", id, err)
	}
	if j.Schema != JournalSchema {
		return nil, fmt.Errorf("the journal of run %s has schema %q, this stackward reads %q", id, j.Schema, JournalSchema)
	}
	if j.RunID != id {
		return nil, fmt.Errorf("the journal in %s names run %q", RunDir(id), j.RunID)
	}
	return &j, nil
}

// redactedOutput is command output fit for the journal.
func redactedOutput(b []byte) string {
	const limit = 4 << 10
	s := string(b)
	if len(s) > limit {
		s = s[:limit] + "\n[cut]"
	}
	return redact.String(s)
}
