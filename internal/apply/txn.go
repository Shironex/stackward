package apply

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"path"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/Shironex/stackward/internal/plan"
	"github.com/Shironex/stackward/internal/redact"
	"github.com/Shironex/stackward/internal/report"
)

// The access-critical transaction. Steps that can lock the owner out (SSH,
// the firewall, users) run only inside it:
//
//	preflight -> arm the rollback timer -> apply -> validate -> open
//	                                         |          |
//	                                         +-- fail --+--> roll back at once
//
// open -> confirmed      stackward confirm from a new SSH session (or --console)
// open -> rolled-back    the timer fired at the deadline; blocks access steps
//                        until stackward confirm --ack-rollback
// open -> rollback-failed  the rollback itself failed; blocks the same way
//
// The timer is a systemd transient timer and service (systemd-run), so it
// runs whatever happens to the SSH session or to this process. It starts a
// root-owned copy of this binary, kept under the transaction's directory,
// with `undo --transaction ID --by-timer`. The state lives in TxnStatePath
// and every change to it is made under the run lock.

// TxnSchema names the JSON shape of the transaction state, described by
// schema/transaction.v1.json. Change both together.
const TxnSchema = "stackward.transaction.v1"

// Where the transaction state lives.
const (
	StateDir     = "/var/lib/stackward"
	TxnStatePath = StateDir + "/transaction.json"
	txnRoot      = StateDir + "/transactions"
)

// Transaction statuses.
const (
	TxnOpen           = "open"            // applied and validated, waiting for a confirm
	TxnConfirmed      = "confirmed"       // confirmed; the change stays
	TxnRolledBack     = "rolled-back"     // the change was undone
	TxnRollbackFailed = "rollback-failed" // the undo failed part way; look by hand
	TxnAborted        = "aborted"         // the timer could not be armed; nothing changed
)

// Why a transaction rolled back.
const (
	CauseTimer       = "timer"        // no confirm before the deadline
	CauseValidation  = "validation"   // the checks after the steps failed
	CauseApplyFailed = "apply-failed" // a step failed
	CauseManual      = "manual"       // stackward undo --transaction
)

// How a transaction was confirmed.
const (
	ViaSSH     = "new-ssh-session"
	ViaConsole = "console"
)

// Deadline bounds: long enough to open a second session, short enough
// that a lockout does not last.
const (
	DefaultConfirmWithin = 5 * time.Minute
	MinConfirmWithin     = 30 * time.Second
	MaxConfirmWithin     = 30 * time.Minute
)

// TimerLockWait is how long the rollback waits for the run lock when an
// apply or a confirm holds it, and TimerLockInterval how often it tries.
const (
	TimerLockWait     = 10 * time.Minute
	TimerLockInterval = 2 * time.Second
)

// checkTimeout limits each command the transaction runs itself.
const checkTimeout = time.Minute

// Txn is the transaction state file.
type Txn struct {
	Schema string      `json:"schema"`
	Tool   report.Tool `json:"tool"`
	// ID is the run id of the apply run, whose journal undo reads.
	ID       string   `json:"id"`
	Status   string   `json:"status"`
	Steps    []string `json:"steps"`
	OpenedAt string   `json:"opened_at"`
	// Deadline is when the timer rolls back, RFC 3339 UTC.
	Deadline      string `json:"deadline"`
	ConfirmWithin string `json:"confirm_within"`
	TimerUnit     string `json:"timer_unit"`
	// Rollback is the command the timer runs.
	Rollback []string `json:"rollback"`
	// Session is the session that applied.
	Session        Session  `json:"session"`
	ConfirmedAt    string   `json:"confirmed_at,omitempty"`
	ConfirmedVia   string   `json:"confirmed_via,omitempty"`
	ConfirmSession *Session `json:"confirm_session,omitempty"`
	RolledBackAt   string   `json:"rolled_back_at,omitempty"`
	Cause          string   `json:"cause,omitempty"`
	// Error is why the rollback or the arming failed.
	Error   string `json:"error,omitempty"`
	AckedAt string `json:"acked_at,omitempty"`
}

// TxnDir is the directory of transaction id: the binary the timer runs.
func TxnDir(id string) string { return path.Join(txnRoot, id) }

// TxnBinary is the copy of stackward the timer of transaction id runs.
func TxnBinary(id string) string { return path.Join(TxnDir(id), "stackward") }

// TimerUnit is the name of the transient units (.timer and .service) of
// transaction id.
func TimerUnit(id string) string { return "stackward-rollback-" + id }

// CheckConfirmWithin refuses a deadline outside the bounds.
func CheckConfirmWithin(d time.Duration) error {
	if d < MinConfirmWithin || d > MaxConfirmWithin {
		return fmt.Errorf("--confirm-within %s is outside %s to %s", d, MinConfirmWithin, MaxConfirmWithin)
	}
	return nil
}

// LoadTxn reads the transaction state; no file is no transaction (nil).
func LoadTxn(h Host) (*Txn, error) {
	b, err := h.ReadFile(TxnStatePath)
	if errors.Is(err, fs.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("reading the transaction state: %w", err)
	}
	dec := json.NewDecoder(bytes.NewReader(b))
	dec.DisallowUnknownFields()
	var t Txn
	if err := dec.Decode(&t); err != nil {
		return nil, fmt.Errorf("reading the transaction state %s: %w", TxnStatePath, err)
	}
	if t.Schema != TxnSchema {
		return nil, fmt.Errorf("the transaction state %s has schema %q, this stackward reads %q", TxnStatePath, t.Schema, TxnSchema)
	}
	if !ValidRunID(t.ID) {
		return nil, fmt.Errorf("the transaction state %s names %q, not a run id", TxnStatePath, t.ID)
	}
	return &t, nil
}

// SaveTxn writes the transaction state atomically, readable by root only.
func SaveTxn(h Host, t *Txn) error {
	if err := h.MkdirAll(StateDir, 0o700); err != nil {
		return err
	}
	b, err := json.MarshalIndent(t, "", "  ")
	if err != nil {
		return err
	}
	return h.WriteAtomic(TxnStatePath, append(b, '\n'), FileState{Mode: 0o600, UID: -1, GID: -1}, nil)
}

// DeadlinePassed reports whether now is at or after the deadline. A
// deadline that cannot be read counts as passed.
func (t *Txn) DeadlinePassed(now time.Time) bool {
	d, err := time.Parse(time.RFC3339, t.Deadline)
	return err != nil || !now.Before(d)
}

// Blocks returns why access-critical steps cannot run now, or "".
// Non-access steps never ask.
func (t *Txn) Blocks(now time.Time) string {
	if t == nil {
		return ""
	}
	switch t.Status {
	case TxnOpen:
		if t.DeadlinePassed(now) {
			return fmt.Sprintf("transaction %s is still open although its deadline passed at %s, so its rollback did not run (the timer is gone, for example after a reboot, or it is waiting for the lock); roll it back with: sudo stackward undo --transaction %s", t.ID, t.Deadline, t.ID)
		}
		return fmt.Sprintf("transaction %s is open until %s and only one transaction can be open; confirm it from a new SSH session (sudo stackward confirm %s) or let it roll back", t.ID, t.Deadline, t.ID)
	case TxnRolledBack, TxnRollbackFailed:
		if t.AckedAt == "" {
			return fmt.Sprintf("transaction %s %s (%s) at %s, so access-critical steps stay blocked until you acknowledge it: sudo stackward confirm --ack-rollback %s", t.ID, RollbackWords(t.Status), t.Cause, t.RolledBackAt, t.ID)
		}
	}
	return ""
}

// RollbackWords says what happened to a transaction in status
// rolled-back or rollback-failed.
func RollbackWords(status string) string {
	if status == TxnRollbackFailed {
		return "tried to roll back and failed"
	}
	return "was rolled back"
}

// Baseline is what the preflight saw before anything changed.
type Baseline struct {
	// Ports are the ports sshd is configured for that something listens
	// on now: they must still be listened on after the change.
	Ports []string
}

// Preflight checks, before anything changes, that the transaction can
// protect the change: systemd-run exists, sshd's configuration is valid
// now (so a failure after the change is the change's fault), and sshd's
// ports are listened on. It only reads.
func Preflight(ctx context.Context, h Host) (Baseline, error) {
	if _, _, err := runCheck(ctx, h, "systemd-run", "--version"); err != nil {
		return Baseline{}, fmt.Errorf("the rollback timer needs systemd-run: %w", err)
	}
	if _, _, err := runCheck(ctx, h, "sshd", "-t"); err != nil {
		return Baseline{}, fmt.Errorf("sshd -t fails before any change, so the transaction could not tell a broken change from a broken start; fix sshd's configuration first: %w", err)
	}
	_, out, err := runCheck(ctx, h, "sshd", "-T")
	if err != nil {
		return Baseline{}, err
	}
	ports := parseSSHDT(out)["port"]
	if len(ports) == 0 {
		return Baseline{}, errors.New("sshd -T names no port")
	}
	_, out, err = runCheck(ctx, h, "ss", "-Htln")
	if err != nil {
		return Baseline{}, err
	}
	listening := listeningPorts(out)
	var b Baseline
	for _, p := range ports {
		if listening[p] {
			b.Ports = append(b.Ports, p)
		}
	}
	if len(b.Ports) == 0 {
		return Baseline{}, fmt.Errorf("nothing listens on sshd's port %s now, so the transaction cannot check that SSH still works after the change; start ssh first", strings.Join(ports, ", "))
	}
	return b, nil
}

// ValidateAccess runs the checks after the steps: sshd -t passes, sshd -T
// shows every setting the steps mean to leave in place, and sshd's ports
// are listened on (the baseline ports too, unless a step sets the port).
// It returns every command it ran for the journal, and an error naming
// every failed check.
func ValidateAccess(ctx context.Context, h Host, steps []plan.Step, base Baseline) ([]JournalCommand, error) {
	var cmds []JournalCommand
	var failed []string
	jc, _, err := runCheck(ctx, h, "sshd", "-t")
	cmds = append(cmds, jc)
	if err != nil {
		return cmds, fmt.Errorf("sshd -t fails after the change: %w", err)
	}
	jc, out, err := runCheck(ctx, h, "sshd", "-T")
	cmds = append(cmds, jc)
	if err != nil {
		return cmds, fmt.Errorf("sshd -T fails after the change: %w", err)
	}
	eff := parseSSHDT(out)
	setsPort := false
	for _, s := range steps {
		want := plan.SSHDExpect(s)
		keys := make([]string, 0, len(want))
		for k := range want {
			keys = append(keys, k)
		}
		slices.Sort(keys)
		for _, k := range keys {
			setsPort = setsPort || k == "port"
			if got := strings.Join(eff[k], ","); got != want[k] {
				failed = append(failed, fmt.Sprintf("step %s: sshd -T shows %s %q, the step means %q", s.ID, k, got, want[k]))
			}
		}
	}
	jc, out, err = runCheck(ctx, h, "ss", "-Htln")
	cmds = append(cmds, jc)
	if err != nil {
		return cmds, err
	}
	listening := listeningPorts(out)
	need := append([]string{}, eff["port"]...)
	if !setsPort {
		need = append(need, base.Ports...)
	}
	slices.Sort(need)
	for _, p := range slices.Compact(need) {
		if !listening[p] {
			failed = append(failed, "nothing listens on port "+p+", where sshd should")
		}
	}
	if len(failed) > 0 {
		return cmds, errors.New(strings.Join(failed, "; "))
	}
	return cmds, nil
}

// parseSSHDT reads `sshd -T` output: one "key value" per line, keys in
// lower case, a key repeated for each value (port, listenaddress).
func parseSSHDT(out string) map[string][]string {
	m := map[string][]string{}
	for _, line := range strings.Split(out, "\n") {
		k, v, ok := strings.Cut(strings.TrimSpace(line), " ")
		if !ok || k == "" {
			continue
		}
		m[strings.ToLower(k)] = append(m[strings.ToLower(k)], strings.TrimSpace(v))
	}
	return m
}

// listeningPorts reads `ss -Htln`: the local address is the fourth field
// (0.0.0.0:22, [::]:22, *:22).
func listeningPorts(out string) map[string]bool {
	m := map[string]bool{}
	for _, line := range strings.Split(out, "\n") {
		f := strings.Fields(line)
		if len(f) < 4 {
			continue
		}
		i := strings.LastIndexByte(f[3], ':')
		if i < 0 {
			continue
		}
		if p := f[3][i+1:]; p != "" {
			if _, err := strconv.Atoi(p); err == nil {
				m[p] = true
			}
		}
	}
	return m
}

// runCheck runs one command the transaction needs and records it.
func runCheck(ctx context.Context, h Host, args ...string) (JournalCommand, string, error) {
	ctx, cancel := context.WithTimeout(ctx, checkTimeout)
	defer cancel()
	res := h.Run(ctx, args)
	jc := JournalCommand{Kind: KindCheck, Args: redactAll(args), ExitCode: res.ExitCode, DurationMS: res.Duration.Milliseconds(), Output: redactedOutput(res.Output)}
	cmd := strings.Join(args, " ")
	if res.Err != nil {
		jc.Error = redact.String(res.Err.Error())
		return jc, "", fmt.Errorf("%s: %w", cmd, res.Err)
	}
	if res.ExitCode != 0 {
		msg := strings.TrimSpace(string(res.Output))
		if i := strings.IndexByte(msg, '\n'); i >= 0 {
			msg = msg[:i]
		}
		return jc, string(res.Output), fmt.Errorf("%s exited %d: %s", cmd, res.ExitCode, redact.String(msg))
	}
	return jc, string(res.Output), nil
}

// ArmTimer starts the transient timer that runs t.Rollback after d, and
// checks that it is active.
func ArmTimer(ctx context.Context, h Host, t *Txn, d time.Duration) error {
	args := []string{
		"systemd-run", "--quiet", "--collect",
		"--unit=" + t.TimerUnit,
		"--description=stackward: roll back transaction " + t.ID + " unless it is confirmed",
		"--on-active=" + strconv.Itoa(int(d.Seconds())) + "s",
		"--timer-property=AccuracySec=1s",
		"--timer-property=RemainAfterElapse=no",
	}
	if _, _, err := runCheck(ctx, h, append(args, t.Rollback...)...); err != nil {
		return fmt.Errorf("arming the rollback timer: %w", err)
	}
	if state := unitState(ctx, h, t.TimerUnit+".timer"); state != "active" {
		return fmt.Errorf("the rollback timer %s.timer is %q after systemd-run, not active", t.TimerUnit, state)
	}
	return nil
}

// Disarm stops the transient timer and service of a transaction and checks
// that neither is still active. Stopping units that are gone already is
// not an error.
func Disarm(ctx context.Context, h Host, unit string) error {
	units := []string{unit + ".timer", unit + ".service"}
	_, _, _ = runCheck(ctx, h, append([]string{"systemctl", "stop"}, units...)...)
	for _, u := range units {
		switch state := unitState(ctx, h, u); state {
		case "active", "activating", "deactivating", "reloading", "refreshing":
			return fmt.Errorf("%s is still %s after systemctl stop", u, state)
		case "error":
			return fmt.Errorf("cannot ask systemd about %s", u)
		}
	}
	return nil
}

// unitState is what `systemctl is-active` prints for unit ("inactive" for
// a unit that does not exist), or "error" when it could not run.
func unitState(ctx context.Context, h Host, unit string) string {
	ctx, cancel := context.WithTimeout(ctx, checkTimeout)
	defer cancel()
	res := h.Run(ctx, []string{"systemctl", "is-active", unit})
	if res.Err != nil {
		return "error"
	}
	return strings.TrimSpace(string(res.Output))
}

// TxnOptions configure RunTransaction.
type TxnOptions struct {
	Options
	ConfirmWithin time.Duration
	// Session is the session that applies.
	Session Session
	// Exe is the path of the running binary; the timer runs a copy.
	Exe      string
	Baseline Baseline
}

// RunTransaction applies access-critical steps as a transaction: it copies
// the binary, writes the state as open, arms the rollback timer, applies
// the steps and validates them. On a failure after anything changed it
// rolls back at once and disarms the timer; the returned Txn says what
// happened. On success the timer stays armed and the state stays open.
// The caller holds the run lock and has checked that no transaction blocks
// (Txn.Blocks) and that Preflight passed.
func RunTransaction(ctx context.Context, prepared []Prepared, o TxnOptions) (*Journal, *Txn, error) {
	if o.Now == nil {
		o.Now = time.Now
	}
	if o.RunID == "" {
		o.RunID = NewRunID(o.Now())
	}
	h := o.Host
	if err := CheckConfirmWithin(o.ConfirmWithin); err != nil {
		return nil, nil, err
	}
	if err := installBinary(h, o.Exe, o.RunID); err != nil {
		return nil, nil, fmt.Errorf("copying stackward for the rollback timer: %w", err)
	}
	if err := proveBinary(ctx, h, o.RunID); err != nil {
		removeBinary(h, o.RunID)
		return nil, nil, err
	}
	now := o.Now()
	t := &Txn{
		Schema: TxnSchema, Tool: report.Tool{Name: "stackward", Version: o.Version},
		ID: o.RunID, Status: TxnOpen, Steps: []string{},
		OpenedAt: stamp(now), Deadline: stamp(now.Add(o.ConfirmWithin)), ConfirmWithin: o.ConfirmWithin.String(),
		TimerUnit: TimerUnit(o.RunID),
		Rollback:  []string{TxnBinary(o.RunID), "undo", "--transaction", o.RunID, "--yes", "--by-timer"},
		Session:   o.Session,
	}
	var steps []plan.Step
	for _, p := range prepared {
		t.Steps = append(t.Steps, p.Step.ID)
		steps = append(steps, p.Step)
	}
	// The state is open before the timer can fire, so the rollback finds it.
	if err := SaveTxn(h, t); err != nil {
		return nil, nil, fmt.Errorf("writing the transaction state: %w", err)
	}
	if err := ArmTimer(ctx, h, t, o.ConfirmWithin); err != nil {
		t.Status, t.Error = TxnAborted, err.Error()
		_ = Disarm(ctx, h, t.TimerUnit)
		_ = SaveTxn(h, t)
		removeBinary(h, t.ID)
		return nil, t, err
	}
	o.Transaction = &JournalTxn{Status: TxnOpen, Deadline: t.Deadline, TimerUnit: t.TimerUnit, Checks: []JournalCommand{}}
	undo := UndoOptions{Host: h, Now: o.Now, CommandTimeout: o.CommandTimeout, Progress: o.Progress}
	j, err := Execute(ctx, prepared, o.Options)
	if j == nil {
		// Nothing was written: no journal, no change.
		t.Status, t.Error = TxnAborted, err.Error()
		_ = Disarm(ctx, h, t.TimerUnit)
		_ = SaveTxn(h, t)
		removeBinary(h, t.ID)
		return nil, t, err
	}
	if err != nil {
		return j, t, rollBackNow(ctx, h, j, t, CauseApplyFailed, err, undo)
	}
	checks, verr := ValidateAccess(ctx, h, steps, o.Baseline)
	j.Transaction.Checks = append(j.Transaction.Checks, checks...)
	if err := SaveJournal(h, j); err != nil {
		verr = errors.Join(verr, fmt.Errorf("saving the journal: %w", err))
	}
	if verr != nil {
		return j, t, rollBackNow(ctx, h, j, t, CauseValidation, fmt.Errorf("validation failed: %w", verr), undo)
	}
	return j, t, nil
}

// rollBackNow rolls back while the person is still there, then disarms the
// timer. The rollback comes first: if it dies, the timer is still armed.
// An interrupt (Ctrl-C) that stopped the steps must not stop their
// rollback, so it runs without the caller's cancellation.
func rollBackNow(ctx context.Context, h Host, j *Journal, t *Txn, cause string, why error, o UndoOptions) error {
	ctx = context.WithoutCancel(ctx)
	if o.Progress != nil {
		o.Progress("rolling back at once: %v", why)
	}
	rerr := RollBack(ctx, h, j, t, cause, o)
	// The state is no longer open either way, so the timer would find
	// nothing to do; stop it.
	derr := Disarm(ctx, h, t.TimerUnit)
	if rerr != nil {
		return fmt.Errorf("%w; the rollback failed too: %w", why, rerr)
	}
	removeBinary(h, t.ID)
	if derr != nil {
		return fmt.Errorf("%w; rolled back, but the timer could not be stopped (%w): when it fires it finds nothing to do", why, derr)
	}
	return why
}

// RollBack undoes the transaction's run from its journal and records the
// outcome in the state and the journal. A rollback by the timer must be
// acknowledged before access steps run again; one the person watched
// (validation, a failed step, a manual undo) is acknowledged by it. It
// does not touch the timer.
func RollBack(ctx context.Context, h Host, j *Journal, t *Txn, cause string, o UndoOptions) error {
	if o.Now == nil {
		o.Now = time.Now
	}
	_, err := Undo(ctx, j, o)
	if errors.Is(err, errAlreadyUndone) {
		err = nil
	}
	now := stamp(o.Now())
	t.RolledBackAt, t.Cause = now, cause
	if err != nil {
		t.Status, t.Error = TxnRollbackFailed, err.Error()
	} else {
		t.Status = TxnRolledBack
		if cause != CauseTimer {
			t.AckedAt = now
		}
	}
	syncJournalTxn(j, t)
	jerr := SaveJournal(h, j)
	if serr := SaveTxn(h, t); serr != nil {
		return errors.Join(err, jerr, fmt.Errorf("writing the transaction state: %w", serr))
	}
	return errors.Join(err, jerr)
}

// ConfirmTxn keeps the change of open transaction t: unless console is
// set, now must be a new SSH session (CompareSessions); the deadline must
// not have passed; the timer must stop. Then the state says confirmed
// (UpdateJournalTxn copies it into the journal). It returns why the
// session was accepted.
func ConfirmTxn(ctx context.Context, h Host, t *Txn, console bool, sess Session, now time.Time) (string, error) {
	if t.Status != TxnOpen {
		return "", fmt.Errorf("transaction %s is %s, not open", t.ID, t.Status)
	}
	if t.DeadlinePassed(now) {
		return "", fmt.Errorf("the deadline of transaction %s passed at %s: its rollback is due or running, so it cannot be confirmed (if it did not roll back, run sudo stackward undo --transaction %s)", t.ID, t.Deadline, t.ID)
	}
	via, why := ViaConsole, "--console: the session check is skipped (the provider console path)"
	if !console {
		ok, reason := CompareSessions(t.Session, sess)
		if !ok {
			return "", errors.New(reason)
		}
		via, why = ViaSSH, reason
	}
	if err := Disarm(ctx, h, t.TimerUnit); err != nil {
		return "", fmt.Errorf("the rollback timer could not be stopped, so the transaction stays open and rolls back at %s: %w", t.Deadline, err)
	}
	t.Status, t.ConfirmedAt, t.ConfirmedVia = TxnConfirmed, stamp(now), via
	s := sess
	t.ConfirmSession = &s
	if err := SaveTxn(h, t); err != nil {
		t.Status, t.ConfirmedAt, t.ConfirmedVia, t.ConfirmSession = TxnOpen, "", "", nil
		return "", fmt.Errorf("the rollback timer is stopped but the state could not be written (%w); roll back with sudo stackward undo --transaction %s, or confirm again", err, t.ID)
	}
	removeBinary(h, t.ID)
	return why, nil
}

// AckRollback acknowledges a rollback, so access steps may run again.
func AckRollback(h Host, t *Txn, now time.Time) error {
	if t.Status != TxnRolledBack && t.Status != TxnRollbackFailed {
		return fmt.Errorf("transaction %s is %s; there is no rollback to acknowledge", t.ID, t.Status)
	}
	if t.AckedAt != "" {
		return nil
	}
	t.AckedAt = stamp(now)
	if err := SaveTxn(h, t); err != nil {
		return err
	}
	removeBinary(h, t.ID)
	return nil
}

func syncJournalTxn(j *Journal, t *Txn) {
	if j.Transaction == nil {
		j.Transaction = &JournalTxn{Deadline: t.Deadline, TimerUnit: t.TimerUnit, Checks: []JournalCommand{}}
	}
	jt := j.Transaction
	jt.Status, jt.ConfirmedAt, jt.ConfirmedVia, jt.RolledBackAt, jt.Cause = t.Status, t.ConfirmedAt, t.ConfirmedVia, t.RolledBackAt, t.Cause
}

// UpdateJournalTxn copies the state into the journal of the run.
func UpdateJournalTxn(h Host, t *Txn) error {
	j, err := LoadJournal(h, t.ID)
	if err != nil {
		return err
	}
	syncJournalTxn(j, t)
	return SaveJournal(h, j)
}

// installBinary copies the running binary to TxnBinary(id), owned by
// root (the writing process) and executable by root only, in a directory
// only root can enter. A copy, so the rollback does not depend on the
// binary the person ran staying where it is, unchanged.
func installBinary(h Host, exe, id string) error {
	if exe == "" {
		return errors.New("the path of the running binary is unknown")
	}
	exe = filepath.ToSlash(filepath.Clean(exe))
	b, err := h.ReadFile(exe)
	if err != nil {
		return err
	}
	for _, d := range []string{StateDir, txnRoot, TxnDir(id)} {
		if err := h.MkdirAll(d, 0o700); err != nil {
			return err
		}
	}
	return h.WriteAtomic(TxnBinary(id), b, FileState{Mode: 0o700, UID: -1, GID: -1}, nil)
}

// proveBinary runs the copy once as a systemd service, the way the timer
// will (`systemd-run --wait`, which returns the service's exit status), so
// a copy that cannot run there (a noexec mount, a missing interpreter) is
// found before anything changes.
func proveBinary(ctx context.Context, h Host, id string) error {
	if _, _, err := runCheck(ctx, h, "systemd-run", "--quiet", "--collect", "--wait", "--unit=stackward-check-"+id, TxnBinary(id), "version"); err != nil {
		return fmt.Errorf("the copy of stackward the rollback timer would run does not start as a systemd service, so the transaction could not roll back: %w", err)
	}
	return nil
}

// removeBinary removes the copy and its directory once nothing will run
// it. A failure leaves a file under StateDir and nothing else.
func removeBinary(h Host, id string) {
	_ = h.Remove(TxnBinary(id))
	_ = h.Remove(TxnDir(id))
}
