package cli

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/Shironex/stackward/internal/apply"
	"github.com/Shironex/stackward/internal/plan"
	"github.com/Shironex/stackward/internal/report"
	"github.com/Shironex/stackward/internal/version"
)

// consoleReminder is printed before any access-critical step: the provider
// console is the way back in when SSH stops working.
const consoleReminder = `stackward apply: ACCESS-CRITICAL change (SSH, firewall or users)
Before you go on, make sure you can reach this server's provider console
(the web, VNC or serial console of your hosting provider) and log in there.
If this change locks SSH out and the rollback does not bring it back, the
console is the only way in.

`

// txnApply is what apply hands to the transaction.
type txnApply struct {
	planFile string
	plan     *plan.Plan
	sum      string
	sel      apply.Selection
	prepared []apply.Prepared
	hostname string
	runID    string
	within   time.Duration
	yes      bool
}

// applyTransaction runs access-critical steps inside the rollback
// transaction. The caller holds the run lock.
func applyTransaction(ctx context.Context, env applyEnv, a txnApply, stdout, stderr io.Writer) int {
	fail := func(format string, args ...any) int {
		fmt.Fprintf(stderr, "stackward apply: "+format+"\n", args...)
		return report.ExitError
	}
	fmt.Fprint(stdout, consoleReminder)
	if err := apply.WritePreview(stdout, a.planFile, a.plan, a.sel, a.prepared); err != nil {
		return fail("%v", err)
	}
	n := apply.ToRun(a.prepared)
	if n == 0 {
		fmt.Fprintln(stdout, "\nstackward apply: nothing to do, every selected step is already applied; no transaction was opened and nothing was changed")
		return report.ExitOK
	}
	t, err := apply.LoadTxn(env.host)
	if err != nil {
		return fail("%v; nothing was changed", err)
	}
	if why := t.Blocks(env.now()); why != "" {
		return fail("%s; nothing was changed", why)
	}
	if why, err := apply.StaleBootUnits(env.host, t); err != nil || why != "" {
		return fail("%s; nothing was changed", errOr(err, why))
	}
	sess := env.session()
	confirmFrom, err := proveLive(ctx, env, a.sel.Steps, sess, stdout)
	if err != nil {
		return fail("%v; nothing was changed", err)
	}
	base, err := apply.Preflight(ctx, env.host)
	if err != nil {
		return fail("%v; nothing was changed", err)
	}
	fmt.Fprintf(stdout, "\ntransaction: the steps run inside a rollback transaction\n")
	fmt.Fprintf(stdout, "   a systemd timer (%s.timer) rolls them back after %s unless confirmed;\n", apply.TimerUnit(a.runID), a.within)
	fmt.Fprintf(stdout, "   it runs on its own, so a dropped SSH session cannot stop it\n")
	fmt.Fprintf(stdout, "   a boot unit (%s) rolls them back if the host reboots first, before sshd starts\n", apply.BootUnit(a.runID))
	fmt.Fprintf(stdout, "   after the steps: sshd -t, the effective sshd -T values, and sshd still listening on %s\n", strings.Join(base.Ports, ", "))
	fmt.Fprintf(stdout, "   a failed check rolls back at once\n")
	fmt.Fprintf(stdout, "   confirm with stackward confirm from a NEW SSH session (this one is refused)\n")
	if len(confirmFrom) > 0 {
		fmt.Fprintf(stdout, "   that session must come over the way that stays: from %s\n", strings.Join(confirmFrom, ", "))
	}
	if ok, err := confirm(env, a.yes, stdout, fmt.Sprintf("\nApply %d access-critical step(s) in a transaction that rolls back in %s unless confirmed? [y/N] ", n, a.within)); !ok {
		if err != nil {
			return fail("%v; nothing was changed", err)
		}
		fmt.Fprintln(stdout, "stackward apply: not confirmed; nothing was changed")
		return report.ExitError
	}
	fmt.Fprintf(stdout, "session:   %s\n", describeSession(sess))
	exe, err := env.exe()
	if err != nil {
		return fail("cannot find the running binary for the rollback timer: %v; nothing was changed", err)
	}
	j, txn, runErr := apply.RunTransaction(ctx, a.prepared, apply.TxnOptions{
		Options: apply.Options{
			Host: env.host, Version: version.String(), Now: env.now, RunID: a.runID,
			Plan: apply.PlanRef{
				File: a.planFile, SHA256: a.sum, Schema: a.plan.Schema, ToolVersion: a.plan.Tool.Version, GeneratedAt: a.plan.GeneratedAt,
			},
			HostRef:  report.Host{HostnameHash: report.HashHostname(a.hostname)},
			Progress: func(format string, args ...any) { fmt.Fprintf(stdout, "  "+format+"\n", args...) },
		},
		ConfirmWithin: a.within, Session: sess, Exe: exe, Baseline: base, ConfirmFrom: confirmFrom,
	})
	if j == nil {
		return fail("%v; nothing was changed", runErr)
	}
	_ = apply.WriteResult(stdout, j)
	if runErr != nil {
		fmt.Fprintf(stderr, "stackward apply: %v\n", runErr)
		if txn.Status == apply.TxnRolledBack {
			fmt.Fprintf(stderr, "Transaction %s was rolled back at once; the host is as it was before. Nothing to acknowledge.\n", txn.ID)
		} else {
			fmt.Fprintf(stderr, "Transaction %s is %s. Check the files in the journal %s by hand, then acknowledge with: sudo stackward confirm --ack-rollback %s\n", txn.ID, txn.Status, apply.JournalPath(txn.ID), txn.ID)
		}
		return exitStepFailed
	}
	fmt.Fprintf(stdout, `
Transaction %[1]s is OPEN: applied and validated.
Unless you confirm before %[2]s (within %[3]s), the rollback timer undoes it.

Keep this session open. Open a NEW SSH session to this host and run there:
   sudo stackward confirm %[1]s
If the new session cannot log in, do nothing: the change rolls back at the deadline.
From the provider console instead:   sudo stackward confirm --console %[1]s
To roll back now:                    sudo stackward undo --transaction %[1]s
`, txn.ID, txn.Deadline, a.within)
	return report.ExitOK
}

// proveLive runs the lockout guard for steps that close or narrow a way
// in, over facts read from this host now (the plan's may be stale) and
// the applying session, and prints the proof. It returns the networks the
// confirming session must come from.
func proveLive(ctx context.Context, env applyEnv, steps []plan.Step, sess apply.Session, stdout io.Writer) ([]string, error) {
	if !apply.NeedsProof(steps) {
		return nil, nil
	}
	fmt.Fprintf(stdout, "\nlockout guard: proving a second way in from this host's live state (read only)...\n")
	proofs, err := apply.GuardAccess(steps, env.liveFacts(ctx), sess)
	if err != nil {
		return nil, err
	}
	for i, p := range proofs {
		if !p.Needed {
			continue
		}
		fmt.Fprintf(stdout, "   %s %s\n", steps[i].ID, strings.Join(p.Narrows, ", "))
		for _, w := range p.Ways {
			fmt.Fprintf(stdout, "   second way in: %s\n", w)
		}
	}
	return apply.ConfirmFrom(proofs), nil
}

// errOr is err's text, or why when err is nil.
func errOr(err error, why string) string {
	if err != nil {
		return err.Error()
	}
	return why
}

// describeSession says which session facts were found.
func describeSession(s apply.Session) string {
	var parts []string
	if s.SSHConnection != "" {
		f := strings.Fields(s.SSHConnection)
		if len(f) >= 2 {
			parts = append(parts, "SSH from "+f[0]+" port "+f[1])
		} else {
			parts = append(parts, "SSH connection "+s.SSHConnection)
		}
	}
	if s.SSHD != "" {
		parts = append(parts, "sshd process "+strings.SplitN(s.SSHD, ":", 2)[0])
	}
	if s.AuditSession != "" {
		parts = append(parts, "audit session "+s.AuditSession)
	}
	if s.XDGSession != "" {
		parts = append(parts, "logind session "+s.XDGSession)
	}
	if len(parts) == 0 {
		return "not an SSH session (no session facts found); confirm will need --console"
	}
	return strings.Join(parts, ", ")
}

// Who runs undo --transaction: a person, the rollback timer or the boot
// unit.
const (
	byPerson = ""
	byTimer  = "timer"
	byBoot   = "boot"
)

// undoTransaction rolls back an open transaction: by hand, from the
// rollback timer or from the boot unit (by). The timer and the boot unit
// wait for the lock, do nothing when the transaction is no longer open,
// leave the rollback to be acknowledged and do not stop the timer's units.
func undoTransaction(env applyEnv, id string, yes bool, by string, stdout, stderr io.Writer) int {
	fail := func(format string, a ...any) int {
		fmt.Fprintf(stderr, "stackward undo: "+format+"\n", a...)
		return report.ExitError
	}
	if !apply.ValidRunID(id) {
		return fail("%q is not a transaction id (they look like 20260301T120000Z-1a2b3c)", id)
	}
	if err := needRootOnLinux(env, "undo"); err != nil {
		return fail("%v; nothing was changed", err)
	}
	release, err := lockForUndo(env, id, by)
	if err != nil {
		return fail("%v; nothing was changed", err)
	}
	defer func() { _ = release() }()
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	t, err := apply.LoadTxn(env.host)
	if err != nil {
		return fail("%v; nothing was changed", err)
	}
	if t == nil || t.ID != id || t.Status != apply.TxnOpen {
		return notOpen(ctx, env, t, id, by, stdout, stderr)
	}
	j, err := apply.LoadJournal(env.host, id)
	if err != nil {
		return fail("%v", err)
	}
	if by == byPerson {
		if why := hostMismatch(env, "transaction", id, j.Host.HostnameHash); why != "" {
			return fail("%s", why)
		}
		if code, ok := askUndoTransaction(env, j, t, yes, stdout, stderr); !ok {
			return code
		}
	} else {
		noteHost(env, t, j.Host.HostnameHash, stdout)
	}
	return rollBackTransaction(ctx, env, j, t, by, stdout, stderr)
}

// hostMismatch says why a person's undo refuses a journal whose hostname
// hash is not this host's, or "".
func hostMismatch(env applyEnv, what, id, applied string) string {
	hostname, _ := env.hostname()
	if hostname != "" && applied == report.HashHostname(hostname) {
		return ""
	}
	now := "this host has no hostname"
	if hostname != "" {
		now = "this host is " + report.HashHostname(hostname)
	}
	return fmt.Sprintf("%s %s was applied on host %s and %s, so undo will not restore its journal here. If this is the same machine under a new name, set the old hostname back (hostnamectl set-hostname) and run undo again; nothing was changed", what, id, applied, now)
}

// noteHost records, for the rollback timer and the boot unit, the hostname
// hash the rollback runs under and any mismatch with the one that applied.
// They do not check it: at early boot the hostname may be unset or the
// image default, and a renamed host must still roll back. The state, the
// journal and the binary copy are local files this machine wrote.
func noteHost(env applyEnv, t *apply.Txn, applied string, stdout io.Writer) {
	hostname, _ := env.hostname()
	t.RollbackHost = "unset"
	if hostname != "" {
		t.RollbackHost = report.HashHostname(hostname)
	}
	if t.RollbackHost == applied {
		return
	}
	t.HostNote = fmt.Sprintf("rolled back while the hostname was %s, applied on %s; the automatic rollback does not check the hostname", t.RollbackHost, applied)
	fmt.Fprintf(stdout, "stackward undo: note: %s\n", t.HostNote)
}

// lockForUndo takes the run lock: the timer and the boot unit wait for it,
// a person does not.
func lockForUndo(env applyEnv, id, by string) (func() error, error) {
	holder := "rollback of transaction " + id
	if by != byPerson {
		return apply.AcquireRunLockWait(env.host, holder, apply.TimerLockWait, apply.TimerLockInterval, env.sleep)
	}
	return apply.AcquireRunLock(env.host, holder)
}

// notOpen answers an undo of a transaction that is not the current open
// one. The boot unit removes itself then: it has nothing left to do.
func notOpen(ctx context.Context, env applyEnv, t *apply.Txn, id, by string, stdout, stderr io.Writer) int {
	if by == byBoot {
		if err := apply.RemoveBootUnit(ctx, env.host, id); err != nil {
			fmt.Fprintf(stderr, "stackward undo: warning: %v\n", err)
		}
	}
	if t == nil || t.ID != id {
		if by != byPerson {
			fmt.Fprintf(stdout, "stackward undo: transaction %s is not the current transaction; nothing to roll back\n", id)
			return report.ExitOK
		}
		fmt.Fprintf(stderr, "stackward undo: transaction %s is not the current transaction; nothing was changed\n", id)
		return report.ExitError
	}
	fmt.Fprintf(stdout, "stackward undo: transaction %s is %s; nothing to roll back\n", id, t.Status)
	return report.ExitOK
}

// askUndoTransaction shows a person what the rollback does and asks. ok is
// false when the caller must stop with code.
func askUndoTransaction(env applyEnv, j *apply.Journal, t *apply.Txn, yes bool, stdout, stderr io.Writer) (int, bool) {
	fmt.Fprintf(stdout, "stackward undo: transaction %s (open until %s)\n\nWill do, newest change first:\n", t.ID, t.Deadline)
	for _, l := range apply.UndoScript(j) {
		fmt.Fprintf(stdout, "   %s\n", l)
	}
	fmt.Fprintf(stdout, "and stop the timer %s.timer and remove the boot unit %s\n", t.TimerUnit, apply.BootUnit(t.ID))
	ok, err := confirm(env, yes, stdout, "\nRoll back this transaction now? [y/N] ")
	if ok {
		return 0, true
	}
	if err != nil {
		fmt.Fprintf(stderr, "stackward undo: %v; nothing was changed\n", err)
		return report.ExitError, false
	}
	fmt.Fprintln(stdout, "stackward undo: not confirmed; nothing was changed")
	return report.ExitError, false
}

// rollBackTransaction rolls the open transaction back and says what
// happened.
func rollBackTransaction(ctx context.Context, env applyEnv, j *apply.Journal, t *apply.Txn, by string, stdout, stderr io.Writer) int {
	id := t.ID
	cause := apply.CauseManual
	switch by {
	case byTimer:
		cause = apply.CauseTimer
		fmt.Fprintf(stdout, "stackward undo: transaction %s was not confirmed before %s; rolling it back\n", id, t.Deadline)
	case byBoot:
		cause = apply.CauseBoot
		fmt.Fprintf(stdout, "stackward undo: the host booted while transaction %s was open (deadline %s); rolling it back before sshd starts\n", id, t.Deadline)
	}
	progress := func(format string, a ...any) { fmt.Fprintf(stdout, "  "+format+"\n", a...) }
	err := apply.RollBack(ctx, env.host, j, t, cause, apply.UndoOptions{Host: env.host, Now: env.now, Progress: progress})
	if err != nil {
		fmt.Fprintf(stderr, "stackward undo: the rollback of transaction %s failed: %v\nCheck the files in the journal %s by hand, then acknowledge with: sudo stackward confirm --ack-rollback %s\n", id, err, apply.JournalPath(id), id)
		return exitStepFailed
	}
	if by != byPerson {
		fmt.Fprintf(stdout, "stackward undo: transaction %s rolled back; access-critical steps stay blocked until: sudo stackward confirm --ack-rollback %s\n", id, id)
		return report.ExitOK
	}
	if err := apply.Disarm(ctx, env.host, t.TimerUnit); err != nil {
		fmt.Fprintf(stderr, "stackward undo: rolled back, but the timer could not be stopped (%v); when it fires it finds nothing to do\n", err)
	}
	fmt.Fprintf(stdout, "stackward undo: transaction %s rolled back; the journal %s says what was restored\n", id, apply.JournalPath(id))
	return report.ExitOK
}

func runConfirm(args []string, stdout, stderr io.Writer) int {
	return runConfirmEnv(args, stdout, stderr, hostApplyEnv())
}

// runConfirmEnv keeps the change of an open transaction, or acknowledges a
// rollback.
func runConfirmEnv(args []string, stdout, stderr io.Writer, env applyEnv) int {
	var console bool
	var ack string
	fs := flag.NewFlagSet("confirm", flag.ContinueOnError)
	fs.SetOutput(stderr)
	fs.BoolVar(&console, "console", false, "confirm from the provider console: skip the new SSH session check")
	fs.StringVar(&ack, "ack-rollback", "", "acknowledge that transaction ID was rolled back, so access-critical steps may run again")
	fs.Usage = func() {
		fmt.Fprintf(stderr, `Usage: stackward confirm [--console] ID
       stackward confirm --ack-rollback ID
       stackward confirm            (show the current transaction)

Keep the change of an open access-critical transaction and stop its
rollback timer. It must run from a NEW SSH session: the session that
applied is refused, because surviving the change proves nothing about a
fresh login. --console is the one way around that rule, for the provider
console. Needs root.

Flags:
`)
		fs.PrintDefaults()
		fmt.Fprintf(stderr, "\nExit codes: 0 confirmed or acknowledged, 2 refused or error (nothing changed).\n")
	}
	pos, err := parseInterleaved(fs, args)
	if err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return report.ExitOK
		}
		return report.ExitError
	}
	fail := func(format string, a ...any) int {
		fmt.Fprintf(stderr, "stackward confirm: "+format+"\n", a...)
		return report.ExitError
	}
	if len(pos) > 1 || (ack != "" && (len(pos) > 0 || console)) {
		return fail("give one transaction id, or --ack-rollback ID alone")
	}
	id := ack
	if len(pos) == 1 {
		id = pos[0]
	}
	if id != "" && !apply.ValidRunID(id) {
		return fail("%q is not a transaction id (they look like 20260301T120000Z-1a2b3c)", id)
	}
	if err := needRootOnLinux(env, "confirm"); err != nil {
		return fail("%v; nothing was changed", err)
	}
	holder := "confirm"
	if id != "" {
		holder += " of " + id
	}
	release, err := apply.AcquireRunLock(env.host, holder)
	if err != nil {
		return fail("%v; nothing was changed", err)
	}
	defer func() { _ = release() }()
	t, err := apply.LoadTxn(env.host)
	if err != nil {
		return fail("%v", err)
	}
	if id == "" {
		writeTxnStatus(stdout, t, env.now())
		return report.ExitOK
	}
	if t == nil || t.ID != id {
		return fail("transaction %s is not the current transaction; run stackward confirm without an id to see it", id)
	}
	now := env.now()
	if ack != "" {
		if t.AckedAt != "" && (t.Status == apply.TxnRolledBack || t.Status == apply.TxnRollbackFailed) {
			fmt.Fprintf(stdout, "stackward confirm: the rollback of transaction %s was already acknowledged at %s\n", id, t.AckedAt)
			return report.ExitOK
		}
		if err := apply.AckRollback(env.host, t, now); err != nil {
			return fail("%v", err)
		}
		fmt.Fprintf(stdout, "stackward confirm: transaction %s %s (%s) at %s.\n", id, apply.RollbackWords(t.Status), t.Cause, t.RolledBackAt)
		if t.Status == apply.TxnRollbackFailed {
			fmt.Fprintf(stdout, "The rollback failed: %s\nCheck the files in the journal %s by hand.\n", t.Error, apply.JournalPath(id))
		}
		fmt.Fprintf(stdout, "Acknowledged: access-critical steps may run again.\n")
		return report.ExitOK
	}
	sess := env.session()
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	why, err := apply.ConfirmTxn(ctx, env.host, t, console, sess, now)
	if err != nil {
		if !console {
			fmt.Fprintf(stderr, "session:   %s\n", describeSession(sess))
		}
		return fail("%v", err)
	}
	fmt.Fprintf(stdout, "stackward confirm: %s\n", why)
	if err := apply.UpdateJournalTxn(env.host, t); err != nil {
		fmt.Fprintf(stderr, "stackward confirm: warning: the journal could not be updated: %v\n", err)
	}
	fmt.Fprintf(stdout, "stackward confirm: transaction %s confirmed; the rollback timer is stopped and the change stays\n", id)
	return report.ExitOK
}

// writeTxnStatus prints the current transaction.
func writeTxnStatus(w io.Writer, t *apply.Txn, now time.Time) {
	if t == nil {
		fmt.Fprintln(w, "stackward confirm: no transaction has run on this host")
		return
	}
	fmt.Fprintf(w, "transaction: %s\nstatus:      %s\nsteps:       %s\nopened:      %s\ndeadline:    %s\n", t.ID, t.Status, strings.Join(t.Steps, ", "), t.OpenedAt, t.Deadline)
	if t.ConfirmedAt != "" {
		fmt.Fprintf(w, "confirmed:   %s (%s)\n", t.ConfirmedAt, t.ConfirmedVia)
	}
	if t.RolledBackAt != "" {
		fmt.Fprintf(w, "rolled back: %s (%s)\n", t.RolledBackAt, t.Cause)
	}
	if t.Error != "" {
		fmt.Fprintf(w, "error:       %s\n", t.Error)
	}
	if t.HostNote != "" {
		fmt.Fprintf(w, "note:        %s\n", t.HostNote)
	}
	if why := t.Blocks(now); why != "" {
		fmt.Fprintf(w, "\n%s\n", why)
	}
}
