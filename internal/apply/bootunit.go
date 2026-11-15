package apply

import (
	"bytes"
	"context"
	_ "embed"
	"fmt"
	"path"
	"slices"
	"strings"
	"text/template"
)

// The boot unit makes the rollback survive a reboot. The rollback timer is
// a transient unit, and a reboot drops it; the boot unit is a persistent
// oneshot service in /etc/systemd/system that runs the same root only copy
// of stackward at boot with `undo --transaction ID --by-boot`. That rolls
// the transaction back only while its state is still open, before sshd
// starts, and removes the unit. Confirm and every rollback remove it too.
//
// It has DefaultDependencies=no: the default dependencies order a service
// after basic.target, which comes after sockets.target and so after
// ssh.socket, and Before=ssh.socket would then be an ordering cycle.
//
// It is enabled with `systemctl enable` rather than a symlink written by
// hand: systemd derives the link from the unit's own [Install] section,
// Host has no symlink write (and does not need one), and enable reloads
// systemd. Removal deletes the link and the file through Host and runs
// `systemctl daemon-reload`, which also works when the unit file is gone
// already and only a dangling link is left.

// Where the boot unit lives.
const (
	SystemdUnitDir = "/etc/systemd/system"
	// BootTarget is the target that wants the boot unit.
	BootTarget       = "sysinit.target"
	bootUnitPrefix   = "stackward-boot-rollback-"
	bootUnitSuffix   = ".service"
	bootUnitWantsDir = SystemdUnitDir + "/" + BootTarget + ".wants"
)

//go:embed bootunit.service.tmpl
var bootUnitTemplate string

var bootUnitTmpl = template.Must(template.New("boot unit").Option("missingkey=error").Parse(bootUnitTemplate))

// BootUnit is the name of the boot unit of transaction id. It differs from
// TimerUnit, whose .service is the transient service of the timer.
func BootUnit(id string) string { return bootUnitPrefix + id + bootUnitSuffix }

// BootUnitPath is the unit file of transaction id.
func BootUnitPath(id string) string { return path.Join(SystemdUnitDir, BootUnit(id)) }

// bootUnitLink is the link `systemctl enable` makes for transaction id.
func bootUnitLink(id string) string { return path.Join(bootUnitWantsDir, BootUnit(id)) }

// BootUnitText is the unit file of transaction id, from the one template.
func BootUnitText(id string) (string, error) {
	if !ValidRunID(id) {
		return "", fmt.Errorf("%q is not a run id", id)
	}
	var b bytes.Buffer
	err := bootUnitTmpl.Execute(&b, map[string]string{
		"ID": id, "State": TxnStatePath, "Binary": TxnBinary(id), "Target": BootTarget,
	})
	return b.String(), err
}

// InstallBootUnit writes the boot unit of transaction id, enables it and
// checks that the link is there.
func InstallBootUnit(ctx context.Context, h Host, id string) error {
	text, err := BootUnitText(id)
	if err != nil {
		return err
	}
	if err := h.MkdirAll(SystemdUnitDir, 0o755); err != nil {
		return err
	}
	if err := h.WriteAtomic(BootUnitPath(id), []byte(text), FileState{Mode: 0o644, UID: -1, GID: -1}, nil); err != nil {
		return fmt.Errorf("writing the boot unit %s: %w", BootUnitPath(id), err)
	}
	if _, _, err := runCheck(ctx, h, "systemctl", "enable", BootUnit(id)); err != nil {
		return fmt.Errorf("enabling the boot unit: %w", err)
	}
	st, err := h.Stat(bootUnitLink(id))
	if err != nil {
		return err
	}
	if !st.Symlink {
		return fmt.Errorf("the boot unit %s is not enabled after systemctl enable: %s is missing", BootUnit(id), bootUnitLink(id))
	}
	return nil
}

// RemoveBootUnit removes the boot unit of transaction id (its link and its
// file) and reloads systemd. A unit that is gone already is not an error,
// and then nothing runs.
func RemoveBootUnit(ctx context.Context, h Host, id string) error {
	removed := false
	for _, p := range []string{bootUnitLink(id), BootUnitPath(id)} {
		st, err := h.Stat(p)
		if err != nil {
			return err
		}
		if !st.Exists {
			continue
		}
		if err := h.Remove(p); err != nil {
			return fmt.Errorf("removing %s: %w", p, err)
		}
		removed = true
	}
	if !removed {
		return nil
	}
	if _, _, err := runCheck(ctx, h, "systemctl", "daemon-reload"); err != nil {
		return fmt.Errorf("the boot unit %s is removed, but systemd could not reload: %w", BootUnit(id), err)
	}
	return nil
}

// removeBootUnitOrWarn removes the boot unit and says what to do by hand
// when it cannot. A unit left behind does no harm (at boot it finds the
// transaction no longer open), but apply refuses access steps until it is
// gone (StaleBootUnits).
func removeBootUnitOrWarn(ctx context.Context, h Host, id string, progress func(string, ...any)) {
	if err := RemoveBootUnit(ctx, h, id); err != nil && progress != nil {
		progress("warning: %v; remove it by hand: %s", err, bootUnitFix([]string{id}))
	}
}

// StaleBootUnits returns why access steps cannot run because a boot unit
// is left over without an open transaction of its own, with the commands
// that remove it, or "".
func StaleBootUnits(h Host, t *Txn) (string, error) {
	ids := map[string]bool{}
	for _, dir := range []string{SystemdUnitDir, bootUnitWantsDir} {
		names, err := h.ReadDir(dir)
		if err != nil {
			return "", fmt.Errorf("listing %s: %w", dir, err)
		}
		for _, n := range names {
			id, ok := strings.CutPrefix(n, bootUnitPrefix)
			if id, ok2 := strings.CutSuffix(id, bootUnitSuffix); ok && ok2 {
				ids[id] = true
			}
		}
	}
	var stale []string
	for id := range ids {
		if t != nil && t.Status == TxnOpen && t.ID == id {
			continue
		}
		stale = append(stale, id)
	}
	if len(stale) == 0 {
		return "", nil
	}
	slices.Sort(stale)
	names := make([]string, len(stale))
	for i, id := range stale {
		names[i] = bootUnitPrefix + id + bootUnitSuffix
	}
	return fmt.Sprintf("a stackward boot rollback unit is left over without an open transaction (%s), so the last transaction did not finish cleaning up; remove it with: %s", strings.Join(names, ", "), bootUnitFix(stale)), nil
}

// bootUnitFix is the shell line that removes the boot units of ids.
func bootUnitFix(ids []string) string {
	var paths []string
	for _, id := range ids {
		paths = append(paths, shellQuote(bootUnitLink(id)), shellQuote(BootUnitPath(id)))
	}
	return "sudo rm -f " + strings.Join(paths, " ") + " && sudo systemctl daemon-reload"
}
