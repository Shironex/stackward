package plan

import (
	"fmt"
	"path"
	"slices"
	"strconv"
	"strings"

	"github.com/Shironex/stackward/internal/checks"
	"github.com/Shironex/stackward/internal/facts"
)

// sysctl-hardening: one sysctl.d drop-in with the hardening values that
// KRN-002, KRN-003 and KRN-004 find off baseline, applied at once with
// `sysctl -p` on that file only. It never sets net.ipv4.ip_forward and never
// edits /etc/sysctl.conf or /etc/ufw/sysctl.conf.

const sysctlDropin = "/etc/sysctl.d/90-stackward-hardening.conf"

// sysctlConfFile is applied after every drop-in (see facts/sysctl.go).
const sysctlConfFile = "/etc/sysctl.conf"

var sysctlChecks = []string{"KRN-002", "KRN-003", "KRN-004"}

// sysctlBPFKey cannot be lowered again without a reboot, so the undo
// does not try.
const sysctlBPFKey = "kernel.unprivileged_bpf_disabled"

var (
	sysctlLoad   = []string{"sysctl", "-p", sysctlDropin}
	sysctlRemove = []string{"rm", "-f", sysctlDropin}
)

func init() {
	Register(Generator{
		ID:    "sysctl-hardening",
		Title: "Set the kernel hardening values with a sysctl drop-in",
		Fixes: sysctlChecks,
		Risk:  Safe,
		Plan:  planSysctlHardening,

		Authorize: authorizeSysctlHardening,
		Pin:       pinSysctlUndo,
		Check:     checkSysctlHardening,
	})
}

// renderSysctlDropin is the drop-in for the given fixes. Authorize renders
// it again from the keys a plan names, so a plan cannot carry other text.
func renderSysctlDropin(fixList []string, fixes []checks.SysctlFix) string {
	var b strings.Builder
	fmt.Fprintf(&b, "# Written by stackward: plan step sysctl-hardening, fixes %s.\n", strings.Join(fixList, ", "))
	b.WriteString("# Hardening values only: net.ipv4.ip_forward and the other settings\n")
	b.WriteString("# Docker needs are never set here. Remove this file to undo at the\n")
	b.WriteString("# next boot.\n")
	for _, f := range fixes {
		fmt.Fprintf(&b, "%s = %d\n", f.Key, f.Want)
	}
	return b.String()
}

func planSysctlHardening(in Input) Outcome {
	if out, need := checkGate(in, sysctlChecks); !need {
		return out
	}
	if in.Facts == nil || in.Facts.Sysctl == nil {
		return Skip(SkipUnknown, "the sysctl facts are missing (planning from a report alone, or the sysctl collector did not run)")
	}
	s := in.Facts.Sysctl
	for key, set := range s.Configured {
		if set.File == sysctlDropin {
			return Skip(SkipManual, "%s already exists (it sets %s) but the running values are still off; find what resets them before planning again", sysctlDropin, key)
		}
	}

	var fixes []checks.SysctlFix
	fixed := map[string]bool{}
	for _, f := range checks.SysctlFixes(s) {
		if l, _ := in.Level(f.CheckID); l != checks.Warn && l != checks.Fail {
			continue
		}
		fixes = append(fixes, f)
		fixed[f.CheckID] = true
	}
	ufw := checks.UFWSysctlOverrides(s)
	if len(fixes) == 0 {
		if len(ufw) > 0 {
			return Skip(SkipManual, "the running values are fine, but /etc/ufw/sysctl.conf resets %s on every ufw enable and reload; edit that file by hand", strings.Join(ufw, ", "))
		}
		return Skip(SkipManual, "the KRN findings name no running value a drop-in can fix")
	}

	var fixList []string
	for _, id := range sysctlChecks {
		if fixed[id] {
			fixList = append(fixList, id)
		}
	}
	touches := []string{"file:" + sysctlDropin}
	var undo []Command
	notes := []string{}
	irreversible := false
	for _, f := range fixes {
		touches = append(touches, "sysctl:"+f.Key)
		if f.Key == sysctlBPFKey {
			irreversible = true
			continue // the kernel refuses to lower it again
		}
		undo = append(undo, cmd("restore the running value", "sysctl", "-w", fmt.Sprintf("%s=%d", f.Key, f.Current)))
		if later := laterSetting(s.Configured[f.Key].File); later != "" && s.Configured[f.Key].Value != strconv.Itoa(f.Want) {
			notes = append(notes, fmt.Sprintf("%s sets %s = %s and is read after this drop-in, so the old value returns at boot; change it there by hand.", later, f.Key, s.Configured[f.Key].Value))
		}
	}
	if len(ufw) > 0 {
		notes = append(notes, "/etc/ufw/sysctl.conf sets "+strings.Join(ufw, ", ")+" and ufw applies it again on every enable and reload; this step leaves that file alone.")
	}
	if irreversible {
		notes = append(notes, "kernel.unprivileged_bpf_disabled = 1 cannot be lowered again without a reboot.")
	}

	return Outcome{Step: &Step{
		Fixes:    fixList,
		Restarts: []string{},
		Touches:  touches,
		Edits:    []FileEdit{newEdit(sysctlDropin, Create, "0644", "", renderSysctlDropin(fixList, fixes))},
		Commands: []Command{
			cmd("apply this drop-in now, and only this file, not the whole sysctl.d tree", sysctlLoad...),
		},
		Undo: Undo{
			Description: "Remove the drop-in so the old values return at the next boot, and set the old running values now.",
			Commands:    append([]Command{cmd("remove the drop-in", sysctlRemove...)}, undo...),
		},
		Notes: notes,
	}}
}

// laterSetting returns file when sysctl reads it after the stackward
// drop-in (a drop-in whose name sorts later, or /etc/sysctl.conf).
func laterSetting(file string) string {
	if file == "" || file == sysctlDropin {
		return ""
	}
	if file == sysctlConfFile || path.Base(file) > path.Base(sysctlDropin) {
		return file
	}
	return ""
}

// sysctlTargets is every setting the drop-in may hold, with the value it
// sets and the check it fixes. It asks checks.SysctlFixes itself, over a
// Docker host where every watched key is first 1 and then 0, so the plan
// and apply share the checks' one baseline. ip_forward is never in it.
var sysctlTargets = func() map[string]checks.SysctlFix {
	out := map[string]checks.SysctlFix{}
	for _, v := range []string{"0", "1"} {
		s := &facts.Sysctl{Values: map[string]string{}, DockerPresent: true}
		for _, k := range facts.WatchedSysctls {
			s.Values[k] = v
		}
		for _, f := range checks.SysctlFixes(s) {
			f.Current = 0
			out[f.Key] = f
		}
	}
	delete(out, "net.ipv4.ip_forward")
	return out
}()

// parseSysctlDropin reads the key = value lines of a drop-in stackward
// wrote, refusing any key it does not set and any repeated key.
func parseSysctlDropin(content string) ([]checks.SysctlFix, error) {
	var out []checks.SysctlFix
	seen := map[string]bool{}
	for _, line := range strings.Split(content, "\n") {
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		key, val, ok := strings.Cut(line, " = ")
		if !ok {
			return nil, fmt.Errorf("%s: line %q is not key = value", sysctlDropin, line)
		}
		t, known := sysctlTargets[key]
		if !known {
			return nil, fmt.Errorf("%s: %s is not a setting the step manages", sysctlDropin, key)
		}
		if val != strconv.Itoa(t.Want) {
			return nil, fmt.Errorf("%s: %s = %s, the step only ever sets %d", sysctlDropin, key, val, t.Want)
		}
		if seen[key] {
			return nil, fmt.Errorf("%s: %s is set twice", sysctlDropin, key)
		}
		seen[key] = true
		out = append(out, t)
	}
	if len(out) == 0 {
		return nil, fmt.Errorf("%s sets nothing", sysctlDropin)
	}
	return out, nil
}

func authorizeSysctlHardening(s Step) error {
	e, err := wantOneEdit(s, sysctlDropin, Create)
	if err != nil {
		return err
	}
	fixes, err := parseSysctlDropin(e.New)
	if err != nil {
		return err
	}
	if err := wantContent(e, renderSysctlDropin(s.Fixes, fixes)); err != nil {
		return err
	}
	if err := wantValidate(e, nil); err != nil {
		return err
	}
	if err := wantRestarts(s); err != nil {
		return err
	}
	if err := wantCommands("commands", s.Commands, sysctlLoad); err != nil {
		return err
	}
	// Undo: remove the drop-in, then restore each running value (any
	// number: it is what the audit saw), key for key in drop-in order.
	if len(s.Undo.Commands) == 0 || !slices.Equal(s.Undo.Commands[0].Args, sysctlRemove) {
		return fmt.Errorf("undo: the first command must be %s", strings.Join(sysctlRemove, " "))
	}
	rest := s.Undo.Commands[1:]
	i := 0
	for _, f := range fixes {
		if f.Key == sysctlBPFKey {
			continue
		}
		if i >= len(rest) {
			return fmt.Errorf("undo: no command restores %s", f.Key)
		}
		a := rest[i].Args
		if len(a) != 3 || a[0] != "sysctl" || a[1] != "-w" || !strings.HasPrefix(a[2], f.Key+"=") {
			return fmt.Errorf("undo: command %q does not restore %s", strings.Join(a, " "), f.Key)
		}
		val := strings.TrimPrefix(a[2], f.Key+"=")
		if _, err := strconv.Atoi(val); err != nil {
			return fmt.Errorf("undo: %s=%s is not a number", f.Key, val)
		}
		i++
	}
	if i != len(rest) {
		return fmt.Errorf("undo: %d commands more than the step runs", len(rest)-i)
	}
	return nil
}

// pinSysctlUndo refuses an undo that restores a key to a value other than
// the one the host holds now. The plan carries no facts, and a hand edited
// plan could otherwise choose what undo sets a key to, so the value that
// counts is the running one, the one the audit recorded. A value that
// changed since the audit also refuses: plan again. Authorize has already
// matched the undo commands to the drop-in, key for key.
func pinSysctlUndo(r Reader, s Step) error {
	fixes, err := parseSysctlDropin(s.Edits[0].New)
	if err != nil {
		return err
	}
	rest := s.Undo.Commands[1:]
	i := 0
	for _, f := range fixes {
		if f.Key == sysctlBPFKey {
			continue
		}
		val, _ := strconv.Atoi(strings.TrimPrefix(rest[i].Args[2], f.Key+"="))
		i++
		b, err := r.ReadFile("/proc/sys/" + strings.ReplaceAll(f.Key, ".", "/"))
		if err != nil {
			return fmt.Errorf("reading the running value of %s: %w", f.Key, err)
		}
		running, err := strconv.Atoi(strings.TrimSpace(string(b)))
		if err != nil {
			return fmt.Errorf("the running value of %s is not a number: %q", f.Key, strings.TrimSpace(string(b)))
		}
		if val != running {
			return fmt.Errorf("undo restores %s to %d but it is %d on this host now; undo may only restore the running value, so plan again", f.Key, val, running)
		}
	}
	return nil
}

// checkSysctlHardening: applied when the drop-in holds the planned content
// and every value in it is also the running value.
func checkSysctlHardening(r Reader, s Step) (bool, string, error) {
	e := s.Edits[0]
	ok, err := FileHolds(r, sysctlDropin, e.NewSHA256)
	if err != nil || !ok {
		return false, "", err
	}
	fixes, err := parseSysctlDropin(e.New)
	if err != nil {
		return false, "", err
	}
	for _, f := range fixes {
		p := "/proc/sys/" + strings.ReplaceAll(f.Key, ".", "/")
		b, err := r.ReadFile(p)
		if err != nil {
			return false, "", fmt.Errorf("reading the running value of %s: %w", f.Key, err)
		}
		if strings.TrimSpace(string(b)) != strconv.Itoa(f.Want) {
			return false, "", nil
		}
	}
	return true, sysctlDropin + " already holds the planned content and the running values match it", nil
}
