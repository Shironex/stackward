package plan

import (
	"fmt"
	"path"
	"strconv"
	"strings"

	"github.com/Shironex/stackward/internal/checks"
)

// sysctl-hardening: one sysctl.d drop-in with the hardening values that
// KRN-002, KRN-003 and KRN-004 find off baseline, applied at once with
// `sysctl -p` on that file only. It never sets net.ipv4.ip_forward and never
// edits /etc/sysctl.conf or /etc/ufw/sysctl.conf.

const sysctlDropin = "/etc/sysctl.d/90-stackward-hardening.conf"

// sysctlConfFile is applied after every drop-in (see facts/sysctl.go).
const sysctlConfFile = "/etc/sysctl.conf"

var sysctlChecks = []string{"KRN-002", "KRN-003", "KRN-004"}

func init() {
	Register(Generator{
		ID:    "sysctl-hardening",
		Title: "Set the kernel hardening values with a sysctl drop-in",
		Fixes: sysctlChecks,
		Risk:  Safe,
		Plan:  planSysctlHardening,
	})
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

	var b strings.Builder
	var fixList []string
	for _, id := range sysctlChecks {
		if fixed[id] {
			fixList = append(fixList, id)
		}
	}
	fmt.Fprintf(&b, "# Written by stackward: plan step sysctl-hardening, fixes %s.\n", strings.Join(fixList, ", "))
	b.WriteString("# Hardening values only: net.ipv4.ip_forward and the other settings\n")
	b.WriteString("# Docker needs are never set here. Remove this file to undo at the\n")
	b.WriteString("# next boot.\n")
	touches := []string{"file:" + sysctlDropin}
	var undo []Command
	notes := []string{}
	irreversible := false
	for _, f := range fixes {
		fmt.Fprintf(&b, "%s = %d\n", f.Key, f.Want)
		touches = append(touches, "sysctl:"+f.Key)
		if f.Key == "kernel.unprivileged_bpf_disabled" {
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
		Edits:    []FileEdit{newEdit(sysctlDropin, Create, "0644", "", b.String())},
		Commands: []Command{
			cmd("apply this drop-in now, and only this file, not the whole sysctl.d tree", "sysctl", "-p", sysctlDropin),
		},
		Undo: Undo{
			Description: "Remove the drop-in so the old values return at the next boot, and set the old running values now.",
			Commands:    append([]Command{cmd("remove the drop-in", "rm", "-f", sysctlDropin)}, undo...),
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
