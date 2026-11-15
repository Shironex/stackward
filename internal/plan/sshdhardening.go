package plan

import (
	"errors"
	"fmt"
	"path"
	"slices"
	"strings"

	"github.com/Shironex/stackward/internal/checks"
	"github.com/Shironex/stackward/internal/facts"
	"github.com/Shironex/stackward/internal/facts/sshd"
)

// sshd-hardening: one sshd drop-in with the settings SSH-001 to SSH-005
// find off: key only login (no password, no keyboard-interactive), no
// root login, no empty passwords, MaxAuthTries 3. sshd takes the first
// value it reads, so the drop-in is named to sort before cloud-init's
// 50-cloud-init.conf, and the plan checks from the parsed configuration
// that nothing read earlier sets the same keyword. The staged file is
// checked with sshd -t, then the transaction checks the whole
// configuration with sshd -t and sshd -T (SSHD) before it is kept.
//
// The main sshd_config is never edited. Settings the lockout guard needs
// to prove a second way in for (all of them) are refused by it when no
// non-root sudo account can log in with a key afterwards.

const sshdDropin = "/etc/ssh/sshd_config.d/00-stackward-hardening.conf"

// sshdSetting is one value the drop-in can hold.
type sshdSetting struct {
	check   string
	keyword string // as written in the file
	value   string
}

// key is the keyword as sshd -T prints it.
func (s sshdSetting) key() string { return strings.ToLower(s.keyword) }

// sshdSettings in the order the drop-in writes them.
var sshdSettings = []sshdSetting{
	{"SSH-001", "PasswordAuthentication", "no"},
	{"SSH-002", "KbdInteractiveAuthentication", "no"},
	{"SSH-003", "PermitRootLogin", "no"},
	{"SSH-004", "PermitEmptyPasswords", "no"},
	{"SSH-005", "MaxAuthTries", "3"},
}

var (
	sshdValidate = []string{"sshd", "-t", "-f"}
	sshdReload   = []string{"systemctl", "try-reload-or-restart", "ssh.service"}
	sshdRemove   = []string{"rm", "-f", sshdDropin}
)

// sshdChecks are the checks the drop-in fixes.
var sshdChecks = func() []string {
	ids := make([]string, len(sshdSettings))
	for i, s := range sshdSettings {
		ids[i] = s.check
	}
	return ids
}()

func init() {
	Register(Generator{
		ID:    SSHDHardeningID,
		Title: "Allow key logins only, refuse root and limit auth tries with an early sshd drop-in",
		Fixes: sshdChecks,
		Risk:  AccessCritical,
		Order: orderSSHDHardening,
		Plan:  planSSHDHardening,

		Authorize:        authorizeSSHDHardening,
		Check:            checkSSHDHardening,
		CommandsOnChange: true,
		SSHD:             sshdOfStep,
	})
}

// renderSSHDDropin is the drop-in for the given settings and the checks it
// claims. Authorize renders it again from the lines a plan holds.
func renderSSHDDropin(fixes []string, set []sshdSetting) string {
	var b strings.Builder
	fmt.Fprintf(&b, "# Written by stackward: plan step %s, fixes %s.\n", SSHDHardeningID, strings.Join(fixes, ", "))
	b.WriteString("# Named to sort first: sshd keeps the first value it reads. Remove this\n")
	b.WriteString("# file and reload ssh.service to undo.\n")
	for _, s := range set {
		fmt.Fprintf(&b, "%s %s\n", s.keyword, s.value)
	}
	return b.String()
}

func planSSHDHardening(in Input) Outcome {
	if out, need := checkGate(in, sshdChecks); !need {
		return out
	}
	if in.Facts == nil || in.Facts.SSH == nil {
		return Skip(SkipUnknown, "the ssh facts are missing (planning from a report alone, or the ssh collector did not run)")
	}
	s := in.Facts.SSH
	if !s.Installed {
		return Skip(SkipPassing, "no OpenSSH server is installed")
	}
	if s.Config == nil || len(s.Config.Unreadable()) > 0 {
		return Skip(SkipUnknown, "not every sshd configuration file could be read, so where the drop-in would be read is unknown; run the audit with sudo")
	}
	inc, ok := dropinInclude(s.Config)
	if !ok {
		return Skip(SkipManual, "sshd's configuration does not include %s from its global section (Include /etc/ssh/sshd_config.d/*.conf); add the setting to sshd_config by hand", path.Dir(sshdDropin))
	}
	if slices.ContainsFunc(s.Config.Files, func(f sshd.File) bool { return f.Path == sshdDropin }) {
		return Skip(SkipManual, "%s already exists but the checks still fail; read it before planning again", sshdDropin)
	}
	set, fixes, notes := chooseSSHDSettings(in, s, inc)
	if len(set) == 0 {
		return Skip(SkipManual, "%s", strings.Join(notes, "; "))
	}
	if s.Socket.Active() {
		notes = append(notes, fmt.Sprintf("sshd runs under socket activation (%s); the drop-in sets no port or listen address, so reloading ssh.service is enough and %s is left alone.", s.Socket.Unit, s.Socket.Unit))
	}
	notes = append(notes,
		"Existing SSH sessions stay open. Before you confirm, log in again in a new session with your key: that is the proof the change works.",
		"Ubuntu 22.04 and later and Debian 12 and later; older OpenSSH reads KbdInteractiveAuthentication differently.")
	return Outcome{Step: &Step{
		Fixes:    fixes,
		Restarts: []string{"ssh"},
		Touches:  []string{"file:" + sshdDropin, "service:ssh"},
		Edits:    []FileEdit{withValidate(newEdit(sshdDropin, Create, "0644", "", renderSSHDDropin(fixes, set)), sshdValidate)},
		Commands: []Command{cmd("load the new settings; running sessions stay open", sshdReload...)},
		Undo: Undo{
			Description: "Remove the drop-in and reload ssh.service; the earlier values return for new logins.",
			Commands: []Command{
				cmd("remove the drop-in", sshdRemove...),
				cmd("load the earlier settings", sshdReload...),
			},
		},
		Notes: notes,
	}}
}

func withValidate(e FileEdit, v []string) FileEdit {
	e.Validate = append([]string{}, v...)
	return e
}

// chooseSSHDSettings picks the settings whose checks warn or fail and that
// the drop-in can actually change, the checks it can claim, and notes for
// the rest.
func chooseSSHDSettings(in Input, s *facts.SSH, inc sshd.Include) ([]sshdSetting, []string, []string) {
	var set []sshdSetting
	var fixes, notes []string
	for _, st := range sshdSettings {
		if l, _ := in.Level(st.check); l != checks.Warn && l != checks.Fail {
			continue
		}
		if why := sshdSettingBlocked(in.Facts, s, st); why != "" {
			notes = append(notes, why)
			continue
		}
		cur, known := s.Value(st.key())
		if known && strings.EqualFold(cur, st.value) {
			notes = append(notes, fmt.Sprintf("%s is already %s globally; a Match block sets it otherwise, which a drop-in cannot change (edit that block by hand)", st.keyword, cur))
			continue
		}
		if d, ok := readBefore(s.Config, inc, st.key()); ok {
			notes = append(notes, fmt.Sprintf("%s:%d sets %s and is read before %s, so the drop-in would not win; change it there by hand", d.File, d.Line, d.Value, sshdDropin))
			continue
		}
		set = append(set, st)
		if b := matchSets(s.Config, st.key()); b != "" {
			notes = append(notes, fmt.Sprintf("the Match block at %s sets %s too; the drop-in changes only the global value, so %s still names that block", b, st.keyword, st.check))
			continue
		}
		fixes = append(fixes, st.check)
	}
	if len(set) > 0 && len(fixes) == 0 {
		// The step still changes the global values; claim the first.
		fixes = append(fixes, set[0].check)
	}
	return set, fixes, notes
}

// sshdSettingBlocked says why a setting must stay out of the drop-in on
// this host, or "".
func sshdSettingBlocked(f *facts.Facts, s *facts.SSH, st sshdSetting) string {
	methods, _ := s.Setting("authenticationmethods")
	nonDefault := len(methods) > 1 || (len(methods) == 1 && !strings.EqualFold(methods[0], "any"))
	switch st.check {
	case "SSH-001", "SSH-002":
		if nonDefault {
			return fmt.Sprintf("AuthenticationMethods is %q; turning %s off could break it, so it is left for you", strings.Join(methods, " "), st.keyword)
		}
		if st.check == "SSH-002" && len(s.PAM2FA) > 0 {
			return fmt.Sprintf("keyboard-interactive carries a PAM second factor (%s), so it stays on", strings.Join(s.PAM2FA, ", "))
		}
	case "SSH-003":
		if f.PaaS == nil {
			return "PermitRootLogin is left alone: the platform facts are missing, and Coolify or Dokploy log in as root by default"
		}
		if len(f.PaaS.Platforms) > 0 {
			return fmt.Sprintf("PermitRootLogin is left alone: %s logs in as root by default; move it to its own account (paas-user), then turn root login off by hand", f.PaaS.Platforms[0].Name)
		}
	}
	return ""
}

// dropinInclude finds the global Include whose pattern matches the drop-in.
func dropinInclude(c *sshd.Config) (sshd.Include, bool) {
	for _, inc := range c.Includes {
		if inc.Match != 0 {
			continue
		}
		if ok, err := path.Match(inc.Pattern, sshdDropin); err == nil && ok {
			return inc, true
		}
	}
	return sshd.Include{}, false
}

// readBefore returns the first global directive for key that sshd could
// read before the drop-in. It counts as read after only when it is sure:
// a later line of the file holding the Include, a file the same pattern
// matches that sorts after the drop-in, or a file read after such a file.
func readBefore(c *sshd.Config, inc sshd.Include, key string) (sshd.Directive, bool) {
	later := -1
	for i, f := range c.Files {
		if ok, _ := path.Match(inc.Pattern, f.Path); ok && f.Path > sshdDropin {
			later = i
			break
		}
	}
	index := map[string]int{}
	for i, f := range c.Files {
		if _, seen := index[f.Path]; !seen {
			index[f.Path] = i
		}
	}
	for _, d := range c.Directives {
		if d.Match != 0 || sshd.Canonical(d.Keyword) != key {
			continue
		}
		switch {
		case d.File == inc.File && d.Line > inc.Line:
		case later >= 0 && index[d.File] >= later:
		default:
			return d, true
		}
	}
	return sshd.Directive{}, false
}

// matchSets returns where a Match block sets key, or "".
func matchSets(c *sshd.Config, key string) string {
	for _, d := range c.Directives {
		if d.Match > 0 && sshd.Canonical(d.Keyword) == key && d.Match <= len(c.Matches) {
			m := c.Matches[d.Match-1]
			return fmt.Sprintf("%s:%d (%s)", m.File, m.Line, m.Criteria)
		}
	}
	return ""
}

// sshdLines parses the setting lines of a drop-in, refusing anything the
// step would not write.
func sshdLines(content string) ([]sshdSetting, error) {
	var out []sshdSetting
	for _, line := range strings.Split(strings.TrimSuffix(content, "\n"), "\n") {
		if strings.HasPrefix(line, "#") {
			continue
		}
		f := strings.Fields(line)
		i := slices.IndexFunc(sshdSettings, func(s sshdSetting) bool { return len(f) == 2 && f[0] == s.keyword && f[1] == s.value })
		if i < 0 {
			return nil, fmt.Errorf("%s: line %q is not a setting the step writes", sshdDropin, line)
		}
		out = append(out, sshdSettings[i])
	}
	return out, nil
}

func authorizeSSHDHardening(s Step) error {
	e, err := wantOneEdit(s, sshdDropin, Create)
	if err != nil {
		return err
	}
	set, err := sshdLines(e.New)
	if err != nil {
		return err
	}
	if len(set) == 0 {
		return errors.New("the drop-in sets nothing")
	}
	for _, f := range s.Fixes {
		if !slices.ContainsFunc(set, func(st sshdSetting) bool { return st.check == f }) {
			return fmt.Errorf("it claims to fix %s but does not set its keyword", f)
		}
	}
	// Re-render in the step's own order, so lines cannot be shuffled or
	// repeated.
	var ordered []sshdSetting
	for _, st := range sshdSettings {
		if slices.Contains(set, st) {
			ordered = append(ordered, st)
		}
	}
	if err := wantContent(e, renderSSHDDropin(s.Fixes, ordered)); err != nil {
		return err
	}
	if err := wantValidate(e, sshdValidate); err != nil {
		return err
	}
	if err := wantRestarts(s, "ssh"); err != nil {
		return err
	}
	if err := wantCommands("commands", s.Commands, sshdReload); err != nil {
		return err
	}
	return wantCommands("undo", s.Undo.Commands, sshdRemove, sshdReload)
}

// sshdOfStep returns the effective settings the drop-in leaves, as sshd -T
// prints them. A drop-in that does not parse leaves nothing to compare;
// Authorize refuses it before it runs.
func sshdOfStep(s Step) map[string]string {
	out := map[string]string{}
	for _, e := range s.Edits {
		if e.Path != sshdDropin {
			continue
		}
		set, err := sshdLines(e.New)
		if err != nil {
			// An unknown line: say it touches password login, so the
			// guard still asks for a proof.
			out["passwordauthentication"] = "no"
			continue
		}
		for _, st := range set {
			out[st.key()] = st.value
		}
	}
	return out
}

// checkSSHDHardening: applied when the drop-in holds the planned content.
// The reload follows the write in the same run.
func checkSSHDHardening(r Reader, s Step) (bool, string, error) {
	ok, err := FileHolds(r, sshdDropin, s.Edits[0].NewSHA256)
	if err != nil || !ok {
		return false, "", err
	}
	return true, sshdDropin + " already holds the planned content", nil
}
