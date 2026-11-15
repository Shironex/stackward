package plan

import (
	"errors"
	"fmt"
	"io/fs"
	"slices"
	"strings"

	"github.com/Shironex/stackward/internal/checks"
	"github.com/Shironex/stackward/internal/facts"
)

// lock-default-user: lock the cloud image's default account (ubuntu,
// debian, admin, ec2-user) once another admin account is proven (USR-003).
// For each such account it sets the shell to nologin, locks a usable
// password and moves its authorized keys files aside, so neither a key
// nor a password logs in. It never deletes the account, never edits its
// sudoers line (taking sudo away is on the never touched list) and never
// reads or prints a key.
//
// The lockout guard proves the way that stays, and this step asks more of
// it (Access.ApplierStays): the account applying it must itself be a
// non-root sudo user that logs in with a key, so the owner has logged in
// as the new admin account before the default one is locked. Create,
// prove, then lock.

const (
	nologinShell = "/usr/sbin/nologin"
	lockedSuffix = ".stackward-locked"
)

// lockTarget is one default account the step locks.
type lockTarget struct {
	name string
	// shell is the login shell the undo puts back; "" when the step does
	// not change the shell (it is already a nologin shell).
	shell string
	// lock is true when the step locks a usable password.
	lock bool
	// keyFiles are the authorized keys files moved aside.
	keyFiles []string
}

func (t lockTarget) commands() [][]string {
	var out [][]string
	if t.shell != "" {
		out = append(out, []string{"usermod", "--shell", nologinShell, t.name})
	}
	if t.lock {
		out = append(out, []string{"usermod", "--lock", t.name})
	}
	for _, f := range t.keyFiles {
		out = append(out, []string{"mv", "-T", f, f + lockedSuffix})
	}
	return out
}

func (t lockTarget) undo() [][]string {
	var out [][]string
	for i := len(t.keyFiles) - 1; i >= 0; i-- {
		f := t.keyFiles[i]
		out = append(out, []string{"mv", "-T", f + lockedSuffix, f})
	}
	if t.lock {
		out = append(out, []string{"usermod", "--unlock", t.name})
	}
	if t.shell != "" {
		out = append(out, []string{"usermod", "--shell", t.shell, t.name})
	}
	return out
}

func lockCommands(ts []lockTarget) (cmds, undo [][]string) {
	for _, t := range ts {
		cmds = append(cmds, t.commands()...)
	}
	for i := len(ts) - 1; i >= 0; i-- {
		undo = append(undo, ts[i].undo()...)
	}
	return cmds, undo
}

func init() {
	Register(Generator{
		ID:    LockDefaultUserID,
		Title: "Lock the cloud image's default account once another admin account is proven",
		Fixes: []string{"USR-003"},
		Risk:  AccessCritical,
		Order: orderLockDefault,
		Plan:  planLockDefault,

		Authorize: authorizeLockDefault,
		Pin:       pinLockDefault,
		Check:     checkLockDefault,
		Access:    accessLockDefault,
	})
}

func planLockDefault(in Input) Outcome {
	if out, need := checkGate(in, []string{"USR-003"}); !need {
		return out
	}
	u, s, skip := accountFacts(in)
	if skip != nil {
		return *skip
	}
	if !u.PasswordStatusChecked {
		return Skip(SkipUnknown, "the password status needs root (passwd -S -a); run the audit with sudo")
	}
	var targets []lockTarget
	var notes []string
	for _, acc := range u.Accounts {
		if !slices.Contains(facts.DefaultCloudUsers, acc.Name) || !warns(in, "USR-003", "user:"+acc.Name) {
			continue
		}
		t, why := lockTargetOf(s, acc)
		if why != "" {
			return Skip(SkipManual, "%s", why)
		}
		if t.shell == "" && !t.lock && len(t.keyFiles) == 0 {
			notes = append(notes, acc.Name+" has no login shell, password or key left; only its NOPASSWD sudo line remains, which stackward never removes")
			continue
		}
		targets = append(targets, t)
	}
	if len(targets) == 0 {
		if len(notes) > 0 {
			return Skip(SkipManual, "%s", strings.Join(notes, "; "))
		}
		return Skip(SkipManual, "USR-003 names no default account this step can lock")
	}
	return Outcome{Step: lockStep(targets, u)}
}

// warns reports whether check id warns or fails for subject.
func warns(in Input, id, subject string) bool {
	for _, r := range in.Results {
		if r.ID == id && r.Subject == subject && (r.Level == checks.Warn || r.Level == checks.Fail) {
			return true
		}
	}
	return false
}

// lockTargetOf works out what locking acc takes, or why the step cannot.
func lockTargetOf(s *facts.SSH, acc facts.Account) (lockTarget, string) {
	t := lockTarget{name: acc.Name}
	if acc.Home != homeOf(acc.Name) {
		return t, fmt.Sprintf("the home of %s is %s, not %s; lock it by hand", acc.Name, acc.Home, homeOf(acc.Name))
	}
	if acc.LoginShell {
		if !validShell(acc.Shell) {
			return t, fmt.Sprintf("the shell of %s (%q) is not one the undo puts back (%s); lock it by hand", acc.Name, acc.Shell, strings.Join(loginShells, ", "))
		}
		t.shell = acc.Shell
	}
	switch acc.PasswordStatus {
	case "P":
		t.lock = true
	case "NP":
		return t, fmt.Sprintf("%s has an empty password; fix USR-002 first (passwd -l %s)", acc.Name, acc.Name)
	case "L":
	default:
		return t, fmt.Sprintf("the password status of %s is unknown; run the audit with sudo", acc.Name)
	}
	if s.UsersError != "" {
		return t, "the authorized keys could not be read: " + s.UsersError
	}
	for _, kf := range keysOf(s, acc.Name) {
		if !slices.Contains(lockableKeyFiles(acc.Name), kf.Path) {
			return t, fmt.Sprintf("%s has an authorized keys file at %s, which this step does not move; lock it by hand", acc.Name, kf.Path)
		}
		if kf.Error != "" {
			return t, fmt.Sprintf("%s could not be inspected (%s); run the audit with sudo", kf.Path, kf.Error)
		}
		t.keyFiles = append(t.keyFiles, kf.Path)
	}
	slices.Sort(t.keyFiles)
	if acc.AuthorizedKeys != nil && *acc.AuthorizedKeys && !slices.Contains(t.keyFiles, keysFile(acc.Name)) {
		return t, fmt.Sprintf("%s exists but the ssh facts do not list it; run the audit with sudo", keysFile(acc.Name))
	}
	return t, ""
}

func lockableKeyFiles(name string) []string {
	return []string{keysFile(name), keysFile(name) + "2"}
}

// loginShells are the shells an undo may put back. A plan cannot name
// another, and Pin ties the one it names to the account's shell now.
var loginShells = []string{
	"/bin/bash", "/usr/bin/bash", "/bin/sh", "/usr/bin/sh", "/bin/dash", "/usr/bin/dash",
	"/bin/zsh", "/usr/bin/zsh", "/usr/bin/fish", "/bin/ksh", "/usr/bin/ksh", "/bin/tcsh", "/usr/bin/tcsh",
}

// validShell accepts a shell an undo may hand to usermod --shell.
func validShell(sh string) bool { return slices.Contains(loginShells, sh) }

func lockStep(ts []lockTarget, u *facts.Users) *Step {
	cmds, undo := lockCommands(ts)
	s := &Step{Restarts: []string{}}
	var names []string
	for _, t := range ts {
		names = append(names, t.name)
		s.Touches = append(s.Touches, "account:"+t.name)
		if len(t.keyFiles) > 0 {
			s.Touches = append(s.Touches, "authorized-keys:"+t.name)
		}
	}
	for _, c := range cmds {
		s.Commands = append(s.Commands, cmd(lockWhy(c), c...))
	}
	for _, c := range undo {
		s.Undo.Commands = append(s.Undo.Commands, cmd("undo: "+lockWhy(c), c...))
	}
	s.Undo.Description = "Move the authorized keys files back, unlock the password if the step locked it, and put the old shell back."
	s.Notes = []string{
		"Apply it from an SSH session of the admin account that stays (logged in with its key): the lockout guard refuses it from any other session, and from the account it locks.",
		"Running sessions of " + strings.Join(names, ", ") + " stay open; new logins are refused.",
	}
	nopasswd := nopasswdOf(u)
	for _, n := range names {
		if nopasswd[n] {
			s.Notes = append(s.Notes, n+" keeps its NOPASSWD sudo line: taking sudo away is on the never touched list. Nobody can log in as "+n+" to use it, but USR-003 keeps naming it until you remove the line by hand.")
		}
	}
	return s
}

func lockWhy(c []string) string {
	switch {
	case c[0] == "mv":
		return "move the authorized keys aside, so no key logs in"
	case c[1] == "--lock":
		return "lock the password"
	case c[1] == "--unlock":
		return "unlock the password"
	case c[2] == nologinShell:
		return "refuse a login shell"
	}
	return "put the old shell back"
}

// nopasswdOf lists the accounts named on a NOPASSWD sudoers line.
func nopasswdOf(u *facts.Users) map[string]bool {
	out := map[string]bool{}
	for _, s := range u.Sudoers {
		for _, r := range s.NoPasswd {
			for _, w := range strings.Split(r.Who, ",") {
				out[strings.TrimSpace(w)] = true
			}
		}
	}
	return out
}

// lockTargets reads the targets back from the commands and undo of s.
// Authorize renders them again and compares, so this only has to be
// lenient enough to find the names and the old shells.
func lockTargets(s Step) ([]lockTarget, error) {
	var ts []lockTarget
	idx := map[string]int{}
	get := func(name string) (*lockTarget, error) {
		if !slices.Contains(facts.DefaultCloudUsers, name) {
			return nil, fmt.Errorf("%q is not a cloud image's default account; the step locks only %s", name, strings.Join(facts.DefaultCloudUsers, ", "))
		}
		if i, ok := idx[name]; ok {
			return &ts[i], nil
		}
		idx[name] = len(ts)
		ts = append(ts, lockTarget{name: name})
		return &ts[len(ts)-1], nil
	}
	for _, c := range s.Commands {
		a := c.Args
		switch {
		case len(a) == 4 && a[0] == "usermod" && a[1] == "--shell" && a[2] == nologinShell:
			t, err := get(a[3])
			if err != nil {
				return nil, err
			}
			t.shell = undoShell(s, a[3])
		case len(a) == 3 && a[0] == "usermod" && a[1] == "--lock":
			t, err := get(a[2])
			if err != nil {
				return nil, err
			}
			t.lock = true
		case len(a) == 4 && a[0] == "mv" && a[1] == "-T":
			name := keyFileOwner(a[2])
			t, err := get(name)
			if err != nil {
				return nil, err
			}
			t.keyFiles = append(t.keyFiles, a[2])
		default:
			return nil, fmt.Errorf("command %q is not one the step runs", strings.Join(a, " "))
		}
	}
	return ts, nil
}

// undoShell finds the shell the undo puts back for name.
func undoShell(s Step, name string) string {
	for _, c := range s.Undo.Commands {
		a := c.Args
		if len(a) == 4 && a[0] == "usermod" && a[1] == "--shell" && a[3] == name {
			return a[2]
		}
	}
	return ""
}

// keyFileOwner returns the account of /home/NAME/.ssh/authorized_keys{,2}.
func keyFileOwner(p string) string {
	rest, ok := strings.CutPrefix(p, homeRoot+"/")
	if !ok {
		return ""
	}
	name, _, _ := strings.Cut(rest, "/")
	if !slices.Contains(lockableKeyFiles(name), p) {
		return ""
	}
	return name
}

func authorizeLockDefault(s Step) error {
	if len(s.Edits) != 0 {
		return fmt.Errorf("edits %d files, the step edits none", len(s.Edits))
	}
	ts, err := lockTargets(s)
	if err != nil {
		return err
	}
	if len(ts) == 0 {
		return errors.New("the step locks no account")
	}
	for _, t := range ts {
		if t.shell == "" && slices.ContainsFunc(s.Commands, func(c Command) bool { return len(c.Args) == 4 && c.Args[1] == "--shell" && c.Args[3] == t.name }) {
			return fmt.Errorf("the undo does not put the shell of %s back", t.name)
		}
		if t.shell != "" && !validShell(t.shell) {
			return fmt.Errorf("the undo would set the shell of %s to %q, which is not a login shell the step puts back", t.name, t.shell)
		}
	}
	cmds, undo := lockCommands(ts)
	if err := wantRestarts(s); err != nil {
		return err
	}
	if err := wantCommands("commands", s.Commands, cmds...); err != nil {
		return err
	}
	return wantCommands("undo", s.Undo.Commands, undo...)
}

func accessLockDefault(s Step) Access {
	a := Access{ApplierStays: true}
	ts, err := lockTargets(s)
	if err != nil {
		// A step that does not parse is refused by Authorize; for the
		// guard it disables every default account.
		return Access{ApplierStays: true, Disables: append([]string{}, facts.DefaultCloudUsers...), RemovesKeys: append([]string{}, facts.DefaultCloudUsers...)}
	}
	for _, t := range ts {
		a.Disables = append(a.Disables, t.name)
		if len(t.keyFiles) > 0 {
			a.RemovesKeys = append(a.RemovesKeys, t.name)
		}
	}
	return a
}

// pinLockDefault ties the plan to the host as it is now: the shell the
// undo restores is the account's shell now, and every keys file is still
// in place with nothing at the name it is moved to. A host that is half
// locked (an earlier run that failed) is refused.
func pinLockDefault(r Reader, s Step) error {
	ts, err := lockTargets(s)
	if err != nil {
		return err
	}
	for _, t := range ts {
		acc, err := passwdEntry(r, t.name)
		if err != nil {
			return err
		}
		if acc == nil {
			return fmt.Errorf("the account %s no longer exists; plan again", t.name)
		}
		if t.shell != "" && acc.Shell != t.shell {
			return fmt.Errorf("the shell of %s is %q now, the plan restores %q; plan again", t.name, acc.Shell, t.shell)
		}
		for _, f := range t.keyFiles {
			if _, err := r.ReadFile(f); err != nil {
				return fmt.Errorf("%s: %w; plan again", f, err)
			}
			if _, err := r.ReadFile(f + lockedSuffix); !errors.Is(err, fs.ErrNotExist) {
				return fmt.Errorf("%s exists already (an earlier run?); move it away by hand, then plan again", f+lockedSuffix)
			}
		}
	}
	return nil
}

// checkLockDefault: applied when every account's shell is nologin (where
// the step changes it) and every keys file sits at its locked name.
func checkLockDefault(r Reader, s Step) (bool, string, error) {
	ts, err := lockTargets(s)
	if err != nil {
		return false, "", err
	}
	for _, t := range ts {
		if t.shell != "" {
			acc, err := passwdEntry(r, t.name)
			if err != nil || acc == nil || acc.Shell != nologinShell {
				return false, "", err
			}
		}
		for _, f := range t.keyFiles {
			if _, err := r.ReadFile(f); !errors.Is(err, fs.ErrNotExist) {
				return false, "", nil
			}
			if _, err := r.ReadFile(f + lockedSuffix); err != nil {
				return false, "", nil
			}
		}
	}
	return true, "the default accounts are already locked", nil
}
