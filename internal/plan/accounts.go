package plan

import (
	"errors"
	"fmt"
	"io/fs"
	"regexp"
	"slices"
	"strings"

	"github.com/Shironex/stackward/internal/facts"
)

// admin-user and paas-user: create an account with NOPASSWD sudo through
// its own sudoers drop-in. The admin account gets the authorized keys of
// an existing account, copied on the host, so no key ever passes through
// the plan, the journal or the screen. The PaaS account gets an empty
// ~/.ssh for the platform's key. Neither ever gets a password: useradd
// leaves the password locked, and nothing sets or prints one.
//
// Both are access-critical, so they run inside the transaction: the owner
// proves the admin account by logging in as it, in a new SSH session,
// and confirming from there. Their undo deletes the account they created
// (userdel --remove), which is why apply refuses them when the account,
// its group or its home already exists.

// AccountChoices are the owner's choices for the account steps. Empty
// fields plan nothing.
type AccountChoices struct {
	// Admin is the admin account to create (--admin-user).
	Admin string
	// AdminKeysFrom is the existing account whose authorized_keys the
	// admin account gets (--admin-keys-from).
	AdminKeysFrom string
	// PaaS is the account the platform logs in as (--paas-user).
	PaaS string
}

// Step ids of the account steps.
const (
	AdminUserID       = "admin-user"
	PaaSUserID        = "paas-user"
	LockDefaultUserID = "lock-default-user"
	SSHDHardeningID   = "sshd-hardening"
)

// Order of the account steps among access-critical steps: create the
// accounts, harden sshd, and lock the default account last.
const (
	orderAdminUser = 10 + iota*10
	orderPaaSUser
	orderSSHDHardening
	orderLockDefault
)

var accountName = regexp.MustCompile(`^[a-z][a-z0-9_-]{0,30}$`)

// ValidAccountName refuses a name stackward would not create or copy keys
// from: not a plain lower case login name, root, or a cloud image's
// default account (those are what the lock step locks).
func ValidAccountName(name string) error {
	switch {
	case !accountName.MatchString(name):
		return fmt.Errorf("%q is not a plain login name (a lower case letter, then up to 30 lower case letters, digits, _ or -)", name)
	case name == "root":
		return errors.New("root is not an account to create or copy keys from")
	}
	return nil
}

// validNewAccount is ValidAccountName plus the cloud default names, which
// the lock step would lock again.
func validNewAccount(name string) error {
	if err := ValidAccountName(name); err != nil {
		return err
	}
	if slices.Contains(facts.DefaultCloudUsers, name) {
		return fmt.Errorf("%s is a cloud image's default account name, which lock-default-user locks; choose another", name)
	}
	return nil
}

const (
	passwdFile = "/etc/passwd"
	groupFile  = "/etc/group"
	homeRoot   = "/home"
	sshShell   = "/bin/bash"
)

// sudoersDropin is the sudoers drop-in of account name. sudo skips files
// in /etc/sudoers.d whose name holds a dot, so the staged copy apply
// validates (".NAME.stackward-*") is never read as a rule.
func sudoersDropin(name string) string { return "/etc/sudoers.d/90-stackward-" + name }

func homeOf(name string) string { return homeRoot + "/" + name }

func keysFile(name string) string { return homeOf(name) + "/.ssh/authorized_keys" }

// visudoCheck validates the staged sudoers drop-in.
var visudoCheck = []string{"visudo", "-c", "-f"}

// accountSpec is one account step: the admin or the PaaS account.
type accountSpec struct {
	id, name string
	// keysFrom is the account whose authorized_keys are copied; "" for
	// the PaaS account, which gets an empty ~/.ssh.
	keysFrom string
}

func (a accountSpec) sudoers() string {
	what := "the admin account"
	if a.id == PaaSUserID {
		what = "the account the platform (Coolify, Dokploy) logs in as"
	}
	return fmt.Sprintf("# Written by stackward: plan step %s, %s.\n", a.id, what) +
		"# NOPASSWD because the account has no password; stackward never sets one.\n" +
		"# Remove this file to take the rights away.\n" +
		a.name + " ALL=(ALL:ALL) NOPASSWD: ALL\n"
}

func (a accountSpec) commands() [][]string {
	out := [][]string{
		{"useradd", "--create-home", "--home-dir", homeOf(a.name), "--user-group", "--shell", sshShell, a.name},
		{"install", "-d", "-m", "0700", "-o", a.name, "-g", a.name, homeOf(a.name) + "/.ssh"},
	}
	if a.keysFrom != "" {
		out = append(out, []string{"install", "-m", "0600", "-o", a.name, "-g", a.name, keysFile(a.keysFrom), keysFile(a.name)})
	}
	return out
}

func (a accountSpec) undo() [][]string {
	return [][]string{
		{"rm", "-f", sudoersDropin(a.name)},
		{"userdel", "--remove", a.name},
	}
}

// step renders the whole step from the spec. Authorize renders it again
// from the names a plan holds and compares.
func (a accountSpec) step(notes []string) *Step {
	why := []string{
		"create the account with a home and its own group; its password stays locked",
		"create ~/.ssh, owned by the account, mode 0700",
		"copy the authorized keys of " + a.keysFrom + " on the host, so no key passes through the plan",
	}
	s := &Step{
		Restarts: []string{},
		Touches:  []string{"account:" + a.name, "file:" + sudoersDropin(a.name), "file:" + homeOf(a.name)},
		Edits:    []FileEdit{newEdit(sudoersDropin(a.name), Create, "0440", "", a.sudoers())},
		Undo: Undo{
			Description: fmt.Sprintf("Remove the sudoers drop-in and delete the account %s with its home and group (userdel --remove). Anything saved in that home is deleted with it.", a.name),
		},
		Notes: notes,
	}
	s.Edits[0].Validate = append([]string{}, visudoCheck...)
	if a.keysFrom != "" {
		s.Touches = append(s.Touches, "authorized-keys:"+a.name)
	}
	for i, c := range a.commands() {
		s.Commands = append(s.Commands, cmd(why[i], c...))
	}
	for i, c := range a.undo() {
		s.Undo.Commands = append(s.Undo.Commands, cmd([]string{"remove the sudoers drop-in", "delete the account, its home and its group"}[i], c...))
	}
	return s
}

func init() {
	Register(Generator{
		ID:    AdminUserID,
		Title: "Create an admin account with sudo and the keys of an existing account",
		Fixes: []string{"SSH-003", "USR-003"},
		Risk:  AccessCritical,
		Order: orderAdminUser,
		Plan:  planAdminUser,

		Authorize: func(s Step) error { return authorizeAccount(AdminUserID, s) },
		Pin:       pinAccount,
		Check:     checkAccount,
		Access:    func(Step) Access { return Access{} },
	})
	Register(Generator{
		ID:    PaaSUserID,
		Title: "Create a separate account for the platform to log in as instead of root",
		Fixes: []string{"SSH-003"},
		Risk:  AccessCritical,
		Order: orderPaaSUser,
		Plan:  planPaaSUser,

		Authorize: func(s Step) error { return authorizeAccount(PaaSUserID, s) },
		Pin:       pinAccount,
		Check:     checkAccount,
		Access:    func(Step) Access { return Access{} },
	})
}

// accountFacts returns the users and SSH facts, or the skip when they are
// missing.
func accountFacts(in Input) (*facts.Users, *facts.SSH, *Outcome) {
	switch {
	case in.Facts == nil:
		o := Skip(SkipUnknown, "there are no facts (planning from a report alone)")
		return nil, nil, &o
	case in.Facts.Users == nil:
		o := Skip(SkipUnknown, "the accounts were not audited")
		return nil, nil, &o
	case in.Facts.SSH == nil:
		o := Skip(SkipUnknown, "sshd was not audited")
		return nil, nil, &o
	case len(in.Facts.Users.Sudoers) == 0:
		o := Skip(SkipManual, "sudo is not installed (no /etc/sudoers); install it first")
		return nil, nil, &o
	}
	return in.Facts.Users, in.Facts.SSH, nil
}

// newAccountClash says why name cannot be created on this host, or "".
func newAccountClash(u *facts.Users, name string) string {
	if err := validNewAccount(name); err != nil {
		return err.Error()
	}
	for _, a := range u.Accounts {
		if a.Name == name {
			return fmt.Sprintf("the account %s already exists; stackward only creates new accounts, so its undo never deletes one it did not create", name)
		}
	}
	for _, g := range u.Groups {
		if g.Name == name {
			return fmt.Sprintf("a group named %s already exists; useradd --user-group would fail", name)
		}
	}
	return ""
}

func planAdminUser(in Input) Outcome {
	u, s, skip := accountFacts(in)
	if skip != nil {
		return *skip
	}
	ch := in.Accounts
	if ch.Admin == "" {
		if names := otherAdmins(u, s); len(names) > 0 {
			return Skip(SkipPassing, "an admin account besides root and the cloud default exists (%s)", strings.Join(names, ", "))
		}
		return Skip(SkipManual, "no admin account exists besides root and the cloud default; name one with stackward plan --admin-user NAME --admin-keys-from USER (USER is the account whose authorized keys it gets)")
	}
	if why := newAccountClash(u, ch.Admin); why != "" {
		return Skip(SkipManual, "%s", why)
	}
	if ch.AdminKeysFrom == "" {
		return Skip(SkipManual, "name the account whose authorized keys %s gets with --admin-keys-from USER; stackward never invents a key", ch.Admin)
	}
	if why := keySource(u, s, ch.AdminKeysFrom); why != "" {
		return Skip(SkipManual, "%s", why)
	}
	a := accountSpec{id: AdminUserID, name: ch.Admin, keysFrom: ch.AdminKeysFrom}
	return Outcome{Step: a.step([]string{
		fmt.Sprintf("%s gets sudo without a password (NOPASSWD), like the cloud image's default account; USR-004 lists it. Set a password and drop NOPASSWD later if you prefer.", a.name),
		fmt.Sprintf("Prove it before you confirm: open a new SSH session as %s with the key of %s and run sudo stackward confirm from there.", a.name, a.keysFrom),
		"lock-default-user is planned once a session of this account applies it.",
	})}
}

// keySource says why account name cannot give its authorized keys, or "".
func keySource(u *facts.Users, s *facts.SSH, name string) string {
	if err := ValidAccountName(name); err != nil {
		return err.Error()
	}
	var acc *facts.Account
	for i := range u.Accounts {
		if u.Accounts[i].Name == name {
			acc = &u.Accounts[i]
		}
	}
	switch {
	case acc == nil:
		return fmt.Sprintf("there is no account %s to copy authorized keys from", name)
	case acc.UID == 0:
		return fmt.Sprintf("%s has uid 0; stackward does not copy root's keys", name)
	case acc.Home != homeOf(name):
		return fmt.Sprintf("the home of %s is %s, not %s; copy the keys by hand", name, acc.Home, homeOf(name))
	}
	if s.UsersError != "" {
		return "the authorized keys could not be read: " + s.UsersError
	}
	for _, kf := range keysOf(s, name) {
		if kf.Path == keysFile(name) && kf.Error == "" {
			if usableKeys(kf) == 0 {
				return fmt.Sprintf("%s holds no key current OpenSSH accepts", kf.Path)
			}
			return ""
		}
	}
	return fmt.Sprintf("%s has no readable %s to copy (run the audit as root)", name, keysFile(name))
}

// otherAdmins lists the accounts that are not root or a cloud default and
// have sudo and a usable key.
func otherAdmins(u *facts.Users, s *facts.SSH) []string {
	var out []string
	for _, acc := range u.Accounts {
		if acc.UID == 0 || !acc.LoginShell || slices.Contains(facts.DefaultCloudUsers, acc.Name) {
			continue
		}
		a := account{Account: acc, groups: u.GroupsOf(acc), keys: keysOf(s, acc.Name)}
		if lacking(u, a, change{}) == "" {
			out = append(out, acc.Name)
		}
	}
	return out
}

func planPaaSUser(in Input) Outcome {
	u, _, skip := accountFacts(in)
	if skip != nil {
		return *skip
	}
	p := in.Facts.PaaS
	if p == nil {
		return Skip(SkipUnknown, "the platform facts are missing (the paas collector did not run)")
	}
	if len(p.Platforms) == 0 {
		return Skip(SkipPassing, "no platform (Coolify, Dokploy) was found; a PaaS account is only for one")
	}
	name := in.Accounts.PaaS
	if name == "" {
		return Skip(SkipManual, "the platform logs in as root unless it has its own account; name one with stackward plan --paas-user NAME")
	}
	if name == in.Accounts.Admin {
		return Skip(SkipManual, "the PaaS account must not be the admin account (%s)", name)
	}
	if why := newAccountClash(u, name); why != "" {
		return Skip(SkipManual, "%s", why)
	}
	a := accountSpec{id: PaaSUserID, name: name}
	return Outcome{Step: a.step([]string{
		fmt.Sprintf("%s gets sudo without a password (NOPASSWD): the platform needs it to run Docker and write its files. USR-004 lists it as expected for a PaaS account.", name),
		fmt.Sprintf("No key is added: put the platform's public key (shown in its panel) into %s, then switch the server's user in the platform to %s.", keysFile(name), name),
		"Root login stays as it is until the platform logs in as this account; sshd-hardening leaves PermitRootLogin alone on a platform host.",
	})}
}

var adminKeySource = regexp.MustCompile(`^/home/([a-z][a-z0-9_-]{0,30})/\.ssh/authorized_keys$`)

// authorizeAccount re-derives an account step from the names it holds:
// the account from its sudoers drop-in, the key source from the copy
// command. Everything else must be exactly what the step renders.
func authorizeAccount(id string, s Step) error {
	if len(s.Edits) != 1 {
		return fmt.Errorf("edits %d files, the step only ever creates one sudoers drop-in", len(s.Edits))
	}
	e := s.Edits[0]
	name, ok := strings.CutPrefix(e.Path, "/etc/sudoers.d/90-stackward-")
	if !ok {
		return fmt.Errorf("edits %s, the step only ever creates /etc/sudoers.d/90-stackward-NAME", e.Path)
	}
	if err := validNewAccount(name); err != nil {
		return fmt.Errorf("%s: %w", e.Path, err)
	}
	a := accountSpec{id: id, name: name}
	if id == AdminUserID {
		if len(s.Commands) != 3 || len(s.Commands[2].Args) != 9 {
			return errors.New("commands are not the ones the step runs: the admin account step creates the account, its ~/.ssh and copies one authorized_keys file")
		}
		m := adminKeySource.FindStringSubmatch(s.Commands[2].Args[7])
		if m == nil {
			return fmt.Errorf("the keys are copied from %q, the step copies only /home/USER/.ssh/authorized_keys", s.Commands[2].Args[7])
		}
		if err := ValidAccountName(m[1]); err != nil || m[1] == name {
			return fmt.Errorf("the keys are copied from %s, which is not an account the step copies keys from", m[1])
		}
		a.keysFrom = m[1]
	}
	if e.Action != Create || e.Mode != "0440" {
		return fmt.Errorf("%s: the step creates it with mode 0440 (action %q, mode %q)", e.Path, e.Action, e.Mode)
	}
	if err := wantContent(e, a.sudoers()); err != nil {
		return err
	}
	if err := wantValidate(e, visudoCheck); err != nil {
		return err
	}
	if err := wantRestarts(s); err != nil {
		return err
	}
	if err := wantCommands("commands", s.Commands, a.commands()...); err != nil {
		return err
	}
	return wantCommands("undo", s.Undo.Commands, a.undo()...)
}

// specOf reads the account and the key source back from an authorized
// step.
func specOf(s Step) accountSpec {
	name := strings.TrimPrefix(s.Edits[0].Path, "/etc/sudoers.d/90-stackward-")
	a := accountSpec{id: s.ID, name: name}
	if s.ID == AdminUserID && len(s.Commands) == 3 {
		if m := adminKeySource.FindStringSubmatch(s.Commands[2].Args[7]); m != nil {
			a.keysFrom = m[1]
		}
	}
	return a
}

// checkAccount: applied when the account exists, its drop-in holds the
// planned rules and, for the admin account, its authorized_keys is there.
func checkAccount(r Reader, s Step) (bool, string, error) {
	a := specOf(s)
	exists, err := passwdHas(r, a.name)
	if err != nil || !exists {
		return false, "", err
	}
	ok, err := FileHolds(r, sudoersDropin(a.name), s.Edits[0].NewSHA256)
	if err != nil || !ok {
		return false, "", err
	}
	if a.keysFrom != "" {
		b, err := r.ReadFile(keysFile(a.name))
		if errors.Is(err, fs.ErrNotExist) || (err == nil && len(b) == 0) {
			return false, "", nil
		}
		if err != nil {
			return false, "", err
		}
	}
	return true, fmt.Sprintf("the account %s exists with its sudoers drop-in", a.name), nil
}

// pinAccount refuses to create an account whose name, group or home is
// already taken on the host: the undo would delete what it did not
// create. For the admin account the key source must hold keys now.
func pinAccount(r Reader, s Step) error {
	a := specOf(s)
	if exists, err := passwdHas(r, a.name); err != nil || exists {
		return orErr(err, fmt.Errorf("the account %s exists now (or exists in part from an earlier run); stackward only creates new accounts; plan again", a.name))
	}
	gb, err := r.ReadFile(groupFile)
	if err != nil {
		return err
	}
	for _, g := range facts.ParseGroup(gb) {
		if g.Name == a.name {
			return fmt.Errorf("a group named %s exists now; plan again with another name", a.name)
		}
	}
	if _, err := r.ReadFile(homeOf(a.name)); !errors.Is(err, fs.ErrNotExist) {
		return fmt.Errorf("%s exists now; its undo would delete it, so stackward refuses to create %s over it", homeOf(a.name), a.name)
	}
	if a.keysFrom != "" {
		b, err := r.ReadFile(keysFile(a.keysFrom))
		if err != nil {
			return fmt.Errorf("the keys to copy, %s: %w", keysFile(a.keysFrom), err)
		}
		if len(strings.TrimSpace(string(b))) == 0 {
			return fmt.Errorf("%s is empty now; there is no key to copy", keysFile(a.keysFrom))
		}
	}
	return nil
}

// passwdHas reports whether /etc/passwd has account name.
func passwdHas(r Reader, name string) (bool, error) {
	acc, err := passwdEntry(r, name)
	return acc != nil, err
}

// passwdEntry returns the /etc/passwd entry of name, nil when absent.
func passwdEntry(r Reader, name string) (*facts.Account, error) {
	b, err := r.ReadFile(passwdFile)
	if err != nil {
		return nil, err
	}
	for _, a := range facts.ParsePasswd(b) {
		if a.Name == name {
			return &a, nil
		}
	}
	return nil, nil
}

func orErr(err, otherwise error) error {
	if err != nil {
		return err
	}
	return otherwise
}
