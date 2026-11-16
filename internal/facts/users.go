package facts

import (
	"bufio"
	"bytes"
	"context"
	"errors"
	"fmt"
	"io/fs"
	"path"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/Shironex/stackward/internal/sudoersdrop"
)

// Users is accounts, groups, sudoers and login state (USR group).
//
// What is never read: /etc/shadow. Empty and locked passwords come from
// `passwd -S -a` (root only), which prints a status letter per account and
// never the hash. sudoers is not secret and is read as root; without root
// its files are only stat-ed.
type Users struct {
	Accounts []Account `json:"accounts"`
	Groups   []Group   `json:"groups,omitempty"`
	Sudoers  []Sudoers `json:"sudoers,omitempty"`
	// PasswordStatusChecked is true when `passwd -S -a` ran (root only), so
	// Account.PasswordStatus is meaningful.
	PasswordStatusChecked bool `json:"password_status_checked"`
	// LastlogChecked is true when `lastlog` ran and parsed.
	LastlogChecked bool `json:"lastlog_checked"`
}

// Account is one /etc/passwd entry plus what is known about it.
type Account struct {
	Name  string `json:"name"`
	UID   int    `json:"uid"`
	GID   int    `json:"gid"`
	Home  string `json:"home,omitempty"`
	Shell string `json:"shell,omitempty"`
	// LoginShell is true when the shell is not nologin, false, sync, halt
	// or shutdown.
	LoginShell bool `json:"login_shell"`
	// PasswordStatus is the `passwd -S` letter: "P" usable password, "L"
	// locked, "NP" no password (empty hash). Empty when not checked.
	PasswordStatus string `json:"password_status,omitempty"`
	// LastLogin and NeverLoggedIn come from lastlog. Both unset means lastlog
	// had no usable line for the account.
	LastLogin     time.Time `json:"last_login,omitzero"`
	NeverLoggedIn bool      `json:"never_logged_in,omitempty"`
	// AuthorizedKeys says whether ~/.ssh/authorized_keys exists (stat only,
	// never read). Probed only for the usual cloud-init default accounts;
	// nil means not probed or not statable.
	AuthorizedKeys *bool `json:"authorized_keys,omitempty"`
}

// Group is one /etc/group entry.
type Group struct {
	Name    string   `json:"name"`
	GID     int      `json:"gid"`
	Members []string `json:"members,omitempty"`
}

// Sudoers is one sudoers file (/etc/sudoers or a file in /etc/sudoers.d).
type Sudoers struct {
	Path string `json:"path"`
	// Perm is the permission bits; UID and GID the owner.
	Perm uint32 `json:"perm"`
	UID  int    `json:"uid"`
	GID  int    `json:"gid"`
	// NonRootWritable is true when anyone but root can write the file:
	// owner is not root, or the group or other write bit is set.
	NonRootWritable bool `json:"non_root_writable"`
	// Readable is false when the contents could not be read (not root).
	Readable bool `json:"readable"`
	// NoPasswd lists the user specs carrying a NOPASSWD tag.
	NoPasswd []SudoRule `json:"nopasswd,omitempty"`
	// Principals lists every principal of a user spec line (users and
	// %groups), so checks can tell who else holds admin rights.
	Principals []string `json:"principals,omitempty"`
	// Content is the file text, kept only for stackward's own drop-ins
	// (/etc/sudoers.d/90-stackward-*) up to ownDropinMax bytes, so a check
	// can tell them from anyone else's. Never kept for other files.
	Content string `json:"content,omitempty"`
}

// SudoRule is one user spec line with NOPASSWD.
type SudoRule struct {
	Who  string `json:"who"`
	Line int    `json:"line"`
}

// GroupsOf returns the names of every group the account belongs to,
// primary group included, sorted.
func (u *Users) GroupsOf(a Account) []string {
	seen := map[string]bool{}
	for _, g := range u.Groups {
		if g.GID == a.GID {
			seen[g.Name] = true
		}
		for _, m := range g.Members {
			if m == a.Name {
				seen[g.Name] = true
			}
		}
	}
	out := make([]string, 0, len(seen))
	for n := range seen {
		out = append(out, n)
	}
	sort.Strings(out)
	return out
}

// DefaultCloudUsers are the accounts cloud images create for the first login.
var DefaultCloudUsers = []string{"ubuntu", "debian", "admin", "ec2-user"}

// Paths the users collector reads.
const (
	passwdPath     = "/etc/passwd"
	groupPath      = "/etc/group"
	sudoersPath    = "/etc/sudoers"
	sudoersDirPath = "/etc/sudoers.d"
)

var nonLoginShells = map[string]bool{
	"": true, "/usr/sbin/nologin": true, "/sbin/nologin": true, "/usr/bin/nologin": true,
	"/bin/false": true, "/usr/bin/false": true, "/bin/sync": true, "/sbin/halt": true, "/sbin/shutdown": true,
}

type usersCollector struct{}

func init() { Register(usersCollector{}) }

func (usersCollector) Name() string    { return "users" }
func (usersCollector) NeedsRoot() bool { return false }

func (usersCollector) Collect(ctx context.Context, sys System, out *Facts) error {
	b, err := sys.ReadFile(passwdPath)
	if err != nil {
		return fmt.Errorf("passwd: %w", err)
	}
	u := &Users{Accounts: ParsePasswd(b)}
	var errs []error

	if gb, err := sys.ReadFile(groupPath); err != nil {
		errs = append(errs, fmt.Errorf("group: %w", err))
	} else {
		u.Groups = ParseGroup(gb)
	}

	if sys.Identity().Root {
		// `passwd -S -a` reads /etc/shadow itself and prints only a status
		// letter per account: stackward never sees a hash.
		if res, err := sys.Run(ctx, "passwd", "-S", "-a"); err != nil || res.ExitCode != 0 {
			errs = append(errs, fmt.Errorf("passwd -S -a: %w", cmdErr(err, res)))
		} else {
			applyPasswordStatus(u, ParsePasswdStatus(res.Stdout))
		}
	}

	if res, err := sys.Run(ctx, "lastlog"); err == nil && res.ExitCode == 0 {
		if applyLastlog(u, ParseLastlog(res.Stdout)) {
			u.LastlogChecked = true
		}
	}

	probeAuthorizedKeys(sys, u)
	u.Sudoers = collectSudoers(sys)

	out.Users = u
	return errors.Join(errs...)
}

func cmdErr(err error, res CmdResult) error {
	if err != nil {
		return err
	}
	msg := strings.TrimSpace(string(res.Stderr))
	if len(msg) > 120 {
		msg = msg[:120]
	}
	return fmt.Errorf("exit %d %s", res.ExitCode, msg)
}

// ParsePasswd parses /etc/passwd.
func ParsePasswd(b []byte) []Account {
	var out []Account
	sc := bufio.NewScanner(bytes.NewReader(b))
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		f := strings.Split(line, ":")
		if len(f) < 7 || f[0] == "" {
			continue
		}
		uid, err1 := strconv.Atoi(f[2])
		gid, err2 := strconv.Atoi(f[3])
		if err1 != nil || err2 != nil {
			continue
		}
		out = append(out, Account{
			Name: f[0], UID: uid, GID: gid, Home: f[5], Shell: f[6],
			LoginShell: !nonLoginShells[f[6]],
		})
	}
	return out
}

// ParseGroup parses /etc/group.
func ParseGroup(b []byte) []Group {
	var out []Group
	sc := bufio.NewScanner(bytes.NewReader(b))
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		f := strings.Split(line, ":")
		if len(f) < 4 || f[0] == "" {
			continue
		}
		gid, err := strconv.Atoi(f[2])
		if err != nil {
			continue
		}
		g := Group{Name: f[0], GID: gid}
		for _, m := range strings.Split(f[3], ",") {
			if m = strings.TrimSpace(m); m != "" {
				g.Members = append(g.Members, m)
			}
		}
		out = append(out, g)
	}
	return out
}

// ParsePasswdStatus parses `passwd -S -a`: "name STATUS date min max warn
// inactive" per line. It returns name to status letter(s).
func ParsePasswdStatus(b []byte) map[string]string {
	out := map[string]string{}
	sc := bufio.NewScanner(bytes.NewReader(b))
	for sc.Scan() {
		f := strings.Fields(sc.Text())
		if len(f) >= 2 && (f[1] == "P" || f[1] == "L" || f[1] == "NP" || f[1] == "LK") {
			st := f[1]
			if st == "LK" {
				st = "L"
			}
			out[f[0]] = st
		}
	}
	return out
}

func applyPasswordStatus(u *Users, st map[string]string) {
	if len(st) == 0 {
		return
	}
	u.PasswordStatusChecked = true
	for i := range u.Accounts {
		u.Accounts[i].PasswordStatus = st[u.Accounts[i].Name]
	}
}

// LastlogEntry is one parsed lastlog line.
type LastlogEntry struct {
	Never bool
	At    time.Time
}

var lastlogDate = regexp.MustCompile(`[A-Z][a-z]{2} [A-Z][a-z]{2} +\d{1,2} \d{2}:\d{2}:\d{2} [+-]\d{4} \d{4}`)

// ParseLastlog parses the lastlog command output (C locale).
func ParseLastlog(b []byte) map[string]LastlogEntry {
	out := map[string]LastlogEntry{}
	sc := bufio.NewScanner(bytes.NewReader(b))
	for sc.Scan() {
		line := sc.Text()
		f := strings.Fields(line)
		if len(f) == 0 || f[0] == "Username" {
			continue
		}
		if strings.Contains(line, "**Never logged in**") {
			out[f[0]] = LastlogEntry{Never: true}
			continue
		}
		if d := lastlogDate.FindString(line); d != "" {
			if t, err := time.Parse("Mon Jan _2 15:04:05 -0700 2006", d); err == nil {
				out[f[0]] = LastlogEntry{At: t.UTC()}
			}
		}
	}
	return out
}

func applyLastlog(u *Users, ll map[string]LastlogEntry) bool {
	if len(ll) == 0 {
		return false
	}
	for i := range u.Accounts {
		if e, ok := ll[u.Accounts[i].Name]; ok {
			u.Accounts[i].NeverLoggedIn = e.Never
			u.Accounts[i].LastLogin = e.At
		}
	}
	return true
}

func probeAuthorizedKeys(sys System, u *Users) {
	for i := range u.Accounts {
		a := &u.Accounts[i]
		if !contains(DefaultCloudUsers, a.Name) || a.Home == "" {
			continue
		}
		_, err := sys.Meta(path.Join(a.Home, ".ssh", "authorized_keys"))
		switch {
		case err == nil:
			t := true
			a.AuthorizedKeys = &t
		case errors.Is(err, fs.ErrNotExist):
			f := false
			a.AuthorizedKeys = &f
		}
	}
}

func contains(list []string, s string) bool {
	for _, v := range list {
		if v == s {
			return true
		}
	}
	return false
}

// collectSudoers stats and reads /etc/sudoers and /etc/sudoers.d/*. sudo
// ignores include-dir files whose name contains a dot or ends in "~".
func collectSudoers(sys System) []Sudoers {
	paths := []string{sudoersPath}
	if entries, err := sys.ReadDir(sudoersDirPath); err == nil {
		for _, e := range entries {
			n := e.Name()
			if e.IsDir() || strings.Contains(n, ".") || strings.HasSuffix(n, "~") {
				continue
			}
			paths = append(paths, path.Join(sudoersDirPath, n))
		}
	}
	var out []Sudoers
	for _, p := range paths {
		m, err := sys.Meta(p)
		if err != nil {
			continue
		}
		s := Sudoers{
			Path: p, Perm: uint32(m.Mode.Perm()), UID: m.UID, GID: m.GID,
			NonRootWritable: (m.UID != 0 && m.UID != -1) || m.Mode.Perm()&0o022 != 0,
		}
		if b, err := sys.ReadFile(p); err == nil {
			s.Readable = true
			s.NoPasswd, s.Principals = ParseSudoers(b)
			if _, own := sudoersdrop.NameOf(p); own && len(b) <= ownDropinMax {
				s.Content = string(b)
			}
		}
		out = append(out, s)
	}
	return out
}

// ownDropinMax caps the content kept of a stackward drop-in; the step's
// file is a few hundred bytes.
const ownDropinMax = 2048

var nopasswdTag = regexp.MustCompile(`\bNOPASSWD\s*:`)

// ParseSudoers extracts, from a sudoers file, the user specs with NOPASSWD
// and every user spec principal. Defaults and alias lines are skipped.
func ParseSudoers(b []byte) (nopasswd []SudoRule, principals []string) {
	seen := map[string]bool{}
	lines := strings.Split(string(b), "\n")
	for i := 0; i < len(lines); i++ {
		start := i + 1
		line := strings.TrimSpace(lines[i])
		for strings.HasSuffix(line, "\\") && i+1 < len(lines) {
			i++
			line = strings.TrimSuffix(line, "\\") + " " + strings.TrimSpace(lines[i])
		}
		if line == "" || strings.HasPrefix(line, "#") || strings.HasPrefix(line, "@") {
			continue
		}
		who := strings.Fields(line)[0]
		if strings.HasPrefix(who, "Defaults") || strings.HasSuffix(who, "_Alias") {
			continue
		}
		for _, p := range strings.Split(who, ",") {
			if p = strings.TrimSpace(p); p != "" && !seen[p] {
				seen[p] = true
				principals = append(principals, p)
			}
		}
		if nopasswdTag.MatchString(line) {
			nopasswd = append(nopasswd, SudoRule{Who: who, Line: start})
		}
	}
	return nopasswd, principals
}
