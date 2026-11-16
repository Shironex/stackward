package checks

import (
	"fmt"
	"strings"
	"time"

	"github.com/Shironex/stackward/internal/facts"
	"github.com/Shironex/stackward/internal/sudoersdrop"
)

// USR checks read what the users collector gathers (facts/users.go).

// unusedLogin is how long a login account may go unseen before USR-006 warns.
const unusedLogin = 90 * 24 * time.Hour

// adminGroups are the groups that grant sudo by default on Debian family
// and RHEL family systems.
var adminGroups = []string{"sudo", "admin", "wheel"}

func init() {
	Register(Check{ID: "USR-001", Run: checkExtraUID0})
	Register(Check{ID: "USR-002", Run: checkEmptyPassword})
	Register(Check{ID: "USR-003", Run: checkDefaultCloudUsers})
	Register(Check{ID: "USR-004", Run: checkSudoers})
	Register(Check{ID: "USR-005", Run: checkDockerGroup})
	Register(Check{ID: "USR-006", Run: checkStaleLogins})
	Register(Check{ID: "USR-007", Run: checkRootPassword})
}

func userSubject(name string) string { return "user:" + name }

func checkExtraUID0(in Input) []Result {
	u := in.Facts.Users
	if u == nil {
		return []Result{NotInspected(in.Facts, "users")}
	}
	var out []Result
	for _, a := range u.Accounts {
		if a.UID == 0 && a.Name != "root" {
			out = append(out, Result{Subject: userSubject(a.Name), Level: Fail,
				Message:  fmt.Sprintf("account %s has uid 0 (root equivalent)", a.Name),
				Evidence: map[string]any{"uid": 0, "shell": a.Shell}})
		}
	}
	if len(out) == 0 {
		return One(Pass, "root is the only account with uid 0", map[string]any{"accounts": len(u.Accounts)})
	}
	return out
}

func checkEmptyPassword(in Input) []Result {
	u := in.Facts.Users
	if u == nil {
		return []Result{NotInspected(in.Facts, "users")}
	}
	if !u.PasswordStatusChecked {
		return One(Unknown, "password status needs root (read with `passwd -S -a`, which never prints hashes); run with sudo", map[string]any{"checked": false})
	}
	var out []Result
	for _, a := range u.Accounts {
		if a.LoginShell && a.PasswordStatus == "NP" {
			out = append(out, Result{Subject: userSubject(a.Name), Level: Fail,
				Message:  fmt.Sprintf("login account %s has an empty password", a.Name),
				Evidence: map[string]any{"status": a.PasswordStatus, "shell": a.Shell}})
		}
	}
	if len(out) == 0 {
		return One(Pass, "no login account has an empty password", map[string]any{"checked": true})
	}
	return out
}

func checkDefaultCloudUsers(in Input) []Result {
	u := in.Facts.Users
	if u == nil {
		return []Result{NotInspected(in.Facts, "users")}
	}
	var defaults []facts.Account
	for _, a := range u.Accounts {
		if contains(facts.DefaultCloudUsers, a.Name) {
			defaults = append(defaults, a)
		}
	}
	if len(defaults) == 0 {
		return One(Pass, "no default cloud account (ubuntu, debian, admin, ec2-user) exists", map[string]any{"default_users": []string{}})
	}
	nopasswd := nopasswdPrincipals(u)
	other, known := otherAdminExists(u)
	var out []Result
	for _, d := range defaults {
		var why []string
		if d.LoginShell {
			why = append(why, "login shell")
		}
		if d.AuthorizedKeys != nil && *d.AuthorizedKeys {
			why = append(why, "authorized key")
		}
		if hasNopasswd(u, d, nopasswd) {
			why = append(why, "NOPASSWD sudo")
		}
		ev := map[string]any{"reasons": why, "other_admin": other}
		switch {
		case len(why) == 0:
			out = append(out, Result{Subject: userSubject(d.Name), Level: Pass,
				Message: fmt.Sprintf("default account %s is locked down", d.Name), Evidence: ev})
		case other:
			out = append(out, Result{Subject: userSubject(d.Name), Level: Warn,
				Message:  fmt.Sprintf("default account %s is still usable (%s) and another admin exists", d.Name, strings.Join(why, ", ")),
				Evidence: ev})
		case !known:
			out = append(out, Result{Subject: userSubject(d.Name), Level: Unknown,
				Message:  fmt.Sprintf("default account %s is usable (%s); sudoers needs root to tell whether another admin exists", d.Name, strings.Join(why, ", ")),
				Evidence: ev})
		default:
			out = append(out, Result{Subject: userSubject(d.Name), Level: Pass,
				Message:  fmt.Sprintf("default account %s is the only admin; locking it would remove your way in", d.Name),
				Evidence: ev})
		}
	}
	return out
}

// nopasswdPrincipals lists the principals with a NOPASSWD user spec.
func nopasswdPrincipals(u *facts.Users) map[string]bool {
	out := map[string]bool{}
	for _, s := range u.Sudoers {
		for _, r := range s.NoPasswd {
			for _, w := range strings.Split(r.Who, ",") {
				out[w] = true
			}
		}
	}
	return out
}

func hasNopasswd(u *facts.Users, a facts.Account, nopasswd map[string]bool) bool {
	if nopasswd[a.Name] {
		return true
	}
	for _, g := range u.GroupsOf(a) {
		if nopasswd["%"+g] {
			return true
		}
	}
	return false
}

// otherAdminExists reports whether an account outside the cloud defaults
// can administer the host (admin group member or sudoers principal). known
// is false when the answer could be a no only because sudoers was unreadable.
func otherAdminExists(u *facts.Users) (found, known bool) {
	principals := map[string]bool{}
	known = true
	for _, s := range u.Sudoers {
		if !s.Readable {
			known = false
		}
		for _, p := range s.Principals {
			principals[p] = true
		}
	}
	for _, a := range u.Accounts {
		if a.UID == 0 || contains(facts.DefaultCloudUsers, a.Name) || !a.LoginShell || a.UID < 1000 {
			continue
		}
		if principals[a.Name] {
			return true, true
		}
		for _, g := range u.GroupsOf(a) {
			if contains(adminGroups, g) || principals["%"+g] {
				return true, true
			}
		}
	}
	return false, known
}

func contains(list []string, s string) bool {
	for _, v := range list {
		if v == s {
			return true
		}
	}
	return false
}

func checkSudoers(in Input) []Result {
	u := in.Facts.Users
	if u == nil {
		return []Result{NotInspected(in.Facts, "users")}
	}
	if len(u.Sudoers) == 0 {
		return One(Skip, "no /etc/sudoers: sudo is not installed", map[string]any{"files": 0, "unreadable": 0})
	}
	var out []Result
	unreadable := 0
	for _, s := range u.Sudoers {
		if !s.Readable {
			unreadable++
		}
		if !s.NonRootWritable && len(s.NoPasswd) == 0 {
			continue
		}
		rules := make([]string, 0, len(s.NoPasswd))
		for _, r := range s.NoPasswd {
			rules = append(rules, fmt.Sprintf("%s (line %d)", r.Who, r.Line))
		}
		ev := map[string]any{"perm": fmt.Sprintf("%04o", s.Perm), "uid": s.UID, "gid": s.GID, "nopasswd": rules}
		switch {
		case s.NonRootWritable:
			out = append(out, Result{Subject: "file:" + s.Path, Level: Fail, Evidence: ev,
				Message: fmt.Sprintf("%s is writable by someone other than root (mode %04o, owner uid %d): that is a root escalation", s.Path, s.Perm, s.UID)})
		case ownDropinWriter(s) != "":
			name, _ := sudoersdrop.NameOf(s.Path)
			ev["written_by"] = ownDropinWriter(s)
			out = append(out, Result{Subject: "file:" + s.Path, Level: Info, Evidence: ev,
				Message: fmt.Sprintf("written by stackward %s for %s; passwordless sudo because the account has no password", ownDropinWriter(s), name)})
		default:
			out = append(out, Result{Subject: "file:" + s.Path, Level: Warn, Evidence: ev,
				Message: fmt.Sprintf("NOPASSWD sudo for %s: expected for a PaaS account, make sure it is deliberate", strings.Join(rules, ", "))})
		}
	}
	if len(out) > 0 {
		return out
	}
	ev := map[string]any{"files": len(u.Sudoers), "unreadable": unreadable}
	if unreadable > 0 {
		return One(Unknown, "sudoers contents need root to read; file permissions are fine, NOPASSWD entries could not be checked", ev)
	}
	return One(Pass, "sudoers files are root owned and not writable by others; no NOPASSWD entries", ev)
}

// ownDropinWriter is the plan step that wrote s, or "" when s is anything
// else. Only the exact drop-in a step renders counts: its path, root:root,
// the mode the step sets, and its content byte for byte, so an extra line,
// another account name or a loosened mode keeps the warning.
func ownDropinWriter(s facts.Sudoers) string {
	name, ok := sudoersdrop.NameOf(s.Path)
	if !ok || s.UID != 0 || s.GID != 0 || s.Perm != sudoersdrop.Perm || s.Content == "" {
		return ""
	}
	id, _ := sudoersdrop.Writer(name, s.Content)
	return id
}

func checkDockerGroup(in Input) []Result {
	u := in.Facts.Users
	if u == nil {
		return []Result{NotInspected(in.Facts, "users")}
	}
	hasGroup := false
	for _, g := range u.Groups {
		if g.Name == "docker" {
			hasGroup = true
		}
	}
	if !hasGroup {
		return One(Skip, "no docker group on this host", map[string]any{"group": "docker"})
	}
	var out []Result
	for _, a := range u.Accounts {
		if a.UID == 0 || !contains(u.GroupsOf(a), "docker") {
			continue
		}
		out = append(out, Result{Subject: userSubject(a.Name), Level: Warn,
			Message:  fmt.Sprintf("%s is in the docker group, which is root equivalent (it can mount the host filesystem)", a.Name),
			Evidence: map[string]any{"group": "docker"}})
	}
	if len(out) == 0 {
		return One(Pass, "no account besides root is in the docker group", map[string]any{"group": "docker"})
	}
	return out
}

func checkStaleLogins(in Input) []Result {
	f := in.Facts
	u := f.Users
	if u == nil {
		return []Result{NotInspected(f, "users")}
	}
	if !u.LastlogChecked {
		return One(Unknown, "last login times unavailable (lastlog missing or empty; newer systems use lastlog2)", map[string]any{"checked": false})
	}
	var out []Result
	considered := 0
	for _, a := range u.Accounts {
		if a.UID < 1000 || a.UID >= 65534 || !a.LoginShell || a.PasswordStatus == "L" {
			continue
		}
		if !a.NeverLoggedIn && a.LastLogin.IsZero() {
			continue // no usable lastlog line
		}
		considered++
		days := 0
		last := "never"
		if !a.NeverLoggedIn {
			if f.CollectedAt.Sub(a.LastLogin) < unusedLogin {
				continue
			}
			days = int(f.CollectedAt.Sub(a.LastLogin).Hours() / 24)
			last = a.LastLogin.UTC().Format(time.RFC3339)
		}
		msg := fmt.Sprintf("login account %s has not logged in for %d days", a.Name, days)
		if a.NeverLoggedIn {
			msg = fmt.Sprintf("login account %s has never logged in", a.Name)
		}
		out = append(out, Result{Subject: userSubject(a.Name), Level: Warn, Message: msg,
			Evidence: map[string]any{"last_login": last, "days": days}})
	}
	if len(out) == 0 {
		return One(Pass, "every login account was seen in the last 90 days", map[string]any{"accounts": considered})
	}
	return out
}

func checkRootPassword(in Input) []Result {
	u := in.Facts.Users
	if u == nil {
		return []Result{NotInspected(in.Facts, "users")}
	}
	var root *facts.Account
	for i := range u.Accounts {
		if u.Accounts[i].Name == "root" {
			root = &u.Accounts[i]
		}
	}
	if root == nil || !u.PasswordStatusChecked || root.PasswordStatus == "" {
		return One(Unknown, "root password status needs root (read with `passwd -S`); run with sudo", map[string]any{"status": ""})
	}
	ev := map[string]any{"status": root.PasswordStatus}
	switch root.PasswordStatus {
	case "L":
		return One(Info, "root password is locked: recovery is the provider console or rescue mode; note where that path is stored", ev)
	case "NP":
		return One(Info, "root has no password set (see USR-002); recovery is the provider console or rescue mode", ev)
	}
	return One(Info, "root has a password set; it works on the console and for su, keep it in a password manager", ev)
}
