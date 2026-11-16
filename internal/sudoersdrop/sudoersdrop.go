// Package sudoersdrop is the one description of the sudoers drop-in the
// admin-user and paas-user plan steps write. The plan renders it, and the
// USR-004 check recognises it again by rendering the same text, so the two
// cannot drift apart. It is pure: no host access.
package sudoersdrop

import (
	"fmt"
	"strings"
)

// Step ids of the steps that write the drop-in.
const (
	AdminUserID = "admin-user"
	PaaSUserID  = "paas-user"
)

// Mode is the permission string of the drop-in; Perm the same bits.
const (
	Mode        = "0440"
	Perm uint32 = 0o440
)

// prefix is the path of every drop-in, up to the account name. sudo skips
// files whose name holds a dot, so the staged copy apply validates
// (".NAME.stackward-*") is never read as a rule.
const prefix = "/etc/sudoers.d/90-stackward-"

// Path is the drop-in of account name.
func Path(name string) string { return prefix + name }

// NameOf is the account a drop-in path belongs to; false for any other path.
func NameOf(path string) (string, bool) {
	name, ok := strings.CutPrefix(path, prefix)
	return name, ok && name != ""
}

// Render is the exact content step stepID writes for account name.
func Render(stepID, name string) string {
	what := "the admin account"
	if stepID == PaaSUserID {
		what = "the account the platform (Coolify, Dokploy) logs in as"
	}
	return fmt.Sprintf("# Written by stackward: plan step %s, %s.\n", stepID, what) +
		"# NOPASSWD because the account has no password; stackward never sets one.\n" +
		"# Remove this file to take the rights away.\n" +
		name + " ALL=(ALL:ALL) NOPASSWD: ALL\n"
}

// Writer returns the id of the step whose rendering for name is content,
// or false when no step writes exactly that content.
func Writer(name, content string) (string, bool) {
	for _, id := range []string{AdminUserID, PaaSUserID} {
		if content == Render(id, name) {
			return id, true
		}
	}
	return "", false
}
