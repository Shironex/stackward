package apply

import (
	"bytes"
	"os"
	"path/filepath"
	"strconv"
	"strings"
)

// Session is what tells one login session from another. The transaction
// records it for the session that applied, and `stackward confirm`
// compares it with its own: a confirm from the same session proves nothing
// about a fresh login, so it is refused.
//
// Every field is "" when it cannot be read. None of them can be trusted
// alone (see CompareSessions and docs/safety.md for the limits), which is
// why all of them are compared.
type Session struct {
	// SSHConnection is SSH_CONNECTION ("client port server port"): the
	// TCP connection of the session. A new connection has a new client
	// port. Read from the environment, or from the session's login shell
	// when sudo dropped it.
	SSHConnection string `json:"ssh_connection,omitempty"`
	// AuditSession is /proc/self/sessionid, the kernel audit session that
	// pam_loginuid opens at login. sudo and su keep it, so it names the
	// login, not the shell. "" when unset (4294967295).
	AuditSession string `json:"audit_session,omitempty"`
	// LoginUID is /proc/self/loginuid, the user who logged in. Recorded,
	// not compared: a second session of the same user is the normal case.
	LoginUID string `json:"login_uid,omitempty"`
	// XDGSession is XDG_SESSION_ID, the logind session.
	XDGSession string `json:"xdg_session,omitempty"`
	// SSHD is the per session sshd process this command descends from, as
	// "PID:START" (start time in clock ticks after boot, so a reused pid
	// does not match). "" when no sshd is an ancestor.
	SSHD string `json:"sshd,omitempty"`
}

// OverSSH reports whether the session came in over SSH.
func (s Session) OverSSH() bool { return s.SSHD != "" || s.SSHConnection != "" }

// unsetID is what the kernel shows for an audit session or login uid that
// was never set.
const unsetID = "4294967295"

// maxAncestors bounds the walk up the process tree.
const maxAncestors = 64

// ReadSession reads the session of process pid from procRoot ("/proc" on a
// real host; a directory laid out like /proc in tests). getenv is the
// process's own environment. It only reads.
func ReadSession(procRoot string, pid int, getenv func(string) string) Session {
	s := Session{
		SSHConnection: getenv("SSH_CONNECTION"),
		XDGSession:    getenv("XDG_SESSION_ID"),
		AuditSession:  readID(filepath.Join(procRoot, strconv.Itoa(pid), "sessionid")),
		LoginUID:      readID(filepath.Join(procRoot, strconv.Itoa(pid), "loginuid")),
	}
	// Walk up the tree to the first sshd. The process right below it is
	// the login shell, whose environment still holds SSH_CONNECTION and
	// XDG_SESSION_ID when sudo has dropped them from ours.
	below := 0
	for p, n := pid, 0; p > 1 && n < maxAncestors; n++ {
		comm, ppid, start, ok := readStat(procRoot, p)
		if !ok {
			break
		}
		if comm == "sshd" || comm == "sshd-session" {
			s.SSHD = strconv.Itoa(p) + ":" + start
			break
		}
		below, p = p, ppid
	}
	if s.SSHD != "" && below != 0 {
		env := readEnviron(filepath.Join(procRoot, strconv.Itoa(below), "environ"))
		if s.SSHConnection == "" {
			s.SSHConnection = env["SSH_CONNECTION"]
		}
		if s.XDGSession == "" {
			s.XDGSession = env["XDG_SESSION_ID"]
		}
	}
	return s
}

func readID(p string) string {
	b, err := os.ReadFile(p)
	if err != nil {
		return ""
	}
	v := strings.TrimSpace(string(b))
	if v == unsetID {
		return ""
	}
	return v
}

// readStat parses /proc/PID/stat: the command name sits in parentheses
// and may hold spaces or parentheses itself, so the fields after it are
// read from the last ')'.
func readStat(procRoot string, pid int) (comm string, ppid int, start string, ok bool) {
	b, err := os.ReadFile(filepath.Join(procRoot, strconv.Itoa(pid), "stat"))
	if err != nil {
		return "", 0, "", false
	}
	open, end := bytes.IndexByte(b, '('), bytes.LastIndexByte(b, ')')
	if open < 0 || end < open {
		return "", 0, "", false
	}
	comm = string(b[open+1 : end])
	// After ")": state(3) ppid(4) ... starttime(22).
	f := strings.Fields(string(b[end+1:]))
	if len(f) < 20 {
		return "", 0, "", false
	}
	ppid, err = strconv.Atoi(f[1])
	if err != nil {
		return "", 0, "", false
	}
	return comm, ppid, f[19], true
}

func readEnviron(p string) map[string]string {
	b, err := os.ReadFile(p)
	if err != nil {
		return nil
	}
	out := map[string]string{}
	for _, kv := range bytes.Split(b, []byte{0}) {
		if k, v, ok := strings.Cut(string(kv), "="); ok {
			out[k] = v
		}
	}
	return out
}

// CompareSessions decides whether now, the session running `stackward
// confirm`, is a new SSH session compared with applied, the one that
// applied the transaction. It returns ok and why in words.
//
// The rules, strictest first:
//   - now must be an SSH session (a sshd ancestor or SSH_CONNECTION);
//     without one it is the console path, which needs --console;
//   - any fact both sessions have that is equal means the same session:
//     the same audit session, the same sshd process, the same TCP
//     connection (also a multiplexed ControlMaster channel) or the same
//     logind session;
//   - when the transaction was applied outside SSH, any SSH session is new;
//   - otherwise at least one fact both have must differ: a session that
//     cannot be told apart is refused, never assumed new.
func CompareSessions(applied, now Session) (ok bool, why string) {
	if !now.OverSSH() {
		return false, "this command does not run in an SSH session (no sshd ancestor, no SSH_CONNECTION); from the provider console, confirm with --console"
	}
	type fact struct{ name, a, b string }
	facts := []fact{
		{"audit session id", applied.AuditSession, now.AuditSession},
		{"sshd session process", applied.SSHD, now.SSHD},
		{"SSH connection (client address and port)", applied.SSHConnection, now.SSHConnection},
		{"logind session id", applied.XDGSession, now.XDGSession},
	}
	var differ []string
	for _, f := range facts {
		if f.a == "" || f.b == "" {
			continue
		}
		if f.a == f.b {
			return false, "this is the session that applied the transaction (same " + f.name + "); open a new SSH session and confirm from there"
		}
		differ = append(differ, f.name)
	}
	if !applied.OverSSH() {
		return true, "the transaction was applied outside SSH and this is an SSH session"
	}
	if len(differ) == 0 {
		return false, "cannot tell this session from the one that applied: they share no fact to compare (audit session id, sshd process, SSH connection, logind session); open a new SSH session, or confirm from the provider console with --console"
	}
	return true, "a new SSH session: its " + strings.Join(differ, ", ") + " differ from the session that applied"
}
