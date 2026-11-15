package apply_test

import (
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"

	"github.com/Shironex/stackward/internal/apply"
)

// The session that applies in these tests, and two others.
var (
	applying   = apply.Session{SSHConnection: "192.0.2.10 50022 198.51.100.5 22", AuditSession: "7", SSHD: "700:5000", LoginUID: "1000"}
	newSession = apply.Session{SSHConnection: "192.0.2.10 50544 198.51.100.5 22", AuditSession: "9", SSHD: "900:7000", LoginUID: "1000"}
	console    = apply.Session{LoginUID: "0"}
)

func TestCompareSessions(t *testing.T) {
	sshdOnly := apply.Session{SSHD: "700:5000"}
	for name, tc := range map[string]struct {
		applied, now apply.Session
		ok           bool
		want         string
	}{
		"new session":                {applying, newSession, true, "differ"},
		"same session":               {applying, applying, false, "same"},
		"same audit session (tmux)":  {applying, apply.Session{SSHConnection: newSession.SSHConnection, AuditSession: "7", SSHD: "900:7000"}, false, "audit session"},
		"same connection (mux)":      {applying, apply.Session{SSHConnection: applying.SSHConnection, AuditSession: "9", SSHD: "900:7000"}, false, "SSH connection"},
		"same sshd process":          {applying, apply.Session{SSHConnection: newSession.SSHConnection, SSHD: "700:5000"}, false, "sshd session process"},
		"same logind session":        {apply.Session{SSHD: "1:1", XDGSession: "4"}, apply.Session{SSHD: "2:2", XDGSession: "4"}, false, "logind"},
		"pid reused, start differs":  {sshdOnly, apply.Session{SSHD: "700:9999"}, true, "differ"},
		"console confirm":            {applying, console, false, "--console"},
		"no facts at all":            {applying, apply.Session{}, false, "--console"},
		"nothing comparable":         {apply.Session{SSHConnection: "192.0.2.10 50022 198.51.100.5 22"}, apply.Session{SSHD: "900:7000"}, false, "share no fact"},
		"applied from console":       {console, newSession, true, "outside SSH"},
		"applied with no facts":      {apply.Session{}, newSession, true, "outside SSH"},
		"only connection, new port":  {apply.Session{SSHConnection: "192.0.2.10 50022 198.51.100.5 22"}, apply.Session{SSHConnection: "192.0.2.10 50023 198.51.100.5 22"}, true, "SSH connection"},
		"same audit id, both no ssh": {apply.Session{AuditSession: "7"}, apply.Session{AuditSession: "7"}, false, "not run in an SSH session"},
	} {
		ok, why := apply.CompareSessions(tc.applied, tc.now)
		if ok != tc.ok || !strings.Contains(why, tc.want) {
			t.Errorf("%s: ok %v, want %v: %s", name, ok, tc.ok, why)
		}
	}
}

// writeProc lays out one process of a fake /proc.
func writeProc(t *testing.T, root string, pid, ppid int, comm string, files map[string]string) {
	t.Helper()
	dir := filepath.Join(root, strconv.Itoa(pid))
	stat := strconv.Itoa(pid) + " (" + comm + ") S " + strconv.Itoa(ppid) + " 1 1 0 -1 4194560 100 0 0 0 0 0 0 0 20 0 1 0 " + strconv.Itoa(pid*10) + " 1000 100\n"
	files["stat"] = stat
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	for name, content := range files {
		if err := os.WriteFile(filepath.Join(dir, name), []byte(content), 0o600); err != nil {
			t.Fatal(err)
		}
	}
}

func TestReadSession(t *testing.T) {
	proc := t.TempDir()
	// stackward <- sudo <- bash <- sshd (session) <- sshd (listener) <- init
	writeProc(t, proc, 500, 400, "stackward", map[string]string{"sessionid": "7\n", "loginuid": "1000\n"})
	writeProc(t, proc, 400, 300, "sudo", map[string]string{})
	writeProc(t, proc, 300, 200, "bash", map[string]string{"environ": "HOME=/home/u\x00SSH_CONNECTION=192.0.2.10 50022 198.51.100.5 22\x00XDG_SESSION_ID=4\x00"})
	writeProc(t, proc, 200, 100, "sshd", map[string]string{})
	writeProc(t, proc, 100, 1, "sshd", map[string]string{})
	noEnv := func(string) string { return "" }

	s := apply.ReadSession(proc, 500, noEnv)
	want := apply.Session{SSHConnection: "192.0.2.10 50022 198.51.100.5 22", AuditSession: "7", LoginUID: "1000", XDGSession: "4", SSHD: "200:2000"}
	if s != want {
		t.Errorf("under sudo: %+v, want %+v", s, want)
	}
	// Our own environment wins over the shell's.
	s = apply.ReadSession(proc, 500, func(k string) string {
		if k == "SSH_CONNECTION" {
			return "192.0.2.10 1 198.51.100.5 22"
		}
		return ""
	})
	if s.SSHConnection != "192.0.2.10 1 198.51.100.5 22" {
		t.Errorf("own env: %+v", s)
	}
	// OpenSSH 9.8 and later name the session process sshd-session; a
	// command name may hold spaces and parentheses.
	writeProc(t, proc, 210, 100, "sshd-session", map[string]string{})
	writeProc(t, proc, 310, 210, "my (odd) shell", map[string]string{})
	writeProc(t, proc, 510, 310, "stackward", map[string]string{"sessionid": "4294967295\n"})
	s = apply.ReadSession(proc, 510, noEnv)
	if s.SSHD != "210:2100" || s.AuditSession != "" {
		t.Errorf("sshd-session: %+v", s)
	}
	// No sshd ancestor: the console or a service.
	writeProc(t, proc, 600, 1, "login", map[string]string{})
	writeProc(t, proc, 610, 600, "stackward", map[string]string{"sessionid": "3\n"})
	s = apply.ReadSession(proc, 610, noEnv)
	if s.OverSSH() || s.AuditSession != "3" {
		t.Errorf("console: %+v", s)
	}
	// A /proc that cannot be read gives an empty session, not a panic.
	if s := apply.ReadSession(filepath.Join(proc, "missing"), 1, noEnv); s != (apply.Session{}) {
		t.Errorf("missing proc: %+v", s)
	}
}
