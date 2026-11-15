package facts

import (
	"context"
	"io/fs"
	"reflect"
	"strings"
	"testing"
	"testing/fstest"
)

// sshFake extends fakeSystem with what the ssh collector needs to see:
// paths that answer permission denied and per path owner and mode.
type sshFake struct {
	*fakeSystem
	denied map[string]bool
	owner  map[string]int // uid per path; default 0
}

func newSSHFake(files map[string]string, root bool) *sshFake {
	f := &sshFake{fakeSystem: newFakeSystem(files), denied: map[string]bool{}, owner: map[string]int{}}
	if root {
		f.host = Host{Hostname: "host.example.com", Root: true}
	}
	return f
}

func (f *sshFake) deny(p string) { f.denied[p] = true }

func (f *sshFake) mode(p string, m fs.FileMode) { f.files[f.rel(p)].Mode = m }

func (f *sshFake) dir(p string, m fs.FileMode, uid int) {
	f.files[f.rel(p)] = &fstest.MapFile{Mode: fs.ModeDir | m}
	f.owner[p] = uid
}

func permErr(p string) error { return &fs.PathError{Op: "open", Path: p, Err: fs.ErrPermission} }

func (f *sshFake) ReadFile(p string) ([]byte, error) {
	if f.denied[p] {
		return nil, permErr(p)
	}
	return f.fakeSystem.ReadFile(p)
}

func (f *sshFake) ReadDir(p string) ([]fs.DirEntry, error) {
	if f.denied[p] {
		return nil, permErr(p)
	}
	return f.fakeSystem.ReadDir(p)
}

func (f *sshFake) Meta(p string) (FileMeta, error) {
	for d := range f.denied {
		if strings.HasPrefix(p, d+"/") {
			return FileMeta{}, permErr(p) // a denied directory hides its children
		}
	}
	m, err := f.fakeSystem.Meta(p)
	if err == nil {
		m.UID = f.owner[p]
	}
	return m, err
}

const (
	testPasswd = `root:x:0:0:root:/root:/bin/bash
daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin
sshd:x:110:65534::/run/sshd:/usr/sbin/nologin
alice:x:1000:1000:Alice:/home/alice:/bin/bash
bob:x:1001:1001::/home/bob:/bin/bash
nobody:x:65534:65534:nobody:/nonexistent:/usr/sbin/nologin
`
	edKey = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIGtra2tra2tra2tra2tra2tra2tra2tra2tra2tra2tr alice@example.com\n"
)

func baseSSHFiles() map[string]string {
	return map[string]string{
		"/etc/ssh/sshd_config":                      "Include /etc/ssh/sshd_config.d/*.conf\nKbdInteractiveAuthentication no\nUsePAM yes\n",
		"/etc/ssh/sshd_config.d/50-cloud-init.conf": "PasswordAuthentication yes\n",
		"/etc/ssh/sshd_config.d/60-harden.conf":     "PasswordAuthentication no\nPermitRootLogin no\n",
		"/etc/ssh/ssh_host_ed25519_key":             "PRIVATE",
		"/etc/ssh/ssh_host_ed25519_key.pub":         edKey,
		"/etc/pam.d/sshd":                           "@include common-auth\nauth required pam_google_authenticator.so nullok\n",
		"/etc/passwd":                               testPasswd,
		"/home/alice/.ssh/authorized_keys":          "# keys\n" + edKey,
	}
}

func socketShow(listen string) CmdResult {
	return CmdResult{Stdout: []byte("LoadState=loaded\nActiveState=active\nSubState=listening\nUnitFileState=enabled\nListen=" + listen + " (Stream)\n")}
}

func TestSSHCollectorNonRoot(t *testing.T) {
	sys := newSSHFake(baseSSHFiles(), false)
	sys.deny("/etc/ssh/sshd_config.d/50-cloud-init.conf")
	sys.deny("/home/bob")
	sys.deny("/root")
	sys.dir("/home/alice", 0o750, 1000)
	sys.dir("/home/alice/.ssh", 0o755, 1000)
	sys.dir("/home/bob", 0o750, 1001)
	sys.dir("/root", 0o700, 0)
	sys.owner["/home/alice/.ssh/authorized_keys"] = 1000
	sys.mode("/home/alice/.ssh/authorized_keys", 0o664)
	sys.mode("/etc/ssh/ssh_host_ed25519_key", 0o600)
	sys.cmds["systemctl show ssh.socket --property=LoadState,ActiveState,SubState,UnitFileState,Listen"] = socketShow("[::]:22")
	sys.cmds["ss -Htln"] = CmdResult{Stdout: []byte("LISTEN 0 4096 127.0.0.53%lo:53 0.0.0.0:*\nLISTEN 0 4096 *:22 *:*\n")}

	out := &Facts{}
	err := (sshCollector{}).Collect(context.Background(), sys, out)
	if err != nil {
		t.Fatal(err)
	}
	s := out.SSH
	if !s.Installed || s.Source != "files" || s.SshdTError != "not root" || s.Complete {
		t.Fatalf("ssh = %+v", s)
	}
	if v, ok := s.Value("PermitRootLogin"); ok {
		t.Errorf("PermitRootLogin = %q: set after the unreadable drop-in, must be unknown", v)
	}
	if v, ok := s.Value("kbdinteractiveauthentication"); ok {
		t.Errorf("kbd = %q, must be unknown (unreadable drop-in sorts before it)", v)
	}
	if _, ok := s.Setting("allowusers"); ok {
		t.Error("allowusers must be unknown when incomplete")
	}
	if !s.Socket.Active() || !reflect.DeepEqual(s.Socket.Listen, []string{"[::]:22"}) {
		t.Errorf("socket = %+v", s.Socket)
	}
	if !s.ListeningInspected || !reflect.DeepEqual(s.Listening, []string{"*:22"}) {
		t.Errorf("listening = %v", s.Listening)
	}
	if !reflect.DeepEqual(s.PAM2FA, []string{"pam_google_authenticator"}) {
		t.Errorf("pam = %v", s.PAM2FA)
	}
	if len(s.HostKeys) != 1 || s.HostKeys[0].Type != "ssh-ed25519" || s.HostKeys[0].Bits != 256 || s.HostKeys[0].Configured {
		t.Errorf("host keys = %+v", s.HostKeys)
	}
	users := map[string]SSHUser{}
	for _, u := range s.Users {
		users[u.Name] = u
	}
	if len(users) != 3 {
		t.Fatalf("users = %+v", s.Users)
	}
	if u := users["root"]; !strings.Contains(u.Error, "permission denied") {
		t.Errorf("root = %+v", u)
	}
	if u := users["bob"]; !strings.Contains(u.Error, "permission denied") {
		t.Errorf("bob = %+v", u)
	}
	a := users["alice"]
	if a.SSHDir == nil || a.SSHDir.Mode.Perm() != 0o755 || len(a.KeyFiles) != 1 {
		t.Fatalf("alice = %+v", a)
	}
	kf := a.KeyFiles[0]
	if kf.Path != "/home/alice/.ssh/authorized_keys" || kf.Meta.UID != 1000 || kf.Meta.Mode.Perm() != 0o664 ||
		len(kf.Keys) != 1 || kf.Keys[0].Type != "ssh-ed25519" {
		t.Errorf("alice key file = %+v", kf)
	}
}

func TestSSHCollectorRootUsesSshdT(t *testing.T) {
	sys := newSSHFake(baseSSHFiles(), true)
	sys.cmds["sshd -T"] = CmdResult{Stdout: []byte("port 2222\npasswordauthentication yes\npermitrootlogin no\n" +
		"listenaddress [::]:2222\nlistenaddress 0.0.0.0:2222\nhostkey /etc/ssh/ssh_host_ed25519_key\nhostkey /etc/ssh/ssh_host_rsa_key\n")}
	sys.cmds["systemctl show ssh.socket --property=LoadState,ActiveState,SubState,UnitFileState,Listen"] = CmdResult{Stdout: []byte("LoadState=not-found\nActiveState=inactive\n")}
	sys.cmds["systemctl show sshd.socket --property=LoadState,ActiveState,SubState,UnitFileState,Listen"] = CmdResult{Stdout: []byte("LoadState=not-found\nActiveState=inactive\n")}
	sys.cmds["ss -Htln"] = CmdResult{Stdout: []byte("LISTEN 0 128 0.0.0.0:22 0.0.0.0:*\nLISTEN 0 128 [::]:22 [::]:*\nLISTEN 0 511 0.0.0.0:80 0.0.0.0:*\n")}

	out := &Facts{}
	if err := (sshCollector{}).Collect(context.Background(), sys, out); err != nil {
		t.Fatal(err)
	}
	s := out.SSH
	if s.Source != "sshd -T" || !s.Complete {
		t.Fatalf("source = %q (%s)", s.Source, s.SshdTError)
	}
	if v, _ := s.Value("passwordauthentication"); v != "yes" {
		t.Errorf("password = %q", v)
	}
	if s.Config == nil || len(s.Config.Directives) != 5 {
		t.Errorf("files must still be parsed: %+v", s.Config)
	}
	if s.Socket == nil || s.Socket.LoadState != "not-found" || s.Socket.Active() {
		t.Errorf("socket = %+v", s.Socket)
	}
	if len(s.Listening) != 0 || !s.ListeningInspected {
		t.Errorf("listening on 2222 = %v (22 and 80 are not the configured port)", s.Listening)
	}
	if len(s.HostKeys) != 1 || !s.HostKeys[0].Configured {
		t.Errorf("host keys = %+v (configured rsa key is missing on disk)", s.HostKeys)
	}
}

func TestSSHCollectorSshdTFailsFallsBack(t *testing.T) {
	sys := newSSHFake(baseSSHFiles(), true)
	sys.cmds["sshd -T"] = CmdResult{ExitCode: 255, Stderr: []byte("Missing privilege separation directory: /run/sshd\n")}
	out := &Facts{}
	_ = (sshCollector{}).Collect(context.Background(), sys, out)
	s := out.SSH
	if s.Source != "files" || !s.Complete || s.SshdTError != "Missing privilege separation directory: /run/sshd" {
		t.Fatalf("ssh = %+v", s)
	}
	if v, _ := s.Value("passwordauthentication"); v != "yes" {
		t.Errorf("password = %q, want the cloud-init value", v)
	}
	if s.SocketError == "" || s.ListeningError == "" || s.ListeningInspected {
		t.Errorf("missing commands must be recorded: %q %q", s.SocketError, s.ListeningError)
	}
}

func TestSSHCollectorNotInstalled(t *testing.T) {
	out := &Facts{}
	if err := (sshCollector{}).Collect(context.Background(), newSSHFake(map[string]string{"/etc/passwd": testPasswd}, true), out); err != nil {
		t.Fatal(err)
	}
	if out.SSH == nil || out.SSH.Installed {
		t.Fatalf("ssh = %+v", out.SSH)
	}
}

func TestSSHCollectorMainUnreadable(t *testing.T) {
	sys := newSSHFake(baseSSHFiles(), false)
	sys.deny("/etc/ssh/sshd_config")
	out := &Facts{}
	err := (sshCollector{}).Collect(context.Background(), sys, out)
	if err == nil || !strings.Contains(err.Error(), "not readable") {
		t.Fatalf("err = %v", err)
	}
	if out.SSH == nil || len(out.SSH.Effective) != 0 {
		t.Fatalf("ssh = %+v", out.SSH)
	}
}

func TestParseSSListen(t *testing.T) {
	out := "State Recv-Q Send-Q Local Address:Port Peer Address:Port\n" +
		"LISTEN 0 4096 127.0.0.53%lo:53 0.0.0.0:*\nLISTEN 0 128 [fe80::1%eth0]:22 [::]:*\nLISTEN 0 128 [::]:22 [::]:*\n"
	want := []string{"127.0.0.53:53", "[fe80::1]:22", "[::]:22"}
	if got := ParseSSListen([]byte(out)); !reflect.DeepEqual(got, want) {
		t.Fatalf("got %v, want %v", got, want)
	}
}

func TestParsePAM2FA(t *testing.T) {
	body := "# auth required pam_oath.so\nauth [success=1 default=ignore] /lib/security/pam_u2f.so cue\n" +
		"-auth optional pam_duo.so\nsession required pam_google_authenticator.so\naccount required pam_oath.so\n"
	if got := ParsePAM2FA([]byte(body)); !reflect.DeepEqual(got, []string{"pam_u2f", "pam_duo"}) {
		t.Fatalf("got %v", got)
	}
}

func TestAuthorizedKeysPaths(t *testing.T) {
	e := Account{Name: "alice", UID: 1000, Home: "/home/alice"}
	got := authorizedKeysPaths(".ssh/authorized_keys /etc/ssh/keys/%u %h/extra_%U none 100%%", e)
	want := []string{"/home/alice/.ssh/authorized_keys", "/etc/ssh/keys/alice", "/home/alice/extra_1000", "/home/alice/100%"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("got %v, want %v", got, want)
	}
}
