package facts

import (
	"context"
	"testing"
)

const f2bUnitKey = "systemctl show fail2ban.service --property=" + unitProperties

const f2bJailConf = `[INCLUDES]
before = paths-debian.conf

[DEFAULT]
#ignoreip = 127.0.0.1/8 ::1
bantime  = 10m
port = 0:65535
enabled = false

[sshd]
port    = ssh
logpath = %(sshd_log)s

[nginx-http-auth]
port    = http,https
`

func TestFail2banCollector(t *testing.T) {
	sys := newFakeSystem(map[string]string{
		"/etc/fail2ban/jail.conf":                     f2bJailConf,
		"/etc/fail2ban/jail.d/defaults-debian.conf":   "[sshd]\nenabled = true\n",
		"/etc/fail2ban/jail.local":                    "[DEFAULT]\nignoreip = 127.0.0.1/8 ::1\n           100.64.0.0/10 ; tailnet\n\n[sshd]\nport = %(ssh_port)s\nssh_port = 2222\n",
		"/etc/fail2ban/jail.d/recidive.local":         "[recidive]\nenabled = true\nignoreip = 127.0.0.1/8\n",
		"/etc/fail2ban/jail.d/zz-ignored.conf.bak":    "[nginx-http-auth]\nenabled = true\n",
		"/etc/fail2ban/filter.d/sshd.conf":            "[Definition]\n",
		"/etc/fail2ban/jail.d/nginx-http-auth.conf~":  "[nginx-http-auth]\nenabled = true\n",
		"/etc/fail2ban/jail.d/defaults-debian.local~": "",
	})
	sys.host.Root = true
	sys.cmds[f2bUnitKey] = unitShow("loaded", "active", "enabled")
	sys.cmds["fail2ban-client status"] = CmdResult{Stdout: []byte("Status\n|- Number of jail:\t2\n`- Jail list:\tsshd, recidive\n")}

	out := &Facts{}
	if err := (fail2banCollector{}).Collect(context.Background(), sys, out); err != nil {
		t.Fatal(err)
	}
	f := out.Fail2ban
	if !f.Installed || !f.StatusRead || len(f.ActiveJails) != 2 || f.ActiveJails[0] != "recidive" {
		t.Fatalf("status: %+v", f)
	}
	if !f.ConfigRead || len(f.Jails) != 2 {
		t.Fatalf("jails: %+v", f.Jails)
	}
	sshd, ok := f.Jail("sshd")
	if !ok || !sshd.Enabled || sshd.Port != "2222" || len(sshd.IgnoreIP) != 3 || sshd.IgnoreIP[2] != "100.64.0.0/10" {
		t.Errorf("sshd: %+v", sshd)
	}
	if r, ok := f.Jail("recidive"); !ok || len(r.IgnoreIP) != 1 {
		t.Errorf("recidive: %+v", r)
	}
	if a, k := f.JailActive("sshd"); !a || !k {
		t.Error("sshd should be active")
	}
	if a, k := f.JailActive("nginx-http-auth"); a || !k {
		t.Error("nginx-http-auth should be inactive")
	}
}

func TestFail2banNonRoot(t *testing.T) {
	sys := newFakeSystem(map[string]string{"/etc/fail2ban/jail.conf": f2bJailConf})
	sys.cmds[f2bUnitKey] = unitShow("loaded", "active", "enabled")
	sys.cmds["fail2ban-client status"] = CmdResult{ExitCode: 255}
	out := &Facts{}
	if err := (fail2banCollector{}).Collect(context.Background(), sys, out); err != nil {
		t.Fatal(err)
	}
	f := out.Fail2ban
	if f.StatusRead || !f.ConfigRead {
		t.Fatalf("non root: %+v", f)
	}
	// sshd is configured but not enabled; the server runs: a known no.
	if a, k := f.JailActive("sshd"); a || !k {
		t.Errorf("sshd: %v %v", a, k)
	}

	out = &Facts{}
	if err := (fail2banCollector{}).Collect(context.Background(), newFakeSystem(nil), out); err != nil {
		t.Fatal(err)
	}
	if out.Fail2ban.Installed {
		t.Error("absent")
	}
	if r, k := out.Fail2ban.Running(); r || !k {
		t.Error("absent fail2ban is a known not running")
	}
}

// A failed install can leave /etc/fail2ban/jail.d behind, empty. Without
// fail2ban-client and with systemd saying the unit is not there, that is
// not fail2ban: a known "absent", so CS-010 can answer.
func TestFail2banLeftoverConfigDirIsNotInstalled(t *testing.T) {
	sys := newFakeSystem(map[string]string{"/etc/fail2ban/jail.d/.keep": ""})
	sys.host.Root = true
	sys.cmds[f2bUnitKey] = unitShow("not-found", "inactive", "")
	out := &Facts{}
	if err := (fail2banCollector{}).Collect(context.Background(), sys, out); err != nil {
		t.Fatal(err)
	}
	f := out.Fail2ban
	if f.Installed || !f.ConfigDir {
		t.Fatalf("leftover dir: %+v", f)
	}
	if r, k := f.Running(); r || !k {
		t.Errorf("running %v known %v, want a known no", r, k)
	}
	if a, k := f.JailActive("sshd"); a || !k {
		t.Errorf("sshd jail %v known %v, want a known no", a, k)
	}
	// When systemd cannot be asked, the directory still counts: whether
	// fail2ban runs is then unknown, not absent.
	delete(sys.cmds, f2bUnitKey)
	out = &Facts{}
	if err := (fail2banCollector{}).Collect(context.Background(), sys, out); err != nil {
		t.Fatal(err)
	}
	if !out.Fail2ban.Installed {
		t.Errorf("no systemd answer: %+v", out.Fail2ban)
	}
}
