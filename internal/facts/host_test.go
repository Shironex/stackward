package facts

import (
	"context"
	"strings"
	"testing"
	"time"
)

func collectOne(t *testing.T, c Collector, sys System) (*Facts, error) {
	t.Helper()
	out := &Facts{}
	err := c.Collect(context.Background(), sys, out)
	return out, err
}

func TestUsersCollector(t *testing.T) {
	sys := newFakeSystem(map[string]string{
		"/etc/passwd": "root:x:0:0:root:/root:/bin/bash\nubuntu:x:1000:1000::/home/ubuntu:/bin/bash\n" +
			"alice:x:1001:1001::/home/alice:/bin/bash\ndaemon:x:1:1::/usr/sbin:/usr/sbin/nologin\n" +
			"toor:x:0:0::/root:/bin/sh\n",
		"/etc/group": "root:x:0:\nsudo:x:27:alice\ndocker:x:998:alice,ubuntu\nubuntu:x:1000:\n",
		"/etc/sudoers": "Defaults env_reset\nroot ALL=(ALL:ALL) ALL\n%sudo ALL=(ALL:ALL) ALL\n" +
			"@includedir /etc/sudoers.d\n",
		"/etc/sudoers.d/90-cloud-init-users": "# comment\nubuntu ALL=(ALL) NOPASSWD:ALL\n",
		"/etc/sudoers.d/README.md":           "ignored ALL=(ALL) NOPASSWD:ALL\n",
		"/home/ubuntu/.ssh/authorized_keys":  "ssh-ed25519 AAAA placeholder\n",
	})
	sys.host.Root = true
	sys.cmds["passwd -S -a"] = CmdResult{Stdout: []byte("root L 2026-01-01 0 99999 7 -1\nubuntu NP 2026-01-01 0 99999 7 -1\nalice P 2026-01-01 0 99999 7 -1\n")}
	sys.cmds["lastlog"] = CmdResult{Stdout: []byte("Username         Port     From             Latest\n" +
		"root                                       **Never logged in**\n" +
		"alice            pts/0    192.0.2.10       Mon Nov  3 10:15:01 +0000 2026\n")}
	f, err := collectOne(t, usersCollector{}, sys)
	if err != nil {
		t.Fatal(err)
	}
	u := f.Users
	if len(u.Accounts) != 5 || !u.PasswordStatusChecked || !u.LastlogChecked {
		t.Fatalf("unexpected users: %+v", u)
	}
	byName := map[string]Account{}
	for _, a := range u.Accounts {
		byName[a.Name] = a
	}
	if byName["daemon"].LoginShell || !byName["alice"].LoginShell {
		t.Error("login shell detection wrong")
	}
	if byName["ubuntu"].PasswordStatus != "NP" || byName["alice"].LastLogin.IsZero() || !byName["root"].NeverLoggedIn {
		t.Errorf("status or lastlog not applied: %+v", byName)
	}
	if k := byName["ubuntu"].AuthorizedKeys; k == nil || !*k {
		t.Error("authorized key not seen")
	}
	if got := strings.Join(u.GroupsOf(byName["alice"]), ","); got != "alice,docker,sudo" && got != "docker,sudo" {
		t.Errorf("groups of alice: %s", got)
	}
	var cloud *Sudoers
	for i := range u.Sudoers {
		if u.Sudoers[i].Path == "/etc/sudoers.d/90-cloud-init-users" {
			cloud = &u.Sudoers[i]
		}
		if strings.HasSuffix(u.Sudoers[i].Path, "README.md") {
			t.Error("file with a dot must be skipped like sudo does")
		}
	}
	if cloud == nil || len(cloud.NoPasswd) != 1 || cloud.NoPasswd[0].Who != "ubuntu" || cloud.NonRootWritable {
		t.Errorf("cloud sudoers: %+v", cloud)
	}
}

func TestUsersCollectorWithoutRoot(t *testing.T) {
	sys := newFakeSystem(map[string]string{"/etc/passwd": "root:x:0:0:r:/root:/bin/bash\n"})
	f, err := collectOne(t, usersCollector{}, sys)
	if err == nil {
		t.Error("missing /etc/group should make the run partial")
	}
	if f.Users == nil || f.Users.PasswordStatusChecked || f.Users.LastlogChecked {
		t.Errorf("without root nothing about passwords may be recorded: %+v", f.Users)
	}
	if _, err := collectOne(t, usersCollector{}, newFakeSystem(nil)); err == nil {
		t.Error("missing /etc/passwd must fail")
	}
}

func TestParseSudoers(t *testing.T) {
	np, pr := ParseSudoers([]byte("Cmnd_Alias X = /bin/ls\nUser_Alias A = bob\n#includedir /etc/sudoers.d\n" +
		"deploy ALL=(ALL) \\\n  NOPASSWD: /usr/bin/docker\nalice,bob ALL=(ALL) ALL\n%wheel ALL=(ALL) NOPASSWD: ALL\n"))
	if len(np) != 2 || np[0].Who != "deploy" || np[0].Line != 4 || np[1].Who != "%wheel" || np[1].Line != 7 {
		t.Errorf("nopasswd: %+v", np)
	}
	if strings.Join(pr, " ") != "deploy alice bob %wheel" {
		t.Errorf("principals: %v", pr)
	}
}

func TestSudoersWritable(t *testing.T) {
	sys := newFakeSystem(map[string]string{"/etc/sudoers": "root ALL=(ALL) ALL\n"})
	sys.files["etc/sudoers"].Mode = 0o666
	if s := collectSudoers(sys); len(s) != 1 || !s[0].NonRootWritable {
		t.Errorf("0666 sudoers must be flagged: %+v", s)
	}
	sys.files["etc/sudoers"].Mode = 0o440
	if s := collectSudoers(sys); s[0].NonRootWritable {
		t.Error("0440 root owned file is fine")
	}
}

const aptDump = `APT::Periodic::Update-Package-Lists "1";
APT::Periodic::Unattended-Upgrade "1";
Unattended-Upgrade::Allowed-Origins "";
Unattended-Upgrade::Allowed-Origins:: "${distro_id}:${distro_codename}";
Unattended-Upgrade::Allowed-Origins:: "${distro_id}:${distro_codename}-security";
Unattended-Upgrade::Automatic-Reboot "true";
Unattended-Upgrade::Automatic-Reboot-Time "03:30";
`

func TestParseAptConf(t *testing.T) {
	c := parseAptConf(aptDump)
	if c.scalar("APT::Periodic::Unattended-Upgrade") != "1" || len(c.list("Unattended-Upgrade::Allowed-Origins")) != 2 {
		t.Errorf("dump parse: %v", c)
	}
	blocks := parseAptConf(`// comment
Unattended-Upgrade::Allowed-Origins {
	"${distro_id}:${distro_codename}"; // trailing
	/* "disabled"; */
	"${distro_id}:${distro_codename}-security";
};
APT::Periodic { Unattended-Upgrade "0"; };
Unattended-Upgrade::Automatic-Reboot "false";
`)
	if got := blocks.list("Unattended-Upgrade::Allowed-Origins"); len(got) != 2 || !strings.HasSuffix(got[1], "-security") {
		t.Errorf("block list: %v", got)
	}
	if blocks.scalar("APT::Periodic::Unattended-Upgrade") != "0" || isTrue(blocks.scalar("Unattended-Upgrade::Automatic-Reboot")) {
		t.Errorf("nested or bool: %v", blocks)
	}
}

func TestParseAptSimulate(t *testing.T) {
	total, sec, pkgs := ParseAptSimulate([]byte("Reading package lists...\n" +
		"Inst libssl3t64 [3.0.13-0ubuntu3.1] (3.0.13-0ubuntu3.4 Ubuntu:24.04/noble-updates, Ubuntu:24.04/noble-security [amd64])\n" +
		"Inst vim [2:9.1.0016-1ubuntu7] (2:9.1.0016-1ubuntu7.1 Ubuntu:24.04/noble-updates [amd64])\n" +
		"Conf libssl3t64 (3.0.13-0ubuntu3.4 Ubuntu:24.04/noble-updates [amd64])\n"))
	if total != 2 || sec != 1 || len(pkgs) != 1 || pkgs[0] != "libssl3t64" {
		t.Errorf("got %d %d %v", total, sec, pkgs)
	}
}

func TestUpdatesCollector(t *testing.T) {
	sys := newFakeSystem(map[string]string{
		"/var/lib/apt/periodic/unattended-upgrades-stamp":      "",
		"/var/lib/apt/periodic/update-success-stamp":           "",
		"/var/log/unattended-upgrades/unattended-upgrades.log": "x",
	})
	sys.cmds["dpkg-query -W -f=${Status} unattended-upgrades"] = CmdResult{Stdout: []byte("install ok installed")}
	sys.cmds["apt-config dump"] = CmdResult{Stdout: []byte(aptDump)}
	sys.cmds["systemctl is-enabled apt-daily-upgrade.timer"] = CmdResult{Stdout: []byte("enabled\n")}
	sys.cmds["systemctl is-active apt-daily-upgrade.timer"] = CmdResult{Stdout: []byte("inactive\n"), ExitCode: 3}
	sys.cmds["apt-get "+strings.Join(aptSimulateArgs, " ")] = CmdResult{Stdout: []byte("Inst a [1] (2 Debian-Security:12/bookworm-security [amd64])\n")}
	stamp := time.Date(2026, 3, 1, 6, 0, 0, 0, time.UTC)
	for _, p := range []string{"var/lib/apt/periodic/unattended-upgrades-stamp", "var/lib/apt/periodic/update-success-stamp"} {
		sys.files[p].ModTime = stamp
	}
	f, err := collectOne(t, updatesCollector{}, sys)
	if err != nil {
		t.Fatal(err)
	}
	u := f.Updates
	if !u.Apt || !u.UnattendedInstalled || u.PeriodicUnattended != "1" || !u.AutomaticReboot || u.AutomaticRebootTime != "03:30" {
		t.Errorf("updates: %+v", u)
	}
	if u.TimerEnabled == nil || !*u.TimerEnabled || u.TimerActive == nil || *u.TimerActive {
		t.Errorf("timer: %+v %+v", u.TimerEnabled, u.TimerActive)
	}
	if !u.LastRun.Equal(stamp) || u.ListsUpdated.IsZero() || !u.PendingChecked || u.PendingSecurity != 1 {
		t.Errorf("stamps or pending: %+v", u)
	}
}

func TestUpdatesCollectorNoApt(t *testing.T) {
	f, err := collectOne(t, updatesCollector{}, newFakeSystem(nil))
	if err != nil || f.Updates == nil || f.Updates.Apt {
		t.Errorf("non apt host must record Apt=false: %v %+v", err, f.Updates)
	}
}

func TestUpdatesFallsBackToFiles(t *testing.T) {
	sys := newFakeSystem(map[string]string{
		"/etc/apt/apt.conf.d/20auto-upgrades":                "APT::Periodic::Unattended-Upgrade \"1\";\n",
		"/etc/apt/apt.conf.d/50unattended-upgrades":          "Unattended-Upgrade::Allowed-Origins {\n\"x:y-security\";\n};\n",
		"/etc/apt/apt.conf.d/50unattended-upgrades.dpkg-old": "APT::Periodic::Unattended-Upgrade \"0\";\n",
	})
	sys.cmds["dpkg-query"] = CmdResult{}
	f, _ := collectOne(t, updatesCollector{}, sys)
	u := f.Updates
	if u.ConfigSource != "files" || u.PeriodicUnattended != "1" || len(u.AllowedOrigins) != 1 {
		t.Errorf("fallback: %+v", u)
	}
}

func TestSysctlCollector(t *testing.T) {
	sys := newFakeSystem(map[string]string{
		"/proc/sys/net/ipv4/ip_forward":         "0\n",
		"/proc/sys/net/ipv4/conf/all/rp_filter": "1\n",
		"/proc/sys/net/ipv6/conf/all/accept_ra": "0\n",
		"/etc/sysctl.d/99-hardening.conf":       "# profile\nnet.ipv4.ip_forward = 0\nnet.ipv6.conf.all.accept_ra=0\nunrelated.key=1\n",
		"/usr/lib/sysctl.d/99-hardening.conf":   "net.ipv4.ip_forward=1\n",
		"/etc/sysctl.conf":                      "net.ipv4.conf.all.rp_filter=2\n",
		"/etc/ufw/sysctl.conf":                  "net/ipv4/conf/all/log_martians=0\n",
		"/var/run/docker.sock":                  "",
		"/proc/net/if_inet6": "fe800000000000000000000000000001 02 40 20 80 eth0\n" +
			"20010db8000000000000000000000002 02 40 00 00 eth0\n" +
			"00000000000000000000000000000001 01 80 10 80 lo\n",
	})
	f, err := collectOne(t, sysctlCollector{}, sys)
	if err != nil {
		t.Fatal(err)
	}
	s := f.Sysctl
	if s.Values["net.ipv4.ip_forward"] != "0" || len(s.Values) != 3 {
		t.Errorf("values: %v", s.Values)
	}
	if c := s.Configured["net.ipv4.ip_forward"]; c.Value != "0" || c.File != "/etc/sysctl.d/99-hardening.conf" {
		t.Errorf("an /etc drop-in must mask the /usr/lib one: %+v", c)
	}
	if c := s.Configured["net.ipv4.conf.all.rp_filter"]; c.File != "/etc/sysctl.conf" {
		t.Errorf("sysctl.conf wins last: %+v", c)
	}
	if s.UFW["net.ipv4.conf.all.log_martians"] != "0" || !s.DockerPresent || s.TailscalePresent || !s.GlobalIPv6Dynamic {
		t.Errorf("hints: %+v", s)
	}
	if _, err := collectOne(t, sysctlCollector{}, newFakeSystem(nil)); err == nil {
		t.Error("no readable value must be a partial result")
	}
}

func TestJournalCollector(t *testing.T) {
	sys := newFakeSystem(map[string]string{
		"/etc/systemd/journald.conf":                 "[Journal]\n#Storage=auto\nSystemMaxUse=5G\n",
		"/usr/lib/systemd/journald.conf.d/10-x.conf": "[Journal]\nStorage=volatile\n",
		"/etc/systemd/journald.conf.d/10-x.conf":     "[Journal]\nSystemMaxUse=1G\n",
		"/var/log/journal/.keep":                     "",
		"/var/log/nginx/access.log":                  strings.Repeat("x", 10),
		"/var/log/nginx/access.log.1.gz":             "x",
		"/etc/logrotate.d/nginx":                     "/var/log/nginx/*.log {\n  weekly\n  rotate 4\n}\n",
		"/usr/local/bin/node_exporter":               "",
	})
	sys.cmds["journalctl --disk-usage"] = CmdResult{Stdout: []byte("Archived and active journals take up 1.5G in the file system.\n")}
	f, err := collectOne(t, journalCollector{}, sys)
	if err != nil {
		t.Fatal(err)
	}
	j := f.Journal
	if j.SystemMaxUse != "1G" || j.Storage != "auto" || !j.PersistentDir || !j.Persistent {
		t.Errorf("config: %+v", j)
	}
	if !j.DiskUsageChecked || j.DiskUsageBytes != int64(1.5*(1<<30)) {
		t.Errorf("disk usage: %+v", j)
	}
	if len(j.ProxyLogs) != 1 || !j.ProxyLogs[0].Rotated || j.ProxyLogs[0].SizeBytes != 10 {
		t.Errorf("proxy logs: %+v", j.ProxyLogs)
	}
	if len(j.Agents) != 1 || j.Agents[0] != "node_exporter" {
		t.Errorf("agents: %v", j.Agents)
	}
}

func TestJournalVolatileNoPersistentDir(t *testing.T) {
	f, _ := collectOne(t, journalCollector{}, newFakeSystem(map[string]string{"/etc/systemd/journald.conf": "[Journal]\n"}))
	if f.Journal.Persistent || f.Journal.Storage != "auto" || f.Journal.DiskUsageChecked {
		t.Errorf("%+v", f.Journal)
	}
}

func TestParseJournalDiskUsage(t *testing.T) {
	for in, want := range map[string]int64{
		"Journals take up 8.0M on disk.":                        8 << 20,
		"Archived and active journals take up 512.0K in the fi": 512 << 10,
	} {
		if got, ok := ParseJournalDiskUsage([]byte(in)); !ok || got != want {
			t.Errorf("%q: %d %v", in, got, ok)
		}
	}
	if _, ok := ParseJournalDiskUsage([]byte("nothing")); ok {
		t.Error("must not parse")
	}
}

func TestClockCollector(t *testing.T) {
	sys := newFakeSystem(nil)
	sys.cmds["timedatectl show"] = CmdResult{Stdout: []byte("Timezone=Etc/UTC\nCanNTP=yes\nNTP=yes\nNTPSynchronized=no\n")}
	f, err := collectOne(t, clockCollector{}, sys)
	if err != nil || f.Clock.NTPSynchronized || !f.Clock.NTPEnabled || !f.Clock.CanNTP || f.Clock.Timezone != "Etc/UTC" {
		t.Errorf("%v %+v", err, f.Clock)
	}
	if _, err := collectOne(t, clockCollector{}, newFakeSystem(nil)); err == nil {
		t.Error("missing timedatectl must fail so the check says unknown")
	}
	sys.cmds["timedatectl show"] = CmdResult{Stdout: []byte("Timezone=UTC\n")}
	if _, err := collectOne(t, clockCollector{}, sys); err == nil {
		t.Error("no NTPSynchronized property must fail")
	}
}

const dfOut = `Filesystem     1024-blocks     Used Available Capacity Mounted on
/dev/sda1         20000000 17400000   2600000      87% /
tmpfs               500000        0    500000       0% /dev/shm
/dev/sdb1        100000000 96000000   4000000      96% /var/lib/docker
`

func TestDiskCollector(t *testing.T) {
	sys := newFakeSystem(map[string]string{"/var/lib/docker/.keep": ""})
	sys.cmds["df -P -k"] = CmdResult{Stdout: []byte(dfOut)}
	f, err := collectOne(t, diskCollector{}, sys)
	if err != nil {
		t.Fatal(err)
	}
	m := f.Disk.Mounts
	if len(m) != 3 || m[0].Mount != "/" || m[1].Path != "/var" || m[1].Mount != "/" || m[2].Mount != "/var/lib/docker" || m[2].UsedPercent != 96 {
		t.Errorf("%+v", m)
	}
	if _, err := collectOne(t, diskCollector{}, newFakeSystem(nil)); err == nil {
		t.Error("missing df must fail")
	}
}

func TestMountForBoundary(t *testing.T) {
	list := []DiskMount{{Mount: "/"}, {Mount: "/var/lib"}}
	if m, _ := mountFor(list, "/var/library"); m.Mount != "/" {
		t.Error("/var/lib must not match /var/library")
	}
}

func TestParseLogrotatePatterns(t *testing.T) {
	got := ParseLogrotatePatterns([]byte("weekly\ninclude /etc/logrotate.d\n# c\n\"/var/log/a b/*.log\" /var/log/x.log {\n rotate 1\n}\n/var/log/y\n/var/log/z {\n}\n"))
	if len(got) < 2 || got[len(got)-1] != "/var/log/z" || !matchesAny(got, "/var/log/x.log") {
		t.Errorf("%v", got)
	}
}
