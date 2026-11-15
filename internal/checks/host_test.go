package checks

import (
	"strings"
	"testing"
	"time"

	"github.com/Shironex/stackward/internal/facts"
)

func bp(b bool) *bool { return &b }

type levelCase struct {
	name string
	f    *facts.Facts
	want Level
}

func runLevels(t *testing.T, run func(Input) []Result, cases []levelCase) {
	t.Helper()
	for _, tc := range cases {
		if tc.f.CollectedAt.IsZero() {
			tc.f.CollectedAt = now
		}
		rs := run(Input{Facts: tc.f})
		worst := rs[0].Level
		for _, r := range rs {
			if r.Level == Fail || (r.Level == Warn && worst != Fail) {
				worst = r.Level
			}
		}
		if worst != tc.want {
			t.Errorf("%s: got %s (%v), want %s", tc.name, worst, rs, tc.want)
		}
	}
}

func users(a ...facts.Account) *facts.Users {
	return &facts.Users{Accounts: a, PasswordStatusChecked: true, LastlogChecked: true}
}

func TestUSR001(t *testing.T) {
	runLevels(t, checkExtraUID0, []levelCase{
		{"nil", &facts.Facts{}, Unknown},
		{"only root", &facts.Facts{Users: users(facts.Account{Name: "root"})}, Pass},
		{"second uid 0", &facts.Facts{Users: users(facts.Account{Name: "root"}, facts.Account{Name: "toor"})}, Fail},
		{"others", &facts.Facts{Users: users(facts.Account{Name: "root"}, facts.Account{Name: "bob", UID: 1000})}, Pass},
	})
	rs := checkExtraUID0(Input{Facts: &facts.Facts{Users: users(facts.Account{Name: "root"}, facts.Account{Name: "toor"})}})
	if len(rs) != 1 || rs[0].Level != Fail || rs[0].Subject != "user:toor" {
		t.Errorf("got %v", rs)
	}
}

func TestUSR002(t *testing.T) {
	np := facts.Account{Name: "x", UID: 1000, LoginShell: true, PasswordStatus: "NP"}
	noShell := facts.Account{Name: "svc", UID: 5, PasswordStatus: "NP"}
	unchecked := users(np)
	unchecked.PasswordStatusChecked = false
	runLevels(t, checkEmptyPassword, []levelCase{
		{"nil", &facts.Facts{}, Unknown},
		{"not root", &facts.Facts{Users: unchecked}, Unknown},
		{"empty", &facts.Facts{Users: users(np)}, Fail},
		{"nologin ignored", &facts.Facts{Users: users(noShell)}, Pass},
		{"locked", &facts.Facts{Users: users(facts.Account{Name: "a", LoginShell: true, PasswordStatus: "L"})}, Pass},
	})
}

func TestUSR003(t *testing.T) {
	yes := true
	ubuntu := facts.Account{Name: "ubuntu", UID: 1000, GID: 1000, LoginShell: true, AuthorizedKeys: &yes}
	locked := facts.Account{Name: "ubuntu", UID: 1000, GID: 1000}
	alice := facts.Account{Name: "alice", UID: 1001, GID: 1001, LoginShell: true}
	sudoGroup := []facts.Group{{Name: "sudo", GID: 27, Members: []string{"alice"}}}
	readable := []facts.Sudoers{{Path: "/etc/sudoers", Readable: true}}
	mk := func(sud []facts.Sudoers, g []facts.Group, a ...facts.Account) *facts.Facts {
		u := users(a...)
		u.Sudoers, u.Groups = sud, g
		return &facts.Facts{Users: u}
	}
	runLevels(t, checkDefaultCloudUsers, []levelCase{
		{"nil", &facts.Facts{}, Unknown},
		{"none present", mk(nil, nil, alice), Pass},
		{"locked down", mk(readable, sudoGroup, locked, alice), Pass},
		{"usable with another admin", mk(readable, sudoGroup, ubuntu, alice), Warn},
		{"only admin", mk(readable, nil, ubuntu), Pass},
		{"unreadable sudoers", mk([]facts.Sudoers{{Path: "/etc/sudoers"}}, nil, ubuntu), Unknown},
		{"nopasswd line counts", mk([]facts.Sudoers{{Readable: true, NoPasswd: []facts.SudoRule{{Who: "ubuntu"}}, Principals: []string{"ubuntu", "alice"}}}, nil, locked, alice), Warn},
	})
}

func TestUSR004(t *testing.T) {
	ok := facts.Sudoers{Path: "/etc/sudoers", Perm: 0o440, Readable: true}
	runLevels(t, checkSudoers, []levelCase{
		{"nil", &facts.Facts{}, Unknown},
		{"no sudo", &facts.Facts{Users: users()}, Skip},
		{"clean", &facts.Facts{Users: &facts.Users{Sudoers: []facts.Sudoers{ok}}}, Pass},
		{"unreadable", &facts.Facts{Users: &facts.Users{Sudoers: []facts.Sudoers{{Path: "/etc/sudoers", Perm: 0o440}}}}, Unknown},
		{"nopasswd", &facts.Facts{Users: &facts.Users{Sudoers: []facts.Sudoers{{Path: "/etc/sudoers.d/x", Readable: true, NoPasswd: []facts.SudoRule{{Who: "deploy", Line: 1}}}}}}, Warn},
		{"writable", &facts.Facts{Users: &facts.Users{Sudoers: []facts.Sudoers{{Path: "/etc/sudoers", Perm: 0o666, NonRootWritable: true}}}}, Fail},
	})
}

func TestUSR005(t *testing.T) {
	alice := facts.Account{Name: "alice", UID: 1001, GID: 1001}
	g := []facts.Group{{Name: "docker", GID: 998, Members: []string{"alice"}}}
	mk := func(g []facts.Group, a ...facts.Account) *facts.Facts {
		u := users(a...)
		u.Groups = g
		return &facts.Facts{Users: u}
	}
	runLevels(t, checkDockerGroup, []levelCase{
		{"nil", &facts.Facts{}, Unknown},
		{"no group", mk(nil, alice), Skip},
		{"member", mk(g, alice), Warn},
		{"empty group", mk([]facts.Group{{Name: "docker", GID: 998}}, alice), Pass},
	})
}

func TestUSR006(t *testing.T) {
	old := facts.Account{Name: "old", UID: 1001, LoginShell: true, LastLogin: now.Add(-100 * 24 * time.Hour)}
	recent := facts.Account{Name: "new", UID: 1002, LoginShell: true, LastLogin: now.Add(-2 * 24 * time.Hour)}
	never := facts.Account{Name: "nev", UID: 1003, LoginShell: true, NeverLoggedIn: true}
	locked := facts.Account{Name: "lk", UID: 1004, LoginShell: true, NeverLoggedIn: true, PasswordStatus: "L"}
	nolast := users(recent)
	nolast.LastlogChecked = false
	runLevels(t, checkStaleLogins, []levelCase{
		{"nil", &facts.Facts{}, Unknown},
		{"no lastlog", &facts.Facts{Users: nolast}, Unknown},
		{"recent", &facts.Facts{Users: users(recent)}, Pass},
		{"stale", &facts.Facts{Users: users(recent, old)}, Warn},
		{"never", &facts.Facts{Users: users(never)}, Warn},
		{"locked never", &facts.Facts{Users: users(locked)}, Pass},
	})
}

func TestUSR007(t *testing.T) {
	root := func(st string) *facts.Facts {
		return &facts.Facts{Users: users(facts.Account{Name: "root", PasswordStatus: st})}
	}
	runLevels(t, checkRootPassword, []levelCase{
		{"nil", &facts.Facts{}, Unknown},
		{"unknown status", root(""), Unknown},
		{"locked", root("L"), Info},
		{"password", root("P"), Info},
	})
}

func TestUPD(t *testing.T) {
	good := func(mod func(*facts.Updates)) *facts.Facts {
		u := &facts.Updates{Apt: true, UnattendedInstalled: true, PeriodicUnattended: "1", ConfigSource: "apt-config",
			TimerEnabled: bp(true), AllowedOrigins: []string{"Ubuntu:noble-security"}, LastRun: now.Add(-24 * time.Hour),
			PendingChecked: true, ListsUpdated: now.Add(-24 * time.Hour)}
		if mod != nil {
			mod(u)
		}
		return &facts.Facts{Updates: u}
	}
	t.Run("001", func(t *testing.T) {
		runLevels(t, checkUnattendedEnabled, []levelCase{
			{"nil", &facts.Facts{}, Unknown},
			{"no apt", &facts.Facts{Updates: &facts.Updates{}}, Skip},
			{"ok", good(nil), Pass},
			{"not installed", good(func(u *facts.Updates) { u.UnattendedInstalled = false }), Fail},
			{"periodic off", good(func(u *facts.Updates) { u.PeriodicUnattended = "0" }), Fail},
			{"timer off", good(func(u *facts.Updates) { u.TimerEnabled = bp(false) }), Fail},
			{"timer unknown", good(func(u *facts.Updates) { u.TimerEnabled = nil }), Unknown},
			{"config unread", good(func(u *facts.Updates) { u.ConfigSource = "" }), Unknown},
		})
	})
	t.Run("002", func(t *testing.T) {
		runLevels(t, checkUnattendedRecent, []levelCase{
			{"nil", &facts.Facts{}, Unknown},
			{"not installed", good(func(u *facts.Updates) { u.UnattendedInstalled = false }), Skip},
			{"recent", good(nil), Pass},
			{"stale", good(func(u *facts.Updates) { u.LastRun = now.Add(-5 * 24 * time.Hour) }), Warn},
			{"never", good(func(u *facts.Updates) { u.LastRun = time.Time{} }), Warn},
		})
	})
	t.Run("003", func(t *testing.T) {
		runLevels(t, checkSecurityPocket, []levelCase{
			{"nil", &facts.Facts{}, Unknown},
			{"ok", good(nil), Pass},
			{"debian pattern", good(func(u *facts.Updates) {
				u.AllowedOrigins = []string{"origin=Debian,codename=${distro_codename}-security"}
			}), Pass},
			{"missing", good(func(u *facts.Updates) { u.AllowedOrigins = []string{"Ubuntu:noble"} }), Warn},
			{"empty", good(func(u *facts.Updates) { u.AllowedOrigins = nil }), Warn},
		})
	})
	t.Run("004", func(t *testing.T) {
		overdue := good(nil)
		overdue.Reboot = &facts.Reboot{Required: true, Since: now.Add(-20 * 24 * time.Hour)}
		overdueAuto := good(func(u *facts.Updates) { u.AutomaticReboot = true })
		overdueAuto.Reboot = overdue.Reboot
		runLevels(t, checkRebootPolicy, []levelCase{
			{"nil", &facts.Facts{}, Unknown},
			{"policy", good(nil), Info},
			{"overdue and off", overdue, Warn},
			{"overdue but automatic", overdueAuto, Info},
		})
	})
	t.Run("005", func(t *testing.T) {
		os := func(id, v string) *facts.Facts { return &facts.Facts{OS: &facts.OS{ID: id, VersionID: v}} }
		runLevels(t, checkSupportedRelease, []levelCase{
			{"nil", &facts.Facts{}, Unknown},
			{"supported", os("ubuntu", "24.04"), Pass},
			{"past", os("ubuntu", "20.04"), Fail},
			{"debian past", os("debian", "10"), Fail},
			{"unlisted", os("ubuntu", "99.04"), Unknown},
			{"other distro", os("rocky", "9"), Skip},
		})
		soon := &facts.Facts{CollectedAt: day(2027, time.April, 1), OS: &facts.OS{ID: "ubuntu", VersionID: "22.04"}}
		runLevels(t, checkSupportedRelease, []levelCase{{"within 90 days", soon, Warn}})
	})
	t.Run("006", func(t *testing.T) {
		runLevels(t, checkPendingSecurity, []levelCase{
			{"nil", &facts.Facts{}, Unknown},
			{"not checked", good(func(u *facts.Updates) { u.PendingChecked = false }), Unknown},
			{"none", good(nil), Pass},
			{"pending", good(func(u *facts.Updates) { u.PendingSecurity = 2 }), Warn},
		})
	})
}

func TestEOLTableIsSane(t *testing.T) {
	seen := map[string]bool{}
	for _, e := range eolTable {
		k := e.id + " " + e.version
		if seen[k] {
			t.Errorf("duplicate %s", k)
		}
		seen[k] = true
		if e.end.IsZero() || e.end.Year() < 2020 {
			t.Errorf("%s: implausible date %v", k, e.end)
		}
	}
	// Every release stackward is tested on must be in the table.
	for id, versions := range testedReleases {
		for _, v := range versions {
			if _, ok := lookupEOL(id, v); !ok {
				t.Errorf("tested release %s %s is missing from eolTable", id, v)
			}
		}
	}
}

func sysctlFacts(docker, tailscale bool, vals map[string]string) *facts.Facts {
	return &facts.Facts{Sysctl: &facts.Sysctl{DockerPresent: docker, TailscalePresent: tailscale, Values: vals}}
}

func TestKRN001(t *testing.T) {
	runLevels(t, checkIPForward, []levelCase{
		{"nil", &facts.Facts{}, Unknown},
		{"no docker", sysctlFacts(false, false, map[string]string{keyIPForward: "0"}), Skip},
		{"unreadable", sysctlFacts(true, false, nil), Unknown},
		{"zero", sysctlFacts(true, false, map[string]string{keyIPForward: "0"}), Fail},
		{"one", sysctlFacts(true, false, map[string]string{keyIPForward: "1"}), Pass},
	})
}

func TestKRN002(t *testing.T) {
	runLevels(t, checkRPFilter, []levelCase{
		{"nil", &facts.Facts{}, Unknown},
		{"neither", sysctlFacts(false, false, map[string]string{keyRPFilterAll: "1"}), Skip},
		{"unreadable", sysctlFacts(true, false, nil), Unknown},
		{"strict all", sysctlFacts(true, false, map[string]string{keyRPFilterAll: "1", keyRPFilterDef: "2"}), Warn},
		{"strict default tailscale", sysctlFacts(false, true, map[string]string{keyRPFilterAll: "2", keyRPFilterDef: "1"}), Warn},
		{"loose", sysctlFacts(true, true, map[string]string{keyRPFilterAll: "2", keyRPFilterDef: "2"}), Pass},
		{"off", sysctlFacts(true, true, map[string]string{keyRPFilterAll: "0"}), Pass},
	})
}

func allOK(table []baseline) map[string]string {
	m := map[string]string{}
	for _, b := range table {
		m[b.key] = "2"
		if !b.atLeast {
			m[b.key] = "1"
			if b.want == 0 {
				m[b.key] = "0"
			}
		}
	}
	return m
}

func TestKRN003And004(t *testing.T) {
	net := allOK(netBaseline)
	bad := allOK(netBaseline)
	bad["net.ipv4.conf.all.accept_redirects"] = "1"
	ufwFacts := sysctlFacts(false, false, allOK(netBaseline))
	ufwFacts.Sysctl.UFW = map[string]string{"net.ipv4.conf.all.log_martians": "0"}
	runLevels(t, checkNetBaseline, []levelCase{
		{"nil", &facts.Facts{}, Unknown},
		{"unreadable", sysctlFacts(false, false, nil), Unknown},
		{"ok", sysctlFacts(false, false, net), Pass},
		{"off", sysctlFacts(false, false, bad), Warn},
		{"ufw resets", ufwFacts, Warn},
	})
	kern := allOK(kernelBaseline)
	weak := allOK(kernelBaseline)
	weak["kernel.kptr_restrict"] = "0"
	partial := map[string]string{"kernel.kptr_restrict": "1"} // yama and others absent
	runLevels(t, checkKernelBaseline, []levelCase{
		{"nil", &facts.Facts{}, Unknown},
		{"unreadable", sysctlFacts(false, false, nil), Unknown},
		{"ok", sysctlFacts(false, false, kern), Pass},
		{"weak", sysctlFacts(false, false, weak), Warn},
		{"partial ok", sysctlFacts(false, false, partial), Pass},
	})
}

func TestKRN005(t *testing.T) {
	mk := func(ra string, cfg bool, dyn bool) *facts.Facts {
		f := sysctlFacts(false, false, map[string]string{keyRAAll: ra})
		f.Sysctl.GlobalIPv6Dynamic = dyn
		if cfg {
			f.Sysctl.Configured = map[string]facts.SysctlSetting{keyRAAll: {Value: "0", File: "/etc/sysctl.d/99-x.conf"}}
		}
		return f
	}
	runLevels(t, checkAcceptRA, []levelCase{
		{"nil", &facts.Facts{}, Unknown},
		{"unreadable", sysctlFacts(false, false, nil), Unknown},
		{"default", mk("1", false, true), Pass},
		{"profile set it, dynamic address", mk("0", true, true), Warn},
		{"profile set it, static v6", mk("0", true, false), Pass},
		{"zero without a profile", mk("0", false, true), Pass},
	})
}

func journalFacts(mod func(*facts.Journal)) *facts.Facts {
	j := &facts.Journal{Storage: "auto", Persistent: true, PersistentDir: true, SystemMaxUse: "1G", DiskUsageChecked: true, DiskUsageBytes: 3 << 30}
	if mod != nil {
		mod(j)
	}
	return &facts.Facts{Journal: j}
}

func TestLOG(t *testing.T) {
	t.Run("001", func(t *testing.T) {
		runLevels(t, checkJournalCap, []levelCase{
			{"nil", &facts.Facts{}, Unknown},
			{"capped", journalFacts(nil), Pass},
			{"unset", journalFacts(func(j *facts.Journal) { j.SystemMaxUse = "" }), Warn},
			{"volatile", journalFacts(func(j *facts.Journal) { j.SystemMaxUse, j.Persistent = "", false }), Skip},
		})
	})
	t.Run("002", func(t *testing.T) {
		runLevels(t, checkProxyLogRotation, []levelCase{
			{"nil", &facts.Facts{}, Unknown},
			{"no logs", journalFacts(nil), Skip},
			{"small", journalFacts(func(j *facts.Journal) {
				j.ProxyLogs = []facts.LogFile{{Path: "/var/log/nginx/access.log", SizeBytes: 1 << 20}}
			}), Pass},
			{"big rotated", journalFacts(func(j *facts.Journal) {
				j.ProxyLogs = []facts.LogFile{{Path: "/var/log/nginx/access.log", SizeBytes: 3 << 30, Rotated: true}}
			}), Pass},
			{"big unrotated", journalFacts(func(j *facts.Journal) {
				j.ProxyLogs = []facts.LogFile{{Path: "/var/log/nginx/access.log", SizeBytes: 3 << 30}}
			}), Warn},
		})
	})
	t.Run("003", func(t *testing.T) {
		runLevels(t, checkJournalSize, []levelCase{
			{"nil", &facts.Facts{}, Unknown},
			{"unchecked", journalFacts(func(j *facts.Journal) { j.DiskUsageChecked = false }), Unknown},
			{"info", journalFacts(nil), Info},
		})
	})
	t.Run("004", func(t *testing.T) {
		runLevels(t, checkMonitoringAgent, []levelCase{
			{"nil", &facts.Facts{}, Unknown},
			{"none", journalFacts(nil), Info},
			{"found", journalFacts(func(j *facts.Journal) { j.Agents = []string{"netdata"} }), Info},
		})
		agentMsg := func(f *facts.Facts) string {
			f.CollectedAt = now
			return checkMonitoringAgent(Input{Facts: f})[0].Message
		}
		withContainer := func(image string, running bool) *facts.Facts {
			f := journalFacts(nil)
			f.Docker = &facts.Docker{Containers: []facts.DockerContainer{{Name: "mon", Image: image, Running: running}}}
			return f
		}
		for image, want := range map[string]string{
			"grafana/alloy:v1.4.2":                      "alloy (container mon)",
			"docker.io/grafana/alloy@sha256:abc":        "alloy (container mon)",
			"quay.io/prometheus/node-exporter:v1.8.0":   "node_exporter (container mon)",
			"prom/node-exporter":                        "node_exporter (container mon)",
			"registry.example.com:5000/netdata/netdata": "netdata (container mon)",
			"gcr.io/datadoghq/agent:7":                  "datadog-agent (container mon)",
			"timberio/vector:0.40-alpine":               "vector (container mon)",
			"nginx:1.27":                                "no metrics agent found",
			"example.com/grafana/alloy-config-tool:1":   "no metrics agent found",
			"example.com/team/not-telegraf-but-similar": "no metrics agent found",
		} {
			if got := agentMsg(withContainer(image, true)); !strings.Contains(got, want) {
				t.Errorf("image %s: %q, want %q", image, got, want)
			}
		}
		if got := agentMsg(withContainer("grafana/alloy", false)); !strings.Contains(got, "no metrics agent found") {
			t.Errorf("stopped container counted: %q", got)
		}
		viaProcess := journalFacts(nil)
		viaProcess.Listeners = &facts.Listeners{Sockets: []facts.Listener{{Proto: "tcp", Port: 9100, Processes: []string{"node_exporter"}}}}
		if got := agentMsg(viaProcess); !strings.Contains(got, "node_exporter (process)") {
			t.Errorf("process: %q", got)
		}
		both := journalFacts(func(j *facts.Journal) { j.Agents = []string{"alloy"} })
		both.Docker = &facts.Docker{Containers: []facts.DockerContainer{{Name: "mon", Image: "grafana/alloy", Running: true}}}
		if got := agentMsg(both); got != "metrics agent found: alloy (container mon)" {
			t.Errorf("merged: %q", got)
		}
	})
	t.Run("005", func(t *testing.T) {
		runLevels(t, checkJournalPersistent, []levelCase{
			{"nil", &facts.Facts{}, Unknown},
			{"persistent", journalFacts(nil), Pass},
			{"volatile", journalFacts(func(j *facts.Journal) { j.Persistent = false }), Warn},
		})
	})
}

func TestHumanBytes(t *testing.T) {
	for n, want := range map[int64]string{512: "512 B", 1536: "1.5 KiB", 3 << 30: "3.0 GiB"} {
		if got := humanBytes(n); got != want {
			t.Errorf("%d: %s", n, got)
		}
	}
}

func TestSYS004And005(t *testing.T) {
	clock := func(sync, enabled, can bool) *facts.Facts {
		return &facts.Facts{Clock: &facts.Clock{NTPSynchronized: sync, NTPEnabled: enabled, CanNTP: can}}
	}
	runLevels(t, checkTimeSync, []levelCase{
		{"nil", &facts.Facts{}, Unknown},
		{"synced", clock(true, true, true), Pass},
		{"not synced", clock(false, true, true), Warn},
		{"off", clock(false, false, true), Warn},
		{"no service", clock(false, false, false), Warn},
	})
	disk := func(pcts ...int) *facts.Facts {
		d := &facts.Disk{}
		for i, p := range pcts {
			d.Mounts = append(d.Mounts, facts.DiskMount{Path: []string{"/", "/var", "/var/lib/docker"}[i], Mount: []string{"/", "/var", "/var/lib/docker"}[i], UsedPercent: p})
		}
		return &facts.Facts{Disk: d}
	}
	runLevels(t, checkDiskUsage, []levelCase{
		{"nil", &facts.Facts{}, Unknown},
		{"empty", &facts.Facts{Disk: &facts.Disk{}}, Unknown},
		{"fine", disk(40, 85), Pass},
		{"warn", disk(40, 86), Warn},
		{"fail", disk(96), Fail},
		{"worst wins", disk(10, 90, 96), Fail},
	})
	same := &facts.Facts{Disk: &facts.Disk{Mounts: []facts.DiskMount{{Path: "/", Mount: "/", UsedPercent: 90}, {Path: "/var", Mount: "/", UsedPercent: 90}}}}
	if rs := checkDiskUsage(Input{Facts: same}); len(rs) != 1 {
		t.Errorf("paths on one filesystem must give one result: %v", rs)
	}
}

func TestSysctlFixes(t *testing.T) {
	if SysctlFixes(nil) != nil {
		t.Error("nil facts must give no fixes")
	}
	good := allOK(netBaseline)
	for k, v := range allOK(kernelBaseline) {
		good[k] = v
	}
	good[keyRPFilterAll], good[keyRPFilterDef] = "2", "2"
	good[keyIPForward] = "0"
	if got := SysctlFixes(sysctlFacts(true, false, good).Sysctl); len(got) != 0 {
		t.Errorf("baseline values gave fixes (ip_forward must never be one): %v", got)
	}
	bad := map[string]string{}
	for k, v := range good {
		bad[k] = v
	}
	bad[keyRPFilterAll] = "1"
	bad["net.ipv4.conf.all.accept_redirects"] = "1"
	bad["kernel.kptr_restrict"] = "0"
	f := sysctlFacts(true, false, bad)
	want := []SysctlFix{
		{"KRN-002", keyRPFilterAll, 1, 2},
		{"KRN-003", "net.ipv4.conf.all.accept_redirects", 1, 0},
		{"KRN-004", "kernel.kptr_restrict", 0, 1},
	}
	got := SysctlFixes(f.Sysctl)
	if len(got) != len(want) {
		t.Fatalf("fixes %v, want %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Errorf("fix %d: %v, want %v", i, got[i], want[i])
		}
	}
	// Strict rp_filter is only a finding with Docker or Tailscale.
	if got := SysctlFixes(sysctlFacts(false, false, map[string]string{keyRPFilterAll: "1"}).Sysctl); len(got) != 0 {
		t.Errorf("rp_filter fixed without Docker or Tailscale: %v", got)
	}
}
