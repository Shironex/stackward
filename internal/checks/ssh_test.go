package checks

import (
	"io/fs"
	"strings"
	"testing"

	"github.com/Shironex/stackward/internal/facts"
	"github.com/Shironex/stackward/internal/facts/sshd"
)

// hardened is a root sshd -T result that passes every config check.
func sshHardened() *facts.SSH {
	return &facts.SSH{
		Installed: true, Source: "sshd -T", Complete: true,
		Effective: map[string][]string{
			"passwordauthentication":       {"no"},
			"kbdinteractiveauthentication": {"no"},
			"permitrootlogin":              {"no"},
			"permitemptypasswords":         {"no"},
			"maxauthtries":                 {"3"},
			"allowusers":                   {"alice", "deploy"},
			"x11forwarding":                {"no"},
			"allowagentforwarding":         {"no"},
			"authenticationmethods":        {"any"},
			"port":                         {"22"},
			"listenaddress":                {"[::]:22", "0.0.0.0:22"},
			"kexalgorithms":                {"sntrup761x25519-sha512@openssh.com,curve25519-sha256"},
			"ciphers":                      {"chacha20-poly1305@openssh.com,aes256-gcm@openssh.com"},
			"macs":                         {"hmac-sha2-256-etm@openssh.com,hmac-sha2-512-etm@openssh.com"},
		},
		Config:    &sshd.Config{Files: []sshd.File{{Path: "/etc/ssh/sshd_config", Readable: true}}},
		Socket:    &facts.SSHSocket{Unit: "ssh.socket", LoadState: "not-found"},
		Listening: []string{"0.0.0.0:22", "[::]:22"}, ListeningInspected: true,
		PAMInspected: true,
	}
}

// nonRoot is the files fallback with an unreadable cloud-init drop-in.
func sshNonRoot() *facts.SSH {
	return &facts.SSH{
		Installed: true, Source: "files", SshdTError: "not root",
		Effective: map[string][]string{"permitrootlogin": {"no"}},
		Config: &sshd.Config{Files: []sshd.File{
			{Path: "/etc/ssh/sshd_config", Readable: true},
			{Path: "/etc/ssh/sshd_config.d/50-cloud-init.conf", Error: "permission denied"},
		}},
		ListeningInspected: true, Listening: []string{"*:22"},
	}
}

func sshWith(s *facts.SSH, kv ...string) *facts.SSH {
	for i := 0; i+1 < len(kv); i += 2 {
		if kv[i+1] == "" {
			delete(s.Effective, kv[i])
		} else {
			s.Effective[kv[i]] = strings.Fields(kv[i+1])
		}
	}
	return s
}

// withMatch appends a Match block setting keyword to value.
func sshMatch(s *facts.SSH, criteria, keyword, value string) *facts.SSH {
	s.Config.Matches = append(s.Config.Matches, sshd.Match{Criteria: criteria, File: "/etc/ssh/sshd_config", Line: 40})
	s.Config.Directives = append(s.Config.Directives, sshd.Directive{Keyword: keyword, Value: value,
		File: "/etc/ssh/sshd_config", Line: 41, Match: len(s.Config.Matches)})
	return s
}

func runSSH(t *testing.T, fn func(Input) []Result, s *facts.SSH) []Result {
	t.Helper()
	f := &facts.Facts{SSH: s, Host: &facts.Host{Root: s != nil && s.Source == "sshd -T"},
		Collectors: []facts.CollectorStatus{{Name: "ssh", Status: facts.StatusOK}}}
	rs := fn(Input{Facts: f})
	if len(rs) == 0 {
		t.Fatal("no result")
	}
	return rs
}

type sshCase struct {
	name string
	s    *facts.SSH
	want Level
}

func runCases(t *testing.T, id string, fn func(Input) []Result, cases []sshCase) {
	t.Helper()
	cases = append(cases,
		sshCase{"not inspected", nil, Unknown},
		sshCase{"not installed", &facts.SSH{Installed: false}, Skip},
	)
	for _, tc := range cases {
		rs := runSSH(t, fn, tc.s)
		if len(rs) != 1 {
			t.Errorf("%s %s: want one result, got %+v", id, tc.name, rs)
			continue
		}
		if rs[0].Level != tc.want {
			t.Errorf("%s %s: got %s (%s), want %s", id, tc.name, rs[0].Level, rs[0].Message, tc.want)
		}
	}
}

func TestSSH001(t *testing.T) {
	runCases(t, "SSH-001", checkPasswordAuth, []sshCase{
		{"off", sshHardened(), Pass},
		{"on", sshWith(sshHardened(), "passwordauthentication", "yes"), Fail},
		{"on, second factor only", sshWith(sshHardened(), "passwordauthentication", "yes", "authenticationmethods", "publickey,password"), Warn},
		{"on, not offered", sshWith(sshHardened(), "passwordauthentication", "yes", "authenticationmethods", "publickey"), Warn},
		{"on, one list allows it alone", sshWith(sshHardened(), "passwordauthentication", "yes", "authenticationmethods", "publickey,password password"), Fail},
		{"match user", sshMatch(sshHardened(), "User deploy", "passwordauthentication", "yes"), Warn},
		{"match all", sshMatch(sshHardened(), "all", "passwordauthentication", "yes"), Fail},
		{"match turning it off is fine", sshMatch(sshHardened(), "User deploy", "passwordauthentication", "no"), Pass},
		{"unreadable drop-in", sshNonRoot(), Unknown},
	})
	rs := runSSH(t, checkPasswordAuth, sshNonRoot())
	if !strings.Contains(rs[0].Message, "50-cloud-init.conf (permission denied)") || strings.Contains(rs[0].Message, "sudo") {
		t.Errorf("unknown message should name the file and leave the sudo hint to the report: %q", rs[0].Message)
	}
}

func TestSSH001FirstMatchValueWins(t *testing.T) {
	s := sshMatch(sshHardened(), "User deploy", "passwordauthentication", "no")
	// A second line in the same block is ignored by sshd.
	s.Config.Directives = append(s.Config.Directives, sshd.Directive{Keyword: "passwordauthentication", Value: "yes", Match: 1})
	if l := runSSH(t, checkPasswordAuth, s)[0].Level; l != Pass {
		t.Fatalf("got %s", l)
	}
}

func TestSSH002(t *testing.T) {
	pam := sshWith(sshHardened(), "kbdinteractiveauthentication", "yes")
	pam.PAM2FA = []string{"pam_google_authenticator"}
	runCases(t, "SSH-002", checkKbdInteractive, []sshCase{
		{"off", sshHardened(), Pass},
		{"on", sshWith(sshHardened(), "kbdinteractiveauthentication", "yes"), Fail},
		{"on with pam 2fa", pam, Warn},
		{"on after key", sshWith(sshHardened(), "kbdinteractiveauthentication", "yes", "authenticationmethods", "publickey,keyboard-interactive:pam"), Warn},
		{"match", sshMatch(sshHardened(), "Address 192.0.2.0/24", "kbdinteractiveauthentication", "yes"), Warn},
		{"unknown", sshNonRoot(), Unknown},
	})
}

func TestSSH003(t *testing.T) {
	runCases(t, "SSH-003", checkRootLogin, []sshCase{
		{"no", sshHardened(), Pass},
		{"yes", sshWith(sshHardened(), "permitrootlogin", "yes"), Fail},
		{"prohibit-password", sshWith(sshHardened(), "permitrootlogin", "prohibit-password"), Warn},
		{"without-password", sshWith(sshHardened(), "permitrootlogin", "without-password"), Warn},
		{"forced-commands-only", sshWith(sshHardened(), "permitrootlogin", "forced-commands-only"), Warn},
		{"match address yes", sshMatch(sshHardened(), "Address 192.0.2.5", "permitrootlogin", "yes"), Warn},
		{"match all yes", sshMatch(sshHardened(), "all", "permitrootlogin", "yes"), Fail},
		{"known before unreadable file", sshNonRoot(), Pass},
		{"unknown", sshWith(sshNonRoot(), "permitrootlogin", ""), Unknown},
	})
}

func TestSSH004(t *testing.T) {
	runCases(t, "SSH-004", checkEmptyPasswords, []sshCase{
		{"no", sshHardened(), Pass},
		{"yes", sshWith(sshHardened(), "permitemptypasswords", "yes"), Fail},
		{"match", sshMatch(sshHardened(), "User kiosk", "permitemptypasswords", "yes"), Fail},
		{"unknown", sshNonRoot(), Unknown},
	})
}

func TestSSH005(t *testing.T) {
	runCases(t, "SSH-005", checkMaxAuthTries, []sshCase{
		{"3", sshHardened(), Pass},
		{"4", sshWith(sshHardened(), "maxauthtries", "4"), Pass},
		{"6", sshWith(sshHardened(), "maxauthtries", "6"), Warn},
		{"match raises", sshMatch(sshHardened(), "User ci", "maxauthtries", "10"), Warn},
		{"garbage", sshWith(sshHardened(), "maxauthtries", "lots"), Unknown},
		{"unknown", sshNonRoot(), Unknown},
	})
}

func TestSSH006(t *testing.T) {
	groupsOnly := sshWith(sshHardened(), "allowusers", "", "allowgroups", "sshusers")
	partial := sshNonRoot()
	partial.Effective["allowgroups"] = []string{"admins"} // cannot happen for accumulating keywords, but a value wins
	runCases(t, "SSH-006", checkAllowList, []sshCase{
		{"users", sshHardened(), Pass},
		{"groups", groupsOnly, Pass},
		{"none", sshWith(sshHardened(), "allowusers", ""), Warn},
		{"unknown", sshNonRoot(), Unknown},
		{"partial with value", partial, Pass},
	})
}

func TestSSH007(t *testing.T) {
	runCases(t, "SSH-007", checkForwarding, []sshCase{
		{"off", sshHardened(), Pass},
		{"x11", sshWith(sshHardened(), "x11forwarding", "yes"), Warn},
		{"agent", sshWith(sshHardened(), "allowagentforwarding", "yes"), Warn},
		{"match", sshMatch(sshHardened(), "User dev", "x11forwarding", "yes"), Warn},
		{"unknown", sshNonRoot(), Unknown},
		{"one known yes is enough", sshWith(sshNonRoot(), "x11forwarding", "yes"), Warn},
	})
}

func sshDropIns(dirs ...sshd.Directive) *facts.SSH {
	s := sshHardened()
	s.Config.Files = append(s.Config.Files,
		sshd.File{Path: "/etc/ssh/sshd_config.d/50-cloud-init.conf", Readable: true},
		sshd.File{Path: "/etc/ssh/sshd_config.d/60-harden.conf", Readable: true})
	s.Config.Directives = dirs
	return s
}

func TestSSH008(t *testing.T) {
	cloud := sshd.Directive{Keyword: "passwordauthentication", Value: "yes", File: "/etc/ssh/sshd_config.d/50-cloud-init.conf", Line: 1}
	harden := sshd.Directive{Keyword: "passwordauthentication", Value: "no", File: "/etc/ssh/sshd_config.d/60-harden.conf", Line: 1}
	rootEarly := sshd.Directive{Keyword: "permitrootlogin", Value: "prohibit-password", File: "/etc/ssh/sshd_config.d/50-cloud-init.conf", Line: 2}
	rootLate := sshd.Directive{Keyword: "permitrootlogin", Value: "no", File: "/etc/ssh/sshd_config.d/60-harden.conf", Line: 2}
	inMatch := harden
	inMatch.Match = 1

	runCases(t, "SSH-008", checkDropInOrder, []sshCase{
		{"good order", sshDropIns(harden, cloud), Pass},
		{"shadowed", sshDropIns(cloud, harden), Warn},
		{"two keywords one file", sshDropIns(cloud, rootEarly, harden, rootLate), Warn},
		{"match lines are not global", sshDropIns(cloud, inMatch), Pass},
		{"unreadable", sshNonRoot(), Unknown},
	})
	rs := runSSH(t, checkDropInOrder, sshDropIns(cloud, rootEarly, harden, rootLate))
	if rs[0].Subject != "file:/etc/ssh/sshd_config.d/50-cloud-init.conf" || len(rs[0].Evidence["settings"].([]shadowed)) != 2 {
		t.Errorf("result = %+v", rs[0])
	}
	if !strings.Contains(rs[0].Message, "passwordauthentication yes (line 1) wins over no in /etc/ssh/sshd_config.d/60-harden.conf line 1") {
		t.Errorf("message = %q", rs[0].Message)
	}
}

func TestSSH009(t *testing.T) {
	files := sshHardened()
	files.Source = "files"
	matched := sshHardened()
	matched.Source = "files"
	sshMatch(matched, "User deploy", "x11forwarding", "yes")
	runCases(t, "SSH-009", checkMatchCoverage, []sshCase{
		{"sshd -T", sshHardened(), Skip},
		{"files, no match", files, Pass},
		{"files, match", matched, Unknown},
		{"partial", sshNonRoot(), Unknown},
	})
}

func TestSSH010(t *testing.T) {
	sock := func(s *facts.SSH, listen ...string) *facts.SSH {
		s.Socket = &facts.SSHSocket{Unit: "ssh.socket", LoadState: "loaded", ActiveState: "active", Listen: listen}
		return s
	}
	moved := sock(sshWith(sshHardened(), "port", "2222", "listenaddress", "[::]:2222 0.0.0.0:2222"), "[::]:22")
	moved.Listening = []string{"*:22"}
	dual := sock(sshHardened(), "[::]:22")
	dual.Listening = []string{"*:22"}
	v6only := sshHardened()
	v6only.Listening = []string{"[::]:22"}
	specific := sshWith(sshHardened(), "listenaddress", "192.0.2.10:22 [2001:db8::10]:22")
	named := sshWith(sshHardened(), "listenaddress", "ssh.example.com:22")
	noSS := sshHardened()
	noSS.ListeningInspected, noSS.ListeningError = false, "ss not found"
	// listenAt sets ListenAddress in the files as well as in sshd -T.
	listenAt := func(s *facts.SSH, addrs ...string) *facts.SSH {
		s = sshWith(s, "listenaddress", strings.Join(addrs, " "))
		for i, a := range addrs {
			s.Config.Directives = append(s.Config.Directives, sshd.Directive{Keyword: "listenaddress", Value: a, File: "/etc/ssh/sshd_config", Line: 10 + i})
		}
		return s
	}
	pinned := sock(listenAt(sshHardened(), "100.64.0.7:22", "10.0.0.7:22"), "100.64.0.7:22", "10.0.0.7:22")
	pinned.Listening = []string{"100.64.0.7:22", "10.0.0.7:22"}
	ignored := sock(listenAt(sshHardened(), "100.64.0.7:22"), "[::]:22")
	ignored.Listening = []string{"*:22"}
	extra := sock(listenAt(sshHardened(), "100.64.0.7:22"), "100.64.0.7:22", "192.0.2.10:22")
	extra.Listening = []string{"100.64.0.7:22", "192.0.2.10:22"}
	extraPort := sock(sshHardened(), "[::]:22", "[::]:2222")
	extraPort.Listening = []string{"*:22", "*:2222"}
	runCases(t, "SSH-010", checkListeners, []sshCase{
		{"plain match", sshHardened(), Pass},
		{"socket activation, no ListenAddress", dual, Pass},
		{"socket on tailnet and private, matching ListenAddress", pinned, Pass},
		{"ListenAddress the socket ignores", ignored, Warn},
		{"socket listens beyond ListenAddress", extra, Warn},
		{"socket on another port, no ListenAddress", extraPort, Warn},
		{"port moved without socket restart", moved, Fail},
		{"v4 not listening", v6only, Fail},
		{"specific covered by wildcard", specific, Pass},
		{"host name", named, Unknown},
		{"no ss", noSS, Unknown},
		{"config unknown", sshNonRoot(), Unknown},
	})
	rs := runSSH(t, checkListeners, moved)
	if !strings.Contains(rs[0].Message, "daemon-reload") || !strings.Contains(rs[0].Message, "2222") {
		t.Errorf("message = %q", rs[0].Message)
	}
}

func sshMeta(perm fs.FileMode, uid int) *facts.FileMeta {
	return &facts.FileMeta{Mode: perm, UID: uid}
}

func TestSSH012(t *testing.T) {
	hostKeys := func(k ...facts.SSHHostKey) *facts.SSH { s := sshHardened(); s.HostKeys = k; return s }
	ed := facts.SSHHostKey{Path: "/etc/ssh/ssh_host_ed25519_key", Configured: true, Meta: sshMeta(0o600, 0), Type: "ssh-ed25519", Bits: 256}
	rsaSmall := facts.SSHHostKey{Path: "/etc/ssh/ssh_host_rsa_key", Meta: sshMeta(0o600, 0), Type: "ssh-rsa", Bits: 2048}
	rsaNoPub := facts.SSHHostKey{Path: "/etc/ssh/ssh_host_rsa_key", Meta: sshMeta(0o600, 0)}
	dsa := facts.SSHHostKey{Path: "/etc/ssh/ssh_host_dsa_key", Meta: sshMeta(0o600, 0), Type: "ssh-dss", Bits: 1024}
	worldReadable := ed
	worldReadable.Meta = sshMeta(0o644, 0)
	groupReadable := ed
	groupReadable.Meta = sshMeta(0o640, 0)
	owned := ed
	owned.Meta = sshMeta(0o600, 1000)
	noMeta := ed
	noMeta.Meta, noMeta.MetaError = nil, "permission denied"
	runCases(t, "SSH-012", checkHostKeys, []sshCase{
		{"ed25519", hostKeys(ed), Pass},
		{"small rsa", hostKeys(rsaSmall), Warn},
		{"rsa size unknown", hostKeys(rsaNoPub), Unknown},
		{"dsa", hostKeys(dsa), Warn},
		{"world readable", hostKeys(worldReadable), Fail},
		{"group readable", hostKeys(groupReadable), Warn},
		{"wrong owner", hostKeys(owned), Fail},
		{"no meta", hostKeys(noMeta), Unknown},
		{"none found", hostKeys(), Unknown},
	})
	rs := runSSH(t, checkHostKeys, hostKeys(ed, dsa))
	if len(rs) != 2 || rs[1].Subject != "file:/etc/ssh/ssh_host_dsa_key" {
		t.Errorf("one result per key file: %+v", rs)
	}
}

func sshUser(name string, uid int, home, dir, ak fs.FileMode, keys ...sshd.PubKey) facts.SSHUser {
	return facts.SSHUser{Name: name, UID: uid, Home: "/home/" + name,
		HomeMeta: sshMeta(home, uid), SSHDir: sshMeta(dir, uid),
		KeyFiles: []facts.SSHKeyFile{{Path: "/home/" + name + "/.ssh/authorized_keys", Meta: sshMeta(ak, uid), Keys: keys}}}
}

func sshUsers(u ...facts.SSHUser) *facts.SSH { s := sshHardened(); s.Users = u; return s }

var ed25519Key = sshd.PubKey{Type: "ssh-ed25519", Bits: 256}

func TestSSH013(t *testing.T) {
	denied := facts.SSHUser{Name: "bob", UID: 1001, Home: "/home/bob", Error: "/home/bob: permission denied"}
	foreign := sshUser("alice", 1000, 0o750, 0o700, 0o600)
	foreign.KeyFiles[0].Meta.UID = 1002
	unreadableKeys := sshUser("alice", 1000, 0o750, 0o700, 0o600)
	unreadableKeys.KeyFiles[0].Meta, unreadableKeys.KeyFiles[0].Error = nil, "permission denied"
	pp := sshUsers(sshUser("alice", 1000, 0o750, 0o700, 0o600))
	pp.UsersError = "permission denied"
	runCases(t, "SSH-013", checkSSHFileModes, []sshCase{
		{"private", sshUsers(sshUser("alice", 1000, 0o750, 0o700, 0o600)), Pass},
		{"authorized_keys 0644 is fine", sshUsers(sshUser("alice", 1000, 0o755, 0o700, 0o644)), Pass},
		{"authorized_keys group writable", sshUsers(sshUser("alice", 1000, 0o750, 0o700, 0o664)), Fail},
		{"ssh dir 0755", sshUsers(sshUser("alice", 1000, 0o750, 0o755, 0o600)), Warn},
		{"ssh dir world writable", sshUsers(sshUser("alice", 1000, 0o750, 0o777, 0o600)), Fail},
		{"home group writable", sshUsers(sshUser("alice", 1000, 0o775, 0o700, 0o600)), Fail},
		{"key file owned by another user", sshUsers(foreign), Fail},
		{"key file unreadable", sshUsers(unreadableKeys), Unknown},
		{"home denied", sshUsers(denied), Unknown},
		{"no users", sshUsers(), Skip},
		{"passwd unreadable", pp, Unknown},
	})
	asUser := sshUsers(denied)
	asUser.Source = "files" // run() marks only sshd -T facts as root
	rs := runSSH(t, checkSSHFileModes, asUser)
	if !strings.Contains(rs[0].Message, "/home/bob") || strings.Contains(rs[0].Message, "sudo") {
		t.Errorf("non root unknown should name the path and leave the sudo hint to the report: %q", rs[0].Message)
	}
}

func TestSSH014(t *testing.T) {
	root := sshUser("root", 0, 0o700, 0o700, 0o600, ed25519Key)
	root.Home = "/root"
	weakRSA := sshUser("alice", 1000, 0o750, 0o700, 0o600, sshd.PubKey{Type: "ssh-rsa", Bits: 1024}, ed25519Key)
	dss := sshUser("alice", 1000, 0o750, 0o700, 0o600, sshd.PubKey{Type: "ssh-dss", Bits: 1024})
	unread := sshUser("alice", 1000, 0o750, 0o700, 0o600)
	unread.KeyFiles[0].Error = "permission denied"
	rootAllowed := sshUsers(root)
	rootAllowed.Effective["permitrootlogin"] = []string{"prohibit-password"}
	runCases(t, "SSH-014", checkAuthorizedKeyTypes, []sshCase{
		{"ed25519", sshUsers(sshUser("alice", 1000, 0o750, 0o700, 0o600, ed25519Key)), Pass},
		{"rsa 4096", sshUsers(sshUser("alice", 1000, 0o750, 0o700, 0o600, sshd.PubKey{Type: "ssh-rsa", Bits: 4096})), Pass},
		{"rsa 1024", sshUsers(weakRSA), Warn},
		{"dsa", sshUsers(dss), Warn},
		{"stale root keys", sshUsers(root), Warn},
		{"root keys in use", rootAllowed, Pass},
		{"unreadable", sshUsers(unread), Unknown},
		{"empty key file", sshUsers(sshUser("alice", 1000, 0o750, 0o700, 0o600)), Skip},
		{"no users", sshUsers(), Skip},
	})
}

// TestSSH014Fingerprints: the fingerprints of a user's keys go into the
// evidence, sorted, so stackward diff can name a new authorized key; a
// key without one (an old facts file) leaves the field out.
func TestSSH014Fingerprints(t *testing.T) {
	a := sshd.PubKey{Type: "ssh-ed25519", Bits: 256, Fingerprint: "SHA256:bbbb"}
	b := sshd.PubKey{Type: "ssh-ed25519", Bits: 256, Fingerprint: "SHA256:aaaa"}
	rs := runSSH(t, checkAuthorizedKeyTypes, sshUsers(sshUser("alice", 1000, 0o750, 0o700, 0o600, a, b)))
	if got, ok := rs[0].Evidence["fingerprints"].([]string); !ok || strings.Join(got, ",") != "SHA256:aaaa,SHA256:bbbb" {
		t.Errorf("fingerprints = %v", rs[0].Evidence["fingerprints"])
	}
	rs = runSSH(t, checkAuthorizedKeyTypes, sshUsers(sshUser("alice", 1000, 0o750, 0o700, 0o600, ed25519Key)))
	if _, ok := rs[0].Evidence["fingerprints"]; ok {
		t.Errorf("no fingerprint known, the field should be absent: %v", rs[0].Evidence)
	}
}

func TestSSH015(t *testing.T) {
	plus := sshWith(sshHardened(), "macs", "+hmac-sha1")
	plusGood := sshWith(sshHardened(), "macs", "+hmac-sha2-512")
	minus := sshWith(sshHardened(), "ciphers", "-aes128-cbc")
	files := sshWith(sshHardened(), "kexalgorithms", "", "ciphers", "", "macs", "")
	files.Source, files.SshdTError = "files", "not root"
	runCases(t, "SSH-015", checkWeakAlgorithms, []sshCase{
		{"modern", sshHardened(), Pass},
		{"stock macs", sshWith(sshHardened(), "macs", "umac-64-etm@openssh.com,hmac-sha2-256-etm@openssh.com,hmac-sha1"), Warn},
		{"cbc", sshWith(sshHardened(), "ciphers", "aes128-ctr,aes256-cbc"), Warn},
		{"sha1 kex", sshWith(sshHardened(), "kexalgorithms", "curve25519-sha256,diffie-hellman-group14-sha1"), Warn},
		{"gss prefix", sshWith(sshHardened(), "kexalgorithms", "gss-group14-sha1-toWM5Slw5Ew8Mqkay+al2g=="), Warn},
		{"appended weak", plus, Warn},
		{"appended strong, default unknown", plusGood, Unknown},
		{"removal from default", minus, Unknown},
		{"not set in files", files, Unknown},
	})
}
