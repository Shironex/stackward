package sshd

import (
	"io/fs"
	"path"
	"reflect"
	"strings"
	"testing"
	"testing/fstest"
)

// memFS is an in memory tree where some paths answer permission denied, as
// root owned 0600 drop-ins do for a non root audit.
type memFS struct {
	m      fstest.MapFS
	denied map[string]bool
}

func newMemFS(files map[string]string, denied ...string) *memFS {
	m := fstest.MapFS{}
	for p, body := range files {
		m[strings.TrimPrefix(p, "/")] = &fstest.MapFile{Data: []byte(body), Mode: 0o644}
	}
	d := map[string]bool{}
	for _, p := range denied {
		d[p] = true
	}
	return &memFS{m: m, denied: d}
}

func (f *memFS) ReadFile(p string) ([]byte, error) {
	if f.denied[p] {
		return nil, &fs.PathError{Op: "open", Path: p, Err: fs.ErrPermission}
	}
	return fs.ReadFile(f.m, strings.TrimPrefix(path.Clean(p), "/"))
}

func (f *memFS) ReadDir(p string) ([]fs.DirEntry, error) {
	if f.denied[p] {
		return nil, &fs.PathError{Op: "open", Path: p, Err: fs.ErrPermission}
	}
	return fs.ReadDir(f.m, strings.TrimPrefix(path.Clean(p), "/"))
}

const ubuntuMain = `# Ubuntu style main file
Include /etc/ssh/sshd_config.d/*.conf

KbdInteractiveAuthentication no
UsePAM yes
X11Forwarding yes
PrintMotd no
AcceptEnv LANG LC_*
Subsystem	sftp	/usr/lib/openssh/sftp-server
`

func TestFirstValueWinsAcrossDropIns(t *testing.T) {
	// The trap: cloud-init's 50- drop-in sorts before a hardening file
	// named 60-, so its "yes" wins and the later "no" is ignored.
	fsys := newMemFS(map[string]string{
		"/etc/ssh/sshd_config":                       ubuntuMain,
		"/etc/ssh/sshd_config.d/50-cloud-init.conf":  "PasswordAuthentication yes\n",
		"/etc/ssh/sshd_config.d/60-hardening.conf":   "PasswordAuthentication no\nPermitRootLogin no\n",
		"/etc/ssh/sshd_config.d/10-early.conf":       "MaxAuthTries 3\n",
		"/etc/ssh/sshd_config.d/README":              "PasswordAuthentication no\n", // not *.conf
		"/etc/ssh/sshd_config.d/.hidden.conf":        "PasswordAuthentication no\n", // * skips dot files
		"/etc/ssh/sshd_config.d/Z-upper-first.conf":  "LoginGraceTime 30\n",
		"/etc/ssh/sshd_config.d/99-late.conf":        "MaxAuthTries 6\nX11Forwarding no\n",
		"/etc/ssh/sshd_config.d/99-late.conf.dpkg-o": "PermitRootLogin yes\n",
	})
	c := Parse(fsys, "/etc/ssh/sshd_config")
	var order []string
	for _, f := range c.Files {
		order = append(order, f.Path)
	}
	want := []string{
		"/etc/ssh/sshd_config",
		"/etc/ssh/sshd_config.d/10-early.conf",
		"/etc/ssh/sshd_config.d/50-cloud-init.conf",
		"/etc/ssh/sshd_config.d/60-hardening.conf",
		"/etc/ssh/sshd_config.d/99-late.conf",
		"/etc/ssh/sshd_config.d/Z-upper-first.conf", // byte order: digits < upper case
	}
	if !reflect.DeepEqual(order, want) {
		t.Fatalf("read order\n got %v\nwant %v", order, want)
	}
	if !c.Complete {
		t.Fatal("all files readable, want Complete")
	}
	checks := map[string]string{
		"passwordauthentication":       "yes", // 50- beats 60-
		"permitrootlogin":              "no",
		"maxauthtries":                 "3",  // 10- beats 99-
		"x11forwarding":                "no", // drop-ins (included first) beat the main file
		"kbdinteractiveauthentication": "no",
		"logingracetime":               "30",
		"allowagentforwarding":         "yes", // built in default
	}
	for k, v := range checks {
		if got := c.Effective[k]; len(got) != 1 || got[0] != v {
			t.Errorf("%s = %v, want %s", k, got, v)
		}
	}
	if got := c.Effective["acceptenv"]; !reflect.DeepEqual(got, []string{"LANG", "LC_*"}) {
		t.Errorf("acceptenv = %v", got)
	}
	if !contains(c.Defaulted, "allowagentforwarding") || contains(c.Defaulted, "passwordauthentication") {
		t.Errorf("defaulted = %v", c.Defaulted)
	}
	if got := c.Effective["listenaddress"]; !reflect.DeepEqual(got, []string{"[::]:22", "0.0.0.0:22"}) {
		t.Errorf("listenaddress = %v", got)
	}
}

func contains(xs []string, x string) bool {
	for _, v := range xs {
		if v == x {
			return true
		}
	}
	return false
}

func TestIncludeBeforeAndAfter(t *testing.T) {
	// Lines before an Include win over the included file; lines after
	// lose to it.
	fsys := newMemFS(map[string]string{
		"/etc/ssh/sshd_config": "PermitRootLogin no\nInclude extra.conf\nPasswordAuthentication yes\n",
		"/etc/ssh/extra.conf":  "PermitRootLogin yes\nPasswordAuthentication no\n",
	})
	c := Parse(fsys, "/etc/ssh/sshd_config")
	if c.Effective["permitrootlogin"][0] != "no" || c.Effective["passwordauthentication"][0] != "no" {
		t.Fatalf("effective = %v", c.Effective)
	}
}

func TestMultiplePatternsAndNesting(t *testing.T) {
	fsys := newMemFS(map[string]string{
		"/etc/ssh/sshd_config":      "Include b.conf a/*.conf missing.conf nomatch/*.conf\n",
		"/etc/ssh/b.conf":           "Include /etc/ssh/nested/*.conf\n",
		"/etc/ssh/nested/1.conf":    "Port 2222\n",
		"/etc/ssh/a/2.conf":         "Port 2200\nListenAddress 192.0.2.10\nListenAddress [2001:db8::1]:2022\n",
		"/etc/ssh/a/sub/ignored.cf": "Port 1\n",
	})
	c := Parse(fsys, "/etc/ssh/sshd_config")
	var order []string
	for _, f := range c.Files {
		order = append(order, f.Path)
	}
	want := []string{"/etc/ssh/sshd_config", "/etc/ssh/b.conf", "/etc/ssh/nested/1.conf", "/etc/ssh/a/2.conf"}
	if !reflect.DeepEqual(order, want) {
		t.Fatalf("order %v, want %v", order, want)
	}
	if !c.Complete {
		t.Fatal("a missing include is ignored by sshd and must not break completeness")
	}
	if got := c.Effective["port"]; !reflect.DeepEqual(got, []string{"2222", "2200"}) {
		t.Errorf("port = %v", got)
	}
	wantLA := []string{"192.0.2.10:2222", "192.0.2.10:2200", "[2001:db8::1]:2022"}
	if got := c.Effective["listenaddress"]; !reflect.DeepEqual(got, wantLA) {
		t.Errorf("listenaddress = %v, want %v", got, wantLA)
	}
}

func TestIncludeDepthLimit(t *testing.T) {
	fsys := newMemFS(map[string]string{"/etc/ssh/sshd_config": "Include /etc/ssh/sshd_config\n"})
	c := Parse(fsys, "/etc/ssh/sshd_config")
	if len(c.Problems) == 0 || !strings.Contains(c.Problems[0], "deeper than 16") {
		t.Fatalf("problems = %v", c.Problems)
	}
	if len(c.Files) != MaxDepth+1 {
		t.Errorf("read %d files, want %d", len(c.Files), MaxDepth+1)
	}
}

func TestUnreadableDropIn(t *testing.T) {
	// Non root on Ubuntu 24.04: 50-cloud-init.conf is 0600. Keywords set
	// before it stay known; anything it could set first becomes unknown.
	fsys := newMemFS(map[string]string{
		"/etc/ssh/sshd_config":                      ubuntuMain,
		"/etc/ssh/sshd_config.d/10-hardening.conf":  "PermitRootLogin no\nAllowUsers alice\n",
		"/etc/ssh/sshd_config.d/50-cloud-init.conf": "PasswordAuthentication yes\n",
	}, "/etc/ssh/sshd_config.d/50-cloud-init.conf")
	c := Parse(fsys, "/etc/ssh/sshd_config")
	if c.Complete {
		t.Fatal("want incomplete")
	}
	if got := c.Unreadable(); !reflect.DeepEqual(got, []string{"/etc/ssh/sshd_config.d/50-cloud-init.conf"}) {
		t.Fatalf("unreadable = %v", got)
	}
	if c.Files[2].Error != "permission denied" {
		t.Errorf("error = %q", c.Files[2].Error)
	}
	if c.Effective["permitrootlogin"][0] != "no" {
		t.Error("PermitRootLogin was set before the unreadable file and must stay known")
	}
	for _, k := range []string{"passwordauthentication", "kbdinteractiveauthentication", "allowusers", "port", "listenaddress", "allowagentforwarding"} {
		if v, ok := c.Effective[k]; ok {
			t.Errorf("%s = %v, want unknown", k, v)
		}
	}
	if len(c.Defaulted) != 0 {
		t.Errorf("no defaults may apply when incomplete: %v", c.Defaulted)
	}
}

func TestUnreadableDirectory(t *testing.T) {
	fsys := newMemFS(map[string]string{
		"/etc/ssh/sshd_config":          "Include /etc/ssh/sshd_config.d/*.conf\n",
		"/etc/ssh/sshd_config.d/x.conf": "Port 22\n",
	}, "/etc/ssh/sshd_config.d")
	c := Parse(fsys, "/etc/ssh/sshd_config")
	if c.Complete || len(c.Unreadable()) != 1 || c.Unreadable()[0] != "/etc/ssh/sshd_config.d/*.conf" {
		t.Fatalf("files = %+v", c.Files)
	}
}

func TestUnreadableMain(t *testing.T) {
	c := Parse(newMemFS(map[string]string{"/etc/ssh/sshd_config": "Port 22\n"}, "/etc/ssh/sshd_config"), "/etc/ssh/sshd_config")
	if c.Complete || len(c.Effective) != 0 {
		t.Fatalf("complete=%v effective=%v", c.Complete, c.Effective)
	}
	c = Parse(newMemFS(nil), "/etc/ssh/sshd_config")
	if c.Complete || c.Files[0].Readable {
		t.Fatalf("missing main: %+v", c.Files)
	}
}

func TestMatchBlocks(t *testing.T) {
	fsys := newMemFS(map[string]string{
		"/etc/ssh/sshd_config": `PasswordAuthentication no
Include /etc/ssh/sshd_config.d/*.conf
Match User deploy
    PasswordAuthentication yes
    Include /etc/ssh/match.d/*.conf
    PubkeyAuthentication yes
Match Address 192.0.2.0/24,198.51.100.7
    PermitRootLogin yes
Match all
    X11Forwarding yes
`,
		// A Match opened in a drop-in ends with the drop-in.
		"/etc/ssh/sshd_config.d/20-sftp.conf":  "Match Group sftp\n  ForceCommand internal-sftp\n",
		"/etc/ssh/sshd_config.d/30-after.conf": "MaxAuthTries 2\n",
		"/etc/ssh/match.d/deploy.conf":         "AllowTcpForwarding no\n",
	})
	c := Parse(fsys, "/etc/ssh/sshd_config")
	if len(c.Matches) != 4 {
		t.Fatalf("matches = %+v", c.Matches)
	}
	if c.Matches[0].Criteria != "Group sftp" || c.Matches[1].Criteria != "User deploy" || !c.Matches[3].All() {
		t.Errorf("criteria = %+v", c.Matches)
	}
	if c.Effective["maxauthtries"][0] != "2" {
		t.Error("a directive after a drop-in Match block is global again")
	}
	if c.Effective["passwordauthentication"][0] != "no" || c.Effective["x11forwarding"][0] != "no" {
		t.Errorf("Match lines leaked into the global section: %v", c.Effective)
	}
	got := map[string]int{}
	for _, d := range c.Directives {
		got[d.Keyword+"="+d.Value+"@"+path.Base(d.File)] = d.Match
	}
	want := map[string]int{
		"passwordauthentication=no@sshd_config":   0,
		"forcecommand=internal-sftp@20-sftp.conf": 1,
		"maxauthtries=2@30-after.conf":            0,
		"passwordauthentication=yes@sshd_config":  2,
		"allowtcpforwarding=no@deploy.conf":       2, // include inside Match
		"pubkeyauthentication=yes@sshd_config":    2, // still inside after the include
		"permitrootlogin=yes@sshd_config":         3,
		"x11forwarding=yes@sshd_config":           4,
	}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("directive contexts\n got %v\nwant %v", got, want)
	}
}

func TestUnreadableInsideMatchOnlyTaintsMatch(t *testing.T) {
	fsys := newMemFS(map[string]string{
		"/etc/ssh/sshd_config": "Match User deploy\n  Include /etc/ssh/secret.conf\n",
		"/etc/ssh/secret.conf": "PasswordAuthentication yes\n",
	}, "/etc/ssh/secret.conf")
	c := Parse(fsys, "/etc/ssh/sshd_config")
	if !c.Complete {
		t.Error("an unreadable file inside a Match block does not hide global values")
	}
	if !c.Matches[0].Incomplete {
		t.Error("want the Match block marked incomplete")
	}
}

func TestSplitLine(t *testing.T) {
	cases := []struct {
		in   string
		kw   string
		args []string
		ok   bool
	}{
		{"  # comment", "", nil, false},
		{"", "", nil, false},
		{"PasswordAuthentication no", "PasswordAuthentication", []string{"no"}, true},
		{"PasswordAuthentication=no", "PasswordAuthentication", []string{"no"}, true},
		{"PasswordAuthentication = no\r", "PasswordAuthentication", []string{"no"}, true},
		{"\tPort\t2222 # trailing comment", "Port", []string{"2222"}, true},
		{`Banner "/etc/my banner"`, "Banner", []string{"/etc/my banner"}, true},
		{`ForceCommand 'echo "hi there"'`, "ForceCommand", []string{`echo "hi there"`}, true},
		{`AllowUsers a b  c`, "AllowUsers", []string{"a", "b", "c"}, true},
		{`AuthorizedKeysCommand /bin/x a#b`, "AuthorizedKeysCommand", []string{"/bin/x", "a#b"}, true},
		{"Lonely", "Lonely", nil, true},
	}
	for _, tc := range cases {
		kw, args, ok := splitLine(tc.in)
		if kw != tc.kw || !reflect.DeepEqual(args, tc.args) || ok != tc.ok {
			t.Errorf("%q: got %q %q %v", tc.in, kw, args, ok)
		}
	}
}

func TestAliasesShareOneSlot(t *testing.T) {
	// ChallengeResponseAuthentication is the old name of
	// KbdInteractiveAuthentication: whichever comes first wins.
	fsys := newMemFS(map[string]string{
		"/etc/ssh/sshd_config": "ChallengeResponseAuthentication yes\nKbdInteractiveAuthentication no\n",
	})
	c := Parse(fsys, "/etc/ssh/sshd_config")
	if c.Effective["kbdinteractiveauthentication"][0] != "yes" {
		t.Fatalf("effective = %v", c.Effective["kbdinteractiveauthentication"])
	}
	if c.Directives[0].Keyword != "kbdinteractiveauthentication" {
		t.Errorf("alias not canonical: %+v", c.Directives[0])
	}
}

func TestListenAddressFamilies(t *testing.T) {
	cases := []struct {
		addrs  []string
		ports  []string
		family string
		want   []string
	}{
		{nil, []string{"22"}, "any", []string{"[::]:22", "0.0.0.0:22"}},
		{nil, []string{"22", "2222"}, "inet", []string{"0.0.0.0:22", "0.0.0.0:2222"}},
		{nil, []string{"22"}, "inet6", []string{"[::]:22"}},
		{[]string{"192.0.2.1:2200", "2001:db8::5", "host.example.com rdomain r1"}, []string{"22"}, "any",
			[]string{"192.0.2.1:2200", "[2001:db8::5]:22", "host.example.com:22"}},
	}
	for _, tc := range cases {
		if got := listenAddresses(tc.addrs, tc.ports, tc.family); !reflect.DeepEqual(got, tc.want) {
			t.Errorf("%v %v %s: got %v, want %v", tc.addrs, tc.ports, tc.family, got, tc.want)
		}
	}
}

func TestParseEffective(t *testing.T) {
	out := "port 22\nport 2222\npasswordauthentication no\nlistenaddress [::]:22\nchallengeresponseauthentication no\n\n"
	eff := ParseEffective([]byte(out))
	if !reflect.DeepEqual(eff["port"], []string{"22", "2222"}) || eff["passwordauthentication"][0] != "no" ||
		eff["kbdinteractiveauthentication"][0] != "no" || eff["listenaddress"][0] != "[::]:22" {
		t.Fatalf("eff = %v", eff)
	}
}
