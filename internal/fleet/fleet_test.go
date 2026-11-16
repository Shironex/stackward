package fleet

import (
	"bytes"
	"context"
	"encoding/binary"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/Shironex/stackward/internal/audit"
	"github.com/Shironex/stackward/internal/facts"
	"github.com/Shironex/stackward/internal/report"
	"github.com/Shironex/stackward/internal/sandbox"
)

// fakeEnv puts testdata/fakessh.sh on PATH as ssh (and a logging sudo),
// gives the "remote" its own TMPDIR and writes the canned reports. It
// returns the remote TMPDIR and the stand in binary.
type fakeEnv struct {
	tmp     string // remote TMPDIR
	sshLog  string
	binLog  string
	sudoLog string
	bin     Binary
}

func newFakeEnv(t *testing.T) *fakeEnv {
	t.Helper()
	dir := t.TempDir()
	e := &fakeEnv{
		tmp:     filepath.Join(dir, "remote-tmp"),
		sshLog:  filepath.Join(dir, "ssh-calls"),
		binLog:  filepath.Join(dir, "bin.log"),
		sudoLog: filepath.Join(dir, "sudo.log"),
	}
	pathDir := filepath.Join(dir, "path")
	for _, d := range []string{e.tmp, pathDir, e.sshLog} {
		if err := os.MkdirAll(d, 0o755); err != nil {
			t.Fatal(err)
		}
	}
	src, err := filepath.Abs(filepath.Join("testdata", "fakessh.sh"))
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(src, filepath.Join(pathDir, "ssh")); err != nil {
		t.Fatal(err)
	}
	sudo := "#!/bin/sh\necho \"$*\" >> \"$FAKE_SUDO_LOG\"\n[ \"$1\" = -n ] && [ \"$2\" = -- ] || exit 1\nshift 2\nexec \"$@\"\n"
	if err := os.WriteFile(filepath.Join(pathDir, "sudo"), []byte(sudo), 0o755); err != nil {
		t.Fatal(err)
	}
	binSrc, err := filepath.Abs(filepath.Join("testdata", "fakebinary.sh"))
	if err != nil {
		t.Fatal(err)
	}
	e.bin = Binary{Path: binSrc, Arch: AMD64}

	reportPath := filepath.Join(dir, "report.json")
	writeReport(t, reportPath, nil)
	evilPath := filepath.Join(dir, "evil.json")
	writeReport(t, evilPath, func(r *report.Report) {
		r.Host.OS = "Ubuntu\x1b]0;owned\x07\x1b[2J"
		r.Results[0].Message = "line one\nFAKE: forged line\u202e"
	})

	t.Setenv("PATH", pathDir+string(os.PathListSeparator)+os.Getenv("PATH"))
	t.Setenv("FAKE_SSH_LOG", e.sshLog)
	t.Setenv("FAKE_SSH_TMP", e.tmp)
	t.Setenv("FAKE_BIN_LOG", e.binLog)
	t.Setenv("FAKE_SUDO_LOG", e.sudoLog)
	t.Setenv("FAKE_REPORT", reportPath)
	t.Setenv("FAKE_EVIL_REPORT", evilPath)
	t.Setenv("FAKE_SSH_DOWN", "")
	t.Setenv("FAKE_SSH_ARM", "")
	return e
}

// writeReport writes a real report.v1 document from a fixture.
func writeReport(t *testing.T, path string, edit func(*report.Report)) {
	t.Helper()
	fh, err := os.Open(filepath.Join("..", "..", "test", "fixtures", "debian-12-reboot-overdue", "facts.json"))
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = fh.Close() }()
	f, err := facts.Load(fh)
	if err != nil {
		t.Fatal(err)
	}
	rep, err := audit.Evaluate(f, audit.Options{Version: "test", Sandbox: sandbox.Status{State: sandbox.Landlock, ABI: 4}})
	if err != nil {
		t.Fatal(err)
	}
	if edit != nil {
		edit(rep)
	}
	var b bytes.Buffer
	if err := report.WriteJSON(&b, rep); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, b.Bytes(), 0o600); err != nil {
		t.Fatal(err)
	}
}

func (e *fakeEnv) read(t *testing.T, path string) string {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil && !os.IsNotExist(err) {
		t.Fatal(err)
	}
	return string(b)
}

// sshCalls returns the arguments of every ssh call.
func (e *fakeEnv) sshCalls(t *testing.T) [][]string {
	t.Helper()
	ents, err := os.ReadDir(e.sshLog)
	if err != nil {
		t.Fatal(err)
	}
	var calls [][]string
	for _, x := range ents {
		b := e.read(t, filepath.Join(e.sshLog, x.Name()))
		calls = append(calls, strings.Split(strings.TrimSuffix(b, "\n"), "\n"))
	}
	return calls
}

// sshText is every ssh call's arguments in one string.
func (e *fakeEnv) sshText(t *testing.T) string {
	var b strings.Builder
	for _, c := range e.sshCalls(t) {
		b.WriteString(strings.Join(c, "\n") + "\n")
	}
	return b.String()
}

// leftovers lists what is left in the remote TMPDIR.
func (e *fakeEnv) leftovers(t *testing.T) []string {
	t.Helper()
	ents, err := os.ReadDir(e.tmp)
	if err != nil {
		t.Fatal(err)
	}
	var names []string
	for _, x := range ents {
		names = append(names, x.Name())
	}
	return names
}

func (e *fakeEnv) run(t *testing.T, hosts []string, o Options) []report.FleetHost {
	t.Helper()
	if o.Binaries == nil {
		o.Binaries = []Binary{e.bin}
	}
	if o.Version == "" {
		o.Version = "v1.2.3"
	}
	res, err := Run(context.Background(), hosts, o)
	if err != nil {
		t.Fatal(err)
	}
	if len(res) != len(hosts) {
		t.Fatalf("%d results for %d hosts", len(res), len(hosts))
	}
	for i, h := range hosts {
		if res[i].Host != h {
			t.Fatalf("result %d is %q, want %q (order must follow the input)", i, res[i].Host, h)
		}
	}
	return res
}

func TestRunSuccess(t *testing.T) {
	e := newFakeEnv(t)
	res := e.run(t, []string{"web1.example.com", "admin@db1"}, Options{Parallel: 2, Remote: RemoteArgs{Profile: "tunnel", Timeout: 20 * time.Second}})
	for _, r := range res {
		if r.Status != report.FleetAudited || r.Report == nil || r.Error != "" || r.Cleanup != "" {
			t.Fatalf("%s: %+v", r.Host, r)
		}
		if r.Arch != "amd64" || r.Report.Summary.Fail == 0 {
			t.Errorf("%s: arch %q, summary %+v", r.Host, r.Arch, r.Report.Summary)
		}
	}
	if left := e.leftovers(t); len(left) != 0 {
		t.Errorf("the remote temporary directory must be removed, left: %v", left)
	}
	binLog := e.read(t, e.binLog)
	for _, want := range []string{
		"web1.example.com audit --json --fail-on never --profile tunnel --timeout 20s",
		"admin@db1 audit --json --fail-on never --profile tunnel --timeout 20s",
		"drwx------",
	} {
		if !strings.Contains(binLog, want) {
			t.Errorf("binary log misses %q:\n%s", want, binLog)
		}
	}
	if strings.Contains(binLog, "drwxr") {
		t.Errorf("the temporary directory must be private (700):\n%s", binLog)
	}
	if e.read(t, e.sudoLog) != "" {
		t.Error("sudo used without Sudo")
	}
	// Every ssh call carries the fixed options and puts the host after "--".
	calls := e.sshCalls(t)
	if len(calls) != 4 {
		t.Errorf("%d ssh calls, want 4 (uname and run per host)", len(calls))
	}
	for _, args := range calls {
		want := append(append([]string{}, sshOptions...), "--")
		if len(args) != len(want)+2 || strings.Join(args[:len(want)], " ") != strings.Join(want, " ") {
			t.Errorf("ssh args %q, want %q HOST COMMAND", args, want)
		}
	}
}

func TestRunSudo(t *testing.T) {
	e := newFakeEnv(t)
	res := e.run(t, []string{"web1"}, Options{Sudo: true})
	if res[0].Status != report.FleetAudited {
		t.Fatalf("%+v", res[0])
	}
	if got := e.read(t, e.sudoLog); !strings.HasPrefix(got, "-n -- ") || !strings.Contains(got, "/stackward audit --json") {
		t.Errorf("sudo log %q, want sudo -n -- .../stackward audit", got)
	}
}

func TestRunPartialFailure(t *testing.T) {
	e := newFakeEnv(t)
	t.Setenv("FAKE_SSH_DOWN", "down1")
	res := e.run(t, []string{"web1", "down1", "broken1", "web2"}, Options{Parallel: 3})
	want := map[string]string{"web1": report.FleetAudited, "down1": report.FleetError, "broken1": report.FleetError, "web2": report.FleetAudited}
	for _, r := range res {
		if r.Status != want[r.Host] {
			t.Errorf("%s: status %s, want %s (%s)", r.Host, r.Status, want[r.Host], r.Error)
		}
	}
	if !strings.Contains(res[1].Error, "ssh failed (exit 255)") || !strings.Contains(res[1].Error, "Connection refused") {
		t.Errorf("down host error: %q", res[1].Error)
	}
	if !strings.Contains(res[2].Error, "the remote audit failed (exit 2): stackward audit: something broke") {
		t.Errorf("broken host error: %q", res[2].Error)
	}
	if strings.Contains(res[2].Error, tmpMarker) {
		t.Errorf("the directory marker must not reach the user: %q", res[2].Error)
	}
	if left := e.leftovers(t); len(left) != 0 {
		t.Errorf("left on the remote: %v", left)
	}
	fl := report.NewFleet("test", "2026-01-01T00:00:00Z", res)
	if fl.Summary.Audited != 2 || fl.Summary.Failed != 2 || fl.ExitCode(report.FailOnNever) != report.ExitError {
		t.Errorf("summary %+v, exit %d", fl.Summary, fl.ExitCode(report.FailOnNever))
	}
}

func TestRunCleansUpWhenTheTrapCannotRun(t *testing.T) {
	e := newFakeEnv(t)
	res := e.run(t, []string{"killed1", "web1"}, Options{})
	if res[0].Status != report.FleetError || res[0].Cleanup != "" {
		t.Fatalf("killed host: %+v", res[0])
	}
	if res[1].Status != report.FleetAudited {
		t.Fatalf("a killed host must not stop the others: %+v", res[1])
	}
	if left := e.leftovers(t); len(left) != 0 {
		t.Errorf("the local side must remove the directory the trap left: %v", left)
	}
	if !strings.Contains(e.sshText(t), "rm -rf -- '"+e.tmp) {
		t.Errorf("no cleanup connection in the ssh log:\n%s", e.sshText(t))
	}
}

func TestRunArchMismatch(t *testing.T) {
	e := newFakeEnv(t)
	t.Setenv("FAKE_SSH_ARM", "pi1")
	res := e.run(t, []string{"pi1", "web1"}, Options{})
	if res[0].Status != report.FleetError || res[0].Arch != "arm64" {
		t.Fatalf("%+v", res[0])
	}
	for _, want := range []string{"linux/arm64", "stackward_1.2.3_linux_arm64.tar.gz", "--ssh-binary"} {
		if !strings.Contains(res[0].Error, want) {
			t.Errorf("mismatch error misses %q: %s", want, res[0].Error)
		}
	}
	if strings.Contains(e.read(t, e.binLog), "pi1") {
		t.Error("nothing may be copied to a host of another architecture")
	}
	if res[1].Status != report.FleetAudited {
		t.Errorf("%+v", res[1])
	}
	// With a binary for each architecture both hosts run.
	arm := Binary{Path: e.bin.Path, Arch: ARM64}
	res = e.run(t, []string{"pi1", "web1"}, Options{Binaries: []Binary{e.bin, arm}})
	if res[0].Status != report.FleetAudited || res[1].Status != report.FleetAudited {
		t.Errorf("mixed fleet: %+v / %+v", res[0], res[1])
	}
}

func TestRunCleansHostileOutput(t *testing.T) {
	e := newFakeEnv(t)
	res := e.run(t, []string{"evil1"}, Options{})
	if res[0].Report == nil {
		t.Fatalf("%+v", res[0])
	}
	fl := report.NewFleet("test", "2026-01-01T00:00:00Z", res)
	for name, write := range map[string]func(*bytes.Buffer) error{
		"text": func(b *bytes.Buffer) error { return report.WriteFleetText(b, fl, report.TextOptions{Passing: true}) },
		"md": func(b *bytes.Buffer) error {
			return report.WriteFleetMarkdown(b, fl, report.MarkdownOptions{Passing: true})
		},
	} {
		var b bytes.Buffer
		if err := write(&b); err != nil {
			t.Fatal(err)
		}
		out := b.String()
		if strings.ContainsAny(out, "\x1b\x07\u202e") || strings.Contains(out, "\nFAKE: forged") {
			t.Errorf("%s: control characters from the host reached the output", name)
		}
	}
}

func TestRunRefusesNonReports(t *testing.T) {
	for _, tc := range []struct {
		body string
		want string
	}{
		{"not json", "did not send a report.v1"},
		{`{"schema":"stackward.plan.v1"}`, "schema"},
	} {
		e := newFakeEnv(t)
		p := filepath.Join(t.TempDir(), "r.json")
		if err := os.WriteFile(p, []byte(tc.body), 0o600); err != nil {
			t.Fatal(err)
		}
		t.Setenv("FAKE_REPORT", p)
		res := e.run(t, []string{"web1"}, Options{})
		if res[0].Status != report.FleetError || !strings.Contains(res[0].Error, tc.want) {
			t.Errorf("%q: %+v", tc.body, res[0])
		}
	}
}

func TestRunTimeout(t *testing.T) {
	e := newFakeEnv(t)
	slow := filepath.Join(t.TempDir(), "slow.sh")
	if err := os.WriteFile(slow, []byte("#!/bin/sh\nsleep 5\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	defer func(d time.Duration) { sshWaitDelay = d }(sshWaitDelay)
	sshWaitDelay = 200 * time.Millisecond
	start := time.Now()
	res := e.run(t, []string{"web1"}, Options{Binaries: []Binary{{Path: slow, Arch: AMD64}}, HostTimeout: 500 * time.Millisecond})
	if res[0].Status != report.FleetError || !strings.Contains(res[0].Error, "timed out") {
		t.Errorf("%+v", res[0])
	}
	if time.Since(start) > 4*time.Second {
		t.Errorf("took %s", time.Since(start))
	}
	if left := e.leftovers(t); len(left) != 0 {
		t.Errorf("a timed out host must be cleaned up from this side: %v", left)
	}
}

func TestHostValidation(t *testing.T) {
	good := []string{"web1", "web1.example.com", "admin@db1", "deploy_user@10.0.0.1", "2001:db8::1", "my-alias"}
	for _, h := range good {
		if err := ValidateHost(h); err != nil {
			t.Errorf("%q refused: %v", h, err)
		}
	}
	bad := []string{
		"", "-oProxyCommand=touch /tmp/owned", "-p", "--", "a b", "a;b", "a|b", "$(id)", "`id`",
		"a'b", `a"b`, "a\nb", "host%h", "a/b", "@host", "user@-host", "a@b@c", "web1\x1b[2J",
		"host\\x", strings.Repeat("a", 300),
	}
	for _, h := range bad {
		if err := ValidateHost(h); err == nil {
			t.Errorf("%q accepted", h)
		}
	}
	if err := ValidateHost("-oProxyCommand=x"); err == nil || !strings.Contains(err.Error(), "option") {
		t.Errorf("a leading '-' must say why: %v", err)
	}
}

func TestReadHostsAndDedup(t *testing.T) {
	hosts, err := ReadHosts(strings.NewReader("# fleet\nweb1\n\n  db1  # primary\nweb1\n"))
	if err != nil {
		t.Fatal(err)
	}
	all, err := Hosts([]string{"web2", "db1"}, hosts)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Join(all, ",") != "web2,db1,web1" {
		t.Errorf("hosts %v", all)
	}
	if _, err := ReadHosts(strings.NewReader("web1\n-oProxyCommand=x\n")); err == nil || !strings.Contains(err.Error(), "line 2") {
		t.Errorf("bad line: %v", err)
	}
	if _, err := Hosts(nil, nil); err == nil {
		t.Error("no hosts accepted")
	}
	many := make([]string, MaxHosts+1)
	for i := range many {
		many[i] = "h" + strings.Repeat("x", 1) + string(rune('a'+i%26)) + strings.Repeat("y", i/26)
	}
	if _, err := Hosts(many); err == nil {
		t.Error("over MaxHosts accepted")
	}
}

func TestRemoteScript(t *testing.T) {
	args, err := RemoteArgs{Profile: "tunnel", Timeout: time.Minute, ShowHostname: true}.args()
	if err != nil {
		t.Fatal(err)
	}
	for _, sudo := range []bool{false, true} {
		s := remoteScript(sudo, args)
		if strings.ContainsAny(s, "'\n!") {
			t.Errorf("the script must be one line without single quotes or '!': %s", s)
		}
		for _, want := range []string{"umask 077", "mktemp -d", `trap "rm -rf \"$d\"" EXIT`, "chmod 700", "audit --json --fail-on never --profile tunnel --timeout 1m0s --show-hostname"} {
			if !strings.Contains(s, want) {
				t.Errorf("script misses %q: %s", want, s)
			}
		}
		if strings.Contains(s, "sudo") != sudo {
			t.Errorf("sudo=%v: %s", sudo, s)
		}
	}
	if _, err := (RemoteArgs{Profile: "moat"}).args(); err == nil {
		t.Error("a bad profile reached the remote command")
	}
}

func TestTmpDirFrom(t *testing.T) {
	for _, tc := range []struct {
		stderr string
		want   string
	}{
		{tmpMarker + "/tmp/stackward.Ab12Cd34Ef\n", "/tmp/stackward.Ab12Cd34Ef"},
		{"warning\n" + tmpMarker + "/var/tmp/x/stackward.abcdef\nmore", "/var/tmp/x/stackward.abcdef"},
		{tmpMarker + "/tmp/stackward.abc'; rm -rf / #\n", ""},
		{tmpMarker + "/tmp/../etc/stackward.abcdef\n", ""},
		{tmpMarker + "/home/me\n", ""},
		{tmpMarker + "relative/stackward.abcdef\n", ""},
		{"nothing\n", ""},
	} {
		got, ok := tmpDirFrom([]byte(tc.stderr))
		if got != tc.want || ok != (tc.want != "") {
			t.Errorf("%q: got %q %v, want %q", tc.stderr, got, ok, tc.want)
		}
	}
}

func TestRemoteArch(t *testing.T) {
	for in, want := range map[string]Arch{"x86_64\n": AMD64, "aarch64": ARM64, "arm64": ARM64} {
		if got, err := RemoteArch(in); err != nil || got != want {
			t.Errorf("%q: %q %v", in, got, err)
		}
	}
	for _, in := range []string{"", "armv7l", "riscv64", "i686"} {
		if _, err := RemoteArch(in); err == nil {
			t.Errorf("%q accepted", in)
		}
	}
}

// elfHeader returns a minimal 64 bit little endian ELF header.
func elfHeader(machine uint16, class byte) []byte {
	h := make([]byte, 64)
	copy(h, []byte{0x7f, 'E', 'L', 'F', class, 1, 1})
	binary.LittleEndian.PutUint16(h[16:], 2) // ET_EXEC
	binary.LittleEndian.PutUint16(h[18:], machine)
	binary.LittleEndian.PutUint32(h[20:], 1)
	binary.LittleEndian.PutUint16(h[52:], 64)
	binary.LittleEndian.PutUint16(h[54:], 56)
	binary.LittleEndian.PutUint16(h[58:], 64)
	return h
}

func TestBinaryArchAndLoad(t *testing.T) {
	dir := t.TempDir()
	write := func(name string, b []byte) string {
		p := filepath.Join(dir, name)
		if err := os.WriteFile(p, b, 0o755); err != nil {
			t.Fatal(err)
		}
		return p
	}
	amd := write("amd", elfHeader(62, 2))
	arm := write("arm", elfHeader(183, 2))
	riscv := write("riscv", elfHeader(243, 2))
	script := write("script", []byte("#!/bin/sh\n"))
	if a, err := BinaryArch(amd); err != nil || a != AMD64 {
		t.Errorf("amd64: %q %v", a, err)
	}
	if a, err := BinaryArch(arm); err != nil || a != ARM64 {
		t.Errorf("arm64: %q %v", a, err)
	}
	for _, p := range []string{riscv, script} {
		if _, err := BinaryArch(p); err == nil {
			t.Errorf("%s accepted", p)
		}
	}
	bins, err := LoadBinaries([]string{amd, arm}, "v1.2.3")
	if err != nil || len(bins) != 2 {
		t.Fatalf("%v %v", bins, err)
	}
	if _, err := LoadBinaries([]string{amd, amd}, "v1.2.3"); err == nil {
		t.Error("two amd64 builds accepted")
	}
	if _, err := LoadBinaries([]string{script}, "v1.2.3"); err == nil {
		t.Error("a non ELF file accepted")
	}
	if _, err := pickBinary(bins[:1], ARM64, "dev"); err == nil || !strings.Contains(err.Error(), "stackward_<version>_linux_arm64.tar.gz") {
		t.Errorf("pick: %v", err)
	}
}

func TestCapped(t *testing.T) {
	c := &capped{max: 4, strict: true}
	if _, err := c.Write([]byte("abcdef")); err == nil || !c.over || string(c.Bytes()) != "abcd" {
		t.Errorf("strict: %q %v", c.Bytes(), err)
	}
	l := &capped{max: 4}
	if n, err := l.Write([]byte("abcdef")); err != nil || n != 6 || string(l.Bytes()) != "abcd" {
		t.Errorf("lenient: %d %q %v", n, l.Bytes(), err)
	}
}
