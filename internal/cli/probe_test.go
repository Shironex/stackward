package cli

import (
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/Shironex/stackward/internal/report"
	"github.com/Shironex/stackward/internal/schemacheck"
)

// Probe tests only ever target 127.0.0.1 and pass --no-sandbox.

// answer sets the consent seams for one test.
func answer(t *testing.T, tty bool, input string) {
	t.Helper()
	oldIn, oldTTY := probeStdin, probeStdinTTY
	probeStdin, probeStdinTTY = strings.NewReader(input), func() bool { return tty }
	t.Cleanup(func() { probeStdin, probeStdinTTY = oldIn, oldTTY })
}

func TestProbeRefusesBadTargets(t *testing.T) {
	answer(t, false, "")
	cases := map[string][]string{
		"range":        {"192.0.2.0/24", "--i-own-this"},
		"v6 range":     {"2001:db8::/32", "--i-own-this"},
		"dash range":   {"192.0.2.1-50", "--i-own-this"},
		"two hosts":    {"192.0.2.1", "192.0.2.2", "--i-own-this"},
		"no host":      {"--i-own-this"},
		"bad ports":    {"192.0.2.1", "--ports", "1-1024", "--i-own-this"},
		"bad hostname": {"192.0.2.1", "--hostname", "https://app.example.com/", "--i-own-this"},
		"bad profile":  {"192.0.2.1", "--profile", "moat", "--i-own-this"},
		"bad format":   {"192.0.2.1", "--format", "yaml", "--i-own-this"},
	}
	for name, args := range cases {
		code, out, errs := run(append([]string{"probe", "--no-sandbox"}, args...)...)
		if code != report.ExitError || out != "" {
			t.Errorf("%s: exit %d, stdout %q", name, code, out)
		}
		if strings.Contains(errs, "may be illegal") {
			t.Errorf("%s: invalid input must be refused before the consent step: %q", name, errs)
		}
	}
	if _, _, errs := run("probe", "192.0.2.0/24", "--i-own-this"); !strings.Contains(errs, "never a range") {
		t.Errorf("CIDR message: %q", errs)
	}
}

func TestProbeConsentGuard(t *testing.T) {
	// Not a terminal and no --i-own-this: refused, nothing probed.
	answer(t, false, "y\n")
	code, out, errs := run("probe", "--no-sandbox", "127.0.0.1")
	if code != report.ExitError || out != "" || !strings.Contains(errs, "may be illegal") || !strings.Contains(errs, "--i-own-this") {
		t.Fatalf("non interactive: %d %q %q", code, out, errs)
	}
	// A terminal answering no.
	answer(t, true, "n\n")
	if code, out, errs := run("probe", "--no-sandbox", "127.0.0.1"); code != report.ExitError || out != "" || !strings.Contains(errs, "not confirmed") {
		t.Fatalf("answered no: %d %q %q", code, out, errs)
	}
}

func TestProbeLoopbackJSON(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Skip(err)
	}
	defer func() { _ = ln.Close() }()
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			_, _ = c.Write([]byte("SSH-2.0-OpenSSH_9.6 cli-test\r\n"))
			_ = c.Close()
		}
	}()
	_, port, _ := net.SplitHostPort(ln.Addr().String())

	// A terminal answering yes; flags after the host work too.
	answer(t, true, "y\n")
	out := filepath.Join(t.TempDir(), "probe.json")
	code, stdout, errs := run("probe", "127.0.0.1", "--no-sandbox", "--json", "--timeout", "300ms",
		"--ports", port, "--profile", "tunnel", "--fail-on", "never", "--out", out)
	if code != report.ExitOK || stdout != "" {
		t.Fatalf("exit %d stdout %q stderr %q", code, stdout, errs)
	}
	if !strings.Contains(errs, "may be illegal") || !strings.Contains(errs, "[y/N]") {
		t.Errorf("consent prompt missing: %q", errs)
	}
	body, err := os.ReadFile(out)
	if err != nil {
		t.Fatal(err)
	}
	schema, err := os.ReadFile(filepath.Join("..", "..", "schema", "report.v1.json"))
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range schemacheck.Validate(schema, body) {
		t.Error(e)
	}
	s := string(body)
	for _, want := range []string{
		`"target": "127.0.0.1"`, `"state": "disabled"`, `"name": "tunnel"`,
		`"banner": "SSH-2.0-OpenSSH_9.6 cli-test"`, `"subject": "port:tcp/` + port + `"`, `"id": "PRB-006"`,
	} {
		if !strings.Contains(s, want) {
			t.Errorf("report lacks %s", want)
		}
	}
	if strings.Contains(s, `"id": "SYS-`) {
		t.Error("probe report lists audit checks")
	}
}

// Each case is a target that is this machine; the interface lookup is faked.
func TestProbeSelfTargetWarns(t *testing.T) {
	old := probeLocalAddrs
	probeLocalAddrs = func() ([]netip.Addr, error) { return []netip.Addr{netip.MustParseAddr("2001:db8::5")}, nil }
	t.Cleanup(func() { probeLocalAddrs = old })
	for _, target := range []string{"127.0.0.1", "::1", "2001:db8::5"} {
		answer(t, false, "")
		code, out, errs := run("probe", "--no-sandbox", "--i-own-this", "--timeout", "100ms", "--fail-on", "never", "--ports", "9", target)
		if code != report.ExitOK {
			t.Fatalf("%s: exit %d: %s", target, code, errs)
		}
		if !strings.Contains(errs, "is this machine") || !strings.Contains(errs, "not an outside view") {
			t.Errorf("%s: stderr lacks the warning: %q", target, errs)
		}
		if !strings.Contains(out, "WARNING:") || !strings.Contains(out, "not an outside view") {
			t.Errorf("%s: banner missing in:\n%s", target, out)
		}
	}
}

func TestProbeSelfTargetJSONRecorded(t *testing.T) {
	answer(t, false, "")
	code, out, _ := run("probe", "--no-sandbox", "--i-own-this", "--json", "--timeout", "100ms", "--fail-on", "never", "127.0.0.1")
	if code != report.ExitOK {
		t.Fatalf("exit %d", code)
	}
	schema, err := os.ReadFile(filepath.Join("..", "..", "schema", "report.v1.json"))
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range schemacheck.Validate(schema, []byte(out)) {
		t.Error(e)
	}
	if !strings.Contains(out, `"self_target": true`) {
		t.Errorf("report lacks self_target:\n%s", out)
	}
}

func TestProbeTextWithOwnFlag(t *testing.T) {
	answer(t, false, "")
	code, out, errs := run("probe", "--no-sandbox", "--i-own-this", "--timeout", "200ms", "--fail-on", "never", "127.0.0.1")
	if code != report.ExitOK {
		t.Fatalf("exit %d: %s", code, errs)
	}
	for _, want := range []string{"probe (stackward.report.v1)", "target:    127.0.0.1", "PRB  Outside view", "profile unknown"} {
		if !strings.Contains(out, want) {
			t.Errorf("missing %q in:\n%s", want, out)
		}
	}
	if code, _, _ := run("probe", "-h"); code != report.ExitOK {
		t.Errorf("probe -h: exit %d", code)
	}

}
