package cli

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/Shironex/stackward/internal/report"
	"github.com/Shironex/stackward/internal/waiver"
)

// usrWaivers accepts the one fail of the usr-bad fixture that is not
// critical.
const usrWaivers = `version: 1
waivers:
  - check: USR-004
    subject: file:/etc/sudoers.d/deploy
    reason: the deploy tool rewrites it
    expires: 2026-06-30
`

func writeWaivers(t *testing.T, dir, body string, mode os.FileMode) string {
	t.Helper()
	p := filepath.Join(dir, waiver.DefaultFile)
	if err := os.WriteFile(p, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(p, mode); err != nil {
		t.Fatal(err)
	}
	return p
}

func TestAuditWaiversFlag(t *testing.T) {
	p := writeWaivers(t, t.TempDir(), usrWaivers, 0o644)
	code, out, errs := run("audit", "--no-sandbox", "--facts", fixture("usr-bad"), "--waivers", p, "--json")
	if code != report.ExitFindings {
		t.Fatalf("exit %d (stderr %s); usr-bad keeps critical fails", code, errs)
	}
	var rep report.Report
	if err := json.Unmarshal([]byte(out), &rep); err != nil {
		t.Fatal(err)
	}
	if rep.Summary.Accepted != 1 || rep.Summary.Fail != 2 || len(rep.Waivers) != 1 || rep.Waivers[0].Status != report.WaiverApplied {
		t.Errorf("summary %+v, waivers %+v", rep.Summary, rep.Waivers)
	}
}

func TestAuditDefaultWaiversFile(t *testing.T) {
	facts, err := filepath.Abs(fixture("usr-bad"))
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	t.Chdir(dir)
	_, out, _ := run("audit", "--no-sandbox", "--facts", facts)
	if strings.Contains(out, "waivers:") {
		t.Errorf("no waivers file, but the header has a waivers line:\n%s", out)
	}
	writeWaivers(t, dir, usrWaivers, 0o600)
	_, out, errs := run("audit", "--no-sandbox", "--facts", facts)
	if !strings.Contains(out, "waivers:   1 applied") || !strings.Contains(out, "ACCEPTED FAIL, USR-004") {
		t.Errorf("default .stackward.yml not read (stderr %s):\n%s", errs, out)
	}
	// --dump-facts never needs the waivers, so a broken file does not block a bug report.
	writeWaivers(t, dir, "version: 1\nwaivers: &a\n", 0o600)
	if code, _, errs := run("audit", "--no-sandbox", "--facts", facts, "--dump-facts"); code != report.ExitOK {
		t.Errorf("--dump-facts with a broken waivers file: exit %d (%s)", code, errs)
	}
}

func TestAuditWaiversErrors(t *testing.T) {
	dir := t.TempDir()
	cases := map[string]struct {
		path func() string
		want string
	}{
		"missing named file": {func() string { return filepath.Join(dir, "nope.yml") }, "nope.yml"},
		"malformed": {func() string {
			return writeWaivers(t, t.TempDir(), "version: 1\nwaivers:\n  - check: NET-004\n", 0o600)
		}, "line 3: waiver has no \"subject\""},
		"no expiry": {func() string {
			return writeWaivers(t, t.TempDir(), "version: 1\nwaivers:\n  - check: NET-004\n    subject: host\n    reason: x\n", 0o600)
		}, "no \"expires\""},
		"directory":      {func() string { return t.TempDir() }, "not a regular file"},
		"group writable": {func() string { return writeWaivers(t, t.TempDir(), usrWaivers, 0o664) }, "writable by group or others"},
	}
	for name, tc := range cases {
		code, out, errs := run("audit", "--no-sandbox", "--facts", fixture("usr-bad"), "--waivers", tc.path())
		if code != report.ExitError || !strings.Contains(errs, tc.want) || out != "" {
			t.Errorf("%s: exit %d, stdout %d bytes, stderr %q; want exit %d and %q", name, code, len(out), errs, report.ExitError, tc.want)
		}
	}
}

func TestTUIWaiversFlag(t *testing.T) {
	code, _, errs := run("tui", "--report", savedReport("usr-bad"), "--waivers", "x.yml")
	if code != report.ExitError || !strings.Contains(errs, "already shows its waivers") {
		t.Errorf("tui --report --waivers: exit %d %q", code, errs)
	}
	code, _, errs = run("tui", "--plan", "plan.json", "--waivers", "x.yml")
	if code != report.ExitError || !strings.Contains(errs, "--waivers does not go with --plan") {
		t.Errorf("tui --plan --waivers: exit %d %q", code, errs)
	}
	p := writeWaivers(t, t.TempDir(), "version: 9\nwaivers: []\n", 0o600)
	code, _, errs = run("tui", "--no-sandbox", "--facts", fixture("usr-bad"), "--waivers", p)
	if code != report.ExitError || !strings.Contains(errs, "unsupported version") {
		t.Errorf("tui with a bad waivers file must fail before the terminal check: exit %d %q", code, errs)
	}
}
