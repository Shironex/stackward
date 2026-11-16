package cli

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/charmbracelet/x/exp/golden"

	"github.com/Shironex/stackward/internal/report"
)

// The printed units are goldens under testdata/TestSchedulePrintGolden/.
// After an intended change: go test ./internal/cli -run TestSchedulePrintGolden -update
func TestSchedulePrintGolden(t *testing.T) {
	cases := map[string][]string{
		"root-default": {"--print", "--binary", "/usr/local/bin/stackward"},
		"account-provider-no-metric": {
			"--print", "--binary", "/usr/bin/stackward", "--user", "stackward",
			"--on-calendar", "Mon *-*-* 03:00:00", "--randomized-delay", "15m",
			"--report-dir", "/srv/audit", "--textfile-dir", "",
			"--", "--provider", "hetzner", "--profile", "tunnel", "--timeout=30s",
		},
		"same-dir": {
			"--print", "--binary", "/opt/stackward/bin/stackward",
			"--report-dir", "/var/lib/node-exporter", "--textfile-dir", "/var/lib/node-exporter",
			"--randomized-delay", "0",
		},
	}
	for name, args := range cases {
		t.Run(name, func(t *testing.T) {
			code, out, errs := run(append([]string{"schedule"}, args...)...)
			if code != report.ExitOK {
				t.Fatalf("exit %d, stderr %s", code, errs)
			}
			golden.RequireEqual(t, out)
		})
	}
}

// TestScheduleWritesNothing: schedule only prints. Run in an empty working
// directory with both output directories pointing into it, nothing may
// appear on disk, and stdout must carry both units.
func TestScheduleWritesNothing(t *testing.T) {
	dir := t.TempDir()
	t.Chdir(dir)
	reportDir := filepath.ToSlash(filepath.Join(dir, "report"))
	metricDir := filepath.ToSlash(filepath.Join(dir, "metric"))
	if err := os.Mkdir(reportDir, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(metricDir, 0o700); err != nil {
		t.Fatal(err)
	}
	code, out, errs := run("schedule", "--print", "--binary", "/usr/bin/stackward",
		"--report-dir", reportDir, "--textfile-dir", metricDir)
	if code != report.ExitOK {
		t.Fatalf("exit %d, stderr %s", code, errs)
	}
	if !strings.Contains(out, "[Service]") || !strings.Contains(out, "[Timer]") {
		t.Fatalf("both units must be printed:\n%s", out)
	}
	for _, d := range []string{dir, reportDir, metricDir} {
		entries, err := os.ReadDir(d)
		if err != nil {
			t.Fatal(err)
		}
		var names []string
		for _, e := range entries {
			if e.Name() != "report" && e.Name() != "metric" {
				names = append(names, e.Name())
			}
		}
		if len(names) > 0 {
			t.Errorf("schedule --print wrote %v into %s", names, d)
		}
	}
}

func TestScheduleDefaultBinaryIsThisOne(t *testing.T) {
	exe, err := thisBinary()
	if err != nil || checkUnitPath("--binary", exe) != nil {
		t.Skipf("test binary path %q is not printable into a unit", exe)
	}
	code, out, errs := run("schedule", "--print")
	if code != report.ExitOK {
		t.Fatalf("exit %d, stderr %s", code, errs)
	}
	if !strings.Contains(out, "ExecStart="+exe+" audit ") {
		t.Errorf("default --binary must be this binary %s:\n%s", exe, out)
	}
}

func TestScheduleRefuses(t *testing.T) {
	bin := []string{"--print", "--binary", "/usr/bin/stackward"}
	cases := map[string]struct {
		args []string
		want string
	}{
		"no print":            {[]string{"--binary", "/usr/bin/stackward"}, "pass --print"},
		"calendar newline":    {append(bin, "--on-calendar", "daily\nExecStartPre=/bin/sh -c id"), "control characters"},
		"calendar specifier":  {append(bin, "--on-calendar", "%H"), "specifier"},
		"calendar empty":      {append(bin, "--on-calendar", " "), "empty"},
		"negative delay":      {append(bin, "--randomized-delay", "-1m"), "negative"},
		"user newline":        {append(bin, "--user", "root\nUser=x"), "account name"},
		"user upper":          {append(bin, "--user", "Root"), "account name"},
		"relative binary":     {[]string{"--print", "--binary", "stackward"}, "absolute path"},
		"binary space":        {[]string{"--print", "--binary", "/usr/bin/stack ward"}, "absolute path"},
		"binary specifier":    {[]string{"--print", "--binary", "/usr/bin/%n"}, "absolute path"},
		"binary dollar":       {[]string{"--print", "--binary", "/usr/bin/$HOME"}, "absolute path"},
		"report dir dotdot":   {append(bin, "--report-dir", "/var/lib/../tmp"), "clean"},
		"report dir root":     {append(bin, "--report-dir", "/"), "clean"},
		"report dir trailing": {append(bin, "--report-dir", "/var/lib/stackward/"), "clean"},
		"report dir newline":  {append(bin, "--report-dir", "/var/lib\n/x"), "absolute path"},
		"textfile relative":   {append(bin, "--textfile-dir", "metrics"), "absolute path"},
		"owned out":           {append(bin, "--", "--out", "/tmp/x"), "set by the unit"},
		"owned out equals":    {append(bin, "--", "--out=/tmp/x"), "set by the unit"},
		"owned single dash":   {append(bin, "--", "-format=text"), "set by the unit"},
		"owned json":          {append(bin, "--", "--json"), "set by the unit"},
		"owned fail-on":       {append(bin, "--", "--fail-on", "warn"), "set by the unit"},
		"owned textfile":      {append(bin, "--", "--textfile", "/tmp/x.prom"), "set by the unit"},
		"no sandbox":          {append(bin, "--", "--no-sandbox"), "set by the unit"},
		"facts":               {append(bin, "--", "--facts", "f.json"), "set by the unit"},
		"dump facts":          {append(bin, "--", "--dump-facts"), "set by the unit"},
		"audit help":          {append(bin, "--", "-h"), "set by the unit"},
		"unknown audit flag":  {append(bin, "--", "--bogus"), "not valid"},
		"stray audit arg":     {append(bin, "--", "stray"), "not valid"},
		"bad profile":         {append(bin, "--", "--profile", "moat"), "profile"},
		"bad provider":        {append(bin, "--", "--provider", "aws"), "not valid"},
		"double dash twice":   {append(bin, "--", "--profile", "tunnel", "--", "x"), `"--" once`},
		"audit arg newline":   {append(bin, "--", "--profile=tunnel\nExecStartPre=/bin/sh"), "control characters"},
		"audit arg bad utf8":  {append(bin, "--", "--profile=\xff"), "UTF-8"},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			code, out, errs := run(append([]string{"schedule"}, tc.args...)...)
			if code != report.ExitError {
				t.Fatalf("exit %d, want %d; stdout %s", code, report.ExitError, out)
			}
			if out != "" {
				t.Errorf("a refused run must print no unit:\n%s", out)
			}
			if !strings.Contains(errs, tc.want) {
				t.Errorf("stderr %q does not say %q", errs, tc.want)
			}
		})
	}
}

func TestScheduleHelp(t *testing.T) {
	code, out, errs := run("schedule", "-h")
	if code != report.ExitOK || out != "" || !strings.Contains(errs, "writes nothing and enables nothing") {
		t.Fatalf("exit %d, stdout %q, stderr %q", code, out, errs)
	}
}

func TestExecWord(t *testing.T) {
	cases := map[string]string{
		"--profile":       "--profile",
		"--timeout=30s":   "--timeout=30s",
		"/usr/bin/x":      "/usr/bin/x",
		"a b":             `"a b"`,
		"50%":             `"50%%"`,
		"$HOME":           `"$$HOME"`,
		`say "hi"`:        `"say \"hi\""`,
		`back\slash`:      `"back\\slash"`,
		"line\nbreak":     `"line\nbreak"`,
		";":               `";"`,
		"${PATH}%n\t$$ x": `"$${PATH}%%n\t$$$$ x"`,
	}
	for in, want := range cases {
		if got := execWord(in); got != want {
			t.Errorf("execWord(%q) = %s, want %s", in, got, want)
		}
	}
}

func TestScheduleUnitHasOneDirectivePerLine(t *testing.T) {
	sf := scheduleFlags{
		print: true, onCalendar: "daily", user: "root", reportDir: "/var/lib/stackward",
		textfileDir: "/var/lib/prometheus/node-exporter", binary: "/usr/bin/stackward",
		auditArgs: []string{"--profile", "tunnel"},
	}
	service, timer := renderScheduleUnits(sf)
	for _, unit := range []string{service, timer} {
		for _, l := range strings.Split(strings.TrimSuffix(unit, "\n"), "\n") {
			if l == "" || strings.HasPrefix(l, "#") || strings.HasPrefix(l, "[") {
				continue
			}
			if !strings.Contains(l, "=") {
				t.Errorf("line %q is not a directive", l)
			}
		}
	}
	for _, want := range []string{
		"NoNewPrivileges=yes", "ProtectSystem=strict", "Persistent=true", "RandomizedDelaySec=0",
		"ReadWritePaths=/var/lib/stackward /var/lib/prometheus/node-exporter", "IPAddressDeny=any",
		"CapabilityBoundingSet=" + rootCapabilities,
	} {
		if !strings.Contains(service+timer, want+"\n") {
			t.Errorf("units lack %q", want)
		}
	}
}
