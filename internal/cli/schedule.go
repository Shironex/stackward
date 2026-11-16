package cli

import (
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"path"
	"path/filepath"
	"regexp"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/Shironex/stackward/internal/profile"
	"github.com/Shironex/stackward/internal/report"
)

// The defaults of stackward schedule. The textfile directory is the one
// the Debian and Ubuntu prometheus-node-exporter package reads.
const (
	scheduleUnit        = "stackward-audit"
	defaultOnCalendar   = "daily"
	defaultRandomDelay  = time.Hour
	defaultReportDir    = "/var/lib/stackward"
	defaultTextfileDir  = "/var/lib/prometheus/node-exporter"
	scheduleReportFile  = "report.json"
	scheduleMetricFile  = "stackward.prom"
	scheduleTempSuffix  = ".tmp"
	scheduleDocsURL     = "https://github.com/Shironex/stackward/blob/main/docs/schedule.md"
	scheduleRootAccount = "root"
)

// rootCapabilities is the capability bounding set of a root run: what the
// collectors need and nothing more. DAC_READ_SEARCH reads root only files
// (sshd host keys, /etc/shadow for passwd -S), DAC_OVERRIDE connects to the
// root owned Docker and tailscaled sockets, NET_ADMIN and NET_RAW let nft and
// iptables list the ruleset, SYS_PTRACE reads other processes' /proc/<pid>/fd
// for the socket owner snapshot.
const rootCapabilities = "CAP_DAC_READ_SEARCH CAP_DAC_OVERRIDE CAP_NET_ADMIN CAP_NET_RAW CAP_SYS_PTRACE"

// scheduleOwnedFlags are audit flags the printed unit sets itself, or that
// a scheduled run must not have. Extra audit flags may not name them.
var scheduleOwnedFlags = map[string]bool{
	"format": true, "json": true, "md": true, "out": true, "textfile": true,
	"fail-on": true, "dump-facts": true, "facts": true, "no-sandbox": true,
	"h": true, "help": true,
}

var (
	// unitPath is the character set allowed in a path printed into a unit:
	// no space, quote, percent, dollar or backslash, so no quoting or
	// specifier escaping is ever needed (ReadWritePaths has no quoting).
	unitPath = regexp.MustCompile(`^/[A-Za-z0-9._/@+-]*$`)
	// unitWord needs no quoting in ExecStart.
	unitWord = regexp.MustCompile(`^[A-Za-z0-9_./:=,+@-]+$`)
	// accountName is a portable user name (useradd's default rule).
	accountName = regexp.MustCompile(`^[a-z_][a-z0-9_-]{0,31}$`)
)

type scheduleFlags struct {
	print       bool
	onCalendar  string
	randomDelay time.Duration
	user        string
	reportDir   string
	textfileDir string
	binary      string
	auditArgs   []string
}

const scheduleUsage = `Usage: stackward schedule --print [flags] [-- audit flags]

Prints a systemd service and timer unit that run a read only audit on a
schedule. stackward writes nothing and enables nothing: you install the
units yourself (see docs/schedule.md). The scheduled run writes the JSON
report and a Prometheus textfile metric to temporary files, then renames
each into place, so readers never see half a file.

Audit flags after "--" are added to the scheduled audit, for example
  stackward schedule --print -- --profile tunnel --timeout 30s
They are checked like audit's own flags. The unit sets --format, --out,
--textfile and --fail-on itself; --facts, --dump-facts and --no-sandbox are
refused.

Flags:
`

func runSchedule(args []string, stdout, stderr io.Writer) int {
	sf, code, done := parseScheduleArgs(args, stderr)
	if done {
		return code
	}
	service, timer := renderScheduleUnits(sf)
	if _, err := io.WriteString(stdout, service+"\n"+timer); err != nil {
		fmt.Fprintf(stderr, "stackward schedule: %v\n", err)
		return report.ExitError
	}
	return report.ExitOK
}

// parseScheduleArgs parses and checks every schedule flag. done is true
// when the run ends here and code is its exit code.
func parseScheduleArgs(args []string, stderr io.Writer) (sf scheduleFlags, code int, done bool) {
	fs := flag.NewFlagSet("schedule", flag.ContinueOnError)
	fs.SetOutput(stderr)
	fs.BoolVar(&sf.print, "print", false, "print the units to stdout (required: schedule never installs anything)")
	fs.StringVar(&sf.onCalendar, "on-calendar", defaultOnCalendar, "when to run, as a systemd OnCalendar expression (check it with systemd-analyze calendar)")
	fs.DurationVar(&sf.randomDelay, "randomized-delay", defaultRandomDelay, "spread the start over up to this long (RandomizedDelaySec), 0 for none")
	fs.StringVar(&sf.user, "user", scheduleRootAccount, "the account the audit runs as; anything but root gives partial coverage")
	fs.StringVar(&sf.reportDir, "report-dir", defaultReportDir, "directory of the JSON report ("+scheduleReportFile+")")
	fs.StringVar(&sf.textfileDir, "textfile-dir", defaultTextfileDir, "node_exporter textfile directory ("+scheduleMetricFile+"), empty for no metric")
	fs.StringVar(&sf.binary, "binary", "", "absolute path of the stackward binary the unit runs (default: this binary)")
	fs.Usage = func() {
		fmt.Fprint(stderr, scheduleUsage)
		fs.PrintDefaults()
	}
	if err := fs.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return sf, report.ExitOK, true
		}
		return sf, report.ExitError, true
	}
	sf.auditArgs = fs.Args()
	if err := sf.check(stderr); err != nil {
		fmt.Fprintf(stderr, "stackward schedule: %v\n", err)
		return sf, report.ExitError, true
	}
	return sf, 0, false
}

// check validates the flags. Everything printed into a unit is either
// refused or escaped here, so no value can add a line, a directive or a
// specifier to the unit.
func (sf *scheduleFlags) check(stderr io.Writer) error {
	if !sf.print {
		return errors.New("schedule only prints the units; pass --print (stackward never installs anything)")
	}
	if err := checkUnitValue("--on-calendar", sf.onCalendar); err != nil {
		return err
	}
	if strings.TrimSpace(sf.onCalendar) == "" {
		return errors.New("--on-calendar is empty")
	}
	if sf.randomDelay < 0 {
		return errors.New("--randomized-delay must not be negative")
	}
	if !accountName.MatchString(sf.user) {
		return fmt.Errorf("--user must be an account name (lower case letters, digits, _ and -), not %q", sf.user)
	}
	if sf.binary == "" {
		exe, err := thisBinary()
		if err != nil {
			return fmt.Errorf("cannot find this binary (%w); pass --binary", err)
		}
		sf.binary = exe
	}
	if err := checkUnitPath("--binary", sf.binary); err != nil {
		return err
	}
	if err := checkUnitPath("--report-dir", sf.reportDir); err != nil {
		return err
	}
	if sf.textfileDir != "" {
		if err := checkUnitPath("--textfile-dir", sf.textfileDir); err != nil {
			return err
		}
	}
	return checkScheduleAuditArgs(sf.auditArgs, stderr)
}

func thisBinary() (string, error) {
	exe, err := os.Executable()
	if err != nil {
		return "", err
	}
	return filepath.EvalSymlinks(exe)
}

// checkUnitValue refuses what could break out of a unit setting: control
// characters (a newline starts a new directive), a percent sign (a
// systemd specifier) and invalid UTF-8.
func checkUnitValue(name, v string) error {
	if !utf8.ValidString(v) {
		return fmt.Errorf("%s is not valid UTF-8", name)
	}
	for _, r := range v {
		if r < 0x20 || r == 0x7f {
			return fmt.Errorf("%s must not contain control characters such as a newline", name)
		}
	}
	if strings.Contains(v, "%") {
		return fmt.Errorf("%s must not contain %%, which systemd reads as a specifier", name)
	}
	return nil
}

// checkUnitPath accepts a clean absolute path made of a small character
// set. Unit paths are Linux paths, so the check uses package path, not
// filepath.
func checkUnitPath(name, p string) error {
	if !unitPath.MatchString(p) {
		return fmt.Errorf("%s must be an absolute path of letters, digits and . _ / @ + -, not %q", name, p)
	}
	if path.Clean(p) != p || p == "/" {
		return fmt.Errorf("%s must be a clean absolute path below /, not %q", name, p)
	}
	return nil
}

// checkScheduleAuditArgs checks the extra audit flags: none may be one the
// unit owns, none may hold a control character, and together they must
// parse as audit flags with valid values.
func checkScheduleAuditArgs(args []string, stderr io.Writer) error {
	for _, a := range args {
		if !utf8.ValidString(a) {
			return errors.New("audit flags must be valid UTF-8")
		}
		for _, r := range a {
			if r < 0x20 || r == 0x7f {
				return fmt.Errorf("audit flag %q must not contain control characters such as a newline", a)
			}
		}
		if a == "--" {
			return errors.New(`give "--" once, before the audit flags`)
		}
		if name, ok := flagName(a); ok && scheduleOwnedFlags[name] {
			return fmt.Errorf("audit flag %s is set by the unit or not allowed in a scheduled run", a)
		}
	}
	if len(args) == 0 {
		return nil
	}
	af, _, _, done := parseAuditArgs(args, stderr)
	if done {
		return errors.New("the audit flags after -- are not valid (see stackward audit -h)")
	}
	if _, _, err := profile.Parse(af.profile); err != nil {
		return err
	}
	return nil
}

// flagName returns the flag name of a token such as -x, --name or
// --name=value.
func flagName(tok string) (string, bool) {
	if !strings.HasPrefix(tok, "-") || tok == "-" {
		return "", false
	}
	name := strings.TrimLeft(tok, "-")
	name, _, _ = strings.Cut(name, "=")
	return name, name != ""
}

// scheduleHardening is the sandbox of the service. The audit only reads, so
// the whole file system is read only except the two output directories
// (ReadWritePaths, written next to it).
const scheduleHardening = `# Hardening: the audit only reads, so the whole file system is read only
# except the output directories. Nothing here hides what the audit inspects
# (no PrivateNetwork, PrivateDevices or ProtectProc).
NoNewPrivileges=yes
ProtectSystem=strict
ProtectHome=read-only
PrivateTmp=yes
ProtectKernelTunables=yes
ProtectKernelModules=yes
ProtectKernelLogs=yes
ProtectControlGroups=yes
ProtectClock=yes
ProtectHostname=yes
RestrictSUIDSGID=yes
RestrictRealtime=yes
RestrictNamespaces=yes
LockPersonality=yes
SystemCallArchitectures=native
RestrictAddressFamilies=AF_UNIX AF_NETLINK AF_INET AF_INET6
`

// renderScheduleUnits returns the service and the timer unit.
func renderScheduleUnits(sf scheduleFlags) (service, timer string) {
	return renderService(sf), renderTimer(sf)
}

func renderService(sf scheduleFlags) string {
	reportPath := path.Join(sf.reportDir, scheduleReportFile)
	exec := []string{sf.binary, "audit", "--format", "json", "--fail-on", "never", "--out", reportPath + scheduleTempSuffix}
	moves := []string{reportPath}
	rw := sf.reportDir
	if sf.textfileDir != "" {
		metricPath := path.Join(sf.textfileDir, scheduleMetricFile)
		exec = append(exec, "--textfile", metricPath+scheduleTempSuffix)
		moves = append(moves, metricPath)
		if sf.textfileDir != sf.reportDir {
			rw += " " + sf.textfileDir
		}
	}
	exec = append(exec, sf.auditArgs...)
	words := make([]string, len(exec))
	for i, w := range exec {
		words[i] = execWord(w)
	}

	var b strings.Builder
	fmt.Fprintf(&b, `# /etc/systemd/system/%s.service
# Printed by stackward schedule --print. stackward never installs or
# enables this unit: install it by hand as docs/schedule.md shows.
[Unit]
Description=stackward read only audit
Documentation=%s
After=docker.service

[Service]
Type=oneshot
`, scheduleUnit, scheduleDocsURL)
	writeAccount(&b, sf.user)
	b.WriteString("ExecStart=" + strings.Join(words, " ") + "\n")
	b.WriteString("# Each file is written under a temporary name and renamed into place\n")
	b.WriteString("# (rename is atomic), and only when the audit succeeded.\n")
	for _, m := range moves {
		b.WriteString("ExecStartPost=/bin/mv -f " + m + scheduleTempSuffix + " " + m + "\n")
	}
	b.WriteString("UMask=0077\nNice=10\nIOSchedulingClass=idle\n")
	b.WriteString(scheduleHardening)
	b.WriteString("ReadWritePaths=" + rw + "\n")
	if usesProvider(sf.auditArgs) {
		b.WriteString("# --provider reads the provider firewall over HTTPS, so IP traffic stays\n")
		b.WriteString("# allowed. Give the credentials with EnvironmentFile=, never in ExecStart.\n")
	} else {
		b.WriteString("# The audit makes no network calls.\nIPAddressDeny=any\n")
	}
	return b.String()
}

func renderTimer(sf scheduleFlags) string {
	return fmt.Sprintf(`# /etc/systemd/system/%[1]s.timer
# Printed by stackward schedule --print. Enable it yourself:
#   systemctl daemon-reload && systemctl enable --now %[1]s.timer
[Unit]
Description=Run the stackward audit on a schedule
Documentation=%[2]s

[Timer]
OnCalendar=%[3]s
RandomizedDelaySec=%[4]d
Persistent=true

[Install]
WantedBy=timers.target
`, scheduleUnit, scheduleDocsURL, sf.onCalendar, int64(sf.randomDelay/time.Second))
}

// writeAccount writes the User= line and the capabilities that go with it.
func writeAccount(b *strings.Builder, user string) {
	b.WriteString("User=" + user + "\n")
	if user == scheduleRootAccount {
		b.WriteString("# Full coverage needs root. The bounding set keeps only what the\n")
		b.WriteString("# collectors use to read: root only files, the Docker socket, the\n")
		b.WriteString("# firewall ruleset and which process owns which socket.\n")
		b.WriteString("CapabilityBoundingSet=" + rootCapabilities + "\n")
		return
	}
	b.WriteString("# Not root: checks that need root say unknown, and the account must be\n")
	b.WriteString("# able to write its output directories.\n")
	b.WriteString("CapabilityBoundingSet=\n")
}

func usesProvider(args []string) bool {
	for _, a := range args {
		if name, ok := flagName(a); ok && name == "provider" {
			return true
		}
	}
	return false
}

// execWord prints one ExecStart argument. A word made of safe characters
// is printed as is; anything else is double quoted with backslash and quote
// escaped. Dollar signs are doubled in every case, so systemd never expands
// a variable. Percent signs and control characters were refused earlier,
// and are escaped here too as a second line of defence.
func execWord(w string) string {
	w = strings.ReplaceAll(w, "%", "%%")
	w = strings.ReplaceAll(w, "$", "$$")
	if unitWord.MatchString(w) {
		return w
	}
	w = strings.NewReplacer(`\`, `\\`, `"`, `\"`, "\n", `\n`, "\r", `\r`, "\t", `\t`).Replace(w)
	return `"` + w + `"`
}
