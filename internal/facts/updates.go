package facts

import (
	"context"
	"errors"
	"fmt"
	"io/fs"
	"path"
	"regexp"
	"sort"
	"strings"
	"time"
)

// Updates is unattended-upgrades state and pending updates (UPD group).
type Updates struct {
	// Apt is false on hosts without dpkg and apt (non Debian family); every
	// other field is then empty.
	Apt bool `json:"apt"`
	// UnattendedInstalled is whether the unattended-upgrades package is
	// installed.
	UnattendedInstalled bool `json:"unattended_installed"`
	// PeriodicUnattended is the APT::Periodic::Unattended-Upgrade value
	// ("1" is daily, "0" or empty is off); PeriodicUpdateLists is
	// APT::Periodic::Update-Package-Lists.
	PeriodicUnattended  string `json:"periodic_unattended,omitempty"`
	PeriodicUpdateLists string `json:"periodic_update_lists,omitempty"`
	// ConfigSource is "apt-config" (effective config) or "files" (parsed
	// from /etc/apt/apt.conf.d when apt-config was unavailable).
	ConfigSource string `json:"config_source,omitempty"`
	// TimerEnabled and TimerActive describe apt-daily-upgrade.timer; nil
	// means systemctl could not tell.
	TimerEnabled *bool `json:"timer_enabled,omitempty"`
	TimerActive  *bool `json:"timer_active,omitempty"`
	// AllowedOrigins joins Allowed-Origins and Origins-Pattern.
	AllowedOrigins []string `json:"allowed_origins,omitempty"`
	// AutomaticReboot is Unattended-Upgrade::Automatic-Reboot.
	AutomaticReboot     bool   `json:"automatic_reboot"`
	AutomaticRebootTime string `json:"automatic_reboot_time,omitempty"`
	// LastRun is the newest of the apt periodic stamp and the
	// unattended-upgrades log files; zero when none was found.
	LastRun time.Time `json:"last_run,omitzero"`
	// ListsUpdated is the apt update-success stamp; zero when none.
	ListsUpdated time.Time `json:"lists_updated,omitzero"`
	// PendingChecked is true when `apt-get -s upgrade` ran. It reflects the
	// package lists as of ListsUpdated, not a fresh apt update.
	PendingChecked      bool     `json:"pending_checked"`
	PendingTotal        int      `json:"pending_total"`
	PendingSecurity     int      `json:"pending_security"`
	PendingSecurityPkgs []string `json:"pending_security_packages,omitempty"`
}

// Paths the updates collector reads.
const (
	aptConfDir        = "/etc/apt/apt.conf.d"
	uuStampPath       = "/var/lib/apt/periodic/unattended-upgrades-stamp"
	updateStampPath   = "/var/lib/apt/periodic/update-success-stamp"
	uuLogDir          = "/var/log/unattended-upgrades"
	aptTimer          = "apt-daily-upgrade.timer"
	maxPendingPkgs    = 50
	maxLogFilesProbed = 50
)

type updatesCollector struct{}

func init() { Register(updatesCollector{}) }

func (updatesCollector) Name() string    { return "updates" }
func (updatesCollector) NeedsRoot() bool { return false }

func (updatesCollector) Collect(ctx context.Context, sys System, out *Facts) error {
	u := &Updates{}
	if _, err := sys.LookPath("dpkg-query"); err != nil {
		out.Updates = u // not an apt host: recorded explicitly
		return nil
	}
	u.Apt = true
	var errs []error

	// `dpkg-query -W` only reads the dpkg database.
	res, err := sys.Run(ctx, "dpkg-query", "-W", "-f=${Status}", "unattended-upgrades")
	u.UnattendedInstalled = err == nil && res.ExitCode == 0 && strings.TrimSpace(string(res.Stdout)) == "install ok installed"
	if err != nil {
		errs = append(errs, fmt.Errorf("dpkg-query: %w", err))
	}

	conf, source, err := aptSettings(ctx, sys)
	if err != nil {
		errs = append(errs, err)
	} else {
		u.ConfigSource = source
		u.PeriodicUnattended = conf.scalar("APT::Periodic::Unattended-Upgrade")
		u.PeriodicUpdateLists = conf.scalar("APT::Periodic::Update-Package-Lists")
		u.AllowedOrigins = append(conf.list("Unattended-Upgrade::Allowed-Origins"), conf.list("Unattended-Upgrade::Origins-Pattern")...)
		u.AutomaticReboot = isTrue(conf.scalar("Unattended-Upgrade::Automatic-Reboot"))
		u.AutomaticRebootTime = conf.scalar("Unattended-Upgrade::Automatic-Reboot-Time")
	}

	u.TimerEnabled = systemctlBool(ctx, sys, "is-enabled", aptTimer, "enabled")
	u.TimerActive = systemctlBool(ctx, sys, "is-active", aptTimer, "active")

	u.LastRun = latestRun(sys)
	if m, err := sys.Meta(updateStampPath); err == nil {
		u.ListsUpdated = time.Unix(m.ModTime, 0).UTC()
	}

	// `apt-get -s` simulates; NoLocking keeps it from taking the dpkg lock,
	// so it also works without root. An empty pkgcache makes apt build the
	// status part of its cache in memory instead of rewriting
	// /var/cache/apt/pkgcache.bin after dpkg changed (apt.conf(5),
	// Dir::Cache), which the no writes sandbox would refuse. srcpkgcache is
	// kept: without it apt reparses every list and needs a temporary file
	// for each signed InRelease, which the sandbox refuses too.
	if res, err := sys.Run(ctx, "apt-get", aptSimulateArgs...); err != nil || res.ExitCode != 0 {
		errs = append(errs, fmt.Errorf("apt-get -s upgrade: %w", cmdErr(err, res)))
	} else {
		u.PendingChecked = true
		u.PendingTotal, u.PendingSecurity, u.PendingSecurityPkgs = ParseAptSimulate(res.Stdout)
	}

	out.Updates = u
	return errors.Join(errs...)
}

// aptSimulateArgs is `apt-get -s upgrade` with no lock and no cache writes.
var aptSimulateArgs = []string{"-s", "-o", "Debug::NoLocking=true", "-o", "Dir::Cache::pkgcache=", "upgrade"}

func isTrue(s string) bool {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "true", "1", "yes", "on":
		return true
	}
	return false
}

// systemctlBool runs `systemctl <verb> <unit>` and returns whether stdout is
// want, or nil when systemctl is missing or could not say.
func systemctlBool(ctx context.Context, sys System, verb, unit, want string) *bool {
	res, err := sys.Run(ctx, "systemctl", verb, unit)
	if err != nil {
		return nil
	}
	state := strings.TrimSpace(string(res.Stdout))
	if state == "" {
		return nil
	}
	v := state == want
	return &v
}

// latestRun finds the newest sign of an unattended-upgrades run.
func latestRun(sys System) time.Time {
	var newest int64
	if m, err := sys.Meta(uuStampPath); err == nil {
		newest = m.ModTime
	}
	if entries, err := sys.ReadDir(uuLogDir); err == nil {
		for i, e := range entries {
			if i >= maxLogFilesProbed {
				break
			}
			if m, err := sys.Meta(path.Join(uuLogDir, e.Name())); err == nil && m.ModTime > newest {
				newest = m.ModTime
			}
		}
	}
	if newest == 0 {
		return time.Time{}
	}
	return time.Unix(newest, 0).UTC()
}

// aptSettings prefers the effective configuration from `apt-config dump`
// (read only) and falls back to parsing /etc/apt/apt.conf.d.
func aptSettings(ctx context.Context, sys System) (aptConf, string, error) {
	if res, err := sys.Run(ctx, "apt-config", "dump"); err == nil && res.ExitCode == 0 {
		return parseAptConf(string(res.Stdout)), "apt-config", nil
	}
	entries, err := sys.ReadDir(aptConfDir)
	if err != nil {
		return nil, "", fmt.Errorf("apt configuration: %w", err)
	}
	names := make([]string, 0, len(entries))
	for _, e := range entries {
		if !e.IsDir() && validAptConfName(e.Name()) {
			names = append(names, e.Name())
		}
	}
	sort.Strings(names)
	var sb strings.Builder
	for _, n := range names {
		b, err := sys.ReadFile(path.Join(aptConfDir, n))
		if err != nil && !errors.Is(err, fs.ErrNotExist) {
			continue
		}
		sb.Write(b)
		sb.WriteByte('\n')
	}
	return parseAptConf(sb.String()), "files", nil
}

var aptConfName = regexp.MustCompile(`^[A-Za-z0-9_.-]+$`)

// validAptConfName mirrors apt: only letters, digits, "_", "-" and "." and
// not a backup ("~", ".dpkg-old" and the like).
func validAptConfName(n string) bool {
	return aptConfName.MatchString(n) && !strings.HasSuffix(n, ".dpkg-old") && !strings.HasSuffix(n, ".dpkg-dist") &&
		!strings.HasSuffix(n, ".dpkg-new") && !strings.HasSuffix(n, ".ucf-old") && !strings.HasSuffix(n, ".ucf-dist") && !strings.HasSuffix(n, ".ucf-new")
}

// aptConf maps a full option name ("APT::Periodic::Unattended-Upgrade") to
// its values in order. A list option has many values.
type aptConf map[string][]string

func (c aptConf) scalar(key string) string {
	v := c[key]
	if len(v) == 0 {
		return ""
	}
	return v[len(v)-1]
}

func (c aptConf) list(key string) []string {
	var out []string
	for _, v := range c[key] {
		if v != "" {
			out = append(out, v)
		}
	}
	return out
}

// parseAptConf parses the apt.conf format: "Key::Sub "value";" lines, nested
// "Key { Sub "value"; };" blocks, list elements as bare quoted strings in a
// block, and //, /* */ and # comments. `apt-config dump` output is a subset.
func parseAptConf(text string) aptConf {
	conf := aptConf{}
	toks := tokenizeApt(text)
	prefix := []string{""}
	var pending []aptTok
	join := func(key string) string {
		key = strings.TrimSuffix(key, "::")
		if top := prefix[len(prefix)-1]; top != "" {
			return top + "::" + key
		}
		return key
	}
	flush := func() {
		switch {
		case len(pending) == 1 && pending[0].quoted:
			k := prefix[len(prefix)-1]
			if k != "" {
				conf[k] = append(conf[k], pending[0].text)
			}
		case len(pending) == 1:
			conf[join(pending[0].text)] = append(conf[join(pending[0].text)], "")
		case len(pending) >= 2:
			k := join(pending[0].text)
			conf[k] = append(conf[k], pending[1].text)
		}
		pending = nil
	}
	for _, t := range toks {
		switch {
		case !t.quoted && t.text == "{":
			key := ""
			if len(pending) > 0 {
				key = join(pending[0].text)
			} else {
				key = prefix[len(prefix)-1]
			}
			prefix = append(prefix, key)
			pending = nil
		case !t.quoted && t.text == "}":
			flush()
			if len(prefix) > 1 {
				prefix = prefix[:len(prefix)-1]
			}
		case !t.quoted && t.text == ";":
			flush()
		default:
			pending = append(pending, t)
		}
	}
	flush()
	return conf
}

type aptTok struct {
	text   string
	quoted bool
}

func tokenizeApt(s string) []aptTok {
	var toks []aptTok
	for i := 0; i < len(s); {
		c := s[i]
		switch {
		case c == ' ' || c == '\t' || c == '\n' || c == '\r':
			i++
		case c == '#' || (c == '/' && i+1 < len(s) && s[i+1] == '/'):
			for i < len(s) && s[i] != '\n' {
				i++
			}
		case c == '/' && i+1 < len(s) && s[i+1] == '*':
			end := strings.Index(s[i+2:], "*/")
			if end < 0 {
				return toks
			}
			i += end + 4
		case c == '{' || c == '}' || c == ';':
			toks = append(toks, aptTok{text: string(c)})
			i++
		case c == '"':
			j := i + 1
			for j < len(s) && s[j] != '"' {
				j++
			}
			toks = append(toks, aptTok{text: s[i+1 : min(j, len(s))], quoted: true})
			i = j + 1
		default:
			j := i
			for j < len(s) && !strings.ContainsRune(" \t\r\n{};\"", rune(s[j])) {
				j++
			}
			toks = append(toks, aptTok{text: s[i:j]})
			i = j
		}
	}
	return toks
}

var aptInst = regexp.MustCompile(`^Inst (\S+) (?:\[[^\]]*\] )?\(([^)]*)\)`)

// ParseAptSimulate counts the upgrades in `apt-get -s upgrade` output and
// those whose origin is a security pocket (Ubuntu "-security", Debian
// "-security", ESM security).
func ParseAptSimulate(b []byte) (total, security int, securityPkgs []string) {
	for _, line := range strings.Split(string(b), "\n") {
		m := aptInst.FindStringSubmatch(line)
		if m == nil {
			continue
		}
		total++
		if strings.Contains(strings.ToLower(m[2]), "security") {
			security++
			if len(securityPkgs) < maxPendingPkgs {
				securityPkgs = append(securityPkgs, m[1])
			}
		}
	}
	return total, security, securityPkgs
}
