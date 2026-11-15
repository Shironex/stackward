package facts

import (
	"bufio"
	"bytes"
	"context"
	"errors"
	"fmt"
	"path"
	"regexp"
	"sort"
	"strings"
)

// Fail2ban is fail2ban's live jails and the jail configuration: which
// jails are enabled, their ports and ignoreip (CS-010, CS-011).
type Fail2ban struct {
	// Installed is true when fail2ban-client, /etc/fail2ban or the unit
	// exists. False with a non nil Fail2ban is a known "absent".
	Installed bool `json:"installed"`
	// Unit is fail2ban.service, nil when systemd could not be asked.
	Unit *ServiceUnit `json:"unit,omitempty"`
	// StatusRead is true when `fail2ban-client status` answered (root);
	// ActiveJails are the jails the server runs.
	StatusRead  bool     `json:"status_read"`
	ActiveJails []string `json:"active_jails,omitempty"`
	// ConfigRead is true when jail.conf or jail.local was read. Jails are
	// the enabled jails plus sshd, with DEFAULT values resolved.
	ConfigRead bool           `json:"config_read"`
	Jails      []Fail2banJail `json:"jails,omitempty"`
}

// Fail2banJail is one jail after merging every config file.
type Fail2banJail struct {
	Name    string `json:"name"`
	Enabled bool   `json:"enabled"`
	// Port is the raw port setting ("ssh", "22", "ssh,2222", "0:65535").
	Port string `json:"port,omitempty"`
	// IgnoreIP are the ignoreip entries that apply to the jail.
	IgnoreIP []string `json:"ignoreip,omitempty"`
}

// Running reports whether the fail2ban server runs, and whether that is
// known.
func (f *Fail2ban) Running() (running, known bool) {
	switch {
	case f == nil:
		return false, false
	case f.StatusRead:
		return true, true
	case f.Unit != nil && f.Unit.Loaded():
		return f.Unit.Active(), true
	case !f.Installed:
		return false, true
	}
	return false, false
}

// Jail returns the named jail from the config.
func (f *Fail2ban) Jail(name string) (Fail2banJail, bool) {
	if f == nil {
		return Fail2banJail{}, false
	}
	for _, j := range f.Jails {
		if j.Name == name {
			return j, true
		}
	}
	return Fail2banJail{}, false
}

// JailActive reports whether a jail runs: from the live status when read,
// else from the config (enabled) with the server running.
func (f *Fail2ban) JailActive(name string) (active, known bool) {
	if f == nil {
		return false, false
	}
	if f.StatusRead {
		for _, j := range f.ActiveJails {
			if j == name {
				return true, true
			}
		}
		return false, true
	}
	running, rk := f.Running()
	if rk && !running {
		return false, true
	}
	if !f.ConfigRead {
		return false, false
	}
	j, ok := f.Jail(name)
	enabled := ok && j.Enabled
	if enabled && !rk {
		return false, false
	}
	return enabled, true
}

const fail2banDir = "/etc/fail2ban"

type fail2banCollector struct{}

func init() { Register(fail2banCollector{}) }

func (fail2banCollector) Name() string    { return "fail2ban" }
func (fail2banCollector) NeedsRoot() bool { return false }

// Collect runs (all read only):
//
//	systemctl show fail2ban.service --property=LoadState,ActiveState,SubState,UnitFileState
//	fail2ban-client status        (root)
//
// and reads /etc/fail2ban/jail.conf, jail.d/*.conf, jail.local and
// jail.d/*.local in fail2ban's own order.
func (fail2banCollector) Collect(ctx context.Context, sys System, out *Facts) error {
	f := &Fail2ban{}
	_, lookErr := sys.LookPath("fail2ban-client")
	f.Unit = readServiceUnit(ctx, sys, "fail2ban.service")
	_, dirErr := sys.ReadDir(fail2banDir)
	f.Installed = lookErr == nil || dirErr == nil || f.Unit.Loaded()
	out.Fail2ban = f
	if !f.Installed {
		return nil
	}
	var errs []error
	if lookErr == nil && sys.Identity().Root {
		res, err := sys.Run(ctx, "fail2ban-client", "status")
		switch {
		case err != nil:
			errs = append(errs, fmt.Errorf("fail2ban-client status: %w", err))
		case res.ExitCode != 0:
			// Exit 255 when the server is not running: not an error.
			if f.Unit.Active() {
				errs = append(errs, fmt.Errorf("fail2ban-client status exited %d: %s", res.ExitCode, firstLine(res.Stderr)))
			}
		default:
			f.StatusRead, f.ActiveJails = true, ParseFail2banStatus(res.Stdout)
		}
	}

	var files []string
	conf := func(name string) { files = append(files, path.Join(fail2banDir, name)) }
	dropIns := func(ext string) {
		entries, err := sys.ReadDir(path.Join(fail2banDir, "jail.d"))
		if err != nil {
			return
		}
		for _, e := range entries {
			if strings.HasSuffix(e.Name(), ext) {
				files = append(files, path.Join(fail2banDir, "jail.d", e.Name()))
			}
		}
	}
	conf("jail.conf")
	dropIns(".conf")
	conf("jail.local")
	dropIns(".local")
	ini := iniSections{}
	for _, p := range files {
		b, err := sys.ReadFile(p)
		if err != nil {
			continue
		}
		f.ConfigRead = true
		ini.merge(b)
	}
	if f.ConfigRead {
		f.Jails = fail2banJails(ini)
	}
	return errors.Join(errs...)
}

// ParseFail2banStatus reads the jail list of `fail2ban-client status`.
func ParseFail2banStatus(b []byte) []string {
	sc := bufio.NewScanner(bytes.NewReader(b))
	for sc.Scan() {
		_, list, ok := strings.Cut(sc.Text(), "Jail list:")
		if !ok {
			continue
		}
		var out []string
		for _, j := range strings.Split(list, ",") {
			if j = strings.TrimSpace(j); j != "" {
				out = append(out, j)
			}
		}
		sort.Strings(out)
		return out
	}
	return nil
}

// iniSections is fail2ban's configparser view: section, key, value. Later
// files override earlier ones key by key.
type iniSections map[string]map[string]string

// merge parses one INI file into s. Continuation lines (indented) extend
// the previous value, as Python's configparser does.
func (s iniSections) merge(b []byte) {
	section, key := "", ""
	sc := bufio.NewScanner(bytes.NewReader(b))
	for sc.Scan() {
		raw := sc.Text()
		line := strings.TrimSpace(raw)
		if line == "" || line[0] == '#' || line[0] == ';' {
			continue
		}
		if raw[0] == ' ' || raw[0] == '\t' {
			if section != "" && key != "" {
				s[section][key] = strings.TrimSpace(s[section][key] + " " + stripINIComment(line))
			}
			continue
		}
		if strings.HasPrefix(line, "[") && strings.HasSuffix(line, "]") {
			section, key = strings.TrimSpace(line[1:len(line)-1]), ""
			if s[section] == nil {
				s[section] = map[string]string{}
			}
			continue
		}
		k, v, ok := strings.Cut(line, "=")
		if !ok {
			k, v, ok = strings.Cut(line, ":")
		}
		if !ok || section == "" {
			continue
		}
		key = strings.ToLower(strings.TrimSpace(k))
		s[section][key] = stripINIComment(strings.TrimSpace(v))
	}
}

// stripINIComment drops an inline "  # comment" or " ; comment".
func stripINIComment(v string) string {
	for _, sep := range []string{" #", " ;", "\t#", "\t;"} {
		if i := strings.Index(v, sep); i >= 0 {
			v = v[:i]
		}
	}
	return strings.TrimSpace(v)
}

var iniInterpRE = regexp.MustCompile(`%\(([^)]+)\)s`)

// get returns key from section, falling back to DEFAULT, with %(name)s
// references resolved a few levels deep.
func (s iniSections) get(section, key string) (string, bool) {
	v, ok := s[section][key]
	if !ok {
		v, ok = s["DEFAULT"][key]
	}
	if !ok {
		return "", false
	}
	for range 5 {
		if !strings.Contains(v, "%(") {
			break
		}
		v = iniInterpRE.ReplaceAllStringFunc(v, func(m string) string {
			name := strings.ToLower(iniInterpRE.FindStringSubmatch(m)[1])
			if r, ok := s[section][name]; ok {
				return r
			}
			if r, ok := s["DEFAULT"][name]; ok {
				return r
			}
			return m
		})
	}
	return v, true
}

// fail2banJails returns the enabled jails plus sshd, sorted by name.
func fail2banJails(s iniSections) []Fail2banJail {
	var out []Fail2banJail
	for name := range s {
		if name == "DEFAULT" || name == "INCLUDES" || name == "Definition" || name == "Init" {
			continue
		}
		en, _ := s.get(name, "enabled")
		enabled := isTrue(en)
		if !enabled && name != "sshd" {
			continue
		}
		j := Fail2banJail{Name: name, Enabled: enabled}
		j.Port, _ = s.get(name, "port")
		if ig, ok := s.get(name, "ignoreip"); ok {
			j.IgnoreIP = strings.FieldsFunc(ig, func(r rune) bool { return r == ' ' || r == ',' || r == '\t' })
		}
		out = append(out, j)
	}
	sort.Slice(out, func(i, k int) bool { return out[i].Name < out[k].Name })
	return out
}
