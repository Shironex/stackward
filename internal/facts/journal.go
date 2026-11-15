package facts

import (
	"bufio"
	"bytes"
	"context"
	"errors"
	"io/fs"
	"path"
	"regexp"
	"sort"
	"strconv"
	"strings"
)

// Journal is journald size and persistence, proxy access log sizes and the
// monitoring agents found (LOG group).
type Journal struct {
	// Storage is the effective Storage= from the journald configuration
	// ("auto" when unset).
	Storage string `json:"storage"`
	// SystemMaxUse is the effective SystemMaxUse= ("" when unset).
	SystemMaxUse string `json:"system_max_use,omitempty"`
	// PersistentDir is whether /var/log/journal exists.
	PersistentDir bool `json:"persistent_dir"`
	// Persistent is the derived answer: Storage=persistent, or auto with
	// the directory present.
	Persistent bool `json:"persistent"`
	// DiskUsageChecked is true when `journalctl --disk-usage` answered;
	// DiskUsageBytes is then the size it reported.
	DiskUsageChecked bool  `json:"disk_usage_checked"`
	DiskUsageBytes   int64 `json:"disk_usage_bytes,omitempty"`
	// ProxyLogs lists access and error logs of the usual reverse proxies.
	ProxyLogs []LogFile `json:"proxy_logs"`
	// Agents names the monitoring agents found (binary or unit present).
	Agents []string `json:"agents"`
}

// LogFile is one log file and whether a logrotate rule covers it.
type LogFile struct {
	Path      string `json:"path"`
	SizeBytes int64  `json:"size_bytes"`
	Rotated   bool   `json:"rotated"`
}

// Paths the journal collector reads.
const (
	journaldConfPath = "/etc/systemd/journald.conf"
	journalDir       = "/var/log/journal"
	logrotateConf    = "/etc/logrotate.conf"
	logrotateDir     = "/etc/logrotate.d"
	maxLogsPerDir    = 40
)

var journaldDropinDirs = []string{"/usr/lib/systemd/journald.conf.d", "/run/systemd/journald.conf.d", "/etc/systemd/journald.conf.d"}

var proxyLogDirs = []string{"/var/log/nginx", "/var/log/caddy", "/var/log/traefik", "/var/log/apache2", "/var/log/haproxy"}

// monitoringAgents maps an agent name to files whose presence shows it is
// installed (binary, config directory or unit).
var monitoringAgents = []struct {
	name  string
	paths []string
}{
	{"node_exporter", []string{"/usr/bin/node_exporter", "/usr/local/bin/node_exporter", "/usr/bin/prometheus-node-exporter", "/etc/systemd/system/node_exporter.service"}},
	{"alloy", []string{"/usr/bin/alloy", "/etc/alloy"}},
	{"grafana-agent", []string{"/usr/bin/grafana-agent", "/etc/grafana-agent.yaml"}},
	{"netdata", []string{"/usr/sbin/netdata", "/etc/netdata"}},
	{"telegraf", []string{"/usr/bin/telegraf", "/etc/telegraf"}},
	{"zabbix-agent", []string{"/usr/sbin/zabbix_agentd", "/usr/sbin/zabbix_agent2"}},
	{"datadog-agent", []string{"/opt/datadog-agent", "/etc/datadog-agent"}},
	{"beszel-agent", []string{"/opt/beszel-agent/beszel-agent", "/usr/local/bin/beszel-agent"}},
}

type journalCollector struct{}

func init() { Register(journalCollector{}) }

func (journalCollector) Name() string    { return "journal" }
func (journalCollector) NeedsRoot() bool { return false }

func (journalCollector) Collect(ctx context.Context, sys System, out *Facts) error {
	j := &Journal{}
	conf := readJournaldConf(sys)
	j.Storage = strings.ToLower(conf["Storage"])
	if j.Storage == "" {
		j.Storage = "auto"
	}
	j.SystemMaxUse = conf["SystemMaxUse"]
	if m, err := sys.Meta(journalDir); err == nil && m.Mode.IsDir() {
		j.PersistentDir = true
	}
	j.Persistent = j.Storage == "persistent" || (j.Storage == "auto" && j.PersistentDir)

	// `journalctl --disk-usage` only sums file sizes.
	if res, err := sys.Run(ctx, "journalctl", "--disk-usage"); err == nil && res.ExitCode == 0 {
		if n, ok := ParseJournalDiskUsage(res.Stdout); ok {
			j.DiskUsageChecked, j.DiskUsageBytes = true, n
		}
	}

	rotated := logrotatePatterns(sys)
	j.ProxyLogs = []LogFile{}
	for _, dir := range proxyLogDirs {
		entries, err := sys.ReadDir(dir)
		if err != nil {
			continue
		}
		n := 0
		for _, e := range entries {
			name := e.Name()
			if e.IsDir() || !strings.HasSuffix(name, ".log") || n >= maxLogsPerDir {
				continue
			}
			p := path.Join(dir, name)
			m, err := sys.Meta(p)
			if err != nil {
				continue
			}
			n++
			j.ProxyLogs = append(j.ProxyLogs, LogFile{Path: p, SizeBytes: m.Size, Rotated: matchesAny(rotated, p)})
		}
	}

	j.Agents = []string{}
	for _, a := range monitoringAgents {
		if anyExists(sys, a.paths) {
			j.Agents = append(j.Agents, a.name)
		}
	}
	out.Journal = j
	return nil
}

// readJournaldConf returns the effective [Journal] settings: the main file,
// then drop-ins in file name order, an /etc file masking a same-named one
// from /run or /usr/lib. Later settings win.
func readJournaldConf(sys System) map[string]string {
	byName := map[string]string{}
	for _, dir := range journaldDropinDirs {
		entries, err := sys.ReadDir(dir)
		if err != nil && !errors.Is(err, fs.ErrNotExist) {
			continue
		}
		for _, e := range entries {
			if !e.IsDir() && strings.HasSuffix(e.Name(), ".conf") {
				byName[e.Name()] = path.Join(dir, e.Name())
			}
		}
	}
	names := make([]string, 0, len(byName))
	for n := range byName {
		names = append(names, n)
	}
	sort.Strings(names)
	files := []string{journaldConfPath}
	for _, n := range names {
		files = append(files, byName[n])
	}
	out := map[string]string{}
	for _, f := range files {
		if b, err := sys.ReadFile(f); err == nil {
			for k, v := range ParseJournaldConf(b) {
				out[k] = v
			}
		}
	}
	return out
}

// ParseJournaldConf returns the key=value pairs of the [Journal] section.
func ParseJournaldConf(b []byte) map[string]string {
	out := map[string]string{}
	inJournal := false
	sc := bufio.NewScanner(bytes.NewReader(b))
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		switch {
		case line == "" || line[0] == '#' || line[0] == ';':
		case strings.HasPrefix(line, "["):
			inJournal = line == "[Journal]"
		case inJournal:
			if k, v, ok := strings.Cut(line, "="); ok {
				out[strings.TrimSpace(k)] = strings.TrimSpace(v)
			}
		}
	}
	return out
}

var journalUsage = regexp.MustCompile(`take up ([0-9.]+)([BKMGTP]?)`)

// ParseJournalDiskUsage parses "Archived and active journals take up 1.2G
// in the file system." into bytes.
func ParseJournalDiskUsage(b []byte) (int64, bool) {
	m := journalUsage.FindSubmatch(b)
	if m == nil {
		return 0, false
	}
	v, err := strconv.ParseFloat(string(m[1]), 64)
	if err != nil {
		return 0, false
	}
	mult := map[string]float64{"": 1, "B": 1, "K": 1 << 10, "M": 1 << 20, "G": 1 << 30, "T": 1 << 40, "P": 1 << 50}[string(m[2])]
	return int64(v * mult), true
}

// logrotatePatterns returns the absolute path patterns that logrotate
// configuration names (the text before each "{").
func logrotatePatterns(sys System) []string {
	files := []string{logrotateConf}
	if entries, err := sys.ReadDir(logrotateDir); err == nil {
		for _, e := range entries {
			if !e.IsDir() {
				files = append(files, path.Join(logrotateDir, e.Name()))
			}
		}
	}
	var out []string
	for _, f := range files {
		if b, err := sys.ReadFile(f); err == nil {
			out = append(out, ParseLogrotatePatterns(b)...)
		}
	}
	return out
}

// ParseLogrotatePatterns returns the absolute path patterns that start a
// logrotate stanza.
func ParseLogrotatePatterns(b []byte) []string {
	var out []string
	var head strings.Builder
	depth := 0
	for _, line := range strings.Split(string(b), "\n") {
		if i := strings.Index(line, "#"); i >= 0 {
			line = line[:i]
		}
		for _, r := range line {
			switch {
			case r == '{':
				if depth == 0 {
					out = append(out, stanzaPaths(head.String())...)
					head.Reset()
				}
				depth++
			case r == '}':
				if depth > 0 {
					depth--
				}
			case depth == 0:
				head.WriteRune(r)
			}
		}
		if depth == 0 {
			head.WriteByte(' ')
		}
	}
	return out
}

func stanzaPaths(head string) []string {
	var out []string
	for _, tok := range strings.Fields(head) {
		tok = strings.Trim(tok, `"'`)
		if strings.HasPrefix(tok, "/") {
			out = append(out, tok)
		}
	}
	return out
}

func matchesAny(patterns []string, p string) bool {
	for _, pat := range patterns {
		if ok, err := path.Match(pat, p); err == nil && ok {
			return true
		}
	}
	return false
}
