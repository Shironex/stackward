package facts

import (
	"context"
	"errors"
	"fmt"
	"path"
	"sort"
	"strings"
)

// Cloudflared is Cloudflare Tunnel connectors found as processes (on the
// host or in containers), the cloudflared systemd unit and its config files
// (CF group). Token values are never stored: command lines are reduced to
// flag names in memory, and the tunnel credentials file is only stat'ed.
type Cloudflared struct {
	// Installed is true when the binary, the unit, a config file or a
	// running connector exists. False with a non nil Cloudflared is a
	// known "no tunnel here".
	Installed bool `json:"installed"`
	// Unit is cloudflared.service, nil when systemd could not be asked.
	Unit *ServiceUnit `json:"unit,omitempty"`
	// UnitTokenInArgs is true when the unit's ExecStart passes the tunnel
	// token on the command line (visible in ps and in the unit file).
	UnitTokenInArgs bool `json:"unit_token_in_args,omitempty"`
	// ProcessesRead is true when /proc could be listed; ProcessesVisible
	// is false when other users' processes are hidden from this user, so
	// zero connectors proves nothing.
	ProcessesRead    bool `json:"processes_read"`
	ProcessesVisible bool `json:"processes_visible"`
	// Connectors are the running cloudflared processes, one per replica.
	Connectors []CloudflaredConnector `json:"connectors,omitempty"`
	// Configs are the config files found and read.
	Configs []CloudflaredConfig `json:"configs,omitempty"`
}

// CloudflaredConnector is one running cloudflared process.
type CloudflaredConnector struct {
	// Container is true when the process runs in a container.
	Container bool `json:"container"`
	// ArgsRead is false when the command line could not be read; the
	// fields below are then unknown.
	ArgsRead bool `json:"args_read"`
	// Mode is "token" (token on the command line), "quick" (a
	// trycloudflare quick tunnel with --url), "named" (anything else: a
	// config file, or the token from TUNNEL_TOKEN) or "" when unknown.
	Mode string `json:"mode,omitempty"`
	// TokenInArgs is true when the tunnel token is a command line
	// argument (the value itself is never stored).
	TokenInArgs bool `json:"token_in_args,omitempty"`
	// ConfigPath is the --config argument, as seen by the process.
	ConfigPath string `json:"config_path,omitempty"`
}

// CloudflaredConfig is one cloudflared config file.
type CloudflaredConfig struct {
	Path string `json:"path"`
	// Tunnel is true when the file names a tunnel.
	Tunnel bool `json:"tunnel"`
	// CredentialsFile is the credentials-file path; CredentialsMode is
	// its permission bits (from stat, never read), "" when missing.
	CredentialsFile string `json:"credentials_file,omitempty"`
	CredentialsMode string `json:"credentials_mode,omitempty"`
	// Ingress are the ingress rules in order. Hostnames are not recorded.
	Ingress []CloudflaredIngress `json:"ingress,omitempty"`
}

// CloudflaredIngress is one ingress rule.
type CloudflaredIngress struct {
	// Hostname is true when the rule matches a hostname (false for the
	// catch all rule).
	Hostname bool `json:"hostname"`
	// Service is the origin, for example "http://localhost:80" or
	// "http_status:404".
	Service string `json:"service"`
}

// TunnelPresent implements profile.TunnelReporter: present is true when a
// connector runs (or the unit is active); a known "no" needs either no
// cloudflared at all with every process visible, or a full process view.
func (c *Cloudflared) TunnelPresent() (present, known bool) {
	if c == nil {
		return false, false
	}
	if len(c.Connectors) > 0 || c.Unit.Active() {
		return true, true
	}
	if c.ProcessesRead && c.ProcessesVisible {
		return false, true
	}
	return false, false
}

// TokenInArgs reports whether any running connector or the unit passes
// the token on the command line, and whether that could be seen at all.
func (c *Cloudflared) TokenInArgs() (inArgs, known bool) {
	if c == nil {
		return false, false
	}
	known = true
	for _, k := range c.Connectors {
		if !k.ArgsRead {
			known = false
		}
		if k.TokenInArgs {
			return true, true
		}
	}
	if c.UnitTokenInArgs {
		return true, true
	}
	return false, known
}

// cloudflaredConfigDirs are where cloudflared looks for config.yml, in its
// own search order (home directories of root only: the audit does not walk
// every home).
var cloudflaredConfigDirs = []string{"/root/.cloudflared", "/root/.cloudflare-warp", "/root/cloudflare-warp", "/etc/cloudflared", "/usr/local/etc/cloudflared"}

type cloudflaredCollector struct{}

func init() { Register(cloudflaredCollector{}) }

func (cloudflaredCollector) Name() string    { return "cloudflared" }
func (cloudflaredCollector) NeedsRoot() bool { return false }

// Collect runs (all read only):
//
//	systemctl show cloudflared.service --property=LoadState,ActiveState,SubState,UnitFileState
//	systemctl show cloudflared.service --property=ExecStart
//
// lists /proc and reads /proc/<pid>/comm, cgroup and (for cloudflared
// processes only) cmdline, reduced to flag names in memory; reads
// config.yml/config.yaml in the default directories and any --config path;
// stats the credentials-file named there (never reads it).
func (cloudflaredCollector) Collect(ctx context.Context, sys System, out *Facts) error {
	c := &Cloudflared{}
	var errs []error
	_, lookErr := sys.LookPath("cloudflared")

	c.Unit = readServiceUnit(ctx, sys, "cloudflared.service")
	configPaths := map[string]bool{}
	if c.Unit.Loaded() {
		if res, err := sys.Run(ctx, "systemctl", "show", "cloudflared.service", "--property=ExecStart"); err == nil {
			a := parseCloudflaredArgs(execStartArgv(ParseKeyValues(res.Stdout)["ExecStart"]))
			c.UnitTokenInArgs = a.tokenInArgs
			if a.config != "" {
				configPaths[a.config] = true
			}
		}
	}

	scan, err := scanProcs(sys, "cloudflared")
	if err != nil {
		errs = append(errs, err)
	} else {
		c.ProcessesRead, c.ProcessesVisible = true, scan.Visible
		for _, e := range scan.Entries {
			k := CloudflaredConnector{Container: e.Container}
			if raw, err := sys.ReadFile("/proc/" + e.PID + "/cmdline"); err == nil && len(raw) > 0 {
				a := parseCloudflaredArgs(strings.Split(strings.TrimRight(string(raw), "\x00"), "\x00"))
				k.ArgsRead, k.Mode, k.TokenInArgs, k.ConfigPath = true, a.mode(), a.tokenInArgs, a.config
				if a.config != "" && !e.Container {
					configPaths[a.config] = true
				}
			}
			c.Connectors = append(c.Connectors, k)
		}
	}

	for _, dir := range cloudflaredConfigDirs {
		for _, name := range []string{"config.yml", "config.yaml"} {
			configPaths[path.Join(dir, name)] = true
		}
	}
	paths := make([]string, 0, len(configPaths))
	for p := range configPaths {
		paths = append(paths, p)
	}
	sort.Strings(paths)
	for _, p := range paths {
		b, err := sys.ReadFile(p)
		if err != nil {
			continue
		}
		cfg := ParseCloudflaredConfig(b)
		cfg.Path = p
		if cfg.CredentialsFile != "" {
			if m, err := sys.Meta(cfg.CredentialsFile); err == nil {
				cfg.CredentialsMode = fmt.Sprintf("%04o", m.Mode.Perm())
			}
		}
		c.Configs = append(c.Configs, cfg)
	}

	c.Installed = lookErr == nil || c.Unit.Loaded() || len(c.Connectors) > 0 || len(c.Configs) > 0
	out.Cloudflared = c
	return errors.Join(errs...)
}

// cloudflaredArgs is what stackward keeps of a cloudflared command line:
// flag facts only, never values other than the config path.
type cloudflaredArgs struct {
	tokenInArgs bool
	quick       bool // --url without "tunnel run"
	config      string
}

func (a cloudflaredArgs) mode() string {
	switch {
	case a.tokenInArgs:
		return "token"
	case a.quick:
		return "quick"
	}
	return "named"
}

// parseCloudflaredArgs reads argv (argv[0] included). The token value is
// looked at only to recognise it and is dropped with argv.
func parseCloudflaredArgs(argv []string) cloudflaredArgs {
	var a cloudflaredArgs
	run, url := false, false
	for i := 0; i < len(argv); i++ {
		arg := argv[i]
		name, value, hasValue := strings.Cut(arg, "=")
		switch strings.TrimLeft(name, "-") {
		case "token":
			if strings.HasPrefix(name, "-") {
				a.tokenInArgs = true
			}
		case "config":
			if !strings.HasPrefix(name, "-") {
				continue
			}
			if !hasValue && i+1 < len(argv) {
				i++
				value = argv[i]
			}
			a.config = value
		case "url":
			if strings.HasPrefix(name, "-") {
				url = true
			}
		case "run":
			run = true
			// `tunnel run <token>` also works: a positional that looks
			// like a token (base64 JSON) after run.
			if i+1 < len(argv) && strings.HasPrefix(argv[i+1], "eyJ") {
				a.tokenInArgs = true
			}
		}
	}
	a.quick = url && !run
	return a
}

// execStartArgv extracts argv from systemd's ExecStart property:
// "{ path=/usr/bin/cloudflared ; argv[]=/usr/bin/cloudflared tunnel run ; ... }".
func execStartArgv(s string) []string {
	_, rest, ok := strings.Cut(s, "argv[]=")
	if !ok {
		return nil
	}
	if i := strings.Index(rest, " ;"); i >= 0 {
		rest = rest[:i]
	}
	return strings.Fields(rest)
}

// ParseCloudflaredConfig reads the tunnel, credentials-file and ingress
// keys of a cloudflared config.yml.
func ParseCloudflaredConfig(b []byte) CloudflaredConfig {
	var cfg CloudflaredConfig
	docs := parseYAMLDocs(b)
	if len(docs) == 0 {
		return cfg
	}
	m := yamlMap(docs[0])
	cfg.Tunnel = yamlStr(m["tunnel"]) != ""
	cfg.CredentialsFile = yamlStr(m["credentials-file"])
	for _, item := range yamlSlice(m["ingress"]) {
		r := yamlMap(item)
		cfg.Ingress = append(cfg.Ingress, CloudflaredIngress{Hostname: yamlStr(r["hostname"]) != "", Service: yamlStr(r["service"])})
	}
	return cfg
}

// The YAML subset reader below is shared by the cloudflared and crowdsec
// collectors. It understands block mappings and sequences, "- key: value"
// items, flow sequences ([a, b]), quoted scalars, literal and folded block
// scalars, comments and "---" document separators: enough for cloudflared
// configs, CrowdSec acquisition and parser files, without a dependency.

type yamlLine struct {
	indent int
	text   string
}

// parseYAMLDocs parses every document in b into map[string]any, []any and
// string values. Malformed input yields partial values, never a panic.
func parseYAMLDocs(b []byte) []any {
	var docs []any
	var cur []yamlLine
	raw := strings.Split(strings.ReplaceAll(string(b), "\r\n", "\n"), "\n")
	flush := func() {
		if len(cur) > 0 {
			p := &yamlParser{lines: cur}
			docs = append(docs, p.block(cur[0].indent))
		}
		cur = nil
	}
	for i := 0; i < len(raw); i++ {
		line := raw[i]
		trimmed := strings.TrimSpace(line)
		if trimmed == "---" || strings.HasPrefix(trimmed, "--- ") || trimmed == "..." {
			flush()
			continue
		}
		text := stripYAMLComment(line)
		if strings.TrimSpace(text) == "" {
			continue
		}
		indent := len(text) - len(strings.TrimLeft(text, " "))
		cur = append(cur, yamlLine{indent: indent, text: strings.TrimSpace(text)})
		// Block scalars keep their raw lines (comments included) as text.
		if v := yamlBlockIndicator(cur[len(cur)-1].text); v {
			for i+1 < len(raw) {
				next := raw[i+1]
				nt := strings.TrimSpace(next)
				ni := len(next) - len(strings.TrimLeft(next, " "))
				if nt != "" && ni <= indent {
					break
				}
				i++
				cur = append(cur, yamlLine{indent: indent + 1 + ni, text: "\x00" + nt})
			}
		}
	}
	flush()
	return docs
}

// yamlBlockIndicator reports whether a line ends in a block scalar
// indicator ("key: |", "- >-").
func yamlBlockIndicator(text string) bool {
	f := strings.Fields(text)
	if len(f) == 0 {
		return false
	}
	last := f[len(f)-1]
	return len(f) >= 2 && (strings.HasPrefix(last, "|") || strings.HasPrefix(last, ">")) && len(last) <= 3
}

func stripYAMLComment(line string) string {
	var quote byte
	for i := 0; i < len(line); i++ {
		ch := line[i]
		switch {
		case quote != 0:
			if ch == quote {
				quote = 0
			}
		case ch == '"' || ch == '\'':
			if i == 0 || line[i-1] == ' ' || line[i-1] == ':' || line[i-1] == '[' || line[i-1] == ',' || line[i-1] == '-' {
				quote = ch
			}
		case ch == '#' && (i == 0 || line[i-1] == ' ' || line[i-1] == '\t'):
			return line[:i]
		}
	}
	return line
}

type yamlParser struct {
	lines []yamlLine
	i     int
}

func isYAMLSeqItem(text string) bool { return text == "-" || strings.HasPrefix(text, "- ") }

func (p *yamlParser) block(indent int) any {
	if p.i >= len(p.lines) {
		return nil
	}
	if isYAMLSeqItem(p.lines[p.i].text) {
		return p.seq(indent)
	}
	return p.mapping(indent)
}

func (p *yamlParser) seq(indent int) []any {
	out := []any{}
	for p.i < len(p.lines) {
		l := p.lines[p.i]
		if l.indent != indent || !isYAMLSeqItem(l.text) {
			break
		}
		rest := strings.TrimSpace(strings.TrimPrefix(l.text, "-"))
		switch {
		case rest == "":
			p.i++
			if p.i < len(p.lines) && p.lines[p.i].indent > indent {
				out = append(out, p.block(p.lines[p.i].indent))
			} else {
				out = append(out, nil)
			}
		case yamlKeyOf(rest) != "" || isYAMLSeqItem(rest):
			// "- key: value": the item is a mapping (or a nested
			// sequence) whose first line starts after the dash.
			off := len(l.text) - len(rest)
			p.lines[p.i] = yamlLine{indent: indent + off, text: rest}
			out = append(out, p.block(indent+off))
		default:
			p.i++
			out = append(out, p.scalarOrBlock(rest, indent))
		}
	}
	return out
}

// yamlKeyOf returns the key when text is "key: value" or "key:".
func yamlKeyOf(text string) string {
	if strings.HasPrefix(text, "\x00") || strings.HasPrefix(text, "[") || strings.HasPrefix(text, "{") {
		return ""
	}
	var key string
	switch text[0] {
	case '"', '\'':
		end := strings.IndexByte(text[1:], text[0])
		if end < 0 {
			return ""
		}
		key = text[1 : end+1]
		rest := text[end+2:]
		if rest != ":" && !strings.HasPrefix(rest, ": ") {
			return ""
		}
		return key
	}
	if i := strings.Index(text, ": "); i > 0 {
		key = text[:i]
	} else if strings.HasSuffix(text, ":") {
		key = strings.TrimSuffix(text, ":")
	}
	if strings.ContainsAny(key, "\"'") {
		return ""
	}
	return strings.TrimSpace(key)
}

func (p *yamlParser) mapping(indent int) map[string]any {
	out := map[string]any{}
	for p.i < len(p.lines) {
		l := p.lines[p.i]
		if l.indent < indent || isYAMLSeqItem(l.text) && l.indent == indent {
			break
		}
		if l.indent > indent {
			p.i++ // stray deeper line: skip it
			continue
		}
		key := yamlKeyOf(l.text)
		if key == "" {
			p.i++
			continue
		}
		_, val, _ := strings.Cut(l.text, ":")
		if strings.HasPrefix(l.text, `"`) || strings.HasPrefix(l.text, "'") {
			val = l.text[len(key)+3:]
		}
		val = strings.TrimSpace(val)
		p.i++
		if val != "" {
			out[key] = p.scalarOrBlock(val, indent)
			continue
		}
		switch {
		case p.i < len(p.lines) && p.lines[p.i].indent > indent:
			out[key] = p.block(p.lines[p.i].indent)
		case p.i < len(p.lines) && p.lines[p.i].indent == indent && isYAMLSeqItem(p.lines[p.i].text):
			out[key] = p.seq(indent)
		default:
			out[key] = ""
		}
	}
	return out
}

// scalarOrBlock reads a scalar value, or the block scalar lines that follow
// a "|" or ">" indicator.
func (p *yamlParser) scalarOrBlock(val string, indent int) any {
	if (strings.HasPrefix(val, "|") || strings.HasPrefix(val, ">")) && len(val) <= 3 {
		var parts []string
		for p.i < len(p.lines) && strings.HasPrefix(p.lines[p.i].text, "\x00") && p.lines[p.i].indent > indent {
			parts = append(parts, strings.TrimPrefix(p.lines[p.i].text, "\x00"))
			p.i++
		}
		sep := "\n"
		if val[0] == '>' {
			sep = " "
		}
		return strings.TrimSpace(strings.Join(parts, sep))
	}
	return yamlScalar(val)
}

func yamlScalar(v string) any {
	v = strings.TrimSpace(v)
	if strings.HasPrefix(v, "[") && strings.HasSuffix(v, "]") {
		out := []any{}
		for _, part := range strings.Split(v[1:len(v)-1], ",") {
			if s := strings.TrimSpace(part); s != "" {
				out = append(out, unquoteYAML(s))
			}
		}
		return out
	}
	return unquoteYAML(v)
}

func unquoteYAML(v string) string {
	if len(v) >= 2 && (v[0] == '"' || v[0] == '\'') && v[len(v)-1] == v[0] {
		return v[1 : len(v)-1]
	}
	return v
}

func yamlMap(v any) map[string]any {
	m, _ := v.(map[string]any)
	return m
}

func yamlSlice(v any) []any {
	s, _ := v.([]any)
	return s
}

func yamlStr(v any) string {
	s, _ := v.(string)
	return s
}

// yamlStrings reads a scalar or a sequence of scalars as a string list.
func yamlStrings(v any) []string {
	switch t := v.(type) {
	case string:
		if t == "" {
			return nil
		}
		return []string{t}
	case []any:
		var out []string
		for _, x := range t {
			if s, ok := x.(string); ok && s != "" {
				out = append(out, s)
			}
		}
		return out
	}
	return nil
}
