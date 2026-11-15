package facts

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"path"
	"regexp"
	"sort"
	"strings"
	"time"
)

// CrowdSec is the CrowdSec engine, bouncers, hub items, acquisition and the
// whitelist and real IP parsers (CS group). Bouncer API keys are never
// stored: the bouncer list keeps names, types and last pull times only, and
// bouncer config files (which hold the key) are not read.
type CrowdSec struct {
	// Installed is true when cscli, /etc/crowdsec, the unit or a running
	// engine exists. False with a non nil CrowdSec is a known "absent".
	Installed bool `json:"installed"`
	// Unit is crowdsec.service, nil when systemd could not be asked.
	Unit *ServiceUnit `json:"unit,omitempty"`
	// ProcessesRead and ProcessesVisible: see Cloudflared.
	ProcessesRead    bool `json:"processes_read"`
	ProcessesVisible bool `json:"processes_visible"`
	// EngineProcesses counts running crowdsec processes (host or
	// container); EngineInContainer counts those in a container.
	EngineProcesses   int `json:"engine_processes"`
	EngineInContainer int `json:"engine_in_container,omitempty"`
	// Cscli is true when cscli is on the host PATH.
	Cscli   bool   `json:"cscli"`
	Version string `json:"version,omitempty"`

	// BouncersRead is true when `cscli bouncers list` answered (root).
	BouncersRead bool              `json:"bouncers_read"`
	Bouncers     []CrowdSecBouncer `json:"bouncers,omitempty"`
	// HubRead is true when the installed collections and parsers were
	// listed.
	HubRead     bool     `json:"hub_read"`
	Collections []string `json:"collections,omitempty"`
	Parsers     []string `json:"parsers,omitempty"`
	// LAPIListen is Config.API.Server.ListenURI ("127.0.0.1:8080"), ""
	// when unknown.
	LAPIListen string `json:"lapi_listen,omitempty"`

	// AcquisitionRead is true when acquis.yaml or acquis.d was read.
	AcquisitionRead bool             `json:"acquisition_read"`
	Acquisition     []CrowdSecSource `json:"acquisition,omitempty"`
	// ParserFilesRead is true when the parser directories were listed.
	// ParserFiles lists only files that whitelist addresses or take the
	// client address from a header.
	ParserFilesRead bool                 `json:"parser_files_read"`
	ParserFiles     []CrowdSecParserFile `json:"parser_files,omitempty"`
}

// CrowdSecBouncer is one registered bouncer.
type CrowdSecBouncer struct {
	Name    string `json:"name"`
	Type    string `json:"type,omitempty"`
	Version string `json:"version,omitempty"`
	// Kind is "firewall" (host packet filter), "proxy" (an L7 bouncer in a
	// reverse proxy), "cloudflare" (at the Cloudflare edge) or "other".
	Kind    string `json:"kind"`
	Revoked bool   `json:"revoked,omitempty"`
	// LastPull is the last time the bouncer pulled decisions; nil when it
	// never did.
	LastPull *time.Time `json:"last_pull,omitempty"`
}

// CrowdSecSource is one acquisition source.
type CrowdSecSource struct {
	// File is the acquisition file the source is declared in.
	File string `json:"file"`
	// Source is "file" (the default), "docker", "journalctl", ...
	Source string `json:"source"`
	// Type is labels.type, the parser family ("traefik", "nginx",
	// "syslog").
	Type       string   `json:"type,omitempty"`
	Paths      []string `json:"paths,omitempty"`
	Containers []string `json:"containers,omitempty"`
}

// CrowdSecParserFile is a parser or postoverflow file of interest.
type CrowdSecParserFile struct {
	Path string `json:"path"`
	Name string `json:"name,omitempty"`
	// WhitelistCIDRs and WhitelistIPs are the whitelist entries.
	WhitelistCIDRs []string `json:"whitelist_cidrs,omitempty"`
	WhitelistIPs   []string `json:"whitelist_ips,omitempty"`
	// RealIPHeader is the header the parser takes the client address from
	// ("cf-connecting-ip"), when it sets source_ip from one.
	RealIPHeader string `json:"real_ip_header,omitempty"`
	// RealIPKeyedTo are literal addresses the parser's filter compares the
	// source with (a parser keyed to one Docker gateway); empty when the
	// filter uses ranges or no address.
	RealIPKeyedTo []string `json:"real_ip_keyed_to,omitempty"`
}

// EngineRunning reports whether the engine runs, and whether that is
// known.
func (c *CrowdSec) EngineRunning() (running, known bool) {
	if c == nil {
		return false, false
	}
	if c.EngineProcesses > 0 || c.Unit.Active() {
		return true, true
	}
	if c.Unit != nil && c.Unit.Loaded() {
		return false, true
	}
	if c.ProcessesRead && c.ProcessesVisible {
		return false, true
	}
	return false, false
}

// HasItem reports whether a collection or parser with the given name (or
// name suffix after the author, "sshd" for "crowdsecurity/sshd") is
// installed.
func (c *CrowdSec) HasItem(name string) bool {
	if c == nil {
		return false
	}
	for _, list := range [][]string{c.Collections, c.Parsers} {
		for _, n := range list {
			if n == name || strings.HasSuffix(n, "/"+name) {
				return true
			}
		}
	}
	return false
}

// Paths the crowdsec collector reads.
const (
	crowdsecDir       = "/etc/crowdsec"
	crowdsecAcquis    = "/etc/crowdsec/acquis.yaml"
	crowdsecAcquisDir = "/etc/crowdsec/acquis.d"
)

// crowdsecParserDirs are the parser and postoverflow stages scanned for
// whitelists and real IP parsers. Hub items are symlinks into the hub.
var crowdsecParserDirs = []string{
	"/etc/crowdsec/parsers/s00-raw",
	"/etc/crowdsec/parsers/s01-parse",
	"/etc/crowdsec/parsers/s02-enrich",
	"/etc/crowdsec/postoverflows/s00-enrich",
	"/etc/crowdsec/postoverflows/s01-whitelist",
}

type crowdsecCollector struct{}

func init() { Register(crowdsecCollector{}) }

func (crowdsecCollector) Name() string    { return "crowdsec" }
func (crowdsecCollector) NeedsRoot() bool { return false }

// Collect runs (all read only):
//
//	systemctl show crowdsec.service --property=LoadState,ActiveState,SubState,UnitFileState
//	cscli version
//	cscli bouncers list -o json          (root)
//	cscli collections list -o json
//	cscli parsers list -o json
//	cscli config show --key Config.API.Server.ListenURI
//
// lists /proc (comm and cgroup of crowdsec processes), reads
// /etc/crowdsec/acquis.yaml, /etc/crowdsec/acquis.d/*.yaml and the parser
// files under /etc/crowdsec/parsers and postoverflows. It never reads
// local_api_credentials.yaml, online_api_credentials.yaml, config.yaml or
// the bouncer configs under /etc/crowdsec/bouncers (they hold keys).
func (crowdsecCollector) Collect(ctx context.Context, sys System, out *Facts) error {
	c := &CrowdSec{}
	var errs []error
	_, lookErr := sys.LookPath("cscli")
	c.Cscli = lookErr == nil
	c.Unit = readServiceUnit(ctx, sys, "crowdsec.service")

	if scan, err := scanProcs(sys, "crowdsec"); err != nil {
		errs = append(errs, err)
	} else {
		c.ProcessesRead, c.ProcessesVisible = true, scan.Visible
		c.EngineProcesses, c.EngineInContainer = scan.count("crowdsec")
	}
	_, dirErr := sys.ReadDir(crowdsecDir)
	c.Installed = c.Cscli || dirErr == nil || c.Unit.Loaded() || c.EngineProcesses > 0
	out.CrowdSec = c
	if !c.Installed {
		return errors.Join(errs...)
	}

	if c.Cscli {
		if res, err := sys.Run(ctx, "cscli", "version"); err == nil {
			c.Version = parseCscliVersion(append(append([]byte{}, res.Stdout...), res.Stderr...))
		}
		res, err := sys.Run(ctx, "cscli", "bouncers", "list", "-o", "json")
		switch {
		case err != nil:
			errs = append(errs, fmt.Errorf("cscli bouncers list: %w", err))
		case res.ExitCode != 0:
			if sys.Identity().Root {
				errs = append(errs, fmt.Errorf("cscli bouncers list exited %d: %s", res.ExitCode, firstLine(res.Stderr)))
			}
		default:
			bs, perr := ParseCrowdSecBouncers(res.Stdout)
			if perr != nil {
				errs = append(errs, perr)
			} else {
				c.BouncersRead, c.Bouncers = true, bs
			}
		}
		cols, colOK := cscliHubList(ctx, sys, "collections")
		pars, parOK := cscliHubList(ctx, sys, "parsers")
		if colOK && parOK {
			c.HubRead, c.Collections, c.Parsers = true, cols, pars
		}
		if res, err := sys.Run(ctx, "cscli", "config", "show", "--key", "Config.API.Server.ListenURI"); err == nil && res.ExitCode == 0 {
			v := strings.Trim(strings.TrimSpace(string(res.Stdout)), `"'`)
			if v != "" && v != "<nil>" && !strings.ContainsAny(v, " \n") {
				c.LAPIListen = v
			}
		}
	}

	c.Acquisition, c.AcquisitionRead = readCrowdSecAcquisition(sys)
	c.ParserFiles, c.ParserFilesRead = readCrowdSecParsers(sys)
	return errors.Join(errs...)
}

var cscliVersionRE = regexp.MustCompile(`(?m)^version:\s*(\S+)`)

func parseCscliVersion(b []byte) string {
	if m := cscliVersionRE.FindSubmatch(b); m != nil {
		return string(m[1])
	}
	return ""
}

// ParseCrowdSecBouncers reads `cscli bouncers list -o json`. Every field
// but name, type, version, revoked and last_pull is dropped, the API key
// (or its hash) included.
func ParseCrowdSecBouncers(b []byte) ([]CrowdSecBouncer, error) {
	trimmed := strings.TrimSpace(string(b))
	if trimmed == "" || trimmed == "null" {
		return []CrowdSecBouncer{}, nil
	}
	var raw []struct {
		Name     string          `json:"name"`
		Type     string          `json:"type"`
		Version  string          `json:"version"`
		Revoked  bool            `json:"revoked"`
		LastPull json.RawMessage `json:"last_pull"`
	}
	if err := json.Unmarshal([]byte(trimmed), &raw); err != nil {
		return nil, fmt.Errorf("cscli bouncers list -o json: %w", err)
	}
	out := make([]CrowdSecBouncer, 0, len(raw))
	for _, r := range raw {
		bc := CrowdSecBouncer{Name: r.Name, Type: r.Type, Version: r.Version, Revoked: r.Revoked, Kind: BouncerKind(r.Type, r.Name)}
		var s string
		if json.Unmarshal(r.LastPull, &s) == nil && s != "" {
			if t, err := time.Parse(time.RFC3339Nano, s); err == nil && t.Year() > 1 {
				u := t.UTC()
				bc.LastPull = &u
			}
		}
		out = append(out, bc)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out, nil
}

// BouncerKind classifies a bouncer by its type, or its name when the type
// is empty.
func BouncerKind(typ, name string) string {
	s := strings.ToLower(typ)
	if s == "" {
		s = strings.ToLower(name)
	}
	switch {
	case strings.Contains(s, "firewall"), strings.Contains(s, "iptables"), strings.Contains(s, "nftables"):
		return "firewall"
	case strings.Contains(s, "cloudflare"):
		return "cloudflare"
	}
	for _, p := range []string{"traefik", "caddy", "nginx", "openresty", "haproxy", "apache", "envoy", "lua", "ingress", "spoa", "wordpress", "php"} {
		if strings.Contains(s, p) {
			return "proxy"
		}
	}
	return "other"
}

// cscliHubList runs `cscli <kind> list -o json` and returns the installed,
// enabled item names.
func cscliHubList(ctx context.Context, sys System, kind string) ([]string, bool) {
	res, err := sys.Run(ctx, "cscli", kind, "list", "-o", "json")
	if err != nil || res.ExitCode != 0 {
		return nil, false
	}
	names, err := ParseCscliHubList(res.Stdout, kind)
	return names, err == nil
}

// ParseCscliHubList reads `cscli collections|parsers list -o json`.
func ParseCscliHubList(b []byte, kind string) ([]string, error) {
	var doc map[string][]struct {
		Name   string `json:"name"`
		Status string `json:"status"`
	}
	if err := json.Unmarshal(b, &doc); err != nil {
		return nil, fmt.Errorf("cscli %s list -o json: %w", kind, err)
	}
	var out []string
	for _, it := range doc[kind] {
		if it.Name == "" || strings.HasPrefix(strings.ToLower(it.Status), "disabled") {
			continue
		}
		out = append(out, it.Name)
	}
	sort.Strings(out)
	return out, nil
}

// yamlFiles lists *.yaml and *.yml files in dir, sorted.
func yamlFiles(sys System, dir string) ([]string, error) {
	entries, err := sys.ReadDir(dir)
	if err != nil {
		return nil, err
	}
	var out []string
	for _, e := range entries {
		n := e.Name()
		if strings.HasSuffix(n, ".yaml") || strings.HasSuffix(n, ".yml") {
			out = append(out, path.Join(dir, n))
		}
	}
	return out, nil
}

func readCrowdSecAcquisition(sys System) ([]CrowdSecSource, bool) {
	files := []string{crowdsecAcquis}
	if more, err := yamlFiles(sys, crowdsecAcquisDir); err == nil {
		files = append(files, more...)
	}
	var out []CrowdSecSource
	read := false
	for _, f := range files {
		b, err := sys.ReadFile(f)
		if err != nil {
			continue
		}
		read = true
		for _, s := range ParseCrowdSecAcquisition(b) {
			s.File = f
			out = append(out, s)
		}
	}
	return out, read
}

// ParseCrowdSecAcquisition reads the sources of one acquisition file
// (several YAML documents).
func ParseCrowdSecAcquisition(b []byte) []CrowdSecSource {
	var out []CrowdSecSource
	for _, d := range parseYAMLDocs(b) {
		m := yamlMap(d)
		if len(m) == 0 {
			continue
		}
		s := CrowdSecSource{Source: yamlStr(m["source"])}
		if s.Source == "" {
			s.Source = "file"
		}
		s.Type = yamlStr(yamlMap(m["labels"])["type"])
		s.Paths = append(yamlStrings(m["filenames"]), yamlStrings(m["filename"])...)
		s.Containers = append(yamlStrings(m["container_name"]), yamlStrings(m["container_name_regexp"])...)
		out = append(out, s)
	}
	return out
}

func readCrowdSecParsers(sys System) ([]CrowdSecParserFile, bool) {
	var out []CrowdSecParserFile
	listed := false
	for _, dir := range crowdsecParserDirs {
		files, err := yamlFiles(sys, dir)
		if err != nil {
			continue
		}
		listed = true
		for _, f := range files {
			b, err := sys.ReadFile(f)
			if err != nil {
				continue
			}
			if pf, ok := ParseCrowdSecParser(b); ok {
				pf.Path = f
				out = append(out, pf)
			}
		}
	}
	return out, listed
}

var (
	ipv4LiteralRE = regexp.MustCompile(`\b(?:\d{1,3}\.){3}\d{1,3}\b`)
	cidrLiteralRE = regexp.MustCompile(`\d/\d`)
	realIPHeaders = []string{"cf-connecting-ip", "true-client-ip", "x-real-ip", "x-forwarded-for"}
)

// ParseCrowdSecParser reports whether a parser file whitelists addresses or
// takes the client address from a header, and what it says. ok is false for
// files of no interest.
func ParseCrowdSecParser(b []byte) (CrowdSecParserFile, bool) {
	var pf CrowdSecParserFile
	lower := strings.ToLower(string(b))
	for _, d := range parseYAMLDocs(b) {
		m := yamlMap(d)
		if pf.Name == "" {
			pf.Name = yamlStr(m["name"])
		}
		if wl := yamlMap(m["whitelist"]); wl != nil {
			pf.WhitelistCIDRs = append(pf.WhitelistCIDRs, yamlStrings(wl["cidr"])...)
			pf.WhitelistIPs = append(pf.WhitelistIPs, yamlStrings(wl["ip"])...)
		}
		if pf.RealIPHeader != "" || !strings.Contains(lower, "source_ip") {
			continue
		}
		for _, h := range realIPHeaders {
			if strings.Contains(lower, h) {
				pf.RealIPHeader = h
				break
			}
		}
		if pf.RealIPHeader != "" {
			pf.RealIPKeyedTo = keyedAddresses(yamlStr(m["filter"]))
		}
	}
	ok := len(pf.WhitelistCIDRs) > 0 || len(pf.WhitelistIPs) > 0 || pf.RealIPHeader != ""
	return pf, ok
}

// keyedAddresses returns the literal IPv4 addresses a filter compares with,
// unless the filter also matches ranges (IpInRange, a CIDR).
func keyedAddresses(filter string) []string {
	l := strings.ToLower(filter)
	if strings.Contains(l, "ipinrange") || strings.Contains(l, "iptorange") || cidrLiteralRE.MatchString(l) {
		return nil
	}
	seen := map[string]bool{}
	var out []string
	for _, ip := range ipv4LiteralRE.FindAllString(filter, -1) {
		if !seen[ip] {
			seen[ip] = true
			out = append(out, ip)
		}
	}
	return out
}
